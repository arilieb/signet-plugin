# -*- encoding: utf-8 -*-
"""
signet.core.remoting module

Async functions for Onyx's UDAP vLEI onboarding flow: submit an onboarding
request, poll for an approval/rejection decision, and perform Dynamic Client
Registration once approved. Each function hits the real endpoint per the
UDAP vLEI onboarding design, short-circuiting to a canned mock_data response
in the DEVELOPMENT environment -- switching to real Onyx servers later is a
zero-UI-change flip once LOCKSMITH_ENVIRONMENT isn't 'development'.

Every function returns the same {'success': bool, ...} / {'success': False,
'error': ...} dict shape used throughout this codebase (see
castellan/core/remoting.py), so callers can use the same result['success']
check idiom.
"""

import html
import json
import re
import tempfile
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urljoin, urlsplit

import httpx
from keri import help

from . import mock_data
from .configing import (
    is_keri_discovery_url,
    is_mock_mode,
    onboarding_endpoint_override,
    onboarding_server_aid,
)
from .presenting import ASSERTION_TYPE

logger = help.ogler.getLogger(__name__)

_TIMEOUT = 30.0


def _loggable_body(content_type: str, body: bytes) -> str:
    """Request body for the log: a JSON packet with its (large) ``ipex_grant`` elided."""
    if "json" in content_type:
        try:
            packet = json.loads(body)
            if isinstance(packet, dict) and "ipex_grant" in packet:
                packet["ipex_grant"] = f"<{len(packet['ipex_grant'])} chars omitted>"
            return json.dumps(packet)
        except ValueError:
            pass
    return f"<{len(body)} bytes omitted>"


def _log_request(method: str, url: str, headers: Dict[str, str], body: str = ""):
    logger.info(f"Onboarding request: {method} {url} headers={headers} body={body}")


_DEBUG_PAGE_PATTERNS = {
    "title": r"<title>(.*?)</title>",
    "exception": r'<pre class="exception_value">(.*?)</pre>',
    "traceback": r'<textarea[^>]*id="traceback_area"[^>]*>(.*?)</textarea>',
}


def _html_error_summary(text: str) -> str:
    """Title, exception and traceback of a framework (Django) debug error page, if it is one."""
    parts = []
    for label, pattern in _DEBUG_PAGE_PATTERNS.items():
        match = re.search(pattern, text, re.DOTALL)
        if match:
            parts.append(f"{label}: {html.unescape(match.group(1)).strip()}")
    return "\n".join(parts)


def _log_response(response: httpx.Response):
    """
    Log status, all headers and the body (to diagnose a bare 4xx/5xx).

    A long non-JSON body (an HTML error page) is saved in full to a temp file, and
    a framework debug page is reduced to its exception and traceback.
    """
    text = response.text
    body = repr(text[:2000])
    saved = ""
    if "json" not in response.headers.get("content-type", "") and len(text) > 2000:
        path = Path(tempfile.gettempdir()) / "signet-onboarding-last-response.html"
        path.write_text(text, encoding="utf-8")
        saved = f" full_body_saved_to={path}"
        body = repr(text[:300])
    logger.info(
        f"Onboarding response: {response.status_code} {response.reason_phrase} "
        f"url={response.url} headers={dict(response.headers)} body={body}{saved}"
    )
    summary = _html_error_summary(text) if saved else ""
    if summary:
        logger.info(f"Onboarding response error page:\n{summary}")


def _error_result(response: httpx.Response) -> Dict[str, Any]:
    """Failure dict from a 4xx/5xx onboarding response, keeping its correlation id."""
    try:
        data = response.json()
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    description = (
        data.get("error_description")
        or data.get("error")
        or f"API error: {response.status_code}"
    )
    correlation_id = data.get("correlation_id") or response.headers.get(
        "Correlation-ID", ""
    )
    if correlation_id:
        description = f"{description} (correlation id: {correlation_id})"
    return {
        "success": False,
        "error": description,
        "status_code": response.status_code,
        "correlation_id": correlation_id,
    }


def _rebase_poll_url(base_url: str, poll_url: str) -> str:
    """
    Move ``poll_url`` onto the host of SIGNET_ONBOARDING_ENDPOINT (keri partners only).

    The override exists because the discovery document names the wrong host, and the
    server builds its ``Content-Location`` from the same wrong host. The path is kept.
    """
    override = onboarding_endpoint_override()
    if not (poll_url and override and is_keri_discovery_url(base_url)):
        return poll_url
    target = urlsplit(override)
    rebased = urlsplit(poll_url)._replace(scheme=target.scheme, netloc=target.netloc)
    return rebased.geturl()


def _decision_result(request_url: str, response: httpx.Response) -> Dict[str, Any]:
    """
    Success dict from a 202 (pending) or 200 (terminal) onboarding response.

    ``Content-Location`` is resolved against ``request_url``: the onboarding host
    can differ from the discovery host.
    """
    data = response.json()
    location = response.headers.get("Content-Location", "")
    purposes = data.get("purposes") or []
    return {
        "success": True,
        "terminal": response.status_code == 200,
        "onboarding_id": data.get("onboarding_id") or data.get("review_id"),
        "decision_due": data.get("decision_due") or "",
        "correlation_id": data.get("correlation_id", ""),
        "status": data.get("status", "pending-verification"),
        "purpose_status": purposes[0].get("status", "") if purposes else "",
        "decision_provenance": data.get("decision_provenance") or {},
        "poll_url": urljoin(request_url, location) if location else "",
        "retry_after": response.headers.get("Retry-After", ""),
        "data": data,
    }


async def discover_server(base_url: str) -> Dict[str, Any]:
    """
    GET {base_url}/.well-known/udap -- find the onboarding endpoint and server AID.

    A ``base_url`` that is itself a ``.well-known/keri`` URL is fetched as-is; that
    document advertises no server AID, so ``aid`` comes from
    SIGNET_ONBOARDING_SERVER_AID ("" if unset; the packet builder rejects that).
    SIGNET_ONBOARDING_ENDPOINT, if set, replaces the document's ``onboarding_endpoint``
    (a workaround for a document that advertises the wrong one).

    Fails if the server does not advertise onboarding (legacy mode).
    ``token_endpoint`` is returned when advertised ("" otherwise): onboarding
    does not need it, Authenticate does.
    """
    if is_mock_mode():
        return mock_data.mock_discover_server(base_url)

    keri = is_keri_discovery_url(base_url)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.get(
                base_url if keri else f"{base_url}/.well-known/udap"
            )
        if response.status_code != 200:
            return {"success": False, "error": f"API error: {response.status_code}"}
        data = response.json()
        endpoint = data.get("onboarding_endpoint")
        if keri and onboarding_endpoint_override():
            logger.info(
                f"Overriding advertised onboarding endpoint {endpoint} "
                f"with {onboarding_endpoint_override()}"
            )
            endpoint = onboarding_endpoint_override()
        aid = onboarding_server_aid() if keri else data.get("aid")
        if not endpoint or (not aid and not keri):
            return {
                "success": False,
                "error": "Server does not offer onboarding.",
            }
        return {
            "success": True,
            "onboarding_endpoint": endpoint,
            "aid": aid,
            "token_endpoint": data.get("token_endpoint") or "",
        }
    except Exception as e:
        logger.error(f"Error discovering server metadata: {e}")
        return {"success": False, "error": str(e)}


async def submit_onboarding(
    base_url: str, url: str, body: bytes, content_type: str = "application/cesr"
) -> Dict[str, Any]:
    """
    POST the onboarding request ``body`` to ``url`` (the discovered endpoint): the raw
    CESR grant, or a JSON packet with ``content_type="application/json"``.

    202 means accepted and pending; 200 means a terminal decision (including
    rejection) was reached inline. Errors carry the server's correlation id.
    """
    if is_mock_mode():
        return mock_data.mock_submit_onboarding({})

    try:
        headers = {"Content-Type": content_type}
        _log_request("POST", url, headers, _loggable_body(content_type, body))
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(url, content=body, headers=headers)
        _log_response(response)

        if response.status_code in (200, 202):
            result = _decision_result(url, response)
            result["poll_url"] = _rebase_poll_url(base_url, result["poll_url"])
            return result
        return _error_result(response)
    except Exception as e:
        logger.error(f"Error submitting onboarding request: {e}")
        return {"success": False, "error": str(e)}


async def poll_onboarding(
    base_url: str, onboarding_id: str, poll_url: str = ""
) -> Dict[str, Any]:
    """
    GET the onboarding status -- ``poll_url`` (from Content-Location) if known,
    else {base_url}/udap/onboarding/{onboarding_id}.

    202 means the decision is still pending (non-terminal); 200 means a
    terminal decision has been made.
    """
    if is_mock_mode():
        return mock_data.mock_poll_onboarding(onboarding_id)

    if not poll_url and is_keri_discovery_url(base_url):
        return {
            "success": False,
            "error": "The server gave no status URL (Content-Location) to poll.",
        }

    poll_url = _rebase_poll_url(base_url, poll_url)
    url = poll_url or f"{base_url}/udap/onboarding/{onboarding_id}"
    try:
        _log_request("GET", url, {})
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.get(url)
        _log_response(response)

        if response.status_code in (200, 202):
            result = _decision_result(url, response)
            result["poll_url"] = _rebase_poll_url(base_url, result["poll_url"])
            return result
        return _error_result(response)
    except Exception as e:
        logger.error(f"Error polling onboarding status: {e}")
        return {"success": False, "error": str(e)}


async def register_dynamic_client(
    base_url: str, registration: Dict[str, Any]
) -> Dict[str, Any]:
    """
    POST {base_url}/register -- UDAP Dynamic Client Registration (ONBOARDING.md S4.4).

    ``registration`` is the body from presenting.build_dcr_request. 201 Created
    returns the client (also for a repeated registration); errors keep the
    server's RFC 7591 ``error`` code and ``correlation_id``.
    """
    if is_mock_mode():
        return mock_data.mock_register_dynamic_client(registration)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(f"{base_url}/register", json=registration)

        if response.status_code == 201:
            data = response.json()
            scopes = data.get("scope", data.get("scopes"))
            if isinstance(scopes, list):
                scopes = " ".join(scopes)
            return {
                "success": True,
                "client_id": data.get("client_id"),
                "scopes": scopes or "",
                "data": data,
            }
        return _error_result(response)
    except Exception as e:
        logger.error(f"Error registering dynamic client: {e}")
        return {"success": False, "error": str(e)}


async def request_access_token(
    token_endpoint: str, client_id: str, client_assertion: str, scope: str = ""
) -> Dict[str, Any]:
    """
    POST ``token_endpoint`` -- OAuth 2.0 ``client_credentials`` with an ACDC client
    assertion (``client_assertion`` from presenting.build_token_assertion).

    ``client_id`` is the value the server issued at DCR (never assumed to be
    the credential SAID). ``scope`` is omitted unless given, so the server applies
    its default scopes. Errors are ``{error, error_description}`` bodies.
    """
    if is_mock_mode():
        return mock_data.mock_request_access_token(client_id)

    form = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": client_assertion,
    }
    if scope:
        form["scope"] = scope

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(token_endpoint, data=form)

        if response.status_code != 200:
            return _error_result(response)
        data = response.json()
        if not isinstance(data, dict) or not data.get("access_token"):
            return {
                "success": False,
                "error": "The server returned no access token.",
                "status_code": response.status_code,
                "correlation_id": "",
            }
        return {
            "success": True,
            "access_token": data["access_token"],
            "token_type": data.get("token_type", "Bearer"),
            "expires_in": data.get("expires_in"),
            "scope": data.get("scope", ""),
            "data": data,
        }
    except Exception as e:
        logger.error(f"Error requesting access token: {e}")
        return {"success": False, "error": str(e)}
