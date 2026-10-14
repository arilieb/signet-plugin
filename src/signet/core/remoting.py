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

import base64
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
    is_json_format,
    is_keri_discovery_url,
    export_method,
    export_status_url_prefix,
    fhir_base_url_override,
    is_mock_mode,
    onboarding_endpoint_override,
    onboarding_server_aid,
    registration_endpoint_override,
    token_endpoint_override,
)
from .presenting import ASSERTION_TYPE

logger = help.ogler.getLogger(__name__)

_TIMEOUT = 30.0

# exportType requested in the $davinci-data-export POST body.
EXPORT_TYPE = "hl7.fhir.us.davinci-pdex#provider-snapshot"


def _loggable_body(content_type: str, body: bytes) -> str:
    """Request body for the log: a JSON packet with its (large) ``ipex_grant`` / ``software_statement`` elided."""
    if "json" in content_type:
        try:
            packet = json.loads(body)
            if isinstance(packet, dict):
                for key in ("ipex_grant", "software_statement"):
                    if key in packet:
                        packet[key] = f"<{len(packet[key])} chars omitted>"
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


def _log_response(response: httpx.Response, label: str = "Onboarding"):
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
        f"{label} response: {response.status_code} {response.reason_phrase} "
        f"url={response.url} headers={dict(response.headers)} body={body}{saved}"
    )
    summary = _html_error_summary(text) if saved else ""
    if summary:
        logger.info(f"{label} response error page:\n{summary}")


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
    details = [
        f"{label}: {data[key]}"
        for key, label in (
            ("failed_layer", "failed layer"),
            ("review_endpoint", "review"),
        )
        if data.get(key)
    ]
    if details:
        description = f"{description} ({'; '.join(details)})"
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
    ``registration_endpoint`` and ``token_endpoint`` are returned when advertised
    ("" otherwise): onboarding needs neither, DCR and Authenticate do. With
    SIGNET_ONBOARDING_FORMAT=json, SIGNET_REGISTRATION_ENDPOINT and
    SIGNET_TOKEN_ENDPOINT replace the advertised values.
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
        registration_endpoint = data.get("registration_endpoint") or ""
        token_endpoint = data.get("token_endpoint") or ""
        if is_json_format():
            if registration_endpoint_override():
                logger.info(
                    f"Overriding advertised registration endpoint {registration_endpoint} "
                    f"with {registration_endpoint_override()}"
                )
                registration_endpoint = registration_endpoint_override()
            if token_endpoint_override():
                logger.info(
                    f"Overriding advertised token endpoint {token_endpoint} "
                    f"with {token_endpoint_override()}"
                )
                token_endpoint = token_endpoint_override()
        return {
            "success": True,
            "onboarding_endpoint": endpoint,
            "aid": aid,
            "registration_endpoint": registration_endpoint,
            "token_endpoint": token_endpoint,
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
    base_url: str, registration: Dict[str, Any], url: str = ""
) -> Dict[str, Any]:
    """
    POST ``url`` (default {base_url}/register) -- UDAP Dynamic Client Registration
    (ONBOARDING.md S4.4).

    ``registration`` is the body from presenting.build_dcr_request. 201 Created
    returns the client (also for a repeated registration); with
    SIGNET_ONBOARDING_FORMAT=json a repeated registration is 200 and also succeeds.
    Errors keep the server's RFC 7591 ``error`` code and ``correlation_id``.
    """
    if is_mock_mode():
        return mock_data.mock_register_dynamic_client(registration)

    try:
        url = url or f"{base_url}/register"
        headers = {"Content-Type": "application/json"}
        _log_request(
            "POST",
            url,
            headers,
            _loggable_body("application/json", json.dumps(registration).encode()),
        )
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(url, json=registration)
        _log_response(response)

        if response.status_code in ((200, 201) if is_json_format() else (201,)):
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
        logger.info(
            f"Token response from {token_endpoint}: "
            f"{ {k: v for k, v in data.items() if k not in _SECRET_TOKEN_FIELDS} } "
            f"(headers={dict(response.headers)})"
        )
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


def fhir_base_url(connection) -> str:
    """
    FHIR base URL of ``connection``: SIGNET_FHIR_BASE_URL if set, else its ``base_url``
    with any ``/.well-known/...`` discovery path stripped.
    """
    override = fhir_base_url_override()
    base = override or connection.base_url.split("/.well-known/", 1)[0].rstrip("/")
    logger.info(
        f"FHIR base URL: {base} (connection base_url={connection.base_url!r}, "
        f"SIGNET_FHIR_BASE_URL={override!r})"
    )
    return base


def _fhir_headers(connection) -> Dict[str, str]:
    """Bearer authorization from the connection's stored token, and FHIR JSON Accept."""
    return {
        "Authorization": f"{connection.token_type or 'Bearer'} {connection.access_token}",
        "Accept": "application/fhir+json",
    }


_SECRET_TOKEN_FIELDS = ("access_token", "refresh_token")
_LOGGED_CLAIMS = ("iss", "aud", "sub", "client_id", "scope", "exp", "iat")


def _token_claims(token: str) -> str:
    """Issuer-side claims of a JWT access token, for the log; the token and signature are never included."""
    parts = token.split(".")
    if len(parts) != 3:
        return "opaque token"
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except ValueError:
        return "undecodable token"
    if not isinstance(claims, dict):
        return "undecodable token"
    return json.dumps({k: claims[k] for k in _LOGGED_CLAIMS if k in claims})


def _log_fhir_request(connection, method: str, url: str):
    """Log a FHIR request; the bearer token itself is never logged."""
    logger.info(
        f"FHIR request: {method} {url} "
        f"(token_type={connection.token_type!r}, token_scope={connection.token_scope!r}, "
        f"token_expires_at={connection.token_expires_at!r}, "
        f"token_claims={_token_claims(connection.access_token)})"
    )


def _fhir_error_result(response: httpx.Response, scope: str = "") -> Dict[str, Any]:
    """
    Failure dict from a 4xx/5xx FHIR response.

    An OperationOutcome's issue ``diagnostics`` / ``details.text`` become the message;
    anything else falls back to ``_error_result``. 401/403 name the granted ``scope``.
    """
    result = _error_result(response)
    result["error"] = f"{result['error']} ({response.request.method} {response.url})"
    try:
        data = response.json()
    except ValueError:
        data = None
    if isinstance(data, dict) and data.get("resourceType") == "OperationOutcome":
        messages = [
            issue.get("diagnostics") or (issue.get("details") or {}).get("text")
            for issue in data.get("issue") or []
            if isinstance(issue, dict)
        ]
        messages = [message for message in messages if message]
        if messages:
            result["error"] = "; ".join(messages)
    if response.status_code in (401, 403):
        granted = f" (granted scope: {scope})" if scope else ""
        result["error"] = (
            f"Access denied by the FHIR server ({response.status_code}){granted}: "
            f"{result['error']}"
        )
    return result


def _group_name(resource: Dict[str, Any]) -> str:
    """Display name of a Group: name, first identifier, code text, else its id."""
    identifiers = resource.get("identifier") or [{}]
    return (
        resource.get("name")
        or identifiers[0].get("value")
        or (resource.get("code") or {}).get("text")
        or resource.get("id", "")
    )


def _next_link(bundle: Dict[str, Any]) -> str:
    for link in bundle.get("link") or []:
        if link.get("relation") == "next" and link.get("url"):
            return link["url"]
    return ""


async def get_groups(connection) -> Dict[str, Any]:
    """
    The Groups the connection may export, as ``{"success": True, "groups": [{"id", "name"}]}``.

    For now a static list (``mock_data.STATIC_GROUP_IDS``) outside mock mode; the partner's
    ``GET /Group`` is not used until it responds reliably (see ``fetch_groups``).
    """
    if is_mock_mode():
        return {"success": True, **mock_data.fhir_groups(connection.connection_id)}
    return {
        "success": True,
        "groups": [
            {"id": group_id, "name": group_id}
            for group_id in mock_data.STATIC_GROUP_IDS
        ],
    }


async def fetch_groups(connection) -> Dict[str, Any]:
    """
    GET {fhir_base}/Group with the connection's bearer token, following Bundle
    ``next`` links -- the Groups the connection may export, as
    ``{"success": True, "groups": [{"id", "name"}]}``.

    The caller authenticates first (``ensure_authenticated``) so the connection
    carries a fresh token.
    """
    try:
        url = f"{fhir_base_url(connection)}/Group"
        groups: list[Dict[str, str]] = []
        seen_urls: set = set()
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            while url and url not in seen_urls:
                seen_urls.add(url)
                _log_fhir_request(connection, "GET", url)
                response = await client.get(url, headers=_fhir_headers(connection))
                _log_response(response, "FHIR")
                if response.status_code != 200:
                    return _fhir_error_result(response, connection.token_scope)
                bundle = response.json()
                for entry in bundle.get("entry") or []:
                    resource = entry.get("resource") or {}
                    if resource.get("id"):
                        groups.append(
                            {"id": resource["id"], "name": _group_name(resource)}
                        )
                url = urljoin(url, _next_link(bundle)) if _next_link(bundle) else ""
        return {"success": True, "groups": groups}
    except Exception as e:
        logger.error(f"Error listing FHIR Groups: {e}")
        return {"success": False, "error": str(e)}


async def davinci_data_export(connection, group_id) -> Dict[str, Any]:
    """
    Kick off ``Group/{group_id}/$davinci-data-export`` asynchronously (``Prefer:
    respond-async``). 202 returns the ``Content-Location`` status URL to poll,
    resolved against the FHIR base (SIGNET_EXPORT_STATUS_URL_PREFIX + the task id replaces a
    status URL the server advertises wrongly); SIGNET_EXPORT_METHOD picks GET or POST (the ATR spec allows both).
    """
    if is_mock_mode():
        return mock_data.mock_davinci_data_export()

    try:
        base = fhir_base_url(connection)
        url = f"{base}/Group/{group_id}/$davinci-data-export/"
        headers = {**_fhir_headers(connection), "Prefer": "respond-async"}
        method = export_method()
        _log_fhir_request(connection, method, url)
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            if method == "POST":
                body = {"exportType": EXPORT_TYPE}
                logger.info(f"FHIR request body: {json.dumps(body)}")
                response = await client.post(
                    url,
                    headers={**headers, "Content-Type": "application/fhir+json"},
                    json=body,
                )
            else:
                response = await client.get(url, headers=headers)
        _log_response(response, "FHIR")

        if response.status_code != 202:
            if response.status_code < 300:
                return {
                    "success": False,
                    "error": f"Unexpected export response: {response.status_code}",
                }
            return _fhir_error_result(response, connection.token_scope)
        location = response.headers.get("Content-Location", "")
        if not location:
            return {
                "success": False,
                "error": "The server gave no status URL (Content-Location) to poll.",
            }
        status_url = urljoin(f"{base}/", location)
        prefix = export_status_url_prefix()
        if prefix:
            task_id = urlsplit(status_url).path.rstrip("/").rsplit("/", 1)[-1]
            logger.info(
                f"Overriding export status URL {status_url} with {prefix}{task_id}"
            )
            status_url = f"{prefix}{task_id}"
        return {"success": True, "status_url": status_url}
    except Exception as e:
        logger.error(f"Error starting data export: {e}")
        return {"success": False, "error": str(e)}


_TASK_PENDING = {"draft", "requested", "received", "accepted", "ready", "in-progress"}
_TASK_FAILED = {"failed", "cancelled", "rejected", "entered-in-error"}


def _output_files(data: Dict[str, Any], status_url: str) -> list[Dict[str, str]]:
    """File ``{type, url}`` entries of a bulk manifest or a completed Task's ``output``."""
    files = []
    for item in data.get("output") or []:
        kind = item.get("type")
        if isinstance(kind, dict):  # Task.output: type is a CodeableConcept
            codings = kind.get("coding") or [{}]
            kind = kind.get("text") or codings[0].get("code") or ""
        url = (
            item.get("url")
            or item.get("valueUri")
            or item.get("valueUrl")
            or (item.get("valueReference") or {}).get("reference")
        )
        if url:
            files.append({"type": kind or "", "url": urljoin(status_url, url)})
    return files


async def poll_export_status(connection, status_url: str) -> Dict[str, Any]:
    """
    GET the export ``status_url``. 202 (or an in-progress Task) is
    ``{"state": "pending", "retry_after"}``; 200 is ``{"state": "complete",
    "files": [{"type", "url"}]}``, parsed from the manifest or Task output.
    """
    if is_mock_mode():
        return mock_data.mock_poll_export_status()

    try:
        _log_fhir_request(connection, "GET", status_url)
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.get(status_url, headers=_fhir_headers(connection))
        _log_response(response, "FHIR")

        retry_after = response.headers.get("Retry-After", "")
        if response.status_code == 202:
            return {"success": True, "state": "pending", "retry_after": retry_after}
        if response.status_code != 200:
            return _fhir_error_result(response, connection.token_scope)

        data = response.json()
        if data.get("resourceType") == "Task":
            status = data.get("status", "")
            if status in _TASK_PENDING:
                return {"success": True, "state": "pending", "retry_after": retry_after}
            if status in _TASK_FAILED:
                return {"success": False, "error": f"Data export {status}."}
        return {
            "success": True,
            "state": "complete",
            "files": _output_files(data, status_url),
        }
    except Exception as e:
        logger.error(f"Error polling export status: {e}")
        return {"success": False, "error": str(e)}


async def download_export_file(
    connection, url: str, dest_dir: Path, filename: str = ""
) -> Dict[str, Any]:
    """Stream the export file at ``url`` into ``dest_dir`` -> ``{"path", "bytes"}``."""
    name = Path(filename or urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]).name
    name = name or "export.ndjson"
    dest_dir = Path(dest_dir)
    if is_mock_mode():
        return mock_data.mock_download_export_file(dest_dir, name)

    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        path = dest_dir / name
        _log_fhir_request(connection, "GET", url)
        headers = {**_fhir_headers(connection), "Accept": "application/fhir+ndjson"}
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code != 200:
                    await response.aread()
                    _log_response(response, "FHIR")
                    return _fhir_error_result(response, connection.token_scope)
                size = 0
                with path.open("wb") as out:
                    async for chunk in response.aiter_bytes():
                        out.write(chunk)
                        size += len(chunk)
        return {"success": True, "path": str(path), "bytes": size}
    except Exception as e:
        logger.error(f"Error downloading export file: {e}")
        return {"success": False, "error": str(e)}
