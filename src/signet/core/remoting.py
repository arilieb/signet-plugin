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

from typing import Any, Dict
from urllib.parse import urljoin

import httpx
from keri import help

from . import mock_data
from .configing import is_mock_mode

logger = help.ogler.getLogger(__name__)

_TIMEOUT = 30.0


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
    correlation_id = data.get("correlation_id", "")
    if correlation_id:
        description = f"{description} (correlation id: {correlation_id})"
    return {
        "success": False,
        "error": description,
        "status_code": response.status_code,
        "correlation_id": correlation_id,
    }


def _decision_result(base_url: str, response: httpx.Response) -> Dict[str, Any]:
    """Success dict from a 202 (pending) or 200 (terminal) onboarding response."""
    data = response.json()
    location = response.headers.get("Content-Location", "")
    purposes = data.get("purposes") or []
    return {
        "success": True,
        "terminal": response.status_code == 200,
        "onboarding_id": data.get("onboarding_id"),
        "correlation_id": data.get("correlation_id", ""),
        "status": data.get("status", "pending-verification"),
        "purpose_status": purposes[0].get("status", "") if purposes else "",
        "decision_provenance": data.get("decision_provenance") or {},
        "poll_url": urljoin(f"{base_url}/", location) if location else "",
        "retry_after": response.headers.get("Retry-After", ""),
        "data": data,
    }


async def discover_server(base_url: str) -> Dict[str, Any]:
    """
    GET {base_url}/.well-known/udap -- find the onboarding endpoint and server AID.

    Fails if the server does not advertise onboarding (legacy mode).
    """
    if is_mock_mode():
        return mock_data.mock_discover_server(base_url)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.get(f"{base_url}/.well-known/udap")
        if response.status_code != 200:
            return {"success": False, "error": f"API error: {response.status_code}"}
        data = response.json()
        endpoint = data.get("onboarding_endpoint")
        aid = data.get("aid")
        if not endpoint or not aid:
            return {
                "success": False,
                "error": "Server does not offer onboarding.",
            }
        return {"success": True, "onboarding_endpoint": endpoint, "aid": aid}
    except Exception as e:
        logger.error(f"Error discovering server metadata: {e}")
        return {"success": False, "error": str(e)}


async def submit_onboarding(
    base_url: str, url: str, body: bytes, headers: Dict[str, str]
) -> Dict[str, Any]:
    """
    POST the signed onboarding request to ``url`` (the discovered endpoint).

    202 means accepted and pending; 200 means a terminal decision (including
    rejection) was reached inline. Errors carry the server's correlation id.
    """
    if is_mock_mode():
        return mock_data.mock_submit_onboarding({})

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(url, content=body, headers=headers)

        if response.status_code in (200, 202):
            return _decision_result(base_url, response)
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

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.get(
                poll_url or f"{base_url}/udap/onboarding/{onboarding_id}"
            )

        if response.status_code in (200, 202):
            return _decision_result(base_url, response)
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
