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

import httpx
from keri import help

from . import mock_data
from .configing import is_mock_mode

logger = help.ogler.getLogger(__name__)

_TIMEOUT = 30.0


async def submit_onboarding(
    base_url: str, connection_packet: Dict[str, Any]
) -> Dict[str, Any]:
    """
    POST {base_url}/udap/onboarding -- submit a new onboarding request.

    Expects 202 Accepted with a Content-Location/Retry-After header and a
    per-purpose status body.
    """
    if is_mock_mode():
        return mock_data.mock_submit_onboarding(connection_packet)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(
                f"{base_url}/udap/onboarding", json=connection_packet
            )

        if response.status_code == 202:
            data = response.json()
            return {
                "success": True,
                "onboarding_id": data.get("onboarding_id"),
                "status": data.get("status", "pending-verification"),
                "retry_after": response.headers.get("Retry-After"),
            }
        else:
            return {"success": False, "error": f"API error: {response.status_code}"}
    except Exception as e:
        logger.error(f"Error submitting onboarding request: {e}")
        return {"success": False, "error": str(e)}


async def poll_onboarding(base_url: str, onboarding_id: str) -> Dict[str, Any]:
    """
    GET {base_url}/udap/onboarding/{onboarding_id} -- poll the onboarding decision.

    202 means the decision is still pending (non-terminal); 200 means a
    terminal decision has been made (approved and/or rejected, per purpose).
    """
    if is_mock_mode():
        return mock_data.mock_poll_onboarding(onboarding_id)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.get(f"{base_url}/udap/onboarding/{onboarding_id}")

        if response.status_code == 202:
            data = response.json()
            return {
                "success": True,
                "terminal": False,
                "status": data.get("status", "in-review"),
            }
        elif response.status_code == 200:
            data = response.json()
            return {
                "success": True,
                "terminal": True,
                "status": data.get("status", "approved"),
                "data": data,
            }
        else:
            return {"success": False, "error": f"API error: {response.status_code}"}
    except Exception as e:
        logger.error(f"Error polling onboarding status: {e}")
        return {"success": False, "error": str(e)}


async def register_dynamic_client(
    base_url: str, approved_purpose_grant: Dict[str, Any]
) -> Dict[str, Any]:
    """
    POST {base_url}/register -- standard UDAP Dynamic Client Registration.

    Returns client_id + scopes on 201 Created, per the sibling
    "UDAP vLEI_ACDC Dynamic Client Registration" doc's shape.
    """
    if is_mock_mode():
        return mock_data.mock_register_dynamic_client(approved_purpose_grant)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(
                f"{base_url}/register", json=approved_purpose_grant
            )

        if response.status_code == 201:
            data = response.json()
            return {
                "success": True,
                "client_id": data.get("client_id"),
                "scopes": data.get("scope", data.get("scopes")),
            }
        else:
            return {"success": False, "error": f"API error: {response.status_code}"}
    except Exception as e:
        logger.error(f"Error registering dynamic client: {e}")
        return {"success": False, "error": str(e)}
