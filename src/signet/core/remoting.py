# -*- encoding: utf-8 -*-
"""
signet.core.remoting module

Async facade over acdc-auth-client for Onyx's UDAP vLEI onboarding flow: discover the
server, submit an onboarding request, poll for an approval/rejection decision, perform
Dynamic Client Registration once approved, and list FHIR Groups. The protocol lives in
the library, which is synchronous: each call runs in a worker thread so the Qt event
loop is never blocked. In the DEVELOPMENT environment each function short-circuits to
a canned mock_data response before the library is reached -- switching to real Onyx
servers later is a zero-UI-change flip once LOCKSMITH_ENVIRONMENT isn't 'development'.

Every function returns the same {'success': bool, ...} / {'success': False,
'error': ...} dict shape used throughout this codebase (see
castellan/core/remoting.py), so callers can use the same result['success']
check idiom. The library raises instead: its errors become that dict here, keeping
``status_code`` (what the 401/403 re-authentication keys on) and ``correlation_id``.

The authenticated FHIR calls (export, download) are not wrapped one by one: the
UI drives them through ``fhir_client`` and ``acdc_auth_client.core.flows``.
"""

import asyncio
from pathlib import Path
from typing import Any, Callable, Dict, List

from acdc_auth_client.core.dcr_client import DynamicRegistrationClient
from acdc_auth_client.core.fhir_client import FhirClient
from acdc_auth_client.core.metadata_client import MetadataDiscoveryClient
from acdc_auth_client.core.onboarding_client import OnboardingClient
from acdc_auth_client.models.errors import ACDCOAuthError
from acdc_auth_client.models.fhir import (
    STATE_COMPLETE,
    DownloadedFile,
    ExportFile,
    ExportKickoff,
    ExportStatus,
)
from acdc_auth_client.models.onboarding import (
    DynamicClient,
    OnboardingDecision,
    ServerDiscovery,
)
from acdc_auth_client.utils.http import exception_message
from keri import help

from . import mock_data
from .configing import client_options, is_mock_mode
from .presenting import connection_info

logger = help.ogler.getLogger(__name__)


def _failure(exc: ACDCOAuthError) -> Dict[str, Any]:
    """Failure dict of a library error: its message (which already carries the server's
    description, failed layer and correlation id) and, for an HTTP error, its status."""
    result: Dict[str, Any] = {"success": False, "error": exc.message}
    status_code = getattr(exc, "status_code", None)
    if status_code is not None:
        result["status_code"] = status_code
        result["correlation_id"] = getattr(exc, "correlation_id", "")
    return result


async def _call(
    action: str, convert: Callable[[Any], Dict[str, Any]], func: Callable, *args
) -> Dict[str, Any]:
    """``convert(func(*args))`` with ``func`` run in a thread; any error becomes a failure dict."""
    try:
        value = await asyncio.to_thread(func, *args)
    except ACDCOAuthError as exc:
        logger.error(f"Error {action}: {exc.message}")
        return _failure(exc)
    except Exception as exc:
        logger.error(f"Error {action}: {exception_message(exc)}")
        return {"success": False, "error": exception_message(exc)}
    return convert(value)


def _invoke(client_class, method: str, *args):
    """``client_class(options=...).method(*args)``, closing the client's session."""
    with client_class(options=client_options()) as client:
        return getattr(client, method)(*args)


def _discover(base_url: str) -> ServerDiscovery:
    options = client_options()
    with MetadataDiscoveryClient(timeout=options.timeout) as client:
        return client.discover_server(base_url, options)


def _discovery_dict(discovery: ServerDiscovery) -> Dict[str, Any]:
    return {"success": True, **discovery.to_dict()}


def _decision_dict(decision: OnboardingDecision) -> Dict[str, Any]:
    return {
        "success": True,
        "terminal": decision.terminal,
        "onboarding_id": decision.onboarding_id,
        "decision_due": decision.decision_due,
        "correlation_id": decision.correlation_id,
        "status": decision.status,
        "purpose_status": decision.purpose_status,
        "decision_provenance": decision.decision_provenance,
        "poll_url": decision.poll_url,
        "retry_after": decision.retry_after,
        "data": decision.data,
    }


def _client_dict(client: DynamicClient) -> Dict[str, Any]:
    return {
        "success": True,
        "client_id": client.client_id,
        "scopes": client.scopes,
        "data": client.data,
    }


async def discover_server(base_url: str) -> Dict[str, Any]:
    """
    GET {base_url}/.well-known/udap -- find the onboarding endpoint and server AID.

    The overrides (SIGNET_ONBOARDING_ENDPOINT, SIGNET_ONBOARDING_SERVER_AID, and in the
    json format SIGNET_REGISTRATION_ENDPOINT / SIGNET_TOKEN_ENDPOINT) are applied by the
    library; see ``MetadataDiscoveryClient.discover_server``. Success carries
    ``onboarding_endpoint``, ``aid``, ``registration_endpoint`` and ``token_endpoint``
    (the last two "" when not advertised).
    """
    if is_mock_mode():
        return mock_data.mock_discover_server(base_url)
    return await _call(
        "discovering server metadata", _discovery_dict, _discover, base_url
    )


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
    return await _call(
        "submitting onboarding request",
        _decision_dict,
        _invoke,
        OnboardingClient,
        "submit",
        base_url,
        url,
        body,
        content_type,
    )


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
    return await _call(
        "polling onboarding status",
        _decision_dict,
        _invoke,
        OnboardingClient,
        "poll",
        base_url,
        onboarding_id,
        poll_url,
    )


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
    return await _call(
        "registering dynamic client",
        _client_dict,
        _invoke,
        DynamicRegistrationClient,
        "register",
        base_url,
        registration,
        url,
    )


async def get_groups(connection_id: str) -> Dict[str, Any]:
    """
    The Groups the connection ``connection_id`` may export, as ``{"success": True, "groups": [{"id", "name"}]}``.

    For now a static list (``mock_data.STATIC_GROUP_IDS``) outside mock mode; the partner's
    ``GET /Group`` is not used until it responds reliably (see ``fetch_groups``).
    """
    if is_mock_mode():
        return {"success": True, **mock_data.fhir_groups(connection_id)}
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

    The caller authenticates first so the connection carries a fresh token.
    """
    return await _call(
        "listing FHIR Groups",
        lambda groups: {
            "success": True,
            "groups": [group.to_dict() for group in groups],
        },
        _invoke,
        FhirClient,
        "list_groups",
        connection_info(connection),
    )


class _MockFhirClient:
    """Stands in for ``FhirClient`` in mock mode: the canned mock_data export."""

    def close(self) -> None:
        pass

    def kickoff_export(self, connection, group_id: str) -> ExportKickoff:
        return ExportKickoff(
            status_url=mock_data.mock_davinci_data_export()["status_url"]
        )

    def poll_export_status(self, connection, status_url: str) -> ExportStatus:
        status = mock_data.mock_poll_export_status()
        files: List[ExportFile] = [ExportFile(**file) for file in status["files"]]
        return ExportStatus(state=STATE_COMPLETE, files=files)

    def download_file(
        self, connection, url: str, dest_dir: Path, filename: str = ""
    ) -> DownloadedFile:
        name = Path(filename or url.rstrip("/").rsplit("/", 1)[-1]).name
        result = mock_data.mock_download_export_file(
            Path(dest_dir), name or "export.ndjson"
        )
        return DownloadedFile(path=result["path"], bytes=result["bytes"])


def fhir_client() -> FhirClient | _MockFhirClient:
    """
    The client of the FHIR calls that need a token (export kickoff, status polls,
    download): the library's ``FhirClient`` configured from the environment, or in
    mock mode a stand-in answering from mock_data. Its calls block: run them in a thread.
    """
    if is_mock_mode():
        return _MockFhirClient()
    return FhirClient(options=client_options())
