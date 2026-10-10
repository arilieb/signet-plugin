# -*- encoding: utf-8 -*-
"""
signet.core.mock_data module

Canned responses for the UDAP vLEI onboarding + Dynamic Client Registration
flow, and seed connections used to demo the Connections list before Onyx's
servers exist. Only active when signet.core.configing.is_mock_mode() is True.
"""

import uuid
from typing import Any, Dict
from urllib.parse import urlparse

from ..db.basing import SignetConnection
from . import configing

ONYX_BASE_URL = "https://onyx.example.com"
CAMBIA_BASE_URL = "https://cambia.example.com"
MERIDIAN_BASE_URL = "https://meridian.example.com"

# Fixture "partners we've already discovered" shown in AddConnectionDialog's
# dropdown. seed_connections() below pre-populates SignetBaser with the
# first two at first on_vault_opened, leaving Meridian as the "remaining
# seed entry" the Add Connection flow is demoed against.
DISCOVERABLE_CONNECTIONS: list[Dict[str, Any]] = [
    {
        "connection_id": "onyx-demo",
        "display_name": "Onyx",
        "logo_icon_path": ":/assets/material-icons/identity_platform.svg",
        "base_url": ONYX_BASE_URL,
        "purpose": "treatment",
    },
    {
        "connection_id": "cambia-demo",
        "display_name": "Cambia",
        "logo_icon_path": ":/assets/material-icons/hive.svg",
        "base_url": CAMBIA_BASE_URL,
        "purpose": "payment",
    },
    {
        "connection_id": "meridian-demo",
        "display_name": "Meridian Health",
        "logo_icon_path": ":/assets/material-icons/hive.svg",
        "base_url": MERIDIAN_BASE_URL,
        "purpose": "operations",
    },
]

# Tracks onboarding_ids that have already been polled once, so a freshly
# submitted connection's immediate follow-up poll (see connections/add.py)
# comes back non-terminal, and only turns terminal on the *next* poll (a
# row-action/view-dialog "Refresh") -- letting the list show it red first,
# per the design doc's async approval flow.
_POLLED_ONCE: set = set()


def mock_discover_server(base_url: str) -> Dict[str, Any]:
    """Canned /.well-known/udap (or full .well-known/keri URL) onboarding discovery."""
    if configing.is_keri_discovery_url(base_url):
        origin = base_url.split("/.well-known/", 1)[0]
        return {
            "success": True,
            "onboarding_endpoint": f"{origin}/udap/onboarding",
            "aid": configing.onboarding_server_aid()
            or "EMockServerAid0000000000000000000000000000000",
            "token_endpoint": f"{origin}/token",
        }
    return {
        "success": True,
        "onboarding_endpoint": f"{base_url}/udap/onboarding",
        "aid": "EMockServerAid0000000000000000000000000000000",
        "token_endpoint": f"{base_url}/token",
    }


def mock_submit_onboarding(_packet: Dict[str, Any]) -> Dict[str, Any]:
    """Canned 202 Accepted response for POST /udap/onboarding."""
    return {
        "success": True,
        "onboarding_id": f"onboarding-{uuid.uuid4().hex[:12]}",
        "status": "pending-verification",
        "retry_after": "30",
    }


def mock_poll_onboarding(onboarding_id: str) -> Dict[str, Any]:
    """
    Canned poll response for GET /udap/onboarding/{id}.

    Real polling is state-dependent server-side; in mock mode the first poll
    for a given onboarding_id comes back non-terminal, and every poll after
    that comes back an approved terminal decision, so the demo flow is
    "submit -> shows red -> Refresh -> turns orange".
    """
    if onboarding_id in _POLLED_ONCE:
        return {
            "success": True,
            "terminal": True,
            "status": "approved",
            "data": {"onboarding_id": onboarding_id, "status": "approved"},
        }

    _POLLED_ONCE.add(onboarding_id)
    return {
        "success": True,
        "terminal": False,
        "status": "pending-verification",
        "data": {"onboarding_id": onboarding_id, "status": "pending-verification"},
    }


def mock_register_dynamic_client(
    approved_purpose_grant: Dict[str, Any],
) -> Dict[str, Any]:
    """Canned 201 Created response for POST /register (UDAP DCR)."""
    return {
        "success": True,
        "client_id": f"client-{uuid.uuid4().hex[:12]}",
        "scopes": approved_purpose_grant.get("scope", "system/Patient.read"),
    }


def mock_request_access_token(client_id: str) -> Dict[str, Any]:
    """Canned 200 response for POST /token (client_credentials)."""
    return {
        "success": True,
        "access_token": uuid.uuid4().hex,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read",
    }


def discoverable_connections() -> list[Dict[str, Any]]:
    """
    Partners offered by AddConnectionDialog: fixtures in mock mode, the local Echelon
    in live dev, else the partner named by SIGNET_PARTNER_URL (if set).
    """
    if configing.is_live_dev():
        return [
            {
                "connection_id": "local-echelon",
                "display_name": "Local Echelon",
                "logo_icon_path": ":/assets/material-icons/identity_platform.svg",
                "base_url": configing.partner_url(),
                "purpose": "TREAT",
            }
        ]
    if configing.is_mock_mode():
        return DISCOVERABLE_CONNECTIONS
    if configing.is_partner_url_set():
        url = configing.partner_url()
        host = urlparse(url).hostname or url
        return [
            {
                "connection_id": host.replace(".", "-"),
                "display_name": host,
                "logo_icon_path": ":/assets/material-icons/identity_platform.svg",
                "base_url": url,
                "purpose": "TREAT",
            }
        ]
    return []


def seed_connections() -> list[SignetConnection]:
    """
    Dummy Onyx (needs_approval) and Cambia (approved) connections used to
    pre-populate SignetBaser on first on_vault_opened, so the Connections
    list/view/DCR-gate flow is immediately exercisable in dev. Meridian is
    left out of the seed so it's available as a fresh pick in
    AddConnectionDialog.
    """
    onyx, cambia, _meridian = DISCOVERABLE_CONNECTIONS
    connections = [
        SignetConnection(
            connection_id=onyx["connection_id"],
            display_name=onyx["display_name"],
            logo_icon_path=onyx["logo_icon_path"],
            base_url=onyx["base_url"],
            status="needs_approval",
            onboarding_id="onboarding-onyx-demo",
            purpose=onyx["purpose"],
        ),
        SignetConnection(
            connection_id=cambia["connection_id"],
            display_name=cambia["display_name"],
            logo_icon_path=cambia["logo_icon_path"],
            base_url=cambia["base_url"],
            status="approved",
            onboarding_id="onboarding-cambia-demo",
            purpose=cambia["purpose"],
        ),
    ]

    # The seeded connections already carry the status a real onboarding_id
    # would only reach after one poll -- mark them pre-polled so the first
    # UI-triggered refresh resolves immediately instead of bouncing back to
    # "pending" per the _POLLED_ONCE contract above.
    _POLLED_ONCE.update(connection.onboarding_id for connection in connections)

    return connections
