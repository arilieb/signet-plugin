# -*- encoding: utf-8 -*-
"""
signet.core.mock_data module

Canned responses for the UDAP vLEI onboarding + Dynamic Client Registration
flow, and seed connections used to demo the Connections list before Onyx's
servers exist. Only active when signet.core.configing.is_mock_mode() is True.
"""

import uuid
from typing import Any, Dict

from ..db.basing import SignetConnection

ONYX_BASE_URL = "https://onyx.example.com"
CAMBIA_BASE_URL = "https://cambia.example.com"


def mock_submit_onboarding(connection_packet: Dict[str, Any]) -> Dict[str, Any]:
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

    Real polling is state-dependent server-side; in mock mode we return an
    immediate terminal approval so the DCR flow is exercisable without
    waiting on a real decision.
    """
    return {
        "success": True,
        "terminal": True,
        "status": "approved",
        "data": {"onboarding_id": onboarding_id, "status": "approved"},
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


def seed_connections() -> list[SignetConnection]:
    """
    Dummy Onyx (needs_approval) and Cambia (approved) connections used to
    pre-populate SignetBaser on first on_vault_opened, so the Connections
    list/view/DCR-gate flow is immediately exercisable in dev.
    """
    return [
        SignetConnection(
            connection_id="onyx-demo",
            display_name="Onyx",
            logo_icon_path=":/assets/material-icons/identity_platform.svg",
            base_url=ONYX_BASE_URL,
            status="needs_approval",
            onboarding_id="onboarding-onyx-demo",
            purpose="treatment",
        ),
        SignetConnection(
            connection_id="cambia-demo",
            display_name="Cambia",
            logo_icon_path=":/assets/material-icons/hive.svg",
            base_url=CAMBIA_BASE_URL,
            status="approved",
            onboarding_id="onboarding-cambia-demo",
            purpose="payment",
        ),
    ]
