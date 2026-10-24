# -*- encoding: utf-8 -*-
"""
signet.connections.refresh module

Shared onboarding status update used by the add dialog, the connections list
and the view dialog, so every path persists the same richer server state.
"""

from typing import Any

from acdc_auth_client.core.flows import apply_onboarding_decision, normalize_status
from acdc_auth_client.models.onboarding import OnboardingDecision
from keri.help import helping

from ..core import remoting
from ..db.basing import SignetConnection

__all__ = ["apply_result", "normalize_status", "refresh_connection"]


def apply_result(connection: SignetConnection, result: dict[str, Any]) -> None:
    """Copy a successful submit/poll result (``remoting``'s dict) onto the connection."""
    decision = OnboardingDecision(
        terminal=bool(result.get("terminal")),
        onboarding_id=result.get("onboarding_id"),
        status=result.get("status", ""),
        decision_due=result.get("decision_due") or "",
        correlation_id=result.get("correlation_id") or "",
        purpose_status=result.get("purpose_status") or "",
        decision_provenance=result.get("decision_provenance") or {},
        poll_url=result.get("poll_url") or "",
        retry_after=result.get("retry_after") or "",
    )
    apply_onboarding_decision(connection, decision)


async def refresh_connection(db, connection: SignetConnection) -> dict[str, Any]:
    """
    Poll the connection's onboarding status and persist the outcome.

    Returns the poll result. On failure the error is stored in last_error
    (status is left untouched) and the result has success False.
    """
    result = await remoting.poll_onboarding(
        connection.base_url, connection.onboarding_id, connection.poll_url
    )
    if result.get("success"):
        apply_result(connection, result)
    else:
        connection.last_checked_at = helping.nowIso8601()
        connection.last_error = result.get("error", "")
    db.signet_connections.pin(keys=(connection.connection_id,), val=connection)
    return result
