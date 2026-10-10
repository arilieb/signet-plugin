# -*- encoding: utf-8 -*-
"""
signet.connections.refresh module

Shared onboarding status update used by the add dialog, the connections list
and the view dialog, so every path persists the same richer server state.
"""

from typing import Any

from keri.help import helping

from ..core import remoting
from ..db.basing import SignetConnection


def normalize_status(status: str) -> str:
    """Map onboarding-doc status strings onto the 4-bucket SignetConnection.status."""
    if status == "approved":
        return "approved"
    if status == "rejected":
        return "rejected"
    return "needs_approval"


def apply_result(connection: SignetConnection, result: dict[str, Any]) -> None:
    """Copy a successful submit/poll result onto the connection."""
    connection.last_checked_at = helping.nowIso8601()
    connection.last_error = ""
    connection.status = normalize_status(result.get("status", ""))
    connection.onboarding_id = result.get("onboarding_id") or connection.onboarding_id
    connection.correlation_id = (
        result.get("correlation_id") or connection.correlation_id
    )
    connection.poll_url = result.get("poll_url") or connection.poll_url
    connection.decision_due = result.get("decision_due") or connection.decision_due
    connection.retry_after = result.get("retry_after") or ""
    connection.purpose_status = (
        result.get("purpose_status") or connection.purpose_status
    )
    connection.decision_provenance = (
        result.get("decision_provenance") or connection.decision_provenance
    )


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
