# -*- encoding: utf-8 -*-
"""
signet.connections.status module

Shared status -> display mapping used by the connections list, view dialog,
and DCR gate so all three stay in sync on colors/labels/icons.
"""

from datetime import datetime, timezone

from locksmith.ui import colors

STATUS_DISPLAY = {
    "needs_approval": ("Needs Approval", colors.DANGER),
    "approved": ("Approved", colors.WARNING_YELLOW),
    "rejected": ("Rejected", colors.DANGER),
    "registered": ("Registered", colors.SUCCESS_INDICATOR),
}

ROW_ACTION_ICONS = {
    "Refresh": ":/assets/material-icons/refresh.svg",
    "Register": ":/assets/material-icons/shield_lock.svg",
    "Authenticate": ":/assets/material-icons/verified.svg",
    "Delete": ":/assets/material-icons/delete.svg",
}


def primary_row_action(status: str, has_client_id: bool) -> list[str]:
    """Status-dependent row actions, before the always-present View/Delete."""
    if status == "needs_approval":
        return ["Refresh"]
    if status == "approved":
        return ["Register"]
    if status == "registered" and has_client_id:
        return ["Authenticate"]
    return []


def format_expiry(iso: str) -> str:
    """An ISO-8601 token expiry rendered in local time, e.g. ``2026-10-08 14:30``."""
    expires = datetime.fromisoformat(iso)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires.astimezone().strftime("%Y-%m-%d %H:%M")
