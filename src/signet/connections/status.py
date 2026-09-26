# -*- encoding: utf-8 -*-
"""
signet.connections.status module

Shared status -> display mapping used by the connections list, view dialog,
and DCR gate so all three stay in sync on colors/labels/icons.
"""

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
    "Delete": ":/assets/material-icons/delete.svg",
}
