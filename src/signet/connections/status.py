# -*- encoding: utf-8 -*-
"""
signet.connections.status module

Shared status -> display mapping used by the connections list, view dialog,
and DCR gate so all three stay in sync on colors/labels/icons.
"""

from locksmith.ui import colors

# Collapses the onboarding design doc's 7-state machine into the 3 buckets
# the spec calls out, plus a 4th terminal "rejected" bucket the doc requires
# but the spec didn't explicitly design for -- styled like needs_approval
# but with no actions available, since it's terminal.
STATUS_DISPLAY = {
    "needs_approval": ("Needs Approval", colors.DANGER),
    "approved": ("Approved", colors.WARNING_YELLOW),
    "rejected": ("Rejected", colors.DANGER),
    "registered": ("Registered", colors.SUCCESS_INDICATOR),
}

ROW_ACTION_ICONS = {
    "Refresh": ":/assets/material-icons/refresh.svg",
    "Register": ":/assets/material-icons/shield_lock.svg",
}
