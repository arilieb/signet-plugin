# -*- encoding: utf-8 -*-
"""
signet.connections.list module

Connections list page -- shows the vault's UDAP vLEI onboarding connections
(Onyx, and other partners), their approval status, and the row action
("Refresh" or "Proceed with Dynamic Client Registration") available for
each status. Refresh is row-action-only: PaginatedTableWidget has no
built-in table-wide refresh button.
"""

from typing import Any

import qasync
from keri import help
from keri.help import helping

from locksmith.ui import colors
from locksmith.ui.toolkit.tables import PaginatedTableWidget
from locksmith.ui.toolkit.widgets.page import LocksmithFormPage, guarded

from ..core import remoting

logger = help.ogler.getLogger(__name__)

# Collapses the onboarding design doc's 7-state machine into the 3 buckets
# the spec calls out, plus a 4th terminal "rejected" bucket the doc requires
# but the spec didn't explicitly design for -- styled like needs_approval
# but with no actions available, since it's terminal.
_STATUS_DISPLAY = {
    "needs_approval": ("Needs Approval", colors.DANGER),
    "approved": ("Approved", colors.WARNING_YELLOW),
    "rejected": ("Rejected", colors.DANGER),
    "registered": ("Registered", colors.SUCCESS_INDICATOR),
}

_ROW_ACTION_ICONS = {
    "Refresh": ":/assets/material-icons/refresh.svg",
    "Proceed with Dynamic Client Registration": ":/assets/material-icons/shield_lock.svg",
}


class ConnectionsListPage(LocksmithFormPage):
    """Paginated list of signet connections and their onboarding status."""

    def __init__(self, app, parent=None):
        self.app = app
        self._parent = parent

        super().__init__(
            title="Connections",
            icon_path=":/assets/material-icons/p2p.svg",
            parent=parent,
            show_header=False,
            banner_position="bottom",
        )
        self._setup_ui()

    def _setup_ui(self):
        """Set up the page UI."""
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.table = PaginatedTableWidget(
            columns=["Connection", "URL", "Status"],
            column_widths={"Connection": 220, "Status": 200, "Actions": 50},
            title="Connections",
            icon_path=":/assets/material-icons/p2p.svg",
            show_add_button=True,
            add_button_text="Add Connection",
            row_actions=["Refresh", "Dynamic Client Registration"],
            row_actions_callback=self._get_row_actions,
            row_action_icons=_ROW_ACTION_ICONS,
            items_per_page=10,
            parent=self,
        )

        self.table.add_clicked.connect(self._on_add_connection)
        self.table.row_action_triggered.connect(self._on_row_action_signal)

        self.content_layout.addWidget(self.table)

        logger.info("ConnectionsListPage initialized with table widget")

    def _get_db(self):
        """Return the signet plugin's LMDB, or None if no vault is open."""
        if not self.app or not self.app.vault:
            return None
        return self.app.vault.plugin_state.get("signet", {}).get("db")

    def _get_row_actions(
        self, row_data: dict[str, Any]
    ) -> tuple[list[str], dict[str, str]]:
        """Determine which row action to show based on connection status."""
        status = row_data.get("_status", "")
        if status == "needs_approval":
            actions = ["Refresh"]
        elif status == "approved":
            actions = ["Proceed with Dynamic Client Registration"]
        else:
            actions = []
        return actions, _ROW_ACTION_ICONS

    def _transform_connection_to_row(self, connection) -> dict[str, Any]:
        """Build a table row dict from a SignetConnection."""
        display, color = _STATUS_DISPLAY.get(
            connection.status, ("Unknown", colors.DANGER)
        )

        row: dict[str, Any] = {
            "Connection": connection.display_name,
            "URL": connection.base_url,
            "Status": display,
            "Status_color": color,
            "_status": connection.status,
            "_connection_id": connection.connection_id,
        }

        # Registered (fully connected) rows show their partner's logo next
        # to the connection name.
        if connection.status == "registered" and connection.logo_icon_path:
            row["Connection_icon"] = connection.logo_icon_path
            row["Connection_icon_side"] = "before"

        return row

    @guarded("Failed to load connections.")
    def _load_connections(self):
        """Load connections from SignetBaser and populate the table."""
        db = self._get_db()
        if db is None:
            logger.warning("No signet db available to load connections")
            return

        self.clear_error()

        connections = [
            connection for _, connection in db.signet_connections.getItemIter()
        ]
        rows = [
            self._transform_connection_to_row(connection) for connection in connections
        ]

        self.table.set_static_data(rows)

        logger.info(f"Loaded {len(rows)} connections")

    @guarded("Failed to add connection.")
    def _on_add_connection(self):
        """Handle Add Connection click.

        AddConnectionDialog is implemented in a follow-up pass; the button
        is wired up but currently a no-op.
        """
        logger.info(
            "Add Connection clicked, but AddConnectionDialog is not yet implemented"
        )

    @guarded("Failed to perform the requested action.")
    def _on_row_action_signal(self, row_data: dict[str, Any], action: str):
        """Handle row action from the skewer menu."""
        connection_id = row_data.get("_connection_id", "")

        if action == "Refresh":
            self._refresh_connection(connection_id)
        elif action == "Proceed with Dynamic Client Registration":
            # DynamicClientRegistrationGateDialog is implemented in a
            # follow-up pass; the row action is wired up but currently a
            # no-op.
            logger.info(
                f"DCR requested for connection {connection_id}, but the gate dialog is not yet implemented"
            )
        else:
            logger.warning(f"Unknown row action: {action}")

    @qasync.asyncSlot()
    async def _refresh_connection(self, connection_id: str):
        """Poll the connection's onboarding status and persist any change."""
        db = self._get_db()
        if db is None:
            return

        connection = db.signet_connections.get(keys=(connection_id,))
        if connection is None:
            self.show_error("Connection not found.")
            return

        result = await remoting.poll_onboarding(
            connection.base_url, connection.onboarding_id
        )
        if not result.get("success"):
            self.show_error(result.get("error", "Failed to refresh connection status."))
            return

        connection.last_checked_at = helping.nowIso8601()
        if result.get("terminal"):
            connection.status = result.get("status", connection.status)
        db.signet_connections.pin(keys=(connection_id,), val=connection)

        self._load_connections()

    def on_show(self):
        """Called when page becomes visible - load connections."""
        logger.info("ConnectionsListPage shown, loading connections")
        self._load_connections()
