# -*- encoding: utf-8 -*-
"""
signet.connections.list module

Connections list page -- shows the vault's UDAP vLEI onboarding connections
(Onyx, and other partners), their approval status, and the row action
("Refresh" or "Register") available for
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
from .add import AddConnectionDialog
from .dcr_gate import DynamicClientRegistrationGateDialog
from .status import ROW_ACTION_ICONS as _ROW_ACTION_ICONS
from .status import STATUS_DISPLAY as _STATUS_DISPLAY
from .view import ViewConnectionDialog

logger = help.ogler.getLogger(__name__)


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
        self.table.row_clicked.connect(self._on_row_clicked)

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
            actions = ["Register"]
        else:
            actions = []
        actions.append("View")
        actions.append("Delete")
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
        """Handle Add Connection click."""
        dialog = AddConnectionDialog(
            app=self.app, on_success=self._load_connections, parent=self
        )
        dialog.open()

    @guarded("Failed to perform the requested action.")
    def _on_row_clicked(self, row_data: Any):
        """Handle row click to open the read-only view dialog."""
        if not isinstance(row_data, dict):
            return
        connection_id = row_data.get("_connection_id", "")
        if not connection_id:
            return
        dialog = ViewConnectionDialog(
            app=self.app,
            connection_id=connection_id,
            on_success=self._load_connections,
            parent=self,
        )
        dialog.open()

    @guarded("Failed to perform the requested action.")
    def _on_row_action_signal(self, row_data: dict[str, Any], action: str):
        """Handle row action from the skewer menu."""
        connection_id = row_data.get("_connection_id", "")

        if action == "Refresh":
            self._refresh_connection(connection_id)
        elif action == "Register":
            dialog = DynamicClientRegistrationGateDialog(
                app=self.app,
                connection_id=connection_id,
                on_success=self._load_connections,
                parent=self,
            )
            dialog.open()
        elif action == "View":
            dialog = ViewConnectionDialog(
                app=self.app,
                connection_id=connection_id,
                on_success=self._load_connections,
                parent=self,
            )
            dialog.open()
        elif action == "Delete":
            self._on_delete_connection(row_data)
        else:
            logger.warning(f"Unknown row action: {action}")

    def _on_delete_connection(self, row_data: dict[str, Any]):
        """Open the delete confirmation dialog for the selected connection."""
        from .delete import DeleteConnectionDialog

        db = self._get_db()
        if db is None:
            self.show_error("No signet database available.")
            return

        connection_id = row_data.get("_connection_id", "")
        display_name = row_data.get("Connection", "") or connection_id
        if not connection_id:
            logger.error("Cannot delete: no connection_id found")
            return

        dialog = DeleteConnectionDialog(
            db=db,
            connection_id=connection_id,
            display_name=display_name,
            on_success=self._on_connection_deleted,
            parent=self,
        )
        dialog.open()

    def _on_connection_deleted(self, connection_id: str):
        """Reload the table after a connection has been deleted."""
        logger.info(f"Connection {connection_id} deleted, reloading list")
        self._load_connections()

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

        previous_status = connection.status
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

        # Per spec: a refresh that crosses needs_approval -> approved should
        # pop the DCR gate dialog automatically.
        if previous_status == "needs_approval" and connection.status == "approved":
            dialog = DynamicClientRegistrationGateDialog(
                app=self.app,
                connection_id=connection_id,
                on_success=self._load_connections,
                parent=self,
            )
            dialog.open()

    def on_show(self):
        """Called when page becomes visible - load connections."""
        logger.info("ConnectionsListPage shown, loading connections")
        self._load_connections()
