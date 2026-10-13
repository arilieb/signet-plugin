# -*- encoding: utf-8 -*-
"""
signet.fhir.list module

FHIR APIs page -- progressive disclosure with Connection and Group dropdowns
above a table of FHIR endpoints. Clicking a row runs an invisible
authentication pre-check against the selected connection (reusing a still-valid
token); only on success does the (future) downstream action run.
"""

import json
from typing import Any

import qasync
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget
from keri import help

from locksmith.ui import colors
from locksmith.ui.toolkit.tables import PaginatedTableWidget
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox
from locksmith.ui.toolkit.widgets.page import LocksmithFormPage, guarded
from signet.core import remoting

from ..connections.authenticate import ensure_authenticated

logger = help.ogler.getLogger(__name__)

_API_ICON = ":/assets/material-icons/api.svg"
_INTRO_TEXT = "To get started with PDex Member Match, select a connection from the dropdown below."
_NO_CONNECTIONS_TEXT = (
    "No active connections available. Register a connection on the Connections page."
)


class FhirApisListPage(LocksmithFormPage):
    """FHIR endpoints per Group, for a registered connection."""

    def __init__(self, app, parent=None):
        self.app = app
        self._parent = parent
        self._authenticating = False
        self._connection_by_id: dict[str, Any] = {}
        self._group_by_id: dict[str, dict] = {}

        super().__init__(
            title="DaVinci Data Export",
            icon_path=_API_ICON,
            parent=parent,
            banner_position="bottom",
        )
        self._setup_ui()

    def _setup_ui(self):
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(12)

        # Container for dropdowns
        self._selector_container = QWidget()
        selector_layout = QVBoxLayout(self._selector_container)
        selector_layout.setContentsMargins(16, 16, 16, 0)
        selector_layout.setSpacing(12)

        # Intro text
        self._intro_label = QLabel(_INTRO_TEXT)
        self._intro_label.setWordWrap(True)
        self._intro_label.setStyleSheet(
            f"font-size: 14px; color: {colors.TEXT_SUBTLE};"
        )
        selector_layout.addWidget(self._intro_label)

        # Connection dropdown
        self._connection_selector = FloatingLabelComboBox(label_text="Connection")
        self._connection_selector.setFixedWidth(400)
        self._connection_selector.currentIndexChanged.connect(
            self._on_connection_changed
        )
        selector_layout.addWidget(self._connection_selector)

        # Group dropdown (initially hidden)
        self._group_selector = FloatingLabelComboBox(label_text="Group ID")
        self._group_selector.setFixedWidth(400)
        self._group_selector.currentIndexChanged.connect(self._on_group_changed)
        self._group_selector.hide()
        selector_layout.addWidget(self._group_selector)

        self.content_layout.addWidget(self._selector_container)

        # Table widget (initially hidden)
        self.table = PaginatedTableWidget(
            columns=["Resource", "Operation", "Endpoint", "Scope", "Purpose"],
            column_widths={"Resource": 140, "Operation": 120, "Purpose": 100},
            title="DaVinci Data Export",
            show_add_button=False,
            icon_path=_API_ICON,
            items_per_page=10,
            parent=self,
        )
        self.table.row_clicked.connect(self._on_row_clicked)
        self.table.hide()

        self.content_layout.addWidget(self.table)
        self.content_layout.addStretch()

        logger.info(
            "FhirApisListPage initialized with dropdown selectors and table widget"
        )

    def _get_db(self):
        """Return the signet plugin's LMDB, or None if no vault is open."""
        if not self.app or not self.app.vault:
            return None
        return self.app.vault.plugin_state.get("signet", {}).get("db")

    def _registered_connections(self) -> list:
        db = self._get_db()
        if db is None:
            return []
        return [
            connection
            for _, connection in db.signet_connections.getItemIter()
            if connection.status == "registered"
        ]

    @guarded("Failed to load FHIR APIs.")
    def on_show(self):
        """Called when the page becomes visible - reset to initial state."""
        self.clear_error()
        self._populate_connection_dropdown()
        # Reset to initial state
        self._group_selector.hide()
        self.table.hide()

    def _populate_connection_dropdown(self):
        """Populate the connection dropdown with registered connections."""
        self._connection_selector.blockSignals(True)
        self._connection_selector.clear()
        self._connection_by_id.clear()

        connections = self._registered_connections()
        if not connections:
            self._intro_label.setText(_NO_CONNECTIONS_TEXT)
            self._connection_selector.setEnabled(False)
            return

        self._intro_label.setText(_INTRO_TEXT)
        self._connection_selector.setEnabled(True)

        # Add placeholder item
        self._connection_selector.addItem("Select a connection...", None)

        for connection in connections:
            self._connection_by_id[connection.connection_id] = connection
            self._connection_selector.addItem(
                connection.display_name, connection.connection_id
            )

        self._connection_selector.setCurrentIndex(0)
        self._connection_selector.blockSignals(False)

    @guarded("Failed to load Group IDs.")
    @qasync.asyncSlot(int)
    async def _on_connection_changed(self, index: int):
        """Handle connection selection change."""
        connection_id = self._connection_selector.currentData()
        if connection_id is None:
            # Placeholder selected - hide group selector and table
            self._group_selector.hide()
            self.table.hide()
            return

        # Populate groups for selected connection
        await self._populate_group_dropdown(connection_id)
        self._group_selector.show()
        self.table.hide()

    async def _populate_group_dropdown(self, connection_id: str):
        """Populate the group dropdown for the selected connection."""
        self._group_selector.blockSignals(True)
        self._group_selector.clear()
        self._group_by_id.clear()

        connection = self._connection_by_id[connection_id]
        response = await remoting.get_groups(connection)
        groups = response.get("entry", [])

        # Add placeholder item
        self._group_selector.addItem("Select a group...", None)

        for group in groups:
            resource = group.get("resource", {})
            self._group_by_id[resource["id"]] = group
            self._group_selector.addItem(resource["name"], resource["id"])

        self._group_selector.setCurrentIndex(0)
        self._group_selector.blockSignals(False)

    @guarded("Failed to load FHIR endpoints.")
    @qasync.asyncSlot(int)
    async def _on_group_changed(self, index: int):
        """Handle group selection change."""
        group_id = self._group_selector.currentData()
        if group_id is None:
            # Placeholder selected - hide table
            self.table.hide()
            return

        connection_id = self._connection_selector.currentData()
        if connection_id is None:
            return

        connection = self._connection_by_id[connection_id]
        response = await remoting.davinci_data_export(connection, group_id)
        print(json.dumps(response, indent=2))
        # Load and display FHIR endpoints
        self.table.set_static_data([])
        self.table.show()

    @qasync.asyncSlot(object)
    async def _on_row_clicked(self, row_data: Any):
        """Authenticate (or reuse a valid token) before acting on the row."""
        if self._authenticating or not isinstance(row_data, dict):
            return
        connection_id = self._connection_selector.currentData()
        db = self._get_db()
        if connection_id is None or db is None:
            return

        self._authenticating = True
        try:
            self.clear_error()
            result = await ensure_authenticated(self.app.vault, db, connection_id)
            if not result.get("success"):
                message = result.get("error", "Authentication failed.")
                logger.error(f"FHIR row click: authentication failed: {message}")
                self.show_error(message)
                return
            self._on_authenticated_row(row_data)
        except Exception as exc:
            logger.exception(f"FHIR row click: authentication failed: {exc}")
            self.show_error(f"Authentication failed: {exc}")
        finally:
            self._authenticating = False

    def _on_authenticated_row(self, row_data: dict[str, Any]):
        """Placeholder for the downstream action once the connection is authenticated."""
        logger.info(
            f"Authenticated; would call {row_data.get('Endpoint')} "
            f"({row_data.get('Resource')} {row_data.get('Operation')})"
        )
