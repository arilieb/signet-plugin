# -*- encoding: utf-8 -*-
"""
signet.fhir.list module

FHIR APIs page -- a two-stage selector (registered connection -> Group ID)
over a table of that Group's FHIR endpoints. Clicking a row runs an invisible
authentication pre-check against the selected connection (reusing a still-valid
token); only on success does the (future) downstream action run.
"""

from typing import Any

import qasync
from PySide6.QtCore import QSize
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtWidgets import QLabel
from keri import help

from locksmith.ui.toolkit.tables import TwoStageSelectionTableWidget
from locksmith.ui.toolkit.widgets.page import LocksmithFormPage, guarded

from ..connections.authenticate import ensure_authenticated
from ..core import mock_data

logger = help.ogler.getLogger(__name__)

_API_ICON = ":/assets/material-icons/api.svg"
_STAGE1_TEXT = "Select a currently active connection from the dropdown"
_STAGE1_NONE_TEXT = (
    "No active connections. Register a connection on the Connections page."
)
_STAGE2_TEXT = "Select a Group ID from the dropdown"
_LOGO_SIZE = 96


def _icon_label(icon_path: str) -> QLabel | None:
    """A QLabel showing ``icon_path`` (a resource path), or None if empty/unloadable."""
    if not icon_path:
        return None
    icon = QIcon(icon_path)
    if icon.isNull():
        return None
    # Rasterize the (vector) icon at the screen's native pixel density rather
    # than upscaling a small pixmap, which blurs.
    screen = QGuiApplication.primaryScreen()
    ratio = screen.devicePixelRatio() if screen else 1.0
    pixmap = icon.pixmap(QSize(_LOGO_SIZE, _LOGO_SIZE), ratio)
    label = QLabel()
    label.setPixmap(pixmap)
    return label


class FhirApisListPage(LocksmithFormPage):
    """FHIR endpoints per Group, for a registered connection."""

    def __init__(self, app, parent=None):
        self.app = app
        self._parent = parent
        self._authenticating = False

        super().__init__(
            title="FHIR APIs",
            icon_path=_API_ICON,
            parent=parent,
            show_header=False,
            banner_position="bottom",
        )
        self._setup_ui()

    def _setup_ui(self):
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.table = TwoStageSelectionTableWidget(
            columns=["Resource", "Operation", "Endpoint", "Scope", "Purpose"],
            column_widths={"Resource": 140, "Operation": 120, "Purpose": 100},
            primary_label="Connection",
            secondary_label="Group ID",
            title="FHIR APIs",
            icon_path=_API_ICON,
            items_per_page=10,
            parent=self,
        )
        self.table.primary_changed.connect(self._on_primary_changed)
        self.table.secondary_changed.connect(self._on_secondary_changed)
        self.table.row_clicked.connect(self._on_row_clicked)

        self.content_layout.addWidget(self.table)

        logger.info("FhirApisListPage initialized with table widget")

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
        """Called when the page becomes visible - restart from stage 1."""
        self.clear_error()
        connections = self._registered_connections()
        self.table.set_primary_options(
            [
                (connection.display_name, connection.connection_id)
                for connection in connections
            ]
        )
        self.table.set_empty_state(
            1,
            _STAGE1_TEXT if connections else _STAGE1_NONE_TEXT,
            _icon_label(_API_ICON),
        )
        self.table.reset()
        self.table.focus_primary()

    @guarded("Failed to load Group IDs.")
    def _on_primary_changed(self, connection_id: Any):
        if connection_id is None:
            return
        db = self._get_db()
        connection = (
            db.signet_connections.get(keys=(connection_id,)) if db is not None else None
        )
        groups = mock_data.fhir_groups(connection_id)
        self.table.set_secondary_options(
            [(group["display_name"], group["group_id"]) for group in groups]
        )
        logo = _icon_label(connection.logo_icon_path) if connection else None
        self.table.set_empty_state(2, _STAGE2_TEXT, logo)

    @guarded("Failed to load FHIR endpoints.")
    def _on_secondary_changed(self, group_id: Any):
        connection_id = self.table.primary_data()
        if connection_id is None or group_id is None:
            return
        self.table.set_static_data(mock_data.fhir_endpoints(connection_id, group_id))

    @qasync.asyncSlot(object)
    async def _on_row_clicked(self, row_data: Any):
        """Authenticate (or reuse a valid token) before acting on the row."""
        if self._authenticating or not isinstance(row_data, dict):
            return
        connection_id = self.table.primary_data()
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
