# -*- encoding: utf-8 -*-
"""
signet.fhir.list module

FHIR APIs page -- progressive disclosure with Connection and Group dropdowns
above a table of FHIR endpoints. Clicking a row runs an invisible
authentication pre-check against the selected connection (reusing a still-valid
token); only on success does the (future) downstream action run.
"""

import asyncio
from pathlib import Path
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
_EXPORT_COLUMNS = ["File", "Type", "Size", "Status"]
_EXPORT_DIR = Path.home() / "signet-exports"
_DEFAULT_POLL_SECONDS = 5.0
_MAX_POLL_SECONDS = 60.0
_MAX_POLLS = 120
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
        self._export_run = 0  # bumped per export so a superseded poll loop stops
        self._export_group_id = ""
        self._export_rows: dict[str, dict] = {}  # File column -> row incl. url

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

        # Scope granted with the connection's current token
        self._scope_label = QLabel()
        self._scope_label.setStyleSheet(
            f"font-size: 12px; color: {colors.TEXT_SUBTLE};"
        )
        self._scope_label.hide()
        selector_layout.addWidget(self._scope_label)

        self.content_layout.addWidget(self._selector_container)

        # Table widget (initially hidden)
        self.table = PaginatedTableWidget(
            columns=_EXPORT_COLUMNS,
            column_widths={"Type": 140, "Size": 100, "Status": 140},
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
        self._scope_label.hide()
        self.table.hide()

    def _populate_connection_dropdown(self):
        """Populate the connection dropdown with registered connections."""
        self._connection_selector.blockSignals(True)
        try:
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
        finally:
            self._connection_selector.blockSignals(False)

    async def _authorized_connection(self, connection_id: str):
        """
        Authenticate (reusing a still-valid token) and return the connection re-read from
        the db, so it carries the fresh access token. Raises RuntimeError on failure.
        """
        db = self._get_db()
        if db is None:
            raise RuntimeError("No signet database available.")
        result = await ensure_authenticated(self.app.vault, db, connection_id)
        if not result.get("success"):
            raise RuntimeError(result.get("error", "Authentication failed."))
        connection = db.signet_connections.get(keys=(connection_id,))
        if connection is None:
            raise RuntimeError("Connection not found.")
        return connection

    @qasync.asyncSlot(int)
    async def _on_connection_changed(self, index: int):
        """Handle connection selection change."""
        self._export_run += 1  # abandon any export in flight
        self.clear_error()
        connection_id = self._connection_selector.currentData()
        self.table.hide()
        if connection_id is None:
            # Placeholder selected - hide group selector
            self._group_selector.hide()
            self._scope_label.hide()
            return

        try:
            # Populate groups for selected connection
            if await self._populate_group_dropdown(connection_id):
                self._group_selector.show()
        except Exception as exc:
            logger.exception(f"Failed to load Group IDs: {exc}")
            self._group_selector.hide()
            self.show_error(f"Failed to load Group IDs: {exc}")

    async def _populate_group_dropdown(self, connection_id: str) -> bool:
        """
        Populate the group dropdown for the selected connection.

        Returns False (with the error shown, the combo left empty) when the Groups
        could not be loaded.
        """
        self._group_selector.blockSignals(True)
        try:
            self._group_selector.clear()
            self._group_by_id.clear()
            self._scope_label.hide()

            connection = await self._authorized_connection(connection_id)
            if connection.token_scope:
                self._scope_label.setText(f"Granted scope: {connection.token_scope}")
                self._scope_label.show()

            response = await remoting.get_groups(connection)
            if not response.get("success"):
                message = response.get("error", "Failed to load Group IDs.")
                logger.error(f"FHIR Groups: {message}")
                self.show_error(message)
                return False

            # Add placeholder item
            self._group_selector.addItem("Select a group...", None)

            for group in response.get("groups", []):
                self._group_by_id[group["id"]] = group
                self._group_selector.addItem(group["name"], group["id"])

            self._group_selector.setCurrentIndex(0)
            return True
        finally:
            self._group_selector.blockSignals(False)

    @qasync.asyncSlot(int)
    async def _on_group_changed(self, index: int):
        """Handle group selection change: start a data export and follow it to completion."""
        self._export_run += 1
        run = self._export_run
        self.clear_error()
        group_id = self._group_selector.currentData()
        connection_id = self._connection_selector.currentData()
        if group_id is None or connection_id is None:
            # Placeholder selected - hide table
            self.table.hide()
            return

        try:
            await self._run_export(run, connection_id, group_id)
        except Exception as exc:
            logger.exception(f"FHIR data export failed: {exc}")
            if run == self._export_run:
                self.show_error(f"Data export failed: {exc}")

    def _show_export_rows(self, rows: list[dict[str, Any]]):
        self.table.set_static_data(rows)
        self.table.show()

    async def _run_export(self, run: int, connection_id: str, group_id: str):
        self._export_group_id = group_id
        self._export_rows = {}
        self._show_export_rows(
            [{"File": "Data export", "Type": "", "Size": "", "Status": "Requested"}]
        )

        connection = await self._authorized_connection(connection_id)
        kickoff = await remoting.davinci_data_export(connection, group_id)
        if run != self._export_run:
            return
        if not kickoff.get("success"):
            self.table.hide()
            self.show_error(kickoff.get("error", "Data export failed."))
            return

        status_url = kickoff["status_url"]
        for _ in range(_MAX_POLLS):
            # Re-authenticates if the token expired while waiting
            connection = await self._authorized_connection(connection_id)
            status = await remoting.poll_export_status(connection, status_url)
            if run != self._export_run:
                return
            if not status.get("success"):
                self.table.hide()
                self.show_error(status.get("error", "Data export failed."))
                return
            if status["state"] == "complete":
                self._show_export_files(status.get("files", []))
                return
            self._show_export_rows(
                [
                    {
                        "File": "Data export",
                        "Type": "",
                        "Size": "",
                        "Status": "In progress",
                    }
                ]
            )
            try:
                delay = float(status.get("retry_after") or _DEFAULT_POLL_SECONDS)
            except ValueError:
                delay = _DEFAULT_POLL_SECONDS
            await asyncio.sleep(min(max(delay, 1.0), _MAX_POLL_SECONDS))
            if run != self._export_run:
                return

        self.table.hide()
        self.show_error("Data export is taking too long; try again later.")

    def _show_export_files(self, files: list[dict[str, str]]):
        """One row per exported file; clicking a row downloads it."""
        self._export_rows = {}
        for number, file in enumerate(files, start=1):
            kind = file.get("type", "")
            name = f"{kind or 'export'}-{number}.ndjson"
            self._export_rows[name] = {
                "File": name,
                "Type": kind,
                "Size": "",
                "Status": "Ready",
                "url": file["url"],
            }
        if not self._export_rows:
            self._show_export_rows(
                [{"File": "No files", "Type": "", "Size": "", "Status": "Complete"}]
            )
            return
        self._refresh_export_rows()

    def _refresh_export_rows(self):
        self._show_export_rows(
            [
                {column: row[column] for column in _EXPORT_COLUMNS}
                for row in self._export_rows.values()
            ]
        )

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
            await self._on_authenticated_row(connection_id, row_data)
        except Exception as exc:
            logger.exception(f"FHIR row click failed: {exc}")
            self.show_error(f"Download failed: {exc}")
        finally:
            self._authenticating = False

    async def _on_authenticated_row(self, connection_id: str, row_data: dict[str, Any]):
        """Download the clicked export file into the exports folder."""
        row = self._export_rows.get(row_data.get("File", ""))
        if row is None:
            return  # a status-only row

        row["Status"] = "Downloading"
        self._refresh_export_rows()
        connection = await self._authorized_connection(connection_id)
        result = await remoting.download_export_file(
            connection,
            row["url"],
            _EXPORT_DIR / (self._export_group_id or "group"),
            filename=row["File"],
        )
        if not result.get("success"):
            row["Status"] = "Failed"
            self._refresh_export_rows()
            self.show_error(result.get("error", "Download failed."))
            return
        row["Size"] = f"{result['bytes']:,} B"
        row["Status"] = "Downloaded"
        self._refresh_export_rows()
        logger.info(f"Downloaded {row['File']} to {result['path']}")
