# -*- encoding: utf-8 -*-
"""
signet.connections.view module

Read-only dialog for a single connection: name, URL, credential, and a
status badge, plus exactly one conditional action button (mutually
exclusive per status): "Refresh" while needs_approval, "Register" once approved,
no button once rejected or registered.
"""
from collections.abc import Callable

import qasync
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QSpacerItem, QVBoxLayout, QWidget
from keri import help
from keri.help import helping

from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton

from ..core import remoting
from .status import STATUS_DISPLAY

logger = help.ogler.getLogger(__name__)


class ViewConnectionDialog(LocksmithDialog):
    """Read-only view of a signet connection with one status-dependent action button."""

    def __init__(self, app, connection_id: str, on_success: Callable[[], None] | None = None, parent=None):
        self.app = app
        self.connection_id = connection_id
        self.on_success = on_success
        self.action_btn: LocksmithButton | None = None
        self.action_spacer = None

        content_widget = QWidget()
        self.content_layout = QVBoxLayout(content_widget)
        self.content_layout.setContentsMargins(0, 10, 0, 0)
        self.content_layout.setSpacing(10)

        self.button_row = QHBoxLayout()
        self.button_row.addStretch()
        self.close_btn = LocksmithInvertedButton("Close")
        self.button_row.addWidget(self.close_btn)
        self.button_row.addStretch()

        connection = self._get_connection()
        display_name = connection.display_name if connection else "Connection"

        super().__init__(
            parent=parent,
            title=display_name,
            title_icon=":/assets/material-icons/p2p.svg",
            content=content_widget,
            buttons=self.button_row,
        )

        self.setFixedSize(480, 325)
        self.close_btn.clicked.connect(self.close)

        self._build_content()

    def _get_db(self):
        if not self.app or not self.app.vault:
            return None
        return self.app.vault.plugin_state.get("signet", {}).get("db")

    def _get_connection(self):
        db = self._get_db()
        if db is None:
            return None
        return db.signet_connections.get(keys=(self.connection_id,))

    def _clear_content(self):
        self._clear_layout(self.content_layout)

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self._clear_layout(item.layout())

    def _build_content(self):
        self._clear_content()

        connection = self._get_connection()
        if connection is None:
            self.content_layout.addWidget(QLabel("Connection not found."))
            self._set_action_button(None)
            return

        self.set_title(connection.display_name)

        self.content_layout.addSpacing(20)
        info_label = QLabel("Connection Information:")
        info_label.setStyleSheet("font-weight: 600; font-size: 13px;")
        self.content_layout.addWidget(info_label)
        self.content_layout.addSpacing(5)

        # Bordered container that holds all of the connection details
        info_container = QWidget()
        info_container.setObjectName("connectionInfoContainer")
        info_container.setStyleSheet(f"""
            QWidget#connectionInfoContainer {{
                border: 1px solid {colors.BORDER};
                border-radius: 6px;
                background-color: {colors.BACKGROUND_CONTENT};
            }}
        """)
        info_grid = QGridLayout(info_container)
        info_grid.setContentsMargins(15, 15, 15, 15)
        info_grid.setHorizontalSpacing(12)
        info_grid.setVerticalSpacing(4)
        info_grid.setColumnStretch(1, 1)

        row = 0

        status_label = QLabel("Status:")
        status_label.setStyleSheet("font-weight: 600; font-size: 13px;")
        display, color = STATUS_DISPLAY.get(connection.status, ("Unknown", colors.DANGER))
        badge = QLabel(display)
        badge.setStyleSheet(f"font-size: 13px; color: {color};")
        info_grid.addWidget(status_label, row, 0)
        info_grid.addWidget(badge, row, 1)
        row += 1

        row = self._add_field_row(info_grid, row, "URL", connection.base_url or "—")
        row = self._add_field_row(info_grid, row, "Credential", connection.selected_credential_said or "—")
        if connection.client_id:
            row = self._add_field_row(info_grid, row, "Client ID", connection.client_id)

        self.content_layout.addWidget(info_container)
        self.content_layout.addStretch()
        self._set_action_button(connection.status)

    def _add_field_row(self, grid, row: int, label: str, value: str) -> int:
        label_widget = QLabel(f"{label}:")
        label_widget.setStyleSheet("font-weight: 600; font-size: 13px;")
        grid.addWidget(label_widget, row, 0)
        value_widget = QLabel(value)
        value_widget.setStyleSheet(f"font-size: 13px; color: {colors.TEXT_SUBTLE};")
        value_widget.setWordWrap(True)
        grid.addWidget(value_widget, row, 1)
        return row + 1

    def _set_action_button(self, status: str | None):
        if self.action_btn is not None:
            self.button_row.removeWidget(self.action_btn)
            self.action_btn.deleteLater()
            self.action_btn = None

        if self.action_spacer is not None:
            self.button_row.removeItem(self.action_spacer)
            self.action_spacer = None

        if status == "needs_approval":
            self.action_btn = LocksmithButton("Refresh")
            self.action_btn.clicked.connect(self._on_refresh)
        elif status == "approved":
            self.action_btn = LocksmithButton("Register")
            self.action_btn.clicked.connect(self._on_proceed_with_dcr)
        else:
            return

        # Insert before the trailing stretch (last item) so the group stays centered
        insert_index = self.button_row.count() - 1
        self.action_spacer = QSpacerItem(10, 0)
        self.button_row.insertItem(insert_index, self.action_spacer)
        self.button_row.insertWidget(insert_index + 1, self.action_btn)

    @qasync.asyncSlot()
    async def _on_refresh(self):
        connection = self._get_connection()
        db = self._get_db()
        if connection is None or db is None or self.action_btn is None:
            return

        self.action_btn.setEnabled(False)
        self.action_btn.setText("Refreshing...")

        previous_status = connection.status
        result = await remoting.poll_onboarding(connection.base_url, connection.onboarding_id)
        if not result.get("success"):
            self.show_error(result.get("error", "Failed to refresh connection status."))
            self.action_btn.setEnabled(True)
            self.action_btn.setText("Refresh")
            return

        connection.last_checked_at = helping.nowIso8601()
        if result.get("terminal"):
            connection.status = result.get("status", connection.status)
        db.signet_connections.pin(keys=(self.connection_id,), val=connection)

        self._build_content()

        if self.on_success:
            self.on_success()

        if previous_status == "needs_approval" and connection.status == "approved":
            self._open_dcr_gate()

    def _on_proceed_with_dcr(self):
        self._open_dcr_gate()

    def _open_dcr_gate(self):
        from .dcr_gate import DynamicClientRegistrationGateDialog
        dialog = DynamicClientRegistrationGateDialog(
            app=self.app,
            connection_id=self.connection_id,
            on_success=self._on_dcr_success,
            parent=self.parent(),
        )
        dialog.show()

    def _on_dcr_success(self):
        self._build_content()
        if self.on_success:
            self.on_success()