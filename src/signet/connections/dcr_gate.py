# -*- encoding: utf-8 -*-
"""
signet.connections.dcr_gate module

Confirm/cancel gate before performing UDAP Dynamic Client Registration for
an approved connection. Reusable from three call sites: the list page's row
action, the view dialog's action button, and automatically whenever a
refresh transitions a connection from needs_approval to approved (list row
action, view dialog refresh, or the tail of the add-connection flow).
"""

from collections.abc import Callable

import qasync
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget
from keri import help

from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithButton,
    LocksmithDialog,
    LocksmithInvertedButton,
)

from ..core import remoting

logger = help.ogler.getLogger(__name__)


class DynamicClientRegistrationGateDialog(LocksmithDialog):
    """Confirm/cancel dialog gating manual Dynamic Client Registration."""

    def __init__(
        self,
        app,
        connection_id: str,
        on_success: Callable[[], None] | None = None,
        parent=None,
    ):
        self.app = app
        self.connection_id = connection_id
        self.on_success = on_success

        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(0, 10, 0, 0)

        message = QLabel(
            "Approval has been granted, proceed with dynamic client registration?"
        )
        message.setWordWrap(True)
        message.setStyleSheet(f"font-size: 14px; color: {colors.TEXT_PRIMARY};")
        layout.addWidget(message)
        layout.addStretch()

        button_row = QHBoxLayout()
        button_row.addStretch()
        self.cancel_button = LocksmithInvertedButton("Cancel")
        button_row.addWidget(self.cancel_button)
        button_row.addSpacing(10)
        self.confirm_button = LocksmithButton("Proceed")
        button_row.addWidget(self.confirm_button)

        super().__init__(
            parent=parent,
            title="Dynamic Client Registration",
            title_icon=":/assets/material-icons/shield_lock.svg",
            content=content_widget,
            buttons=button_row,
        )

        self.setFixedSize(420, 220)

        self.cancel_button.clicked.connect(self.close)
        self.confirm_button.clicked.connect(self._on_confirm)

    def _get_db(self):
        if not self.app or not self.app.vault:
            return None
        return self.app.vault.plugin_state.get("signet", {}).get("db")

    @qasync.asyncSlot()
    async def _on_confirm(self):
        db = self._get_db()
        if db is None:
            self.show_error("No signet database available.")
            return

        connection = db.signet_connections.get(keys=(self.connection_id,))
        if connection is None:
            self.show_error("Connection not found.")
            return

        self.confirm_button.setEnabled(False)
        self.confirm_button.setText("Registering...")
        self.cancel_button.setEnabled(False)

        try:
            approved_purpose_grant = {
                "purpose": connection.purpose,
                "onboarding_id": connection.onboarding_id,
            }
            result = await remoting.register_dynamic_client(
                connection.base_url, approved_purpose_grant
            )

            if not result.get("success"):
                self.show_error(
                    result.get("error", "Dynamic client registration failed.")
                )
                self.confirm_button.setEnabled(True)
                self.confirm_button.setText("Proceed")
                self.cancel_button.setEnabled(True)
                return

            connection.status = "registered"
            connection.client_id = result.get("client_id", "")
            db.signet_connections.pin(keys=(self.connection_id,), val=connection)

            logger.info(
                f"Connection {self.connection_id} registered with client_id {connection.client_id}"
            )

            if self.on_success:
                self.on_success()

            self.accept()
        except Exception as exc:
            logger.exception(
                f"DynamicClientRegistrationGateDialog: registration failed: {exc}"
            )
            self.show_error(f"Dynamic client registration failed: {exc}")
            self.confirm_button.setEnabled(True)
            self.confirm_button.setText("Proceed")
            self.cancel_button.setEnabled(True)
