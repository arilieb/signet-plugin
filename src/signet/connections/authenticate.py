# -*- encoding: utf-8 -*-
"""
signet.connections.authenticate module

Confirm/cancel dialog for the "Authenticate" row action: re-presents the
registered credential to the server's token endpoint (OAuth 2.0
client_credentials with an ACDC client assertion) and stores the returned
bearer token on the connection. Modeled on dcr_gate.
"""

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import qasync
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget
from keri import help
from keri.help import helping

from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithButton,
    LocksmithDialog,
    LocksmithInvertedButton,
)

from ..core import configing, presenting, remoting
from .status import format_expiry

logger = help.ogler.getLogger(__name__)

_PROMPT = "Authenticate with this server using your registered credential?"


async def authenticate_connection(vault, db, connection_id: str) -> dict:
    """
    Obtain and store an access token for a registered connection (no UI).

    Returns ``{"success": True, "token_expires_at": iso}`` or
    ``{"success": False, "error": str}``.
    """
    connection = db.signet_connections.get(keys=(connection_id,))
    if connection is None:
        return {"success": False, "error": "Connection not found."}
    if connection.status != "registered":
        return {"success": False, "error": "The connection is not registered."}

    # Only the client_id the server issued for this (AID, credential) is
    # ever sent -- never the credential SAID.
    client_id = db.resolve_client_id(connection)
    if not client_id:
        return {
            "success": False,
            "error": "No client registration found for this identifier and "
            "credential. Register again.",
        }

    discovery = await remoting.discover_server(connection.base_url)
    if not discovery.get("success"):
        return {
            "success": False,
            "error": discovery.get("error", "Server discovery failed."),
        }
    token_endpoint = discovery.get("token_endpoint")
    if not token_endpoint:
        return {
            "success": False,
            "error": "Server does not advertise a token endpoint.",
        }

    try:
        assertion = (
            ""
            if configing.is_mock_mode()
            else presenting.build_token_assertion(vault, connection)
        )
    except presenting.PresentingError as exc:
        return {"success": False, "error": str(exc)}

    result = await remoting.request_access_token(token_endpoint, client_id, assertion)
    if not result.get("success"):
        return {
            "success": False,
            "error": result.get("error", "Authentication failed."),
        }

    # Computed once at receipt; never recomputed on read.
    now = datetime.now(timezone.utc)
    expires_in = int(result.get("expires_in") or 0)
    connection.access_token = result["access_token"]
    connection.token_type = result.get("token_type", "Bearer")
    connection.token_scope = result.get("scope", "")
    connection.token_expires_at = (now + timedelta(seconds=expires_in)).isoformat()
    connection.last_authenticated_at = helping.nowIso8601()
    db.signet_connections.pin(keys=(connection_id,), val=connection)

    logger.info(f"Connection {connection_id} authenticated")
    return {"success": True, "token_expires_at": connection.token_expires_at}


async def ensure_authenticated(vault, db, connection_id: str) -> dict:
    """Reuse a still-valid stored token, else authenticate; same return shape."""
    connection = db.signet_connections.get(keys=(connection_id,))
    if connection is not None and connection.has_valid_token():
        logger.info(f"Connection {connection_id}: reusing valid access token")
        return {"success": True, "token_expires_at": connection.token_expires_at}
    return await authenticate_connection(vault, db, connection_id)


class AuthenticateDialog(LocksmithDialog):
    """Confirm/cancel dialog that obtains an access token for a registered connection."""

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

        self.message = QLabel(_PROMPT)
        self.message.setWordWrap(True)
        self.message.setStyleSheet(f"font-size: 14px; color: {colors.TEXT_PRIMARY};")
        layout.addWidget(self.message)
        layout.addStretch()

        button_row = QHBoxLayout()
        button_row.addStretch()
        self.cancel_button = LocksmithInvertedButton("Cancel")
        button_row.addWidget(self.cancel_button)
        button_row.addSpacing(10)
        self.confirm_button = LocksmithButton("Authenticate")
        button_row.addWidget(self.confirm_button)

        super().__init__(
            parent=parent,
            title="Authenticate",
            title_icon=":/assets/material-icons/verified.svg",
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

        self.confirm_button.setEnabled(False)
        self.confirm_button.setText("Authenticating...")
        self.cancel_button.setEnabled(False)

        try:
            result = await authenticate_connection(
                self.app.vault, db, self.connection_id
            )
            if not result.get("success"):
                self.show_error(result.get("error", "Authentication failed."))
                self._reset_buttons()
                return

            if self.on_success:
                self.on_success()

            self._show_authenticated(result["token_expires_at"])
        except Exception as exc:
            logger.exception(f"AuthenticateDialog: authentication failed: {exc}")
            self.show_error(f"Authentication failed: {exc}")
            self._reset_buttons()

    def _show_authenticated(self, token_expires_at: str):
        """Swap to the success state: no raw token is shown."""
        self.message.setText(
            f"Authenticated — token expires {format_expiry(token_expires_at)}"
        )
        self.confirm_button.hide()
        self.cancel_button.setText("Close")
        self.cancel_button.setEnabled(True)

    def _reset_buttons(self):
        self.confirm_button.setEnabled(True)
        self.confirm_button.setText("Authenticate")
        self.cancel_button.setEnabled(True)
