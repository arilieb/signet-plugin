# -*- encoding: utf-8 -*-
"""
signet.connections.authenticate module

Confirm/cancel dialog for the "Authenticate" row action: re-presents the
registered credential to the server's token endpoint (OAuth 2.0
client_credentials with an ACDC client assertion) and stores the returned
bearer token on the connection. Modeled on dcr_gate.
"""

import asyncio
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import qasync
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget
from acdc_auth_client.core import flows
from acdc_auth_client.core.options import ConnectionInfo
from acdc_auth_client.models.errors import ACDCOAuthError
from keri import help
from keri.help import helping

from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithButton,
    LocksmithDialog,
    LocksmithInvertedButton,
)

from ..core import configing, mock_data, presenting
from .status import format_expiry

logger = help.ogler.getLogger(__name__)

_PROMPT = "Authenticate with this server using your registered credential?"


def _mock_token() -> flows.AuthResult:
    """The canned token of mock mode, as the library would return it."""
    token = mock_data.mock_request_access_token("")
    now = datetime.now(timezone.utc)
    return flows.AuthResult(
        access_token=token["access_token"],
        token_type=token["token_type"],
        token_scope=token["scope"],
        token_expires_at=(now + timedelta(seconds=token["expires_in"])).isoformat(),
        last_authenticated_at=helping.nowIso8601(),
    )


def _obtain_token(vault, info: ConnectionInfo) -> flows.AuthResult:
    """A fresh token for the connection (the canned one in mock mode)."""
    if configing.is_mock_mode():
        return _mock_token()
    return flows.authenticate(
        info, vault.hby, vault.rgy.reger, configing.client_options()
    )


def authenticate_sync(vault, db, connection_id: str, force: bool = True) -> dict:
    """
    Obtain and store an access token for a registered connection (no UI, blocking).

    Reuses a still-valid stored token unless ``force``. Runs the library's network
    calls, so call it from a thread (``authenticate_connection`` / ``ensure_authenticated``).

    Returns ``{"success": True, "token_expires_at": iso}`` or
    ``{"success": False, "error": str}``.
    """
    connection = db.signet_connections.get(keys=(connection_id,))
    if connection is None:
        return {"success": False, "error": "Connection not found."}
    if not force and connection.has_valid_token():
        logger.info(f"Connection {connection_id}: reusing valid access token")
        return {"success": True, "token_expires_at": connection.token_expires_at}
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
    info = presenting.connection_info(connection)
    info.client_id = client_id

    try:
        result = _obtain_token(vault, info)
    except ACDCOAuthError as exc:
        return {"success": False, "error": exc.message or "Authentication failed."}

    # The expiry was computed once at receipt; never recomputed on read.
    result.apply_to(connection)
    db.signet_connections.pin(keys=(connection_id,), val=connection)
    logger.info(f"Connection {connection_id} authenticated")
    return {"success": True, "token_expires_at": connection.token_expires_at}


def authorized_connection(
    vault, db, connection_id: str, force: bool = False
) -> ConnectionInfo:
    """
    Authenticate (reusing a still-valid token unless ``force``) and return the connection
    re-read from the db as a ``ConnectionInfo``, so it carries the fresh access token.
    Raises RuntimeError on failure. Blocking: the ``get_connection`` of
    ``flows.call_with_reauth`` / ``flows.export_group``, which run in a thread.
    """
    result = authenticate_sync(vault, db, connection_id, force)
    if not result.get("success"):
        raise RuntimeError(result.get("error", "Authentication failed."))
    connection = db.signet_connections.get(keys=(connection_id,))
    if connection is None:
        raise RuntimeError("Connection not found.")
    return presenting.connection_info(connection)


async def authenticate_connection(vault, db, connection_id: str) -> dict:
    """Obtain and store a fresh access token for a registered connection (no UI)."""
    return await asyncio.to_thread(authenticate_sync, vault, db, connection_id, True)


async def ensure_authenticated(vault, db, connection_id: str) -> dict:
    """Reuse a still-valid stored token, else authenticate; same return shape."""
    return await asyncio.to_thread(authenticate_sync, vault, db, connection_id, False)


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
