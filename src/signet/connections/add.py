# -*- encoding: utf-8 -*-
"""
signet.connections.add module

Dialog for adding a new UDAP vLEI onboarding connection: pick a discovered
partner, pick the credential to present, submit the onboarding request, and
immediately poll once for the (rare) case where the request is approved
inline -- per the onboarding design doc's idempotency semantics. Discovery
of partners is assumed already done; the dropdown is just the fixture list
in mock_data minus whichever partners already have a SignetConnection.
"""

from collections.abc import Callable

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
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox

from ..core import credentials, mock_data, remoting
from ..db.basing import SignetConnection

logger = help.ogler.getLogger(__name__)


class AddConnectionDialog(LocksmithDialog):
    """Dialog for submitting a new onboarding request to a discovered partner."""

    def __init__(self, app, on_success: Callable[[], None] | None = None, parent=None):
        self.app = app
        self.on_success = on_success
        self._partner_by_display: dict[str, dict] = {}
        self._credential_by_display: dict[str, dict] = {}
        self._is_submitting = False

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 10, 0, 0)
        content_layout.setSpacing(12)

        desc = QLabel("Select a partner to onboard with.")
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 14px; color: {colors.TEXT_SUBTLE};")
        content_layout.addWidget(desc)

        self.partner_selector = FloatingLabelComboBox(label_text="Select a connection")
        self.partner_selector.setFixedWidth(420)
        content_layout.addWidget(self.partner_selector)

        self.detail_section = QWidget()
        detail_layout = QVBoxLayout(self.detail_section)
        detail_layout.setContentsMargins(0, 10, 0, 0)
        detail_layout.setSpacing(10)

        self.url_label = QLabel("")
        self.url_label.setStyleSheet(f"font-size: 13px; color: {colors.TEXT_SUBTLE};")
        self.url_label.setWordWrap(True)
        detail_layout.addWidget(self.url_label)

        self.credential_selector = FloatingLabelComboBox(label_text="Select Credential")
        self.credential_selector.setFixedWidth(420)
        detail_layout.addWidget(self.credential_selector)

        self.detail_section.setVisible(False)
        content_layout.addWidget(self.detail_section)

        content_layout.addStretch()

        button_row = QHBoxLayout()
        button_row.addStretch()
        self.cancel_btn = LocksmithInvertedButton("Cancel")
        button_row.addWidget(self.cancel_btn)
        button_row.addSpacing(10)
        self.submit_btn = LocksmithButton("Add Connection")
        self.submit_btn.setEnabled(False)
        button_row.addWidget(self.submit_btn)

        super().__init__(
            parent=parent,
            title="Add Connection",
            title_icon=":/assets/material-icons/p2p.svg",
            content=content_widget,
            buttons=button_row,
        )

        self.setFixedSize(480, 420)

        self.cancel_btn.clicked.connect(self.close)
        self.submit_btn.clicked.connect(self._on_submit)
        self.partner_selector.currentIndexChanged.connect(self._on_partner_selected)

        self._populate_partner_dropdown()

    def _get_db(self):
        if not self.app or not self.app.vault:
            return None
        return self.app.vault.plugin_state.get("signet", {}).get("db")

    def _populate_partner_dropdown(self):
        db = self._get_db()
        existing_ids: set[str] = set()
        if db is not None:
            existing_ids = {
                connection_id
                for connection_id, _ in db.signet_connections.getItemIter()
            }

        self.partner_selector.clear()
        self._partner_by_display.clear()

        for partner in mock_data.DISCOVERABLE_CONNECTIONS:
            if partner["connection_id"] in existing_ids:
                continue
            display = partner["display_name"]
            self._partner_by_display[display] = partner
            self.partner_selector.addItem(display)

        if not self._partner_by_display:
            self.partner_selector.setEnabled(False)

    def _on_partner_selected(self, _index: int):
        display = self.partner_selector.currentText()
        partner = self._partner_by_display.get(display)

        if partner is None:
            self.detail_section.setVisible(False)
            self.submit_btn.setEnabled(False)
            return

        self.url_label.setText(f"URL: {partner['base_url']}")
        self._populate_credential_dropdown()
        self.detail_section.setVisible(True)
        self.submit_btn.setEnabled(True)

    def _populate_credential_dropdown(self):
        self.credential_selector.clear()
        self._credential_by_display.clear()

        vault = self.app.vault if self.app else None
        for credential in credentials.filter_legal_entity_subunit_credentials(vault):
            display = credential.get("title") or credential.get("said", "Credential")
            self._credential_by_display[display] = credential
            self.credential_selector.addItem(display)

    def _on_submit(self):
        if self._is_submitting:
            return

        display = self.partner_selector.currentText()
        partner = self._partner_by_display.get(display)
        if partner is None:
            self.show_error("Select a connection to add.")
            return

        credential_display = self.credential_selector.currentText()
        credential = self._credential_by_display.get(credential_display)
        if credential is None:
            self.show_error("Select a credential to present.")
            return

        self._is_submitting = True
        self.submit_btn.setEnabled(False)
        self.submit_btn.setText("Adding...")
        self.clear_error()
        self._do_submit(partner, credential)

    @qasync.asyncSlot()
    async def _do_submit(self, partner: dict, credential: dict):
        db = self._get_db()
        if db is None:
            self.show_error("No signet database available.")
            self._reset_submit_button()
            return

        try:
            connection_packet = {
                "display_name": partner["display_name"],
                "purpose": partner.get("purpose", ""),
                "credential_said": credential.get("said", ""),
            }

            submit_result = await remoting.submit_onboarding(
                partner["base_url"], connection_packet
            )
            if not submit_result.get("success"):
                self.show_error(
                    submit_result.get("error", "Failed to submit onboarding request.")
                )
                return

            onboarding_id = submit_result.get("onboarding_id", "")
            status = submit_result.get("status", "needs_approval")

            # Per the design doc's idempotency semantics, immediately follow
            # the submission with one poll to catch an already-approved
            # decision.
            poll_result = await remoting.poll_onboarding(
                partner["base_url"], onboarding_id
            )
            if poll_result.get("success") and poll_result.get("terminal"):
                status = poll_result.get("status", status)

            connection = SignetConnection(
                connection_id=partner["connection_id"],
                display_name=partner["display_name"],
                logo_icon_path=partner.get("logo_icon_path", ""),
                base_url=partner["base_url"],
                status=self._normalize_status(status),
                onboarding_id=onboarding_id,
                purpose=partner.get("purpose", ""),
                selected_credential_said=credential.get("said", ""),
                last_checked_at=helping.nowIso8601(),
            )
            db.signet_connections.pin(keys=(connection.connection_id,), val=connection)

            logger.info(
                f"Added connection {connection.connection_id} with status {connection.status}"
            )

            self.close()

            if self.on_success:
                self.on_success()

            if connection.status == "approved":
                self._open_dcr_gate(connection)
        except Exception as exc:
            logger.exception(f"AddConnectionDialog: failed to add connection: {exc}")
            self.show_error(f"Failed to add connection: {exc}")
        finally:
            self._reset_submit_button()

    @staticmethod
    def _normalize_status(status: str) -> str:
        """Map onboarding-doc status strings onto the 4-bucket SignetConnection.status."""
        if status == "approved":
            return "approved"
        if status == "rejected":
            return "rejected"
        return "needs_approval"

    def _reset_submit_button(self):
        self._is_submitting = False
        self.submit_btn.setEnabled(True)
        self.submit_btn.setText("Add Connection")

    def _open_dcr_gate(self, connection: SignetConnection):
        from .dcr_gate import DynamicClientRegistrationGateDialog

        dialog = DynamicClientRegistrationGateDialog(
            app=self.app,
            connection_id=connection.connection_id,
            on_success=self.on_success,
            parent=self.parent(),
        )
        dialog.show()
