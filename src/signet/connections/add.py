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
from typing import Hashable

import qasync
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget
from keri import help
from keri.help import helping

from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithButton,
    LocksmithDialog,
    LocksmithInvertedButton,
    SelectionRevealSection,
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
        self._partner_by_id: dict[str, dict] = {}
        self._credential_by_display: dict[str, dict] = {}
        self._credential_selectors: dict[str, FloatingLabelComboBox] = {}
        self._is_submitting = False

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 10, 0, 0)
        content_layout.setSpacing(12)

        desc = QLabel("Select a partner to onboard with.")
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 14px; color: {colors.TEXT_SUBTLE};")
        content_layout.addWidget(desc)

        self.partner_selector = SelectionRevealSection(
            label_text="Select a connection",
            on_selection_changed=self._on_partner_selected,
        )
        self.partner_selector.setFixedWidth(420)
        content_layout.addWidget(self.partner_selector)

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
            show_overlay=False
        )

        self.setFixedWidth(480)

        self.cancel_btn.clicked.connect(self.close)
        self.submit_btn.clicked.connect(self._on_submit)
        self.register_selection_section(self.partner_selector)

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

        self.partner_selector.clear_options()
        self._partner_by_id.clear()

        for partner in mock_data.DISCOVERABLE_CONNECTIONS:
            if partner["connection_id"] in existing_ids:
                continue
            connection_id = partner["connection_id"]
            self._partner_by_id[connection_id] = partner
            card = self._build_partner_card(partner)
            self.partner_selector.add_option(connection_id, partner["display_name"], card)

        if not self._partner_by_id:
            self.partner_selector.setEnabled(False)

    def _build_partner_card(self, partner: dict) -> QWidget:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 10, 0, 0)
        page_layout.setSpacing(10)

        card = QFrame()
        card.setFixedWidth(420)
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {colors.BACKGROUND_CONTENT};
                border: 1px solid {colors.BORDER_NEUTRAL};
                border-radius: 8px;
            }}
        """)

        layout = QHBoxLayout(card)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        icon_label = QLabel()
        icon = QIcon(partner.get("logo_icon_path", ""))
        icon_label.setPixmap(icon.pixmap(32, 32))
        icon_label.setFixedSize(32, 32)
        icon_label.setStyleSheet(f"border: none;")

        layout.addWidget(icon_label)

        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(4)

        name_label = QLabel(partner["display_name"])
        name_label.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {colors.TEXT_PRIMARY}; border: none;")
        text_layout.addWidget(name_label)

        url_label = QLabel(partner.get("base_url", ""))
        url_label.setWordWrap(True)
        url_label.setStyleSheet(f"font-size: 12px; color: {colors.TEXT_SUBTLE}; border: none;")
        text_layout.addWidget(url_label)

        layout.addLayout(text_layout)

        page_layout.addWidget(card)

        credential_selector = FloatingLabelComboBox(label_text="Select Credential")
        credential_selector.setFixedWidth(420)
        page_layout.addWidget(credential_selector)
        self._credential_selectors[partner["connection_id"]] = credential_selector
        self._populate_credential_dropdown(credential_selector)

        page.adjustSize()
        return page

    def _on_partner_selected(self, key: Hashable):
        if key is SelectionRevealSection.NONE_KEY:
            self.submit_btn.setEnabled(False)
            return
        self.submit_btn.setEnabled(True)

    def _populate_credential_dropdown(self, selector: FloatingLabelComboBox):
        vault = self.app.vault if self.app else None
        for credential in credentials.filter_legal_entity_subunit_credentials(vault):
            display = credential.get("title") or credential.get("said", "Credential")
            self._credential_by_display[display] = credential
            selector.addItem(display)

    def _on_submit(self):
        if self._is_submitting:
            return

        connection_id = self.partner_selector.currentData()
        partner = self._partner_by_id.get(connection_id)
        if partner is None:
            self.show_error("Select a connection to add.")
            return

        selector = self._credential_selectors.get(connection_id)
        credential_display = selector.currentText() if selector else ""
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
