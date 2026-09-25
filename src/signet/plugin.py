# -*- encoding: utf-8 -*-
"""
signet.plugin module

SignetPlugin -- registers the Keriguard Signet Connections page and menu.

No AccountProviderPlugin mixin and no ESSR client: per explicit instruction
this plugin needs no setup gate or account-creation flow. FHIR APIs is a
disabled placeholder menu entry with no page registered -- it exists but
never triggers navigation.
"""

from __future__ import annotations

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QWidget
from keri import help
from locksmith.plugins.base import PluginBase
from locksmith.ui.toolkit.widgets.buttons import BackButton
from locksmith.ui.vault.menu import MenuButton, MenuSpacer

from .connections.list import ConnectionsListPage
from .core import mock_data
from .db.basing import SignetBaser

logger = help.ogler.getLogger(__name__)


class SignetPlugin(PluginBase):
    """Keriguard Signet plugin -- Connections CRUD for Onyx's UDAP vLEI onboarding flow."""

    def __init__(self):
        self._app = None
        self._db: SignetBaser | None = None
        self._pages: dict[str, QWidget] = {}
        self._entry_button: MenuButton | None = None
        self._submenu_items: list[QWidget] = []
        self._nav_buttons_by_page: dict[str, MenuButton] = {}

    @property
    def plugin_id(self) -> str:
        return "signet"

    def get_description(self) -> str:
        return (
            "Keriguard Signet integration for Onyx's UDAP vLEI onboarding flow: submit an "
            "onboarding request, track approval status, and complete Dynamic Client Registration."
        )

    def initialize(self, app, parent) -> None:
        self._app = app
        self._pages = {
            "signet_connections_list": ConnectionsListPage(app, parent=None),
        }
        self._build_menu()

    # -------------------------------------------------------------------------
    # Menu
    # -------------------------------------------------------------------------

    def _build_menu(self) -> None:
        self._entry_button = MenuButton(
            QIcon(":/assets/material-icons/verified.svg"),
            "Keriguard Signet",
        )
        self._entry_button.is_account_btn = True
        self._submenu_items = self._create_submenu_items()

    def _create_submenu_items(self) -> list[QWidget]:
        items: list[QWidget] = [BackButton(dark_mode=False), MenuSpacer(10)]

        connections_btn = MenuButton(
            QIcon(":/assets/material-icons/p2p.svg"), "Connections"
        )
        connections_btn.clicked.connect(
            self._make_nav_handler("signet_connections_list", connections_btn)
        )
        items.append(connections_btn)
        self._nav_buttons_by_page["signet_connections_list"] = connections_btn

        # FHIR APIs: menu item exists but never triggers navigation or logic.
        fhir_btn = MenuButton(QIcon(":/assets/material-icons/api.svg"), "FHIR APIs")
        fhir_btn.setEnabled(False)
        fhir_btn.setToolTip("Coming soon")
        items.append(fhir_btn)

        return items

    def _make_nav_handler(self, page_key: str, button: MenuButton):
        def handler():
            for item in self._submenu_items:
                if isinstance(item, MenuButton):
                    item.set_active(False)
            button.set_active(True)
            self._navigate(page_key)

        return handler

    def _navigate(self, page_key: str) -> None:
        vault_page = self._get_vault_page()
        if vault_page:
            vault_page._show_page(page_key)
            page = self._pages.get(page_key)
            if page and hasattr(page, "on_show"):
                page.on_show()

    def _get_vault_page(self):
        if hasattr(self._app, "_vault_page"):
            return self._app._vault_page
        return None

    # -------------------------------------------------------------------------
    # PluginBase lifecycle
    # -------------------------------------------------------------------------

    def on_vault_opened(self, vault) -> None:
        self._db = SignetBaser(name=vault.hby.name, reopen=True)
        vault.plugin_state["signet"] = {"db": self._db}

        if next(self._db.signet_connections.getItemIter(), None) is None:
            for connection in mock_data.seed_connections():
                self._db.signet_connections.pin(
                    keys=(connection.connection_id,), val=connection
                )

    def on_vault_closed(self, vault) -> None:
        vault.plugin_state.pop("signet", None)
        if self._db:
            self._db.close()
            self._db = None

    def get_menu_entry(self) -> MenuButton:
        return self._entry_button

    def get_menu_section(self) -> list[QWidget]:
        return self._submenu_items

    def get_pages(self) -> dict[str, QWidget]:
        return self._pages
