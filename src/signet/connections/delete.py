# -*- encoding: utf-8 -*-
"""
signet.connections.delete module

Dialog for deleting a locally-tracked signet connection record. There is no
remote delete endpoint in the UDAP vLEI onboarding design -- deletion only
removes the connection from the plugin's own SignetBaser.
"""

from collections.abc import Callable

from keri import help
from locksmith.ui.toolkit.widgets.dialogs import LocksmithResourceDeletionDialog

logger = help.ogler.getLogger(__name__)


class DeleteConnectionDialog(LocksmithResourceDeletionDialog):
    """Dialog for confirming and deleting a signet connection record."""

    def __init__(
        self,
        db,
        connection_id: str,
        display_name: str,
        on_success: Callable[[str], None] | None = None,
        parent=None,
    ):
        self.db = db
        self.connection_id = connection_id
        self.on_success = on_success

        super().__init__(
            parent=parent,
            resource_type="connection",
            resource_name=display_name,
            title_icon=":/assets/material-icons/delete.svg",
        )

        self.delete_button.clicked.disconnect(self.accept)
        self.delete_button.clicked.connect(self._do_delete)

    def _do_delete(self):
        """Handle the delete button click and remove the connection record."""
        try:
            self.db.signet_connections.rem(keys=(self.connection_id,))
        except Exception as exc:
            logger.exception(
                f"DeleteConnectionDialog: failed to delete connection {self.connection_id}: {exc}"
            )
            self.show_error(f"Failed to delete connection: {exc}")
            return

        logger.info(f"Connection {self.connection_id} deleted")

        if self.on_success:
            self.on_success(self.connection_id)

        self.accept()
