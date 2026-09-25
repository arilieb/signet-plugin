# -*- encoding: utf-8 -*-
"""
signet.db.basing module

Signet-specific dataclasses and database (SignetBaser). Fully independent of
locksmith core's healthKERI connections store -- signet owns its own
list/state entirely.
"""
from dataclasses import dataclass, field

from keri import help
from keri.db import dbing, koming
from keri.help import helping

logger = help.ogler.getLogger(__name__)


@dataclass
class SignetConnection:
    """A single UDAP vLEI onboarding connection tracked by the signet plugin."""

    connection_id: str
    display_name: str = ""  # Person/org display name (e.g. "Onyx")
    logo_icon_path: str = ""
    base_url: str = ""  # Onyx server URL for this connection
    status: str = "needs_approval"  # needs_approval | approved | rejected | registered
    onboarding_id: str = ""
    purpose: str = ""
    decision_due: str = ""
    selected_credential_said: str = ""
    client_id: str = ""  # Populated post-DCR
    created_at: str = field(default_factory=helping.nowIso8601)
    last_checked_at: str = ""


class SignetBaser(dbing.LMDBer):
    """Plugin-owned database for signet connection state.

    Kept separate from locksmith core's LMDB so signet's Connection model
    does not share storage with the existing healthKERI connections UI.
    """
    TailDirPath = "keri/signet"
    AltTailDirPath = ".keri/signet"
    TempPrefix = "rt"

    def __init__(self, name="signet", headDirPath=None, reopen=True, **kwa):
        self.signet_connections = None

        super(SignetBaser, self).__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, readonly=False, **kwa):
        super(SignetBaser, self).reopen(readonly, **kwa)

        self.signet_connections = koming.Komer(
            db=self,
            subkey='conn.',
            schema=SignetConnection,
        )

        return self.env
