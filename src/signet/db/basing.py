# -*- encoding: utf-8 -*-
"""
signet.db.basing module

Signet-specific dataclasses and database (SignetBaser). Fully independent of
locksmith core's healthKERI connections store -- signet owns its own
list/state entirely.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

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
    # Onboarding state added with the grant-based flow. Every field is
    # defaulted so connections pinned before these existed still deserialize.
    hab_name: str = ""  # Local identifier that signed and presented
    hab_aid: str = ""
    correlation_id: str = ""
    server_aid: str = ""
    poll_url: str = ""  # Absolute URL from Content-Location
    retry_after: str = ""
    purpose_status: str = ""  # Server-side status: in-review, approved, ...
    decision_provenance: dict = field(default_factory=dict)
    last_error: str = ""
    # DCR client metadata (ONBOARDING.md S4.4). redirect_uris are approved with
    # onboarding; scopes are what the server granted at registration.
    redirect_uris: list = field(default_factory=list)
    client_name: str = ""
    scopes: str = ""
    # Access token from the Authenticate action (client_credentials). Stored
    # plaintext in LMDB like the rest of the connection record.
    # token_expires_at is computed once at receipt (now + expires_in), never on read.
    access_token: str = ""
    token_type: str = ""
    token_scope: str = ""
    token_expires_at: str = ""  # ISO-8601
    last_authenticated_at: str = ""

    def has_valid_token(self) -> bool:
        """True while a stored access token has not yet expired."""
        if not self.access_token or not self.token_expires_at:
            return False
        try:
            expires = datetime.fromisoformat(self.token_expires_at)
        except ValueError:
            return False
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires > datetime.now(timezone.utc)


@dataclass
class ClientIdPin:
    """The ``client_id`` a server issued at DCR for one (AID, credential SAID)."""

    client_id: str
    registered_at: str = field(default_factory=helping.nowIso8601)


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
        self.client_ids = None

        super(SignetBaser, self).__init__(
            name=name, headDirPath=headDirPath, reopen=reopen, **kwa
        )

    def reopen(self, readonly=False, **kwa):
        super(SignetBaser, self).reopen(readonly, **kwa)

        self.signet_connections = koming.Komer(
            db=self,
            subkey="conn.",
            schema=SignetConnection,
        )
        # Keyed (connection_id, aid, said). The user's binding is (AID, SAID) ->
        # client_id; connection_id is prepended because the same AID and
        # credential may register with two servers that issue different ids.
        self.client_ids = koming.Komer(
            db=self,
            subkey="cid.",
            schema=ClientIdPin,
        )

        return self.env

    def pin_client_id(
        self, connection_id: str, aid: str, said: str, client_id: str
    ) -> None:
        """Bind ``client_id`` to (aid, said) on a connection, replacing any prior pin."""
        if not client_id:
            raise ValueError("client_id must not be empty")
        self.client_ids.pin(
            keys=(connection_id, aid, said), val=ClientIdPin(client_id=client_id)
        )

    def get_client_id(self, connection_id: str, aid: str, said: str) -> str | None:
        """The client_id pinned to (aid, said) on a connection, or None."""
        pin = self.client_ids.get(keys=(connection_id, aid, said))
        return pin.client_id if pin is not None else None

    def rem_client_ids(self, connection_id: str) -> None:
        """Remove every client_id pin of a connection."""
        self.client_ids.trim(keys=(connection_id, ""))

    def resolve_client_id(self, connection: SignetConnection) -> str | None:
        """
        The client_id pinned to the connection's current (hab_aid, credential SAID).

        A registered legacy record that has ``client_id`` but no pin is pinned
        lazily from its own (immutable) ``hab_aid`` and ``selected_credential_said``,
        which are what produced that DCR response. Only done when the connection
        has no pins at all, so a stale ``client_id`` is never bound to a different
        credential. Never falls back to the SAID.
        """
        aid, said = connection.hab_aid, connection.selected_credential_said
        client_id = self.get_client_id(connection.connection_id, aid, said)
        if (
            client_id is None
            and connection.client_id
            and aid
            and said
            and not any(
                self.client_ids.getItemIter(keys=(connection.connection_id, ""))
            )
        ):
            self.pin_client_id(
                connection.connection_id, aid, said, connection.client_id
            )
            client_id = connection.client_id
        return client_id
