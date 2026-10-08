# -*- encoding: utf-8 -*-
"""
signet.core.devbootstrap module

Live-dev bootstrap (SIGNET_LIVE=1 in the DEVELOPMENT environment). Idempotent
setup of the holder state the real onboarding flow needs against local
infrastructure (kli witness demo, vLEI-server, registrar, echelon-server):

- queue OOBI resolution for the demo witnesses, the vLEI schemas, and any
  extra OOBIs (e.g. the QVI and LE AIDs) in SIGNET_DEV_OOBIS;
- create a witnessed holder AID named ``signet-dev-holder``;
- from a vault doer, poll the holder's witnesses as mailboxes (Locksmith's
  director does not), request witness receipts for the holder once the witness
  OOBIs have resolved, and admit pending IPEX grants addressed to local
  identifiers, so credentials issued by scripts/dev-live/issue-chain-ecr.sh
  or issue-chain-lesr.sh land in the vault.

The credentials themselves are issued externally; issuing in-process is out
of scope.
"""

import os
import time

from hio.base import doing
from keri import help
from keri.core.eventing import OobiRecord
from keri.help import helping

from locksmith.core import ipexing

logger = help.ogler.getLogger(__name__)

HOLDER_ALIAS = "signet-dev-holder"
WITNESS_OOBIS = (
    "http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller",
    "http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller",
    "http://127.0.0.1:5644/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller",
)
WITNESS_AIDS = tuple(oobi.split("/")[4] for oobi in WITNESS_OOBIS)
SCHEMA_SERVER = "http://127.0.0.1:7723"
# QVI, LE, ECR Auth, ECR, LE Subunit, LESR Auth, LESR schemas (keep in sync with scripts/dev-live/env.sh)
SCHEMA_SAIDS = (
    "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
    "EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g",
    "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw",
    "EP1jGIb7KXotuUZJf1NSu5wQ089epFfv93cpZECj-YBs",
    "ECoqb1jxC9f9zwh664stMAy6gpnNduvP_3SCQlLvkPAR",
    "EHfJ563sbivepFRzk506fJenWIeVG2uXdAes8iJhHJan",
)


def dev_oobis() -> list[str]:
    """All OOBIs to resolve: witnesses, schemas, then SIGNET_DEV_OOBIS (comma separated)."""
    extra = [o.strip() for o in os.environ.get("SIGNET_DEV_OOBIS", "").split(",")]
    return (
        list(WITNESS_OOBIS)
        + [f"{SCHEMA_SERVER}/oobi/{said}" for said in SCHEMA_SAIDS]
        + [o for o in extra if o]
    )


def queue_oobis(hby, oobis) -> None:
    """Queue OOBIs for the vault's Oobiery, skipping ones already queued or resolved."""
    for oobi in oobis:
        if hby.db.oobis.get(keys=(oobi,)) is not None:
            continue
        if hby.db.roobi.get(keys=(oobi,)) is not None:
            continue
        hby.db.oobis.pin(keys=(oobi,), val=OobiRecord(date=helping.nowIso8601()))


def ensure_holder(hby):
    """The witnessed ``signet-dev-holder`` hab, created on first call."""
    hab = hby.habByName(HOLDER_ALIAS)
    if hab is None:
        hab = hby.makeHab(
            name=HOLDER_ALIAS, wits=list(WITNESS_AIDS), toad=2, transferable=True
        )
    logger.info("Dev holder %s: %s", HOLDER_ALIAS, hab.pre)
    return hab


def witnesses_resolved(hab) -> bool:
    """True once the hab's witnesses' endpoints are known (their OOBIs resolved)."""
    return all(hab.fetchUrls(eid=wit) for wit in hab.kever.wits)


def ensure_witness_pollers(vault, hab) -> None:
    """
    Poll the holder's witnesses as mailboxes.

    Locksmith's MailboxDirector only polls explicitly activated mailboxes (not
    witnesses, unlike keripy's), yet witnesses deliver both their receipts and
    IPEX grants to the holder through their mailboxes.
    """
    active = {mailbox for _, pre, mailbox in vault.mbx.mailboxes if pre == hab.pre}
    for wit in hab.kever.wits:
        if wit not in active:
            vault.mbx.add_poller(hab=hab, mailbox=wit)


def maintain(vault, tock=2.0, interval=2.0, rerequest_after=30.0):
    """
    Doer generator: keep the dev holder receipted and its grants admitted.

    Receipt requests wait until the witness OOBIs have resolved (the receiptor
    raises, and kills the vault's doist, if a witness has no known endpoint).
    Pending grants are retried every ``interval`` seconds since they arrive by
    mailbox later. The doer is scheduled far more often than ``tock`` suggests,
    so everything is throttled on wall-clock time.
    """

    def do(tymth, tock=tock, **kwa):
        yield tock
        logger.info("Dev maintenance doer started")
        last_request = None
        last_run = 0.0
        while True:
            if time.monotonic() - last_run < interval:
                yield tock
                continue
            last_run = time.monotonic()
            try:
                hab = vault.hby.habByName(HOLDER_ALIAS)
                if hab is not None:
                    witnessed = vault.hby.db.fullyWitnessed(hab.kever.serder)
                    resolved = witnesses_resolved(hab)
                    if resolved:
                        ensure_witness_pollers(vault, hab)
                    if not witnessed and resolved:
                        if (
                            last_request is None
                            or time.monotonic() - last_request >= rerequest_after
                        ):
                            logger.info("Requesting witness receipts for %s", hab.pre)
                            vault.witDoer.msgs.append(dict(pre=hab.pre))
                            last_request = time.monotonic()
                admit_pending_grants(vault)
            except Exception as exc:
                logger.warning("Live-dev maintenance failed: %s", exc)
            yield tock

    return do


def admit_pending_grants(vault) -> list[str]:
    """Admit /ipex/grant messages to local habs whose credential isn't saved yet."""
    hby, rgy = vault.hby, vault.rgy
    admitted: list[str] = []
    # A credential's chain must be admitted before it: retry until a pass admits nothing.
    progress = True
    while progress:
        progress = False
        for (said,), serder in list(hby.db.exns.getItemIter()):
            if serder.ked.get("r") != "/ipex/grant":
                continue
            hab = hby.habs.get(serder.ked.get("a", {}).get("i", ""))
            if hab is None:
                continue
            acdc = serder.ked.get("e", {}).get("acdc", {})
            if not acdc or rgy.reger.saved.get(keys=acdc.get("d", "")):
                continue
            try:
                ipexing.Admitter(hby, hab, rgy).admit(said)
            except Exception as exc:
                logger.debug("Could not yet admit grant %s: %s", said, exc)
                continue
            admitted.append(acdc["d"])
            progress = True
    return admitted


def bootstrap(vault) -> None:
    """Run every idempotent live-dev setup step; failures are logged, not raised."""
    for step in (
        lambda: queue_oobis(vault.hby, dev_oobis()),
        lambda: ensure_holder(vault.hby),
        lambda: vault.extend([doing.doify(maintain(vault))]),
    ):
        try:
            step()
        except Exception as exc:
            logger.warning("Live-dev bootstrap step failed: %s", exc)
