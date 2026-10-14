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
  or issue-chain-lesr-subunit.sh land in the vault;
- optionally (SIGNET_DEV_LESR_AUTH_FILE), issue the LESR Authorization of the
  simple LESR chain (issue-chain-lesr-simple.sh) from the holder in-process.

Credentials are issued externally by the scripts, except that LESR Auth: in the
simple chain the holder is the Legal Entity AID, whose keys only the vault has.
"""

import json
import os
import time
from types import SimpleNamespace

from hio.base import doing
from keri import help
from keri.core import coring, serdering
from keri.core.eventing import OobiRecord, SealEvent
from keri.help import helping
from keri.kering import Kinds

from locksmith.core import ipexing

from .credentials import LEGAL_ENTITY_SCHEMA_SAID

logger = help.ogler.getLogger(__name__)

HOLDER_ALIAS = "signet-dev-holder"
WITNESS_OOBIS = (
    "http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller",
    "http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller",
    "http://127.0.0.1:5644/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller",
)
WITNESS_AIDS = tuple(oobi.split("/")[4] for oobi in WITNESS_OOBIS)
SCHEMA_SERVER = "http://127.0.0.1:7723"
# LESR Authorization schema (keep in sync with SCHEMA_LESR_AUTH in scripts/dev-live/env.sh)
LESR_AUTH_SCHEMA_SAID = "ECoqb1jxC9f9zwh664stMAy6gpnNduvP_3SCQlLvkPAR"
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


def lesr_auth_config() -> dict | None:
    """
    ``{"attributes": ..., "rules": ...}`` from the file named by SIGNET_DEV_LESR_AUTH_FILE
    (written by issue-chain-lesr-simple.sh), or None when unset or unreadable.
    """
    path = os.environ.get("SIGNET_DEV_LESR_AUTH_FILE", "").strip()
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        logger.warning("Cannot read SIGNET_DEV_LESR_AUTH_FILE %s: %s", path, exc)
        return None
    if not isinstance(data, dict) or not isinstance(data.get("attributes"), dict):
        logger.warning("SIGNET_DEV_LESR_AUTH_FILE %s has no attributes object", path)
        return None
    return data


def _credentials_of(reger, index, pre: str, schema_said: str):
    """Credentials in ``reger.<index>[pre]`` (issus or subjs) of ``schema_said``."""
    found = []
    for saider in index.get(keys=(pre,)):
        creder = reger.creds.get(keys=(saider.qb64,))
        if creder is not None and creder.sad.get("s") == schema_said:
            found.append(creder)
    return found


def lesr_auth_target(reger, holder_pre: str):
    """The admitted LE credential issued to the holder (the Legal Entity AID), or None."""
    for creder in _credentials_of(
        reger, reger.subjs, holder_pre, LEGAL_ENTITY_SCHEMA_SAID
    ):
        if reger.saved.get(keys=creder.said) is not None:
            return creder
    return None


def issued_lesr_auth(reger, holder_pre: str) -> str | None:
    """SAID of a LESR Auth the holder has already issued, or None."""
    issued = _credentials_of(reger, reger.issus, holder_pre, LESR_AUTH_SCHEMA_SAID)
    return issued[0].said if issued else None


class LesrAuthState:
    """Per-process progress of the LESR Auth step, so a pass never repeats work in flight."""

    def __init__(self, retry_after: float = 60.0):
        self.busy = False
        self.auth_said: str | None = None
        self.granted = False
        self.retry_after = retry_after
        self.retry_at = 0.0


def lesr_auth_next(reger, hab, state: LesrAuthState, config, now: float):
    """
    What the LESR Auth step should do on this pass: ``("issue", le_creder)``,
    ``("grant", auth_said)`` or None.

    Needs SIGNET_DEV_LESR_AUTH_FILE (``config``) and an admitted LE credential
    issued to the holder; the LE credential's issuer is the QVI the Auth goes to.
    """
    if config is None or state.busy or now < state.retry_at:
        return None
    le = lesr_auth_target(reger, hab.pre)
    if le is None:
        return None
    auth_said = state.auth_said or issued_lesr_auth(reger, hab.pre)
    if auth_said is None:
        return "issue", le
    if not state.granted:
        return "grant", auth_said
    return None


def lesr_auth_do(
    vault, state: LesrAuthState, hab, action, config, tock=0.0, timeout=120.0
):
    """
    Doer generator: issue the LESR Auth from ``hab`` (to the QVI that issued the LE
    credential, with an I2I ``le`` edge) and IPEX-grant it to the QVI.

    Modeled on locksmith's IssueCredentialDoer and SendGrantDoer, but driven off the
    vault's own registrar and credentialer. Completion is state-based (the TEL/KEL
    witness receipts), so a failure just logs and the next maintenance pass retries.
    """
    kind, subject = action

    def do(tymth, tock=tock, **kwa):
        yield tock
        try:
            rgy, registrar, credentialer = (
                vault.rgy,
                vault.registrar,
                vault.credentialer,
            )
            if kind == "issue":
                le = subject
                qvi = le.sad["i"]
                registry = rgy.registryByName(LESR_AUTH_SCHEMA_SAID)
                if registry is not None and registry.hab.pre != hab.pre:
                    raise RuntimeError(
                        "registry for the LESR Auth schema is another AID's"
                    )
                if registry is None:
                    registry = rgy.makeRegistry(
                        name=LESR_AUTH_SCHEMA_SAID,
                        prefix=hab.pre,
                        nonce=coring.randomNonce(),
                    )
                    rseal = SealEvent(registry.regk, "0", registry.regd)
                    anc = hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])
                    registrar.incept(
                        iserder=registry.vcp, anc=serdering.SerderKERI(raw=bytes(anc))
                    )
                    deadline = time.monotonic() + timeout
                    while not registrar.complete(pre=registry.regk, sn=0):
                        rgy.processEscrows()
                        if time.monotonic() > deadline:
                            raise TimeoutError("registry inception was not receipted")
                        yield tock
                    logger.info("Created LESR Auth registry %s", registry.regk)

                edges = {
                    "d": "",
                    "le": {"n": le.said, "s": LEGAL_ENTITY_SCHEMA_SAID, "o": "I2I"},
                }
                _, edges = coring.Saider.saidify(
                    sad=edges, kind=Kinds.json, label=coring.Saids.d
                )
                creder = credentialer.create(
                    regname=LESR_AUTH_SCHEMA_SAID,
                    recp=qvi,
                    schema=LESR_AUTH_SCHEMA_SAID,
                    source=edges,
                    rules=config.get("rules") or {},
                    data=config["attributes"],
                    private=False,
                )
                state.auth_said = (
                    creder.said
                )  # remembered before the waits: never issue twice
                dt = creder.attrib.get("dt") or helping.nowIso8601()
                iserder = registry.issue(said=creder.said, dt=dt)
                rseal = SealEvent(iserder.pre, iserder.snh, iserder.said)
                seal = dict(i=rseal.i, s=rseal.s, d=rseal.d)
                if registry.estOnly:
                    anc = hab.rotate(data=[seal])
                else:
                    anc = hab.interact(data=[seal])
                credentialer.issue(creder, iserder)
                registrar.issue(creder, iserder, serdering.SerderKERI(raw=bytes(anc)))
                deadline = time.monotonic() + timeout
                while not credentialer.complete(said=creder.said):
                    rgy.processEscrows()
                    if time.monotonic() > deadline:
                        raise TimeoutError("LESR Auth issuance was not receipted")
                    yield tock
                logger.info("Issued LESR Auth %s to %s", creder.said, qvi)
                auth_said = creder.said
                qvi_pre = qvi
            else:
                auth_said = subject
                qvi_pre = rgy.reger.creds.get(keys=(auth_said,)).attrib["i"]

            # IPEX-grant it to the QVI (admit is idempotent, so a repeat after a restart is harmless)
            grant = ipexing.SendGrantDoer(
                SimpleNamespace(vault=vault, rgy=rgy),
                hab_pre=hab.pre,
                credential_said=auth_said,
                recipient_pre=qvi_pre,
            )
            vault.extend([grant])
            deadline = time.monotonic() + timeout
            while not grant.done and time.monotonic() <= deadline:
                yield tock
            vault.remove([grant])
            if not grant.done:
                raise TimeoutError("LESR Auth grant was not delivered")
            state.granted = True
            logger.info("Granted LESR Auth %s to %s", auth_said, qvi_pre)
        except Exception as exc:
            logger.warning("LESR Auth step failed (retrying): %s", exc)
            state.retry_at = time.monotonic() + state.retry_after
        finally:
            state.busy = False

    return doing.doify(do)


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
        auth_state = LesrAuthState()
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
                if hab is not None and witnessed:
                    config = lesr_auth_config()
                    action = lesr_auth_next(
                        vault.rgy.reger, hab, auth_state, config, time.monotonic()
                    )
                    if action is not None:
                        auth_state.busy = True  # until the doer's first pass
                        vault.extend(
                            [lesr_auth_do(vault, auth_state, hab, action, config)]
                        )
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
