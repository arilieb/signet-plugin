# -*- encoding: utf-8 -*-
"""
signet.core.presenting module

Builds the onboarding request described in echelon-server's ONBOARDING.md
(S4, D24): a single IPEX grant exn of the presented credential, addressed to
the server, whose ``a.udap`` block carries the typed OOBIs and the requested
purposes, contacts and redirect URIs. The sender's exn signature is the only
signature; the body of POST /udap/onboarding is the raw CESR message.

With SIGNET_ONBOARDING_FORMAT=json the grant is instead wrapped in a JSON
submission packet (SUBMISSION_SHAPE.md) that carries the metadata itself. Its
``ipex_grant`` is the whole credential chain as one CESR stream, in the shape
``kli ipex grant`` sends: KELs, TELs and source credentials, then the grant exn.
"""

import json
import uuid
from dataclasses import dataclass
from typing import Any

from keri import help
from keri.app import signing
from keri.core import coring, serdering
from keri import kering
from keri.peer import exchanging
from keri.help import helping
from keri.vdr import credentialing

from . import configing
from .credentials import LE_SUBUNIT_SCHEMA_SAID, LEGAL_ENTITY_SCHEMA_SAID

logger = help.ogler.getLogger(__name__)

REQUESTED_PURPOSE = "TREAT"

# Demo values for the JSON submission packet (SUBMISSION_SHAPE.md); not user-entered yet.
DEMO_LEI = "549300QKBENKLBXQ8968"
DEMO_QVI_LEI = "254900OPPU84GM83MG36"
DEMO_TECHNICAL_CONTACT = "interop-eng@healthkeri.com"
DEMO_SECURITY_CONTACT = "security@healthkeri.com"
DCR_STATEMENT_TYPE = "urn:ietf:params:oauth:software-statement-type:acdc-vlei"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:acdc-vlei"


class PresentingError(Exception):
    """The onboarding request could not be built."""


@dataclass
class OnboardingRequest:
    """A fully built onboarding POST: raw CESR grant bytes, or a JSON packet."""

    url: str
    body: bytes
    correlation_id: str
    content_type: str = "application/cesr"
    hab_name: str = ""
    hab_aid: str = ""
    server_aid: str = ""


def _grant_embeds(vault, credential_said: str) -> dict[str, Any]:
    """acdc / reg / iss / anc streams of a received credential, as a grant embeds."""
    reger = vault.rgy.reger
    creder, prefixer, seqner, saider = reger.cloneCred(said=credential_said)
    if creder is None:
        raise PresentingError(f"Credential {credential_said} is not in the vault.")

    try:
        acdc = signing.serialize(creder, prefixer, seqner, saider)
        reg = reger.cloneTvtAt(creder.regi)
        iss = reger.cloneTvtAt(creder.said)

        iserder = serdering.SerderKERI(raw=bytes(iss))
        iseqner = coring.Seqner(sn=iserder.sn)
        serder = vault.hby.db.fetchLastSealingEventByEventSeal(
            creder.sad["i"],
            seal=dict(i=iserder.pre, s=iseqner.snh, d=iserder.said),
        )
        anc = vault.hby.db.cloneEvtMsg(pre=serder.pre, fn=0, dig=serder.said)
    except Exception as exc:
        raise PresentingError(f"Unable to build grant for the credential: {exc}")

    return dict(acdc=acdc, reg=reg, iss=iss, anc=anc)


def _build_grant_message(
    vault,
    hab,
    server_aid: str,
    credential_said: str,
    udap: dict[str, Any] | None,
) -> bytearray:
    """
    Raw CESR IPEX grant exn of ``credential_said`` from ``hab`` to ``server_aid``.

    ``udap=None`` builds a plain grant (``a`` is just ``{m, i}``).

    ``ipexGrantExn`` fixes ``a`` to ``{m, i}``, so the exn is built with
    ``exchanging.exchange`` and endorsed with ``last=False`` (the server only
    processes transferable ``tsgs`` groups). ``dt`` is taken at call time: it is
    the server's replay guard, so build a fresh message per request.
    """
    embeds = _grant_embeds(vault, credential_said)
    payload = dict(m="", i=server_aid)
    if udap is not None:
        payload["udap"] = udap
    exn, end = exchanging.exchange(
        route="/ipex/grant",
        sender=hab.pre,
        payload=payload,
        embeds=embeds,
        date=helping.nowIso8601(),
    )
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[: exn.size]
    ims.extend(end)

    msg = bytearray(exn.raw)
    msg.extend(ims)
    return msg


class _ChainCollector:
    """
    Duck-typed stand-in for keripy's ``StreamPoster`` that concatenates messages
    into one CESR stream. Messages whose SAID was already emitted are skipped, which
    de-dupes the KELs and TELs shared between credentials of a chain.
    """

    def __init__(self):
        self.stream = bytearray()
        self._seen: set[str] = set()

    def send(self, serder, attachment=None):
        if serder.said in self._seen:
            return
        self._seen.add(serder.said)
        self.stream.extend(serder.raw)
        if attachment:
            self.stream.extend(attachment)


def _chain_sources(vault, creder) -> list[tuple[Any, bytes]]:
    """
    Credentials reachable through ``creder``'s edges as ``(creder, attachment)``,
    dependencies before dependents (post-order), each once.

    Unlike ``Reger.sources`` (pre-order) this lets the server verify each credential
    without relying on its missing-chain escrow.
    """
    reger = vault.rgy.reger
    seen: set[str] = {creder.said}
    ordered: list[tuple[Any, bytes]] = []

    def visit(node):
        for key, edge in (node.edge or {}).items():
            if key == "d" or not isinstance(edge, dict) or not edge.get("n"):
                continue
            said = edge["n"]
            if said in seen:
                continue
            seen.add(said)
            source, prefixer, seqner, saider = reger.cloneCred(said=said)
            visit(source)
            atc = signing.serialize(source, prefixer, seqner, saider)[source.size :]
            ordered.append((source, atc))

    visit(creder)
    return ordered


def _build_chain_stream(vault, hab, server_aid: str, credential_said: str) -> bytearray:
    """
    CESR stream of the full credential chain of ``credential_said``, as ``kli ipex
    grant`` sends it: issuer KELs and TELs, every chained source credential with its
    own artifacts, then the root's artifacts and the ``/ipex/grant`` exn last.

    Fails fast with ``PresentingError`` when the vault lacks any chain member, its
    TEL or an issuer KEL.
    """
    reger = vault.rgy.reger
    collector = _ChainCollector()
    try:
        creder = reger.cloneCred(said=credential_said)[0]
        for source, atc in _chain_sources(vault, creder):
            credentialing.sendArtifacts(vault.hby, reger, collector, source, server_aid)
            collector.send(source, attachment=atc)
        credentialing.sendArtifacts(vault.hby, reger, collector, creder, server_aid)
    except (KeyError, kering.MissingEntryError, AttributeError) as exc:
        raise PresentingError(
            f"The credential chain of {credential_said} is incomplete in the vault "
            f"(missing {exc}); wait for all grants to be admitted and the issuer "
            "OOBIs to resolve."
        )

    stream = collector.stream
    stream.extend(_build_grant_message(vault, hab, server_aid, credential_said, None))
    return stream


def build_dcr_request(
    vault,
    connection,
    client_name: str = "",
    redirect_uris: list[str] | None = None,
) -> dict[str, str]:
    """
    Body of POST /register (ONBOARDING.md S4.4): an IPEX grant exn of the
    onboarded credential, carrying the client metadata in ``a.udap``.

    ``ipexGrantExn`` fixes ``a`` to ``{m, i}``, so the exn is built with
    ``exchanging.exchange`` and endorsed with ``last=False`` (the server only
    processes transferable ``tsgs`` groups). Built fresh per call: ``dt`` is
    the server's replay guard.

    With SIGNET_ONBOARDING_FORMAT=json this is ``build_dcr_request_json`` instead.
    """
    if configing.is_json_format():
        return build_dcr_request_json(vault, connection)

    hab = vault.hby.habs.get(connection.hab_aid)
    if hab is None:
        raise PresentingError("The presenting identifier is not in this vault.")
    if not connection.selected_credential_said or not connection.server_aid:
        raise PresentingError("The connection has no credential or server AID.")

    udap = {"purpose": connection.purpose or REQUESTED_PURPOSE}
    client_name = client_name or connection.client_name
    redirect_uris = (
        redirect_uris if redirect_uris is not None else connection.redirect_uris
    )
    if client_name:
        udap["client_name"] = client_name
    if redirect_uris:
        udap["redirect_uris"] = list(redirect_uris)

    try:
        msg = _build_grant_message(
            vault,
            hab,
            connection.server_aid,
            connection.selected_credential_said,
            udap,
        )
    except PresentingError:
        raise
    except Exception as exc:
        raise PresentingError(f"Unable to build the registration request: {exc}")

    return {
        "software_statement_type": DCR_STATEMENT_TYPE,
        "software_statement": msg.decode("utf-8"),
        "udap": "1",
    }


def build_dcr_request_json(vault, connection) -> dict[str, Any]:
    """
    Body of POST {registration_endpoint} in the json format: the credential chain as
    a plain ``ipex_grant`` stream (as in the onboarding packet), the presenter's
    witness ``oobi``, and the client metadata at top level (no ``a.udap``).

    ``purpose`` is ``REQUESTED_PURPOSE`` rather than ``connection.purpose``: approval is
    keyed by (AID, purpose) and onboarding sent ``REQUESTED_PURPOSE``. ``redirect_uris``
    are not sent. Built fresh per call: ``dt`` is the server's replay guard.
    """
    hab = vault.hby.habs.get(connection.hab_aid)
    if hab is None:
        raise PresentingError("The presenting identifier is not in this vault.")
    said = connection.selected_credential_said
    if not said:
        raise PresentingError("The connection has no credential.")
    server_aid = connection.server_aid or configing.onboarding_server_aid()
    if not server_aid:
        raise PresentingError(
            "The grant must be addressed to the server, but its AID is unknown "
            "(set SIGNET_ONBOARDING_SERVER_AID)."
        )

    oobi = configing.dcr_oobi_override()
    if not oobi:
        urls = witness_oobi_urls(hab)
        if not urls:
            raise PresentingError(
                f"Identifier {hab.pre} has no witness to host its key state."
            )
        oobi = urls[0]

    try:
        grant = _build_chain_stream(vault, hab, server_aid, said)
    except PresentingError:
        raise
    except Exception as exc:
        raise PresentingError(f"Unable to build the registration request: {exc}")

    return {
        "ipex_grant": grant.decode("utf-8"),
        "oobi": oobi,
        "purpose": REQUESTED_PURPOSE,
        "client_name": connection.client_name,
        "grant_types": ["client_credentials"],
    }


def build_token_assertion(vault, connection) -> str:
    """
    ``client_assertion`` for POST /token (``client_credentials``): the same IPEX
    grant exn of the registered credential that DCR sends, with an empty
    ``a.udap`` (the server ignores it at token time). It must keep embedding the
    full credential: the server re-validates it against its reger and TEL.
    Built fresh per call: ``dt`` is the server's replay guard.
    """
    hab = vault.hby.habs.get(connection.hab_aid)
    if hab is None:
        raise PresentingError("The presenting identifier is not in this vault.")
    server_aid = connection.server_aid
    if configing.is_json_format():
        server_aid = server_aid or configing.onboarding_server_aid()
    if not connection.selected_credential_said or not server_aid:
        raise PresentingError("The connection has no credential or server AID.")

    try:
        msg = _build_grant_message(
            vault,
            hab,
            server_aid,
            connection.selected_credential_said,
            {},
        )
    except PresentingError:
        raise
    except Exception as exc:
        raise PresentingError(f"Unable to build the client assertion: {exc}")
    return msg.decode("utf-8")


def witness_oobi_urls(hab, pre: str | None = None) -> list[str]:
    """Witness-hosted OOBI URLs for ``pre`` (default ``hab.pre``) (ONBOARDING.md S5, D15)."""
    pre = pre or hab.pre
    if configing.assume_palantir_oobis():
        return [f"https://palantir.healthkeri.net/oobi/{pre}"]
    urls = []
    witnesses = hab.fetchWitnessUrls(cid=pre).get("witness") or {}
    for surls in witnesses.values():
        for scheme in ("https", "http"):
            if scheme in surls:
                urls.append(f"{surls[scheme].rstrip('/')}/oobi/{pre}")
                break
    return urls


def _find_chain_credential(vault, credential_said: str, schema_said: str):
    """
    First credential of ``schema_said`` reachable from ``credential_said`` through its
    edges (breadth-first, the credential itself included), or None.
    """
    try:
        creds = vault.rgy.reger.creds
        pending, seen = [credential_said], set()
        while pending and len(seen) < 64:
            said = pending.pop(0)
            if said in seen:
                continue
            seen.add(said)
            creder = creds.get(keys=(said,))
            if creder is None:
                continue
            if creder.sad.get("s") == schema_said:
                return creder
            for edge in (creder.sad.get("e") or {}).values():
                if isinstance(edge, dict) and edge.get("n"):
                    pending.append(edge["n"])
    except Exception as exc:
        logger.warning("Could not walk the credential chain: %s", exc)
    return None


def legal_entity_aid(vault, credential_said: str) -> str | None:
    """
    The Legal Entity AID of the credential's chain: the issuee of its Legal Entity
    vLEI credential. The server cannot pre-configure it (it varies per requester), so
    the requester conveys its key state in ``a.udap.oobis``.
    """
    creder = _find_chain_credential(vault, credential_said, LEGAL_ENTITY_SCHEMA_SAID)
    return ((creder.sad.get("a") or {}).get("i") or None) if creder else None


def legal_entity_subunit(vault, credential_said: str) -> tuple[str, str] | None:
    """
    ``(aid, lei)`` of the JSON packet's ``legal_entity``: the issuee (``a.i``) and
    ``a.LEI`` of the chain's Legal Entity Subunit credential, or of its Legal Entity
    credential when the chain has no subunit (the ECR chain and the simple LESR chain). ``lei`` may be empty.
    None if the chain has neither.
    """
    for schema_said in (LE_SUBUNIT_SCHEMA_SAID, LEGAL_ENTITY_SCHEMA_SAID):
        creder = _find_chain_credential(vault, credential_said, schema_said)
        if creder is not None:
            attrib = creder.sad.get("a") or {}
            return attrib.get("i") or "", attrib.get("LEI") or ""
    return None


def build_oobis(
    hab, credential_said: str, le_aid: str | None = None
) -> list[dict[str, str]]:
    """
    Typed oobis array: key-state OOBIs for the signer and the Legal Entity, plus the
    credential chain URL. In the cesr format, issuer KELs above the LE (QVI, GLEIF) are the
    server's trust roots and come from its config, not the request; the json format
    sends them in the ``ipex_grant`` chain stream.
    """
    oobis = [
        {"type": "aid", "aid": hab.pre, "url": url} for url in witness_oobi_urls(hab)
    ]
    if not oobis:
        raise PresentingError(
            f"Identifier {hab.pre} has no witness to host its key state."
        )
    if le_aid and le_aid != hab.pre:
        oobis.extend(
            {"type": "aid", "aid": le_aid, "url": url}
            for url in witness_oobi_urls(hab, le_aid)
        )

    registrar = configing.registrar_url()
    if not registrar:
        raise PresentingError(
            "SIGNET_REGISTRAR_URL is not set; cannot reference the credential chain."
        )
    oobis.append(
        {
            "type": "credential",
            "said": credential_said,
            "url": f"{registrar}/credential/{credential_said}"
            "?chains=true&tel=true&registry=true",
        }
    )
    return oobis


def _credential_issuee(vault, credential_said: str) -> str:
    """The issuee (``a.i``) of a received credential, or '' if unknown."""
    creder = vault.rgy.reger.creds.get(keys=(credential_said,))
    return (creder.attrib or {}).get("i", "") if creder is not None else ""


def build_onboarding_grant(
    vault,
    credential: dict[str, Any],
    endpoint: str,
    server_aid: str,
    contacts: list[Any] | None = None,
    redirect_uris: list[str] | None = None,
) -> OnboardingRequest:
    """
    Build the POST /udap/onboarding request for ``credential`` (ONBOARDING.md S4).

    Like ``build_dcr_request``, ``ipexGrantExn`` fixes ``a`` to ``{m, i}``, so the
    exn is built with ``exchanging.exchange`` and endorsed with ``last=False``.
    Built fresh per call: ``dt`` is the server's replay guard.
    """
    if configing.is_mock_mode():
        return OnboardingRequest(
            url=endpoint,
            body=b"",
            correlation_id=uuid.uuid4().hex[:16],
            server_aid=server_aid,
        )

    holder_pre = credential.get("holder_pre", "")
    hab = vault.hby.habs.get(holder_pre)
    if hab is None:
        raise PresentingError(
            "The selected credential is not held by a local identifier."
        )

    said = credential["said"]
    # The server binds the credential's issuee to the exn sender (D25): fail
    # here with a clear message instead of a 403.
    if _credential_issuee(vault, said) != hab.pre:
        raise PresentingError(
            "The credential is not issued to the presenting identifier."
        )

    correlation_id = uuid.uuid4().hex[:16]
    udap = {
        "requested_purposes": [REQUESTED_PURPOSE],
        "contacts": contacts or [],
        "redirect_uris": redirect_uris or [],
        "correlation_id": correlation_id,
        "oobis": build_oobis(hab, said, legal_entity_aid(vault, said)),
    }

    try:
        body = _build_grant_message(vault, hab, server_aid, said, udap)
    except PresentingError:
        raise
    except Exception as exc:
        raise PresentingError(f"Unable to build the onboarding request: {exc}")

    return OnboardingRequest(
        url=endpoint,
        body=bytes(body),
        correlation_id=correlation_id,
        hab_name=hab.name,
        hab_aid=hab.pre,
        server_aid=server_aid,
    )


def build_onboarding_packet(
    vault,
    credential: dict[str, Any],
    endpoint: str,
    server_aid: str,
) -> OnboardingRequest:
    """
    Build the JSON submission packet (SUBMISSION_SHAPE.md) for ``credential``: a JSON
    envelope carrying the credential chain as ``ipex_grant``: one CESR stream of the
    issuer KELs, TELs and chained credentials (``_build_chain_stream``) ending in the
    IPEX grant exn.

    The grant is plain (``a`` is ``{m, i}``, no ``a.udap``) since the packet carries
    the metadata. Built fresh per call: ``dt`` is the server's replay guard.

    ``legal_entity`` describes the Legal Entity Subunit (``legal_entity_subunit``): its
    issuee AID and ``LEI``, or the Legal Entity itself when the chain has no subunit
    (the simple LESR chain), then the presenter's AID and ``DEMO_LEI``.

    With SIGNET_ONBOARDING_OMIT_GRANT the grant is neither built nor sent (the server
    field is optional while its grant verification is unfinished), so no server AID is
    needed either.

    SIGNET_ONBOARDING_OOBI (comma-separated) replaces the witness-derived
    ``legal_entity.oobi`` list.
    """
    if configing.is_mock_mode():
        return OnboardingRequest(
            url=endpoint,
            body=b"",
            content_type="application/json",
            correlation_id=uuid.uuid4().hex[:16],
            server_aid=server_aid,
        )

    holder_pre = credential.get("holder_pre", "")
    hab = vault.hby.habs.get(holder_pre)
    if hab is None:
        raise PresentingError(
            "The selected credential is not held by a local identifier."
        )

    said = credential["said"]
    if _credential_issuee(vault, said) != hab.pre:
        raise PresentingError(
            "The credential is not issued to the presenting identifier."
        )
    omit_grant = configing.omit_ipex_grant()
    if not server_aid and not omit_grant:
        raise PresentingError(
            "The server advertises no AID; set SIGNET_ONBOARDING_SERVER_AID."
        )

    le_aid, le_lei = legal_entity_subunit(vault, said) or ("", "")
    le_aid = le_aid or hab.pre
    oobis = configing.onboarding_oobi_override() or witness_oobi_urls(hab, le_aid)
    if not oobis:
        raise PresentingError(
            f"Identifier {le_aid} has no witness to host its key state."
        )

    grant = None
    if not omit_grant:
        try:
            grant = _build_chain_stream(vault, hab, server_aid, said)
        except PresentingError:
            raise
        except Exception as exc:
            raise PresentingError(f"Unable to build the onboarding request: {exc}")

    correlation_id = uuid.uuid4().hex[:16]
    packet = {
        "correlation_id": correlation_id,
        "legal_entity": {
            "lei": le_lei or DEMO_LEI,
            "aid": le_aid,
            "qvi_lei": DEMO_QVI_LEI,
            "oobi": oobis,
        },
        "submitter": {"role": credential.get("role", "")},
        "requested_purposes": [
            {"purpose": REQUESTED_PURPOSE, "scopes": configing.onboarding_scopes()}
        ],
        "client_metadata": {},
        "contacts": {
            "technical": DEMO_TECHNICAL_CONTACT,
            "security": DEMO_SECURITY_CONTACT,
        },
    }
    if grant is not None:
        packet["ipex_grant"] = grant.decode("utf-8")

    return OnboardingRequest(
        url=endpoint,
        body=json.dumps(packet).encode("utf-8"),
        content_type="application/json",
        correlation_id=correlation_id,
        hab_name=hab.name,
        hab_aid=hab.pre,
        server_aid=server_aid,
    )


def build_onboarding_request(
    vault,
    credential: dict[str, Any],
    endpoint: str,
    server_aid: str,
    redirect_uris: list[str] | None = None,
) -> OnboardingRequest:
    """Build the onboarding request in the configured format (SIGNET_ONBOARDING_FORMAT)."""
    if configing.onboarding_format() == configing.ONBOARDING_FORMAT_JSON:
        return build_onboarding_packet(vault, credential, endpoint, server_aid)
    return build_onboarding_grant(
        vault, credential, endpoint, server_aid, redirect_uris=redirect_uris
    )
