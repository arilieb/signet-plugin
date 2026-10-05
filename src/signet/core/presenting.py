# -*- encoding: utf-8 -*-
"""
signet.core.presenting module

Builds the signed onboarding request described in echelon-server's
ONBOARDING.md (S4, D16): a JSON packet carrying typed OOBIs and an IPEX grant
of the presented credential addressed to the server, plus HTTP message
signature headers (Signify-Resource, Signify-Timestamp, Digest, nonce) made
with the presenting identifier's keys.
"""

import base64
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from hio.help import Hict
from keri import help
from keri.app import signing
from keri.core import coring, serdering
from keri.end import ending
from keri.help import helping
from keri.vc import protocoling

from . import configing
from .credentials import LEGAL_ENTITY_SCHEMA_SAID

logger = help.ogler.getLogger(__name__)

REQUESTED_PURPOSE = "TREAT"
SIGNATURE_NAME = "signify"
SIGNED_FIELDS = (
    "signify-resource",
    "@method",
    "@path",
    "signify-timestamp",
    "digest",
)


class PresentingError(Exception):
    """The onboarding request could not be built."""


@dataclass
class OnboardingRequest:
    """A fully built, signed POST /udap/onboarding request."""

    url: str
    body: bytes
    headers: dict[str, str]
    correlation_id: str
    hab_name: str = ""
    hab_aid: str = ""
    server_aid: str = ""
    packet: dict[str, Any] = field(default_factory=dict)


def body_digest(body: bytes) -> str:
    """Digest header value the server recomputes: sha-256=<base64>."""
    return "sha-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()


def build_grant(vault, hab, credential_said: str, server_aid: str) -> str:
    """
    IPEX grant exn of a received credential, addressed to ``server_aid``.

    Mirrors locksmith.core.ipexing.Granter.grant but does not feed the exn back
    into a local Exchanger: that is only needed when granting to a peer we
    also run, and parsing our own presentation has side effects we don't want.
    """
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

        exn, atc = protocoling.ipexGrantExn(
            hab=hab,
            recp=server_aid,
            message="",
            acdc=acdc,
            reg=reg,
            iss=iss,
            anc=anc,
            dt=helping.nowIso8601(),
        )
    except PresentingError:
        raise
    except Exception as exc:
        raise PresentingError(f"Unable to build grant for the credential: {exc}")

    msg = bytearray(exn.raw)
    msg.extend(atc)
    return msg.decode("utf-8")


def witness_oobi_urls(hab, pre: str | None = None) -> list[str]:
    """Witness-hosted OOBI URLs for ``pre`` (default ``hab.pre``) (ONBOARDING.md S5, D15)."""
    pre = pre or hab.pre
    urls = []
    witnesses = hab.fetchWitnessUrls(cid=pre).get("witness") or {}
    for surls in witnesses.values():
        for scheme in ("https", "http"):
            if scheme in surls:
                urls.append(f"{surls[scheme].rstrip('/')}/oobi/{pre}")
                break
    return urls


def legal_entity_aid(vault, credential_said: str) -> str | None:
    """
    The Legal Entity AID of the credential's chain: the issuee of its Legal Entity
    vLEI credential. The server cannot pre-configure it (it varies per requester), so
    the requester conveys its key state in the packet.
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
            if creder.sad.get("s") == LEGAL_ENTITY_SCHEMA_SAID:
                return (creder.sad.get("a") or {}).get("i") or None
            for edge in (creder.sad.get("e") or {}).values():
                if isinstance(edge, dict) and edge.get("n"):
                    pending.append(edge["n"])
    except Exception as exc:
        logger.warning("Could not resolve the Legal Entity AID: %s", exc)
    return None


def build_oobis(
    hab, credential_said: str, le_aid: str | None = None
) -> list[dict[str, str]]:
    """
    Typed oobis array: key-state OOBIs for the signer and the Legal Entity, plus the
    credential chain URL. Issuer KELs above the LE (QVI, GLEIF) are the server's trust
    roots and come from its config, not the packet.
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


def sign_request(hab, method: str, path: str, body: bytes) -> dict[str, str]:
    """HTTP signature headers over method, path, resource, timestamp and body digest."""
    headers = Hict(
        [
            ("Signify-Resource", hab.pre),
            ("Signify-Timestamp", helping.nowIso8601()),
            ("Digest", body_digest(body)),
        ]
    )
    header, qsig = ending.siginput(
        name=SIGNATURE_NAME,
        method=method,
        path=path,
        headers=headers,
        fields=list(SIGNED_FIELDS),
        hab=hab,
        nonce=secrets.token_hex(16),
        alg="ed25519",
        keyid=hab.pre,
    )
    headers.extend(header)
    signage = ending.Signage(
        markers={SIGNATURE_NAME: qsig},
        indexed=False,
        signer=None,
        ordinal=None,
        digest=None,
        kind=None,
    )
    headers.extend(ending.signature([signage]))
    return dict(headers)


def build_onboarding_request(
    vault,
    credential: dict[str, Any],
    endpoint: str,
    server_aid: str,
    contacts: list[Any] | None = None,
) -> OnboardingRequest:
    """Build and sign the POST /udap/onboarding request for ``credential``."""
    if configing.is_mock_mode():
        return OnboardingRequest(
            url=endpoint,
            body=b"{}",
            headers={},
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
    correlation_id = uuid.uuid4().hex[:16]
    # Per the design doc the packet's legal_entity.aid is the AID that signs and
    # sends the grant; with an ECR that is the person AID, not the LE's.
    packet = {
        "legal_entity": {"aid": hab.pre},
        "submitter": {"ecr_said": said, "role": credential.get("role", "")},
        "requested_purposes": [REQUESTED_PURPOSE],
        "contacts": contacts or [],
        "correlation_id": correlation_id,
        "oobis": build_oobis(hab, said, legal_entity_aid(vault, said)),
        "grant": build_grant(vault, hab, said, server_aid),
    }
    body = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    headers = sign_request(hab, "POST", urlparse(endpoint).path, body)
    headers["Content-Type"] = "application/json"

    return OnboardingRequest(
        url=endpoint,
        body=body,
        headers=headers,
        correlation_id=correlation_id,
        hab_name=hab.name,
        hab_aid=hab.pre,
        server_aid=server_aid,
        packet=packet,
    )
