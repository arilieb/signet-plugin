# -*- encoding: utf-8 -*-
"""
signet.core.credentials module

Filters the vault's received credentials down to those whose schema SAID is in
the accepted set (SIGNET_CREDENTIAL_SCHEMAS, default the LESR), presented when
submitting a UDAP vLEI onboarding request.

The ECR chain is GLEIF External -> QVI -> LE -> ECR Auth -> ECR; the LESR chain
is External -> QVI -> LE -> LE Subunit -> LESR Auth -> LESR (ONBOARDING.md S4.6).
The default LESR SAID (configing.LESR_SCHEMA_SAID) may change on re-saidification;
SIGNET_CREDENTIAL_SCHEMAS overrides it.
"""

from typing import Any

from keri import help

from .configing import ECR_SCHEMA_SAID, accepted_credential_schemas, is_mock_mode

logger = help.ogler.getLogger(__name__)

LEGAL_ENTITY_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"

# Seeded so the "Select Credential" dropdown in AddConnectionDialog isn't
# empty in mock mode (never in live dev, which must use real credentials).
_MOCK_CREDENTIAL = {
    "said": "EEngagementContextRolePlaceholder0000000",
    "title": "Engagement Context Role (placeholder)",
    "holder_pre": "",
    "role": "Staff System Engineer",
    "schema_said": ECR_SCHEMA_SAID,
}


def filter_credentials(vault) -> list[dict[str, Any]]:
    """Return the vault's received credentials matching an accepted schema SAID."""
    accepted = accepted_credential_schemas()
    matching: list[dict[str, Any]] = []

    if vault is not None and getattr(vault, "hby", None) is not None:
        saids = []
        for pre in vault.hby.habs.keys():
            saids.extend(vault.rgy.reger.subjs.get(keys=(pre,)))

        for credential in vault.rgy.reger.cloneCreds(saids, vault.hby.db):
            schema = credential.get("schema") or {}  # schemer.sed: the schema dict
            if schema.get("$id") not in accepted:
                continue
            sad = credential.get("sad", {})
            attrib = sad.get("a", {})
            matching.append(
                {
                    "said": sad.get("d", ""),
                    "title": schema.get("title", ""),
                    "holder_pre": attrib.get("i", ""),
                    "role": attrib.get("policyDomainRole")
                    or attrib.get("engagementContextRole", ""),
                }
            )

    if not matching and is_mock_mode():
        matching.append(dict(_MOCK_CREDENTIAL))

    return matching
