# -*- encoding: utf-8 -*-
"""
signet.core.credentials module

Filters the vault's received credentials down to the "legal entity subunit
role" credential presented when submitting a UDAP vLEI onboarding request.

Flagging explicitly: neither UDAP_vLEI_Onboarding_Intake_Design.md nor its
sibling DCR/auth docs use the phrase "legal entity subunit role" -- it only
appears in the planning note this task was scoped from. The real vLEI chain
in this codebase (acdc-auth-server/schema/sample-vlei-graph/) has qvi,
legal-entity, ecr, and ecr-auth schemas but nothing named "subunit".
LEGAL_ENTITY_SUBUNIT_SCHEMA_SAID is a placeholder pending the real schema.
"""
from typing import Any

from keri import help

from .configing import is_mock_mode

logger = help.ogler.getLogger(__name__)

LEGAL_ENTITY_SUBUNIT_SCHEMA_SAID = "TBD"

# Seeded so the "Select Credential" dropdown in AddConnectionDialog isn't
# empty in dev, since no vault will actually hold a credential against the
# placeholder schema SAID above until the real schema exists.
_MOCK_CREDENTIAL = {
    "said": "ELegalEntitySubunitPlaceholder00000000000",
    "title": "Legal Entity Subunit Role (placeholder)",
    "schema_said": LEGAL_ENTITY_SUBUNIT_SCHEMA_SAID,
}


def filter_legal_entity_subunit_credentials(vault) -> list[dict[str, Any]]:
    """Return the vault's received credentials matching the legal entity subunit schema."""
    matching: list[dict[str, Any]] = []

    if vault is not None and getattr(vault, "hby", None) is not None:
        saids = []
        for pre in vault.hby.habs.keys():
            saids.extend(vault.rgy.reger.subjs.get(keys=(pre,)))

        for credential in vault.rgy.reger.cloneCreds(saids, vault.hby.db):
            schemer = credential.get("schema")
            if schemer is None or schemer.said != LEGAL_ENTITY_SUBUNIT_SCHEMA_SAID:
                continue
            matching.append({
                "said": credential.get("sad", {}).get("d", ""),
                "title": schemer.sed.get("title", ""),
            })

    if not matching and is_mock_mode():
        matching.append(dict(_MOCK_CREDENTIAL))

    return matching