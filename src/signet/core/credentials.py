# -*- encoding: utf-8 -*-
"""
signet.core.credentials module

Filters the vault's received credentials down to the ECR (Engagement Context
Role) credentials presented when submitting a UDAP vLEI onboarding request.

The chain is GLEIF External -> QVI -> LE -> ECR Auth -> ECR (ONBOARDING.md
S4.6; design doc S5 recommends an ECR as the submitter credential).
"""

from typing import Any

from keri import help

from .configing import is_mock_mode

logger = help.ogler.getLogger(__name__)

LEGAL_ENTITY_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
ECR_SCHEMA_SAID = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"

# Seeded so the "Select Credential" dropdown in AddConnectionDialog isn't
# empty in mock mode (never in live dev, which must use real credentials).
_MOCK_CREDENTIAL = {
    "said": "EEngagementContextRolePlaceholder0000000",
    "title": "Engagement Context Role (placeholder)",
    "holder_pre": "",
    "role": "Staff System Engineer",
    "schema_said": ECR_SCHEMA_SAID,
}


def filter_ecr_credentials(vault) -> list[dict[str, Any]]:
    """Return the vault's received credentials matching the ECR schema."""
    matching: list[dict[str, Any]] = []

    if vault is not None and getattr(vault, "hby", None) is not None:
        saids = []
        for pre in vault.hby.habs.keys():
            saids.extend(vault.rgy.reger.subjs.get(keys=(pre,)))

        for credential in vault.rgy.reger.cloneCreds(saids, vault.hby.db):
            schema = credential.get("schema") or {}  # schemer.sed: the schema dict
            if schema.get("$id") != ECR_SCHEMA_SAID:
                continue
            sad = credential.get("sad", {})
            attrib = sad.get("a", {})
            matching.append(
                {
                    "said": sad.get("d", ""),
                    "title": schema.get("title", ""),
                    "holder_pre": attrib.get("i", ""),
                    "role": attrib.get("engagementContextRole", ""),
                }
            )

    if not matching and is_mock_mode():
        matching.append(dict(_MOCK_CREDENTIAL))

    return matching
