# -*- encoding: utf-8 -*-
"""
signet.core.configing module

Environment-driven configuration for the signet plugin: the mock-mode gate
(real remoting calls short-circuit to canned mock_data responses in the
DEVELOPMENT environment unless SIGNET_LIVE=1), the partner discovery URL, and
the onboarding format (single CESR grant, or a JSON submission packet).
"""

import os

from locksmith.core.configing import Environments, LocksmithConfig

# Placeholder base URL used by seed/mock data only; real per-connection
# base_urls come from each SignetConnection.
DEFAULT_ONYX_BASE_URL = "https://onyx.example.com"


DEFAULT_LOCAL_PARTNER_URL = "http://127.0.0.1:8000"

# Discovery document path of KERI-aware partners; a partner URL may be the full URL of it.
KERI_WELL_KNOWN = "/.well-known/keri"

ONBOARDING_FORMAT_CESR = "cesr"
ONBOARDING_FORMAT_JSON = "json"

# Engagement Context Role (ECR) credential schema SAID.
ECR_SCHEMA_SAID = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"

# Legal Entity Service Representative (LESR) credential schema SAID; the default
# submitter credential (keep in sync with SCHEMA_LESR in scripts/dev-live/env.sh).
LESR_SCHEMA_SAID = "EHfJ563sbivepFRzk506fJenWIeVG2uXdAes8iJhHJan"


def _is_development() -> bool:
    return LocksmithConfig.get_instance().environment == Environments.DEVELOPMENT


def is_live_dev() -> bool:
    """True in the DEVELOPMENT environment with SIGNET_LIVE=1: real calls to local infrastructure."""
    return _is_development() and os.environ.get("SIGNET_LIVE", "") in ("1", "true")


def is_mock_mode() -> bool:
    """True when remoting calls should short-circuit to canned mock responses."""
    return _is_development() and not is_live_dev()


def partner_url() -> str:
    """Partner base URL, or full ``.well-known/keri`` URL (SIGNET_PARTNER_URL); defaults to local Echelon."""
    return os.environ.get("SIGNET_PARTNER_URL", DEFAULT_LOCAL_PARTNER_URL).rstrip("/")


def is_partner_url_set() -> bool:
    """True when SIGNET_PARTNER_URL is explicitly set (``partner_url`` always has a default)."""
    return bool(os.environ.get("SIGNET_PARTNER_URL", "").strip())


def is_keri_discovery_url(url: str) -> bool:
    """True when ``url`` is the full URL of a partner's ``.well-known/keri`` document."""
    return url.split("?", 1)[0].rstrip("/").endswith(KERI_WELL_KNOWN)


def onboarding_format() -> str:
    """Onboarding request format (SIGNET_ONBOARDING_FORMAT): ``json`` packet, else ``cesr`` grant."""
    raw = os.environ.get("SIGNET_ONBOARDING_FORMAT", "").strip().lower()
    return (
        ONBOARDING_FORMAT_JSON
        if raw == ONBOARDING_FORMAT_JSON
        else ONBOARDING_FORMAT_CESR
    )


def onboarding_server_aid() -> str:
    """AID the onboarding grant is addressed to when discovery does not advertise one."""
    return os.environ.get("SIGNET_ONBOARDING_SERVER_AID", "").strip()


def omit_ipex_grant() -> bool:
    """True when the JSON packet is sent without ``ipex_grant`` (SIGNET_ONBOARDING_OMIT_GRANT=1|true)."""
    return os.environ.get("SIGNET_ONBOARDING_OMIT_GRANT", "").strip().lower() in (
        "1",
        "true",
    )


def onboarding_endpoint_override() -> str:
    """Onboarding endpoint replacing the one a ``.well-known/keri`` document advertises (SIGNET_ONBOARDING_ENDPOINT)."""
    return os.environ.get("SIGNET_ONBOARDING_ENDPOINT", "").strip()


def registrar_url() -> str:
    """Base URL of the registrar hosting credential chains (SIGNET_REGISTRAR_URL)."""
    return os.environ.get("SIGNET_REGISTRAR_URL", "").rstrip("/")


def accepted_credential_schemas() -> tuple[str, ...]:
    """Schema SAIDs of credentials offered for onboarding (SIGNET_CREDENTIAL_SCHEMAS, comma-separated).

    Defaults to the LESR schema when unset or blank.
    """
    raw = os.environ.get("SIGNET_CREDENTIAL_SCHEMAS", "")
    saids = tuple(said.strip() for said in raw.split(",") if said.strip())
    return saids or (LESR_SCHEMA_SAID,)
