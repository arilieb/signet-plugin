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

# Scopes requested at onboarding unless SIGNET_ONBOARDING_SCOPES says otherwise.
DEFAULT_ONBOARDING_SCOPES = ("system/Group.read",)

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


def is_json_format() -> bool:
    """True when ``onboarding_format`` is ``json``: the single gate for the SLAP-style DCR and token flow."""
    return onboarding_format() == ONBOARDING_FORMAT_JSON


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


def onboarding_oobi_override() -> list[str]:
    """OOBIs replacing the witness-derived ``legal_entity.oobi`` of the JSON packet (SIGNET_ONBOARDING_OOBI, comma-separated)."""
    raw = os.environ.get("SIGNET_ONBOARDING_OOBI", "")
    return [oobi.strip() for oobi in raw.split(",") if oobi.strip()]


def assume_palantir_oobis() -> bool:
    """True when every OOBI is assumed to be hosted at ``https://palantir.healthkeri.net/oobi/{aid}`` instead of derived from keripy witness records (SIGNET_ASSUME_PALANTIR_OOBIS=1|true)."""
    return os.environ.get("SIGNET_ASSUME_PALANTIR_OOBIS", "").strip().lower() in (
        "1",
        "true",
    )


def registration_endpoint_override() -> str:
    """Registration endpoint replacing the advertised one in the json format (SIGNET_REGISTRATION_ENDPOINT)."""
    return os.environ.get("SIGNET_REGISTRATION_ENDPOINT", "").strip()


def token_endpoint_override() -> str:
    """Token endpoint replacing the advertised one in the json format (SIGNET_TOKEN_ENDPOINT)."""
    return os.environ.get("SIGNET_TOKEN_ENDPOINT", "").strip()


def fhir_base_url_override() -> str:
    """FHIR base URL replacing the one derived from the connection's base_url (SIGNET_FHIR_BASE_URL)."""
    return os.environ.get("SIGNET_FHIR_BASE_URL", "").strip().rstrip("/")


def export_method() -> str:
    """HTTP method of ``$davinci-data-export`` (SIGNET_EXPORT_METHOD): ``GET``, else ``POST``."""
    raw = os.environ.get("SIGNET_EXPORT_METHOD", "").strip().upper()
    return "GET" if raw == "GET" else "POST"


def export_status_url_prefix() -> str:
    """URL prefix the export task id is appended to, replacing the advertised status URL (SIGNET_EXPORT_STATUS_URL_PREFIX)."""
    raw = os.environ.get("SIGNET_EXPORT_STATUS_URL_PREFIX", "").strip()
    return f"{raw.rstrip('/')}/" if raw else ""


def onboarding_scopes() -> list[str]:
    """Scopes requested at onboarding (SIGNET_ONBOARDING_SCOPES, space-separated); defaults to ``system/Group.read``."""
    raw = os.environ.get("SIGNET_ONBOARDING_SCOPES", "")
    return raw.split() or list(DEFAULT_ONBOARDING_SCOPES)


def dcr_oobi_override() -> str:
    """Single OOBI URL replacing the presenter's witness OOBI in the json DCR body (SIGNET_DCR_OOBI)."""
    return os.environ.get("SIGNET_DCR_OOBI", "").strip()


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
