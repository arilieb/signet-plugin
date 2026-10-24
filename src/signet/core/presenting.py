# -*- encoding: utf-8 -*-
"""
signet.core.presenting module

Adapter between signet's state (the Locksmith ``vault``, ``SignetConnection``, the
``SIGNET_*`` environment) and the request builders of acdc-auth-client
(``acdc_auth_client.core.presentation``), which take explicit arguments: the
onboarding request, the DCR body and the token client assertion. The wire shapes
(a single IPEX grant exn, or a JSON submission packet, per
``SIGNET_ONBOARDING_FORMAT``) are the library's; see its ``presentation`` module and
SUBMISSION_SHAPE.md.

This module adds what the library leaves to the host: the vault and connection
unpacking, the mock-mode short-circuit and the demo values of the JSON packet.
"""

import uuid
from typing import Any

from acdc_auth_client.constants import REQUESTED_PURPOSE
from acdc_auth_client.core import presentation
from acdc_auth_client.core.options import ConnectionInfo
from acdc_auth_client.core.presentation import PacketDefaults
from acdc_auth_client.models.errors import PresentationError
from acdc_auth_client.models.onboarding import OnboardingRequest

from . import configing

__all__ = [
    "REQUESTED_PURPOSE",
    "OnboardingRequest",
    "PresentingError",
    "build_dcr_request",
    "build_onboarding_request",
    "build_token_assertion",
    "connection_info",
]

# Demo values for the JSON submission packet (SUBMISSION_SHAPE.md); not user-entered yet.
DEMO_LEI = "549300QKBENKLBXQ8968"
DEMO_QVI_LEI = "254900OPPU84GM83MG36"
DEMO_TECHNICAL_CONTACT = "interop-eng@healthkeri.com"
DEMO_SECURITY_CONTACT = "security@healthkeri.com"

PACKET_DEFAULTS = PacketDefaults(
    lei=DEMO_LEI,
    qvi_lei=DEMO_QVI_LEI,
    technical_contact=DEMO_TECHNICAL_CONTACT,
    security_contact=DEMO_SECURITY_CONTACT,
)

# The onboarding request could not be built.
PresentingError = PresentationError


def connection_info(connection) -> ConnectionInfo:
    """
    ``ConnectionInfo`` of a ``SignetConnection`` (or anything with some of its fields).

    The library never sees the record itself: it works on this copy, and the caller
    writes any new token back (``AuthResult.apply_to``).
    """
    return ConnectionInfo(
        base_url=getattr(connection, "base_url", ""),
        hab_aid=getattr(connection, "hab_aid", ""),
        credential_said=getattr(connection, "selected_credential_said", ""),
        server_aid=getattr(connection, "server_aid", ""),
        client_id=getattr(connection, "client_id", ""),
        client_name=getattr(connection, "client_name", ""),
        purpose=getattr(connection, "purpose", ""),
        redirect_uris=list(getattr(connection, "redirect_uris", None) or []),
        scopes=getattr(connection, "scopes", ""),
        access_token=getattr(connection, "access_token", ""),
        token_type=getattr(connection, "token_type", ""),
        token_scope=getattr(connection, "token_scope", ""),
        token_expires_at=getattr(connection, "token_expires_at", ""),
    )


def build_dcr_request(
    vault,
    connection,
    client_name: str = "",
    redirect_uris: list[str] | None = None,
) -> dict[str, Any]:
    """Body of the registration POST for ``connection``, in the configured format."""
    return presentation.build_dcr_request(
        vault.hby,
        vault.rgy.reger,
        connection_info(connection),
        configing.client_options(),
        client_name=client_name,
        redirect_uris=redirect_uris,
    )


def build_token_assertion(vault, connection) -> str:
    """``client_assertion`` of the token request for ``connection``."""
    return presentation.build_token_assertion(
        vault.hby,
        vault.rgy.reger,
        connection_info(connection),
        configing.client_options(),
    )


def build_onboarding_request(
    vault,
    credential: dict[str, Any],
    endpoint: str,
    server_aid: str,
    redirect_uris: list[str] | None = None,
) -> OnboardingRequest:
    """
    Build the onboarding request for ``credential`` (``{said, holder_pre, role}``) in the
    configured format (SIGNET_ONBOARDING_FORMAT). Built fresh per call: the grant's
    ``dt`` is the server's replay guard.

    In mock mode nothing is built: the request has an empty body.
    """
    options = configing.client_options()
    if configing.is_mock_mode():
        return OnboardingRequest(
            url=endpoint,
            body=b"",
            content_type=(
                presentation.CONTENT_TYPE_JSON
                if options.is_json
                else presentation.CONTENT_TYPE_CESR
            ),
            correlation_id=uuid.uuid4().hex[:16],
            server_aid=server_aid,
        )
    return presentation.build_onboarding_request(
        vault.hby,
        vault.rgy.reger,
        credential["said"],
        credential.get("holder_pre", ""),
        endpoint,
        server_aid,
        options,
        redirect_uris=redirect_uris,
        role=credential.get("role", ""),
        packet_defaults=PACKET_DEFAULTS,
    )
