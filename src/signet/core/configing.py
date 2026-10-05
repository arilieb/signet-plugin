# -*- encoding: utf-8 -*-
"""
signet.core.configing module

Mock-mode gate for the signet plugin. Real remoting calls hit Onyx's UDAP
vLEI onboarding servers per the design doc, but short-circuit to canned
responses in mock_data when running in the DEVELOPMENT environment, so the
Connections flow is clickable/demoable before those servers exist.
"""

import os

from locksmith.core.configing import Environments, LocksmithConfig

# Placeholder base URL for Onyx's UDAP onboarding servers. Real per-connection
# base_urls will come from each SignetConnection once Onyx provisions
# per-partner endpoints; this is only used by seed/mock data today.
DEFAULT_ONYX_BASE_URL = "https://onyx.example.com"


DEFAULT_LOCAL_PARTNER_URL = "http://127.0.0.1:8000"


def _is_development() -> bool:
    return LocksmithConfig.get_instance().environment == Environments.DEVELOPMENT


def is_live_dev() -> bool:
    """True in the DEVELOPMENT environment with SIGNET_LIVE=1: real calls to local infrastructure."""
    return _is_development() and os.environ.get("SIGNET_LIVE", "") in ("1", "true")


def is_mock_mode() -> bool:
    """True when remoting calls should short-circuit to canned mock responses."""
    return _is_development() and not is_live_dev()


def partner_url() -> str:
    """Base URL of the local Echelon server used in live dev (SIGNET_PARTNER_URL)."""
    return os.environ.get("SIGNET_PARTNER_URL", DEFAULT_LOCAL_PARTNER_URL).rstrip("/")


def registrar_url() -> str:
    """Base URL of the registrar hosting credential chains (SIGNET_REGISTRAR_URL)."""
    return os.environ.get("SIGNET_REGISTRAR_URL", "").rstrip("/")
