# -*- encoding: utf-8 -*-
"""
signet.core.configing module

Mock-mode gate for the signet plugin. Real remoting calls hit Onyx's UDAP
vLEI onboarding servers per the design doc, but short-circuit to canned
responses in mock_data when running in the DEVELOPMENT environment, so the
Connections flow is clickable/demoable before those servers exist.
"""
from locksmith.core.configing import Environments, LocksmithConfig

# Placeholder base URL for Onyx's UDAP onboarding servers. Real per-connection
# base_urls will come from each SignetConnection once Onyx provisions
# per-partner endpoints; this is only used by seed/mock data today.
DEFAULT_ONYX_BASE_URL = "https://onyx.example.com"


def is_mock_mode() -> bool:
    """True when remoting calls should short-circuit to canned mock responses."""
    return LocksmithConfig.get_instance().environment == Environments.DEVELOPMENT
