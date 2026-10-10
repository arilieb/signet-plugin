from locksmith.core.configing import Environments, LocksmithConfig

from signet.core import configing, credentials, devbootstrap, mock_data


def _env(monkeypatch, environment, live=None):
    monkeypatch.setattr(
        LocksmithConfig,
        "get_instance",
        classmethod(lambda cls: type("C", (), {"environment": environment})()),
    )
    if live is None:
        monkeypatch.delenv("SIGNET_LIVE", raising=False)
    else:
        monkeypatch.setenv("SIGNET_LIVE", live)


def test_development_is_mock_by_default(monkeypatch):
    _env(monkeypatch, Environments.DEVELOPMENT)
    assert configing.is_mock_mode() and not configing.is_live_dev()
    assert len(mock_data.discoverable_connections()) == 3


def test_live_flag_disables_mock(monkeypatch):
    _env(monkeypatch, Environments.DEVELOPMENT, live="1")
    assert configing.is_live_dev() and not configing.is_mock_mode()
    (partner,) = mock_data.discoverable_connections()
    assert partner["display_name"] == "Local Echelon"
    assert partner["base_url"] == "http://127.0.0.1:8000"
    assert partner["purpose"] == "TREAT"
    assert credentials.filter_credentials(None) == []


def test_partner_url_override(monkeypatch):
    monkeypatch.setenv("SIGNET_PARTNER_URL", "http://x:9/")
    assert configing.partner_url() == "http://x:9"


def test_production_ignores_live_flag(monkeypatch):
    _env(monkeypatch, Environments.PRODUCTION, live="1")
    assert not configing.is_live_dev() and not configing.is_mock_mode()
    assert mock_data.discoverable_connections() == []


def test_dev_oobis_include_extras(monkeypatch):
    monkeypatch.setenv("SIGNET_DEV_OOBIS", "http://a/oobi/E1, http://b/oobi/E2")
    oobis = devbootstrap.dev_oobis()
    assert oobis[-2:] == ["http://a/oobi/E1", "http://b/oobi/E2"]
    assert len(oobis) == 12


def test_accepted_credential_schemas(monkeypatch):
    monkeypatch.delenv("SIGNET_CREDENTIAL_SCHEMAS", raising=False)
    assert configing.accepted_credential_schemas() == (configing.LESR_SCHEMA_SAID,)
    monkeypatch.setenv("SIGNET_CREDENTIAL_SCHEMAS", " E1 ,E2,, ")
    assert configing.accepted_credential_schemas() == ("E1", "E2")
    monkeypatch.setenv("SIGNET_CREDENTIAL_SCHEMAS", "  ")
    assert configing.accepted_credential_schemas() == (configing.LESR_SCHEMA_SAID,)


def test_onboarding_format(monkeypatch):
    monkeypatch.delenv("SIGNET_ONBOARDING_FORMAT", raising=False)
    assert configing.onboarding_format() == "cesr"
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", " JSON ")
    assert configing.onboarding_format() == "json"
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "other")
    assert configing.onboarding_format() == "cesr"


def test_onboarding_server_aid(monkeypatch):
    monkeypatch.delenv("SIGNET_ONBOARDING_SERVER_AID", raising=False)
    assert configing.onboarding_server_aid() == ""
    monkeypatch.setenv("SIGNET_ONBOARDING_SERVER_AID", " Esrv ")
    assert configing.onboarding_server_aid() == "Esrv"


def test_is_keri_discovery_url():
    assert configing.is_keri_discovery_url("https://h/slapv3/pdexv2/.well-known/keri")
    assert configing.is_keri_discovery_url("https://h/.well-known/keri/")
    assert not configing.is_keri_discovery_url("https://h/slapv3")
    assert not configing.is_keri_discovery_url("https://h/.well-known/udap")


def test_partner_url_set_detection(monkeypatch):
    monkeypatch.delenv("SIGNET_PARTNER_URL", raising=False)
    assert not configing.is_partner_url_set()
    monkeypatch.setenv("SIGNET_PARTNER_URL", "  ")
    assert not configing.is_partner_url_set()
    monkeypatch.setenv("SIGNET_PARTNER_URL", "https://h/.well-known/keri")
    assert configing.is_partner_url_set()


def test_explicit_partner_offered_outside_mock(monkeypatch):
    _env(monkeypatch, Environments.PRODUCTION)
    monkeypatch.setenv(
        "SIGNET_PARTNER_URL", "https://api.example.io/x/.well-known/keri"
    )
    (partner,) = mock_data.discoverable_connections()
    assert partner["base_url"] == "https://api.example.io/x/.well-known/keri"
    assert partner["connection_id"] == "api-example-io"
    assert partner["purpose"] == "TREAT"


def test_mock_mode_ignores_explicit_partner(monkeypatch):
    _env(monkeypatch, Environments.DEVELOPMENT)
    monkeypatch.setenv("SIGNET_PARTNER_URL", "https://h/.well-known/keri")
    assert len(mock_data.discoverable_connections()) == 3


def test_onboarding_endpoint_override(monkeypatch):
    monkeypatch.delenv("SIGNET_ONBOARDING_ENDPOINT", raising=False)
    assert configing.onboarding_endpoint_override() == ""
    monkeypatch.setenv("SIGNET_ONBOARDING_ENDPOINT", " https://h/onboarding ")
    assert configing.onboarding_endpoint_override() == "https://h/onboarding"


def test_omit_ipex_grant(monkeypatch):
    monkeypatch.delenv("SIGNET_ONBOARDING_OMIT_GRANT", raising=False)
    assert not configing.omit_ipex_grant()
    for value in ("1", " TRUE "):
        monkeypatch.setenv("SIGNET_ONBOARDING_OMIT_GRANT", value)
        assert configing.omit_ipex_grant()
    monkeypatch.setenv("SIGNET_ONBOARDING_OMIT_GRANT", "0")
    assert not configing.omit_ipex_grant()
