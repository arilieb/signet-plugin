import pytest
from locksmith.core.configing import Environments, LocksmithConfig

from signet.db.basing import SignetConnection
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


_OPTION_VARS = (
    "SIGNET_ONBOARDING_FORMAT",
    "SIGNET_ONBOARDING_ENDPOINT",
    "SIGNET_REGISTRATION_ENDPOINT",
    "SIGNET_TOKEN_ENDPOINT",
    "SIGNET_ONBOARDING_SERVER_AID",
    "SIGNET_FHIR_BASE_URL",
    "SIGNET_EXPORT_METHOD",
    "SIGNET_EXPORT_STATUS_URL_PREFIX",
    "SIGNET_ONBOARDING_SCOPES",
    "SIGNET_ONBOARDING_OMIT_GRANT",
    "SIGNET_ONBOARDING_OOBI",
    "SIGNET_DCR_OOBI",
    "SIGNET_ASSUME_PALANTIR_OOBIS",
    "SIGNET_REGISTRAR_URL",
)


def test_client_options_defaults(monkeypatch):
    for var in _OPTION_VARS:
        monkeypatch.delenv(var, raising=False)
    options = configing.client_options()
    assert options.dialect == "cesr" and not options.is_json
    assert options.export_method == "POST"
    assert options.onboarding_scopes == ("system/Group.read",)
    assert options.onboarding_oobis == ()
    assert not options.omit_ipex_grant and not options.assume_palantir_oobis
    assert (
        options.onboarding_endpoint,
        options.registration_endpoint,
        options.token_endpoint,
        options.server_aid,
        options.fhir_base_url,
        options.export_status_url_prefix,
        options.dcr_oobi,
        options.registrar_url,
    ) == ("",) * 8


def test_client_options_reads_every_env_var(monkeypatch):
    env = {
        "SIGNET_ONBOARDING_FORMAT": "JSON",
        "SIGNET_ONBOARDING_ENDPOINT": " http://o/udap/onboarding ",
        "SIGNET_REGISTRATION_ENDPOINT": "http://o/register",
        "SIGNET_TOKEN_ENDPOINT": "http://o/token",
        "SIGNET_ONBOARDING_SERVER_AID": "Esrv",
        "SIGNET_FHIR_BASE_URL": "http://o/fhir/",
        "SIGNET_EXPORT_METHOD": "get",
        "SIGNET_EXPORT_STATUS_URL_PREFIX": "http://o/status",
        "SIGNET_ONBOARDING_SCOPES": "system/Group.read system/*.read",
        "SIGNET_ONBOARDING_OMIT_GRANT": "1",
        "SIGNET_ONBOARDING_OOBI": "http://w/oobi/a, http://w/oobi/b",
        "SIGNET_DCR_OOBI": "http://w/oobi/c",
        "SIGNET_ASSUME_PALANTIR_OOBIS": "true",
        "SIGNET_REGISTRAR_URL": "http://reg/",
    }
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    options = configing.client_options()
    assert options.to_dict() == {
        "dialect": "json",
        "onboarding_endpoint": "http://o/udap/onboarding",
        "registration_endpoint": "http://o/register",
        "token_endpoint": "http://o/token",
        "server_aid": "Esrv",
        "fhir_base_url": "http://o/fhir",
        "export_method": "GET",
        "export_status_url_prefix": "http://o/status/",
        "onboarding_scopes": ["system/Group.read", "system/*.read"],
        "omit_ipex_grant": True,
        "onboarding_oobis": ["http://w/oobi/a", "http://w/oobi/b"],
        "dcr_oobi": "http://w/oobi/c",
        "assume_palantir_oobis": True,
        "registrar_url": "http://reg",
        "timeout": options.timeout,
        "fhir_timeout": options.fhir_timeout,
    }


def test_client_options_unknown_values_fall_back(monkeypatch):
    # The library rejects an unknown dialect / export method; the env reader does not.
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "xml")
    monkeypatch.setenv("SIGNET_EXPORT_METHOD", "PUT")
    options = configing.client_options()
    assert options.dialect == "cesr" and options.export_method == "POST"


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


def test_onboarding_oobi_override(monkeypatch):
    monkeypatch.delenv("SIGNET_ONBOARDING_OOBI", raising=False)
    assert configing.onboarding_oobi_override() == []
    monkeypatch.setenv(
        "SIGNET_ONBOARDING_OOBI", " https://a/oobi/E1 , ,https://b/oobi/E1 "
    )
    assert configing.onboarding_oobi_override() == [
        "https://a/oobi/E1",
        "https://b/oobi/E1",
    ]


def test_assume_palantir_oobis(monkeypatch):
    monkeypatch.delenv("SIGNET_ASSUME_PALANTIR_OOBIS", raising=False)
    assert configing.assume_palantir_oobis() is False
    for value in ("1", " TRUE "):
        monkeypatch.setenv("SIGNET_ASSUME_PALANTIR_OOBIS", value)
        assert configing.assume_palantir_oobis() is True
    for value in ("0", "false", ""):
        monkeypatch.setenv("SIGNET_ASSUME_PALANTIR_OOBIS", value)
        assert configing.assume_palantir_oobis() is False


def test_is_json_format(monkeypatch):
    monkeypatch.delenv("SIGNET_ONBOARDING_FORMAT", raising=False)
    assert not configing.is_json_format()
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "cesr")
    assert not configing.is_json_format()
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", " JSON ")
    assert configing.is_json_format()


@pytest.mark.parametrize(
    "reader,var",
    [
        (configing.registration_endpoint_override, "SIGNET_REGISTRATION_ENDPOINT"),
        (configing.token_endpoint_override, "SIGNET_TOKEN_ENDPOINT"),
        (configing.dcr_oobi_override, "SIGNET_DCR_OOBI"),
    ],
)
def test_dcr_env_readers(monkeypatch, reader, var):
    monkeypatch.delenv(var, raising=False)
    assert reader() == ""
    monkeypatch.setenv(var, "   ")
    assert reader() == ""
    monkeypatch.setenv(var, " http://x/y ")
    assert reader() == "http://x/y"


def test_known_partner_gets_name_and_logo(monkeypatch):
    _env(monkeypatch, Environments.PRODUCTION)
    monkeypatch.setenv(
        "SIGNET_PARTNER_URL",
        "https://api-dmdh-dev.safhir.io/slapv3/pdexv2/.well-known/keri",
    )
    (partner,) = mock_data.discoverable_connections()
    assert partner["display_name"] == "Onyx"
    assert partner["logo_icon_path"].endswith("onyx-logo-black.png")


def test_unknown_partner_keeps_host_and_generic_icon(monkeypatch):
    _env(monkeypatch, Environments.PRODUCTION)
    monkeypatch.setenv("SIGNET_PARTNER_URL", "https://other.example.com")
    (partner,) = mock_data.discoverable_connections()
    assert partner["display_name"] == "other.example.com"
    assert partner["logo_icon_path"] == mock_data.GENERIC_PARTNER_ICON


def test_apply_known_partner_updates_stored_connection():
    stale = SignetConnection(
        connection_id="x",
        display_name="api-dmdh-dev.safhir.io",
        logo_icon_path=mock_data.GENERIC_PARTNER_ICON,
        base_url="https://api-dmdh-dev.safhir.io/slapv3/pdexv2/.well-known/keri",
    )
    assert mock_data.apply_known_partner(stale)
    assert stale.display_name == "Onyx"
    assert not mock_data.apply_known_partner(stale)  # idempotent
    other = SignetConnection(connection_id="y", base_url="https://other.example.com")
    assert not mock_data.apply_known_partner(other)
