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
    assert credentials.filter_ecr_credentials(None) == []


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
    assert len(oobis) == 3 + 4 + 2
