"""
The presenting adapter: a vault and a SignetConnection in, the library's request
builders called with explicit arguments. The wire shapes of both dialects are covered
by acdc-auth-client's own tests; these pin the unpacking, the defaults and the mock gate.
"""

import asyncio
import threading
from types import SimpleNamespace

import pytest
from acdc_auth_client.core.options import ConnectionInfo
from acdc_auth_client.keri import grants
from acdc_auth_client.models.errors import PresentationError
from keri.app import habbing
from keri.core import coring, serdering

from signet.core import configing, presenting
from signet.db.basing import SignetConnection


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: False)
    for var in ("SIGNET_ONBOARDING_FORMAT", "SIGNET_ONBOARDING_SERVER_AID"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def hab():
    with habbing.openHby(name="signet-test", temp=True) as hby:
        hab = hby.makeHab(name="holder")
        hab._test_hby = hby
        yield hab


def _vault(hby=None, reger=None):
    return SimpleNamespace(
        hby=hby or object(), rgy=SimpleNamespace(reger=reger or object())
    )


def _connection(**kw):
    values = dict(
        connection_id="c1",
        base_url="http://s",
        hab_aid="Eaid",
        server_aid="Esrv",
        selected_credential_said="ECRED",
        purpose="treatment",
        client_name="Onyx",
        redirect_uris=["http://127.0.0.1:9000/cb"],
        client_id="srv-1",
        scopes="system/Group.read",
        access_token="tok",
        token_type="Bearer",
        token_scope="read",
        token_expires_at="2099-01-01T00:00:00+00:00",
    )
    values.update(kw)
    return SignetConnection(**values)


def test_presenting_error_is_the_librarys():
    assert presenting.PresentingError is PresentationError


def test_connection_info_maps_a_signet_connection():
    info = presenting.connection_info(_connection())
    assert info == ConnectionInfo(
        base_url="http://s",
        hab_aid="Eaid",
        credential_said="ECRED",  # selected_credential_said
        server_aid="Esrv",
        client_id="srv-1",
        client_name="Onyx",
        purpose="treatment",
        redirect_uris=["http://127.0.0.1:9000/cb"],
        scopes="system/Group.read",
        access_token="tok",
        token_type="Bearer",
        token_scope="read",
        token_expires_at="2099-01-01T00:00:00+00:00",
    )


def test_connection_info_copies_the_redirect_uris():
    connection = _connection()
    info = presenting.connection_info(connection)
    info.redirect_uris.append("http://other")
    assert connection.redirect_uris == ["http://127.0.0.1:9000/cb"]


def test_connection_info_tolerates_a_partial_record():
    info = presenting.connection_info(
        SimpleNamespace(base_url="http://s", token_scope="x")
    )
    assert info == ConnectionInfo(base_url="http://s", token_scope="x")


@pytest.fixture
def seen(monkeypatch):
    """Records the calls to the library's builders."""
    calls = []

    def recorder(name, result):
        def record(*args, **kwargs):
            calls.append((name, args, kwargs))
            return result

        return record

    monkeypatch.setattr(
        presenting.presentation, "build_dcr_request", recorder("dcr", {"udap": "1"})
    )
    monkeypatch.setattr(
        presenting.presentation, "build_token_assertion", recorder("token", "assertion")
    )
    monkeypatch.setattr(
        presenting.presentation,
        "build_onboarding_request",
        recorder("onboarding", "request"),
    )
    return calls


def test_build_dcr_request_passes_the_vault_and_options(seen, monkeypatch):
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
    vault = _vault()
    body = presenting.build_dcr_request(
        vault, _connection(), client_name="Name", redirect_uris=["http://r"]
    )
    assert body == {"udap": "1"}
    ((name, args, kwargs),) = seen
    hby, reger, info, options = args
    assert (hby, reger) == (vault.hby, vault.rgy.reger)
    assert info.credential_said == "ECRED" and info.hab_aid == "Eaid"
    assert options.is_json
    assert kwargs == {"client_name": "Name", "redirect_uris": ["http://r"]}


def test_build_token_assertion_passes_the_vault_and_options(seen):
    vault = _vault()
    assert presenting.build_token_assertion(vault, _connection()) == "assertion"
    ((name, args, kwargs),) = seen
    hby, reger, info, options = args
    assert (hby, reger) == (vault.hby, vault.rgy.reger)
    assert info.server_aid == "Esrv"
    assert not options.is_json


def test_build_onboarding_request_unpacks_the_credential(seen, monkeypatch):
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
    monkeypatch.setenv("SIGNET_ONBOARDING_SERVER_AID", "Eenv")
    vault = _vault()
    request = presenting.build_onboarding_request(
        vault,
        {"said": "ECRED", "holder_pre": "Eaid", "role": "Engineer"},
        "http://s/udap/onboarding",
        "Esrv",
        redirect_uris=["http://r"],
    )
    assert request == "request"
    ((name, args, kwargs),) = seen
    assert args[:6] == (
        vault.hby,
        vault.rgy.reger,
        "ECRED",
        "Eaid",
        "http://s/udap/onboarding",
        "Esrv",
    )
    assert args[6].is_json and args[6].server_aid == "Eenv"
    assert kwargs == {
        "redirect_uris": ["http://r"],
        "role": "Engineer",
        "packet_defaults": presenting.PACKET_DEFAULTS,
    }


def test_packet_defaults_are_the_demo_values():
    defaults = presenting.PACKET_DEFAULTS
    assert defaults.lei == presenting.DEMO_LEI
    assert defaults.qvi_lei == presenting.DEMO_QVI_LEI
    assert defaults.technical_contact == presenting.DEMO_TECHNICAL_CONTACT
    assert defaults.security_contact == presenting.DEMO_SECURITY_CONTACT


@pytest.mark.parametrize(
    "dialect, content_type",
    [("cesr", "application/cesr"), ("json", "application/json")],
)
def test_build_onboarding_request_mock_mode_is_empty(
    seen, monkeypatch, dialect, content_type
):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: True)
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", dialect)
    request = presenting.build_onboarding_request(
        _vault(), {"said": "E1"}, "http://s/udap/onboarding", "Esrv"
    )
    assert request.body == b"" and request.content_type == content_type
    assert request.url == "http://s/udap/onboarding" and request.server_aid == "Esrv"
    assert len(request.correlation_id) == 16
    assert not seen  # nothing was built


def _stub_embeds(monkeypatch, hab):
    """The credential embeds are stubbed: there is no issued credential chain here."""
    sad = {
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": "Eissuer",
        "s": "Eschema",
        "a": {"d": "", "i": hab.pre},
    }
    _, sad = coring.Saider.saidify(sad=sad, kind="JSON", label="d")
    acdc = coring.Sadder(ked=sad, kind="JSON").raw
    monkeypatch.setattr(grants, "grant_embeds", lambda hby, reger, said: {"acdc": acdc})


def test_token_assertion_is_a_signed_grant_from_the_vaults_identifier(monkeypatch, hab):
    _stub_embeds(monkeypatch, hab)
    connection = _connection(hab_aid=hab.pre)
    assertion = presenting.build_token_assertion(_vault(hab._test_hby), connection)

    exn = serdering.SerderKERI(raw=assertion.encode("utf-8"))
    assert exn.ked["r"] == "/ipex/grant"
    assert exn.ked["i"] == hab.pre
    assert exn.ked["a"]["i"] == "Esrv"
    assert exn.ked["a"]["udap"] == {}
    assert len(assertion) > exn.size  # the signature follows


async def test_assertions_build_in_worker_threads(monkeypatch, hab):
    # The facade runs the library in threads: the habery (opened on the main thread)
    # must sign concurrently from them.
    _stub_embeds(monkeypatch, hab)
    connection = _connection(hab_aid=hab.pre)
    vault = _vault(hab._test_hby)
    threads = []

    def build():
        threads.append(threading.current_thread())
        return presenting.build_token_assertion(vault, connection)

    built = await asyncio.gather(*[asyncio.to_thread(build) for _ in range(6)])

    assert threading.main_thread() not in threads
    assert len(set(built)) == 6  # each is fresh (its own ``dt``/signature)


def test_dcr_request_carries_the_connections_client_metadata(monkeypatch, hab):
    _stub_embeds(monkeypatch, hab)
    connection = _connection(hab_aid=hab.pre)
    body = presenting.build_dcr_request(_vault(hab._test_hby), connection)

    assert body["udap"] == "1"
    exn = serdering.SerderKERI(raw=body["software_statement"].encode("utf-8"))
    assert exn.ked["a"]["udap"] == {
        "purpose": "treatment",
        "client_name": "Onyx",
        "redirect_uris": ["http://127.0.0.1:9000/cb"],
    }


def test_an_unknown_identifier_is_a_presenting_error(hab):
    with pytest.raises(presenting.PresentingError, match="not in this vault"):
        presenting.build_token_assertion(
            _vault(hab._test_hby), _connection(hab_aid="Eunknown")
        )
