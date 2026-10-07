import pytest
from keri.app import habbing
from keri.core import coring, serdering
from keri.help import helping

from signet.core import configing, presenting


@pytest.fixture
def hab():
    with habbing.openHby(name="signet-test", temp=True) as hby:
        hab = hby.makeHab(name="holder")
        hab._test_hby = hby
        yield hab


def test_build_oobis_requires_witness(hab):
    with pytest.raises(presenting.PresentingError, match="witness"):
        presenting.build_oobis(hab, "ESAID")


def test_build_request_unknown_holder(monkeypatch, hab):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: False)

    class Vault:
        hby = hab._test_hby

    with pytest.raises(presenting.PresentingError, match="local identifier"):
        presenting.build_onboarding_grant(
            Vault,
            {"said": "E1", "holder_pre": "Enope"},
            "http://s/udap/onboarding",
            "Esrv",
        )


def _acdc_for(issuee):
    sad = {
        "v": "ACDC10JSON000000_",
        "d": "",
        "i": "Eissuer",
        "s": "Eschema",
        "a": {"d": "", "i": issuee},
    }
    _, sad = coring.Saider.saidify(sad=sad, kind="JSON", label="d")
    return coring.Sadder(ked=sad, kind="JSON").raw, sad["d"]


def _vault(hab, issuee):
    class Creder:
        attrib = {"i": issuee}

    class Creds:
        def get(self, keys):
            return Creder()

    class Reger:
        creds = Creds()

    class Rgy:
        reger = Reger()

    class Vault:
        hby = hab._test_hby
        rgy = Rgy()

    return Vault


def test_build_request_grant_shape(monkeypatch, hab):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: False)
    acdc, said = _acdc_for(hab.pre)
    oobis = [{"type": "aid", "aid": hab.pre, "url": "http://w/oobi"}]
    monkeypatch.setattr(presenting, "_grant_embeds", lambda vault, s: {"acdc": acdc})
    monkeypatch.setattr(presenting, "build_oobis", lambda h, s, le=None: oobis)
    monkeypatch.setattr(presenting, "legal_entity_aid", lambda v, s: None)

    before = helping.nowUTC()
    req = presenting.build_onboarding_grant(
        _vault(hab, hab.pre),
        {"said": said, "holder_pre": hab.pre},
        "http://s/udap/onboarding",
        "Esrv",
        contacts=["a@b.c"],
        redirect_uris=["http://127.0.0.1:9000/cb"],
    )

    assert isinstance(req.body, bytes)
    assert not hasattr(req, "headers") and not hasattr(req, "packet")
    exn = serdering.SerderKERI(raw=req.body)
    assert exn.ked["r"] == "/ipex/grant"
    assert exn.ked["i"] == hab.pre
    assert exn.ked["a"]["i"] == "Esrv"
    assert exn.ked["a"]["udap"] == {
        "requested_purposes": ["TREAT"],
        "contacts": ["a@b.c"],
        "redirect_uris": ["http://127.0.0.1:9000/cb"],
        "correlation_id": req.correlation_id,
        "oobis": oobis,
    }
    assert exn.ked["e"]["acdc"]["d"] == said
    assert helping.fromIso8601(exn.ked["dt"]) >= before.replace(microsecond=0)
    assert len(req.body) > exn.size  # signature and pathed attachments follow
    assert req.hab_name == "holder" and req.hab_aid == hab.pre
    assert req.server_aid == "Esrv"
    assert len(req.correlation_id) == 16


def test_build_request_issuee_must_be_holder(monkeypatch, hab):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: False)
    acdc, said = _acdc_for("Eother")
    monkeypatch.setattr(presenting, "_grant_embeds", lambda vault, s: {"acdc": acdc})

    with pytest.raises(presenting.PresentingError, match="not issued"):
        presenting.build_onboarding_grant(
            _vault(hab, "Eother"),
            {"said": said, "holder_pre": hab.pre},
            "http://s/udap/onboarding",
            "Esrv",
        )


def test_build_request_mock_mode_is_empty(monkeypatch, hab):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: True)
    req = presenting.build_onboarding_grant(
        _vault(hab, hab.pre), {"said": "E1"}, "http://s/udap/onboarding", "Esrv"
    )
    assert req.body == b"" and req.correlation_id


def _dcr_connection(hab, **kw):
    from signet.db.basing import SignetConnection

    return SignetConnection(
        connection_id="c1",
        hab_aid=hab.pre,
        hab_name=hab.name,
        server_aid="Esrv",
        selected_credential_said="ECRED",
        purpose="TREAT",
        client_name="Onyx",
        redirect_uris=["http://127.0.0.1:9000/cb"],
        **kw,
    )


def test_build_dcr_request_shape(hab):

    from keri.core import serdering
    from keri.help import helping

    class Vault:
        hby = hab._test_hby

    from keri.core import coring

    sad = {"v": "ACDC10JSON000000_", "d": "", "i": hab.pre, "s": "Eschema"}
    _, sad = coring.Saider.saidify(sad=sad, kind="JSON", label="d")
    acdc = coring.Sadder(ked=sad, kind="JSON").raw
    said = sad["d"]
    presenting._grant_embeds_orig = presenting._grant_embeds
    presenting._grant_embeds = lambda vault, said: {"acdc": acdc}
    try:
        before = helping.nowUTC()
        body = presenting.build_dcr_request(Vault, _dcr_connection(hab))
    finally:
        presenting._grant_embeds = presenting._grant_embeds_orig

    assert body["software_statement_type"] == presenting.DCR_STATEMENT_TYPE
    assert body["udap"] == "1"
    exn = serdering.SerderKERI(raw=body["software_statement"].encode())
    assert exn.ked["r"] == "/ipex/grant"
    assert exn.ked["i"] == hab.pre
    assert exn.ked["a"]["i"] == "Esrv"
    assert exn.ked["a"]["udap"] == {
        "purpose": "TREAT",
        "client_name": "Onyx",
        "redirect_uris": ["http://127.0.0.1:9000/cb"],
    }
    assert exn.ked["e"]["acdc"]["d"] == said
    assert helping.fromIso8601(exn.ked["dt"]) >= before.replace(microsecond=0)


def test_build_dcr_request_unknown_hab(hab):
    class Vault:
        hby = hab._test_hby

    conn = _dcr_connection(hab)
    conn.hab_aid = "Enope"
    with pytest.raises(presenting.PresentingError, match="identifier"):
        presenting.build_dcr_request(Vault, conn)
