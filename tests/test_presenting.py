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


def _stub_embeds(monkeypatch, hab):
    sad = {"v": "ACDC10JSON000000_", "d": "", "i": hab.pre, "s": "Eschema"}
    _, sad = coring.Saider.saidify(sad=sad, kind="JSON", label="d")
    acdc = coring.Sadder(ked=sad, kind="JSON").raw
    monkeypatch.setattr(presenting, "_grant_embeds", lambda vault, said: {"acdc": acdc})
    return sad["d"]


def test_build_token_assertion_shape(monkeypatch, hab):
    import time

    class Vault:
        hby = hab._test_hby

    said = _stub_embeds(monkeypatch, hab)
    conn = _dcr_connection(hab)
    first = presenting.build_token_assertion(Vault, conn)
    time.sleep(0.01)
    second = presenting.build_token_assertion(Vault, conn)

    exn = serdering.SerderKERI(raw=first.encode())
    assert exn.ked["r"] == "/ipex/grant"
    assert exn.ked["i"] == hab.pre
    assert exn.ked["a"]["i"] == "Esrv"
    assert exn.ked["a"]["udap"] == {}
    assert exn.ked["e"]["acdc"]["d"] == said
    # signed by the holder: attachments follow the exn body
    assert len(first.encode()) > exn.size
    assert serdering.SerderKERI(raw=second.encode()).ked["dt"] != exn.ked["dt"]


def test_build_token_assertion_errors(hab):
    class Vault:
        hby = hab._test_hby

    conn = _dcr_connection(hab)
    conn.hab_aid = "Enope"
    with pytest.raises(presenting.PresentingError, match="identifier"):
        presenting.build_token_assertion(Vault, conn)

    for field in ("selected_credential_said", "server_aid"):
        conn = _dcr_connection(hab)
        setattr(conn, field, "")
        with pytest.raises(presenting.PresentingError, match="credential or server"):
            presenting.build_token_assertion(Vault, conn)


def _packet_setup(monkeypatch, hab, le_aid=None):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: False)
    acdc, said = _acdc_for(hab.pre)
    monkeypatch.setattr(presenting, "_grant_embeds", lambda vault, s: {"acdc": acdc})
    monkeypatch.setattr(presenting, "legal_entity_aid", lambda v, s: le_aid)
    monkeypatch.setattr(
        presenting,
        "witness_oobi_urls",
        lambda h, pre=None: [f"http://w/oobi/{pre or h.pre}"],
    )
    return said


def test_build_packet_shape(monkeypatch, hab):
    import json

    said = _packet_setup(monkeypatch, hab, le_aid="Ele")
    req = presenting.build_onboarding_packet(
        _vault(hab, hab.pre),
        {"said": said, "holder_pre": hab.pre, "role": "Data Exchange Representative"},
        "http://s/onboarding",
        "Esrv",
    )

    assert req.content_type == "application/json"
    packet = json.loads(req.body)
    assert set(packet) == {
        "correlation_id",
        "legal_entity",
        "submitter",
        "requested_purposes",
        "client_metadata",
        "contacts",
        "ipex_grant",
    }
    assert packet["correlation_id"] == req.correlation_id
    assert packet["legal_entity"] == {
        "lei": presenting.DEMO_LEI,
        "aid": "Ele",
        "qvi_lei": presenting.DEMO_QVI_LEI,
        "oobi": ["http://w/oobi/Ele"],
    }
    assert packet["submitter"] == {"role": "Data Exchange Representative"}
    assert packet["requested_purposes"] == [
        {"purpose": "TREAT", "scopes": presenting.DEMO_SCOPES}
    ]
    assert packet["client_metadata"] == {}
    assert packet["contacts"] == {
        "technical": presenting.DEMO_TECHNICAL_CONTACT,
        "security": presenting.DEMO_SECURITY_CONTACT,
    }

    exn = serdering.SerderKERI(raw=packet["ipex_grant"].encode())
    assert exn.ked["r"] == "/ipex/grant"
    assert exn.ked["i"] == hab.pre
    assert exn.ked["a"] == {"m": "", "i": "Esrv"}
    assert exn.ked["e"]["acdc"]["d"] == said
    assert req.hab_aid == hab.pre and req.server_aid == "Esrv"


def test_build_packet_le_aid_falls_back_to_hab(monkeypatch, hab):
    import json

    said = _packet_setup(monkeypatch, hab)
    req = presenting.build_onboarding_packet(
        _vault(hab, hab.pre),
        {"said": said, "holder_pre": hab.pre},
        "http://s/o",
        "Esrv",
    )
    assert json.loads(req.body)["legal_entity"]["aid"] == hab.pre


def test_build_packet_requires_server_aid(monkeypatch, hab):
    said = _packet_setup(monkeypatch, hab)
    with pytest.raises(
        presenting.PresentingError, match="SIGNET_ONBOARDING_SERVER_AID"
    ):
        presenting.build_onboarding_packet(
            _vault(hab, hab.pre),
            {"said": said, "holder_pre": hab.pre},
            "http://s/o",
            "",
        )


def test_build_packet_requires_witness_oobis(monkeypatch, hab):
    said = _packet_setup(monkeypatch, hab)
    monkeypatch.setattr(presenting, "witness_oobi_urls", lambda h, pre=None: [])
    with pytest.raises(presenting.PresentingError, match="witness"):
        presenting.build_onboarding_packet(
            _vault(hab, hab.pre),
            {"said": said, "holder_pre": hab.pre},
            "http://s/o",
            "Esrv",
        )


def test_build_packet_mock_mode_is_empty(monkeypatch, hab):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: True)
    req = presenting.build_onboarding_packet(
        _vault(hab, hab.pre), {"said": "E1"}, "http://s/o", "Esrv"
    )
    assert req.body == b"" and req.content_type == "application/json"
    assert req.correlation_id


def test_build_request_dispatches_on_format(monkeypatch, hab):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: True)
    args = (_vault(hab, hab.pre), {"said": "E1"}, "http://s/o", "Esrv")

    monkeypatch.delenv("SIGNET_ONBOARDING_FORMAT", raising=False)
    assert presenting.build_onboarding_request(*args).content_type == "application/cesr"
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
    assert presenting.build_onboarding_request(*args).content_type == "application/json"


def test_build_packet_omit_grant(monkeypatch, hab):
    import json

    said = _packet_setup(monkeypatch, hab, le_aid="Ele")
    monkeypatch.setenv("SIGNET_ONBOARDING_OMIT_GRANT", "1")

    def no_grant(*a, **kw):
        raise AssertionError("grant must not be built")

    monkeypatch.setattr(presenting, "_build_grant_message", no_grant)
    req = presenting.build_onboarding_packet(
        _vault(hab, hab.pre),
        {"said": said, "holder_pre": hab.pre, "role": "R"},
        "http://s/o",
        "",  # no server AID needed without a grant
    )
    packet = json.loads(req.body)
    assert "ipex_grant" not in packet
    assert packet["legal_entity"]["aid"] == "Ele"
    assert packet["submitter"] == {"role": "R"}
    assert req.hab_aid == hab.pre
