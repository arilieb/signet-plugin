import pytest
from keri.app import habbing
from keri.core import coring, serdering
from keri.help import helping

from types import SimpleNamespace

from signet.core import configing, presenting
from signet.core.credentials import LEGAL_ENTITY_SCHEMA_SAID


@pytest.fixture
def hab():
    with habbing.openHby(name="signet-test", temp=True) as hby:
        hab = hby.makeHab(name="holder")
        hab._test_hby = hby
        yield hab


def test_build_oobis_requires_witness(hab):
    with pytest.raises(presenting.PresentingError, match="witness"):
        presenting.build_oobis(hab, "ESAID")


_REAL_WITNESS_OOBI_URLS = presenting.witness_oobi_urls


class _WitnessedHab:
    """Stand-in hab whose single witness is reachable at ``surls``."""

    pre = "Ehab"

    def __init__(self, surls):
        self._surls = surls

    def fetchWitnessUrls(self, cid):
        return {"witness": {"Ewit": self._surls}}


class _NoFetchHab:
    pre = "Ehab"

    def fetchWitnessUrls(self, cid):
        raise AssertionError("keripy witness lookup must be skipped")


def test_witness_oobi_urls_from_witnesses(monkeypatch):
    monkeypatch.delenv("SIGNET_ASSUME_PALANTIR_OOBIS", raising=False)
    hab = _WitnessedHab({"http": "http://w:5642/", "https": "https://w:5643"})
    assert presenting.witness_oobi_urls(hab) == ["https://w:5643/oobi/Ehab"]
    assert presenting.witness_oobi_urls(hab, "Eother") == ["https://w:5643/oobi/Eother"]


def test_witness_oobi_urls_assume_palantir(monkeypatch):
    monkeypatch.setenv("SIGNET_ASSUME_PALANTIR_OOBIS", "1")
    hab = _NoFetchHab()
    assert presenting.witness_oobi_urls(hab) == [
        "https://palantir.healthkeri.net/oobi/Ehab"
    ]
    assert presenting.witness_oobi_urls(hab, "Eother") == [
        "https://palantir.healthkeri.net/oobi/Eother"
    ]


def test_build_oobis_assume_palantir_needs_no_witness(monkeypatch, hab):
    monkeypatch.setenv("SIGNET_ASSUME_PALANTIR_OOBIS", "true")
    monkeypatch.setenv("SIGNET_REGISTRAR_URL", "http://reg")
    oobis = presenting.build_oobis(hab, "ESAID", le_aid="Ele")
    assert oobis[:2] == [
        {
            "type": "aid",
            "aid": hab.pre,
            "url": f"https://palantir.healthkeri.net/oobi/{hab.pre}",
        },
        {
            "type": "aid",
            "aid": "Ele",
            "url": "https://palantir.healthkeri.net/oobi/Ele",
        },
    ]
    assert oobis[2]["type"] == "credential"


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


def _packet_setup(monkeypatch, hab, le=None):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: False)
    acdc, said = _acdc_for(hab.pre)
    monkeypatch.setattr(presenting, "_grant_embeds", lambda vault, s: {"acdc": acdc})
    monkeypatch.setattr(
        presenting,
        "_build_chain_stream",
        lambda vault, h, srv, s: presenting._build_grant_message(
            vault, h, srv, s, None
        ),
    )
    monkeypatch.setattr(presenting, "legal_entity_subunit", lambda v, s: le)
    monkeypatch.setattr(
        presenting,
        "witness_oobi_urls",
        lambda h, pre=None: [f"http://w/oobi/{pre or h.pre}"],
    )
    return said


def test_build_packet_shape(monkeypatch, hab):
    import json

    said = _packet_setup(monkeypatch, hab, le=("Ele", "LEI123"))
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
        "lei": "LEI123",
        "aid": "Ele",
        "qvi_lei": presenting.DEMO_QVI_LEI,
        "oobi": ["http://w/oobi/Ele"],
    }
    assert packet["submitter"] == {"role": "Data Exchange Representative"}
    assert packet["requested_purposes"] == [
        {"purpose": "TREAT", "scopes": configing.onboarding_scopes()}
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
    legal_entity = json.loads(req.body)["legal_entity"]
    assert legal_entity["aid"] == hab.pre
    assert legal_entity["lei"] == presenting.DEMO_LEI


def test_build_packet_simple_chain_legal_entity_is_holder(monkeypatch, hab):
    import json

    said = _packet_setup(monkeypatch, hab, le=(hab.pre, "LEI42"))
    req = presenting.build_onboarding_packet(
        _vault(hab, hab.pre),
        {"said": said, "holder_pre": hab.pre},
        "http://s/o",
        "Esrv",
    )
    legal_entity = json.loads(req.body)["legal_entity"]
    assert legal_entity["aid"] == hab.pre
    assert legal_entity["lei"] == "LEI42"


def test_build_packet_empty_lei_and_aid_fall_back(monkeypatch, hab):
    import json

    said = _packet_setup(monkeypatch, hab, le=("", ""))
    req = presenting.build_onboarding_packet(
        _vault(hab, hab.pre),
        {"said": said, "holder_pre": hab.pre},
        "http://s/o",
        "Esrv",
    )
    legal_entity = json.loads(req.body)["legal_entity"]
    assert legal_entity["aid"] == hab.pre
    assert legal_entity["lei"] == presenting.DEMO_LEI
    assert legal_entity["oobi"] == [f"http://w/oobi/{hab.pre}"]


def test_build_packet_oobi_override_wins(monkeypatch, hab):
    import json

    said = _packet_setup(monkeypatch, hab, le=("Ele", "LEI123"))
    monkeypatch.setenv("SIGNET_ONBOARDING_OOBI", "http://a/oobi/x, http://b/oobi/x")
    req = presenting.build_onboarding_packet(
        _vault(hab, hab.pre),
        {"said": said, "holder_pre": hab.pre},
        "http://s/o",
        "Esrv",
    )
    legal_entity = json.loads(req.body)["legal_entity"]
    assert legal_entity["aid"] == "Ele"
    assert legal_entity["oobi"] == ["http://a/oobi/x", "http://b/oobi/x"]


def test_build_packet_assume_palantir_oobis(monkeypatch, hab):
    import json

    said = _packet_setup(monkeypatch, hab, le=("Ele", "LEI123"))
    monkeypatch.setattr(presenting, "witness_oobi_urls", _REAL_WITNESS_OOBI_URLS)
    monkeypatch.setenv("SIGNET_ASSUME_PALANTIR_OOBIS", "1")
    req = presenting.build_onboarding_packet(
        _vault(hab, hab.pre),
        {"said": said, "holder_pre": hab.pre},
        "http://s/o",
        "Esrv",
    )
    legal_entity = json.loads(req.body)["legal_entity"]
    assert legal_entity["oobi"] == ["https://palantir.healthkeri.net/oobi/Ele"]


def test_build_packet_oobi_override_beats_assume_palantir(monkeypatch, hab):
    import json

    said = _packet_setup(monkeypatch, hab, le=("Ele", "LEI123"))
    monkeypatch.setattr(presenting, "witness_oobi_urls", _REAL_WITNESS_OOBI_URLS)
    monkeypatch.setenv("SIGNET_ASSUME_PALANTIR_OOBIS", "1")
    monkeypatch.setenv("SIGNET_ONBOARDING_OOBI", "http://a/oobi/x")
    req = presenting.build_onboarding_packet(
        _vault(hab, hab.pre),
        {"said": said, "holder_pre": hab.pre},
        "http://s/o",
        "Esrv",
    )
    assert json.loads(req.body)["legal_entity"]["oobi"] == ["http://a/oobi/x"]


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

    said = _packet_setup(monkeypatch, hab, le=("Ele", "LEI123"))
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


class _Msg:
    def __init__(self, said, raw=None, edge=None):
        self.said = said
        self.raw = raw if raw is not None else said.encode()
        self.size = len(self.raw)
        self.edge = edge


class _Qb64:
    def __init__(self, qb64b):
        self.qb64b = qb64b


def _edge(*saids):
    return {"d": "Eedge", **{f"e{i}": {"n": n} for i, n in enumerate(saids)}}


def _chain_vault(edges, missing=()):
    """Vault whose reger holds a credential per SAID in ``edges`` (said -> child SAIDs)."""
    creds = {
        s: _Msg(s, edge=_edge(*kids) if kids else None) for s, kids in edges.items()
    }

    class Reger:
        def cloneCred(self, said):
            if said in missing or said not in creds:
                raise presenting.kering.MissingEntryError(
                    f"no credential found with said {said}"
                )
            return creds[said], _Qb64(b"P"), _Qb64(b"S"), _Qb64(b"D")

    class Rgy:
        reger = Reger()

    class Vault:
        rgy = Rgy()
        hby = object()

    return Vault, creds


def test_chain_collector_dedupes_and_appends_attachment():
    c = presenting._ChainCollector()
    c.send(_Msg("A", b"aaa"), attachment=b"-1")
    c.send(_Msg("A", b"aaa"), attachment=b"-1")
    c.send(_Msg("B", b"bbb"))
    assert bytes(c.stream) == b"aaa-1bbb"


def test_chain_sources_post_order_diamond_and_cycle():
    # LESR -> Auth -> Subunit -> LE -> QVI, plus LESR -> QVI (diamond) and QVI -> LESR (cycle)
    vault, creds = _chain_vault(
        {
            "LESR": ["Auth", "QVI"],
            "Auth": ["Subunit"],
            "Subunit": ["LE"],
            "LE": ["QVI"],
            "QVI": ["LESR"],
        }
    )
    ordered = presenting._chain_sources(vault, creds["LESR"])
    assert [c.said for c, _ in ordered] == ["QVI", "LE", "Subunit", "Auth"]
    assert all(atc.startswith(b"-") or atc for _, atc in ordered)


def test_build_chain_stream_order(monkeypatch):
    vault, creds = _chain_vault({"LESR": ["QVI"], "QVI": []})
    calls = []

    def fake_send_artifacts(hby, reger, postman, creder, recp):
        calls.append(creder.said)
        postman.send(_Msg(f"kel-{creder.said}", f"[{creder.said}]".encode()))

    monkeypatch.setattr(presenting.credentialing, "sendArtifacts", fake_send_artifacts)
    monkeypatch.setattr(
        presenting, "_build_grant_message", lambda *a: bytearray(b"<grant>")
    )
    stream = presenting._build_chain_stream(vault, None, "Esrv", "LESR")
    assert calls == ["QVI", "LESR"]
    assert stream.endswith(b"<grant>")
    assert stream.index(b"[QVI]") < stream.index(b"[LESR]") < stream.index(b"<grant>")
    assert stream.decode("utf-8")


def test_build_chain_stream_missing_chain_member(monkeypatch):
    vault, _ = _chain_vault({"LESR": ["QVI"], "QVI": []}, missing=("QVI",))
    monkeypatch.setattr(presenting.credentialing, "sendArtifacts", lambda *a: None)
    with pytest.raises(presenting.PresentingError, match="QVI"):
        presenting._build_chain_stream(vault, None, "Esrv", "LESR")


def test_build_chain_stream_missing_issuer_kel(monkeypatch):
    vault, _ = _chain_vault({"LESR": []})

    def boom(*a):
        raise KeyError("Eissuer")

    monkeypatch.setattr(presenting.credentialing, "sendArtifacts", boom)
    with pytest.raises(presenting.PresentingError, match="LESR.*Eissuer"):
        presenting._build_chain_stream(vault, None, "Esrv", "LESR")


def _dcr_json_setup(monkeypatch, hab):
    """json-format DCR with the chain stream reduced to the plain grant exn."""
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
    monkeypatch.delenv("SIGNET_DCR_OOBI", raising=False)
    monkeypatch.delenv("SIGNET_ONBOARDING_SERVER_AID", raising=False)
    said = _stub_embeds(monkeypatch, hab)
    monkeypatch.setattr(
        presenting,
        "_build_chain_stream",
        lambda vault, h, srv, s: presenting._build_grant_message(
            vault, h, srv, s, None
        ),
    )
    monkeypatch.setattr(
        presenting,
        "witness_oobi_urls",
        lambda h, pre=None: ["http://w/oobi/E1", "http://x/oobi/E1"],
    )
    return said


class _HabVault:
    def __init__(self, hab):
        self.hby = hab._test_hby


def test_build_dcr_request_json_shape(monkeypatch, hab):
    _dcr_json_setup(monkeypatch, hab)
    body = presenting.build_dcr_request(_HabVault(hab), _dcr_connection(hab))

    assert set(body) == {"ipex_grant", "oobi", "purpose", "client_name", "grant_types"}
    assert body["oobi"] == "http://w/oobi/E1"
    assert body["purpose"] == presenting.REQUESTED_PURPOSE
    assert body["client_name"] == "Onyx"
    assert body["grant_types"] == ["client_credentials"]
    exn = serdering.SerderKERI(raw=body["ipex_grant"].encode())
    assert exn.ked["r"] == "/ipex/grant"
    assert exn.ked["a"] == {"m": "", "i": "Esrv"}


def test_build_dcr_request_json_purpose_is_requested_purpose(monkeypatch, hab):
    _dcr_json_setup(monkeypatch, hab)
    conn = _dcr_connection(hab)
    conn.purpose = "PAYMENT"
    body = presenting.build_dcr_request_json(_HabVault(hab), conn)
    assert body["purpose"] == presenting.REQUESTED_PURPOSE


def test_build_dcr_request_json_fresh_dt(monkeypatch, hab):
    import time

    _dcr_json_setup(monkeypatch, hab)
    first = presenting.build_dcr_request_json(_HabVault(hab), _dcr_connection(hab))
    time.sleep(0.01)
    second = presenting.build_dcr_request_json(_HabVault(hab), _dcr_connection(hab))
    assert first["ipex_grant"] != second["ipex_grant"]


def test_build_dcr_request_json_oobi_override(monkeypatch, hab):
    _dcr_json_setup(monkeypatch, hab)
    monkeypatch.setenv("SIGNET_DCR_OOBI", "http://o/oobi/E9")
    body = presenting.build_dcr_request_json(_HabVault(hab), _dcr_connection(hab))
    assert body["oobi"] == "http://o/oobi/E9"


def test_build_dcr_request_json_assume_palantir_oobis(monkeypatch, hab):
    _dcr_json_setup(monkeypatch, hab)
    monkeypatch.setattr(presenting, "witness_oobi_urls", _REAL_WITNESS_OOBI_URLS)
    monkeypatch.setenv("SIGNET_ASSUME_PALANTIR_OOBIS", "1")
    body = presenting.build_dcr_request_json(_HabVault(hab), _dcr_connection(hab))
    assert body["oobi"] == f"https://palantir.healthkeri.net/oobi/{hab.pre}"


def test_build_dcr_request_json_oobi_override_beats_assume_palantir(monkeypatch, hab):
    _dcr_json_setup(monkeypatch, hab)
    monkeypatch.setattr(presenting, "witness_oobi_urls", _REAL_WITNESS_OOBI_URLS)
    monkeypatch.setenv("SIGNET_ASSUME_PALANTIR_OOBIS", "1")
    monkeypatch.setenv("SIGNET_DCR_OOBI", "http://o/oobi/E9")
    body = presenting.build_dcr_request_json(_HabVault(hab), _dcr_connection(hab))
    assert body["oobi"] == "http://o/oobi/E9"


def test_build_dcr_request_json_server_aid_falls_back_to_env(monkeypatch, hab):
    _dcr_json_setup(monkeypatch, hab)
    conn = _dcr_connection(hab)
    conn.server_aid = ""
    with pytest.raises(presenting.PresentingError, match="server"):
        presenting.build_dcr_request_json(_HabVault(hab), conn)

    monkeypatch.setenv("SIGNET_ONBOARDING_SERVER_AID", "Eenv")
    body = presenting.build_dcr_request_json(_HabVault(hab), conn)
    exn = serdering.SerderKERI(raw=body["ipex_grant"].encode())
    assert exn.ked["a"]["i"] == "Eenv"


def test_build_dcr_request_json_requires_witness(monkeypatch, hab):
    _dcr_json_setup(monkeypatch, hab)
    monkeypatch.setattr(presenting, "witness_oobi_urls", lambda h, pre=None: [])
    with pytest.raises(presenting.PresentingError, match="witness"):
        presenting.build_dcr_request_json(_HabVault(hab), _dcr_connection(hab))


def test_build_dcr_request_json_unknown_hab_and_no_credential(monkeypatch, hab):
    _dcr_json_setup(monkeypatch, hab)
    conn = _dcr_connection(hab)
    conn.hab_aid = "Enope"
    with pytest.raises(presenting.PresentingError, match="identifier"):
        presenting.build_dcr_request_json(_HabVault(hab), conn)

    conn = _dcr_connection(hab)
    conn.selected_credential_said = ""
    with pytest.raises(presenting.PresentingError, match="credential"):
        presenting.build_dcr_request_json(_HabVault(hab), conn)


def test_build_dcr_request_cesr_unchanged_without_format(monkeypatch, hab):
    monkeypatch.delenv("SIGNET_ONBOARDING_FORMAT", raising=False)
    _stub_embeds(monkeypatch, hab)
    body = presenting.build_dcr_request(_HabVault(hab), _dcr_connection(hab))
    assert set(body) == {"software_statement_type", "software_statement", "udap"}


def test_build_token_assertion_json_falls_back_to_env_server_aid(monkeypatch, hab):
    _stub_embeds(monkeypatch, hab)
    conn = _dcr_connection(hab)
    conn.server_aid = ""
    monkeypatch.delenv("SIGNET_ONBOARDING_FORMAT", raising=False)
    monkeypatch.setenv("SIGNET_ONBOARDING_SERVER_AID", "Eenv")
    with pytest.raises(presenting.PresentingError, match="credential or server"):
        presenting.build_token_assertion(_HabVault(hab), conn)

    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
    exn = serdering.SerderKERI(
        raw=presenting.build_token_assertion(_HabVault(hab), conn).encode()
    )
    assert exn.ked["a"]["i"] == "Eenv"


def _schema_vault(chain):
    """Vault whose ``reger.creds`` holds ``said -> (schema, attrib, child SAIDs)``."""

    class Creder:
        def __init__(self, schema, attrib, kids):
            self.sad = {
                "s": schema,
                "a": attrib,
                "e": {"d": "Eedge", **{f"e{i}": {"n": k} for i, k in enumerate(kids)}},
            }

    store = {said: Creder(*spec) for said, spec in chain.items()}

    class Creds:
        def get(self, keys):
            return store.get(keys[0])

    class Reger:
        creds = Creds()

    class Rgy:
        reger = Reger()

    class Vault:
        rgy = Rgy()

    return Vault


def test_legal_entity_subunit_prefers_subunit_over_le():
    vault = _schema_vault(
        {
            "Elesr": ("Elesr-schema", {"i": "Eholder"}, ["Eauth"]),
            "Eauth": ("Eauth-schema", {"i": "Eqvi"}, ["Esub"]),
            "Esub": (
                presenting.LE_SUBUNIT_SCHEMA_SAID,
                {"i": "Esubunit", "LEI": "SUBLEI"},
                ["Ele"],
            ),
            "Ele": (
                presenting.LEGAL_ENTITY_SCHEMA_SAID,
                {"i": "Ele-aid", "LEI": "LELEI"},
                [],
            ),
        }
    )
    assert presenting.legal_entity_subunit(vault, "Elesr") == ("Esubunit", "SUBLEI")
    assert presenting.legal_entity_aid(vault, "Elesr") == "Ele-aid"


def test_legal_entity_subunit_falls_back_to_le_without_subunit():
    vault = _schema_vault(
        {
            "Eecr": ("Eecr-schema", {"i": "Eholder"}, ["Eauth"]),
            "Eauth": ("Eauth-schema", {"i": "Eqvi"}, ["Ele"]),
            "Ele": (
                presenting.LEGAL_ENTITY_SCHEMA_SAID,
                {"i": "Ele-aid", "LEI": "LELEI"},
                [],
            ),
        }
    )
    assert presenting.legal_entity_subunit(vault, "Eecr") == ("Ele-aid", "LELEI")


def test_legal_entity_subunit_none_without_le_or_subunit():
    vault = _schema_vault({"Eecr": ("Eecr-schema", {"i": "Eholder"}, [])})
    assert presenting.legal_entity_subunit(vault, "Eecr") is None
    assert presenting.legal_entity_aid(vault, "Eecr") is None


def _creds_vault(creds):
    """Vault whose reger.creds maps said -> creder with ``sad``."""

    class Creds:
        def get(self, keys):
            return creds.get(keys[0])

    class Reger:
        creds = Creds()

    class Rgy:
        reger = Reger()

    class Vault:
        rgy = Rgy()

    return Vault


def _sad(said, schema, issuee="", lei="", edges=None):
    a = {"i": issuee, "LEI": lei} if issuee else {}
    return SimpleNamespace(sad={"d": said, "s": schema, "a": a, "e": edges})


def test_legal_entity_subunit_simple_chain_is_the_legal_entity():
    # LESR -> auth (le edge) -> LE -> QVI: no subunit, the holder is the LE issuee
    vault = _creds_vault(
        {
            "LESR": _sad("LESR", "ELESR", "Eholder", edges={"auth": {"n": "AUTH"}}),
            "AUTH": _sad("AUTH", "EAUTH", "Eqvi", edges={"le": {"n": "LE"}}),
            "LE": _sad(
                "LE",
                LEGAL_ENTITY_SCHEMA_SAID,
                "Eholder",
                "LEI42",
                {"qvi": {"n": "QVI"}},
            ),
            "QVI": _sad("QVI", "EQVISCHEMA", "Ele"),
        }
    )
    assert presenting.legal_entity_subunit(vault, "LESR") == ("Eholder", "LEI42")
    assert presenting.legal_entity_aid(vault, "LESR") == "Eholder"


def test_chain_sources_simple_chain_order():
    vault, creds = _chain_vault(
        {"LESR": ["Auth"], "Auth": ["LE"], "LE": ["QVI"], "QVI": []}
    )
    ordered = presenting._chain_sources(vault, creds["LESR"])
    assert [c.said for c, _ in ordered] == ["QVI", "LE", "Auth"]
