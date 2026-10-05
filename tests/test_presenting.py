import base64
import hashlib
import json

import pytest
from keri.app import habbing
from keri.end import ending

from signet.core import configing, presenting


@pytest.fixture
def hab():
    with habbing.openHby(name="signet-test", temp=True) as hby:
        hab = hby.makeHab(name="holder")
        hab._test_hby = hby
        yield hab


def _verify(hab, method, path, headers):
    inputs = [
        i
        for i in ending.desiginput(headers["Signature-Input"].encode())
        if i.name == "signify"
    ]
    inputage = inputs[0]
    cig = ending.designature(headers["Signature"])[0].markers["signify"]
    lowered = {k.lower(): v for k, v in headers.items()}
    items = []
    for fld in inputage.fields:
        if fld == "@method":
            items.append(f'"{fld}": {method}')
        elif fld == "@path":
            items.append(f'"{fld}": {path}')
        else:
            items.append(f'"{fld}": {ending.normalize(lowered[fld])}')
    values = [f"({' '.join(inputage.fields)})", f"created={inputage.created}"]
    for name in ("expires", "nonce", "keyid", "context", "alg"):
        value = getattr(inputage, name)
        if value is not None:
            values.append(f"{name}={value}")
    items.append(f'"@signature-params: {";".join(values)}"')
    ser = "\n".join(items).encode()
    return inputage, hab.kever.verfers[0].verify(sig=cig.raw, ser=ser)


def test_body_digest():
    body = b'{"a":1}'
    expected = base64.b64encode(hashlib.sha256(body).digest()).decode()
    assert presenting.body_digest(body) == f"sha-256={expected}"


def test_sign_request_headers_verify(hab):
    body = b'{"x":"y"}'
    headers = presenting.sign_request(hab, "POST", "/udap/onboarding", body)

    assert headers["Signify-Resource"] == hab.pre
    assert headers["Digest"] == presenting.body_digest(body)
    assert headers["Signify-Timestamp"]

    inputage, ok = _verify(hab, "POST", "/udap/onboarding", headers)
    assert ok
    assert set(presenting.SIGNED_FIELDS).issubset(inputage.fields)
    assert inputage.nonce


def test_sign_request_tampered_path_fails(hab):
    headers = presenting.sign_request(hab, "POST", "/udap/onboarding", b"{}")
    _, ok = _verify(hab, "POST", "/other", headers)
    assert not ok


def test_nonce_differs_per_request(hab):
    a = presenting.sign_request(hab, "POST", "/p", b"{}")
    b = presenting.sign_request(hab, "POST", "/p", b"{}")
    assert a["Signature-Input"] != b["Signature-Input"]


def test_build_oobis_requires_witness(hab):
    with pytest.raises(presenting.PresentingError, match="witness"):
        presenting.build_oobis(hab, "ESAID")


def test_build_request_unknown_holder(monkeypatch, hab):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: False)

    class Vault:
        hby = hab._test_hby

    with pytest.raises(presenting.PresentingError, match="local identifier"):
        presenting.build_onboarding_request(
            Vault,
            {"said": "E1", "holder_pre": "Enope"},
            "http://s/udap/onboarding",
            "Esrv",
        )


def test_build_request_packet_shape(monkeypatch, hab):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: False)
    monkeypatch.setattr(presenting, "build_grant", lambda *a: "GRANT")
    monkeypatch.setattr(
        presenting,
        "build_oobis",
        lambda h, said, le=None: [{"type": "aid", "aid": h.pre, "url": "http://w/oobi"}],
    )

    class Vault:
        hby = hab._test_hby

    req = presenting.build_onboarding_request(
        Vault,
        {"said": "ECRED", "holder_pre": hab.pre, "role": "Auditor"},
        "http://s/udap/onboarding",
        "Esrv",
    )
    packet = json.loads(req.body)
    assert packet["legal_entity"]["aid"] == hab.pre
    assert packet["submitter"] == {"ecr_said": "ECRED", "role": "Auditor"}
    assert packet["requested_purposes"] == ["TREAT"]
    assert packet["grant"] == "GRANT"
    assert packet["correlation_id"] == req.correlation_id
    assert req.headers["Digest"] == presenting.body_digest(req.body)
    assert req.headers["Signify-Resource"] == hab.pre
    assert req.hab_name == "holder"
