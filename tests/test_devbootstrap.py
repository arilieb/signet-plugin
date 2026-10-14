import json
from types import SimpleNamespace

from signet.core import devbootstrap
from signet.core.credentials import LEGAL_ENTITY_SCHEMA_SAID
from signet.core.devbootstrap import LESR_AUTH_SCHEMA_SAID, LesrAuthState

HOLDER = "Eholder"
QVI = "Eqvi"


class _Saider:
    def __init__(self, qb64):
        self.qb64 = qb64


class _Index:
    def __init__(self, data):
        self.data = data

    def get(self, keys):
        return [_Saider(s) for s in self.data.get(keys[0], [])]


class _Creds:
    def __init__(self, creds):
        self.creds = creds

    def get(self, keys):
        return self.creds.get(keys[0])


class _Saved:
    def __init__(self, saids):
        self.saids = saids

    def get(self, keys):
        return object() if keys in self.saids else None


def _creder(said, schema, issuer):
    return SimpleNamespace(said=said, sad={"s": schema, "i": issuer})


def _reger(le_admitted=True, le_present=True, auth_issued=False):
    le = _creder("ELE", LEGAL_ENTITY_SCHEMA_SAID, QVI)
    auth = _creder("EAUTH", LESR_AUTH_SCHEMA_SAID, HOLDER)
    creds = {}
    subjs, issus = {}, {}
    if le_present:
        creds["ELE"] = le
        subjs[HOLDER] = ["ELE"]
    if auth_issued:
        creds["EAUTH"] = auth
        issus[HOLDER] = ["EAUTH"]
    return SimpleNamespace(
        creds=_Creds(creds),
        subjs=_Index(subjs),
        issus=_Index(issus),
        saved=_Saved({"ELE"} if le_admitted else set()),
    )


HAB = SimpleNamespace(pre=HOLDER)
CONFIG = {"attributes": {"AID": HOLDER}, "rules": {}}


def test_no_action_without_config():
    assert devbootstrap.lesr_auth_next(_reger(), HAB, LesrAuthState(), None, 0.0) is None


def test_no_action_until_le_admitted():
    for reger in (_reger(le_admitted=False), _reger(le_present=False)):
        assert devbootstrap.lesr_auth_next(reger, HAB, LesrAuthState(), CONFIG, 0.0) is None


def test_issue_when_le_admitted_and_no_auth():
    action = devbootstrap.lesr_auth_next(_reger(), HAB, LesrAuthState(), CONFIG, 0.0)
    assert action[0] == "issue"
    assert action[1].said == "ELE"


def test_grant_when_auth_issued_but_not_granted():
    reger = _reger(auth_issued=True)
    state = LesrAuthState()
    assert devbootstrap.lesr_auth_next(reger, HAB, state, CONFIG, 0.0) == ("grant", "EAUTH")
    state.granted = True
    assert devbootstrap.lesr_auth_next(reger, HAB, state, CONFIG, 0.0) is None


def test_in_flight_auth_is_not_reissued():
    state = LesrAuthState()
    state.auth_said = "EAUTH"  # created, still awaiting receipts: not yet in reger.issus
    assert devbootstrap.lesr_auth_next(_reger(), HAB, state, CONFIG, 0.0) == ("grant", "EAUTH")


def test_busy_and_retry_backoff():
    state = LesrAuthState()
    state.busy = True
    assert devbootstrap.lesr_auth_next(_reger(), HAB, state, CONFIG, 0.0) is None
    state.busy = False
    state.retry_at = 10.0
    assert devbootstrap.lesr_auth_next(_reger(), HAB, state, CONFIG, 5.0) is None
    assert devbootstrap.lesr_auth_next(_reger(), HAB, state, CONFIG, 10.0) is not None


def test_config_unset_or_bad(monkeypatch, tmp_path):
    monkeypatch.delenv("SIGNET_DEV_LESR_AUTH_FILE", raising=False)
    assert devbootstrap.lesr_auth_config() is None
    path = tmp_path / "auth.json"
    monkeypatch.setenv("SIGNET_DEV_LESR_AUTH_FILE", str(path))
    assert devbootstrap.lesr_auth_config() is None  # missing
    path.write_text("{}")
    assert devbootstrap.lesr_auth_config() is None  # no attributes
    path.write_text(json.dumps(CONFIG))
    assert devbootstrap.lesr_auth_config() == CONFIG
