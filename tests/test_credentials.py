from locksmith.core.configing import Environments, LocksmithConfig

from signet.core import configing, credentials

LESR_SAID = configing.LESR_SCHEMA_SAID
SUBUNIT_SAID = "ESubunitSchemaPlaceholder000000000000000000"


def _cred(said, schema_said, title, **attrib):
    return {
        "schema": {"$id": schema_said, "title": title},
        "sad": {"d": said, "a": {"i": "Eholder", **attrib}},
    }


def _vault(creds):
    class Habs(dict):
        pass

    class Subjs:
        def get(self, keys):
            return ["unused"]

    class Reger:
        subjs = Subjs()

        def cloneCreds(self, saids, db):
            return creds

    class Rgy:
        reger = Reger()

    class Hby:
        habs = Habs({"Eholder": object()})
        db = object()

    class Vault:
        hby = Hby()
        rgy = Rgy()

    return Vault()


def _live(monkeypatch):
    monkeypatch.setattr(
        LocksmithConfig,
        "get_instance",
        classmethod(
            lambda cls: type("C", (), {"environment": Environments.DEVELOPMENT})()
        ),
    )
    monkeypatch.setenv("SIGNET_LIVE", "1")


def _fixtures():
    return [
        _cred(
            "Eecr", configing.ECR_SCHEMA_SAID, "ECR", engagementContextRole="Engineer"
        ),
        _cred("Esub", SUBUNIT_SAID, "LE Subunit"),
        _cred("Elesr", LESR_SAID, "LESR", policyDomainRole="Clinician"),
    ]


def test_default_accepts_lesr_only(monkeypatch):
    _live(monkeypatch)
    monkeypatch.delenv("SIGNET_CREDENTIAL_SCHEMAS", raising=False)
    (found,) = credentials.filter_credentials(_vault(_fixtures()))
    assert found == {
        "said": "Elesr",
        "title": "LESR",
        "holder_pre": "Eholder",
        "role": "Clinician",
    }


def test_env_set_picks_lesr_and_ignores_subunit(monkeypatch):
    _live(monkeypatch)
    monkeypatch.setenv("SIGNET_CREDENTIAL_SCHEMAS", LESR_SAID)
    (found,) = credentials.filter_credentials(_vault(_fixtures()))
    assert found["said"] == "Elesr"
    assert found["role"] == "Clinician"


def test_blank_env_falls_back_to_lesr(monkeypatch):
    _live(monkeypatch)
    monkeypatch.setenv("SIGNET_CREDENTIAL_SCHEMAS", " , ")
    (found,) = credentials.filter_credentials(_vault(_fixtures()))
    assert found["said"] == "Elesr"


def test_env_set_picks_ecr(monkeypatch):
    _live(monkeypatch)
    monkeypatch.setenv("SIGNET_CREDENTIAL_SCHEMAS", configing.ECR_SCHEMA_SAID)
    (found,) = credentials.filter_credentials(_vault(_fixtures()))
    assert found["said"] == "Eecr"


def test_multiple_schemas(monkeypatch):
    _live(monkeypatch)
    monkeypatch.setenv(
        "SIGNET_CREDENTIAL_SCHEMAS", f"{configing.ECR_SCHEMA_SAID}, {LESR_SAID}"
    )
    assert [c["said"] for c in credentials.filter_credentials(_vault(_fixtures()))] == [
        "Eecr",
        "Elesr",
    ]


def test_mock_mode_seeds_placeholder(monkeypatch):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: True)
    monkeypatch.setattr(credentials, "is_mock_mode", lambda: True)
    (found,) = credentials.filter_credentials(None)
    assert found["schema_said"] == configing.ECR_SCHEMA_SAID
