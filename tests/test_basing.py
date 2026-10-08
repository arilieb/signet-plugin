import pytest
from signet.db.basing import SignetBaser, SignetConnection
from contextlib import contextmanager

from signet.connections import refresh


@contextmanager
def _db():
    db = SignetBaser(name="t", temp=True)
    try:
        yield db
    finally:
        db.close(clear=True)


def test_round_trip_richer_fields():
    with _db() as db:
        conn = SignetConnection(
            connection_id="c1",
            hab_name="holder",
            hab_aid="Eaid",
            correlation_id="corr",
            server_aid="Esrv",
            poll_url="http://s/udap/onboarding/ob1",
            retry_after="30",
            purpose_status="in-review",
            decision_provenance={"method": "whitelist"},
            last_error="boom",
        )
        db.signet_connections.pin(keys=("c1",), val=conn)
        assert db.signet_connections.get(keys=("c1",)) == conn


def test_legacy_record_loads_with_defaults():
    with _db() as db:
        # a record pinned before the onboarding fields existed
        db.signet_connections.db.setVal(
            db.signet_connections.sdb,
            b"c0",
            b'{"connection_id":"c0","display_name":"Old","status":"approved"}',
        )
        conn = db.signet_connections.get(keys=("c0",))
        assert isinstance(conn, SignetConnection)
        assert conn.status == "approved"
        assert conn.poll_url == "" and conn.decision_provenance == {}


def test_apply_result_and_normalize():
    conn = SignetConnection(connection_id="c1")
    refresh.apply_result(
        conn,
        {
            "status": "in-review",
            "onboarding_id": "ob1",
            "poll_url": "http://s/p",
            "retry_after": "30",
            "purpose_status": "in-review",
        },
    )
    assert conn.status == "needs_approval" and conn.onboarding_id == "ob1"
    refresh.apply_result(conn, {"status": "approved"})
    assert conn.status == "approved"
    assert conn.poll_url == "http://s/p"
    assert conn.retry_after == ""


def test_dcr_fields_round_trip_and_old_record_defaults():
    with _db() as db:
        conn = SignetConnection(
            connection_id="c1",
            redirect_uris=["http://127.0.0.1:9000/cb"],
            client_name="Onyx",
            scopes="read",
        )
        db.signet_connections.pin(keys=("c1",), val=conn)
        assert db.signet_connections.get(keys=("c1",)) == conn

        db.signet_connections.db.setVal(
            db.signet_connections.sdb, b"c0", b'{"connection_id":"c0"}'
        )
        old = db.signet_connections.get(keys=("c0",))
        assert old.redirect_uris == [] and old.client_name == "" and old.scopes == ""


def test_token_fields_round_trip_and_old_record_defaults():
    with _db() as db:
        conn = SignetConnection(
            connection_id="c1",
            access_token="tok",
            token_type="Bearer",
            token_scope="read",
            token_expires_at="2026-01-01T00:00:00+00:00",
            last_authenticated_at="2025-12-31T23:00:00+00:00",
        )
        db.signet_connections.pin(keys=("c1",), val=conn)
        assert db.signet_connections.get(keys=("c1",)) == conn

        db.signet_connections.db.setVal(
            db.signet_connections.sdb, b"c0", b'{"connection_id":"c0"}'
        )
        old = db.signet_connections.get(keys=("c0",))
        assert old.access_token == "" and old.token_type == ""
        assert old.token_scope == "" and old.token_expires_at == ""
        assert old.last_authenticated_at == ""


def test_client_id_pin_round_trip_and_binding():
    with _db() as db:
        db.pin_client_id("c1", "Eaid", "Esaid", "srv-123")
        assert db.get_client_id("c1", "Eaid", "Esaid") == "srv-123"
        assert db.get_client_id("c1", "Eother", "Esaid") is None
        assert db.get_client_id("c1", "Eaid", "Eother") is None

        # re-registration for the same (AID, SAID) overwrites
        db.pin_client_id("c1", "Eaid", "Esaid", "srv-456")
        assert db.get_client_id("c1", "Eaid", "Esaid") == "srv-456"


def test_client_id_pin_independent_per_connection():
    with _db() as db:
        db.pin_client_id("c1", "Eaid", "Esaid", "one")
        db.pin_client_id("c2", "Eaid", "Esaid", "two")
        assert db.get_client_id("c1", "Eaid", "Esaid") == "one"
        assert db.get_client_id("c2", "Eaid", "Esaid") == "two"


def test_client_id_pin_rejects_empty():
    with _db() as db:
        with pytest.raises(ValueError):
            db.pin_client_id("c1", "Eaid", "Esaid", "")
        assert db.get_client_id("c1", "Eaid", "Esaid") is None


def test_rem_client_ids_only_removes_that_connection():
    with _db() as db:
        db.pin_client_id("c1", "Eaid", "Esaid", "one")
        db.pin_client_id("c1", "Eaid", "Esaid2", "one-b")
        db.pin_client_id("c10", "Eaid", "Esaid", "ten")
        db.rem_client_ids("c1")
        assert db.get_client_id("c1", "Eaid", "Esaid") is None
        assert db.get_client_id("c1", "Eaid", "Esaid2") is None
        assert db.get_client_id("c10", "Eaid", "Esaid") == "ten"


def test_resolve_client_id_returns_pin_never_the_said():
    with _db() as db:
        conn = SignetConnection(
            connection_id="c1",
            status="registered",
            hab_aid="Eaid",
            selected_credential_said="Esaid",
            client_id="srv-123",
        )
        db.pin_client_id("c1", "Eaid", "Esaid", "srv-123")
        assert db.resolve_client_id(conn) == "srv-123"
        conn.selected_credential_said = "Eother"
        assert db.resolve_client_id(conn) is None


def test_resolve_client_id_lazily_pins_legacy_record():
    with _db() as db:
        conn = SignetConnection(
            connection_id="c1",
            status="registered",
            hab_aid="Eaid",
            selected_credential_said="Esaid",
            client_id="legacy-1",
        )
        assert db.get_client_id("c1", "Eaid", "Esaid") is None
        assert db.resolve_client_id(conn) == "legacy-1"
        assert db.get_client_id("c1", "Eaid", "Esaid") == "legacy-1"


def test_resolve_client_id_none_without_pin_or_legacy_client_id():
    with _db() as db:
        conn = SignetConnection(
            connection_id="c1", hab_aid="Eaid", selected_credential_said="Esaid"
        )
        assert db.resolve_client_id(conn) is None


def test_has_valid_token():
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    conn = SignetConnection(connection_id="c1")
    assert not conn.has_valid_token()
    conn.access_token = "tok"
    assert not conn.has_valid_token()
    conn.token_expires_at = (now + timedelta(minutes=5)).isoformat()
    assert conn.has_valid_token()
    conn.token_expires_at = (now - timedelta(minutes=5)).isoformat()
    assert not conn.has_valid_token()
    conn.token_expires_at = "garbage"
    assert not conn.has_valid_token()
