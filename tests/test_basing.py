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
