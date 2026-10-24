from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
import responses
from acdc_auth_client.core import flows

from signet.connections import authenticate, delete
from signet.connections.status import primary_row_action
from signet.db.basing import SignetBaser, SignetConnection

pytest.importorskip("PySide6")


def test_primary_row_action():
    assert primary_row_action("needs_approval", False) == ["Refresh"]
    assert primary_row_action("approved", False) == ["Register"]
    assert primary_row_action("registered", True) == ["Authenticate"]
    assert primary_row_action("registered", False) == []
    assert primary_row_action("rejected", True) == []
    assert primary_row_action("approved", True) == ["Register"]


class _Button:
    def setEnabled(self, _):
        pass

    def setText(self, _):
        pass


def _db(status="registered", client_id="srv-123", pin=True):
    db = SignetBaser(name="t", temp=True)
    db.signet_connections.pin(
        keys=("c1",),
        val=SignetConnection(
            connection_id="c1",
            status=status,
            base_url="http://srv",
            hab_aid="Eaid",
            selected_credential_said="Esaid",
            client_id=client_id,
        ),
    )
    if pin:
        db.pin_client_id("c1", "Eaid", "Esaid", client_id)
    return db


def _VAULT(db):
    return SimpleNamespace(
        plugin_state={"signet": {"db": db}}, hby=None, rgy=SimpleNamespace(reger=None)
    )


def _dialog(db):
    errors, shown = [], []
    dialog = SimpleNamespace(
        app=SimpleNamespace(vault=_VAULT(db)),
        connection_id="c1",
        on_success=None,
        confirm_button=_Button(),
        cancel_button=_Button(),
        show_error=errors.append,
        _reset_buttons=lambda: None,
        _show_authenticated=shown.append,
        _get_db=lambda: db,
    )
    return dialog, errors, shown


SERVER = "http://srv"
_TOKEN_OK = {
    "access_token": "tok",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "read",
}


@pytest.fixture(autouse=True)
def real_mode(monkeypatch):
    """Real calls (mock mode off), the signed assertion stubbed: there is no habery here."""
    monkeypatch.setattr(authenticate.configing, "is_mock_mode", lambda: False)
    monkeypatch.delenv("SIGNET_ONBOARDING_FORMAT", raising=False)
    monkeypatch.delenv("SIGNET_TOKEN_ENDPOINT", raising=False)
    monkeypatch.setattr(
        flows,
        "build_token_assertion",
        lambda hby, reger, conn, options=None: "assertion",
    )


@pytest.fixture
def http():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        yield mock


def _serve(http, token_status=200, token_body=None, token_endpoint=f"{SERVER}/token"):
    """The server's discovery document and token endpoint."""
    http.get(
        f"{SERVER}/.well-known/udap",
        json={
            "onboarding_endpoint": f"{SERVER}/udap/onboarding",
            "aid": "Esrv",
            "token_endpoint": token_endpoint,
        },
    )
    http.post(
        f"{SERVER}/token",
        status=token_status,
        json=_TOKEN_OK if token_body is None else token_body,
    )


def _form(http) -> dict:
    token_call = [c for c in http.calls if c.request.url.endswith("/token")][-1]
    return {k: v[0] for k, v in parse_qs(token_call.request.body).items()}


async def _confirm(dialog):
    await authenticate.AuthenticateDialog._on_confirm.__wrapped__(dialog)


async def test_authenticate_stores_token_and_sends_pinned_client_id(http):
    db = _db()
    try:
        dialog, errors, shown = _dialog(db)
        _serve(http)
        await _confirm(dialog)
        assert not errors
        form = _form(http)
        assert form["client_id"] == "srv-123"
        assert form["client_assertion"] == "assertion"
        assert "scope" not in form  # cesr: the server applies its default scopes
        conn = db.signet_connections.get(keys=("c1",))
        assert conn.access_token == "tok" and conn.token_scope == "read"
        assert conn.has_valid_token()
        assert conn.last_authenticated_at
        assert shown == [conn.token_expires_at]
    finally:
        db.close(clear=True)


async def test_authenticate_refuses_without_matching_pin(http):
    db = _db(client_id="", pin=False)
    try:
        dialog, errors, _ = _dialog(db)
        _serve(http)
        await _confirm(dialog)
        assert errors and "Register again" in errors[0]
        assert not http.calls
    finally:
        db.close(clear=True)


async def test_authenticate_requires_registered(http):
    db = _db(status="approved")
    try:
        dialog, errors, _ = _dialog(db)
        await _confirm(dialog)
        assert errors == ["The connection is not registered."]
        assert not http.calls
    finally:
        db.close(clear=True)


async def test_authenticate_without_token_endpoint(http):
    db = _db()
    try:
        dialog, errors, _ = _dialog(db)
        _serve(http, token_endpoint="")
        await _confirm(dialog)
        assert errors == ["Server does not advertise a token endpoint."]
    finally:
        db.close(clear=True)


async def test_authenticate_server_error_stores_nothing(http):
    db = _db()
    try:
        dialog, errors, shown = _dialog(db)
        _serve(http, 401, {"error": "unauthorized_client"})
        await _confirm(dialog)
        assert errors == ["unauthorized_client"]
        assert not shown
        assert db.signet_connections.get(keys=("c1",)).access_token == ""
    finally:
        db.close(clear=True)


async def test_authenticate_sends_registered_scopes_in_json_format(http, monkeypatch):
    db = _db()
    try:
        conn = db.signet_connections.get(keys=("c1",))
        conn.scopes = "system/Group.read"
        db.signet_connections.pin(keys=("c1",), val=conn)
        dialog, errors, _ = _dialog(db)
        monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
        _serve(http)
        await _confirm(dialog)
        assert not errors
        assert _form(http)["scope"] == "system/Group.read"
    finally:
        db.close(clear=True)


async def test_authenticate_uses_the_token_endpoint_override_in_json_format(
    http, monkeypatch
):
    db = _db()
    try:
        dialog, errors, _ = _dialog(db)
        monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
        monkeypatch.setenv("SIGNET_TOKEN_ENDPOINT", f"{SERVER}/token")
        _serve(http, token_endpoint="http://advertised-wrong/token")
        await _confirm(dialog)
        assert not errors
        assert db.signet_connections.get(keys=("c1",)).access_token == "tok"
    finally:
        db.close(clear=True)


async def test_authenticate_surfaces_server_error_in_json_format(http, monkeypatch):
    db = _db()
    try:
        dialog, errors, _ = _dialog(db)
        monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
        _serve(http, 400, {"error": "invalid_client"})
        await _confirm(dialog)
        assert errors == ["invalid_client"]
        assert db.signet_connections.get(keys=("c1",)).access_token == ""
    finally:
        db.close(clear=True)


def test_delete_dialog_removes_pins():
    db = _db()
    try:
        db.pin_client_id("c2", "Eaid", "Esaid", "other")
        closed = []
        dialog = SimpleNamespace(
            db=db,
            connection_id="c1",
            on_success=None,
            show_error=lambda m: closed.append(m),
            accept=lambda: None,
        )
        delete.DeleteConnectionDialog._do_delete(dialog)
        assert db.signet_connections.get(keys=("c1",)) is None
        assert db.get_client_id("c1", "Eaid", "Esaid") is None
        assert db.get_client_id("c2", "Eaid", "Esaid") == "other"
        assert not closed
    finally:
        db.close(clear=True)


async def test_authenticate_connection_failures(http):
    db = _db()
    try:
        _serve(http, 401, {"error": "denied"})
        result = await authenticate.authenticate_connection(_VAULT(db), db, "c1")
        assert result == {"success": False, "error": "denied"}
        assert not db.signet_connections.get(keys=("c1",)).access_token

        missing = await authenticate.authenticate_connection(_VAULT(db), db, "nope")
        assert missing == {"success": False, "error": "Connection not found."}
    finally:
        db.close(clear=True)


async def test_ensure_authenticated_reuses_valid_token(http):
    db = _db()
    try:
        _serve(http)
        first = await authenticate.ensure_authenticated(_VAULT(db), db, "c1")
        assert first["success"] and len(http.calls) == 2  # discovery, token

        again = await authenticate.ensure_authenticated(_VAULT(db), db, "c1")
        assert again == first
        assert len(http.calls) == 2  # no network the second time
    finally:
        db.close(clear=True)


async def test_authenticate_connection_always_requests_a_new_token(http):
    db = _db()
    try:
        _serve(http)
        await authenticate.authenticate_connection(_VAULT(db), db, "c1")
        await authenticate.authenticate_connection(_VAULT(db), db, "c1")
        assert len(http.calls) == 4
    finally:
        db.close(clear=True)


async def test_ensure_authenticated_reauths_when_expired(http):
    db = _db()
    try:
        _serve(http)
        await authenticate.ensure_authenticated(_VAULT(db), db, "c1")

        conn = db.signet_connections.get(keys=("c1",))
        conn.token_expires_at = "2000-01-01T00:00:00+00:00"
        db.signet_connections.pin(keys=("c1",), val=conn)

        result = await authenticate.ensure_authenticated(_VAULT(db), db, "c1")
        assert result["success"]
        assert len(http.calls) == 4
    finally:
        db.close(clear=True)


async def test_mock_mode_issues_a_canned_token_without_a_request(http, monkeypatch):
    db = _db()
    try:
        monkeypatch.setattr(authenticate.configing, "is_mock_mode", lambda: True)
        result = await authenticate.authenticate_connection(_VAULT(db), db, "c1")
        conn = db.signet_connections.get(keys=("c1",))
        assert result == {"success": True, "token_expires_at": conn.token_expires_at}
        assert conn.has_valid_token() and conn.token_scope == "read"
        assert not http.calls
    finally:
        db.close(clear=True)


def test_authorized_connection_returns_the_stored_token_as_connection_info(http):
    db = _db()
    try:
        _serve(http)
        info = authenticate.authorized_connection(_VAULT(db), db, "c1")
        assert info.access_token == "tok" and info.client_id == "srv-123"
        assert info.credential_said == "Esaid" and info.hab_aid == "Eaid"
        n = len(http.calls)
        authenticate.authorized_connection(_VAULT(db), db, "c1")
        assert len(http.calls) == n  # a valid token is reused
        authenticate.authorized_connection(_VAULT(db), db, "c1", force=True)
        assert len(http.calls) == n + 2
    finally:
        db.close(clear=True)


def test_authorized_connection_raises_when_authentication_fails(http):
    db = _db(status="approved")
    try:
        with pytest.raises(RuntimeError, match="not registered"):
            authenticate.authorized_connection(_VAULT(db), db, "c1")
    finally:
        db.close(clear=True)
