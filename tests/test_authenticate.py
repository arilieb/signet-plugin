from types import SimpleNamespace

import pytest

from signet.connections import authenticate, delete
from signet.connections.status import primary_row_action
from signet.core import presenting, remoting
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


def _dialog(db):
    errors, shown = [], []
    dialog = SimpleNamespace(
        app=SimpleNamespace(vault=SimpleNamespace(plugin_state={"signet": {"db": db}})),
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


async def _confirm(dialog, monkeypatch, token_result, discovery=None, sent=None):
    async def discover(base_url):
        return discovery or {
            "success": True,
            "aid": "Esrv",
            "onboarding_endpoint": "x",
            "token_endpoint": "http://srv/token",
        }

    async def token(endpoint, client_id, assertion, scope=""):
        if sent is not None:
            sent.update(endpoint=endpoint, client_id=client_id)
        return token_result

    monkeypatch.setattr(remoting, "discover_server", discover)
    monkeypatch.setattr(remoting, "request_access_token", token)
    monkeypatch.setattr(presenting, "build_token_assertion", lambda vault, conn: "a")
    monkeypatch.setattr(authenticate.configing, "is_mock_mode", lambda: False)
    await authenticate.AuthenticateDialog._on_confirm.__wrapped__(dialog)


async def test_authenticate_stores_token_and_sends_pinned_client_id(monkeypatch):
    db = _db()
    try:
        dialog, errors, shown = _dialog(db)
        sent = {}
        await _confirm(
            dialog,
            monkeypatch,
            {
                "success": True,
                "access_token": "tok",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "read",
            },
            sent=sent,
        )
        assert not errors
        assert sent == {"endpoint": "http://srv/token", "client_id": "srv-123"}
        conn = db.signet_connections.get(keys=("c1",))
        assert conn.access_token == "tok" and conn.token_scope == "read"
        assert conn.has_valid_token()
        assert conn.last_authenticated_at
        assert shown == [conn.token_expires_at]
    finally:
        db.close(clear=True)


async def test_authenticate_refuses_without_matching_pin(monkeypatch):
    db = _db(client_id="", pin=False)
    try:
        dialog, errors, _ = _dialog(db)
        sent = {}
        await _confirm(dialog, monkeypatch, {"success": True}, sent=sent)
        assert errors and "Register again" in errors[0]
        assert sent == {}
    finally:
        db.close(clear=True)


async def test_authenticate_requires_registered(monkeypatch):
    db = _db(status="approved")
    try:
        dialog, errors, _ = _dialog(db)
        await _confirm(dialog, monkeypatch, {"success": True})
        assert errors == ["The connection is not registered."]
    finally:
        db.close(clear=True)


async def test_authenticate_without_token_endpoint(monkeypatch):
    db = _db()
    try:
        dialog, errors, _ = _dialog(db)
        await _confirm(
            dialog,
            monkeypatch,
            {"success": True},
            discovery={"success": True, "aid": "Esrv", "token_endpoint": ""},
        )
        assert errors == ["Server does not advertise a token endpoint."]
    finally:
        db.close(clear=True)


async def test_authenticate_server_error_stores_nothing(monkeypatch):
    db = _db()
    try:
        dialog, errors, shown = _dialog(db)
        await _confirm(
            dialog, monkeypatch, {"success": False, "error": "unauthorized_client"}
        )
        assert errors == ["unauthorized_client"]
        assert not shown
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
