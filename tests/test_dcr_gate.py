from types import SimpleNamespace

import pytest

from signet.connections import dcr_gate
from signet.core import presenting, remoting
from signet.db.basing import SignetBaser, SignetConnection

pytest.importorskip("PySide6")


class _Button:
    def setEnabled(self, _):
        pass

    def setText(self, _):
        pass


def _dialog(db):
    errors = []
    app = SimpleNamespace(
        vault=SimpleNamespace(plugin_state={"signet": {"db": db}}),
    )
    dialog = SimpleNamespace(
        app=app,
        connection_id="c1",
        on_success=None,
        confirm_button=_Button(),
        cancel_button=_Button(),
        show_error=errors.append,
        accept=lambda: None,
        _reset_buttons=lambda: None,
    )
    dialog._get_db = lambda: db
    return dialog, errors


def _db():
    db = SignetBaser(name="t", temp=True)
    db.signet_connections.pin(
        keys=("c1",),
        val=SignetConnection(
            connection_id="c1",
            status="approved",
            hab_aid="Eaid",
            selected_credential_said="Esaid",
        ),
    )
    return db


async def _confirm(dialog, monkeypatch, result):
    async def register(base_url, registration):
        return result

    monkeypatch.setattr(remoting, "register_dynamic_client", register)
    monkeypatch.setattr(presenting, "build_dcr_request", lambda vault, conn: {})
    monkeypatch.setattr(dcr_gate.configing, "is_mock_mode", lambda: False)
    run = dcr_gate.DynamicClientRegistrationGateDialog._on_confirm.__wrapped__
    await run(dialog)


async def test_registration_pins_client_id(monkeypatch):
    db = _db()
    try:
        dialog, errors = _dialog(db)
        await _confirm(
            dialog,
            monkeypatch,
            {"success": True, "client_id": "srv-123", "scopes": "r"},
        )
        assert not errors
        assert db.get_client_id("c1", "Eaid", "Esaid") == "srv-123"
        conn = db.signet_connections.get(keys=("c1",))
        assert conn.status == "registered" and conn.client_id == "srv-123"
    finally:
        db.close(clear=True)


async def test_registration_without_client_id_is_an_error(monkeypatch):
    db = _db()
    try:
        dialog, errors = _dialog(db)
        await _confirm(dialog, monkeypatch, {"success": True, "scopes": "r"})
        assert errors == ["The server did not return a client_id."]
        assert db.get_client_id("c1", "Eaid", "Esaid") is None
        conn = db.signet_connections.get(keys=("c1",))
        assert conn.status == "approved" and conn.client_id == ""
    finally:
        db.close(clear=True)


def _json_gate(monkeypatch, discovery, result, calls):
    async def discover(base_url):
        calls["discover"].append(base_url)
        return discovery

    async def register(base_url, registration, url=""):
        calls["register"].append((base_url, url))
        return result

    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
    monkeypatch.setattr(remoting, "discover_server", discover)
    monkeypatch.setattr(remoting, "register_dynamic_client", register)
    monkeypatch.setattr(presenting, "build_dcr_request", lambda vault, conn: {})
    monkeypatch.setattr(dcr_gate.configing, "is_mock_mode", lambda: False)


async def test_json_registration_posts_to_discovered_url(monkeypatch):
    db = _db()
    try:
        dialog, errors = _dialog(db)
        calls = {"discover": [], "register": []}
        _json_gate(
            monkeypatch,
            {"success": True, "registration_endpoint": "http://s/register/"},
            {"success": True, "client_id": "srv-1", "scopes": "system/Group.read"},
            calls,
        )
        run = dcr_gate.DynamicClientRegistrationGateDialog._on_confirm.__wrapped__
        await run(dialog)
        assert not errors
        assert len(calls["discover"]) == 1
        assert calls["register"] == [("", "http://s/register/")]
        assert db.get_client_id("c1", "Eaid", "Esaid") == "srv-1"
        conn = db.signet_connections.get(keys=("c1",))
        assert conn.status == "registered" and conn.scopes == "system/Group.read"
    finally:
        db.close(clear=True)


async def test_json_registration_without_advertised_endpoint(monkeypatch):
    db = _db()
    try:
        dialog, errors = _dialog(db)
        calls = {"discover": [], "register": []}
        _json_gate(
            monkeypatch,
            {"success": True, "registration_endpoint": ""},
            {"success": True, "client_id": "x"},
            calls,
        )
        run = dcr_gate.DynamicClientRegistrationGateDialog._on_confirm.__wrapped__
        await run(dialog)
        assert errors == ["Server does not advertise a registration endpoint."]
        assert calls["register"] == []
        assert db.get_client_id("c1", "Eaid", "Esaid") is None
    finally:
        db.close(clear=True)


async def test_json_registration_discovery_failure(monkeypatch):
    db = _db()
    try:
        dialog, errors = _dialog(db)
        calls = {"discover": [], "register": []}
        _json_gate(monkeypatch, {"success": False, "error": "boom"}, {}, calls)
        run = dcr_gate.DynamicClientRegistrationGateDialog._on_confirm.__wrapped__
        await run(dialog)
        assert errors == ["boom"] and calls["register"] == []
    finally:
        db.close(clear=True)


async def test_cesr_registration_never_discovers(monkeypatch):
    db = _db()
    try:
        dialog, errors = _dialog(db)

        async def discover(base_url):
            raise AssertionError("discover_server must not be called")

        monkeypatch.delenv("SIGNET_ONBOARDING_FORMAT", raising=False)
        monkeypatch.setattr(remoting, "discover_server", discover)
        await _confirm(
            dialog, monkeypatch, {"success": True, "client_id": "c", "scopes": ""}
        )
        assert not errors
    finally:
        db.close(clear=True)
