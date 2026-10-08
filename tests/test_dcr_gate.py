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
