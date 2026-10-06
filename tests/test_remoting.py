import json

import httpx
import pytest

from signet.core import remoting


@pytest.fixture(autouse=True)
def real_mode(monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: False)


def _patch(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = transport
        return real(*a, **kw)

    monkeypatch.setattr(remoting.httpx, "AsyncClient", factory)


async def test_submit_pending(monkeypatch):
    def handler(request):
        assert request.headers["signify-resource"] == "Eaid"
        return httpx.Response(
            202,
            json={
                "onboarding_id": "ob1",
                "correlation_id": "c1",
                "status": "in-review",
                "purposes": [{"purpose": "TREAT", "status": "in-review"}],
            },
            headers={"Content-Location": "/udap/onboarding/ob1", "Retry-After": "30"},
        )

    _patch(monkeypatch, handler)
    r = await remoting.submit_onboarding(
        "http://s", "http://s/udap/onboarding", b"{}", {"Signify-Resource": "Eaid"}
    )
    assert r["success"] and not r["terminal"]
    assert r["onboarding_id"] == "ob1"
    assert r["poll_url"] == "http://s/udap/onboarding/ob1"
    assert r["retry_after"] == "30"
    assert r["purpose_status"] == "in-review"


async def test_submit_terminal_approved(monkeypatch):
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            200,
            json={
                "onboarding_id": "ob1",
                "status": "approved",
                "decision_provenance": {"method": "whitelist"},
            },
        ),
    )
    r = await remoting.submit_onboarding("http://s", "http://s/x", b"{}", {})
    assert r["terminal"] and r["status"] == "approved"
    assert r["decision_provenance"] == {"method": "whitelist"}


@pytest.mark.parametrize("code", [400, 401, 403, 503])
async def test_submit_error_keeps_correlation_id(monkeypatch, code):
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            code,
            json={
                "error": "invalid_client",
                "error_description": "Signature is invalid",
                "correlation_id": "abc123",
            },
        ),
    )
    r = await remoting.submit_onboarding("http://s", "http://s/x", b"{}", {})
    assert not r["success"]
    assert r["status_code"] == code
    assert "Signature is invalid" in r["error"]
    assert "abc123" in r["error"]


async def test_poll_uses_poll_url_and_statuses(monkeypatch):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if len(seen) == 1:
            return httpx.Response(
                202, json={"onboarding_id": "ob1", "status": "in-review"}
            )
        return httpx.Response(200, json={"onboarding_id": "ob1", "status": "rejected"})

    _patch(monkeypatch, handler)
    first = await remoting.poll_onboarding("http://s", "ob1", "http://s/custom/ob1")
    second = await remoting.poll_onboarding("http://s", "ob1")
    assert seen == ["http://s/custom/ob1", "http://s/udap/onboarding/ob1"]
    assert not first["terminal"]
    assert second["terminal"] and second["status"] == "rejected"


async def test_discover_server(monkeypatch):
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            200, json={"onboarding_endpoint": "http://s/udap/onboarding", "aid": "Esrv"}
        ),
    )
    r = await remoting.discover_server("http://s")
    assert r == {
        "success": True,
        "onboarding_endpoint": "http://s/udap/onboarding",
        "aid": "Esrv",
    }


async def test_discover_server_legacy_mode(monkeypatch):
    _patch(monkeypatch, lambda req: httpx.Response(200, json={"issuer": "x"}))
    r = await remoting.discover_server("http://s")
    assert not r["success"]


async def test_register_created(monkeypatch):
    def handler(request):
        assert request.url.path == "/register"
        assert json.loads(request.content)["udap"] == "1"
        return httpx.Response(
            201, json={"client_id": "ECRED", "scopes": ["read", "write"]}
        )

    _patch(monkeypatch, handler)
    r = await remoting.register_dynamic_client("http://s", {"udap": "1"})
    assert r["success"] and r["client_id"] == "ECRED"
    assert r["scopes"] == "read write"


@pytest.mark.parametrize(
    "code,err", [(400, "invalid_redirect_uri"), (403, "access_denied"), (503, "temporarily_unavailable")]
)
async def test_register_error_keeps_correlation_id(monkeypatch, code, err):
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            code, json={"error": err, "correlation_id": "abc123"}
        ),
    )
    r = await remoting.register_dynamic_client("http://s", {})
    assert not r["success"]
    assert r["status_code"] == code
    assert err in r["error"] and "abc123" in r["error"]
    assert r["correlation_id"] == "abc123"


async def test_register_mock_mode(monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: True)
    r = await remoting.register_dynamic_client("http://s", {})
    assert r["success"] and r["client_id"]
