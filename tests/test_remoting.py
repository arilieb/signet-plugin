import json

import httpx
import pytest

from urllib.parse import parse_qsl

from signet.core import presenting, remoting


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
    seen = []

    def handler(request):
        seen.append(request)
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
        "http://s", "http://s/udap/onboarding", b"CESRBYTES"
    )
    assert seen[0].headers["content-type"] == "application/cesr"
    assert seen[0].content == b"CESRBYTES"
    assert "signify-resource" not in seen[0].headers
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
    r = await remoting.submit_onboarding("http://s", "http://s/x", b"{}")
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
    r = await remoting.submit_onboarding("http://s", "http://s/x", b"{}")
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
        "token_endpoint": "",
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
    "code,err",
    [
        (400, "invalid_redirect_uri"),
        (403, "access_denied"),
        (503, "temporarily_unavailable"),
    ],
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


async def test_discover_server_returns_token_endpoint(monkeypatch):
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            200,
            json={
                "onboarding_endpoint": "http://s/udap/onboarding",
                "aid": "Esrv",
                "token_endpoint": "http://s/token",
            },
        ),
    )
    r = await remoting.discover_server("http://s")
    assert r["success"] and r["token_endpoint"] == "http://s/token"


async def test_discover_server_without_token_endpoint_still_succeeds(monkeypatch):
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            200, json={"onboarding_endpoint": "http://s/udap/onboarding", "aid": "Esrv"}
        ),
    )
    r = await remoting.discover_server("http://s")
    assert r["success"] and r["token_endpoint"] == ""


async def test_request_access_token_form_and_success(monkeypatch):
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["ctype"] = request.headers["content-type"]
        seen["form"] = dict(parse_qsl(request.content.decode()))
        return httpx.Response(
            200,
            json={
                "access_token": "tok",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "read",
            },
        )

    _patch(monkeypatch, handler)
    r = await remoting.request_access_token("http://s/token", "srv-123", "CESRMSG")
    assert seen["url"] == "http://s/token"
    assert seen["ctype"] == "application/x-www-form-urlencoded"
    assert seen["form"] == {
        "grant_type": "client_credentials",
        "client_id": "srv-123",  # the issued id, not the credential SAID
        "client_assertion_type": presenting.ASSERTION_TYPE,
        "client_assertion": "CESRMSG",
    }
    assert r["success"] and r["access_token"] == "tok"
    assert r["token_type"] == "Bearer" and r["expires_in"] == 3600
    assert r["scope"] == "read"


async def test_request_access_token_sends_scope_when_given(monkeypatch):
    seen = {}

    def handler(request):
        seen["form"] = dict(parse_qsl(request.content.decode()))
        return httpx.Response(200, json={"access_token": "tok"})

    _patch(monkeypatch, handler)
    await remoting.request_access_token("http://s/token", "c", "a", scope="read")
    assert seen["form"]["scope"] == "read"


@pytest.mark.parametrize(
    "code,err",
    [(401, "invalid_client"), (400, "unauthorized_client")],
)
async def test_request_access_token_errors(monkeypatch, code, err):
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            code, json={"error": err, "error_description": f"bad: {err}"}
        ),
    )
    r = await remoting.request_access_token("http://s/token", "c", "a")
    assert not r["success"]
    assert r["status_code"] == code
    assert r["error"] == f"bad: {err}"


async def test_request_access_token_200_without_token(monkeypatch):
    _patch(monkeypatch, lambda req: httpx.Response(200, json={"token_type": "Bearer"}))
    r = await remoting.request_access_token("http://s/token", "c", "a")
    assert not r["success"] and "no access token" in r["error"]


async def test_request_access_token_network_error(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("boom")

    _patch(monkeypatch, handler)
    r = await remoting.request_access_token("http://s/token", "c", "a")
    assert not r["success"] and "boom" in r["error"]


async def test_request_access_token_mock_mode(monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: True)
    r = await remoting.request_access_token("", "c", "")
    assert r["success"] and r["access_token"]
    assert r["expires_in"] == 3600 and r["scope"] == "read"


KERI_URL = "https://api.example.io/slapv3/pdexv2/.well-known/keri"
KERI_DOC = {
    "onboarding_endpoint": "https://other.example.net/slapv3/keri/udap/onboarding",
    "token_endpoint": "https://api.example.io/token",
    "trust_anchor": {"aid": "Egleif"},
}


async def test_discover_keri_url_fetched_as_is(monkeypatch):
    seen = []
    monkeypatch.setenv("SIGNET_ONBOARDING_SERVER_AID", "Esrv")

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json=KERI_DOC)

    _patch(monkeypatch, handler)
    r = await remoting.discover_server(KERI_URL)
    assert seen == [KERI_URL]
    assert r == {
        "success": True,
        "onboarding_endpoint": KERI_DOC["onboarding_endpoint"],
        "aid": "Esrv",
        "token_endpoint": "https://api.example.io/token",
    }


async def test_discover_keri_without_server_aid(monkeypatch):
    monkeypatch.delenv("SIGNET_ONBOARDING_SERVER_AID", raising=False)
    _patch(monkeypatch, lambda req: httpx.Response(200, json=KERI_DOC))
    r = await remoting.discover_server(KERI_URL)
    assert r["success"] and r["aid"] == ""


async def test_discover_keri_requires_onboarding_endpoint(monkeypatch):
    _patch(monkeypatch, lambda req: httpx.Response(200, json={"trust_anchor": {}}))
    r = await remoting.discover_server(KERI_URL)
    assert not r["success"]


async def test_submit_content_type_passthrough(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(202, json={"onboarding_id": "ob1"})

    _patch(monkeypatch, handler)
    await remoting.submit_onboarding(
        "http://s", "http://s/x", b"{}", content_type="application/json"
    )
    assert seen[0].headers["content-type"] == "application/json"


async def test_content_location_joined_against_request_url(monkeypatch):
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            202,
            json={"onboarding_id": "ob1"},
            headers={"Content-Location": "/slapv3/onboarding/ob1"},
        ),
    )
    r = await remoting.submit_onboarding(
        KERI_URL, "https://other.example.net/slapv3/keri/udap/onboarding", b"{}"
    )
    assert r["poll_url"] == "https://other.example.net/slapv3/onboarding/ob1"


async def test_poll_keri_without_poll_url_errors(monkeypatch):
    _patch(monkeypatch, lambda req: pytest.fail("no request expected"))
    r = await remoting.poll_onboarding(KERI_URL, "ob1")
    assert not r["success"] and "poll" in r["error"]


async def test_submit_logs_request_and_response(monkeypatch):
    messages = []
    monkeypatch.setattr(remoting.logger, "info", messages.append)
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            403, text="<html>Forbidden</html>", headers={"Server": "azure"}
        ),
    )
    body = json.dumps({"correlation_id": "c1", "ipex_grant": "X" * 500}).encode()
    r = await remoting.submit_onboarding(
        "http://s", "http://s/x", body, "application/json"
    )
    assert r["error"] == "API error: 403"
    log = "\n".join(messages)
    assert "POST http://s/x" in log and "application/json" in log
    assert "<500 chars omitted>" in log and "XXXXX" not in log
    assert "403" in log and "azure" in log and "<html>Forbidden</html>" in log


async def test_discover_keri_endpoint_override(monkeypatch):
    monkeypatch.setenv(
        "SIGNET_ONBOARDING_ENDPOINT", "https://api.example.io/onboarding"
    )
    _patch(monkeypatch, lambda req: httpx.Response(200, json=KERI_DOC))
    r = await remoting.discover_server(KERI_URL)
    assert r["success"]
    assert r["onboarding_endpoint"] == "https://api.example.io/onboarding"


async def test_discover_keri_override_replaces_missing_endpoint(monkeypatch):
    monkeypatch.setenv(
        "SIGNET_ONBOARDING_ENDPOINT", "https://api.example.io/onboarding"
    )
    _patch(monkeypatch, lambda req: httpx.Response(200, json={"trust_anchor": {}}))
    r = await remoting.discover_server(KERI_URL)
    assert (
        r["success"] and r["onboarding_endpoint"] == "https://api.example.io/onboarding"
    )


async def test_discover_udap_ignores_endpoint_override(monkeypatch):
    monkeypatch.setenv(
        "SIGNET_ONBOARDING_ENDPOINT", "https://api.example.io/onboarding"
    )
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            200, json={"onboarding_endpoint": "http://s/udap/onboarding", "aid": "Esrv"}
        ),
    )
    r = await remoting.discover_server("http://s")
    assert r["onboarding_endpoint"] == "http://s/udap/onboarding"


DEBUG_PAGE = (
    "<html><head><title>ValueError\n at /x</title><style>"
    + "a{}" * 1000
    + "</style></head><body>"
    '<pre class="exception_value">bad &quot;grant&quot;</pre>'
    '<textarea id="traceback_area" cols="140">Traceback (most recent call last):\n'
    "  File x.py, line 1\nValueError: bad</textarea></body></html>"
)


async def test_html_error_page_is_summarised_and_saved(monkeypatch, tmp_path):
    messages = []
    monkeypatch.setattr(remoting.logger, "info", messages.append)
    monkeypatch.setattr(remoting.tempfile, "gettempdir", lambda: str(tmp_path))
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            500,
            text=DEBUG_PAGE,
            headers={"content-type": "text/html", "Correlation-ID": "cid1"},
        ),
    )
    r = await remoting.submit_onboarding("http://s", "http://s/x", b"{}")
    log = "\n".join(messages)
    assert 'exception: bad "grant"' in log
    assert "Traceback (most recent call last)" in log
    assert (tmp_path / "signet-onboarding-last-response.html").read_text() == DEBUG_PAGE
    assert r["correlation_id"] == "cid1" and "cid1" in r["error"]


SAFHIR_ACCEPTED = {
    "correlation_id": "c1",
    "aid": "Eaid",
    "purpose": "TREAT",
    "status": "in-review",
    "review_id": "rev-1",
    "decision_due": "2026-10-12T20:01:04+00:00",
}
OVERRIDE = "https://api.example.io/slapv3/keri/udap/onboarding"
WRONG_HOST_LOCATION = "https://wrong.example.net/slapv3/keri/udap/onboarding/rev-1/"


async def test_submit_review_id_and_poll_url_rebased(monkeypatch):
    monkeypatch.setenv("SIGNET_ONBOARDING_ENDPOINT", OVERRIDE)
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            202, json=SAFHIR_ACCEPTED, headers={"Content-Location": WRONG_HOST_LOCATION}
        ),
    )
    r = await remoting.submit_onboarding(KERI_URL, OVERRIDE, b"{}")
    assert r["onboarding_id"] == "rev-1"
    assert r["decision_due"] == "2026-10-12T20:01:04+00:00"
    assert r["status"] == "in-review" and not r["terminal"]
    assert r["poll_url"] == "https://api.example.io/slapv3/keri/udap/onboarding/rev-1/"


async def test_poll_rebases_stored_poll_url(monkeypatch):
    monkeypatch.setenv("SIGNET_ONBOARDING_ENDPOINT", OVERRIDE)
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={**SAFHIR_ACCEPTED, "status": "approved"})

    _patch(monkeypatch, handler)
    r = await remoting.poll_onboarding(KERI_URL, "rev-1", WRONG_HOST_LOCATION)
    assert seen == ["https://api.example.io/slapv3/keri/udap/onboarding/rev-1/"]
    assert r["terminal"] and r["status"] == "approved"


async def test_poll_url_not_rebased_without_override_or_for_udap(monkeypatch):
    monkeypatch.delenv("SIGNET_ONBOARDING_ENDPOINT", raising=False)
    assert (
        remoting._rebase_poll_url(KERI_URL, WRONG_HOST_LOCATION) == WRONG_HOST_LOCATION
    )
    monkeypatch.setenv("SIGNET_ONBOARDING_ENDPOINT", OVERRIDE)
    assert remoting._rebase_poll_url("http://s", "http://s/p/1") == "http://s/p/1"
