"""
The remoting facade: the library's calls as the {"success", ...} dicts the UI reads,
with the mock gate in front. The wire behaviour (statuses, headers, overrides) is
covered by acdc-auth-client's own tests; these pin the facade's contract.
"""

import pytest
import responses

from signet.core import mock_data, remoting

SERVER = "http://s"


@pytest.fixture(autouse=True)
def real_mode(monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: False)
    for var in (
        "SIGNET_ONBOARDING_FORMAT",
        "SIGNET_ONBOARDING_ENDPOINT",
        "SIGNET_ONBOARDING_SERVER_AID",
        "SIGNET_REGISTRATION_ENDPOINT",
        "SIGNET_TOKEN_ENDPOINT",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def http():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        yield mock


async def test_submit_pending(http):
    http.post(
        f"{SERVER}/udap/onboarding",
        status=202,
        json={
            "onboarding_id": "ob1",
            "correlation_id": "c1",
            "status": "in-review",
            "purposes": [{"purpose": "TREAT", "status": "in-review"}],
        },
        headers={"Content-Location": "/udap/onboarding/ob1", "Retry-After": "30"},
    )
    r = await remoting.submit_onboarding(
        SERVER, f"{SERVER}/udap/onboarding", b"CESRBYTES"
    )
    request = http.calls[0].request
    assert request.headers["Content-Type"] == "application/cesr"
    assert request.body == b"CESRBYTES"
    assert r["success"] and not r["terminal"]
    assert r["onboarding_id"] == "ob1"
    assert r["correlation_id"] == "c1"
    assert r["status"] == "in-review"
    assert r["poll_url"] == f"{SERVER}/udap/onboarding/ob1"
    assert r["retry_after"] == "30"
    assert r["purpose_status"] == "in-review"
    assert r["data"]["onboarding_id"] == "ob1"


async def test_submit_json_packet_content_type(http):
    http.post(f"{SERVER}/x", status=200, json={"onboarding_id": "ob1"})
    await remoting.submit_onboarding(
        SERVER, f"{SERVER}/x", b"{}", content_type="application/json"
    )
    assert http.calls[0].request.headers["Content-Type"] == "application/json"


async def test_submit_terminal_approved(http):
    http.post(
        f"{SERVER}/x",
        status=200,
        json={
            "onboarding_id": "ob1",
            "status": "approved",
            "decision_provenance": {"method": "whitelist"},
        },
    )
    r = await remoting.submit_onboarding(SERVER, f"{SERVER}/x", b"{}")
    assert r["terminal"] and r["status"] == "approved"
    assert r["decision_provenance"] == {"method": "whitelist"}


@pytest.mark.parametrize("code", [400, 401, 403, 503])
async def test_submit_error_keeps_status_and_correlation_id(http, code):
    http.post(
        f"{SERVER}/x",
        status=code,
        json={
            "error": "invalid_client",
            "error_description": "Signature is invalid",
            "correlation_id": "abc123",
        },
    )
    r = await remoting.submit_onboarding(SERVER, f"{SERVER}/x", b"{}")
    assert not r["success"]
    assert r["status_code"] == code
    assert r["correlation_id"] == "abc123"
    assert "Signature is invalid" in r["error"]
    assert "abc123" in r["error"]


async def test_transport_error_has_no_status_code(http):
    # No response was received: the dict carries the message only.
    http.post(f"{SERVER}/x", body=ConnectionError("refused"))
    r = await remoting.submit_onboarding(SERVER, f"{SERVER}/x", b"{}")
    assert r["success"] is False
    assert "refused" in r["error"]
    assert "status_code" not in r


async def test_unexpected_exception_becomes_a_failure(monkeypatch):
    def boom(*args):
        raise ValueError("kaput")

    monkeypatch.setattr(remoting, "_invoke", boom)
    r = await remoting.poll_onboarding(SERVER, "ob1")
    assert r == {"success": False, "error": "ValueError: kaput"}


async def test_poll_uses_poll_url_and_statuses(http):
    http.get(
        "http://s/custom/ob1",
        status=202,
        json={"onboarding_id": "ob1", "status": "in-review"},
    )
    http.get(
        f"{SERVER}/udap/onboarding/ob1",
        status=200,
        json={"onboarding_id": "ob1", "status": "rejected"},
    )
    first = await remoting.poll_onboarding(SERVER, "ob1", "http://s/custom/ob1")
    second = await remoting.poll_onboarding(SERVER, "ob1")
    assert [call.request.url for call in http.calls] == [
        "http://s/custom/ob1",
        f"{SERVER}/udap/onboarding/ob1",
    ]
    assert not first["terminal"]
    assert second["terminal"] and second["status"] == "rejected"


async def test_poll_rebases_keri_poll_url_from_the_env(http, monkeypatch):
    monkeypatch.setenv("SIGNET_ONBOARDING_ENDPOINT", "http://right:9000/onboard")
    http.get(
        "http://right:9000/udap/onboarding/ob1",
        status=200,
        json={"onboarding_id": "ob1", "status": "approved"},
    )
    r = await remoting.poll_onboarding(
        "http://wrong/.well-known/keri",
        "ob1",
        "http://wrong/udap/onboarding/ob1",
    )
    assert r["success"] and r["status"] == "approved"


async def test_discover_server(http):
    http.get(
        f"{SERVER}/.well-known/udap",
        json={"onboarding_endpoint": f"{SERVER}/udap/onboarding", "aid": "Esrv"},
    )
    r = await remoting.discover_server(SERVER)
    assert r == {
        "success": True,
        "onboarding_endpoint": f"{SERVER}/udap/onboarding",
        "aid": "Esrv",
        "registration_endpoint": "",
        "token_endpoint": "",
    }


async def test_discover_server_without_onboarding_fails(http):
    http.get(f"{SERVER}/.well-known/udap", json={"issuer": SERVER})
    r = await remoting.discover_server(SERVER)
    assert not r["success"]
    assert r["error"]


async def test_discover_keri_applies_env_overrides(http, monkeypatch):
    monkeypatch.setenv("SIGNET_ONBOARDING_ENDPOINT", "http://right/udap/onboarding")
    monkeypatch.setenv("SIGNET_ONBOARDING_SERVER_AID", "Eenv")
    url = "http://wrong/.well-known/keri"
    http.get(url, json={"onboarding_endpoint": "http://wrong/udap/onboarding"})
    r = await remoting.discover_server(url)
    assert r["success"]
    assert r["onboarding_endpoint"] == "http://right/udap/onboarding"
    assert r["aid"] == "Eenv"


async def test_discover_json_format_overrides_registration_and_token(http, monkeypatch):
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
    monkeypatch.setenv("SIGNET_REGISTRATION_ENDPOINT", "http://r/register")
    monkeypatch.setenv("SIGNET_TOKEN_ENDPOINT", "http://r/token")
    http.get(
        f"{SERVER}/.well-known/udap",
        json={
            "onboarding_endpoint": f"{SERVER}/udap/onboarding",
            "aid": "Esrv",
            "registration_endpoint": f"{SERVER}/register",
            "token_endpoint": f"{SERVER}/token",
        },
    )
    r = await remoting.discover_server(SERVER)
    assert r["registration_endpoint"] == "http://r/register"
    assert r["token_endpoint"] == "http://r/token"


async def test_register_dynamic_client(http):
    http.post(
        f"{SERVER}/register",
        status=201,
        json={"client_id": "srv-1", "scope": ["a", "b"]},
    )
    r = await remoting.register_dynamic_client(SERVER, {"udap": "1"})
    assert http.calls[0].request.headers["Content-Type"] == "application/json"
    assert r["success"] and r["client_id"] == "srv-1"
    assert r["scopes"] == "a b"


async def test_register_posts_to_the_given_url(http):
    http.post("http://other/reg", status=201, json={"client_id": "srv-1"})
    r = await remoting.register_dynamic_client(SERVER, {}, url="http://other/reg")
    assert r["success"] and r["scopes"] == ""


async def test_repeated_registration_200_succeeds_only_in_json_format(
    http, monkeypatch
):
    http.post(f"{SERVER}/register", status=200, json={"client_id": "srv-1"})
    assert not (await remoting.register_dynamic_client(SERVER, {}))["success"]
    monkeypatch.setenv("SIGNET_ONBOARDING_FORMAT", "json")
    assert (await remoting.register_dynamic_client(SERVER, {}))["success"]


async def test_register_error_keeps_rfc7591_code_and_status(http):
    http.post(
        f"{SERVER}/register",
        status=400,
        json={"error": "invalid_software_statement", "correlation_id": "c9"},
    )
    r = await remoting.register_dynamic_client(SERVER, {})
    assert not r["success"]
    assert r["status_code"] == 400 and r["correlation_id"] == "c9"
    assert "invalid_software_statement" in r["error"]


@pytest.mark.parametrize(
    "call, mock",
    [
        (lambda: remoting.discover_server("http://x"), "mock_discover_server"),
        (
            lambda: remoting.submit_onboarding("http://x", "http://x/y", b""),
            "mock_submit_onboarding",
        ),
        (lambda: remoting.poll_onboarding("http://x", "ob1"), "mock_poll_onboarding"),
        (
            lambda: remoting.register_dynamic_client("http://x", {}),
            "mock_register_dynamic_client",
        ),
    ],
)
async def test_mock_mode_never_reaches_the_library(monkeypatch, call, mock):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: True)
    monkeypatch.setattr(mock_data, mock, lambda *args: {"success": True, "mock": mock})
    monkeypatch.setattr(
        remoting, "_call", lambda *a: pytest.fail("the library must not be called")
    )
    assert await call() == {"success": True, "mock": mock}
