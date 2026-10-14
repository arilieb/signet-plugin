import json
from types import SimpleNamespace

import httpx
import pytest

from signet.core import configing, remoting

FHIR = "http://fhir.test/v1"


@pytest.fixture(autouse=True)
def real_mode(monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: False)
    monkeypatch.delenv("SIGNET_FHIR_BASE_URL", raising=False)
    monkeypatch.delenv("SIGNET_EXPORT_METHOD", raising=False)
    monkeypatch.delenv("SIGNET_EXPORT_STATUS_URL_PREFIX", raising=False)


def _patch(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = transport
        return real(*a, **kw)

    monkeypatch.setattr(remoting.httpx, "AsyncClient", factory)


def _connection(base_url=f"{FHIR}/.well-known/keri"):
    return SimpleNamespace(
        connection_id="c1",
        base_url=base_url,
        access_token="tok123",
        token_type="Bearer",
        token_scope="system/Group.read",
        token_expires_at="2099-01-01T00:00:00+00:00",
    )


def test_fhir_base_url_strips_discovery_path():
    assert remoting.fhir_base_url(_connection()) == FHIR
    assert remoting.fhir_base_url(_connection(f"{FHIR}/")) == FHIR


def test_fhir_base_url_override(monkeypatch):
    monkeypatch.setenv("SIGNET_FHIR_BASE_URL", "http://other/fhir/")
    assert remoting.fhir_base_url(_connection()) == "http://other/fhir"


def test_onboarding_scopes(monkeypatch):
    monkeypatch.delenv("SIGNET_ONBOARDING_SCOPES", raising=False)
    assert configing.onboarding_scopes() == ["system/Group.read"]
    monkeypatch.setenv("SIGNET_ONBOARDING_SCOPES", "system/Group.read system/*.read")
    assert configing.onboarding_scopes() == ["system/Group.read", "system/*.read"]


async def test_get_groups_sends_bearer_and_strips_keri_path(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            json={"entry": [{"resource": {"id": "g1", "name": "Group One"}}]},
        )

    _patch(monkeypatch, handler)
    r = await remoting.fetch_groups(_connection())
    assert str(seen[0].url) == f"{FHIR}/Group"
    assert seen[0].headers["authorization"] == "Bearer tok123"
    assert seen[0].headers["accept"] == "application/fhir+json"
    assert r == {"success": True, "groups": [{"id": "g1", "name": "Group One"}]}


async def test_get_groups_follows_paging(monkeypatch):
    def handler(request):
        if request.url.params.get("page") == "2":
            return httpx.Response(
                200, json={"entry": [{"resource": {"id": "g2", "name": "B"}}]}
            )
        return httpx.Response(
            200,
            json={
                "entry": [{"resource": {"id": "g1", "name": "A"}}],
                "link": [{"relation": "next", "url": f"{FHIR}/Group?page=2"}],
            },
        )

    _patch(monkeypatch, handler)
    r = await remoting.fetch_groups(_connection())
    assert [g["id"] for g in r["groups"]] == ["g1", "g2"]


async def test_get_groups_name_fallbacks(monkeypatch):
    entries = [
        {"resource": {"id": "a", "identifier": [{"value": "ident"}]}},
        {"resource": {"id": "b", "code": {"text": "coded"}}},
        {"resource": {"id": "c"}},
    ]
    _patch(monkeypatch, lambda req: httpx.Response(200, json={"entry": entries}))
    r = await remoting.fetch_groups(_connection())
    assert [g["name"] for g in r["groups"]] == ["ident", "coded", "c"]


async def test_get_groups_401_operation_outcome(monkeypatch):
    _patch(
        monkeypatch,
        lambda req: httpx.Response(
            401,
            json={
                "resourceType": "OperationOutcome",
                "issue": [{"severity": "error", "diagnostics": "token expired"}],
            },
        ),
    )
    r = await remoting.fetch_groups(_connection())
    assert not r["success"]
    assert "token expired" in r["error"]
    assert "system/Group.read" in r["error"]
    assert r["status_code"] == 401


async def test_get_groups_mock_mode(monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: True)
    monkeypatch.setattr(configing, "is_mock_mode", lambda: True)
    conn = _connection()
    conn.connection_id = "onyx-demo"
    r = await remoting.get_groups(conn)
    assert r["success"] and r["groups"][0] == {
        "id": "grp-demo-export-1",
        "name": "grp-demo-export-1",
    }


async def test_get_groups_static_without_http(monkeypatch):
    def handler(request):
        raise AssertionError("no request expected")

    _patch(monkeypatch, handler)
    r = await remoting.get_groups(_connection())
    assert [g["id"] for g in r["groups"]] == [
        "grp-demo-export-1",
        "grp-demo-export-2",
        "grp-demo-export-3",
    ]


async def test_export_kickoff(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            202, headers={"Content-Location": "/v1/export-status/abc"}
        )

    _patch(monkeypatch, handler)
    r = await remoting.davinci_data_export(_connection(), "g1")
    assert seen[0].method == "POST"
    assert str(seen[0].url) == f"{FHIR}/Group/g1/$davinci-data-export/"
    assert seen[0].headers["prefer"] == "respond-async"
    assert seen[0].headers["content-type"] == "application/fhir+json"
    assert json.loads(seen[0].content) == {
        "exportType": "hl7.fhir.us.davinci-pdex#provider-snapshot"
    }
    assert seen[0].headers["authorization"] == "Bearer tok123"
    assert r == {"success": True, "status_url": "http://fhir.test/v1/export-status/abc"}


@pytest.mark.parametrize("slash", ["", "/"])
async def test_export_kickoff_status_url_prefix(monkeypatch, slash):
    monkeypatch.setenv(
        "SIGNET_EXPORT_STATUS_URL_PREFIX",
        f"{FHIR}/Group/davinci-data-export-status{slash}",
    )
    location = f"{FHIR}/blueshost/v2/Group/davinci-data-export-status/abc"
    _patch(
        monkeypatch,
        lambda req: httpx.Response(202, headers={"Content-Location": location}),
    )
    r = await remoting.davinci_data_export(_connection(), "g1")
    assert r["status_url"] == f"{FHIR}/Group/davinci-data-export-status/abc"


async def test_export_kickoff_get(monkeypatch):
    monkeypatch.setenv("SIGNET_EXPORT_METHOD", "get")
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            202, headers={"Content-Location": "/v1/export-status/abc"}
        )

    _patch(monkeypatch, handler)
    r = await remoting.davinci_data_export(_connection(), "g1")
    assert seen[0].method == "GET" and not seen[0].content
    assert seen[0].headers["prefer"] == "respond-async"
    assert r["success"]


async def test_export_kickoff_without_content_location(monkeypatch):
    _patch(monkeypatch, lambda req: httpx.Response(202))
    r = await remoting.davinci_data_export(_connection(), "g1")
    assert not r["success"] and "Content-Location" in r["error"]


async def test_export_kickoff_error(monkeypatch):
    _patch(monkeypatch, lambda req: httpx.Response(403, json={}))
    r = await remoting.davinci_data_export(_connection(), "g1")
    assert not r["success"] and r["status_code"] == 403


async def test_poll_pending(monkeypatch):
    _patch(monkeypatch, lambda req: httpx.Response(202, headers={"Retry-After": "7"}))
    r = await remoting.poll_export_status(_connection(), f"{FHIR}/s/1")
    assert r == {"success": True, "state": "pending", "retry_after": "7"}


async def test_poll_complete_manifest(monkeypatch):
    manifest = {"output": [{"type": "Patient", "url": f"{FHIR}/download/t1"}]}
    _patch(monkeypatch, lambda req: httpx.Response(200, json=manifest))
    r = await remoting.poll_export_status(_connection(), f"{FHIR}/s/1")
    assert r["state"] == "complete"
    assert r["files"] == [{"type": "Patient", "url": f"{FHIR}/download/t1"}]


async def test_poll_task_in_progress(monkeypatch):
    task = {"resourceType": "Task", "status": "in-progress"}
    _patch(monkeypatch, lambda req: httpx.Response(200, json=task))
    r = await remoting.poll_export_status(_connection(), f"{FHIR}/s/1")
    assert r["state"] == "pending"


async def test_poll_task_completed(monkeypatch):
    task = {
        "resourceType": "Task",
        "status": "completed",
        "output": [{"type": {"text": "Coverage"}, "valueUri": "download/t2"}],
    }
    _patch(monkeypatch, lambda req: httpx.Response(200, json=task))
    r = await remoting.poll_export_status(_connection(), f"{FHIR}/s/1")
    assert r["files"] == [{"type": "Coverage", "url": f"{FHIR}/s/download/t2"}]


async def test_poll_task_failed(monkeypatch):
    task = {"resourceType": "Task", "status": "failed"}
    _patch(monkeypatch, lambda req: httpx.Response(200, json=task))
    r = await remoting.poll_export_status(_connection(), f"{FHIR}/s/1")
    assert not r["success"]


async def test_poll_error(monkeypatch):
    _patch(monkeypatch, lambda req: httpx.Response(500, json={}))
    r = await remoting.poll_export_status(_connection(), f"{FHIR}/s/1")
    assert not r["success"] and r["status_code"] == 500


async def test_download_streams_to_disk(monkeypatch, tmp_path):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b'{"id": 1}\n{"id": 2}\n')

    _patch(monkeypatch, handler)
    r = await remoting.download_export_file(
        _connection(),
        f"{FHIR}/download/t1",
        tmp_path / "out",
        filename="Patient-1.ndjson",
    )
    assert seen[0].headers["authorization"] == "Bearer tok123"
    assert r["success"] and r["bytes"] == 20
    assert (
        tmp_path / "out" / "Patient-1.ndjson"
    ).read_bytes() == b'{"id": 1}\n{"id": 2}\n'


async def test_download_error(monkeypatch, tmp_path):
    _patch(monkeypatch, lambda req: httpx.Response(401, json={}))
    r = await remoting.download_export_file(
        _connection(), f"{FHIR}/download/t1", tmp_path
    )
    assert not r["success"] and r["status_code"] == 401


def test_token_claims_logs_issuer_not_token():
    import base64
    import json

    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    token = f"{b64({'alg': 'none'})}.{b64({'iss': 'https://idp', 'aud': 'x', 'secret': 'no'})}.sig"
    logged = remoting._token_claims(token)
    assert json.loads(logged) == {"iss": "https://idp", "aud": "x"}
    assert "sig" not in logged
    assert remoting._token_claims("opaque") == "opaque token"
