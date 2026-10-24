"""
The FHIR side of the remoting facade: Group listing, the mock stand-in for the
library's FhirClient, and the static Group list. Request shapes, error messages,
paging and the export parsing are covered by acdc-auth-client's own tests.
"""

from types import SimpleNamespace

import pytest
import responses
from acdc_auth_client.core.fhir_client import FhirClient
from acdc_auth_client.core.flows import export_group
from acdc_auth_client.core.options import ConnectionInfo

from signet.core import mock_data, remoting

FHIR = "http://fhir.test/v1"


@pytest.fixture(autouse=True)
def real_mode(monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: False)
    monkeypatch.delenv("SIGNET_FHIR_BASE_URL", raising=False)


def _connection(base_url=f"{FHIR}/.well-known/keri"):
    return SimpleNamespace(
        connection_id="c1",
        base_url=base_url,
        access_token="tok123",
        token_type="Bearer",
        token_scope="system/Group.read",
        token_expires_at="2099-01-01T00:00:00+00:00",
    )


async def test_fetch_groups_sends_bearer_and_strips_keri_path():
    with responses.RequestsMock() as http:
        http.get(
            f"{FHIR}/Group",
            json={
                "entry": [
                    {"resource": {"id": "g1", "name": "One"}},
                    {"resource": {"id": "g2"}},
                ]
            },
        )
        r = await remoting.fetch_groups(_connection())
        headers = http.calls[0].request.headers
    assert headers["Authorization"] == "Bearer tok123"
    assert r == {
        "success": True,
        "groups": [{"id": "g1", "name": "One"}, {"id": "g2", "name": "g2"}],
    }


async def test_fetch_groups_access_denied_keeps_the_status_for_reauth():
    with responses.RequestsMock() as http:
        http.get(f"{FHIR}/Group", status=403, json={"error": "forbidden"})
        r = await remoting.fetch_groups(_connection())
    assert not r["success"]
    assert r["status_code"] == 403
    assert "system/Group.read" in r["error"]


async def test_get_groups_is_the_static_list():
    r = await remoting.get_groups("c1")
    assert r["success"]
    assert [group["id"] for group in r["groups"]] == mock_data.STATIC_GROUP_IDS


async def test_get_groups_in_mock_mode_is_the_fixture(monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: True)
    monkeypatch.setattr(mock_data.configing, "is_mock_mode", lambda: True)
    r = await remoting.get_groups("cambia-demo")
    assert r["success"] and r["groups"]


def test_fhir_client_is_the_library_client_outside_mock_mode(monkeypatch):
    monkeypatch.setenv("SIGNET_EXPORT_METHOD", "GET")
    client = remoting.fhir_client()
    try:
        assert isinstance(client, FhirClient)
        assert client.options.export_method == "GET"
    finally:
        client.close()


def test_fhir_client_in_mock_mode_is_the_stand_in(monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: True)
    assert isinstance(remoting.fhir_client(), remoting._MockFhirClient)


def test_mock_client_exports_the_canned_files_through_the_flow(monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: True)
    connection = ConnectionInfo(base_url=FHIR)
    events = list(export_group(lambda force: connection, remoting.fhir_client(), "g1"))
    assert [event.kind for event in events] == ["started", "complete"]
    assert events[0].status_url == mock_data.MOCK_EXPORT_STATUS_URL
    assert [file.to_dict() for file in events[-1].files] == mock_data.MOCK_EXPORT_FILES


def test_mock_client_downloads_a_canned_file(tmp_path, monkeypatch):
    monkeypatch.setattr(remoting, "is_mock_mode", lambda: True)
    connection = ConnectionInfo(base_url=FHIR)
    client = remoting.fhir_client()
    named = client.download_file(
        connection, "http://x/download/p", tmp_path, "p.ndjson"
    )
    assert (tmp_path / "p.ndjson").read_bytes().startswith(b'{"resourceType"')
    assert named.bytes == (tmp_path / "p.ndjson").stat().st_size
    unnamed = client.download_file(
        connection, "http://x/download/mock-patient", tmp_path
    )
    assert unnamed.path == str(tmp_path / "mock-patient")
