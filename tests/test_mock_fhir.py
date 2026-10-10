from signet.core import configing, mock_data

COLUMNS = {"Resource", "Operation", "Endpoint", "Scope", "Purpose"}


def test_fhir_fixtures_shape(monkeypatch):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: True)
    for connection_id, groups in mock_data.FHIR_GROUPS.items():
        assert mock_data.fhir_groups(connection_id) == groups
        for group in groups:
            assert set(group) == {"group_id", "display_name"}
            rows = mock_data.fhir_endpoints(connection_id, group["group_id"])
            assert rows
            for row in rows:
                assert set(row) == COLUMNS
                assert group["group_id"] in row["Endpoint"]


def test_fhir_unknown_ids_are_empty(monkeypatch):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: True)
    assert mock_data.fhir_groups("nope") == []
    assert mock_data.fhir_endpoints("cambia-demo", "nope") == []
    assert mock_data.fhir_endpoints("nope", "cambia-members-2026") == []


def test_fhir_empty_outside_mock_mode(monkeypatch):
    monkeypatch.setattr(configing, "is_mock_mode", lambda: False)
    assert mock_data.fhir_groups("cambia-demo") == []
    assert mock_data.fhir_endpoints("cambia-demo", "cambia-members-2026") == []
