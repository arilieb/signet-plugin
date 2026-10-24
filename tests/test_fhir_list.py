import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from acdc_auth_client.core import flows
from acdc_auth_client.core.options import ConnectionInfo
from acdc_auth_client.models.errors import ExportTimeoutError, FhirError
from acdc_auth_client.models.fhir import (
    DownloadedFile,
    ExportFile,
    ExportKickoff,
    ExportStatus,
)

from signet.fhir import list as list_module
from signet.fhir.list import FhirApisListPage

pytest.importorskip("PySide6")


class _Page:
    """Stands in for the page: only what ``_call_authorized`` touches."""

    def __init__(self):
        self.forced = []

    def _connection_getter(self, connection_id):
        def get_connection(force=False):
            self.forced.append(force)
            return ConnectionInfo(
                base_url="http://x", access_token="forced" if force else "stored"
            )

        return get_connection


async def _run(results):
    page, tokens = _Page(), []

    def call(connection):
        tokens.append(connection.access_token)
        result = results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    result = await FhirApisListPage._call_authorized(page, "c1", call)
    return result, tokens, page.forced


async def test_call_authorized_passes_through_success():
    result, tokens, forced = await _run(["ok"])
    assert result == "ok"
    assert tokens == ["stored"] and forced == [False]


async def test_call_authorized_reauthenticates_once_on_401_or_403():
    for status in (401, 403):
        result, tokens, forced = await _run(
            [FhirError("denied", status_code=status), "ok"]
        )
        assert result == "ok"
        assert tokens == ["stored", "forced"] and forced == [False, True]


async def test_call_authorized_retries_only_once():
    with pytest.raises(FhirError) as caught:
        await _run(
            [FhirError("denied", status_code=403), FhirError("denied", status_code=403)]
        )
    assert caught.value.status_code == 403


@pytest.mark.parametrize("status", [500, None])  # None: a transport error
async def test_call_authorized_does_not_retry_other_errors(status):
    results = [FhirError("boom", status_code=status)]
    with pytest.raises(FhirError):
        await _run(results)
    assert not results  # consumed exactly once


def test_supersede_export_bumps_the_run_and_wakes_the_waiter():
    page = SimpleNamespace(_export_run=3, _export_stop=threading.Event())
    old = page._export_stop
    assert FhirApisListPage._supersede_export(page) == 4
    assert page._export_run == 4
    assert old.is_set()
    assert not page._export_stop.is_set() and page._export_stop is not old


class _FakeFhir:
    """The FHIR calls of an export: ``statuses`` are answered one per poll."""

    def __init__(self, statuses):
        self._statuses = statuses
        self.closed = False

    def kickoff_export(self, connection, group_id):
        return ExportKickoff(status_url="http://x/status")

    def poll_export_status(self, connection, status_url):
        return self._statuses.pop(0)

    def close(self):
        self.closed = True


class _ExportPage:
    """Stands in for the page: only what ``_run_export`` touches."""

    def __init__(self):
        self._export_run = 1
        self._export_stop = SimpleNamespace(wait=self._wait)
        self.sleeps = []
        self.loading_shown = 0
        self.files = None
        self.errors = []
        self.hidden = 0
        self.table = SimpleNamespace(hide=self._hide)

    def _wait(self, seconds):
        self.sleeps.append(seconds)

    def _hide(self):
        self.hidden += 1

    def _connection_getter(self, connection_id):
        return lambda force=False: ConnectionInfo(base_url="http://x")

    def _show_loading(self):
        self.loading_shown += 1

    def _show_export_files(self, files):
        self.files = files

    def show_error(self, message):
        self.errors.append(message)


def _pending(retry_after=""):
    return ExportStatus(state="pending", retry_after=retry_after)


def _complete(*files):
    return ExportStatus(state="complete", files=list(files))


def _export(monkeypatch, statuses):
    fhir = _FakeFhir(statuses)
    monkeypatch.setattr(list_module.remoting, "fhir_client", lambda: fhir)
    return _ExportPage(), fhir


async def test_run_export_shows_the_files_and_waits_between_polls(monkeypatch):
    file = ExportFile(type="Patient", url="http://x/f1")
    page, fhir = _export(monkeypatch, [_pending("10")] * 3 + [_complete(file)])

    await FhirApisListPage._run_export(page, 1, "c1", "g1")

    assert page.sleeps == [1, 2, 4]  # the library's backoff, waited on the stop event
    assert page.files == [{"type": "Patient", "url": "http://x/f1"}]
    assert not page.errors
    assert page.loading_shown == 1  # once at kickoff, not on every poll
    assert fhir.closed


async def test_run_export_failure_hides_the_table_and_shows_the_error(monkeypatch):
    page, fhir = _export(monkeypatch, [])
    fhir.poll_export_status = lambda connection, url: (_ for _ in ()).throw(
        FhirError("Data export failed.", status_code=500)
    )

    await FhirApisListPage._run_export(page, 1, "c1", "g1")

    assert page.errors == ["Data export failed."]
    assert page.hidden == 1 and page.files is None
    assert fhir.closed


async def test_run_export_gives_up_after_the_deadline(monkeypatch):
    page, _ = _export(monkeypatch, [_pending("120") for _ in range(1000)])
    clock = [0.0]

    def wait(seconds):
        clock[0] += seconds

    page._export_stop = SimpleNamespace(wait=wait)
    real_export_group = flows.export_group
    monkeypatch.setattr(
        list_module.flows,
        "export_group",
        lambda *args, **kwargs: real_export_group(
            *args, monotonic=lambda: clock[0], **kwargs
        ),
    )

    await FhirApisListPage._run_export(page, 1, "c1", "g1")

    assert page.errors == [flows.EXPORT_TIMEOUT_MESSAGE]
    assert page.errors == ["Data export is taking too long; try again later."]


async def test_run_export_stops_quietly_when_superseded(monkeypatch):
    page, fhir = _export(monkeypatch, [_pending(), _pending(), _complete()])

    def supersede(seconds):  # a newer export starts while this one waits
        page._export_run = 2

    page._export_stop = SimpleNamespace(wait=supersede)

    await FhirApisListPage._run_export(page, 1, "c1", "g1")

    assert page.files is None and not page.errors and page.hidden == 0
    assert len(fhir._statuses) == 2  # no further poll was made
    assert fhir.closed


async def test_run_export_superseded_error_is_not_shown(monkeypatch):
    page, _ = _export(monkeypatch, [])

    def explode(*args, **kwargs):
        page._export_run = 2
        raise ExportTimeoutError("late")
        yield  # pragma: no cover (a generator)

    monkeypatch.setattr(list_module.flows, "export_group", explode)

    await FhirApisListPage._run_export(page, 1, "c1", "g1")

    assert not page.errors and page.hidden == 0


class _DownloadPage:
    """Stands in for the page: only what ``_on_authenticated_row`` touches."""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self._export_rows = {
            "Patient-1.ndjson": {
                "File": "Patient-1.ndjson",
                "Status": "Ready",
                "Size": "",
                "url": "http://x/f1",
            }
        }
        self.errors = []
        self.statuses = []

    def _refresh_export_rows(self):
        self.statuses.append(self._export_rows["Patient-1.ndjson"]["Status"])

    def _connection_getter(self, connection_id):
        return lambda force=False: ConnectionInfo(base_url="http://x")

    async def _call_authorized(self, connection_id, call):
        return await FhirApisListPage._call_authorized(self, connection_id, call)

    def show_error(self, message):
        self.errors.append(message)


def _download(monkeypatch, tmp_path, fhir):
    destination = tmp_path / "chosen.ndjson"
    monkeypatch.setattr(
        list_module.QFileDialog,
        "getSaveFileName",
        lambda *args, **kwargs: (str(destination), ""),
    )
    monkeypatch.setattr(list_module.remoting, "fhir_client", lambda: fhir)
    return _DownloadPage(tmp_path)


async def test_download_writes_to_the_chosen_file(monkeypatch, tmp_path):
    calls, threads = [], []

    class Fhir:
        def download_file(self, connection, url, dest_dir, filename=""):
            calls.append((url, dest_dir, filename))
            threads.append(threading.current_thread())
            return DownloadedFile(path=str(Path(dest_dir) / filename), bytes=1234)

        def close(self):
            pass

    page = _download(monkeypatch, tmp_path, Fhir())
    await FhirApisListPage._on_authenticated_row(
        page, "c1", {"File": "Patient-1.ndjson"}
    )

    assert calls == [("http://x/f1", tmp_path, "chosen.ndjson")]
    assert threads[0] is not threading.main_thread()  # a slow download frees the UI
    row = page._export_rows["Patient-1.ndjson"]
    assert row["Status"] == "Downloaded" and row["Size"] == "1,234 B"
    assert page.statuses == ["Downloading", "Downloaded"]
    assert not page.errors


async def test_download_failure_marks_the_row_failed(monkeypatch, tmp_path):
    class Fhir:
        def download_file(self, *args, **kwargs):
            raise FhirError("Access denied", status_code=500)

        def close(self):
            pass

    page = _download(monkeypatch, tmp_path, Fhir())
    await FhirApisListPage._on_authenticated_row(
        page, "c1", {"File": "Patient-1.ndjson"}
    )

    assert page._export_rows["Patient-1.ndjson"]["Status"] == "Failed"
    assert page.errors == ["Access denied"]
