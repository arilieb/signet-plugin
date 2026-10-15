from types import SimpleNamespace

from signet.fhir import list as list_module
from signet.fhir.list import FhirApisListPage, _poll_delay


class _Page:
    """Stands in for the page: only what ``_call_authorized`` touches."""

    def __init__(self):
        self.forced = []

    async def _authorized_connection(self, connection_id, force=False):
        self.forced.append(force)
        return SimpleNamespace(access_token="forced" if force else "stored")


async def _run(results):
    page, tokens = _Page(), []

    async def call(connection):
        tokens.append(connection.access_token)
        return results.pop(0)

    result = await FhirApisListPage._call_authorized(page, "c1", call)
    return result, tokens, page.forced


async def test_call_authorized_passes_through_success():
    result, tokens, forced = await _run([{"success": True}])
    assert result == {"success": True}
    assert tokens == ["stored"] and forced == [False]


async def test_call_authorized_reauthenticates_once_on_401_or_403():
    for status in (401, 403):
        result, tokens, forced = await _run(
            [{"success": False, "status_code": status}, {"success": True}]
        )
        assert result == {"success": True}
        assert tokens == ["stored", "forced"] and forced == [False, True]


async def test_call_authorized_retries_only_once():
    result, tokens, _ = await _run(
        [{"success": False, "status_code": 403}, {"success": False, "status_code": 403}]
    )
    assert result["status_code"] == 403 and len(tokens) == 2


async def test_call_authorized_does_not_retry_other_errors():
    result, tokens, _ = await _run([{"success": False, "status_code": 500}])
    assert result["status_code"] == 500 and tokens == ["stored"]


def test_poll_delay_doubles_up_to_ceiling():
    assert [_poll_delay(n, 10.0) for n in range(6)] == [1, 2, 4, 8, 10, 10]


def test_poll_delay_ceiling_below_initial():
    assert _poll_delay(0, 0.5) == 0.5


class _ExportPage:
    """Stands in for the page: only what ``_run_export`` touches."""

    def __init__(self, statuses):
        self._export_run = 1
        self._statuses = statuses
        self.loading_shown = 0
        self.kicked_off = False
        self.files = None
        self.errors = []
        self.table = SimpleNamespace(hide=lambda: None)

    async def _call_authorized(self, connection_id, call):
        if not self.kicked_off:
            self.kicked_off = True
            return {"success": True, "status_url": "http://x/status"}
        return self._statuses.pop(0)

    def _show_loading(self):
        self.loading_shown += 1

    def _show_export_files(self, files):
        self.files = files

    def show_error(self, message):
        self.errors.append(message)


def _fake_clock(monkeypatch):
    clock, sleeps = [0.0], []

    async def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(list_module.asyncio, "sleep", sleep)
    monkeypatch.setattr(list_module.time, "monotonic", lambda: clock[0])
    return sleeps


async def test_run_export_backs_off_to_retry_after(monkeypatch):
    sleeps = _fake_clock(monkeypatch)
    pending = {"success": True, "state": "in-progress", "retry_after": "10"}
    page = _ExportPage(
        [pending] * 6 + [{"success": True, "state": "complete", "files": []}]
    )

    await FhirApisListPage._run_export(page, 1, "c1", "g1")

    assert sleeps == [1, 2, 4, 8, 10, 10]
    assert page.files == [] and not page.errors
    assert page.loading_shown == 1  # once at kickoff, not on every poll


async def test_run_export_keeps_ceiling_when_retry_after_missing(monkeypatch):
    sleeps = _fake_clock(monkeypatch)
    page = _ExportPage(
        [
            {"success": True, "state": "in-progress", "retry_after": "3"},
            {"success": True, "state": "in-progress"},
            {"success": True, "state": "in-progress"},
            {"success": True, "state": "complete", "files": []},
        ]
    )

    await FhirApisListPage._run_export(page, 1, "c1", "g1")

    assert sleeps == [1, 2, 3]


async def test_run_export_gives_up_after_deadline(monkeypatch):
    _fake_clock(monkeypatch)
    pending = {"success": True, "state": "in-progress", "retry_after": "120"}
    page = _ExportPage([dict(pending) for _ in range(1000)])

    await FhirApisListPage._run_export(page, 1, "c1", "g1")

    assert page.errors == ["Data export is taking too long; try again later."]
