"""CLI tests for glinet-profiler (capture mode + server-mode dispatch)."""
# pylint: disable=missing-function-docstring,redefined-outer-name,unused-argument

import glinet_profiler.cli as cli_mod

PROFILE = {
    "id": "zz1300_9.9.9",
    "model": "zz1300",
    "firmware_version": "9.9.9",
    "services": {"system": {"get_info": {"status": "available", "covered_by": None}}},
}

MAN = {"devices": [{"id": "mt6000_4.9.0", "model": "mt6000", "firmware_version": "4.9.0"}]}


def test_capture_mode_new_device_submit_link(monkeypatch, tmp_path, capsys):
    """A device not in the manifest → NEW status + submission link."""

    async def fake_capture(
        ip,
        username,
        password,
        *,
        ssh=True,
        dangerous=False,
        include_destructive=False,
        keep_data=False,
        on_progress=None,
    ):  # noqa: ARG001
        return PROFILE

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        return MAN  # manifest reachable but zz1300 not in it

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh"])
    assert rc == 0
    out = tmp_path / "zz1300_9.9.9.json"
    assert out.exists()
    stdout = capsys.readouterr().out
    assert "issues/new" in stdout
    assert "zz1300_9.9.9.json" in stdout
    assert "NEW" in stdout


def test_capture_mode_offline_submit_link(monkeypatch, tmp_path, capsys):
    """When fetch_manifest returns None → offline message + submission link."""

    async def fake_capture(
        ip,
        username,
        password,
        *,
        ssh=True,
        dangerous=False,
        include_destructive=False,
        keep_data=False,
        on_progress=None,
    ):  # noqa: ARG001
        return PROFILE

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        return None  # offline

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh"])
    assert rc == 0
    stdout = capsys.readouterr().out
    assert "couldn't reach the registry" in stdout
    assert "issues/new" in stdout


def test_capture_mode_include_destructive_implies_dangerous(monkeypatch, tmp_path):
    seen = {}

    async def fake_capture(
        ip,
        username,
        password,
        *,
        ssh=True,
        dangerous=False,
        include_destructive=False,
        keep_data=False,
        on_progress=None,
    ):  # noqa: ARG001
        seen["dangerous"] = dangerous
        seen["include_destructive"] = include_destructive
        return PROFILE

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        return None

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh", "--include-destructive"])
    assert rc == 0
    assert seen == {"dangerous": True, "include_destructive": True}


def test_capture_mode_keep_data_is_local_only(monkeypatch, tmp_path, capsys):
    """--keep-data passes keep_data through, prints LOCAL-ONLY, and skips the submission flow."""
    seen = {}
    fetched = {"called": False}

    async def fake_capture(
        ip,
        username,
        password,
        *,
        ssh=True,
        dangerous=False,
        include_destructive=False,
        keep_data=False,
        on_progress=None,
    ):  # noqa: ARG001
        seen["keep_data"] = keep_data
        return PROFILE

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        fetched["called"] = True
        return MAN

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh", "--keep-data"])
    assert rc == 0
    assert seen["keep_data"] is True
    assert fetched["called"] is False  # local-only: no registry lookup / submission
    assert "LOCAL-ONLY" in capsys.readouterr().out


def test_no_ip_starts_web_server(monkeypatch):
    called = {}
    monkeypatch.setattr(cli_mod, "serve", lambda **kwargs: called.update(kwargs))
    rc = cli_mod.main(["--port", "9999", "--no-browser", "--registry-url", "http://x/i.json"])
    assert rc == 0
    assert called["port"] == 9999
    assert called["open_browser"] is False
    assert called["registry_url"] == "http://x/i.json"


def test_capture_mode_known_device(monkeypatch, tmp_path, capsys):
    """A device already in the manifest → display 'already in the registry' message."""

    async def fake_capture(
        ip,
        username,
        password,
        *,
        ssh=True,
        dangerous=False,
        include_destructive=False,
        keep_data=False,
        on_progress=None,
    ):  # noqa: ARG001
        return {**PROFILE, "model": "mt6000", "firmware_version": "4.9.0", "id": "mt6000_4.9.0"}

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        return MAN  # contains mt6000_4.9.0

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh"])
    assert rc == 0
    assert "already in the registry" in capsys.readouterr().out
