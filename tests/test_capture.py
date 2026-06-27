"""capture() tests against a mocked enumeration (no router)."""
# pylint: disable=missing-function-docstring,redefined-outer-name,unused-argument

import json

import glinet_profiler.capture as capture_mod
from glinet_profiler.capture import _base_url, capture


def test_base_url_normalizes_bare_ip():
    assert _base_url("192.168.8.1") == "http://192.168.8.1"
    assert _base_url("http://192.168.8.1/") == "http://192.168.8.1"
    assert _base_url("https://router") == "https://router"


RAW = {
    "device": {
        "model": "mt6000",
        "firmware_version": "4.9.0",
        "mac": "94:83:C4:AA:BB:CC",
        "sn": "SECRET123",
    },
    "services": {
        "system": {
            "get_info": {
                "status": "available",
                "error_code": None,
                "risk": "read",
                "discovered_by": "catalog",
                "covered_by": "router_info",
                "params": None,
                "schema": {"model": "str"},
                "value": {"mac": "94:83:C4:AA:BB:CC"},
            }
        }
    },
}


async def test_capture_returns_sanitized_profile(monkeypatch):
    async def fake_enumerate(
        host, username, password, *, ssh, dangerous=False, include_destructive=False, on_progress
    ):  # noqa: ARG001
        return RAW

    monkeypatch.setattr(capture_mod, "_enumerate", fake_enumerate)
    profile = await capture("http://192.168.8.1", "root", "pw")
    assert profile["id"] == "mt6000_4.9.0"
    assert profile["model"] == "mt6000"
    assert "mac" not in profile and "sn" not in profile
    assert "value" not in profile["services"]["system"]["get_info"]
    blob = json.dumps(profile)
    assert "SECRET123" not in blob and "94:83:C4" not in blob


async def test_capture_passes_ssh_flag(monkeypatch):
    seen = {}

    async def fake_enumerate(
        host, username, password, *, ssh, dangerous=False, include_destructive=False, on_progress
    ):  # noqa: ARG001
        seen["ssh"] = ssh
        return RAW

    monkeypatch.setattr(capture_mod, "_enumerate", fake_enumerate)
    await capture("http://x", "root", "pw", ssh=True)
    assert seen["ssh"] is True


async def test_capture_passes_dangerous_flags(monkeypatch):
    seen = {}

    async def fake_enumerate(
        host, username, password, *, ssh, dangerous=False, include_destructive=False, on_progress
    ):  # noqa: ARG001
        seen["dangerous"] = dangerous
        seen["include_destructive"] = include_destructive
        return RAW

    monkeypatch.setattr(capture_mod, "_enumerate", fake_enumerate)
    await capture("http://x", "root", "pw", dangerous=True, include_destructive=True)
    assert seen == {"dangerous": True, "include_destructive": True}


async def test_capture_forwards_progress(monkeypatch):
    events = []

    async def record(event):
        events.append(event)

    async def fake_enumerate(
        host, username, password, *, ssh, dangerous=False, include_destructive=False, on_progress
    ):  # noqa: ARG001
        await on_progress({"event": "progress", "phase": "probe", "done": 1, "message": "x"})
        return RAW

    monkeypatch.setattr(capture_mod, "_enumerate", fake_enumerate)
    await capture("http://x", "root", "pw", on_progress=record)
    phases = [e["phase"] for e in events]
    assert "probe" in phases  # forwarded from _enumerate
    assert "sanitize" in phases  # emitted by capture() after enumeration
