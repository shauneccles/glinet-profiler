"""capture() tests against a mocked enumeration (no router)."""
# pylint: disable=missing-function-docstring,redefined-outer-name,unused-argument,too-few-public-methods

import json

import aiohttp
import pytest

import glinet_profiler.capture as capture_mod
from glinet_profiler.capture import _base_url, _rpc_post, capture


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


class _Resp:
    def __init__(self, status, data):
        self.status, self._data = status, data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def json(self, content_type=None):
        return self._data


class _Session:
    """Fake aiohttp session: post() yields queued _Resp objects, or raises a queued exception."""

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls = 0

    def post(self, url, json=None, timeout=None):  # noqa: A002
        outcome = self._outcomes[self.calls]
        self.calls += 1
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


async def test_rpc_post_retries_5xx_then_succeeds():
    sess = _Session([_Resp(503, {}), _Resp(502, {}), _Resp(200, {"result": "ok"})])
    out = await _rpc_post(sess, "http://x/rpc", {}, backoff=0)
    assert out == {"result": "ok"}
    assert sess.calls == 3  # two transient 5xx retried, third succeeds


async def test_rpc_post_retries_refused_connection():
    sess = _Session([aiohttp.ClientConnectionError("refused"), _Resp(200, {"result": 1})])
    out = await _rpc_post(sess, "http://x/rpc", {}, backoff=0)
    assert out == {"result": 1}
    assert sess.calls == 2


async def test_rpc_post_does_not_retry_timeout():
    # a timeout is a genuinely slow method (nil-param fast-crashes are fixed by sending {} args),
    # so it propagates to the caller (-> UNREACHABLE) rather than tying up a worker on retries
    sess = _Session([TimeoutError()])
    with pytest.raises(TimeoutError):
        await _rpc_post(sess, "http://x/rpc", {}, backoff=0)
    assert sess.calls == 1


async def test_rpc_post_gives_up_after_max_retries():
    sess = _Session([_Resp(503, {})] * 6)
    with pytest.raises(ConnectionError):
        await _rpc_post(sess, "http://x/rpc", {}, retries=2, backoff=0)
    assert sess.calls == 3  # initial attempt + 2 retries, then it raises


async def test_rpc_post_does_not_retry_a_real_answer():
    sess = _Session([_Resp(200, {"error": {"code": -32601}})])
    out = await _rpc_post(sess, "http://x/rpc", {}, backoff=0)
    assert out["error"]["code"] == -32601  # a JSON-RPC error is a real reply, not a worker shortage
    assert sess.calls == 1
