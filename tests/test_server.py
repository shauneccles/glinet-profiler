"""Server API tests (aiohttp test client; no router)."""
# pylint: disable=missing-function-docstring,redefined-outer-name,unused-argument

import pytest

import glinet_profiler.capture as capture_mod
from glinet_profiler.server import make_app

TOKEN = "test-token"
PROFILE = {
    "id": "mt6000_4.9.0",
    "model": "mt6000",
    "firmware_version": "4.9.0",
    "services": {
        "system": {
            "get_info": {
                "status": "available",
                "error_code": None,
                "risk": "read",
                "discovered_by": "catalog",
                "covered_by": "router_info",
                "params": None,
                "schema": {},
            }
        }
    },
}


@pytest.fixture
async def client(aiohttp_client, monkeypatch):
    async def fake_capture(host, username, password, *, ssh=False):  # noqa: ARG001
        return PROFILE

    monkeypatch.setattr(capture_mod, "capture", fake_capture)
    return await aiohttp_client(make_app(TOKEN))


async def test_enumerate_requires_token(client):
    resp = await client.post("/api/enumerate", json={"host": "http://x", "password": "p"})
    assert resp.status == 401


async def test_enumerate_with_token_returns_profile_lookup_submit(client):
    resp = await client.post(
        "/api/enumerate",
        headers={"X-Profiler-Token": TOKEN},
        json={"host": "http://x", "username": "root", "password": "p", "ssh": False},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["profile"]["model"] == "mt6000"
    assert data["lookup"] is not None  # mt6000_4.9.0 is in the bundled registry
    assert "issues/new" in data["submit_url"]


async def test_index_is_served(client):
    resp = await client.get("/")
    assert resp.status == 200
    assert "glinet-profiler" in await resp.text()


def test_open_browser_skips_under_wsl(monkeypatch):
    import glinet_profiler.server as srv  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(srv, "_is_wsl", lambda: True)
    calls = []
    monkeypatch.setattr(srv.webbrowser, "open", calls.append)
    srv._open_browser("http://127.0.0.1:1234/")  # pylint: disable=protected-access
    assert not calls  # under WSL we must NOT invoke the (broken) browser opener
