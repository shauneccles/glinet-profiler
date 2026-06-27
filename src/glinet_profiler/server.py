"""The local launcher web server (aiohttp, 127.0.0.1, token-guarded API)."""

import asyncio
import secrets
import socket
import webbrowser
from importlib import resources
from pathlib import Path

from aiohttp import web

from . import capture as capture_mod
from . import registry as registry_mod
from . import submit as submit_mod

_WEB = resources.files("glinet_profiler") / "web"
_ALLOWED_HOSTS = ("127.0.0.1", "localhost")


def _guard(request: web.Request, token: str) -> None:
    if request.headers.get("X-Profiler-Token") != token:
        raise web.HTTPUnauthorized(text="missing or invalid token")
    if (request.host or "").split(":")[0] not in _ALLOWED_HOSTS:
        raise web.HTTPForbidden(text="local access only")


def make_app(token: str, *, registry_url: str | None = None) -> web.Application:
    """Build the aiohttp application. `registry_url` is reserved for a live registry (unused in v1)."""
    _ = registry_url  # v1 uses the bundled registry
    app = web.Application()

    async def index(_request: web.Request) -> web.StreamResponse:
        return web.FileResponse(str(_WEB / "index.html"))

    async def asset(request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        path = Path(str(_WEB / name))
        if name not in ("app.js", "style.css") or not path.is_file():
            raise web.HTTPNotFound()
        return web.FileResponse(str(path))

    async def api_enumerate(request: web.Request) -> web.Response:
        _guard(request, token)
        body = await request.json()
        profile = await capture_mod.capture(
            body["host"],
            body.get("username") or "root",
            body.get("password", ""),
            ssh=bool(body.get("ssh", True)),
        )
        match = registry_mod.lookup(profile.get("model", ""), profile.get("firmware_version", ""))
        return web.json_response(
            {
                "profile": profile,
                "lookup": match,
                "submit_url": submit_mod.prefilled_issue_url(profile),
            }
        )

    async def api_registry(request: web.Request) -> web.Response:
        _guard(request, token)
        return web.json_response(registry_mod.load_manifest())

    app.router.add_get("/", index)
    app.router.add_post("/api/enumerate", api_enumerate)
    app.router.add_get("/api/registry", api_registry)
    app.router.add_get("/{name}", asset)
    return app


def serve(*, port: int = 0, open_browser: bool = True, registry_url: str | None = None) -> None:
    """Start the launcher on 127.0.0.1 (ephemeral port by default) and optionally open the browser."""
    token = secrets.token_urlsafe(16)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    actual_port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{actual_port}/?t={token}"

    async def _run() -> None:
        runner = web.AppRunner(make_app(token, registry_url=registry_url))
        await runner.setup()
        await web.SockSite(runner, sock).start()
        print(f"glinet-profiler is running at:\n  {url}\nPress Ctrl+C to stop.")
        if open_browser:
            webbrowser.open(url)
        await asyncio.Event().wait()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print("\nstopped.")
