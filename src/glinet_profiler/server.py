"""The local launcher web server (aiohttp, 127.0.0.1, token-guarded API)."""

import json
import os
import secrets
import socket
import webbrowser
from importlib import resources
from pathlib import Path
from typing import Any

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


def make_app(
    token: str, *, registry_url: str = registry_mod.DEFAULT_REGISTRY_URL
) -> web.Application:
    """Build the aiohttp application."""
    app = web.Application()

    async def index(_request: web.Request) -> web.StreamResponse:
        return web.FileResponse(str(_WEB / "index.html"))

    async def asset(request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        path = Path(str(_WEB / name))
        if name not in ("app.js", "style.css") or not path.is_file():
            raise web.HTTPNotFound()
        return web.FileResponse(str(path))

    async def api_enumerate(request: web.Request) -> web.StreamResponse:
        _guard(request, token)
        body = await request.json()
        resp = web.StreamResponse(
            headers={"Content-Type": "application/x-ndjson", "Cache-Control": "no-store"}
        )
        await resp.prepare(request)

        async def emit(event: dict[str, Any]) -> None:
            await resp.write((json.dumps(event) + "\n").encode())
            print(f"[capture] {event.get('message') or event.get('event')}")

        try:
            profile = await capture_mod.capture(
                body["host"],
                body.get("username") or "root",
                body.get("password", ""),
                ssh=bool(body.get("ssh", True)),
                dangerous=bool(body.get("dangerous", False)),
                include_destructive=bool(body.get("include_destructive", False)),
                on_progress=emit,
            )
            manifest = await registry_mod.fetch_manifest(registry_url)
            match = registry_mod.lookup(
                profile.get("model", ""), profile.get("firmware_version", ""), manifest
            )
            await emit(
                {
                    "event": "result",
                    "profile": profile,
                    "lookup": match,
                    "registry_reachable": manifest is not None,
                    "submit_url": submit_mod.prefilled_issue_url(profile),
                }
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            await emit({"event": "error", "message": str(exc)})
        await resp.write_eof()
        return resp

    app.router.add_get("/", index)
    app.router.add_post("/api/enumerate", api_enumerate)
    app.router.add_get("/{name}", asset)
    return app


def _is_wsl() -> bool:
    """Detect WSL, where the default browser opener (gio) fails with 'Operation not supported'."""
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in Path("/proc/version").read_text(encoding="utf-8").lower()
    except OSError:
        return False


def _open_browser(url: str) -> None:
    """Best-effort open the URL; under WSL (or on failure) just point the user at the printed URL."""
    if _is_wsl():
        print("  (auto-open isn't supported here — open the URL above in your browser)")
        return
    try:
        webbrowser.open(url)
    except (webbrowser.Error, OSError):  # pragma: no cover - best-effort, never fatal
        print("  (couldn't auto-open a browser — open the URL above)")


def serve(
    *,
    port: int = 0,
    open_browser: bool = True,
    registry_url: str = registry_mod.DEFAULT_REGISTRY_URL,
) -> None:
    """Start the launcher on 127.0.0.1 (ephemeral port by default) and optionally open the browser."""
    token = secrets.token_urlsafe(16)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    actual_port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{actual_port}/?t={token}"
    app = make_app(token, registry_url=registry_url)

    async def _on_startup(_app: web.Application) -> None:
        print(f"glinet-profiler is running at:\n  {url}\nPress Ctrl+C to stop.")
        if open_browser:
            _open_browser(url)

    app.on_startup.append(_on_startup)
    # web.run_app installs signal handlers and drains in-flight requests on Ctrl+C
    # (graceful shutdown) — no more "Executor shutdown has been called" tracebacks.
    web.run_app(app, sock=sock, print=None, handle_signals=True)
    print("stopped.")
