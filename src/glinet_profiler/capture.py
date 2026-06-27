"""Server-side capture: enumerate a device read-only and return a sanitized profile."""

import json
from collections.abc import Awaitable, Callable
from typing import Any

from .enumerator.probe import device_id
from .sanitize import project_report

# Async progress sink: awaited with `{"event": "progress", "phase": ..., ...}` dicts.
ProgressFn = Callable[[dict[str, Any]], Awaitable[None]]


async def _noop(_event: dict[str, Any]) -> None:
    """Default no-op progress sink."""


def _base_url(host: str) -> str:
    """Normalize a router IP / host / URL to a base URL (defaults to http://)."""
    base = host.strip().rstrip("/")
    if "://" not in base:
        base = f"http://{base}"
    return base


async def _enumerate(  # pylint: disable=too-many-locals,too-many-arguments
    host: str,
    username: str,
    password: str,
    *,
    ssh: bool,
    dangerous: bool,
    include_destructive: bool,
    on_progress: ProgressFn,
) -> dict[str, Any]:
    """Run the read-only enumeration and return the raw report dict (performs I/O)."""
    import aiohttp  # pylint: disable=import-outside-toplevel  # noqa: PLC0415  (local so tests can patch _enumerate)

    from .enumerator.probe import (
        enumerate_device,  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
    )
    from .enumerator.report import (
        to_json,  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
    )
    from .enumerator.ssh import (  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
        SshUnavailable,
        ssh_discover,
    )
    from .glinet_login import login  # pylint: disable=import-outside-toplevel  # noqa: PLC0415

    base = _base_url(host)
    rpc_url = f"{base}/rpc"
    host_only = base.split("://", 1)[1].split("/")[0]

    surface = None
    if ssh:
        await on_progress(
            {
                "event": "progress",
                "phase": "ssh",
                "message": "SSH ground-truth discovery (up to 12s)…",
            }
        )
        try:
            surface = await ssh_discover(host_only, username="root", password=password)
            await on_progress(
                {"event": "progress", "phase": "ssh", "message": "SSH ground-truth captured."}
            )
        except SshUnavailable:
            surface = None
            await on_progress(
                {
                    "event": "progress",
                    "phase": "ssh",
                    "message": "SSH unavailable — continuing with the catalog.",
                }
            )

    async with aiohttp.ClientSession() as session:
        await on_progress({"event": "progress", "phase": "login", "message": "Logging in…"})
        sid = await login(session, rpc_url, username, password)
        probed = 0

        async def caller(service: str, method: str, args: dict[str, Any] | None) -> dict[str, Any]:
            nonlocal probed
            params: list[Any] = [sid, service, method]
            if args is not None:
                params.append(args)
            payload = {"jsonrpc": "2.0", "id": 0, "method": "call", "params": params}
            async with session.post(rpc_url, json=payload) as resp:
                data: dict[str, Any] = await resp.json(content_type=None)
            probed += 1
            await on_progress(
                {
                    "event": "progress",
                    "phase": "probe",
                    "done": probed,
                    "message": f"Probing {service}.{method}",
                }
            )
            return data

        await on_progress(
            {
                "event": "progress",
                "phase": "probe",
                "done": 0,
                "message": "Probing the API surface…",
            }
        )
        info_env = await caller("system", "get_info", None)
        info = info_env.get("result")
        device_info = info if isinstance(info, dict) else {}
        if dangerous:
            note = "⚠ Dangerous mode: calling WRITE endpoints — this changes your router's config."
            if include_destructive:
                note += " DESTRUCTIVE methods (reboot/reset/upgrade) will be called LAST."
            await on_progress({"event": "progress", "phase": "warn", "message": note})
        report = await enumerate_device(
            caller,
            device_info=device_info,
            ssh_surface=surface,
            probe_writes=dangerous,
            include_destructive=include_destructive,
        )
        raw: dict[str, Any] = json.loads(to_json(report))
        return raw


async def capture(
    host: str,
    username: str,
    password: str,
    *,
    ssh: bool = True,
    dangerous: bool = False,
    include_destructive: bool = False,
    on_progress: ProgressFn | None = None,
) -> dict[str, Any]:
    """Enumerate (read-only by default; SSH attempted by default) and return the sanitized profile.

    By default no write/set endpoint is ever HTTP-called — SSH-discovered writes are recorded as
    ``discovered``. ``dangerous`` additionally calls WRITE endpoints (changes config — spare
    routers); ``dangerous`` + ``include_destructive`` also calls DESTRUCTIVE methods last
    (reboot/reset/upgrade — sacrificial routers).

    ``on_progress``, if given, is awaited with ``{"event": "progress", ...}`` dicts as the
    capture proceeds (ssh → login → probe → sanitize), for live UI/console feedback.
    """
    progress = on_progress or _noop
    raw = await _enumerate(
        host,
        username,
        password,
        ssh=ssh,
        dangerous=dangerous,
        include_destructive=include_destructive,
        on_progress=progress,
    )
    await progress({"event": "progress", "phase": "sanitize", "message": "Sanitizing profile…"})
    return project_report(raw, device_id(raw.get("device", {})))
