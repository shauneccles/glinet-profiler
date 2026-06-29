"""Server-side capture: enumerate a device read-only and return a sanitized profile."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp

from .enumerator.probe import device_id
from .sanitize import project_report

# Async progress sink: awaited with `{"event": "progress", "phase": ..., ...}` dicts.
ProgressFn = Callable[[dict[str, Any]], Awaitable[None]]

# A scan shares the router's tiny fcgiwrap RPC backend (4 workers) with whatever else hits /rpc
# (e.g. Home Assistant polling). When there's no free worker a probe gets a 5xx or a refused
# connection that isn't a real answer — retry those with exponential backoff *inside* the
# concurrency slot, so a saturated scan yields instead of piling on. A real JSON-RPC reply is
# never retried; a timeout isn't either (that's a genuinely slow method — the cap below is set
# high enough for the slow-but-finite ones, and a true hang shouldn't tie a worker up on retries).
_REQUEST_TIMEOUT = 20.0  # seconds; a few methods legitimately take >12s (e.g. mptun.get_token ~15s)
_MAX_PROBE_RETRIES = 3
_RETRY_BACKOFF = 0.4  # seconds; exponential: 0.4, 0.8, 1.6


async def _rpc_post(
    session: aiohttp.ClientSession,
    url: str,
    payload: dict[str, Any],
    *,
    retries: int = _MAX_PROBE_RETRIES,
    backoff: float = _RETRY_BACKOFF,
) -> dict[str, Any]:
    """POST a JSON-RPC call, retrying only transient backend saturation (5xx / refused connection).

    Backing off happens while holding the caller's concurrency slot, so a saturated scan
    self-throttles instead of hammering. Timeouts are not retried (genuinely slow methods); the
    per-request cap is set high enough for the slow-but-finite ones, and the rest stay UNREACHABLE.
    """
    for attempt in range(retries + 1):
        try:
            async with session.post(
                url, json=payload, timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT)
            ) as resp:
                if resp.status >= 500:
                    raise ConnectionError(f"backend HTTP {resp.status}")
                data: dict[str, Any] = await resp.json(content_type=None)
                return data
        except (aiohttp.ClientError, ConnectionError):
            if attempt >= retries:
                raise
            await asyncio.sleep(backoff * 2**attempt)
    raise ConnectionError("probe retries exhausted")  # unreachable: loop returns or raises


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
    """Run the enumeration and return the raw report dict (performs I/O).

    Read-only by default; ``dangerous`` calls write endpoints and ``include_destructive``
    calls destructive ones (see ``capture``).
    """
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
            # _rpc_post applies a 20s per-request cap and retries transient worker-shortage failures
            # (5xx / refused). A genuinely slow method that exceeds the cap propagates and the
            # enumerator's _probe records it UNREACHABLE.
            data = await _rpc_post(session, rpc_url, payload)
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
        # Auto-tune concurrency to the router's RPC backend: stay one under its fcgiwrap
        # worker count so a busy scan can't starve the router's own UI. Falls back to the
        # built-in default when SSH didn't run or the worker count couldn't be read.
        concurrency: int | None = None
        if surface is not None and surface.rpc_workers:
            concurrency = max(1, min(16, surface.rpc_workers - 1))
            await on_progress(
                {
                    "event": "progress",
                    "phase": "probe",
                    "message": f"RPC backend has {surface.rpc_workers} workers — "
                    f"probing at concurrency {concurrency}.",
                }
            )
        report = await enumerate_device(
            caller,
            device_info=device_info,
            ssh_surface=surface,
            probe_writes=dangerous,
            include_destructive=include_destructive,
            concurrency=concurrency,
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
