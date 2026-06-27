"""Server-side capture: enumerate a device read-only and return a sanitized profile."""

import json
from typing import Any

from .enumerator.probe import device_id
from .sanitize import project_report


async def _enumerate(  # pylint: disable=too-many-locals
    host: str, username: str, password: str, *, ssh: bool
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

    base = host.rstrip("/")
    rpc_url = f"{base}/rpc"
    host_only = base.replace("https://", "").replace("http://", "").split("/")[0]

    surface = None
    if ssh:
        try:
            surface = await ssh_discover(host_only, username="root", password=password)
        except SshUnavailable:
            surface = None

    async with aiohttp.ClientSession() as session:
        sid = await login(session, rpc_url, username, password)

        async def caller(service: str, method: str, args: dict[str, Any] | None) -> dict[str, Any]:
            params: list[Any] = [sid, service, method]
            if args is not None:
                params.append(args)
            payload = {"jsonrpc": "2.0", "id": 0, "method": "call", "params": params}
            async with session.post(rpc_url, json=payload) as resp:
                data: dict[str, Any] = await resp.json(content_type=None)
                return data

        info_env = await caller("system", "get_info", None)
        info = info_env.get("result")
        device_info = info if isinstance(info, dict) else {}
        report = await enumerate_device(caller, device_info=device_info, ssh_surface=surface)
        raw: dict[str, Any] = json.loads(to_json(report))
        return raw


async def capture(host: str, username: str, password: str, *, ssh: bool = True) -> dict[str, Any]:
    """Enumerate (read-only; SSH attempted by default) and return the sanitized profile."""
    raw = await _enumerate(host, username, password, ssh=ssh)
    return project_report(raw, device_id(raw.get("device", {})))
