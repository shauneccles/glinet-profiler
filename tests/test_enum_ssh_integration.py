"""enumerate_device merges an injected SshSurface (no paramiko needed)."""
# pylint: disable=missing-function-docstring,redefined-outer-name,unused-argument

import asyncio

from glinet_profiler.enumerator.models import ProbeStatus, SshSurface
from glinet_profiler.enumerator.probe import enumerate_device


async def test_ssh_surface_adds_confirmed_methods_with_params():
    responses = {
        ("system", "get_info"): {"result": {"model": "x", "firmware_version": "1"}},
        ("network_acl", "get_acl_rules"): {"result": {"rules": []}},
    }

    async def caller(service, method, args):  # noqa: ARG001
        return responses.get((service, method), {"error": {"code": -32601}})

    surface = SshSurface(
        services=["network_acl"],
        methods={"network_acl": ["get_acl_rules"]},
        params={"network_acl": {"get_acl_rules": ["period"]}},
        accounts=[{"username": "root", "acl": "root"}],
        features=["flowstatistics"],
    )
    report = await enumerate_device(
        caller,
        device_info={"model": "x", "firmware_version": "1"},
        ssh_surface=surface,
    )
    hit = next(
        m for m in report.methods if (m.service, m.method) == ("network_acl", "get_acl_rules")
    )
    assert hit.discovered_by == "ssh"
    assert hit.status is ProbeStatus.AVAILABLE
    assert hit.params == ["period"]
    assert report.device["accounts"] == [{"username": "root", "acl": "root"}]
    assert report.device["features"] == ["flowstatistics"]


def _surface() -> SshSurface:
    # get_rules=read, set_rules=write, reboot=destructive(dangerous)
    return SshSurface(services=["acl"], methods={"acl": ["get_rules", "set_rules", "reboot"]})


async def _run(*, probe_writes=False, include_destructive=False):
    called: list[tuple[str, str]] = []

    async def caller(service, method, args):  # noqa: ARG001
        called.append((service, method))
        return {"result": {}}

    report = await enumerate_device(
        caller,
        device_info={"model": "x", "firmware_version": "1"},
        ssh_surface=_surface(),
        probe_writes=probe_writes,
        include_destructive=include_destructive,
    )
    by = {m.method: m for m in report.methods if m.discovered_by == "ssh"}
    return called, by


async def test_ssh_default_discovers_writes_without_calling_them():
    called, by = await _run()
    assert by["get_rules"].status is ProbeStatus.AVAILABLE  # read: probed
    assert by["set_rules"].status is ProbeStatus.DISCOVERED  # write: captured, not called
    assert by["reboot"].status is ProbeStatus.DISCOVERED  # destructive: captured, not called
    assert ("acl", "set_rules") not in called
    assert ("acl", "reboot") not in called


async def test_ssh_dangerous_probes_writes_but_not_destructive():
    called, by = await _run(probe_writes=True)
    assert by["set_rules"].status is ProbeStatus.AVAILABLE  # write: HTTP-called
    assert ("acl", "set_rules") in called
    assert by["reboot"].status is ProbeStatus.DISCOVERED  # destructive: still not called
    assert ("acl", "reboot") not in called


async def test_ssh_include_destructive_probes_reboot_last():
    called, by = await _run(probe_writes=True, include_destructive=True)
    assert by["reboot"].status is ProbeStatus.AVAILABLE  # destructive: HTTP-called
    assert ("acl", "reboot") in called
    assert called[-1] == ("acl", "reboot")  # destructive runs dead last


async def test_probe_sends_empty_args_not_none():
    seen_args = []

    async def caller(service, method, args):  # noqa: ARG001
        seen_args.append(args)
        return {"error": {"code": -32601}}

    await enumerate_device(caller, device_info={"model": "x", "firmware_version": "1"})
    assert seen_args  # the catalog pass probed something
    assert all(a == {} for a in seen_args)  # {} not None — avoids the router's nil-param crashes


async def test_enumerate_respects_concurrency_limit():
    in_flight = 0
    max_seen = 0

    async def caller(service, method, args):  # noqa: ARG001
        nonlocal in_flight, max_seen
        in_flight += 1
        max_seen = max(max_seen, in_flight)
        await asyncio.sleep(0.002)
        in_flight -= 1
        return {"error": {"code": -32601}}  # absent — fast, no value to redact

    await enumerate_device(
        caller, device_info={"model": "x", "firmware_version": "1"}, concurrency=2
    )
    assert max_seen == 2  # the semaphore held in-flight probes to exactly the limit
