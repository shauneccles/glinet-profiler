"""enumerate_device merges an injected SshSurface (no paramiko needed)."""
# pylint: disable=missing-function-docstring,redefined-outer-name,unused-argument

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
