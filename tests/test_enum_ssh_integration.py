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
