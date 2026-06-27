"""Brute-force planning + a fake-caller brute run."""
# pylint: disable=missing-function-docstring,redefined-outer-name,unused-argument

import pytest

from glinet_profiler.enumerator.catalog import DESTRUCTIVE_METHODS, is_read_method
from glinet_profiler.enumerator.models import ProbeStatus
from glinet_profiler.enumerator.probe import brute_plan, enumerate_device


def test_dangerous_plan_is_read_only():
    plan = brute_plan(dangerous=True, dangerous_full=False, include_destructive=False)
    assert plan
    assert all(is_read_method(method) for _, method in plan)


def test_full_plan_includes_mutating_but_not_destructive():
    plan = brute_plan(dangerous=True, dangerous_full=True, include_destructive=False)
    methods = {m for _, m in plan}
    assert any(not is_read_method(m) for m in methods)  # has mutating
    assert methods.isdisjoint(DESTRUCTIVE_METHODS)  # no destructive


def test_include_destructive_adds_destructive():
    plan = brute_plan(dangerous=True, dangerous_full=True, include_destructive=True)
    methods = {m for _, m in plan}
    assert methods & DESTRUCTIVE_METHODS


async def test_brute_surfaces_non_catalog_service():
    responses = {
        ("system", "get_info"): {"result": {"model": "x", "firmware_version": "1"}},
        ("astrowarp", "get_status"): {"result": {"on": True}},
    }

    async def caller(service, method, args):  # noqa: ARG001
        return responses.get((service, method), {"error": {"code": -32601}})

    report = await enumerate_device(
        caller,
        device_info={"model": "x", "firmware_version": "1"},
        brute="dangerous",
    )
    hit = next((m for m in report.methods if m.service == "astrowarp"), None)
    assert hit is not None
    assert hit.discovered_by == "brute"
    assert hit.status is ProbeStatus.AVAILABLE


async def test_invalid_brute_value_raises():
    async def caller(service, method, args):  # noqa: ARG001
        return {"result": {}}

    with pytest.raises(ValueError):
        await enumerate_device(
            caller, device_info={"model": "x", "firmware_version": "1"}, brute="typo"
        )
