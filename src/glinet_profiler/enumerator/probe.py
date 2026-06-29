"""Async enumeration engine: probe a device through an injectable caller."""

import asyncio
import re
from collections.abc import Awaitable
from typing import Any

from .catalog import CATALOG, COMMON_READ_METHODS, DESTRUCTIVE_METHODS, is_read_method, risk_of
from .classify import classify
from .coverage import covered_by
from .models import Caller, DeviceReport, MethodReport, ProbeStatus, Risk, SshSurface
from .redact import redact, schema_of
from .wordlist import (
    ACTIVE_READ_SEEDS,
    MUTATING_METHOD_SEEDS,
    READ_METHOD_SEEDS,
    SERVICE_SEEDS,
)

_SLUG = re.compile(r"[^a-z0-9.]+")
_CONCURRENCY = (
    3  # GL.iNet's RPC backend is fcgiwrap with only 4 CGI workers on my MT6000; stay under that
)
# so a few slow/hung methods can't starve the router's own UI (nginx fastcgi_read_timeout is 300s,
# so a hung glc keeps a worker busy long after our client times out).


def device_id(device: dict[str, Any]) -> str:
    """Slug `model_firmware` from a get_info dict, with fallbacks."""
    model = (
        device.get("model") or device.get("device_type") or device.get("board_info") or "unknown"
    )
    firmware = device.get("firmware_version") or "unknown"
    model_slug = _SLUG.sub("-", model.lower()).strip("-")
    firmware_slug = _SLUG.sub("-", firmware.lower()).strip("-")
    return f"{model_slug}_{firmware_slug}"


async def _probe(
    caller: Caller, service: str, method: str
) -> tuple[ProbeStatus, int | None, object]:
    # Probe with an empty params object, not None. Many GL.iNet handlers index `params.x`
    # directly; with no params table they crash ("attempt to index a nil value"), returning
    # non-JSON (-> UNREACHABLE) and leaving a Lua stack trace in the router's log. An empty
    # table indexes cleanly, so the method returns its real result or a clean error instead.
    try:
        envelope = await caller(service, method, {})
    except Exception:  # pylint: disable=broad-except
        return ProbeStatus.UNREACHABLE, None, None
    result = classify(envelope)
    value = envelope.get("result") if result.status is ProbeStatus.AVAILABLE else None
    return result.status, result.error_code, value


def brute_plan(
    *, dangerous: bool, dangerous_full: bool, include_destructive: bool
) -> list[tuple[str, str]]:
    """The (service, method) pairs the brute pass will try."""
    if not dangerous:
        return []
    methods: list[str] = list(READ_METHOD_SEEDS)
    if dangerous_full:
        methods += list(ACTIVE_READ_SEEDS) + list(MUTATING_METHOD_SEEDS)
    methods = [m for m in methods if include_destructive or m not in DESTRUCTIVE_METHODS]
    seen: set[tuple[str, str]] = set()
    plan: list[tuple[str, str]] = []
    for service in SERVICE_SEEDS:
        for method in methods:
            if (service, method) not in seen:
                seen.add((service, method))
                plan.append((service, method))
    return plan


def _catalog_targets() -> list[tuple[str, str, Risk]]:
    targets: list[tuple[str, str, Risk]] = []
    seen: set[tuple[str, str]] = set()
    for service, methods in CATALOG.items():
        for method, risk in methods.items():
            if risk is Risk.READ and (service, method) not in seen:
                targets.append((service, method, risk))
                seen.add((service, method))
        for method in COMMON_READ_METHODS:
            if (service, method) not in seen:
                targets.append((service, method, Risk.READ))
                seen.add((service, method))
    return targets


async def enumerate_device(  # pylint: disable=too-many-arguments,too-many-locals
    caller: Caller,
    *,
    redact_values: bool = True,
    device_info: dict[str, Any] | None = None,
    brute: str = "off",
    include_destructive: bool = False,
    probe_writes: bool = False,
    concurrency: int | None = None,
    ssh_surface: SshSurface | None = None,
) -> DeviceReport:
    """Probe the read-only catalog surface and assemble a DeviceReport.

    SSH-discovered methods are, by default, recorded as ``DISCOVERED`` without an HTTP call.
    ``probe_writes`` additionally calls WRITE-risk methods (changes config — spare routers);
    ``probe_writes`` + ``include_destructive`` also calls DESTRUCTIVE methods (reboot/reset/
    upgrade), deferred to the very end so they don't abort the rest of the scan.
    ``concurrency`` bounds in-flight probes (default ``_CONCURRENCY``); the caller can pass a
    value derived from the device's fcgiwrap worker count.
    """
    if brute not in {"off", "dangerous", "dangerous_full"}:
        raise ValueError(f"brute must be 'off', 'dangerous', or 'dangerous_full'; got {brute!r}")

    sem = asyncio.Semaphore(concurrency or _CONCURRENCY)

    async def _report(
        service: str,
        method: str,
        mrisk: Risk,
        discovered_by: str,
        params: list[str] | None = None,
    ) -> MethodReport:
        """Probe one (service, method) under the concurrency limit and build its report."""
        async with sem:
            status, code, value = await _probe(caller, service, method)
        return MethodReport(
            service=service,
            method=method,
            status=status,
            error_code=code,
            risk=mrisk,
            discovered_by=discovered_by,
            params=params,
            schema=schema_of(value) if value is not None else None,
            value=redact(value, enabled=redact_values) if value is not None else None,
            covered_by=covered_by(service, method),
        )

    def _discovered(
        service: str, method: str, mrisk: Risk, params: list[str] | None
    ) -> MethodReport:
        """Record an SSH-discovered method without any HTTP call (from the device's files)."""
        return MethodReport(
            service=service,
            method=method,
            status=ProbeStatus.DISCOVERED,
            error_code=None,
            risk=mrisk,
            discovered_by="ssh",
            params=params,
            schema=None,
            value=None,
            covered_by=covered_by(service, method),
        )

    if device_info is None:
        status, _code, value = await _probe(caller, "system", "get_info")
        device_info = value if status is ProbeStatus.AVAILABLE and isinstance(value, dict) else {}

    # catalog pass — concurrent; asyncio.gather preserves input order
    targets = _catalog_targets()
    for service, method, _risk in targets:
        assert is_read_method(method), f"refusing non-read method {service}.{method}"
    methods: list[MethodReport] = list(
        await asyncio.gather(*[_report(s, m, r, "catalog") for s, m, r in targets])
    )

    probed = {(m.service, m.method) for m in methods}
    if brute != "off":
        # NOTE: brute is never enabled from capture()/CLI/web. If it is ever wired up with
        # include_destructive, destructive seeds here are probed concurrently (not deferred-
        # last like the SSH path) — add the same deferral before exposing it.
        plan = brute_plan(
            dangerous=True,
            dangerous_full=(brute == "dangerous_full"),
            include_destructive=include_destructive,
        )
        todo = [(s, m) for s, m in plan if (s, m) not in probed]
        for rec in await asyncio.gather(*[_report(s, m, risk_of(m), "brute") for s, m in todo]):
            if rec.status is not ProbeStatus.ABSENT:  # only record hits
                methods.append(rec)

    probed = {(m.service, m.method) for m in methods}
    if ssh_surface is not None:
        # destructive probes (reboot/reset/upgrade) run LAST so one that kills the
        # SSH/HTTP session doesn't throw away the rest of the scan. NOTE: the WRITE-vs-
        # DANGEROUS split below is only as good as catalog.DESTRUCTIVE_METHODS — a
        # destructive method missing from that set is treated as a WRITE and, under
        # --dangerous, called concurrently rather than deferred. Keep that set current.
        tasks: list[Awaitable[MethodReport]] = []
        deferred: list[tuple[str, str, list[str] | None]] = []
        for service, smethods in ssh_surface.methods.items():
            params_map = ssh_surface.params.get(service, {})
            for method in smethods:
                if (service, method) in probed:
                    continue
                probed.add((service, method))
                mrisk = risk_of(method)
                params = params_map.get(method)
                if is_read_method(method) or (probe_writes and mrisk is Risk.WRITE):
                    tasks.append(_report(service, method, mrisk, "ssh", params))
                elif probe_writes and include_destructive and mrisk is Risk.DANGEROUS:
                    deferred.append((service, method, params))
                else:
                    methods.append(_discovered(service, method, mrisk, params))
        methods.extend(await asyncio.gather(*tasks))
        for service, method, params in deferred:
            methods.append(await _report(service, method, Risk.DANGEROUS, "ssh", params))
        device_info = {
            **(device_info or {}),
            "accounts": ssh_surface.accounts,
            "features": ssh_surface.features,
        }
    return DeviceReport(device=device_info or {}, methods=methods)
