"""Render a DeviceReport to JSON, Markdown, and terminal summary."""

import json
from typing import Any

from .models import DeviceReport, MethodReport, ProbeStatus
from .probe import device_id

_PRESENT = (ProbeStatus.AVAILABLE, ProbeStatus.NEEDS_PARAMS)


def _method_dict(m: MethodReport) -> dict[str, Any]:
    return {
        "status": str(m.status),
        "error_code": m.error_code,
        "risk": str(m.risk),
        "discovered_by": m.discovered_by,
        "params": m.params,
        "schema": m.schema,
        "value": m.value,
        "covered_by": m.covered_by,
    }


def _services_map(report: DeviceReport) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for m in report.methods:
        out.setdefault(m.service, {})[m.method] = _method_dict(m)
    return out


def _not_wrapped(report: DeviceReport) -> list[MethodReport]:
    return [m for m in report.methods if m.status in _PRESENT and m.covered_by is None]


def to_json(report: DeviceReport) -> str:
    """Machine-readable per-device report."""
    return json.dumps(
        {"device": report.device, "services": _services_map(report)},
        indent=2,
        sort_keys=True,
    )


def to_markdown(report: DeviceReport) -> str:
    """Human-readable per-device API exposure document."""
    dev = report.device
    lines = [
        f"# API exposure: {dev.get('model', 'unknown')} ({dev.get('firmware_version', 'unknown')})",
        "",
        "> Values are redacted by default; review before committing.",
        "",
        "## Services",
        "",
        "| Service | Method | Status | Risk | Wrapped by gli4py |",
        "|---|---|---|---|---|",
    ]
    for m in sorted(report.methods, key=lambda x: (x.service, x.method)):
        if m.status in _PRESENT:
            lines.append(
                f"| {m.service} | {m.method} | {m.status} | {m.risk} | {m.covered_by or '—'} |"
            )
    lines += ["", "## Available but not yet wrapped by gli4py", ""]
    nw = _not_wrapped(report)
    lines += [
        f"- `{m.service}.{m.method}`" for m in sorted(nw, key=lambda x: (x.service, x.method))
    ] or ["- (none)"]
    return "\n".join(lines) + "\n"


def summary_lines(report: DeviceReport) -> list[str]:
    """Terminal summary: counts + the not-yet-wrapped worklist."""
    counts: dict[str, int] = {}
    for m in report.methods:
        counts[str(m.status)] = counts.get(str(m.status), 0) + 1
    nw = _not_wrapped(report)
    lines = [
        f"Device: {report.device.get('model', 'unknown')} ({report.device.get('firmware_version', 'unknown')}) "
        f"[id: {device_id(report.device)}]",
        "Counts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
        f"Not yet wrapped by gli4py ({len(nw)}):",
    ]
    lines += [
        f"  - {m.service}.{m.method}" for m in sorted(nw, key=lambda x: (x.service, x.method))
    ]
    return lines
