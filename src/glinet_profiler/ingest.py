"""Validate + ingest a submitted device profile into the registry."""

import json
import re
from pathlib import Path
from typing import Any

from gli4py.enumerator.probe import device_id

from .registry import rebuild

_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")
_REQUIRED = ("model", "firmware_version", "services")
_IDENTIFIERS = ("mac", "sn", "sn_bak")


def validate_profile(data: Any) -> str | None:  # pylint: disable=too-many-return-statements
    """Return an error message if `data` is not a clean sanitized profile, else None."""
    if not isinstance(data, dict):
        return "submission is not a JSON object"
    for key in _REQUIRED:
        if key not in data:
            return f"missing required key: {key}"
    if not isinstance(data["services"], dict):
        return "'services' must be an object"
    for ident in _IDENTIFIERS:
        if ident in data:
            return f"profile contains a device identifier ({ident}); submit a sanitized profile, not a raw report"
    for service, methods in data["services"].items():
        if not isinstance(methods, dict):
            return f"service '{service}' must be an object"
        for method, rec in methods.items():
            if not isinstance(rec, dict):
                return f"method '{service}.{method}' must be an object"
            if "value" in rec:
                return f"method '{service}.{method}' contains a response value; submit a sanitized profile"
    if _MAC_RE.search(json.dumps(data)):
        return "profile contains a MAC-address-like value; submit a sanitized profile"
    return None


def ingest(submission: Path, data_dir: Path) -> str:
    """Validate `submission`, write devices/<id>.json, rebuild the manifest; return the id."""
    data = json.loads(submission.read_text(encoding="utf-8"))
    error = validate_profile(data)
    if error:
        raise ValueError(error)
    new_id = device_id({"model": data["model"], "firmware_version": data["firmware_version"]})
    if not _ID_RE.fullmatch(new_id):
        raise ValueError(f"could not derive a safe id from model/firmware (got {new_id!r})")
    data["id"] = new_id
    devices_dir = data_dir / "devices"
    devices_dir.mkdir(parents=True, exist_ok=True)
    (devices_dir / f"{new_id}.json").write_text(
        json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
    )
    rebuild(data_dir)
    return new_id
