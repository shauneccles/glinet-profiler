"""Sanitizing projection: a raw enumerator report -> publishable profile.

Drops device identifiers (mac/sn/sn_bak) and every method response value;
keeps model+firmware plus the per-method API shape (status/risk/coverage/params/schema).
The schema is kept intact: its keys are type-erased API field-names (documentation),
not device values.

Also keeps a small ``capabilities`` block from ``system get_info`` — the regulatory
``country_code`` and the ``software_feature``/``hardware_feature`` capability maps. These are
non-identifying (booleans + hardware descriptors, no mac/sn) and explain *why* a method works
or errors on a given variant (e.g. no modem hardware -> the modem.* methods error).
"""

from typing import Any

_DEVICE_FIELDS = ("model", "firmware_version", "vendor", "device_type", "hardware_version")
# Allowlist of non-identifying capability fields lifted from system.get_info. Strict allowlist:
# mac/sn/sn_bak and everything else in get_info are dropped.
_CAPABILITY_FIELDS = ("country_code", "software_feature", "hardware_feature")
_METHOD_FIELDS = ("status", "error_code", "risk", "discovered_by", "covered_by", "params", "schema")


def project_report(
    raw: dict[str, Any], device_id_str: str, *, keep_data: bool = False
) -> dict[str, Any]:
    """Project a raw enumerator report to the sanitized, publishable profile.

    ``keep_data`` additionally keeps each method's response ``value`` (already secret-redacted by
    the enumerator: password/key/serial/token/... scrubbed). This is for LOCAL signature analysis
    only — the result is *not* a publishable profile (it carries response data, so the registry's
    validator rejects it).
    """
    device = raw.get("device", {})
    out: dict[str, Any] = {"id": device_id_str}
    for field in _DEVICE_FIELDS:
        if field in device:
            out[field] = device[field]
    capabilities = {field: device[field] for field in _CAPABILITY_FIELDS if field in device}
    if capabilities:
        out["capabilities"] = capabilities
    method_fields = (*_METHOD_FIELDS, "value") if keep_data else _METHOD_FIELDS
    out["services"] = {
        service: {
            method: {field: rec.get(field) for field in method_fields}
            for method, rec in methods.items()
        }
        for service, methods in raw.get("services", {}).items()
    }
    return out
