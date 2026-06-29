"""Tests for the sanitizing projection."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import json
import re

from glinet_profiler.sanitize import project_report

RAW = {
    "device": {
        "model": "mt6000",
        "firmware_version": "4.9.0",
        "vendor": "GL.iNet",
        "device_type": "router",
        "hardware_version": "1.0",
        "mac": "94:83:C4:AA:BB:CC",
        "sn": "SECRET123",
        "sn_bak": "SECRET456",
        "country_code": "US",
        "software_feature": {"adguard": True, "vpn": True, "cellular_ref": "1.0"},
        "hardware_feature": {"usb3": "2-1", "simo": False},
    },
    "services": {
        "system": {
            "get_info": {
                "status": "available",
                "error_code": None,
                "risk": "read",
                "discovered_by": "catalog",
                "covered_by": "router_info",
                "params": None,
                "schema": {"model": "str", "mac": "str"},
                "value": {"mac": "94:83:C4:AA:BB:CC", "sn": "SECRET123"},
            },
        },
    },
}


def test_keeps_allowlist_and_method_fields():
    out = project_report(RAW, "mt6000_4.9.0")
    assert out["id"] == "mt6000_4.9.0"
    assert out["model"] == "mt6000" and out["firmware_version"] == "4.9.0"
    assert out["vendor"] == "GL.iNet"
    m = out["services"]["system"]["get_info"]
    assert m["status"] == "available" and m["covered_by"] == "router_info"
    # schema is kept intact (type-erased field-names, incl. "mac", are API docs)
    assert m["schema"] == {"model": "str", "mac": "str"}


def test_keeps_non_identifying_capabilities():
    out = project_report(RAW, "mt6000_4.9.0")
    caps = out["capabilities"]
    assert caps["country_code"] == "US"
    assert caps["software_feature"]["vpn"] is True
    assert caps["hardware_feature"]["simo"] is False  # explains why modem.* would error


def test_keep_data_keeps_method_value():
    kept = project_report(RAW, "mt6000_4.9.0", keep_data=True)
    dropped = project_report(RAW, "mt6000_4.9.0")
    assert "value" not in dropped["services"]["system"]["get_info"]  # default still drops it
    # keep_data is a pure projection toggle: it keeps whatever value the enumerator already redacted
    raw_value = RAW["services"]["system"]["get_info"]["value"]
    assert kept["services"]["system"]["get_info"]["value"] == raw_value


def test_drops_identifiers_and_values():
    out = project_report(RAW, "mt6000_4.9.0")
    for k in ("mac", "sn", "sn_bak"):  # identifiers dropped from the top level
        assert k not in out
    assert "capabilities" in out  # ...but the non-identifying capability block is kept
    # method-level response value is dropped
    assert "value" not in out["services"]["system"]["get_info"]
    # no actual identifier VALUE survives (the real MAC / serials)
    blob = json.dumps(out)
    assert "SECRET123" not in blob and "SECRET456" not in blob
    assert not re.search(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", blob)
