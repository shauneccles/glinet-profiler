"""Tests for submission validation + ingest."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import json

import pytest

from glinet_profiler.ingest import ingest, validate_profile

CLEAN = {
    "id": "ignored", "model": "mt6000", "firmware_version": "4.9.0",
    "services": {"system": {"get_info": {"status": "available", "covered_by": "router_info"}}},
}


def test_validate_accepts_clean():
    assert validate_profile(CLEAN) is None


def test_validate_missing_key():
    assert "missing required key" in validate_profile({"model": "x", "services": {}})


def test_validate_rejects_identifier():
    assert "identifier" in validate_profile({**CLEAN, "mac": "94:83:C4:AA:BB:CC"})


def test_validate_rejects_method_value():
    bad = {**CLEAN, "services": {"s": {"m": {"status": "available", "value": {"x": 1}}}}}
    assert "response value" in validate_profile(bad)


def test_validate_rejects_mac_hex():
    bad = {**CLEAN, "services": {"s": {"m": {"status": "available", "schema": {"a": "94:83:C4:AA:BB:CC"}}}}}
    assert "MAC" in validate_profile(bad)


def test_ingest_writes_and_normalizes_id(tmp_path):
    sub = tmp_path / "submission.json"
    sub.write_text(json.dumps(CLEAN), encoding="utf-8")
    new_id = ingest(sub, tmp_path)
    assert new_id == "mt6000_4.9.0"  # recomputed from model+firmware, not the submitted "ignored"
    written = json.loads((tmp_path / "devices" / "mt6000_4.9.0.json").read_text(encoding="utf-8"))
    assert written["id"] == "mt6000_4.9.0"
    manifest = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert manifest["devices"][0]["id"] == "mt6000_4.9.0"


def test_ingest_raises_on_invalid(tmp_path):
    sub = tmp_path / "submission.json"
    sub.write_text(json.dumps({**CLEAN, "sn": "SECRET"}), encoding="utf-8")
    with pytest.raises(ValueError):
        ingest(sub, tmp_path)
