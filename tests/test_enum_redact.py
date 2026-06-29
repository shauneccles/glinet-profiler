"""Unit tests for redaction and schema capture."""
# pylint: disable=missing-function-docstring,redefined-outer-name

from glinet_profiler.enumerator.redact import redact, schema_of


def test_redacts_secret_keys():
    src = {"ssid": "Home", "key": "s3cret", "private_key": "abc", "wan_password": "p"}
    out = redact(src)
    assert out["ssid"] == "Home"
    assert out["key"] == "<redacted>"
    assert out["private_key"] == "<redacted>"
    assert out["wan_password"] == "<redacted>"  # boundary match on _password


def test_short_ambiguous_token_is_exact_match_only():
    # "ca" is a denylist token but must NOT redact "cache" / "location"
    out = redact({"ca": "CERTDATA", "cache": "ok", "location": "lounge"})
    assert out["ca"] == "<redacted>"
    assert out["cache"] == "ok"
    assert out["location"] == "lounge"


def test_redacts_mac_addresses_anywhere():
    # MAC is a device identifier (incl. client MACs from clients.get_list) — scrub it
    assert redact("94:83:C4:AA:BB:CC") == "<redacted>"
    assert redact({"lan_mac": "94:83:C4:AA:BB:CC"}) == {"lan_mac": "<redacted>"}
    assert redact("client 94-83-C4-AA-BB-CC joined") == "client <redacted> joined"
    assert redact("just text") == "just text"


def test_long_opaque_string_redacted_regardless_of_key():
    blob = "A1b2" * 20  # 80 chars, base64-ish
    out = redact({"blob": blob, "note": "short text is fine"})
    assert out["blob"] == "<redacted>"
    assert out["note"] == "short text is fine"


def test_nested_and_lists():
    out = redact({"peers": [{"name": "p", "preshared_key": "x"}]})
    assert out["peers"][0]["name"] == "p"
    assert out["peers"][0]["preshared_key"] == "<redacted>"


def test_disabled_passthrough():
    src = {"key": "s3cret"}
    assert redact(src, enabled=False) == {"key": "s3cret"}
    assert redact(src, enabled=False) is not src  # still a copy


def test_does_not_mutate_input():
    src = {"key": "s3cret"}
    redact(src)
    assert src["key"] == "s3cret"


def test_schema_of_types_only_no_values():
    s = schema_of({"a": 1, "b": "x", "c": [{"d": True}], "e": None})
    assert s == {"a": "int", "b": "str", "c": [{"d": "bool"}], "e": "NoneType"}


def test_schema_depth_limit():
    assert schema_of({"a": {"b": {"c": 1}}}, depth=1) == {"a": "dict"}
