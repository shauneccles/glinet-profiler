"""Secret redaction and schema capture for probed values."""

import re

REDACTED = "<redacted>"

# Case-insensitive tokens whose value is a secret. Short/ambiguous tokens match
# only as a whole key or on a `_`-boundary; never as a bare substring.
_SECRET_TOKENS = (
    "password",
    "passwd",
    "pwd",
    "key",
    "psk",
    "secret",
    "private_key",
    "privatekey",
    "token",
    "sid",
    "hash",
    "nonce",
    "salt",
    "device_id",
    "serial",
    "sn",
    "ca",
    "cert",
    "dh",
    "ta",
    "pem",
    "csr",
)
_OPAQUE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_MAC_VALUE = re.compile(
    r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
)  # device identifier; scrub anywhere


def _key_is_secret(key: str) -> bool:
    low = key.lower()
    for tok in _SECRET_TOKENS:
        if low == tok or low.endswith("_" + tok) or low.startswith(tok + "_"):
            return True
    return False


def _redact_str(value: str, key: str | None) -> str:
    if key is not None and _key_is_secret(key):
        return REDACTED
    if len(value) >= 64 and _OPAQUE.match(value):
        return REDACTED
    return _MAC_VALUE.sub(REDACTED, value)  # scrub MAC addresses (incl. client MACs) anywhere


def redact(value: object, *, enabled: bool = True, _key: str | None = None) -> object:
    """Deep-copy ``value``, replacing secret-looking string values with ``<redacted>``."""
    if isinstance(value, dict):
        return {k: redact(v, enabled=enabled, _key=k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, enabled=enabled) for v in value]
    if enabled and isinstance(value, str):
        return _redact_str(value, _key)
    return value


def schema_of(value: object, depth: int = 4) -> object:
    """Return a type-name shape mirror of ``value`` (never raw values)."""
    if isinstance(value, dict):
        if depth <= 0:
            return "dict"
        return {k: schema_of(v, depth - 1) for k, v in value.items()}
    if isinstance(value, list):
        if depth <= 0 or not value:
            return "list"
        return [schema_of(value[0], depth - 1)]
    return type(value).__name__
