"""Classify a JSON-RPC envelope into a ProbeResult."""

from typing import Any

from .models import ProbeResult, ProbeStatus

_CODE_STATUS = {
    -32601: ProbeStatus.ABSENT,
    -32602: ProbeStatus.NEEDS_PARAMS,
    -32000: ProbeStatus.AUTH_ERROR,
    -1: ProbeStatus.TOKEN_ERROR,
}


def classify(envelope: dict[str, Any]) -> ProbeResult:
    """Map a JSON-RPC response envelope to a ProbeResult."""
    if "result" in envelope:
        return ProbeResult(ProbeStatus.AVAILABLE)
    error = envelope.get("error")
    if not isinstance(error, dict):
        return ProbeResult(ProbeStatus.OTHER, message="malformed envelope")
    code = error.get("code")
    message = error.get("message")
    code_int = code if isinstance(code, int) else None
    status = (
        _CODE_STATUS.get(code_int, ProbeStatus.OTHER) if code_int is not None else ProbeStatus.OTHER
    )
    return ProbeResult(status, error_code=code_int, message=message)
