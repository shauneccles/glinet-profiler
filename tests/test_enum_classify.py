"""Unit tests for the enumerator probe classifier."""
# pylint: disable=missing-function-docstring,redefined-outer-name

from glinet_profiler.enumerator.classify import classify
from glinet_profiler.enumerator.models import ProbeStatus


def test_result_is_available():
    r = classify({"id": 0, "jsonrpc": "2.0", "result": {"k": 1}})
    assert r.status is ProbeStatus.AVAILABLE
    assert r.error_code is None


def test_method_not_found_is_absent():
    r = classify({"error": {"code": -32601, "message": "Method not found"}})
    assert r.status is ProbeStatus.ABSENT
    assert r.error_code == -32601


def test_invalid_params_is_needs_params():
    r = classify({"error": {"code": -32602, "message": "Invalid params"}})
    assert r.status is ProbeStatus.NEEDS_PARAMS


def test_auth_and_token_errors():
    assert classify({"error": {"code": -32000}}).status is ProbeStatus.AUTH_ERROR
    assert classify({"error": {"code": -1}}).status is ProbeStatus.TOKEN_ERROR


def test_other_error_keeps_code_and_message():
    r = classify({"error": {"code": -12345, "message": "weird"}})
    assert r.status is ProbeStatus.OTHER
    assert r.error_code == -12345
    assert r.message == "weird"


def test_result_present_takes_precedence_over_empty_error_key():
    assert classify({"result": []}).status is ProbeStatus.AVAILABLE
