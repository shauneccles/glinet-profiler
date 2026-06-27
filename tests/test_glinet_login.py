"""Tests for the local GL.iNet challenge-response login."""
# pylint: disable=missing-function-docstring,redefined-outer-name,unused-argument

import pytest

from glinet_profiler.glinet_login import compute_hash, login


def test_compute_hash_deterministic_md5():
    a = compute_hash(1, "abcdefgh", "n0nce", "md5", "root", "pw")
    b = compute_hash(1, "abcdefgh", "n0nce", "md5", "root", "pw")
    assert a == b
    assert len(a) == 32 and all(c in "0123456789abcdef" for c in a)


def test_compute_hash_sha_sizes():
    assert len(compute_hash(5, "abcdefgh", "n", "sha256", "root", "pw")) == 64
    assert len(compute_hash(6, "abcdefgh", "n", "sha512", "root", "pw")) == 128


def test_compute_hash_rejects_unsupported():
    with pytest.raises(ValueError):
        compute_hash(9, "s", "n", "md5", "u", "p")
    with pytest.raises(ValueError):
        compute_hash(1, "s", "n", "bogus", "u", "p")


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def json(self, content_type=None):  # noqa: ARG002
        return self._payload


class _FakeSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.posted = []

    def post(self, url, json=None):  # noqa: A002, ARG002
        self.posted.append(json)
        return _FakeResp(self._responses.pop(0))


async def test_login_returns_sid_and_posts_challenge_then_login():
    session = _FakeSession([
        {"result": {"alg": 1, "salt": "abcdefgh", "nonce": "n0nce", "hash-method": "md5"}},
        {"result": {"sid": "SID-123"}},
    ])
    sid = await login(session, "http://x/rpc", "root", "pw")
    assert sid == "SID-123"
    assert session.posted[0]["method"] == "challenge"
    assert session.posted[1]["method"] == "login"
    assert "hash" in session.posted[1]["params"]


async def test_login_raises_without_sid():
    session = _FakeSession([
        {"result": {"alg": 1, "salt": "abcdefgh", "nonce": "n", "hash-method": "md5"}},
        {"result": {}},
    ])
    with pytest.raises(ValueError):
        await login(session, "http://x/rpc", "root", "pw")
