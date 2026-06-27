"""Self-contained GL.iNet challenge-response login (no gli4py/uplink)."""

import asyncio
import hashlib
from typing import Any

import aiohttp
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt


def compute_hash(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    alg: int, salt: str, nonce: str, hash_method: str, username: str, password: str
) -> str:
    """Compute the GL.iNet login hash for a challenge (CPU-bound)."""
    if alg == 1:
        cipher_password = md5_crypt.using(salt=salt).hash(password)
    elif alg == 5:
        cipher_password = sha256_crypt.using(salt=salt, rounds=5000).hash(password)
    elif alg == 6:
        cipher_password = sha512_crypt.using(salt=salt, rounds=5000).hash(password)
    else:
        raise ValueError(f"unsupported cipher algorithm: {alg}")
    data = f"{username}:{cipher_password}:{nonce}"
    if hash_method == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    if hash_method == "sha256":
        return hashlib.sha256(data.encode()).hexdigest()
    if hash_method == "sha512":
        return hashlib.sha512(data.encode()).hexdigest()
    raise ValueError(f"unsupported hash method: {hash_method}")


def _no_auth_payload(method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 0, "method": method, "params": params}


async def login(session: aiohttp.ClientSession, rpc_url: str, username: str, password: str) -> str:
    """Run the challenge-response login over `session`; return the session id (sid)."""
    async with session.post(
        rpc_url, json=_no_auth_payload("challenge", {"username": username})
    ) as resp:
        challenge: dict[str, Any] = (await resp.json(content_type=None)).get("result", {})
    hsh = await asyncio.to_thread(
        compute_hash,
        challenge["alg"],
        challenge["salt"],
        challenge["nonce"],
        challenge.get("hash-method", "md5"),
        username,
        password,
    )
    async with session.post(
        rpc_url, json=_no_auth_payload("login", {"username": username, "hash": hsh})
    ) as resp:
        result: dict[str, Any] = (await resp.json(content_type=None)).get("result", {})
    sid = result.get("sid")
    if not sid:
        raise ValueError("login failed: router did not return a session id")
    return str(sid)
