# Internalize the enumerator; drop gli4py — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the enumerator engine into glinet-profiler, reimplement the GL.iNet login locally, drop the gli4py dependency entirely, and make SSH the default capture mode.

**Architecture:** The self-contained enumerator modules move into `glinet_profiler.enumerator`; a new `glinet_profiler.glinet_login` reimplements the challenge-response auth (libpass + hashlib) so no gli4py/uplink is needed; `capture.py` is rewired to the local engine + login. gli4py's enumerator branch (PR #12) is then closed.

**Tech Stack:** Python 3.11 (stdlib + `aiohttp`, `libpass`, `paramiko`), pytest, ruff, mypy, pylint, zizmor, uv. The gli4py source for the move is on disk at `/home/shaunes/dev/oss/gli4py` (branch `feat/api-enumerator`).

## Global Constraints

- Spec: `docs/specs/2026-06-27-internalize-enumerator-design.md`.
- Repo: **glinet-profiler** (`/home/shaunes/dev/oss/glinet-profiler`). Commands via uv. Gates: ruff, ruff-format, `mypy --strict` (`files=["src"]`), pylint (over `git ls-files '*.py'`), pytest, zizmor (workflows only — unaffected here).
- **Zero gli4py dependency** at the end: `grep -rn "gli4py" src/ tests/ pyproject.toml` returns nothing.
- Net runtime deps: `aiohttp>=3.8.4`, `libpass>=1.8`, `paramiko>=3` (paramiko is **core**, not an extra).
- **SSH default:** `capture(..., ssh=True)`, `server` treats missing `ssh` as True, UI checkbox checked; SSH is attempted and **falls back** to catalog-only on `SshUnavailable`.
- The ported enumerator modules + login + their tests must pass glinet-profiler's ruff + mypy --strict + pylint. The repo's pylint keeps `missing-function-docstring`; new test files start with `# pylint: disable=missing-function-docstring,redefined-outer-name`. mypy override gains `passlib`/`passlib.*`.
- The gli4py-side removal (Task 5) includes a **remote branch deletion** — pause for the user's go-ahead there.

## File Structure

| File | Change |
|---|---|
| `src/glinet_profiler/enumerator/*.py` | Moved from gli4py (no `cli.py`). |
| `src/glinet_profiler/glinet_login.py` | New — `compute_hash` + `login`. |
| `src/glinet_profiler/capture.py` | Rewire to local engine + login; `ssh` default True. |
| `src/glinet_profiler/ingest.py` | `device_id` import → local. |
| `src/glinet_profiler/server.py` | `ssh` defaults True. |
| `src/glinet_profiler/web/index.html` | SSH checkbox `checked`. |
| `pyproject.toml` | Drop gli4py + `[tool.uv.sources]`; add libpass; paramiko core; mypy override. |
| `tests/test_enum_*.py`, `tests/test_glinet_login.py` | Ported enum tests + login test. |

---

### Task 1: Move the enumerator package + port its tests

**Files:**
- Create: `src/glinet_profiler/enumerator/{__init__,probe,report,ssh,models,catalog,classify,coverage,redact,wordlist}.py`
- Modify: `pyproject.toml` (promote `paramiko` to core)
- Test: `tests/test_enum_{brute,catalog,classify,probe,redact,report,ssh_integration,ssh_parse}.py`

**Interfaces:**
- Produces: `glinet_profiler.enumerator.probe.{device_id, enumerate_device}`, `.report.to_json`, `.ssh.{ssh_discover, SshUnavailable}`, `.models.{DeviceReport, ProbeStatus, Risk}`.

- [ ] **Step 1: Copy the modules (excluding cli.py)**

```bash
SRC=/home/shaunes/dev/oss/gli4py/gli4py/enumerator
mkdir -p src/glinet_profiler/enumerator
for m in __init__ probe report ssh models catalog classify coverage redact wordlist; do
  cp "$SRC/$m.py" "src/glinet_profiler/enumerator/$m.py"
done
ls src/glinet_profiler/enumerator/   # 10 files, no cli.py
```
(The modules use only intra-package imports + a lazy `paramiko` import in `ssh.py`; no rewiring needed for the source modules.)

- [ ] **Step 2: Promote paramiko to a core dependency** (`pyproject.toml`)

Change `dependencies` and remove the `ssh` extra:
```toml
dependencies = ["gli4py", "aiohttp>=3.8.4", "paramiko>=3"]
```
Delete the `[project.optional-dependencies]` block (the `ssh = ["paramiko>=3"]` extra). (gli4py stays for now — Task 3 removes it.)

- [ ] **Step 3: Port the enumerator tests (rewire imports)**

```bash
SRCT=/home/shaunes/dev/oss/gli4py/tests
for t in brute catalog classify probe redact report ssh_integration ssh_parse; do
  sed 's/gli4py\.enumerator/glinet_profiler.enumerator/g; s/from gli4py\.enumerator import/from glinet_profiler.enumerator import/g' \
    "$SRCT/test_enum_$t.py" > "tests/test_enum_$t.py"
done
grep -rl "gli4py" tests/test_enum_*.py && echo "STILL HAS gli4py — fix" || echo "imports rewired"
```
(Do NOT port `test_enum_cli.py` — `cli.py` was excluded.)

- [ ] **Step 4: Run the ported enumerator tests**

Run: `uv sync && uv run pytest tests/test_enum_*.py -v`
Expected: all enum tests PASS against `glinet_profiler.enumerator`. (If a test imports a name not in the moved modules, or `paramiko` is missing, fix: confirm Step 2 added paramiko and `uv sync` installed it.)

- [ ] **Step 5: Lint + type + commit**

Run: `uv run ruff check src/glinet_profiler/enumerator tests/test_enum_*.py && uv run ruff format src/glinet_profiler/enumerator tests && uv run mypy src && uv run pylint src/glinet_profiler/enumerator tests/test_enum_*.py`
Expected: ruff clean; mypy clean (the modules shipped py.typed-clean in gli4py); pylint `10.00` (the modules carry their inline pragmas). If pylint flags something the repo config doesn't already disable, add the same scoped disable the gli4py module used.
```bash
git add src/glinet_profiler/enumerator pyproject.toml tests/test_enum_*.py
git commit -m "feat: move the enumerator engine into glinet_profiler (paramiko core)"
```

---

### Task 2: Local login (`glinet_profiler.glinet_login`)

**Files:**
- Create: `src/glinet_profiler/glinet_login.py`
- Modify: `pyproject.toml` (add `libpass`, mypy override)
- Test: `tests/test_glinet_login.py`

**Interfaces:**
- Produces: `compute_hash(alg, salt, nonce, hash_method, username, password) -> str`; `async login(session, rpc_url, username, password) -> str`.

- [ ] **Step 1: Add libpass + mypy override** (`pyproject.toml`)

`dependencies = ["gli4py", "aiohttp>=3.8.4", "paramiko>=3", "libpass>=1.8"]`. In the mypy overrides, set the module list to include passlib:
```toml
[[tool.mypy.overrides]]
module = ["paramiko", "passlib", "passlib.*", "gli4py", "gli4py.*"]
ignore_missing_imports = true
```

- [ ] **Step 2: Write the failing test** `tests/test_glinet_login.py`

```python
"""Tests for the local GL.iNet challenge-response login."""
# pylint: disable=missing-function-docstring,redefined-outer-name

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
```

- [ ] **Step 3: Run to verify failure**

Run: `uv run pytest tests/test_glinet_login.py -v`
Expected: `ModuleNotFoundError: No module named 'glinet_profiler.glinet_login'`.

- [ ] **Step 4: Implement** `src/glinet_profiler/glinet_login.py`

```python
"""Self-contained GL.iNet challenge-response login (no gli4py/uplink)."""

import asyncio
import hashlib
from typing import Any

import aiohttp
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt


def compute_hash(
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


async def login(
    session: aiohttp.ClientSession, rpc_url: str, username: str, password: str
) -> str:
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
```

- [ ] **Step 5: Run to verify pass**

Run: `uv run pytest tests/test_glinet_login.py -v`
Expected: PASS (5 passed).

- [ ] **Step 6: Lint + type + commit**

Run: `uv run ruff check . && uv run mypy src && uv run pylint src/glinet_profiler/glinet_login.py tests/test_glinet_login.py`
Expected: clean / `10.00`.
```bash
git add src/glinet_profiler/glinet_login.py pyproject.toml tests/test_glinet_login.py
git commit -m "feat: local GL.iNet challenge-response login (libpass + hashlib)"
```

---

### Task 3: Rewire capture + ingest; drop gli4py; SSH default

**Files:**
- Modify: `src/glinet_profiler/capture.py`, `src/glinet_profiler/ingest.py`, `src/glinet_profiler/server.py`, `pyproject.toml`
- Test: `tests/test_capture.py`, `tests/test_server.py` (adjust)

**Interfaces:**
- Consumes: `glinet_profiler.enumerator.*` (Task 1), `glinet_profiler.glinet_login.login` (Task 2).

- [ ] **Step 1: Rewrite `src/glinet_profiler/capture.py`**

```python
"""Server-side capture: enumerate a device read-only and return a sanitized profile."""

import json
from typing import Any

from .enumerator.probe import device_id
from .sanitize import project_report


async def _enumerate(  # pylint: disable=too-many-locals
    host: str, username: str, password: str, *, ssh: bool
) -> dict[str, Any]:
    """Run the read-only enumeration and return the raw report dict (performs I/O)."""
    import aiohttp  # pylint: disable=import-outside-toplevel  # noqa: PLC0415  (local so tests can patch _enumerate)

    from .enumerator.probe import enumerate_device  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
    from .enumerator.report import to_json  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
    from .enumerator.ssh import SshUnavailable, ssh_discover  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
    from .glinet_login import login  # pylint: disable=import-outside-toplevel  # noqa: PLC0415

    base = host.rstrip("/")
    rpc_url = f"{base}/rpc"
    host_only = base.replace("https://", "").replace("http://", "").split("/")[0]

    surface = None
    if ssh:
        try:
            surface = await ssh_discover(host_only, username="root", password=password)
        except SshUnavailable:
            surface = None

    async with aiohttp.ClientSession() as session:
        sid = await login(session, rpc_url, username, password)

        async def caller(service: str, method: str, args: dict[str, Any] | None) -> dict[str, Any]:
            params: list[Any] = [sid, service, method]
            if args is not None:
                params.append(args)
            payload = {"jsonrpc": "2.0", "id": 0, "method": "call", "params": params}
            async with session.post(rpc_url, json=payload) as resp:
                data: dict[str, Any] = await resp.json(content_type=None)
                return data

        info_env = await caller("system", "get_info", None)
        info = info_env.get("result")
        device_info = info if isinstance(info, dict) else {}
        report = await enumerate_device(caller, device_info=device_info, ssh_surface=surface)
        raw: dict[str, Any] = json.loads(to_json(report))
        return raw


async def capture(host: str, username: str, password: str, *, ssh: bool = True) -> dict[str, Any]:
    """Enumerate (read-only; SSH attempted by default) and return the sanitized profile."""
    raw = await _enumerate(host, username, password, ssh=ssh)
    return project_report(raw, device_id(raw.get("device", {})))
```

- [ ] **Step 2: Update `ingest.py` import**

In `src/glinet_profiler/ingest.py`, change `from gli4py.enumerator.probe import device_id` to `from glinet_profiler.enumerator.probe import device_id`.

- [ ] **Step 3: SSH default in `server.py`**

In `src/glinet_profiler/server.py`'s `api_enumerate`, change `ssh=bool(body.get("ssh"))` to `ssh=bool(body.get("ssh", True))`.

- [ ] **Step 4: Drop gli4py from `pyproject.toml`**

Set `dependencies = ["aiohttp>=3.8.4", "paramiko>=3", "libpass>=1.8"]` (remove `gli4py`). **Delete the entire `[tool.uv.sources]` block** (the gli4py git pin). In the mypy override, drop `gli4py`/`gli4py.*` (leave `paramiko`, `passlib`, `passlib.*`).

- [ ] **Step 5: Confirm gli4py is gone + suite green**

Run:
```bash
uv sync
grep -rn "gli4py" src/ tests/ pyproject.toml && echo "STILL REFERENCES gli4py" || echo "gli4py fully removed"
uv run pytest -q
```
Expected: `gli4py fully removed`; all tests pass (capture/server tests patch `_enumerate`/`capture`, so they're agnostic to internals; the new default `ssh=True` doesn't affect them). The `test_server` `fake_capture` signature already has `ssh=False` default in its params — confirm it still accepts the call; if it asserts a specific `ssh` value, update to expect `True`.

- [ ] **Step 6: Lint + type + commit**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src && uv run pylint $(git ls-files '*.py')`
Expected: all clean / `10.00`.
```bash
git add src/glinet_profiler/capture.py src/glinet_profiler/ingest.py src/glinet_profiler/server.py pyproject.toml tests/test_capture.py tests/test_server.py uv.lock
git commit -m "feat: rewire capture/ingest to local engine+login; drop gli4py; SSH default"
```

---

### Task 4: SSH checkbox checked by default (UI)

**Files:**
- Modify: `src/glinet_profiler/web/index.html`
- Test: `tests/test_web.py` (if present in this repo) — otherwise structural grep

**Interfaces:**
- Consumes: nothing.

- [ ] **Step 1: Check the box by default** (`src/glinet_profiler/web/index.html`)

Change the SSH checkbox input to be checked and reword the label to note the default + fallback:
```html
    <label class="chk"><input id="ssh" type="checkbox" checked> try SSH ground-truth (default; falls back automatically)</label>
```

- [ ] **Step 2: Verify**

Run: `grep -n 'id="ssh" type="checkbox" checked' src/glinet_profiler/web/index.html`
Expected: one match. (The launcher reads `$("ssh").checked` — now true on load; `app.js` is unchanged.)

- [ ] **Step 3: Commit**

```bash
git add src/glinet_profiler/web/index.html
git commit -m "feat(ui): SSH ground-truth checked by default"
```

---

### Task 5: Remove the enumerator from gli4py

**Files:** (gli4py repo at `/home/shaunes/dev/oss/gli4py`)

- [ ] **Step 1: Close PR #12 with a pointer**

```bash
gh pr close 12 --repo shauneccles/gli4py --comment "Superseded: the enumerator engine has moved into glinet-profiler (https://github.com/shauneccles/glinet-profiler) — it belongs with the discovery/collection product, and glinet-profiler no longer depends on gli4py. gli4py keeps its client library. Closing in favor of that repo."
```

- [ ] **Step 2: Delete the `feat/api-enumerator` branch (PAUSE for user go-ahead on the remote delete)**

Local first:
```bash
cd /home/shaunes/dev/oss/gli4py
git checkout feat/api-transport-boundary 2>/dev/null || git checkout master
git branch -D feat/api-enumerator
```
Remote (the destructive step — only after the user confirms):
```bash
git push origin --delete feat/api-enumerator
```
Expected: PR #12 closed; the branch gone. PR #11 (`feat/api-transport-boundary`) is untouched.

---

## Self-Review

**1. Spec coverage**

| Spec section | Task |
|---|---|
| §2 move enumerator (no cli) | 1 |
| §3 login port (compute_hash + login) | 2 |
| §4 rewire capture + ingest | 3 |
| §5 deps (drop gli4py + source; libpass; paramiko core) | 1 (paramiko), 2 (libpass), 3 (drop gli4py + source) |
| §6 SSH default (capture/server/UI) | 3 (capture/server), 4 (UI) |
| §7 tests (port enum tests; login test; capture/server) | 1, 2, 3 |
| §8 gli4py removal (close #12, delete branch) | 5 |

No uncovered requirements. `test_enum_cli.py` is intentionally not ported (cli dropped).

**2. Placeholder scan:** No TBD/TODO. The module/test moves are concrete `cp`/`sed` from on-disk gli4py sources (reproducible, not placeholders). The login is full code; the rewired `capture.py` is full code.

**3. Type/interface consistency:** `device_id`, `enumerate_device`, `to_json`, `ssh_discover`/`SshUnavailable` keep their gli4py signatures (modules moved verbatim), so `capture.py`'s usage is unchanged except the import path. `login(session, rpc_url, username, password) -> str` (Task 2) is consumed by `capture._enumerate` (Task 3) with matching args. `compute_hash`'s parameters match the challenge fields (`alg`, `salt`, `nonce`, `hash-method`). `capture(..., ssh=True)` and `server`'s `body.get("ssh", True)` agree on the default. The final dependency set (`aiohttp`, `libpass`, `paramiko`) matches across `pyproject.toml`, the imports, and the zero-gli4py grep.

---

## Execution Handoff

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks (`superpowers:subagent-driven-development`).
2. **Inline Execution** — work the tasks in this session with checkpoints (`superpowers:executing-plans`).
