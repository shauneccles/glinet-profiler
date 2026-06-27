# Design: internalize the enumerator engine; drop gli4py entirely

- **Date:** 2026-06-27
- **Status:** Approved (design); pending implementation plan
- **Repo:** glinet-profiler

## 1. Goal & boundary shift

glinet-profiler becomes the home of the **discovery engine** and depends on **nothing from gli4py**. The enumerator (catalog/SSH discovery + report) moves in; the GL.iNet login it needs is reimplemented locally. SSH discovery becomes the **default** capture mode (attempt every time, fall back to catalog-only if unavailable). gli4py loses the enumerator (it keeps only its client library).

Net dependencies after this change: `aiohttp`, `libpass`, `paramiko` — **no `gli4py`, no `uplink`**.

## 2. Move the enumerator package

Copy `gli4py/enumerator/{__init__,probe,report,ssh,models,catalog,classify,coverage,redact,wordlist}.py` → `src/glinet_profiler/enumerator/`. They are **self-contained** (intra-package imports only; `ssh.py` uses `paramiko`; everything else is stdlib). **Drop `cli.py`** — the launcher's `capture.py` is the entry point. The ported modules keep their inline lint pragmas; they must pass glinet-profiler's `ruff` + `mypy --strict` (`files=["src"]`) + `pylint`. `device_id`, `enumerate_device` (probe.py), `to_json` (report.py), `ssh_discover`/`SshUnavailable` (ssh.py) are the surface `capture.py`/`ingest.py` consume.

## 3. Port the login — `src/glinet_profiler/glinet_login.py`

Reimplements gli4py's challenge-response (from its `_transport`) with no `uplink`/`GLinet`:

- **`compute_hash(alg: int, salt: str, nonce: str, hash_method: str, username: str, password: str) -> str`** (pure, CPU-bound, testable):
  - `cipher_password` = `libpass` crypt of `password` with `salt`: `alg==1`→`md5_crypt.using(salt=salt)`, `alg==5`→`sha256_crypt.using(salt=salt, rounds=5000)`, `alg==6`→`sha512_crypt.using(salt=salt, rounds=5000)`; else `ValueError`.
  - `data = f"{username}:{cipher_password}:{nonce}"`; return `hashlib.{md5|sha256|sha512}(data.encode()).hexdigest()` per `hash_method` (default `"md5"`); else `ValueError`.
- **`async login(session: aiohttp.ClientSession, rpc_url: str, username: str, password: str) -> str`**: POST the unauthenticated `challenge` (`{"jsonrpc":"2.0","id":0,"method":"challenge","params":{"username":username}}`), read `result` → `{alg, salt, nonce, hash-method}`; run `compute_hash` via `asyncio.to_thread`; POST `login` (`params={"username":username,"hash":hsh}`); return `result["sid"]`. Raise a clear error if the router doesn't return a sid.

## 4. Rewire capture + ingest

`capture.py`: replace the `gli4py.enumerator.*` + `GLinet`/`uplink` imports with `glinet_profiler.enumerator.*` + the local `login`. It keeps its own aiohttp JSON-RPC `caller` and the patched-`_enumerate` test seam. `_enumerate` now: build session → `sid = await login(session, rpc_url, username, password)` → `caller` → `enumerate_device(caller, device_info=…, ssh_surface=…)` → `to_json`. `ingest.py`: `from glinet_profiler.enumerator.probe import device_id`.

## 5. Dependencies

`pyproject.toml`:
- **Remove** `gli4py` from `dependencies` and the whole `[tool.uv.sources]` block (the gli4py git pin).
- **Add** `libpass>=1.8` to `dependencies`; **promote `paramiko`** from the `ssh` optional-extra to a core dependency (SSH is default) and drop the now-empty `ssh` extra.
- Result: `dependencies = ["aiohttp>=3.8.4", "libpass>=1.8", "paramiko>=3"]`.
- mypy override: replace the `uplink`/`gli4py` modules with `passlib`, `passlib.*` (libpass), keeping `paramiko` (ignore_missing_imports).

## 6. SSH default

- `capture(host, username, password, *, ssh: bool = True)` and `_enumerate(..., ssh: bool)` default `ssh=True`.
- `server.py` `/api/enumerate`: `ssh=bool(body.get("ssh", True))` (missing → on).
- The launcher UI checkbox `#ssh` starts **checked**; its label notes SSH gives ground-truth and falls back automatically.
- Behavior: `ssh_discover` is attempted; on `SshUnavailable` (no SSH service / bad creds / paramiko error) `surface=None` and enumeration proceeds catalog-only. `paramiko` is now always installed.

## 7. Testing

`uv run pytest` (hardware-free) + existing gates (ruff, ruff-format, mypy --strict, pylint, zizmor):
- **Port the enumerator tests** `tests/test_enum_{brute,catalog,classify,probe,redact,report,ssh_integration,ssh_parse}.py` from gli4py, rewiring imports `gli4py.enumerator.*` → `glinet_profiler.enumerator.*`. **Do not** port `test_enum_cli.py` (cli dropped).
- **`tests/test_glinet_login.py`** — `compute_hash` against fixed `(alg, salt, nonce, hash_method, username, password)` vectors (deterministic), incl. each alg/hash-method and the unsupported-alg `ValueError`; `login` against a mocked aiohttp session asserting it returns the sid and posts the challenge then login.
- Update `tests/test_capture.py` (patches `_enumerate`; unaffected by internals) and `tests/test_server.py` (default `ssh` now True) as needed.

## 8. gli4py side — remove the enumerator

The enumerator lives only on gli4py's `feat/api-enumerator` branch (PR #12, unmerged). **Close PR #12** with a note pointing here, and **delete the `feat/api-enumerator` branch** (local + remote) — the enumerator now lives in glinet-profiler. gli4py's `feat/api-transport-boundary` (PR #11) is a separate branch and is untouched; gli4py keeps its client. (Remote branch deletion needs explicit go-ahead at that step.)

## 9. File structure (new/changed in glinet-profiler)

| File | Change |
|---|---|
| `src/glinet_profiler/enumerator/*.py` | New (moved from gli4py; `cli.py` excluded). |
| `src/glinet_profiler/glinet_login.py` | New — challenge-response login (`compute_hash` + `login`). |
| `src/glinet_profiler/capture.py` | Rewire to local enumerator + local login; `ssh` default True. |
| `src/glinet_profiler/ingest.py` | `device_id` import → local. |
| `src/glinet_profiler/server.py` | `ssh` defaults to True. |
| `src/glinet_profiler/web/index.html`, `app.js` | SSH checkbox checked by default. |
| `pyproject.toml` | Drop gli4py + uplink + git source; add libpass; paramiko core. |
| `tests/test_enum_*.py`, `tests/test_glinet_login.py` | Ported enum tests + login test. |
