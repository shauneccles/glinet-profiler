# glinet-profiler

A small **local** web launcher that captures a GL.iNet router's API surface
(read-only), sanitizes it into a shareable **profile**, checks whether that
device + firmware is already in the registry, and lets you download it or open
a prefilled submission.

Your **password never leaves your machine**: it goes from your browser to a
local server (`127.0.0.1`) to your own router. Nothing is uploaded unless you
deliberately submit.

> **Built with AI assistance.** Most of this code was written by Claude — human-directed,
> reviewed change by change, and verified against real hardware. It's open source; read it
> and judge for yourself. The read-only-by-default behaviour and the sanitization are the
> parts to scrutinise.

> **Why a local launcher and not a public site?** GL.iNet's RPC sends no CORS
> headers, so a public browser page cannot talk to your local router. The
> enumeration therefore runs server-side in this launcher (native Python,
> which is not subject to CORS), and the UI is served locally.

## Quick start

Once published you'll be able to run it with no install:

```bash
uvx glinet-profiler
```

From a source checkout:

```bash
uv run glinet-profiler            # starts the launcher, opens your browser
uv run glinet-profiler --no-browser --port 8765
```

Then enter your router URL (e.g. `http://192.168.8.1`), username (`root`), and
password, and click **Capture**. You'll get a sanitized profile, a
"already-known / new" banner, and **Download** / **Submit** actions.

## What's in the profile (and what isn't)

The published profile keeps only the device **model + firmware** and the
**per-method API shape** (status, risk, whether the [gli4py](https://github.com/shauneccles/gli4py)
client wraps it, params, schema). It **drops** device identifiers (`mac`, `sn`,
`sn_bak`) and **all response values** — the raw report never leaves the local
`capture()` step.

Enumeration is strictly **read-only** (a built-in catalog tier, plus an optional
SSH read tier if you tick the box and have SSH access).

## Security

- The launcher binds **`127.0.0.1` only** and guards its API with a per-run
  session token plus a localhost host check (so no other web page can drive it).
- The password is used only to log into your router from the local process and
  is never persisted, logged, or sent anywhere remote.

## How it fits with gli4py and the registry

This package is the **capture launcher** only. The enumeration **engine** lives
inside it (`glinet_profiler/enumerator/`, originally developed in the gli4py
project) — there is **no runtime dependency on gli4py** (deps are just
`aiohttp`, `paramiko`, `libpass`).

- **[gli4py](https://github.com/shauneccles/gli4py)** — the typed GL.iNet Python
  **client library**. Each captured profile records, per method, whether the
  gli4py client already wraps it ("coverage") — a lens for Python developers.
- **[glinet-registry](https://github.com/shauneccles/glinet-registry)** — the
  public, community registry of device profiles (browse site + submission bot).
  The launcher fetches its manifest to tell you whether a device is already
  known, and **Submit** opens its issue form. It releases independently of this
  package.

## Development

```bash
uv sync --all-extras --dev
uv run pytest -q
uv run ruff check . && uv run mypy src && uv run pylint $(git ls-files '*.py')
```

## The three repos

- **glinet-profiler** (this repo) — the capture launcher + enumeration engine.
- **[glinet-registry](https://github.com/shauneccles/glinet-registry)** — the
  device-profile data, browse site, and submission bot.
- **[gli4py](https://github.com/shauneccles/gli4py)** — the GL.iNet Python client
  library (the "coverage" lens shown in each profile).

## License

GPL-3.0-or-later.
