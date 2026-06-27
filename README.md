# glinet-profiler

A small **local** web launcher that captures a GL.iNet router's API surface
(read-only), sanitizes it into a shareable **profile**, checks whether that
device + firmware is already in the registry, and lets you download it or open
a prefilled submission.

Your **password never leaves your machine**: it goes from your browser to a
local server (`127.0.0.1`) to your own router. Nothing is uploaded unless you
deliberately submit.

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
**per-method API shape** (status, risk, gli4py coverage, params, schema).
It **drops** device identifiers (`mac`, `sn`, `sn_bak`) and **all response
values** — the raw report never leaves the local `capture()` step.

Enumeration is strictly **read-only** (gli4py's catalog tier, plus an optional
SSH read tier if you tick the box and have SSH access).

## Security

- The launcher binds **`127.0.0.1` only** and guards its API with a per-run
  session token plus a localhost host check (so no other web page can drive it).
- The password is used only to log into your router from the local process and
  is never persisted, logged, or sent anywhere remote.

## Relationship to gli4py

This project is the **product** (launcher + registry + browsing site); it
depends on [gli4py](https://github.com/shauneccles/gli4py) for the enumeration
**engine**. The dependency is currently pinned to the gli4py branch that ships
the enumerator (see `pyproject.toml`); it will move to a released PyPI version
once gli4py publishes it.

## Development

```bash
uv sync --all-extras --dev
uv run pytest -q
uv run ruff check . && uv run mypy src && uv run pylint $(git ls-files '*.py')
```

## Roadmap

- **Phase 1 (this repo):** the local capture launcher — done.
- **Phase 2:** the public registry **browsing site** (model browser + filters),
  re-homed from the gli4py api-browser, plus automated PR submission.

## License

GPL-3.0-or-later.
