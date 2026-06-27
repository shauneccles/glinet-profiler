# Design: release automation (release-please + PyPI trusted publishing)

- **Date:** 2026-06-27
- **Status:** Approved (design); built (not yet released)
- **Repo:** glinet-profiler

## Goal

A seamless, secretless release pipeline: conventional commits → automated version bump + `CHANGELOG.md` + GitHub Release → publish to PyPI via **trusted publishing** (OIDC, no API token). First public version: **0.0.1**.

## Flow

```
push to main (conventional commits)
   → release-please opens/updates a "release PR" (bumps version in pyproject + CHANGELOG.md)
   → merge the release PR
   → release-please tags vX.Y.Z + creates the GitHub Release (same workflow run)
   → the publish job (gated on release_created) builds + uploads to PyPI via OIDC
```

## Components

- **`release-please-config.json` + `.release-please-manifest.json`** — release-type `python` (manages `[project] version` + `CHANGELOG.md`), manifest bootstrapped at `0.0.0`. The first release is forced to **0.0.1** via a one-time `Release-As: 0.0.1` commit footer (so future releases compute normally from commits).
- **`.github/workflows/release.yml`** — a single workflow with two jobs:
  - `release-please` (perms `contents: write` + `pull-requests: write`) runs `googleapis/release-please-action@<sha>` and exposes `release_created`/`tag_name` outputs.
  - `publish` (`needs: release-please`, `if: release_created == 'true'`, `environment: production`, perms `id-token: write` + `contents: read`) checks out, `uv build`, then `pypa/gh-action-pypi-publish@<sha>` (trusted publishing).
  - **Why one workflow, not two:** GitHub's recursion guard means a release created with `GITHUB_TOKEN` does NOT trigger a separate `on: release` workflow. Publishing in the same run that created the release avoids needing a long-lived PAT, and keeps the OIDC `workflow_ref` claim as `release.yml` (what the PyPI publisher is registered against).
- **`pyproject.toml`** — `version = "0.0.0"` (release-please-managed); PyPI `classifiers` + `[project.urls]` for a clean listing. SPDX `license = "GPL-3.0-or-later"` (no `License ::` classifier, per PEP 639).
- All actions SHA-pinned (zizmor-clean); the existing `dependabot.yml` (github-actions) already covers them.

## Operator prerequisites (one-time, on GitHub/PyPI)

1. **PyPI trusted publisher** must reference: owner `shauneccles`, repo `glinet-profiler`, workflow **`release.yml`**, environment **`production`**.
2. Enable **Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests"** (so release-please can open its PR).
3. The **`production`** environment auto-creates on first use; optionally add a required-reviewer protection rule for a manual gate before publish.

## "Build, don't release"

The infrastructure is committed and pushed; release-please will open a **"release 0.0.1" PR** but **publishes nothing** until that PR is merged (the publish job is gated on `release_created`, which only becomes true when the release PR merges). Merging is a deliberate, later step.

## Testing

YAML parses; `zizmor .github/` clean (SHA pins + minimal perms + `persist-credentials: false`); `uv build` produces a wheel + sdist; the existing gates (ruff/mypy/pylint/pytest) are unaffected. End-to-end publish is verified by the first real release (deferred).
