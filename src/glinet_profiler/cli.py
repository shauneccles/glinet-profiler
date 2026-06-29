"""glinet-profiler console entry point (web UI, or a one-shot CLI capture)."""

import argparse
import asyncio
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from .capture import capture
from .registry import DEFAULT_REGISTRY_URL, fetch_manifest, lookup
from .server import serve
from .submit import prefilled_issue_url


def main(argv: list[str] | None = None) -> int:
    """Start the web launcher, or run a one-shot capture when a router IP is given."""
    parser = argparse.ArgumentParser(
        prog="glinet-profiler", description="Capture a GL.iNet device's API surface."
    )
    parser.add_argument(
        "ip", nargs="?", help="router IP/host — run a one-shot capture (omit to start the web UI)"
    )
    parser.add_argument("--username", default="root", help="router username (default: root)")
    parser.add_argument(
        "--password",
        help="router password (or set GLINET_PASSWORD, or be prompted). "
        "A value passed here is visible to other processes — prefer the env var or the prompt.",
    )
    parser.add_argument("--no-ssh", action="store_true", help="skip SSH ground-truth discovery")
    parser.add_argument(
        "--dangerous",
        action="store_true",
        help="DANGER: HTTP-call WRITE endpoints (set_/add_/...) — changes your router's config. Spare routers only.",
    )
    parser.add_argument(
        "--include-destructive",
        action="store_true",
        help="DANGER: also call DESTRUCTIVE methods (reboot/factory-reset/firmware), last. Implies --dangerous. Sacrificial routers only.",
    )
    parser.add_argument(
        "--keep-data",
        action="store_true",
        help="keep each method's (secret-redacted) response value for local signature analysis. "
        "The result carries response data, so it is LOCAL-ONLY and not registry-publishable.",
    )
    parser.add_argument(
        "--output", "-o", help="write the profile JSON here (default: <id>.json in the cwd)"
    )
    # web-UI mode flags (used when no IP is given)
    parser.add_argument("--port", type=int, default=0, help="web UI port (default: ephemeral)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser")
    parser.add_argument(
        "--registry-url",
        default=DEFAULT_REGISTRY_URL,
        help="registry manifest URL (default: live GitHub Pages URL)",
    )
    args = parser.parse_args(argv)

    if args.ip:
        try:
            return asyncio.run(_capture_cli(args))
        except KeyboardInterrupt:
            print("\ninterrupted.", file=sys.stderr)
            return 130
    serve(port=args.port, open_browser=not args.no_browser, registry_url=args.registry_url)
    return 0


async def _capture_cli(args: argparse.Namespace) -> int:
    """Run a single headless capture; print the registry status + submission link."""
    password = (
        args.password or os.environ.get("GLINET_PASSWORD") or getpass.getpass("Router password: ")
    )

    async def _progress(event: dict[str, Any]) -> None:
        print(f"  {event.get('message', '')}", file=sys.stderr)

    dangerous = args.dangerous or args.include_destructive  # destructive implies write-probing
    try:
        profile = await capture(
            args.ip,
            args.username,
            password,
            ssh=not args.no_ssh,
            dangerous=dangerous,
            include_destructive=args.include_destructive,
            keep_data=args.keep_data,
            on_progress=_progress,
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(f"capture failed: {exc}", file=sys.stderr)
        return 1

    out = Path(args.output) if args.output else Path(f"{profile['id']}.json")
    out.write_text(json.dumps(profile, indent=2, sort_keys=True), encoding="utf-8")

    if args.keep_data:
        print(
            f"\nProfile (with response data): {profile['model']} ({profile['firmware_version']}) -> {out}"
        )
        print("Status:  LOCAL-ONLY — kept secret-redacted response data for signature analysis.")
        print(
            "         Not registry-publishable (carries response values); do not submit this file."
        )
        return 0

    manifest = await fetch_manifest(args.registry_url)
    known = lookup(profile.get("model", ""), profile.get("firmware_version", ""), manifest)
    print(f"\nProfile: {profile['model']} ({profile['firmware_version']}) -> {out}")
    if manifest is None:
        print("Status:  couldn't reach the registry — submit anyway (the bot dedups on the PR):")
        print(f"  open:   {prefilled_issue_url(profile)}")
        print(f"  attach: {out}  (drag it into the issue)")
    elif known:
        print("Status:  already in the registry — nothing to submit.")
    else:
        print("Status:  NEW — contribute it:")
        print(f"  open:   {prefilled_issue_url(profile)}")
        print(f"  attach: {out}  (drag it into the issue)")
    return 0
