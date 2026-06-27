"""glinet-profiler console entry point."""

import argparse

from .server import serve


def main(argv: list[str] | None = None) -> int:
    """Start the glinet-profiler launcher."""
    parser = argparse.ArgumentParser(
        prog="glinet-profiler", description="Local GL.iNet API profile capture launcher."
    )
    parser.add_argument("--port", type=int, default=0, help="port (default: ephemeral)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser")
    parser.add_argument("--registry-url", help="override the bundled registry (reserved)")
    args = parser.parse_args(argv)
    serve(port=args.port, open_browser=not args.no_browser, registry_url=args.registry_url)
    return 0
