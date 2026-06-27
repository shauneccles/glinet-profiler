"""CLI: validate + ingest a submitted profile into the registry (prints the id, or the error)."""

import argparse
import json
import sys
from pathlib import Path

from glinet_profiler.ingest import ingest

_DATA = Path(__file__).resolve().parent.parent / "src" / "glinet_profiler" / "data"


def main(argv: list[str] | None = None) -> int:
    """Ingest the given submission file. On success print the id (exit 0); on failure print to stderr (exit 1)."""
    parser = argparse.ArgumentParser(description="Ingest a submitted device profile.")
    parser.add_argument("submission")
    args = parser.parse_args(argv)
    try:
        print(ingest(Path(args.submission), _DATA))
    except (ValueError, json.JSONDecodeError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
