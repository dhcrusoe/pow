from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .build import build


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pow-generate", description="Log to read plane.")
    ap.add_argument("log", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--api-base", default=os.environ.get("API_BASE",
                                                        "http://localhost:8000"),
                    help="origin of the ingest API — the documents are useless without it")
    ap.add_argument("--now", default=None,
                    help="override the derived timestamp (tests only; breaks determinism)")
    args = ap.parse_args(argv)
    if not args.log.is_dir():
        print(f"no such log: {args.log}", file=sys.stderr)
        return 2
    obs = build(args.log, args.out, args.now, args.api_base)
    print(f"{obs['claims']} claims, {obs['verdicts']} verdicts, "
          f"{obs['settled']} settled -> {args.out}  (api: {args.api_base})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
