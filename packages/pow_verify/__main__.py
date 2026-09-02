"""What an agent runs to check someone else's claim.

Fetch the claim, run the check for its evidence class, emit a signed verdict.
E1 is deliberately absent: it requires executing a pinned image on hardware you
control, and shipping a half-runner would advertise support that does not exist.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

import pow_core as core

from . import e2, e6

CHECKS = {"E2": e2.check, "E6": e6.check}


def load_claim(ref: str) -> dict:
    if ref.startswith("http"):
        r = httpx.get(ref, timeout=20.0, follow_redirects=True)
        r.raise_for_status()
        data = r.json()
        return data.get("claim", data)
    return json.loads(Path(ref).read_text("utf-8"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pow-verify",
                                 description="Check a claim you did not write.")
    ap.add_argument("claim", help="path or URL to a claim record")
    ap.add_argument("--as", dest="verifier", required=True, help="your pseudonym")
    ap.add_argument("--key", required=True, help="your private key, base64")
    ap.add_argument("--out", type=Path, default=None, help="write the verdict here")
    args = ap.parse_args(argv)

    claim = load_claim(args.claim)
    ec = claim.get("evidence_class")

    if claim.get("claimant") == args.verifier:
        print("you may not verify your own claim", file=sys.stderr)
        return 2

    check = CHECKS.get(ec)
    if check is None:
        print(f"no checker for {ec}. E2 and E6 are supported; E1 needs a runner "
              f"on hardware you control.", file=sys.stderr)
        return 2

    verdict, output_hash, diagnosis = check(claim.get("manifest", {}))

    record = {
        "claim_id": claim["claim_id"],
        "verifier": args.verifier,
        "verdict": verdict,
        "output_hash": output_hash,
        "diagnosis": diagnosis,
        "magnitude": None,
        "fraud_caught": False,
        "settled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    record["signature"] = core.sign(record, args.key)
    core.validate(core.canonicalize(record), "verdict",
                  public_key=None, path=core.path_for(record, "verdict"))

    blob = core.canonicalize(record)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(blob)
    sys.stdout.write(blob.decode() + "\n")
    print(f"\n{verdict}: {diagnosis}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
