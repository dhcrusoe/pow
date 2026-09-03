"""What an agent runs to check someone else's claim.

Fetch the claim, run the check for its evidence class, emit a signed verdict.

Four classes settle on YOUR result, not the claimant's: E1, E4 and E7 need you to
redo the work with your own tools, and E5 needs you to read a sealed prediction
against what happened. Those take --observed. Run them without it and you get
UNRESOLVABLE and an explanation of what to go and do — never a FAIL, because
"I have not done the work yet" is not a finding about the claimant.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

import pow_core as core

from . import e1, e2, e3, e4, e5, e6, e7

CHECKS = {"E1": e1.check, "E2": e2.check, "E3": e3.check, "E4": e4.check,
          "E5": e5.check, "E6": e6.check, "E7": e7.check}

# Classes whose verdict is a statement about work the verifier did themselves.
NEEDS_OBSERVED = {"E1", "E4", "E5", "E7"}
# Classes that open a commitment, and so need the seal record fetched.
NEEDS_SEAL = {"E4", "E5", "E7"}


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
    ap.add_argument("--observed", default=None,
                    help="what YOU got, as JSON or a path: {\"value\": 1234} for a "
                         "number, {\"digest\": \"sha256:…\"} for an artifact, "
                         "{\"resolved\": true} for a prediction")
    ap.add_argument("--seal", default=None,
                    help="path or URL to the seal record; defaults to the "
                         "manifest's seal_url")
    args = ap.parse_args(argv)

    claim = load_claim(args.claim)
    ec = claim.get("evidence_class")

    if claim.get("claimant") == args.verifier:
        print("you may not verify your own claim", file=sys.stderr)
        return 2

    check = CHECKS.get(ec)
    if check is None:
        print(f"no checker for {ec}. Adopted classes with a checker here: "
              f"{', '.join(sorted(CHECKS))}.", file=sys.stderr)
        return 2

    manifest = claim.get("manifest", {})
    extra = {}
    if ec in NEEDS_OBSERVED and args.observed:
        raw = args.observed
        if not raw.lstrip().startswith("{"):
            raw = Path(raw).read_text("utf-8")
        extra["observed"] = json.loads(raw)
    if ec in NEEDS_SEAL:
        ref = args.seal or manifest.get("seal_url")
        try:
            extra["seal"] = load_claim(ref) if ref else None
        except Exception:
            extra["seal"] = None          # check_seal reports this properly
        extra["claimant"] = claim.get("claimant", "")

    verdict, output_hash, diagnosis = check(manifest, **extra)

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
