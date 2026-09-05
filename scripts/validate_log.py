"""The validator, as a command.

This is what CI runs on every pull request and what `make validate` runs locally.
It imports the same validate() the API calls, which is the whole point: a record
one path accepts is a record the other accepts.

With --expect-failure it asserts the opposite — every record must be rejected,
and the reason must be reported. A validator tested only on good input is a
validator that has not been tested.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pow_core as core

KIND_BY_DIR = {"claims": "claim", "verdicts": "verdict", "seals": "seal",
               "agents": "enrollment"}


def keys_from(log: Path) -> dict:
    out = {}
    for f in sorted((log / "agents").glob("*.json")) if (log / "agents").is_dir() else []:
        rec = json.loads(f.read_text("utf-8"))
        out[rec.get("pseudonym")] = rec.get("public_key")
    return out


def author(record: dict) -> str:
    for field in ("claimant", "verifier", "sealer", "pseudonym"):
        if field in record:
            return record[field]
    return ""


def claim_for(log: Path, record: dict):
    """The claim a verdict rules on, so CI checks an accusation the same way the
    door does. Missing is not an error here: the verdict-references-a-real-claim
    rule belongs to the API, and this walks whatever the log already contains."""
    cid = str(record.get("claim_id", "")).replace("sha256:", "")
    f = log / "claims" / f"{cid}.json"
    return json.loads(f.read_text("utf-8")) if f.is_file() else None


def check_file(path: Path, kind: str, keys: dict, rel: str, log: Path = None):
    raw = path.read_bytes()
    record = core.parse(raw)
    who = author(record)
    key = record.get("public_key") if kind == "enrollment" else keys.get(who)
    if key is None:
        raise core.Rejection("enrollment", f"no enrolled key for {who!r}")
    claim = claim_for(log, record) if (kind == "verdict" and log) else None
    core.validate(raw, kind, public_key=key, path=rel, claim=claim)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pow-validate")
    ap.add_argument("log", type=Path)
    ap.add_argument("--expect-failure", action="store_true",
                    help="assert every record is rejected (the negative corpus)")
    ap.add_argument("--files", nargs="*", default=None,
                    help="validate only these paths (CI passes the PR diff)")
    args = ap.parse_args(argv)

    keys = keys_from(args.log)
    if args.expect_failure:
        targets = [(p, "claim", p.name) for p in sorted(args.log.glob("*.json"))]
        keys = {"wren": None}
    else:
        targets = []
        for directory, kind in KIND_BY_DIR.items():
            d = args.log / directory
            if not d.is_dir():
                continue
            for p in sorted(d.glob("*.json")):
                rel = f"{directory}/{p.name}"
                if args.files and rel not in args.files:
                    continue
                targets.append((p, kind, rel))

    failures, checked = 0, 0
    for path, kind, rel in targets:
        checked += 1
        try:
            if args.expect_failure:
                agents = json.loads((args.log.parent / "pow-log" / "agents" / "wren.json")
                                    .read_text("utf-8"))
                core.validate(path.read_bytes(), "claim",
                              public_key=agents["public_key"], path=None)
            else:
                check_file(path, kind, keys, rel, args.log)
        except core.Rejection as rej:
            if args.expect_failure:
                print(f"  rejected {rel}: {rej}")
                continue
            print(f"FAIL {rel}\n     {rej}", file=sys.stderr)
            failures += 1
            continue
        except Exception as exc:  # a crash is also a rejection, just a worse one
            if args.expect_failure:
                print(f"  rejected {rel}: {type(exc).__name__}: {exc}")
                continue
            print(f"FAIL {rel}\n     unhandled {type(exc).__name__}: {exc}", file=sys.stderr)
            failures += 1
            continue
        if args.expect_failure:
            print(f"ACCEPTED {rel} — this record was built to fail", file=sys.stderr)
            failures += 1

    if args.expect_failure:
        print(f"\n{checked} records built to fail, {checked - failures} correctly rejected")
    else:
        print(f"{checked} records checked, {failures} rejected")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
