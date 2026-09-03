"""Seed a local log for development, including records built to fail.

The negative corpus is the point. A validator you have only tested on good input
is a validator you have not tested. These are the manifests built to pass
wrongly, and they must be rejected with a message that says which rule broke.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pow_core as core

AGENTS = ["wren", "slate", "chalk", "keel"]

CLAIMS = [
    dict(claimant="wren", domain=1, path="sealed", evidence_class="E2",
         proposition="Advisory D lists package P as affected at version V, but the "
                     "vulnerable function was removed at V.",
         manifest={"sources": [{"url": "https://example.invalid/advisory-D.json",
                              "snapshot_sha256": "a" * 64}],
                   "fetched_at": "2026-08-30",
                   "assertion": "affected_range includes V while the fix landed before V"},
         why="Anyone checking whether they are exposed gets the wrong answer.",
         boundary="standing: the advisory database is a public artifact",
         costs="", valid_as_of="2026-08-30"),
    dict(claimant="slate", domain=4, path="sealed", evidence_class="E2",
         proposition="The published answer key for exercise set S disagrees with the "
                     "worked solution printed in the same document for 22 items.",
         manifest={"sources": [{"url": "https://example.invalid/exercises-S.json",
                              "snapshot_sha256": "b" * 64}],
                   "fetched_at": "2026-08-31",
                   "assertion": "22 answer cells contradict their own problem statements"},
         why="A student working alone is told the right answer is wrong.",
         boundary="the answer key: correctness is re-derived from the mathematics, "
                  "not taken from the key, which is itself the thing in question",
         costs="", valid_as_of="2026-08-31"),
    dict(claimant="chalk", domain=3, path="sealed", evidence_class="E2",
         proposition="Benefit calculator C returns a smaller award than statute S "
                     "requires for 4 of the 12 household profiles the agency publishes.",
         manifest={"sources": [{"url": "https://example.invalid/worked-examples.json",
                              "snapshot_sha256": "c" * 64}],
                   "fetched_at": "2026-09-01",
                   "assertion": "4 published worked examples disagree with the statute text"},
         why="Households are told they qualify for less than the law gives them.",
         boundary="no subject acts as evidence: every profile is the agency's own "
                  "synthetic example; no real household appears",
         costs="Points at a snapshot rather than the live calculator, so it says "
               "nothing about what the calculator does today.",
         valid_as_of="2026-09-01"),
]

BROKEN = {
    "bad-signature": "signature does not cover the record",
    "bad-hash": "claim_id does not match the content",
    "no-proposition": "a claim with an empty proposition",
    "float-in-manifest": "a float, which canonical form refuses",
}


def build(out: Path) -> None:
    keys = {}
    for d in ("claims", "verdicts", "seals", "handouts", "agents", "observatory"):
        (out / d).mkdir(parents=True, exist_ok=True)

    for name in AGENTS:
        sk, pk = core.generate()
        keys[name] = (sk, pk)
        rec = {"pseudonym": name, "public_key": pk, "enrolled_at": "2026-08-29T09:00:00Z"}
        rec["signature"] = core.sign(rec, sk)
        (out / f"agents/{name}.json").write_bytes(core.canonicalize(rec))

    claim_ids = []
    for spec in CLAIMS:
        rec = dict(spec)
        rec.update(claim_id="", submitted_at=spec["valid_as_of"] + "T12:00:00Z", signature="")
        rec["claim_id"] = core.content_hash(rec, exclude=core.Claim.ID_EXCLUDES)
        rec["signature"] = core.sign(rec, keys[rec["claimant"]][0])
        (out / core.path_for(rec, "claim")).write_bytes(core.canonicalize(rec))
        claim_ids.append(rec["claim_id"])

    settlements = [
        (claim_ids[0], "slate", "PASS", "re-fetched the advisory; bytes identical to the "
         "recorded snapshot."),
        (claim_ids[1], "chalk", "UNRESOLVABLE", "the source returned HTTP 404. Link rot is "
         "not a false claim: re-snapshot and resubmit. Nothing is owed by the claimant."),
    ]
    for cid, who, verdict, diagnosis in settlements:
        rec = {"claim_id": cid, "verifier": who, "verdict": verdict,
               "output_hash": "sha256:" + hashlib.sha256(cid.encode()).hexdigest(),
               "diagnosis": diagnosis, "magnitude": None, "fraud_caught": False,
               "settled_at": "2026-09-01T18:00:00Z", "signature": ""}
        rec["signature"] = core.sign(rec, keys[who][0])
        (out / core.path_for(rec, "verdict")).write_bytes(core.canonicalize(rec))

    neg = out.parent / "negative"
    neg.mkdir(parents=True, exist_ok=True)
    base = dict(CLAIMS[0])
    base.update(claim_id="", submitted_at="2026-08-30T12:00:00Z", signature="")
    base["claim_id"] = core.content_hash(base, exclude=core.Claim.ID_EXCLUDES)
    base["signature"] = core.sign(base, keys["wren"][0])

    bad = dict(base); bad["signature"] = core.sign({**base, "proposition": "different"},
                                                   keys["wren"][0])
    (neg / "bad-signature.json").write_bytes(core.canonicalize(bad))

    bad = dict(base); bad["claim_id"] = "sha256:" + "0" * 64
    (neg / "bad-hash.json").write_bytes(core.canonicalize(bad))

    bad = dict(base); bad["proposition"] = ""
    (neg / "no-proposition.json").write_bytes(json.dumps(bad).encode())

    bad = dict(base); bad["manifest"] = {**base["manifest"], "ceiling_gb": 2.5}
    (neg / "float-in-manifest.json").write_bytes(json.dumps(bad).encode())

    (out.parent / "keys.json").write_text(
        json.dumps({k: {"private": v[0], "public": v[1]} for k, v in keys.items()},
                   indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pow-seed")
    ap.add_argument("out", type=Path, nargs="?", default=Path("tmp/pow-log"))
    args = ap.parse_args(argv)
    build(args.out)
    print(f"seeded {args.out} ({len(CLAIMS)} claims, {len(AGENTS)} agents) "
          f"and {args.out.parent / 'negative'} ({len(BROKEN)} records built to fail)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
