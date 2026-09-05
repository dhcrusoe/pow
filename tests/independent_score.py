"""A second implementation of score, written from the specification.

Deliberately structured differently from pow_core.score: it walks records once,
uses no shared helpers, and re-derives the manifest key itself. The point is not
elegance — it is that two people reading the specification arrive at the same
integer. Decomposability is the product, and this is the only test of it.

This should eventually be rewritten in another language. Python-to-Python shares
too many assumptions about dict ordering and integer behaviour to be a fully
independent check.
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Mapping


def _key(claim: Mapping) -> str:
    manifest = json.dumps(claim.get("manifest", {}), sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(manifest.encode("utf-8")).hexdigest()


def score(claims: List[Mapping], verdicts: List[Mapping]) -> Dict[str, int]:
    weights = {"PASS": 10, "FAIL": -15, "INELIGIBLE": -5, "UNRESOLVABLE": 0}
    totals: Dict[str, int] = {}

    def add(who: str, n: int) -> None:
        totals[who] = totals.get(who, 0) + n

    # Every claimant appears, even at zero.
    for c in claims:
        add(c["claimant"], 0)

    # Each claim settles on its earliest verdict, ties broken by verifier name.
    for c in claims:
        mine = [v for v in verdicts if v["claim_id"] == c["claim_id"]]
        if not mine:
            continue
        mine.sort(key=lambda v: (v["settled_at"], v["verifier"]))
        c["_settled"] = mine[0]["verdict"]

    # Duplicate manifests from one claimant collapse to a single settlement.
    seen = set()
    for c in sorted(claims, key=lambda c: c["claim_id"]):
        if "_settled" not in c:
            continue
        ident = (c["claimant"], _key(c))
        if ident in seen:
            continue
        seen.add(ident)
        add(c["claimant"], weights[c["_settled"]])

    # Verification pays every time, re-runs included.
    for v in verdicts:
        add(v["verifier"], 3)

    # Fraud pays 8, but only where two or more distinct verifiers flagged the
    # same claim with a quote, and then it pays each of them. Derived here by
    # counting per claim rather than by calling anything in pow_core.
    accusers: Dict[str, List[str]] = {}
    for v in verdicts:
        if not v.get("fraud_caught"):
            continue
        if not str(v.get("fraud_quote") or "").strip():
            continue
        names = accusers.setdefault(v["claim_id"], [])
        if v["verifier"] not in names:
            names.append(v["verifier"])
    for names in accusers.values():
        if len(names) > 1:
            for who in names:
                add(who, 8)

    for c in claims:
        c.pop("_settled", None)
    return dict(sorted(totals.items()))
