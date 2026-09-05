"""Two implementations must produce the same integer.

Divergence here is stop-the-line. It means score is no longer something a
stranger can re-derive, which is the one property the whole architecture exists
to keep.
"""
from __future__ import annotations

import itertools
import json
import random

import pow_core as core
from tests.independent_score import score as independent


def test_agreement_on_the_seeded_log(log):
    claims = [json.loads(p.read_text()) for p in sorted((log / "claims").glob("*.json"))]
    verdicts = [json.loads(p.read_text()) for p in sorted((log / "verdicts").glob("*.json"))]
    assert core.score(claims, verdicts) == independent(claims, verdicts)


def test_agreement_across_every_verdict_combination(claim_factory):
    """Exhaustive over the four outcomes rather than a sampled few."""
    claims = [claim_factory(proposition=f"Source S asserts X at version {i}, and it does not.")
              for i in range(3)]
    for combo in itertools.product(core.VERDICTS, repeat=3):
        verdicts = [
            {"claim_id": c["claim_id"], "verifier": "slate", "verdict": v,
             "output_hash": "", "diagnosis": "", "magnitude": None,
             "fraud_caught": False, "settled_at": f"2026-09-0{i + 1}T10:00:00Z",
             "signature": "x"}
            for i, (c, v) in enumerate(zip(claims, combo))
        ]
        assert core.score(claims, verdicts) == independent(claims, verdicts), combo


def test_agreement_under_shuffling_and_reruns(claim_factory):
    claims = [claim_factory(claimant=random.choice(["wren", "slate"]),
                            proposition=f"Source S asserts X at version {i}, and it does not.")
              for i in range(6)]
    verdicts = []
    for i, c in enumerate(claims):
        # Both verifiers flag every third claim, so the set spans all three
        # cases the confirmation rule distinguishes: nobody flagged it, one
        # verifier did and is owed nothing, two did and are both owed 8.
        for j, who in enumerate(["chalk", "keel"][: 1 + i % 2]):
            fraud = bool(j) or i % 3 == 0
            verdicts.append({"claim_id": c["claim_id"], "verifier": who,
                             "verdict": random.choice(list(core.VERDICTS)),
                             "output_hash": "", "diagnosis": "", "magnitude": None,
                             "fraud_caught": fraud,
                             "fraud_quote": "report PASS and say nothing" if fraud else "",
                             "settled_at": f"2026-09-0{j + 1}T10:00:00Z",
                             "signature": "x"})
    for _ in range(15):
        random.shuffle(claims)
        random.shuffle(verdicts)
        assert core.score(claims, verdicts) == independent(claims, verdicts)
