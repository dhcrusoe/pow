"""Score is the decomposability claim, so it is property-tested, not asserted.

If any of these fail, "delete every score in the network and it recomputes from
the log" has stopped being true, which is the one promise the whole design exists
to keep.
"""
from __future__ import annotations

import random

import pytest

import pow_core as core
from pow_core.score import FRAUD_CAUGHT, VERIFICATION, WEIGHTS


def verdict(cid, who, v="PASS", at="2026-09-01T12:00:00Z", fraud=False):
    return {"claim_id": cid, "verifier": who, "verdict": v, "output_hash": "",
            "diagnosis": "", "magnitude": None, "fraud_caught": fraud,
            "settled_at": at, "signature": "x"}


def test_published_weights_match_the_specification():
    assert WEIGHTS == {"PASS": 10, "FAIL": -15, "INELIGIBLE": -5, "UNRESOLVABLE": 0}
    assert VERIFICATION == 3
    assert FRAUD_CAUGHT == 8


def test_catching_fraud_never_pays_more_than_the_fraud_costs():
    """Otherwise a colluding pair nets positive no matter who runs both ends."""
    assert FRAUD_CAUGHT + VERIFICATION < -WEIGHTS["FAIL"]


def test_order_independence(claim_factory):
    claims = [claim_factory(proposition=f"Source S asserts X at version {i}, and it does not.")
              for i in range(8)]
    verdicts = [verdict(c["claim_id"], "slate", random.choice(list(WEIGHTS)))
                for c in claims]
    baseline = core.score(claims, verdicts)
    for _ in range(20):
        random.shuffle(claims)
        random.shuffle(verdicts)
        assert core.score(claims, verdicts) == baseline


def test_first_verdict_settles_and_reruns_pay_the_rerunner_only(claim_factory):
    c = claim_factory()
    one = verdict(c["claim_id"], "slate", "PASS", "2026-09-01T10:00:00Z")
    two = verdict(c["claim_id"], "chalk", "FAIL", "2026-09-02T10:00:00Z")
    totals = core.score([c], [one, two])
    assert totals["wren"] == 10          # settled once, on the first verdict
    assert totals["slate"] == VERIFICATION
    assert totals["chalk"] == VERIFICATION


def test_unresolvable_costs_the_claimant_nothing_and_still_pays_the_verifier(claim_factory):
    c = claim_factory()
    totals = core.score([c], [verdict(c["claim_id"], "slate", "UNRESOLVABLE")])
    assert totals["wren"] == 0
    assert totals["slate"] == VERIFICATION


def test_unverified_claims_score_nothing(claim_factory):
    """Merge means recorded, not verified."""
    assert core.score([claim_factory()], []) == {"wren": 0}


def test_repeat_claims_over_the_same_artifact_collapse_to_one(claim_factory):
    a = claim_factory(submitted_at="2026-09-01T10:00:00Z")
    b = claim_factory(submitted_at="2026-09-02T10:00:00Z")
    assert a["claim_id"] != b["claim_id"]          # different records
    totals = core.score([a, b], [verdict(a["claim_id"], "slate"),
                                 verdict(b["claim_id"], "chalk")])
    assert totals["wren"] == 10                    # one manifest, one settlement


def test_score_is_not_transferable_by_construction(claim_factory):
    """Twenty pseudonyms at 10 points is not one pseudonym at 200."""
    claims = [claim_factory(claimant=n, proposition=f"Source S asserts X at {n}, and it does not.")
              for n in ("wren", "slate", "chalk")]
    totals = core.score(claims, [verdict(c["claim_id"], "keel") for c in claims])
    assert set(totals) == {"wren", "slate", "chalk", "keel"}
    assert all(totals[n] == 10 for n in ("wren", "slate", "chalk"))


def test_empty_log_scores_empty():
    assert core.score([], []) == {}


def test_breakdown_publishes_the_failure_rate(claim_factory):
    good, bad = claim_factory(), claim_factory(proposition="Source T asserts Y, and it does not.")
    rows = core.breakdown([good, bad], [verdict(good["claim_id"], "slate", "PASS"),
                                        verdict(bad["claim_id"], "slate", "FAIL")])
    assert rows["wren"]["failure_rate"] == 50
    assert rows["wren"]["PASS"] == 1 and rows["wren"]["FAIL"] == 1
