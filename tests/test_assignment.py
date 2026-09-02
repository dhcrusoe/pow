"""The draw must be recomputable by anyone and shoppable by nobody."""
from __future__ import annotations

import pow_core as core


def claims_for(n):
    return [{"claim_id": f"sha256:{i:064x}", "claimant": "wren"} for i in range(n)]


def test_you_are_never_assigned_your_own_claim():
    cs = claims_for(5)
    assert core.eligible(cs, [], [], "wren", "2026-09-01T00:00:00Z") == []
    assert len(core.eligible(cs, [], [], "slate", "2026-09-01T00:00:00Z")) == 5


def test_settled_claims_leave_the_queue():
    cs = claims_for(3)
    verdicts = [{"claim_id": cs[0]["claim_id"], "verifier": "keel"}]
    out = core.eligible(cs, verdicts, [], "slate", "2026-09-01T00:00:00Z")
    assert cs[0]["claim_id"] not in out and len(out) == 2


def test_an_unexpired_lease_held_by_someone_else_hides_the_claim():
    cs = claims_for(2)
    handouts = [{"claim_id": cs[0]["claim_id"], "verifier": "keel",
                 "expires_at": "2026-09-09T00:00:00Z"}]
    now = "2026-09-01T00:00:00Z"
    assert cs[0]["claim_id"] not in core.eligible(cs, [], handouts, "slate", now)
    # your own lease does not hide it from you
    assert cs[0]["claim_id"] in core.eligible(cs, [], handouts, "keel", now)


def test_an_expired_lease_returns_the_claim_to_the_pool():
    cs = claims_for(2)
    handouts = [{"claim_id": cs[0]["claim_id"], "verifier": "keel",
                 "expires_at": "2026-08-01T00:00:00Z"}]
    assert cs[0]["claim_id"] in core.eligible(cs, [], handouts, "slate",
                                              "2026-09-01T00:00:00Z")


def test_the_draw_is_deterministic_and_recomputable():
    cs = [c["claim_id"] for c in claims_for(20)]
    a = core.draw(cs, "PUBKEY", "headsha")
    assert a == core.draw(list(reversed(cs)), "PUBKEY", "headsha")


def test_the_draw_is_not_first_in_first_out():
    """FIFO over a public queue is a schedule, and a schedule can be raced."""
    cs = [c["claim_id"] for c in claims_for(40)]
    picks = {core.draw(cs, f"KEY{i}", "head") for i in range(12)}
    assert picks != {cs[0]}, "every verifier drew the queue head"
    assert len(picks) > 1


def test_a_verifier_cannot_shop_the_queue():
    """Your draw is fixed by who you are, not by which claim you would prefer."""
    cs = [c["claim_id"] for c in claims_for(30)]
    mine = core.draw(cs, "MYKEY", "head")
    assert all(core.draw(cs, "MYKEY", "head") == mine for _ in range(10))
    assert core.draw(cs, "OTHERKEY", "head") != mine or len(cs) == 1


def test_the_draw_moves_when_the_log_moves():
    cs = [c["claim_id"] for c in claims_for(30)]
    assert core.draw(cs, "KEY", "head-one") != core.draw(cs, "KEY", "head-two")


def test_an_empty_queue_draws_nothing():
    assert core.draw([], "KEY", "head") is None
