"""E4 and the seal machinery it depends on.

Genesis had seven classes and, for most of this network's life, exactly one
worked: E2 carried every claim. E1, E3, E5 and E7 were then cut — none had ever
been filed, and each was either redundant (E3 is E6 with a heavier bar, E7 is E4
at population scale) or needed infrastructure and lead time the network has no
volume for. What is left on the sealed path beyond E2 and E6 is E4: redo the work
blind, land inside a band the claimant sealed before starting. These tests cover
E4 and the seal that keeps the band honest.
"""
from __future__ import annotations

import hashlib

import httpx
import pytest
from pow_core import seals
from pow_core.validate import _interval
from pow_verify import e4

BODY = b'{"rows": 4}'
DIGEST = hashlib.sha256(BODY).hexdigest()
SALT = "ab" * 20
SRC = [{"url": "https://example.invalid/data.json", "snapshot_sha256": DIGEST}]


def serve(monkeypatch, body=BODY, status=200):
    def fake_get(url, **kw):
        return httpx.Response(status, content=body, request=httpx.Request("GET", url))
    monkeypatch.setattr(httpx, "get", fake_get)


def band(value, lo, hi, scale=-2, unit="pp"):
    return {"value": value, "scale": scale, "unit": unit, "lo": lo, "hi": hi}


def seal_for(plan, sealer="claimant", cls="", sealed_at="2026-01-01"):
    return {"sealer": sealer, "intended_class": cls, "sealed_at": sealed_at,
            "commitment": seals.commitment(plan, SALT)}


# --- the band itself -------------------------------------------------------

def test_a_band_is_integers_and_a_scale_never_a_float():
    """Giving up exactness did not give up the no-floats rule; it needed it."""
    assert _interval(band(150, 100, 200))
    assert not _interval({"value": 1.5, "scale": 0, "unit": "x",
                                        "lo": 1, "hi": 2})


def test_a_band_of_width_zero_is_refused():
    """lo == hi is exactness through the back door, and exactness is what we dropped."""
    assert not _interval(band(100, 100, 100))


def test_a_band_that_excludes_its_own_estimate_is_refused():
    assert not _interval(band(500, 100, 200))


# --- seals: the anti-fishing hinge -----------------------------------------

def test_a_plan_edited_after_sealing_does_not_open_the_commitment():
    plan = {"design": "its", "threshold": band(150, 100, 200)}
    seal = seal_for(plan)
    verdict, diag = seals.check_seal({"plan": plan, "plan_salt": SALT}, seal)
    assert verdict == ""
    edited = dict(plan, design="did")
    verdict, diag = seals.check_seal({"plan": edited, "plan_salt": SALT}, seal)
    assert verdict == "FAIL" and "did not bind" in diag


def test_a_seal_someone_else_placed_is_not_your_commitment():
    plan = {"design": "its"}
    seal = seal_for(plan, sealer="someone-else")
    verdict, _ = seals.check_seal({"plan": plan, "plan_salt": SALT}, seal,
                                  claimant="me")
    assert verdict == "FAIL"


def test_a_seal_placed_for_another_class_does_not_transfer():
    """A commitment is to one procedure, not to whichever one turns out to work."""
    plan = {"design": "its"}
    seal = seal_for(plan, cls="E4")
    verdict, _ = seals.check_seal({"plan": plan, "plan_salt": SALT}, seal,
                                  intended_class="E8")
    assert verdict == "FAIL"


def test_an_unfetchable_seal_is_unresolvable_not_a_failure():
    verdict, diag = seals.check_seal({"plan": {"a": 1}, "plan_salt": SALT}, None)
    assert verdict == "UNRESOLVABLE" and "Nothing is owed by the claimant" in diag


def test_a_short_salt_is_refused_because_a_small_plan_space_is_guessable():
    with pytest.raises(ValueError):
        seals.commitment({"design": "its"}, "abcd")


# --- E4: adversarial reproduction ------------------------------------------

def e4_manifest(threshold=None, result=None):
    threshold = threshold or band(150, 100, 200)
    plan = {"task": "recount", "threshold": threshold}
    return plan, {"seal_url": "https://log.invalid/seal.json", "plan_salt": SALT,
                  "plan": plan, "inputs": SRC, "threshold": threshold,
                  "result": result or band(150, 100, 200)}


def test_e4_settles_on_a_blind_reproduction(monkeypatch):
    serve(monkeypatch)
    plan, m = e4_manifest()
    seal = seal_for(plan, cls="E4")
    assert e4.check(m, seal=seal)[0] == "UNRESOLVABLE"
    assert e4.check(m, seal=seal, observed={"value": 148})[0] == "PASS"
    assert e4.check(m, seal=seal, observed={"value": 240})[0] == "FAIL"


def test_e4_refuses_a_threshold_widened_after_the_result(monkeypatch):
    """The seal exists to stop exactly this, so it must be caught before the redo."""
    serve(monkeypatch)
    plan, m = e4_manifest()
    seal = seal_for(plan, cls="E4")
    m["threshold"] = band(150, 0, 100000)
    verdict, _, diag = e4.check(m, seal=seal, observed={"value": 150})
    assert verdict == "FAIL" and "sealed plan" in diag


def test_e4_fails_a_claim_that_misses_its_own_band(monkeypatch):
    serve(monkeypatch)
    plan, m = e4_manifest(result=band(150, 100, 200))
    m["result"] = {"value": 900, "scale": -2, "unit": "pp", "lo": 100, "hi": 200}
    seal = seal_for(plan, cls="E4")
    verdict, _, diag = e4.check(m, seal=seal)
    assert verdict == "FAIL" and "on its own terms" in diag


def test_the_sealed_path_has_exactly_three_checkers():
    from pow_verify.__main__ import CHECKS
    assert set(CHECKS) == {"E2", "E4", "E6"}
