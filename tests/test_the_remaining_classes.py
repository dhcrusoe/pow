"""The six classes that were advertised and could not be used.

For most of this network's life exactly one class worked. E2 carried every claim,
and six agents surveying six domains independently proposed forty projects that
were all E2 or open path — not for lack of imagination, but because it was the
only door that opened. These tests cover the others.

The change that made them buildable was giving up bit-identity. Verification in
the human world is rarely exact; requiring two strangers to own the same machine
bought a guarantee nobody needed at a price nobody would pay. What replaced it is
a band, and what enforces honesty about the band is a seal.
"""
from __future__ import annotations

import hashlib

import httpx
import pytest

import pow_core as core
from pow_core import seals
from pow_core.validate import REQUIRED_MANIFEST, _interval
from pow_verify import e1, e3, e4, e5, e7, pinned

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


# --- E1: declared replay ---------------------------------------------------

def test_e1_settles_on_the_verifiers_own_number_not_the_claimants(monkeypatch):
    serve(monkeypatch)
    m = {"procedure": "recount the rows", "inputs": SRC, "expected": band(150, 100, 200)}
    assert e1.check(m)[0] == "UNRESOLVABLE"          # nobody has done the work
    assert e1.check(m, observed={"value": 149})[0] == "PASS"
    assert e1.check(m, observed={"value": 301})[0] == "FAIL"


def test_e1_still_demands_exactness_where_exactness_is_the_point(monkeypatch):
    """A band is for findings. An artifact either comes back or it does not."""
    serve(monkeypatch)
    m = {"procedure": "rebuild the archive", "inputs": SRC,
         "expected": {"digest": DIGEST}}
    assert e1.check(m, observed={"digest": DIGEST})[0] == "PASS"
    assert e1.check(m, observed={"digest": "0" * 64})[0] == "FAIL"


def test_e1_no_longer_asks_anyone_for_a_container():
    assert "image" not in dict.fromkeys(REQUIRED_MANIFEST["E1"])
    assert set(REQUIRED_MANIFEST["E1"]) == {"procedure", "inputs",
                                                          "expected"}


# --- E3: attested partner metric -------------------------------------------

def signed_reply(key, nonce, value=150, scale=-2, metric="beds_available"):
    rec = {"metric": metric, "value": value, "scale": scale, "nonce": nonce}
    rec["signature"] = core.sign(rec, key)
    return rec


def test_e3_challenges_the_partner_with_a_nonce_it_has_never_seen(monkeypatch):
    priv, pub = core.generate()
    def fake_get(url, params=None, **kw):
        reply = signed_reply(priv, params["nonce"])
        return httpx.Response(200, json=reply, request=httpx.Request("GET", url))
    monkeypatch.setattr(httpx, "get", fake_get)
    m = {"partner": "Mercy Clinic", "partner_public_key": pub,
         "endpoint": "https://mercy.invalid/metric", "metric": "beds_available",
         "claimed": band(150, 100, 200), "fetched_at": "2026-09-01"}
    verdict, _, diag = e3.check(m)
    assert verdict == "PASS" and "never seen" in diag


def test_e3_refuses_a_recording(monkeypatch):
    """A reply that ignores this challenge proves the metric was true once, to
    somebody, at a moment the claimant chose."""
    priv, pub = core.generate()
    def fake_get(url, params=None, **kw):
        reply = signed_reply(priv, "a-nonce-from-yesterday")
        return httpx.Response(200, json=reply, request=httpx.Request("GET", url))
    monkeypatch.setattr(httpx, "get", fake_get)
    m = {"partner": "Mercy Clinic", "partner_public_key": pub,
         "endpoint": "https://mercy.invalid/metric", "metric": "beds_available",
         "claimed": band(150, 100, 200), "fetched_at": "2026-09-01"}
    verdict, _, diag = e3.check(m)
    assert verdict == "FAIL" and "recording" in diag


def test_e3_refuses_an_endpoint_signing_with_the_wrong_key(monkeypatch):
    priv, pub = core.generate()
    other_priv, _ = core.generate()
    def fake_get(url, params=None, **kw):
        return httpx.Response(200, json=signed_reply(other_priv, params["nonce"]),
                              request=httpx.Request("GET", url))
    monkeypatch.setattr(httpx, "get", fake_get)
    m = {"partner": "Mercy Clinic", "partner_public_key": pub,
         "endpoint": "https://mercy.invalid/metric", "metric": "beds_available",
         "claimed": band(150, 100, 200), "fetched_at": "2026-09-01"}
    assert e3.check(m)[0] == "FAIL"


def test_e3_treats_a_partner_being_down_as_nobodys_fault(monkeypatch):
    _, pub = core.generate()
    def fake_get(url, params=None, **kw):
        raise httpx.ConnectError("no route")
    monkeypatch.setattr(httpx, "get", fake_get)
    m = {"partner": "Mercy Clinic", "partner_public_key": pub,
         "endpoint": "https://mercy.invalid/metric", "metric": "beds_available",
         "claimed": band(150, 100, 200), "fetched_at": "2026-09-01"}
    verdict, _, diag = e3.check(m)
    assert verdict == "UNRESOLVABLE" and "Nothing is owed by the claimant" in diag


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
    seal = seal_for(plan, cls="E5")
    verdict, _ = seals.check_seal({"plan": plan, "plan_salt": SALT}, seal,
                                  intended_class="E7")
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


# --- E5: prospective settlement --------------------------------------------

def e5_manifest(resolves="2026-06-01"):
    pred = {"statement": "the register will list fewer than 40 sites",
            "resolves_on": resolves}
    return pred, {"seal_url": "https://log.invalid/seal.json", "plan_salt": SALT,
                  "prediction": pred, "resolves_on": resolves, "resolution": SRC,
                  "outcome": "the register listed 31 sites"}


def test_e5_will_not_settle_before_the_world_answers(monkeypatch):
    from datetime import date
    serve(monkeypatch)
    pred, m = e5_manifest()
    seal = seal_for(pred, cls="E5")
    verdict, _, diag = e5.check(m, seal=seal, now=date(2026, 3, 1))
    assert verdict == "UNRESOLVABLE"
    assert "Not wrong yet" in diag


def test_e5_settles_on_the_verifiers_reading_of_the_pinned_sources(monkeypatch):
    from datetime import date
    serve(monkeypatch)
    pred, m = e5_manifest()
    seal = seal_for(pred, cls="E5")
    assert e5.check(m, seal=seal, now=date(2026, 7, 1))[0] == "UNRESOLVABLE"
    assert e5.check(m, seal=seal, now=date(2026, 7, 1),
                    observed={"resolved": True})[0] == "PASS"
    assert e5.check(m, seal=seal, now=date(2026, 7, 1),
                    observed={"resolved": False})[0] == "FAIL"


def test_a_prediction_sealed_after_its_resolution_date_is_a_report(monkeypatch):
    from datetime import date
    serve(monkeypatch)
    pred, m = e5_manifest(resolves="2026-06-01")
    seal = seal_for(pred, cls="E5", sealed_at="2026-08-01")
    verdict, _, diag = e5.check(m, seal=seal, now=date(2026, 9, 1))
    assert verdict == "FAIL" and "is a report" in diag


# --- E7: aggregate study ---------------------------------------------------

def e7_manifest(**over):
    plan = {"design": "synthetic-control", "data_published_on": "2026-08-01",
            "estimate_band": {"scale": -2, "unit": "ug_m3", "lo": -212, "hi": -162}}
    m = {"seal_url": "https://log.invalid/seal.json", "plan_salt": SALT, "plan": plan,
         "data_sources": SRC, "population": "residents inside the zone boundary",
         "estimate": band(-187, -212, -162, unit="ug_m3"),
         "refuses": "Says the analysis reproduces. Says nothing about cause."}
    m.update(over)
    return plan, m


def test_e7_settles_on_an_independent_re_run(monkeypatch):
    serve(monkeypatch)
    plan, m = e7_manifest()
    seal = seal_for(plan, cls="E7")
    assert e7.check(m, seal=seal)[0] == "UNRESOLVABLE"
    assert e7.check(m, seal=seal, observed={"value": -190})[0] == "PASS"
    assert e7.check(m, seal=seal, observed={"value": -20})[0] == "FAIL"


def test_e7_refuses_a_plan_sealed_against_data_already_published(monkeypatch):
    """Sealing against numbers already in the world commits to nothing."""
    serve(monkeypatch)
    plan, m = e7_manifest()
    seal = seal_for(plan, cls="E7", sealed_at="2026-09-01")   # after the vintage
    verdict, _, diag = e7.check(m, seal=seal, observed={"value": -190})
    assert verdict == "FAIL" and "already in the world" in diag


def test_e7_refuses_a_claim_that_will_not_say_what_it_does_not_prove(monkeypatch):
    serve(monkeypatch)
    plan, m = e7_manifest(refuses="   ")
    seal = seal_for(plan, cls="E7")
    verdict, _, diag = e7.check(m, seal=seal, observed={"value": -190})
    assert verdict == "FAIL" and "read as more than it is" in diag


def test_e7_requires_every_sealed_specification_to_be_reported(monkeypatch):
    """Twenty sealed, one reported, is the oldest trick in empirical work."""
    serve(monkeypatch)
    plan, m = e7_manifest()
    plan["specifications"] = ["primary", "no-covariates", "donor-cap"]
    m["plan"] = plan
    m["specifications"] = ["primary"]
    seal = seal_for(plan, cls="E7")
    verdict, _, diag = e7.check(m, seal=seal, observed={"value": -190})
    assert verdict == "FAIL" and "the one you show is the one that worked" in diag


def test_every_class_now_has_a_checker():
    from pow_verify.__main__ import CHECKS
    assert set(CHECKS) == {"E1", "E2", "E3", "E4", "E5", "E6", "E7"}
