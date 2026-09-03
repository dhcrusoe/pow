"""The open path: any action, verified as well as strangers can manage.

The sealed path only recognises work that fits a procedure somebody imagined in
advance, which is a permanent failure of imagination encoded as a safety
property. The open path takes anything, and substitutes independent agreement
for certainty. What must not change is that score stays uninflatable by opinion.
"""
from __future__ import annotations

import json

import pytest

import pow_core as core
from pow_generate import build


@pytest.fixture
def site(log, tmp_path):
    out = tmp_path / "site"
    build(log, out, api_base="https://api.invalid")
    return out


def V(cid, who, verdict="PASS", conf=None, at="2026-09-01T10:00:00Z", fraud=False):
    return {"claim_id": cid, "verifier": who, "verdict": verdict, "confidence": conf,
            "method": "", "assertions": [], "would_raise_confidence": "",
            "output_hash": "", "diagnosis": "", "magnitude": None,
            "fraud_caught": fraud, "settled_at": at, "signature": "x"}


@pytest.fixture
def open_claim(keys):
    def make(claimant="wren", **over):
        rec = {
            "claim_id": "", "claimant": claimant, "domain": 3, "path": "open",
            "evidence_class": None,
            "proposition": "Roughly 40 households were told about a benefit they qualify "
                           "for and had not claimed.",
            "why": "People were going without money the law already says is theirs.",
            "manifest": {},
            "action": "Emailed three food banks a list of local households likely "
                      "eligible for an unclaimed benefit, with the statutory test.",
            "beneficiary": "Three food banks and the households they serve",
            "evidence": [{"kind": "email", "to": "a food bank",
                          "sent_at": "2026-09-01T09:00:00Z",
                          "body_sha256": "a" * 64}],
            "how_to_check": "Ask the food banks whether they received it and used it.",
            "boundary": "no subject acts as evidence: no household is named",
            "costs": "", "resolves": "",
            "valid_as_of": "2026-09-01", "submitted_at": "2026-09-01T10:00:00Z",
            "signature": "",
        }
        rec.update(over)
        rec["claim_id"] = core.content_hash(rec, exclude=core.Claim.ID_EXCLUDES)
        rec["signature"] = core.sign(rec, keys[claimant]["private"])
        return rec
    return make


# --- an action nobody anticipated is now claimable ---

def test_an_action_with_no_evidence_class_validates(open_claim, keys):
    c = open_claim()
    core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"],
                  path=core.path_for(c, "claim"))
    assert c["evidence_class"] is None and not c["manifest"]


def test_evidence_shape_is_not_constrained(open_claim, keys):
    """The moment the schema dictates evidence shape, it is a whitelist again."""
    for evidence in (
        [{"kind": "phone call", "notes": "spoke to the duty manager on 1 Sept"}],
        [{"kind": "photo", "sha256": "b" * 64, "taken": "2026-09-01"}],
        [{"kind": "transcript", "url": "https://example.org/t.txt"}],
        [{"anything": "at all, so long as a verifier can act on it"}],
    ):
        c = open_claim(evidence=evidence)
        core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])


def test_a_claim_with_nothing_to_go_on_is_refused(open_claim, keys):
    c = open_claim(evidence=[], how_to_check="")
    with pytest.raises(core.Rejection, match="nothing for a verifier to do"):
        core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])


def test_saying_only_what_you_did_is_not_enough(open_claim, keys):
    c = open_claim(action="did some good")
    with pytest.raises(core.Rejection, match="what you actually did"):
        core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])


def test_the_two_paths_do_not_mix(open_claim, keys, claim_factory):
    with pytest.raises(core.Rejection, match="path 'sealed'"):
        c = open_claim(manifest={"sources": []})
        core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])
    with pytest.raises(core.Rejection, match="path 'open'"):
        c = claim_factory(manifest={})
        core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])


# --- independent agreement replaces the deterministic re-run ---

def test_one_verifier_does_not_settle_an_open_claim(open_claim):
    c = open_claim()
    assert core.settle([c], [V(c["claim_id"], "slate")]) == []
    assert core.score([c], [V(c["claim_id"], "slate")])["wren"] == 0


def test_quorum_settles_it(open_claim):
    c = open_claim()
    vs = [V(c["claim_id"], w) for w in ("slate", "chalk", "keel")]
    e = core.settle([c], vs)[0]
    assert e["verdict"] == "PASS" and e["unanimous"] and e["agreement"] == 100
    assert core.score([c], vs)["wren"] == 10


def test_a_sealed_claim_still_settles_on_one(claim_factory):
    c = claim_factory()
    assert len(core.settle([c], [V(c["claim_id"], "slate")])) == 1


def test_the_majority_decides_and_the_dissent_is_kept(open_claim):
    c = open_claim()
    vs = [V(c["claim_id"], "slate", "PASS"), V(c["claim_id"], "chalk", "PASS"),
          V(c["claim_id"], "keel", "FAIL", at="2026-09-01T11:00:00Z")]
    e = core.settle([c], vs)[0]
    assert e["verdict"] == "PASS" and e["agreement"] == 67 and not e["unanimous"]
    assert e["dissent"] == [{"verifier": "keel", "verdict": "FAIL", "diagnosis": ""}]


def test_a_tied_quorum_settles_nothing(open_claim):
    """Disagreement is a finding. It is not an excuse to pick one."""
    c = open_claim()
    vs = [V(c["claim_id"], "slate", "PASS"), V(c["claim_id"], "chalk", "FAIL"),
          V(c["claim_id"], "keel", "UNRESOLVABLE")]
    assert core.settle([c], vs) == []
    assert core.score([c], vs)["wren"] == 0


def test_one_agent_cannot_be_its_own_quorum(open_claim):
    c = open_claim()
    vs = [V(c["claim_id"], "slate", at=f"2026-09-0{i}T10:00:00Z") for i in (1, 2, 3)]
    assert core.settle([c], vs) == [], "three verdicts from one agent is not independence"


def test_verifiers_are_paid_even_when_quorum_never_arrives(open_claim):
    """A verifier cannot control whether four other agents show up."""
    c = open_claim()
    assert core.score([c], [V(c["claim_id"], "slate")])["slate"] == core.VERIFICATION


# --- grey enters the record, never the number ---

def test_confidence_is_recorded_and_never_scored(open_claim):
    c = open_claim()
    low = [V(c["claim_id"], w, conf=conf) for w, conf in
           (("slate", 51), ("chalk", 55), ("keel", 60))]
    high = [V(c["claim_id"], w, conf=conf) for w, conf in
            (("slate", 99), ("chalk", 98), ("keel", 97))]
    assert core.score([c], low) == core.score([c], high)
    assert core.settle([c], low)[0]["confidence_mean"] == 55
    assert core.settle([c], high)[0]["confidence_mean"] == 98


def test_the_spread_is_published_not_collapsed(open_claim):
    c = open_claim()
    vs = [V(c["claim_id"], w, conf=conf) for w, conf in
          (("slate", 40), ("chalk", 70), ("keel", 95))]
    e = core.settle([c], vs)[0]
    assert (e["confidence_low"], e["confidence_high"]) == (40, 95)
    assert e["confidence_mean"] == 68


def test_a_verdict_can_answer_a_proposition_part_by_part(keys):
    """Five judgments used to be compressed into one enum and buried in prose."""
    v = V("sha256:x", "slate", "PASS", conf=85)
    v["assertions"] = [
        {"claim": "the digest matches", "result": "confirmed"},
        {"claim": "119 records", "result": "confirmed"},
        {"claim": "tokenizes to 5d16", "result": "arguable",
         "note": "parser-dependent; a whitespace splitter simply fails to parse"},
    ]
    v["method"] = "Re-fetched the source cold and re-derived every element."
    v["would_raise_confidence"] = "A second parser agreeing on the tokenization."
    v["signature"] = core.sign(v, keys["slate"]["private"])
    core.validate(core.canonicalize(v), "verdict", public_key=keys["slate"]["public"],
                  path=core.path_for(v, "verdict"))


@pytest.mark.parametrize("bad", [-1, 101, 150])
def test_confidence_stays_within_bounds(keys, bad):
    v = V("sha256:x", "slate", "PASS", conf=bad)
    v["signature"] = core.sign(v, keys["slate"]["private"])
    with pytest.raises(core.Rejection, match="confidence"):
        core.validate(core.canonicalize(v), "verdict", public_key=keys["slate"]["public"])


def test_confidence_is_optional(keys):
    v = V("sha256:x", "slate", "PASS")
    v["signature"] = core.sign(v, keys["slate"]["private"])
    core.validate(core.canonicalize(v), "verdict", public_key=keys["slate"]["public"])


# --- the queue serves quorum ---

def test_an_open_claim_stays_in_the_pool_until_it_has_enough_verifiers(open_claim):
    c = open_claim(claimant="slate")
    cid = c["claim_id"]
    now = "2026-09-02T00:00:00Z"
    lease = [{"claim_id": cid, "verifier": "chalk", "issued_at": now,
              "expires_at": "2026-09-09T00:00:00Z"}]
    assert cid in core.eligible([c], [], lease, "wren", now), \
        "one lease should not hide a claim that needs three verifiers"
    two = lease + [{"claim_id": cid, "verifier": "keel", "issued_at": now,
                    "expires_at": "2026-09-09T00:00:00Z"}]
    assert cid in core.eligible([c], [], two, "wren", now)
    three = two + [{"claim_id": cid, "verifier": "quiet", "issued_at": now,
                    "expires_at": "2026-09-09T00:00:00Z"}]
    assert cid not in core.eligible([c], [], three, "wren", now), "quorum already covered"


def test_you_are_not_handed_a_claim_you_already_ruled_on(open_claim):
    c = open_claim(claimant="slate")
    cid = c["claim_id"]
    assert cid not in core.eligible([c], [V(cid, "wren")], [], "wren",
                                    "2026-09-02T00:00:00Z")


def test_a_sealed_claim_leaves_the_pool_after_one_lease(claim_factory):
    c = claim_factory(claimant="slate")
    now = "2026-09-02T00:00:00Z"
    lease = [{"claim_id": c["claim_id"], "verifier": "chalk", "issued_at": now,
              "expires_at": "2026-09-09T00:00:00Z"}]
    assert c["claim_id"] not in core.eligible([c], [], lease, "wren", now)


# --- the collapse rule still holds on the open path ---

def test_the_same_action_twice_scores_once(open_claim):
    a = open_claim(submitted_at="2026-09-01T10:00:00Z")
    b = open_claim(submitted_at="2026-09-02T10:00:00Z")
    assert a["claim_id"] != b["claim_id"]
    vs = ([V(a["claim_id"], w) for w in ("slate", "chalk", "keel")]
          + [V(b["claim_id"], w) for w in ("slate", "chalk", "keel")])
    assert core.score([a, b], vs)["wren"] == 10


# An agent did real outward-facing work, then could not file it. Three things
# stopped it, and none of them were about the work: a field name it had to guess,
# a default that contradicted the advice, and no example of the path it was told
# to prefer.

def test_an_unknown_field_names_the_fields_that_exist():
    """'timestamp: Extra inputs are not permitted' names the wrong field and no
    right one. The agent guessed again."""
    rec = {"claim_id": "sha256:" + "0" * 64, "claimant": "someone", "domain": 1,
           "proposition": "a proposition long enough to pass", "boundary": "none",
           "valid_as_of": "2026-01-01", "submitted_at": "2026-01-01",
           "timestamp": "2026-01-01", "signature": "x"}
    with pytest.raises(core.Rejection) as got:
        core.validate(core.canonicalize(rec), "claim", public_key=None,
                      path="claims/x.json")
    detail = got.value.detail
    assert "submitted_at" in detail            # the field it actually wanted
    assert "Extra inputs are not permitted" not in detail


def test_the_default_path_is_the_one_the_documentation_recommends():
    """llms.txt says take the open path unless the sealed one genuinely fits.
    The default was sealed, so an agent that omitted the field got the
    restrictive path and a refusal."""
    assert core.records.Claim.model_fields["path"].default == "open"


def test_an_open_shaped_claim_marked_sealed_is_told_exactly_what_to_change():
    rec = {"claim_id": "sha256:" + "0" * 64, "claimant": "someone", "domain": 1,
           "path": "sealed", "proposition": "a proposition long enough to pass",
           "action": "did the thing", "evidence": [{"url": "https://x.invalid"}],
           "how_to_check": "fetch it", "boundary": "none",
           "valid_as_of": "2026-01-01", "submitted_at": "2026-01-01", "signature": "x"}
    with pytest.raises(core.Rejection) as got:
        core.validate(core.canonicalize(rec), "claim", public_key=None,
                      path="claims/x.json")
    assert '"path": "open"' in got.value.detail
    assert "/examples/open-claim.json" in got.value.detail


def test_the_open_path_has_a_worked_example_that_validates(site):
    """Every published example was sealed, on a network that recommends open."""
    ex = json.loads((site / "examples" / "open-claim.json").read_text("utf-8"))
    rec = ex["record"]
    assert rec["path"] == "open"
    assert "evidence_class" not in rec and not rec.get("manifest")
    core.validate(core.canonicalize(rec), "claim", public_key=None,
                  path=core.path_for(rec, "claim"))
    assert ex["signed_bytes"] and ex["canonical_bytes"]
