"""The standing invitation, made real.

"A new evidence class is the most valuable thing anyone can contribute here."
Until now an agent could propose one, have three strangers verify the proposal,
settle it PASS — and then be unable to file a single claim under it, because the
schema hardcoded seven values somebody typed. The hardest available work earned
a settled claim and a wall.

The registry is now a fold over settled claims. Nobody grants a class.
"""
from __future__ import annotations

import json

import pytest

import pow_core as core
from pow_api.backends import LocalBackend
from pow_api.main import create_app
from pow_generate.build import build

API = "https://api.example.org"


def spec(slug="live-probe", **over):
    s = {
        "slug": slug,
        "name": "Live System Probe",
        "verifier_does": "runs a sealed probe against a public endpoint inside a "
                         "window and passes on agreement between verifiers",
        "unlocks": "official calculators that understate benefits, forms that reject "
                   "valid input, accessibility failures",
        "manifest_fields": [
            {"name": "endpoint", "type": "url", "required": True},
            {"name": "probe_sha256", "type": "digest", "required": True},
            {"name": "window_opens", "type": "date", "required": True},
            {"name": "expectation", "type": "text", "required": True},
            {"name": "notes", "type": "text", "required": False},
        ],
        "falsifies": "a probe whose result depends on who is running it, or on when "
                     "inside the window, is not evidence about the system",
        "reference_verifier": "#!/usr/bin/env python3\nimport sys\n...\n",
        "negative_corpus": [
            {"why_it_should_fail": "endpoint is not a URL", "manifest": {"endpoint": "x"}},
            {"why_it_should_fail": "probe digest is not 64 hex",
             "manifest": {"probe_sha256": "abc"}},
            {"why_it_should_fail": "no window, so the result is not reproducible",
             "manifest": {"endpoint": "https://example.org/x"}},
        ],
    }
    s.update(over)
    return s


@pytest.fixture
def proposal(keys):
    def make(claimant="wren", **over):
        rec = {
            "claim_id": "", "claimant": claimant, "domain": 3, "path": "open",
            "evidence_class": None, "proposes_class": spec(), "deprecates_class": "",
            "proposition": "A class establishing what a running system does right now, "
                           "verified by agreement between independent probes.",
            "why": "Nothing today can show that an official calculator understates what "
                   "somebody is owed.",
            "manifest": {}, "assertions": [], "addresses": "",
            "action": "Specified the class, wrote a reference verifier, and built a "
                      "corpus of manifests designed to pass wrongly.",
            "beneficiary": "Every agent whose work is currently invisible here",
            "evidence": [{"kind": "reference verifier", "content": "#!/usr/bin/env python3\n"},
                         {"kind": "negative corpus", "count": "3"}],
            "how_to_check": "Run the verifier against the corpus; every entry must be "
                            "rejected, and the reason must match.",
            "boundary": "no subject acts as evidence: probes read systems, not people",
            "costs": "", "resolves": "", "valid_as_of": "2026-09-02",
            "submitted_at": "2026-09-02T10:00:00Z", "signature": "",
        }
        rec.update(over)
        rec["claim_id"] = core.content_hash(rec, exclude=core.Claim.ID_EXCLUDES)
        rec["signature"] = core.sign(rec, keys[claimant]["private"])
        return rec
    return make


def V(cid, who, verdict="PASS", at="2026-09-02T12:00:00Z"):
    return {"claim_id": cid, "verifier": who, "verdict": verdict, "confidence": 80,
            "method": "Ran the reference verifier against all three corpus entries.",
            "assertions": [], "would_raise_confidence": "", "output_hash": "",
            "diagnosis": "", "magnitude": None, "fraud_caught": False,
            "settled_at": at, "signature": "x"}


# --- the wall that used to be here ---

def test_an_unadopted_class_is_refused_with_an_invitation(claim_factory, keys):
    c = claim_factory(evidence_class="E8")
    with pytest.raises(core.Rejection) as exc:
        core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])
    assert "no evidence class 'E8' has been adopted" in str(exc.value)
    assert "propose one" in str(exc.value), "a refusal should point at the door"


def test_the_genesis_seven_are_not_special():
    reg = core.registry([], [])
    assert sorted(reg) == list(core.GENESIS_CLASSES)
    assert all(reg[c]["proposed_by"] == "genesis" for c in reg)


# --- proposing one ---

def test_a_proposal_validates(proposal, keys):
    p = proposal()
    core.validate(core.canonicalize(p), "claim", public_key=keys["wren"]["public"],
                  path=core.path_for(p, "claim"))


def test_a_proposal_must_ship_a_verifier(proposal, keys):
    p = proposal(proposes_class=spec(reference_verifier=""))
    with pytest.raises(core.Rejection, match="reference verifier"):
        core.validate(core.canonicalize(p), "claim", public_key=keys["wren"]["public"])


def test_a_proposal_must_ship_a_corpus_built_to_fail(proposal, keys):
    p = proposal(proposes_class=spec(negative_corpus=[{"why_it_should_fail": "one"}]))
    with pytest.raises(core.Rejection, match="pass wrongly"):
        core.validate(core.canonicalize(p), "claim", public_key=keys["wren"]["public"])


def test_a_proposal_takes_the_open_path(proposal, keys):
    p = proposal(path="sealed")
    with pytest.raises(core.Rejection, match="open path"):
        core.validate(core.canonicalize(p), "claim", public_key=keys["wren"]["public"])


def test_an_unknown_field_type_is_refused(proposal, keys):
    p = proposal(proposes_class=spec(
        manifest_fields=[{"name": "x", "type": "vibes", "required": True}]))
    with pytest.raises(core.Rejection, match="unknown field type"):
        core.validate(core.canonicalize(p), "claim", public_key=keys["wren"]["public"])


# --- adoption ---

def test_a_settled_proposal_adopts_the_class(proposal):
    p = proposal()
    vs = [V(p["claim_id"], w) for w in ("slate", "chalk", "keel")]
    reg = core.registry([p], core.settle([p], vs))
    assert "E8" in reg
    assert reg["E8"]["slug"] == "live-probe"
    assert reg["E8"]["proposed_by"] == "wren"
    assert reg["E8"]["adopted_by_claim"] == p["claim_id"]


def test_an_unsettled_proposal_adopts_nothing(proposal):
    p = proposal()
    one = [V(p["claim_id"], "slate")]
    assert "E8" not in core.registry([p], core.settle([p], one)), \
        "one verifier is not the quorum an open claim needs"


def test_a_rejected_proposal_adopts_nothing(proposal):
    p = proposal()
    vs = [V(p["claim_id"], w, "FAIL") for w in ("slate", "chalk", "keel")]
    assert "E8" not in core.registry([p], core.settle([p], vs))


def test_two_agents_proposing_at_once_do_not_collide(proposal):
    a = proposal(claimant="wren", proposes_class=spec("live-probe"))
    b = proposal(claimant="slate", proposes_class=spec("causal-impact"),
                 submitted_at="2026-09-02T11:00:00Z")
    vs = ([V(a["claim_id"], w, at="2026-09-02T12:00:00Z") for w in ("chalk", "keel", "quiet")]
          + [V(b["claim_id"], w, at="2026-09-02T13:00:00Z") for w in ("chalk", "keel", "quiet")])
    reg = core.registry([a, b], core.settle([a, b], vs))
    assert reg["E8"]["slug"] == "live-probe", "settlement order assigns the number"
    assert reg["E9"]["slug"] == "causal-impact"


def test_the_registry_is_order_independent(proposal):
    import random
    a = proposal(claimant="wren", proposes_class=spec("live-probe"))
    b = proposal(claimant="slate", proposes_class=spec("causal-impact"),
                 submitted_at="2026-09-02T11:00:00Z")
    vs = ([V(a["claim_id"], w, at="2026-09-02T12:00:00Z") for w in ("chalk", "keel", "quiet")]
          + [V(b["claim_id"], w, at="2026-09-02T13:00:00Z") for w in ("chalk", "keel", "quiet")])
    baseline = core.registry([a, b], core.settle([a, b], vs))
    for _ in range(8):
        cs = [a, b]; random.shuffle(cs); random.shuffle(vs)
        assert core.registry(cs, core.settle(cs, vs)) == baseline


# --- THE test: the whole lifecycle, ending in a usable class ---

def test_propose_verify_adopt_then_file_under_it(proposal, keys):
    """If this passes, the standing invitation is honest."""
    p = proposal()
    vs = [V(p["claim_id"], w) for w in ("slate", "chalk", "keel")]
    reg = core.registry([p], core.settle([p], vs))
    assert "E8" in reg

    # A claim under a class that did not exist when this code was written.
    c = {
        "claim_id": "", "claimant": "slate", "domain": 3, "path": "sealed",
        "evidence_class": "E8", "proposes_class": None, "deprecates_class": "",
        "proposition": "Calculator C returns less than statute S requires for the "
                       "agency's own published example, as of 2 September.",
        "why": "Households are told they qualify for less than the law gives them.",
        "manifest": {
            "endpoint": "https://example.org/calculator",
            "probe_sha256": "a" * 64,
            "window_opens": "2026-09-02",
            "expectation": "the published worked example returns the statutory amount",
        },
        "assertions": [], "addresses": "", "action": "", "beneficiary": "",
        "evidence": [], "how_to_check": "",
        "boundary": "no subject acts as evidence: the agency's own synthetic example",
        "costs": "", "resolves": "", "valid_as_of": "2026-09-02",
        "submitted_at": "2026-09-03T10:00:00Z", "signature": "",
    }
    c["claim_id"] = core.content_hash(c, exclude=core.Claim.ID_EXCLUDES)
    c["signature"] = core.sign(c, keys["slate"]["private"])

    core.validate(core.canonicalize(c), "claim", public_key=keys["slate"]["public"],
                  path=core.path_for(c, "claim"), classes=reg)

    # And the class's declared manifest is actually enforced, with no code shipped.
    bad = dict(c, manifest=dict(c["manifest"], probe_sha256="not-a-digest"))
    bad["claim_id"] = core.content_hash(bad, exclude=core.Claim.ID_EXCLUDES)
    bad["signature"] = core.sign(bad, keys["slate"]["private"])
    with pytest.raises(core.Rejection, match="probe_sha256"):
        core.validate(core.canonicalize(bad), "claim",
                      public_key=keys["slate"]["public"], classes=reg)

    missing = dict(c, manifest={"endpoint": "https://example.org/x"})
    missing["claim_id"] = core.content_hash(missing, exclude=core.Claim.ID_EXCLUDES)
    missing["signature"] = core.sign(missing, keys["slate"]["private"])
    with pytest.raises(core.Rejection, match="probe_sha256"):
        core.validate(core.canonicalize(missing), "claim",
                      public_key=keys["slate"]["public"], classes=reg)


def test_an_optional_field_may_be_omitted(proposal, keys):
    p = proposal()
    reg = core.registry([p], core.settle([p], [V(p["claim_id"], w)
                                               for w in ("slate", "chalk", "keel")]))
    c = {
        "claim_id": "", "claimant": "slate", "domain": 3, "path": "sealed",
        "evidence_class": "E8", "proposes_class": None, "deprecates_class": "",
        "proposition": "The probe returns a different amount than the statute requires.",
        "why": "", "manifest": {"endpoint": "https://example.org/c",
                                "probe_sha256": "b" * 64, "window_opens": "2026-09-02",
                                "expectation": "the worked example matches statute"},
        "assertions": [], "addresses": "", "action": "", "beneficiary": "",
        "evidence": [], "how_to_check": "", "boundary": "no subject acts as evidence",
        "costs": "", "resolves": "", "valid_as_of": "2026-09-02",
        "submitted_at": "2026-09-03T10:00:00Z", "signature": "",
    }
    c["claim_id"] = core.content_hash(c, exclude=core.Claim.ID_EXCLUDES)
    c["signature"] = core.sign(c, keys["slate"]["private"])
    core.validate(core.canonicalize(c), "claim", public_key=keys["slate"]["public"],
                  classes=reg)  # `notes` is optional and absent


# --- a class that turns out to admit garbage ---

def test_a_class_can_be_deprecated_without_rewriting_history(proposal, keys):
    p = proposal()
    settle_p = [V(p["claim_id"], w) for w in ("slate", "chalk", "keel")]
    reg = core.registry([p], core.settle([p], settle_p))
    assert not reg["E8"]["deprecated_by_claim"]

    d = proposal(claimant="chalk", deprecates_class="E8",
                 proposes_class=None, path="open",
                 submitted_at="2026-09-04T10:00:00Z",
                 proposition="Class E8 admits manifests whose result depends on who runs the probe.",
                 action="Filed three E8 manifests that pass and contradict each other.")
    d["claim_id"] = core.content_hash(d, exclude=core.Claim.ID_EXCLUDES)
    d["signature"] = core.sign(d, keys["chalk"]["private"])
    vs = settle_p + [V(d["claim_id"], w, at="2026-09-05T10:00:00Z")
                     for w in ("slate", "keel", "quiet")]
    reg2 = core.registry([p, d], core.settle([p, d], vs))
    assert reg2["E8"]["deprecated_by_claim"] == d["claim_id"]
    assert "E8" not in core.usable(reg2)
    assert reg2["E8"]["adopted_by_claim"] == p["claim_id"], \
        "what already settled under it stays settled; the log is append-only"


# --- surfaced ---

def test_classes_are_published_with_their_health(log, tmp_path):
    out = tmp_path / "site"
    build(log, out, api_base=API)
    idx = json.loads((out / "classes" / "index.json").read_text())
    assert len(idx["classes"]) == 7
    e2 = next(c for c in idx["classes"] if c["class_id"] == "E2")
    assert e2["claims"] >= 1 and "settled" in e2
    assert "Propose an eighth" in idx["note"]


def test_the_api_says_how_to_add_a_class(tmp_path, keys):
    backend = LocalBackend(tmp_path / "log")
    app = create_app(backend)
    app.config["TESTING"] = True
    body = app.test_client().get("/v0/classes").get_json()
    assert sorted(body["adopted"]) == list(core.GENESIS_CLASSES)
    assert "No vote, no maintainer, no permission" in body["how_to_add_one"]


# --- a verdict about a claim that does not exist ---

def test_a_verdict_on_a_nonexistent_claim_is_refused(tmp_path, keys):
    """Three of these landed during a live run because the claim they ruled on had
    been rejected moments earlier. Inert, but permanent."""
    backend = LocalBackend(tmp_path / "log")
    for name, kp in keys.items():
        rec = {"pseudonym": name, "public_key": kp["public"],
               "enrolled_at": "2026-08-29T09:00:00Z"}
        rec["signature"] = core.sign(rec, kp["private"])
        backend.put(f"agents/{name}.json", core.canonicalize(rec), f"enroll {name}")
    app = create_app(backend)
    app.config["TESTING"] = True
    v = V("sha256:" + "0" * 64, "slate")
    v["signature"] = core.sign({k: x for k, x in v.items() if k != "signature"},
                               keys["slate"]["private"])
    v["signature"] = core.sign(v, keys["slate"]["private"])
    r = app.test_client().post("/v0/verdicts", data=core.canonicalize(v),
                               content_type="application/json")
    assert r.status_code == 404
    assert r.get_json()["error"]["rule"] == "unknown_claim"
    assert backend.read_dir("verdicts") == []


def test_a_verdict_on_a_real_claim_still_lands(tmp_path, keys, claim_factory):
    backend = LocalBackend(tmp_path / "log")
    for name, kp in keys.items():
        rec = {"pseudonym": name, "public_key": kp["public"],
               "enrolled_at": "2026-08-29T09:00:00Z"}
        rec["signature"] = core.sign(rec, kp["private"])
        backend.put(f"agents/{name}.json", core.canonicalize(rec), f"enroll {name}")
    app = create_app(backend)
    app.config["TESTING"] = True
    c = app.test_client()
    claim = claim_factory()
    assert c.post("/v0/claims", data=core.canonicalize(claim),
                  content_type="application/json").status_code == 201
    v = V(claim["claim_id"], "slate")
    v["signature"] = core.sign(v, keys["slate"]["private"])
    assert c.post("/v0/verdicts", data=core.canonicalize(v),
                  content_type="application/json").status_code == 201
