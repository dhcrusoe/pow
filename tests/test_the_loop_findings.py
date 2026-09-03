"""Regressions for what two independent agents found running the live loop.

A claimant and a verifier, neither having seen the spec or the code, completed
the protocol end to end and reported where it did not hold up. Each test here is
one of those findings.
"""
from __future__ import annotations

import json

import pytest

import pow_core as core
from pow_api.backends import LocalBackend
from pow_api.main import create_app
from pow_generate.build import build

API = "https://api.example.org"


@pytest.fixture
def site(log, tmp_path):
    out = tmp_path / "site"
    build(log, out, api_base=API)
    return out


# --- the draw promised it could not be shopped, and it could ---

def test_the_draw_seed_is_exactly_specified():
    seed = core.draw_seed("PK", "HEAD", "sha256:abc")
    assert seed == b"PK|HEAD|sha256:abc", "four readings were plausible; now there is one"


def test_a_verifier_can_recompute_its_own_draw():
    import hashlib
    cs = [f"sha256:{i:064x}" for i in range(20)]
    drawn = core.draw(cs, "PK", "HEAD")
    mine = min(cs, key=lambda c: hashlib.sha256(core.draw_seed("PK", "HEAD", c)).digest())
    assert drawn == mine


def test_the_head_moving_would_re_roll_the_bare_draw():
    """The finding, reproduced: this is why the lease has to exist."""
    cs = [f"sha256:{i:064x}" for i in range(30)]
    picks = {core.draw(cs, "PK", f"head{i}") for i in range(6)}
    assert len(picks) > 1, "if this ever passes, the lease is no longer load-bearing"


def test_an_unexpired_lease_makes_re_requesting_the_same_claim(claim_factory):
    cs = [claim_factory(claimant="slate",
                        proposition=f"Source S asserts X at version {i}, and it does not.")
          for i in range(20)]
    now = "2026-09-02T00:00:00Z"
    first = core.assign(cs, [], [], "wren", "PK", "head-one", now)
    lease = [{"claim_id": first, "verifier": "wren", "issued_at": now,
              "expires_at": "2026-09-09T00:00:00Z"}]
    for head in ("head-two", "head-three", "head-four", "head-five"):
        again = core.assign(cs, [], lease, "wren", "PK", head, now)
        assert again == first, "the head moved and the draw re-rolled"


def test_an_expired_lease_releases_you_for_a_new_draw(claim_factory):
    cs = [claim_factory(claimant="slate",
                        proposition=f"Source S asserts X at version {i}, and it does not.")
          for i in range(20)]
    stale = [{"claim_id": cs[0]["claim_id"], "verifier": "wren",
              "issued_at": "2026-08-01T00:00:00Z", "expires_at": "2026-08-04T00:00:00Z"}]
    got = core.assign(cs, [], stale, "wren", "PK", "head", "2026-09-02T00:00:00Z")
    assert got is not None


def test_settling_your_lease_releases_you(claim_factory):
    cs = [claim_factory(claimant="slate",
                        proposition=f"Source S asserts X at version {i}, and it does not.")
          for i in range(6)]
    now = "2026-09-02T00:00:00Z"
    held = cs[0]["claim_id"]
    lease = [{"claim_id": held, "verifier": "wren", "issued_at": now,
              "expires_at": "2026-09-09T00:00:00Z"}]
    settled = [{"claim_id": held, "verifier": "wren"}]
    assert core.assign(cs, settled, lease, "wren", "PK", "head", now) != held


# --- authorship rested on trusting the ingest service ---

def test_every_agents_public_key_is_published(site, log):
    idx = json.loads((site / "agents" / "index.json").read_text())
    enrolled = [json.loads(p.read_text()) for p in sorted((log / "agents").glob("*.json"))]
    assert enrolled, "fixture has no agents"
    for a in enrolled:
        assert idx["agents"][a["pseudonym"]]["public_key"] == a["public_key"]
        rec = json.loads((site / "agents" / a["pseudonym"] / "enrollment.json").read_text())
        core.verify(rec, rec["public_key"])


def test_a_stranger_can_check_authorship_of_a_claim(site, log):
    """The point of publishing keys: verify the claimant signed it, not the service."""
    claims = [json.loads(p.read_text()) for p in (log / "claims").glob("*.json")]
    idx = json.loads((site / "agents" / "index.json").read_text())
    for c in claims:
        core.verify(c, idx["agents"][c["claimant"]]["public_key"])


# --- nothing could be enumerated ---

def test_claims_and_verdicts_are_enumerable(site):
    c = json.loads((site / "claims" / "index.json").read_text())
    v = json.loads((site / "verdicts" / "index.json").read_text())
    assert c["claims"] and all("url" in x and "proposition" in x for x in c["claims"])
    assert isinstance(v["verdicts"], list)


def test_discovery_names_every_index_and_the_url_shape(site):
    wk = json.loads((site / ".well-known" / "pow.json").read_text())
    for key in ("claims", "verdicts", "agent_keys", "sitemap", "built_at"):
        assert key in wk["log"], f"{key} undiscoverable"
    assert "12 hex" in wk["url_shape"]["claim"]
    assert "stopwords" in wk["url_shape"]["slug"]
    assert wk["draw"]["seed"].startswith("utf8(")


def test_an_unverified_claim_is_visible_on_the_homepage(tmp_path, claim_factory):
    """The primary call to action is 'check someone else's'. It pointed at nothing."""
    logdir = tmp_path / "log"
    for d in ("claims", "verdicts", "seals", "handouts", "agents"):
        (logdir / d).mkdir(parents=True)
    c = claim_factory()
    (logdir / "claims" / f"{c['claim_id'].replace('sha256:', '')}.json").write_bytes(
        core.canonicalize(c))
    out = tmp_path / "site"
    build(logdir, out, api_base=API)
    html = (out / "index.html").read_text()
    assert "Claims awaiting check" in html
    assert c["proposition"] in html


# --- a stale snapshot looked frozen rather than behind ---

def test_staleness_is_detectable_by_head_commit_not_by_timestamps(site):
    """Record timestamps are claimant-supplied, so generated_from can sit AHEAD of a
    build that never saw your write. The head commit is the only honest signal."""
    b = json.loads((site / "built_at.json").read_text())
    assert b["built_at"] and b["generated_from"]
    assert "head_commit" in b
    assert "the commit your POST returned" in b["note"]
    assert "whatever timestamp their author wrote" in b["note"]


def test_built_at_is_excluded_from_the_determinism_check(log, tmp_path):
    """The generator must stay a pure function of the log; wall-clock cannot be."""
    import filecmp
    a, b = tmp_path / "a", tmp_path / "b"
    build(log, a, api_base=API)
    build(log, b, api_base=API)
    files = sorted(p.relative_to(a).as_posix() for p in a.rglob("*")
                   if p.is_file() and p.name != "built_at.json")
    match, mismatch, errors = filecmp.cmpfiles(a, b, files, shallow=False)
    assert not mismatch and not errors, f"non-deterministic: {mismatch or errors}"


# --- the docs contradicted themselves and drifted on a verdict name ---

def test_both_proposition_shapes_are_declared_in_scope(site):
    text = (site / "llms.txt").read_text()
    assert "Both shapes are in scope" in text
    assert "Do not manufacture a before-and-after you did not cause" in text


def test_the_verdict_name_matches_the_enum(site):
    text = (site / "llms.txt").read_text()
    assert "NOT ELIGIBLE" not in text
    assert "INELIGIBLE" in text and "INELIGIBLE" in core.VERDICTS


# --- the lease bound to nothing ---

def test_the_assignment_carries_a_lease_id_and_says_it_is_sticky(tmp_path, keys, claim_factory):
    backend = LocalBackend(tmp_path / "log")
    for name, kp in keys.items():
        rec = {"pseudonym": name, "public_key": kp["public"],
               "enrolled_at": "2026-08-29T09:00:00Z"}
        rec["signature"] = core.sign(rec, kp["private"])
        backend.put(f"agents/{name}.json", core.canonicalize(rec), f"enroll {name}")
    app = create_app(backend)
    app.config["TESTING"] = True
    c = app.test_client()
    c.post("/v0/claims", data=core.canonicalize(claim_factory()),
           content_type="application/json")

    first = c.get("/v0/assignment?pseudonym=slate").get_json()
    assert first["lease_id"] and first["reissued"] is False
    assert "re-roll" in first["draw"]["lease"]

    again = c.get("/v0/assignment?pseudonym=slate").get_json()
    assert again["claim"]["claim_id"] == first["claim"]["claim_id"]
    assert again["reissued"] is True, "a second handout was issued for the same lease"
    assert len(backend.read_dir("handouts")) == 1


# The homepage used to hardcode what it said about itself: five domains when
# there were six, a stat card typed in under a lede promising nothing was, and a
# standing invitation advertising a gap that had since been closed. Every one of
# those was true when written. These pin the parts that must stay derived.

def test_the_homepage_renders_every_domain_with_its_boundary(site):
    html = (site / "index.html").read_text("utf-8")
    import pow_core as core
    for n, name in core.DOMAINS.items():
        assert name.replace("&", "&amp;") in html
        assert core.BOUNDARIES[n] in html
    assert "five change domains" not in html
    assert "five domains" not in html.lower()


def test_the_homepage_renders_every_evidence_class_and_its_counts(site):
    """A class nobody files under is telling you something, and the page shows it."""
    html = (site / "index.html").read_text("utf-8")
    import json
    reg = json.loads((site / "classes" / "index.json").read_text("utf-8"))["classes"]
    for c in reg:
        assert c["class_id"] in html
        assert c["name"] in html
    assert len(reg) >= 7


def test_the_numbers_section_claims_nothing_it_typed_in(site):
    """It says nothing on the page is typed in. That has to stay true."""
    html = (site / "index.html").read_text("utf-8")
    assert "Nothing on this page is typed in." in html
    assert "there is no interface through which they could" not in html


def test_a_domain_card_summary_is_derived_from_the_published_scope(site):
    """The one-liner is the scope's first sentence, so a rewrite cannot strand it."""
    import json
    from pow_generate.build import in_short
    doc = json.loads((site / "domains.json").read_text("utf-8"))
    html = (site / "index.html").read_text("utf-8")
    for d in doc["domains"]:
        short = in_short(d["scope"])
        # derived: the same words the published scope opens with, only the
        # "This domain concerns" lead-in removed and the first letter raised.
        assert short.lower().rstrip(".") in d["scope"].lower()
        assert short.replace("&", "&amp;") in html
