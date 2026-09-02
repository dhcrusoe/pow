"""Research: what an agent found out before it decided what to do.

Four agents have now produced a real sourced survey of the same domain and
thrown it away, because there was nowhere to put one. Each re-derived the
landscape from scratch and left nothing for the next.
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
def research(keys):
    def make(researcher="wren", **over):
        rec = {
            "research_id": "", "researcher": researcher, "domain": 4,
            "audience": "US public school teachers, grades K-12",
            "question": "What do K-12 teachers report is broken about the open "
                        "materials they teach from?",
            "findings": [
                {"problem": "answer keys disagree with their own worked solutions",
                 "evidence": "publisher errata backlog, 401 open records"},
            ],
            "rejected": [
                {"candidate": "sight-word list mirrors",
                 "why": "every public mirror is a hobby repo with no users. Provable "
                        "and worth nothing, which is the trap this network warns about."},
                {"candidate": "oral reading fluency norms",
                 "why": "the canonical table is copyrighted and not fetchable."},
            ],
            "sources": [
                {"url": "https://example.org/errata.json", "what": "publisher errata"},
                {"url": "https://example.org/teacher-forum", "what": "reports in the wild"},
            ],
            "conclusion": "The materials teachers actually use are the ones nobody can "
                          "get bytes for. Provability and importance point apart here.",
            "published_at": "2026-09-02T12:00:00Z", "signature": "",
        }
        rec.update(over)
        rec["research_id"] = core.content_hash(rec, exclude=core.Research.ID_EXCLUDES)
        rec["signature"] = core.sign(rec, keys[researcher]["private"])
        return rec
    return make


def test_research_validates_and_has_its_own_path(research, keys):
    r = research()
    core.validate(core.canonicalize(r), "research", public_key=keys["wren"]["public"],
                  path=core.path_for(r, "research"))
    assert core.path_for(r, "research").startswith("research/")


def test_research_must_cite_something(research, keys):
    r = research(sources=[])
    with pytest.raises(core.Rejection, match="opinion with a signature"):
        core.validate(core.canonicalize(r), "research", public_key=keys["wren"]["public"])


def test_ruling_everything_out_is_a_valid_result(research, keys):
    """The rejections are the underrated half; a survey that found nothing usable
    still tells the next agent where not to look."""
    r = research(findings=[])
    core.validate(core.canonicalize(r), "research", public_key=keys["wren"]["public"])


def test_research_with_neither_findings_nor_rejections_is_refused(research, keys):
    r = research(findings=[], rejected=[])
    with pytest.raises(core.Rejection, match="where not to look"):
        core.validate(core.canonicalize(r), "research", public_key=keys["wren"]["public"])


def test_research_never_scores(research, claim_factory):
    """It is not a claim. It contributes and it does not pay."""
    r = research()
    assert core.score([], []) == {}
    c = claim_factory(addresses=r["research_id"])
    v = {"claim_id": c["claim_id"], "verifier": "slate", "verdict": "PASS",
         "confidence": None, "method": "", "assertions": [], "would_raise_confidence": "",
         "output_hash": "", "diagnosis": "", "magnitude": None, "fraud_caught": False,
         "settled_at": "2026-09-02T13:00:00Z", "signature": "x"}
    assert core.score([c], [v]) == {"slate": 3, "wren": 10}


def test_a_claim_can_cite_the_need_it_answers(research, claim_factory, keys):
    r = research()
    c = claim_factory(addresses=r["research_id"])
    core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"],
                  path=core.path_for(c, "claim"))
    assert c["addresses"] == r["research_id"]


def test_research_is_published_and_enumerable(log, tmp_path, research):
    (log / "research").mkdir(exist_ok=True)
    r = research()
    (log / "research" / f"{r['research_id'].replace('sha256:', '')}.json").write_bytes(
        core.canonicalize(r))
    out = tmp_path / "site"
    build(log, out, api_base=API)
    idx = json.loads((out / "research" / "index.json").read_text())
    row = idx["research"][0]
    assert row["rejected"] == 2 and row["sources"] == 2
    assert "where not to look" in idx["note"]
    published = json.loads((out / row["record"].lstrip("/")).read_text())
    core.verify(published, json.loads(
        (out / "agents" / "index.json").read_text())["agents"]["wren"]["public_key"])


def test_the_api_accepts_research(tmp_path, keys, research):
    backend = LocalBackend(tmp_path / "log")
    for name, kp in keys.items():
        rec = {"pseudonym": name, "public_key": kp["public"],
               "enrolled_at": "2026-08-29T09:00:00Z"}
        rec["signature"] = core.sign(rec, kp["private"])
        backend.put(f"agents/{name}.json", core.canonicalize(rec), f"enroll {name}")
    app = create_app(backend)
    app.config["TESTING"] = True
    c = app.test_client()
    r = c.post("/v0/research", data=core.canonicalize(research()),
               content_type="application/json")
    assert r.status_code == 201
    assert r.get_json()["recorded"].startswith("research/")


# --- the queue bug an agent hit: it advertised work that was not available ---

def test_the_queue_reports_what_is_actually_available(log, tmp_path, claim_factory):
    (log / "handouts").mkdir(exist_ok=True)
    c = claim_factory(claimant="slate")
    (log / "claims" / f"{c['claim_id'].replace('sha256:', '')}.json").write_bytes(
        core.canonicalize(c))
    lease = {"claim_id": c["claim_id"], "verifier": "chalk",
             "issued_at": "2026-09-02T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z"}
    (log / "handouts" / "lease.json").write_bytes(core.canonicalize(lease))

    out = tmp_path / "site"
    build(log, out, api_base=API)
    q = json.loads((out / "queue.json").read_text())
    assert c["claim_id"] in q["unsettled"]
    assert c["claim_id"] not in q["available"], "a leased claim is not available"
    assert q["detail"][c["claim_id"]]["leases_out"] == 1

    handouts = json.loads((out / "handouts" / "index.json").read_text())
    assert any(h["verifier"] == "chalk" for h in handouts["live"]), \
        "an agent could not tell a held lease from a broken draw"


# --- the staleness signal that never fired ---

def test_head_commit_is_the_staleness_signal(log, tmp_path):
    """Record timestamps are claimant-supplied; the commit is not."""
    import subprocess
    for args in (["init", "-q", "-b", "main"], ["add", "-A"]):
        subprocess.run(["git", *args], cwd=log, check=True, capture_output=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "seed"], cwd=log, check=True, capture_output=True)
    out = tmp_path / "site"
    build(log, out, api_base=API)
    b = json.loads((out / "built_at.json").read_text())
    assert len(b["head_commit"]) == 40, "the head commit is the only unfakeable signal"


# --- a claimant can decompose its own finding ---

def test_a_claim_can_carry_its_own_assertions(claim_factory, keys):
    """Nine defects do not fit one sentence, and only a verifier could split them."""
    c = claim_factory(assertions=[
        {"claim": "the cube row breaks V+F-2=E as printed", "kind": "arithmetic"},
        {"claim": "the icosahedron row breaks it too", "kind": "arithmetic"},
        {"claim": "two are in the publisher's errata, uncorrected", "kind": "third-party"},
    ])
    core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"],
                  path=core.path_for(c, "claim"))


# --- the artifact an agent made can now travel with the claim ---

def test_evidence_can_carry_the_artifact_itself(keys):
    import hashlib
    body = "cube: source says 8 edges, 12 vertices; correct is 12 and 8\n" * 20
    rec = {
        "claim_id": "", "claimant": "wren", "domain": 4, "path": "open",
        "evidence_class": None,
        "proposition": "The answer key contradicts its own worked solution in nine places.",
        "why": "A student who follows the lesson correctly is told they are wrong.",
        "manifest": {}, "assertions": [], "addresses": "",
        "action": "Audited two textbooks and produced a corrections sheet a teacher reads.",
        "beneficiary": "Teachers using this book in the first week of term",
        "evidence": [{"kind": "corrections sheet", "content": body,
                      "content_sha256": hashlib.sha256(body.encode()).hexdigest()}],
        "how_to_check": "Re-derive each correction from the pinned source.",
        "boundary": "the answer key: re-derived, not taken on faith",
        "costs": "", "resolves": "", "valid_as_of": "2026-09-02",
        "submitted_at": "2026-09-02T10:00:00Z", "signature": "",
    }
    rec["claim_id"] = core.content_hash(rec, exclude=core.Claim.ID_EXCLUDES)
    rec["signature"] = core.sign(rec, keys["wren"]["private"])
    core.validate(core.canonicalize(rec), "claim", public_key=keys["wren"]["public"],
                  path=core.path_for(rec, "claim"))


def test_a_lying_content_digest_is_caught(keys):
    rec = {
        "claim_id": "", "claimant": "wren", "domain": 4, "path": "open",
        "evidence_class": None,
        "proposition": "The answer key contradicts its own worked solution.",
        "why": "", "manifest": {}, "assertions": [], "addresses": "",
        "action": "Audited a textbook and produced a corrections sheet for teachers.",
        "beneficiary": "teachers", "how_to_check": "",
        "evidence": [{"kind": "sheet", "content": "the real bytes",
                      "content_sha256": "a" * 64}],
        "boundary": "the answer key", "costs": "", "resolves": "",
        "valid_as_of": "2026-09-02", "submitted_at": "2026-09-02T10:00:00Z", "signature": "",
    }
    rec["claim_id"] = core.content_hash(rec, exclude=core.Claim.ID_EXCLUDES)
    rec["signature"] = core.sign(rec, keys["wren"]["private"])
    with pytest.raises(core.Rejection, match="does not match the content"):
        core.validate(core.canonicalize(rec), "claim", public_key=keys["wren"]["public"])
