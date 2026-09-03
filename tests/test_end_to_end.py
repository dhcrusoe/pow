"""The whole loop, once, with nothing mocked but the network.

An agent enrolls, makes a claim, a second agent is drawn for it, verifies over
HTTP, posts a verdict, and the generator recomputes a page in which every number
traces to the log. If this passes, the system described in the architecture
actually exists.
"""
from __future__ import annotations

import hashlib
import json

import httpx
import pytest

import pow_core as core
from pow_api.backends import LocalBackend
from pow_api.main import create_app
from pow_generate.build import build
from pow_verify import e2

SOURCE = b'{"entries":[{"id":1,"due":"2024-04-11","results":null}]}'
DIGEST = hashlib.sha256(SOURCE).hexdigest()


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda url, **kw: httpx.Response(
        200, content=SOURCE, request=httpx.Request("GET", url)))
    backend = LocalBackend(tmp_path / "log")
    app = create_app(backend)
    app.config["TESTING"] = True
    return app.test_client(), backend, tmp_path


def enroll(client, name):
    sk, pk = core.generate()
    rec = {"pseudonym": name, "public_key": pk, "enrolled_at": "2026-09-01T09:00:00Z"}
    rec["signature"] = core.sign(rec, sk)
    r = client.post("/v0/agents", data=core.canonicalize(rec),
                    content_type="application/json")
    assert r.status_code == 201, r.get_json()
    return sk, pk


def test_the_whole_loop(world):
    client, backend, tmp = world

    # Two agents, each generating its own key. Nothing issues them.
    wren_sk, _ = enroll(client, "wren")
    slate_sk, _ = enroll(client, "slate")

    # wren makes a claim. Merge records it and nothing more.
    claim = {
        "claim_id": "", "claimant": "wren", "domain": 1, "path": "sealed",
        "evidence_class": "E2",
        "proposition": "Registry R records 1,847 entries past their stated due date.",
        "why": "Eighteen hundred results people were promised were never published.",
        "manifest": {"sources": [{"url": "https://example.invalid/registry.json",
                                  "snapshot_sha256": DIGEST}],
                     "fetched_at": "2026-09-01",
                     "assertion": "results is null past the due date"},
        "boundary": "standing: the registry is a public artifact",
        "costs": "", "resolves": "", "valid_as_of": "2026-09-01",
        "submitted_at": "2026-09-01T10:00:00Z", "signature": "",
    }
    claim["claim_id"] = core.content_hash(claim, exclude=core.Claim.ID_EXCLUDES)
    claim["signature"] = core.sign(claim, wren_sk)
    r = client.post("/v0/claims", data=core.canonicalize(claim),
                    content_type="application/json")
    assert r.status_code == 201 and r.get_json()["verified"] is False

    # Nothing is settled, so it scores nothing.
    assert core.score(backend.read_dir("claims"), backend.read_dir("verdicts")) == {"wren": 0}

    # wren cannot verify its own claim; slate is drawn for it.
    assert client.get("/v0/assignment?pseudonym=wren").get_json()["claim"] is None
    drawn = client.get("/v0/assignment?pseudonym=slate").get_json()
    assert drawn["claim"]["claim_id"] == claim["claim_id"]

    # slate runs the check over HTTP. No container, no runtime.
    verdict, output_hash, diagnosis = e2.check(drawn["claim"]["manifest"])
    assert verdict == "PASS"

    record = {"claim_id": claim["claim_id"], "verifier": "slate", "verdict": verdict,
              "output_hash": output_hash, "diagnosis": diagnosis, "magnitude": None,
              "fraud_caught": False, "settled_at": "2026-09-02T10:00:00Z", "signature": ""}
    record["signature"] = core.sign(record, slate_sk)
    r = client.post("/v0/verdicts", data=core.canonicalize(record),
                    content_type="application/json")
    assert r.status_code == 201

    # The claim leaves the queue for everyone.
    assert client.get("/v0/assignment?pseudonym=slate").get_json()["claim"] is None

    # Score is now derivable by anyone holding only the log and the weight table.
    totals = core.score(backend.read_dir("claims"), backend.read_dir("verdicts"))
    assert totals == {"wren": 10, "slate": 3}

    # And the page says exactly that, with nothing stored.
    site = tmp / "site"
    obs = build(backend.root, site)
    assert obs["settled"] == 1 and obs["rejection_rate"] == 0
    assert json.loads((site / "scores.json").read_text()) == totals

    page = next(site.glob("claims/*/index.html")).read_text()
    assert "1,847 entries past their stated due date" in page
    assert claim["claim_id"] in page, "the full content address belongs on the page"
    assert "ClaimReview" in page

    home = (site / "index.html").read_text()
    # Checked is the whole standard. Whether anyone has since fixed it is a badge
    # on the card, not a separate category of thing.
    assert "What agents have improved" in home
    assert claim["why"] in home
    assert ">checked<" in home and "fixed since" not in home, \
        "nothing was repaired; the badge must not say otherwise"
