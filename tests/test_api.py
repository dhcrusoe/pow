"""The API is transport, not authority.

The load-bearing test here is the last one: a record the API accepts must be one
CI would also accept. Two validation paths that can drift is the failure the
architecture exists to prevent, so it is asserted rather than assumed.
"""
from __future__ import annotations

import json

import pytest

import pow_core as core
from pow_api.backends import LocalBackend
from pow_api.main import create_app


@pytest.fixture
def client(tmp_path, keys):
    backend = LocalBackend(tmp_path / "log")
    for name, kp in keys.items():
        rec = {"pseudonym": name, "public_key": kp["public"],
               "enrolled_at": "2026-08-29T09:00:00Z"}
        rec["signature"] = core.sign(rec, kp["private"])
        backend.put(f"agents/{name}.json", core.canonicalize(rec), f"enroll {name}")
    app = create_app(backend)
    app.config["TESTING"] = True
    with app.test_client() as c:
        c.backend = backend
        yield c


def post(client, path, record):
    return client.post(path, data=core.canonicalize(record),
                       content_type="application/json")


def test_a_signed_claim_is_recorded(client, claim_factory):
    r = post(client, "/v0/claims", claim_factory())
    assert r.status_code == 201
    body = r.get_json()
    assert body["recorded"].startswith("claims/")
    assert body["verified"] is False, "merge means recorded, not verified"
    assert len(client.backend.read_dir("claims")) == 1


def test_a_bad_signature_is_refused_with_the_rule_that_broke(client, claim_factory):
    c = claim_factory()
    c["signature"] = "A" * 88
    r = post(client, "/v0/claims", c)
    assert r.status_code == 400
    assert r.get_json()["error"]["rule"] == "signature"


def test_an_unenrolled_pseudonym_cannot_write(client, claim_factory, keys):
    c = claim_factory()
    c["claimant"] = "stranger"
    c["claim_id"] = core.content_hash(c, exclude=core.Claim.ID_EXCLUDES)
    c["signature"] = core.sign(c, keys["wren"]["private"])
    r = post(client, "/v0/claims", c)
    assert r.status_code == 403
    assert r.get_json()["error"]["rule"] == "enrollment"


def test_the_same_claim_twice_is_a_conflict_not_a_second_record(client, claim_factory):
    c = claim_factory()
    assert post(client, "/v0/claims", c).status_code == 201
    assert post(client, "/v0/claims", c).status_code == 409
    assert len(client.backend.read_dir("claims")) == 1


def test_assignment_never_returns_your_own_claim(client, claim_factory):
    post(client, "/v0/claims", claim_factory(claimant="wren"))
    assert client.get("/v0/assignment?pseudonym=wren").get_json()["claim"] is None
    drawn = client.get("/v0/assignment?pseudonym=slate").get_json()
    assert drawn["claim"]["claimant"] == "wren"
    assert drawn["lease_expires"] > drawn["claim"]["submitted_at"]


def test_assignment_records_a_handout(client, claim_factory):
    post(client, "/v0/claims", claim_factory())
    client.get("/v0/assignment?pseudonym=slate")
    handouts = client.backend.read_dir("handouts")
    assert len(handouts) == 1 and handouts[0]["verifier"] == "slate"


def test_an_empty_queue_says_so_plainly(client):
    body = client.get("/v0/assignment?pseudonym=slate").get_json()
    assert body["claim"] is None and "nothing to verify" in body["note"]


def test_health_and_root_describe_the_service(client):
    assert client.get("/v0/health").get_json()["ok"] is True
    assert "transport, not authority" in client.get("/").get_json()["note"]


def test_the_api_cannot_accept_what_ci_would_reject(client, claim_factory, keys):
    """The single most important test in this file.

    Both write paths import the same validate(). If this ever fails, the API has
    become an authority with its own opinion, and the log stops meaning one thing.
    """
    corpus = [claim_factory(), claim_factory(costs="trades snapshot fidelity"),
              claim_factory(proposition="Registry R lists 1,847 entries past due (n=1,847).")]
    for c in corpus:
        api = post(client, "/v0/claims", c)
        try:
            core.validate(core.canonicalize(c), "claim",
                          public_key=keys[c["claimant"]]["public"],
                          path=core.path_for(c, "claim"))
            ci_ok = True
        except core.Rejection:
            ci_ok = False
        assert (api.status_code == 201) == ci_ok, f"paths disagree on {c['claim_id']}"
