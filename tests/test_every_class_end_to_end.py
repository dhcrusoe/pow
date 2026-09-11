"""Every evidence class through the whole write path, not just its checker.

`test_end_to_end.py` runs the full loop for E2 and stops there. E4 and E6 were
covered only at checker level — `eN.check(manifest)` called directly, with no
API, no validator, no settlement, no build. So a change to `validate.py`,
`score.py`, `canonical.py` or `errors.py` could break a class at the door and
every test would still pass.

This is the matrix that closes that. For each class: enrol two agents through the
API, post a seal if the class opens one, post the claim, run the CI validator
over the resulting log to confirm both write paths agree, take the assignment
draw, file a verdict, and check that score and the published site both reflect
it.

Checker behaviour stays in `test_the_remaining_classes.py` and `test_verify.py`.
What is asserted here is the path a record travels, which is the part no class
but E2 exercised.
"""
from __future__ import annotations

import hashlib
import json

import pow_core as core
import pytest
from pow_api.backends import LocalBackend
from pow_api.main import create_app
from pow_generate.build import build
from pow_verify.__main__ import CHECKS

from scripts.validate_log import main as validate_log

BODY = b'{"rows": 4}'
DIGEST = hashlib.sha256(BODY).hexdigest()
SALT = "ab" * 20
SRC = [{"url": "https://example.invalid/data.json", "snapshot_sha256": DIGEST}]
SEAL_URL = "https://example.invalid/seals/s1.json"
PLAN = {"method": "recount the pinned rows", "cutoff": "2026-01-01"}

# Classes that open a commitment need the seal to exist before the claim does.
NEEDS_SEAL = {"E4"}


def band(value, lo, hi, scale=-2, unit="pp"):
    return {"value": value, "scale": scale, "unit": unit, "lo": lo, "hi": hi}


def manifest_for(evidence_class, partner_key):
    """A manifest that satisfies REQUIRED_MANIFEST for the class, and no more."""
    return {
        "E2": {"sources": SRC, "fetched_at": "2026-09-01",
               "assertion": "results is null past the due date"},
        "E4": {"seal_url": SEAL_URL, "plan_salt": SALT, "plan": PLAN, "inputs": SRC,
               "threshold": band(150, 100, 200), "result": band(149, 120, 180)},
        "E6": {"attestor": "Mercy Clinic",
               "attestation": {"service": "rendered", "on": "2026-09-01"},
               "attestor_public_key": partner_key,
               "attestation_signature": "A" * 88},
    }[evidence_class]


@pytest.fixture
def door(tmp_path):
    backend = LocalBackend(tmp_path / "log")
    app = create_app(backend)
    app.config["TESTING"] = True
    return app.test_client(), backend, tmp_path


def post(client, path, record, key):
    record["signature"] = core.sign(record, key)
    return client.post(path, data=core.canonicalize(record),
                       content_type="application/json")


def enrol(client, name):
    sk, pk = core.generate()
    rec = {"pseudonym": name, "public_key": pk, "enrolled_at": "2026-09-01T09:00:00Z"}
    r = post(client, "/v0/agents", rec, sk)
    assert r.status_code == 201, r.get_json()
    return sk, pk


@pytest.mark.parametrize("evidence_class", sorted(CHECKS))
def test_every_class_survives_the_whole_write_path(evidence_class, door):
    client, backend, tmp = door
    wren_sk, _ = enrol(client, "wren")
    slate_sk, _ = enrol(client, "slate")
    _, partner_key = core.generate()

    # A class that opens a commitment needs the seal filed first, by the same
    # agent, naming the class it is for.
    if evidence_class in NEEDS_SEAL:
        from pow_core import seals
        seal = {"seal_id": "", "sealer": "wren",
                "commitment": seals.commitment(PLAN, SALT),
                "intended_class": evidence_class, "sealed_at": "2026-01-01",
                "signature": ""}
        seal["seal_id"] = core.content_hash(seal, exclude=core.Seal.ID_EXCLUDES)
        r = post(client, "/v0/seals", seal, wren_sk)
        assert r.status_code == 201, (evidence_class, r.get_json())

    claim = {
        "claim_id": "", "claimant": "wren", "domain": 1, "path": "sealed",
        "evidence_class": evidence_class,
        "proposition": "Register R lists 150 entries past their stated due date.",
        "manifest": manifest_for(evidence_class, partner_key),
        "why": "People relying on this register are shown a figure nobody checked.",
        "boundary": "standing: the register is a public artifact",
        "costs": "", "resolves": "", "valid_as_of": "2026-09-01",
        "submitted_at": "2026-09-01T10:00:00Z", "signature": "",
    }
    claim["claim_id"] = core.content_hash(claim, exclude=core.Claim.ID_EXCLUDES)
    r = post(client, "/v0/claims", claim, wren_sk)
    assert r.status_code == 201, (evidence_class, r.get_json())
    assert r.get_json()["verified"] is False, "merge records, it does not verify"

    # Both write paths, or neither. The pull-request path runs the same
    # validate() over what the API just committed; if they disagree, a record
    # accepted here is one CI would refuse, which the README promises cannot
    # happen.
    assert validate_log([str(backend.root)]) == 0, evidence_class

    # A sealed claim needs one verifier, and it may not be its own claimant.
    assert client.get("/v0/assignment?pseudonym=wren").get_json()["claim"] is None
    drawn = client.get("/v0/assignment?pseudonym=slate").get_json()
    assert drawn["claim"]["claim_id"] == claim["claim_id"], evidence_class
    assert drawn["claim"]["evidence_class"] == evidence_class

    verdict = {"claim_id": claim["claim_id"], "verifier": "slate", "verdict": "PASS",
               "output_hash": "sha256:" + DIGEST,
               "diagnosis": f"ran the {evidence_class} procedure and reproduced it.",
               "magnitude": None, "fraud_caught": False,
               "settled_at": "2026-09-02T10:00:00Z", "signature": ""}
    r = post(client, "/v0/verdicts", verdict, slate_sk)
    assert r.status_code == 201, (evidence_class, r.get_json())
    assert validate_log([str(backend.root)]) == 0, evidence_class

    # Settled, so it leaves the queue and pays both sides from the log alone.
    assert client.get("/v0/assignment?pseudonym=slate").get_json()["claim"] is None
    totals = core.score(backend.read_dir("claims"), backend.read_dir("verdicts"))
    assert totals == {"wren": 10, "slate": 3}, evidence_class

    # And the read plane publishes it under the class it was filed as.
    site = tmp / "site"
    obs = build(backend.root, site)
    assert obs["settled"] == 1, evidence_class
    assert json.loads((site / "scores.json").read_text()) == totals

    index = json.loads((site / "claims" / "index.json").read_text())
    row = next(c for c in index["claims"] if c["claim_id"] == claim["claim_id"])
    assert row["evidence_class"] == evidence_class
    assert row["verdict"] == "PASS"

    registry = json.loads((site / "classes" / "index.json").read_text())
    entry = next(c for c in registry["classes"] if c["class_id"] == evidence_class)
    assert entry["claims"] == 1 and entry["settled"] == 1, evidence_class


@pytest.mark.parametrize("evidence_class", sorted(CHECKS))
def test_every_class_refuses_a_manifest_missing_a_required_field(evidence_class, door):
    """The other direction, which is the one that finds bugs.

    The happy-path matrix above passes just as well against a validator that has
    stopped enforcing anything — a valid manifest satisfies no rules and all
    rules alike. Deleting each required field in turn is what proves the door is
    still shut. Verified by mutation: blanking one class's MANIFEST_RULES makes
    this fail and the happy path pass.
    """
    from pow_core.validate import REQUIRED_MANIFEST

    client, _backend, _ = door
    wren_sk, _ = enrol(client, "wren")
    _, partner_key = core.generate()
    full = manifest_for(evidence_class, partner_key)

    required = REQUIRED_MANIFEST[evidence_class]
    assert required, f"{evidence_class} requires nothing at all"

    for field in required:
        short = {k: v for k, v in full.items() if k != field}
        claim = {
            "claim_id": "", "claimant": "wren", "domain": 1, "path": "sealed",
            "evidence_class": evidence_class,
            "proposition": "Register R lists 150 entries past their stated due date.",
            "manifest": short,
            "why": "People relying on this register are shown a figure nobody checked.",
            "boundary": "standing: the register is a public artifact",
            "costs": "", "resolves": "", "valid_as_of": "2026-09-01",
            "submitted_at": "2026-09-01T10:00:00Z", "signature": "",
        }
        claim["claim_id"] = core.content_hash(claim, exclude=core.Claim.ID_EXCLUDES)
        r = post(client, "/v0/claims", claim, wren_sk)
        assert r.status_code == 400, (
            f"{evidence_class} accepted a manifest with {field!r} removed")
        detail = r.get_json()["error"]["detail"]
        assert field in detail, (
            f"{evidence_class} refused without naming the missing {field!r}: {detail}")
