"""E2 and E6, and the three-way distinction that carries the most judgement.

PASS / FAIL / UNRESOLVABLE is where a verifier can quietly do damage. Filing FAIL
on a probably-true claim with a broken source costs the claimant 15 points for a
packaging defect. These tests pin the distinction so it cannot erode.
"""
from __future__ import annotations

import hashlib

import httpx
import pytest

from pow_verify import e2, e6
import pow_core as core

BODY = b'{"entries": [{"id": 1, "due": "2024-04-11", "results": null}]}'
DIGEST = hashlib.sha256(BODY).hexdigest()


def manifest(**over):
    m = {"source": "https://example.invalid/x.json", "fetched_at": "2026-09-01",
         "snapshot_sha256": DIGEST, "assertion": "results is null"}
    m.update(over)
    return m


def patch(monkeypatch, *, body=BODY, status=200, raise_exc=None):
    def fake_get(url, **kw):
        if raise_exc:
            raise raise_exc
        return httpx.Response(status, content=body, request=httpx.Request("GET", url))
    monkeypatch.setattr(httpx, "get", fake_get)


def test_unchanged_source_passes(monkeypatch):
    patch(monkeypatch)
    verdict, out, diag = e2.check(manifest())
    assert verdict == "PASS"
    assert out == f"sha256:{DIGEST}"
    assert "identical to the snapshot" in diag


def test_changed_source_fails_and_shows_both_digests(monkeypatch):
    patch(monkeypatch, body=b'{"entries": []}')
    verdict, out, diag = e2.check(manifest())
    assert verdict == "FAIL"
    assert DIGEST in diag and out.split(":")[1] in diag


def test_a_vanished_source_is_unresolvable_not_a_failure(monkeypatch):
    """Link rot says nothing about the claimant. FAIL would cost them 15 points."""
    patch(monkeypatch, status=404)
    verdict, out, diag = e2.check(manifest())
    assert verdict == "UNRESOLVABLE"
    assert core.score([], []) == {}  # sanity: UNRESOLVABLE weight is zero
    assert "not a false claim" in diag and "resubmit" in diag


def test_a_network_failure_is_unresolvable(monkeypatch):
    patch(monkeypatch, raise_exc=httpx.ConnectError("no route"))
    verdict, _, diag = e2.check(manifest())
    assert verdict == "UNRESOLVABLE"
    assert "Nothing is owed by the claimant" in diag


def test_an_incomplete_manifest_is_unresolvable_not_ineligible(monkeypatch):
    verdict, _, diag = e2.check({"source": "https://x/y"})
    assert verdict == "UNRESOLVABLE"
    assert "missing" in diag


def test_e6_verifies_the_beneficiarys_signature():
    sk, pk = core.generate()
    attestation = {"service": "migration review", "for": "a named partner",
                   "on": "2026-08-01"}
    payload = {"attestation": attestation}
    sig = core.sign(payload, sk)
    verdict, out, diag = e6.check({"attestor": "partner-co", "attestor_public_key": pk,
                                   "attestation": attestation,
                                   "attestation_signature": sig})
    assert verdict == "PASS" and out.startswith("sha256:")


def test_e6_fails_when_the_signature_covers_something_else():
    sk, pk = core.generate()
    sig = core.sign({"attestation": {"service": "something else"}}, sk)
    verdict, _, diag = e6.check({"attestor": "partner-co", "attestor_public_key": pk,
                                 "attestation": {"service": "migration review"},
                                 "attestation_signature": sig})
    assert verdict == "FAIL" and "does not cover" in diag


def test_verdicts_emitted_by_the_checkers_pass_validation(monkeypatch, keys):
    patch(monkeypatch)
    verdict, out, diag = e2.check(manifest())
    rec = {"claim_id": "sha256:" + "a" * 64, "verifier": "slate", "verdict": verdict,
           "output_hash": out, "diagnosis": diag, "magnitude": None,
           "fraud_caught": False, "settled_at": "2026-09-02T10:00:00Z", "signature": ""}
    rec["signature"] = core.sign(rec, keys["slate"]["private"])
    core.validate(core.canonicalize(rec), "verdict",
                  public_key=keys["slate"]["public"], path=core.path_for(rec, "verdict"))
