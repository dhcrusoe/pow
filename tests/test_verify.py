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
    m = {"sources": [{"url": "https://example.invalid/x.json",
                      "snapshot_sha256": DIGEST}],
         "fetched_at": "2026-09-01", "assertion": "results is null"}
    m.update(over)
    return m


def two_sources(second_digest=DIGEST):
    return {"sources": [{"label": "guideline A", "url": "https://example.invalid/a",
                         "snapshot_sha256": DIGEST},
                        {"label": "guideline B", "url": "https://example.invalid/b",
                         "snapshot_sha256": second_digest}],
            "fetched_at": "2026-09-01",
            "assertion": "A recommends X where B recommends not-X"}


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
    # output_hash covers every source, so one verdict speaks for the whole set.
    assert out.startswith("sha256:") and len(out) == 71
    assert "identical to the snapshots" in diag


def test_changed_source_fails_and_shows_both_digests(monkeypatch):
    patch(monkeypatch, body=b'{"entries": []}')
    verdict, out, diag = e2.check(manifest())
    assert verdict == "FAIL"
    assert DIGEST[:12] in diag and "observed" in diag


def test_a_vanished_source_is_unresolvable_not_a_failure(monkeypatch):
    """Link rot says nothing about the claimant. FAIL would cost them 15 points."""
    patch(monkeypatch, status=404)
    verdict, out, diag = e2.check(manifest())
    assert verdict == "UNRESOLVABLE"
    assert core.score([], []) == {}  # sanity: UNRESOLVABLE weight is zero
    assert "Nothing is owed by the claimant" in diag and "resubmit" in diag


def test_a_network_failure_is_unresolvable(monkeypatch):
    patch(monkeypatch, raise_exc=httpx.ConnectError("no route"))
    verdict, _, diag = e2.check(manifest())
    assert verdict == "UNRESOLVABLE"
    assert "Nothing is owed by the claimant" in diag


def test_an_incomplete_manifest_is_unresolvable_not_ineligible(monkeypatch):
    verdict, _, diag = e2.check({"assertion": "nothing to fetch"})
    assert verdict == "UNRESOLVABLE"
    assert "no sources" in diag


def test_several_sources_all_matching_passes(monkeypatch):
    """Comparison claims verify the same way: fetch each, hash each."""
    patch(monkeypatch)
    verdict, out, diag = e2.check(two_sources())
    assert verdict == "PASS"
    assert "2 sources" in diag and "re-runs it from the snapshots alone" in diag


def test_one_changed_source_of_several_fails_and_names_which(monkeypatch):
    patch(monkeypatch)
    verdict, _, diag = e2.check(two_sources(second_digest="f" * 64))
    assert verdict == "FAIL"
    assert "1 of 2" in diag and "guideline B" in diag and "guideline A" not in diag


def test_one_unreadable_source_of_several_is_unresolvable(monkeypatch):
    patch(monkeypatch, status=404)
    verdict, _, diag = e2.check(two_sources())
    assert verdict == "UNRESOLVABLE"
    assert "Nothing is owed by the claimant" in diag


def test_the_old_single_source_form_still_verifies(monkeypatch):
    """Records already in an append-only log cannot be rewritten to a new shape."""
    patch(monkeypatch)
    verdict, _, _ = e2.check({"source": "https://example.invalid/x.json",
                              "snapshot_sha256": DIGEST, "fetched_at": "2026-09-01",
                              "assertion": "results is null"})
    assert verdict == "PASS"


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
