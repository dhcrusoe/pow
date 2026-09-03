"""Reads come from the published site; the log stays canonical.

Reading records back out of GitHub cost one HTTP request per record, so a single
GET /v0/claims at a few hundred records could burn an hour's rate limit. The
generator already visits every record, so it writes them out whole and the API
reads that instead.

The split is not reads-here/writes-there. It is on whether being wrong is
survivable. These tests pin the three places where it is not.
"""
from __future__ import annotations

import json

import httpx
import pytest

from pow_api.backends import ReadPlane
from pow_generate import build


@pytest.fixture
def site(log, tmp_path):
    out = tmp_path / "site"
    build(log, out, api_base="https://api.invalid")
    return out


class FakeLog:
    """A log that counts how often it is asked, so lag and fallback are visible."""

    def __init__(self, rows):
        self.rows, self.calls = rows, 0

    def read_dir(self, name):
        self.calls += 1
        return self.rows.get(name, [])

    def head(self):
        return "f" * 40

    def put(self, *a):
        raise AssertionError("the read model must never write")


def plane(monkeypatch, doc, log, fail=False):
    def fake_get(url, **kw):
        if fail:
            raise httpx.ConnectError("read plane down")
        return httpx.Response(200, json=doc, request=httpx.Request("GET", url))
    rp = ReadPlane("https://site.invalid", log)
    monkeypatch.setattr(rp.client, "get", fake_get)
    return rp


DOC = {"head_commit": "a" * 40, "generated_from": "2026-09-03T00:00:00Z",
       "count": 2, "claims": [{"claim_id": "sha256:1"}, {"claim_id": "sha256:2"}]}


def test_the_read_plane_serves_records_without_touching_the_log(monkeypatch):
    log = FakeLog({"claims": [{"claim_id": "sha256:only-in-the-log"}]})
    rp = plane(monkeypatch, DOC, log)
    assert len(rp.read_dir("claims")) == 2
    assert log.calls == 0


def test_one_fetch_serves_repeated_reads(monkeypatch):
    """The N+1 this replaces was the whole reason for the change."""
    log = FakeLog({})
    rp = plane(monkeypatch, DOC, log)
    seen = []
    real = rp.client.get
    monkeypatch.setattr(rp.client, "get", lambda u, **k: (seen.append(u), real(u, **k))[1])
    for _ in range(5):
        rp.read_dir("claims")
    assert len(seen) == 1


def test_a_broken_build_falls_back_to_the_log_and_says_so(monkeypatch):
    """A cache that freezes at the last good state is worse than no cache."""
    log = FakeLog({"claims": [{"claim_id": "sha256:from-the-log"}]})
    rp = plane(monkeypatch, DOC, log, fail=True)
    rows = rp.read_dir("claims")
    assert rows == [{"claim_id": "sha256:from-the-log"}]
    assert log.calls == 1
    assert "ConnectError" in rp.degraded


def test_the_read_plane_refuses_to_be_written_to(monkeypatch):
    rp = plane(monkeypatch, DOC, FakeLog({}))
    with pytest.raises(RuntimeError):
        rp.put("claims/x.json", b"{}", "no")


def test_health_publishes_the_lag_rather_than_hiding_it(tmp_path, keys, log):
    from pow_api.main import create_app
    from pow_api.backends import LocalBackend
    app = create_app(LocalBackend(log))
    body = app.test_client().get("/v0/health").get_json()
    assert body["ok"] is True
    assert body["log_head"]
    # No READ_PLANE set in development, and the API says so rather than implying
    # a freshness guarantee it is not making.
    assert body["read_plane"] is False


def test_enrolment_claim_existence_and_assignment_still_read_the_log():
    """Stale reads here are not survivable: a missing key 403s an agent's first
    claim, a missing claim 404s a valid verdict, and a stale queue hands out work
    that is already finished."""
    src = (__import__("pathlib").Path("packages/pow_api/main.py")).read_text("utf-8")
    for fn in ("def enrolled_key", "def assignment"):
        i = src.index(fn)
        body = src[i:i + 1400]
        assert 'READS' not in body.split("@app")[0], f"{fn} must read the log"
    assert 'for c in app.config["BACKEND"].read_dir("claims")' in src


def test_the_generator_publishes_whole_records_not_just_summaries(site):
    doc = json.loads((site / "records" / "claims.json").read_text("utf-8"))
    assert doc["count"] == len(doc["claims"])
    assert doc["head_commit"]
    # Full records: a summary would not carry the signature.
    assert all("signature" in c for c in doc["claims"])
    assert "never authoritative" in doc["note"]
