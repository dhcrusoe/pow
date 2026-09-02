"""The read plane.

Two properties matter more than the rest: the generator is itself deterministic,
and the site renders honestly when the log is empty. If the first fails, nothing
downstream is reproducible. If the second fails, the page can only ever look good
full — which is how invented figures get onto a launch page.
"""
from __future__ import annotations

import filecmp
import json
from pathlib import Path

import pytest

import pow_core as core
from pow_generate.build import build, claim_url, slug


def tree(root: Path):
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


def test_the_generator_is_deterministic(log, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    build(log, a)
    build(log, b)
    assert tree(a) == tree(b)
    match, mismatch, errors = filecmp.cmpfiles(a, b, tree(a), shallow=False)
    assert not mismatch and not errors, f"non-deterministic output: {mismatch or errors}"


def test_it_renders_at_zero(tmp_path):
    """Day one: no claims, no agents, no verdicts. The page must say so."""
    empty = tmp_path / "empty-log"
    for d in ("claims", "verdicts", "seals", "handouts", "agents"):
        (empty / d).mkdir(parents=True)
    out = tmp_path / "site"
    obs = build(empty, out)

    assert obs["claims"] == 0 and obs["settled"] == 0
    assert json.loads((out / "scores.json").read_text()) == {}
    q = json.loads((out / "queue.json").read_text())
    assert q["available"] == [] and q["unsettled"] == []

    html = (out / "index.html").read_text()
    assert "Nothing has been fixed yet" in html
    assert "It is empty on purpose" in html
    assert "not yet enough history for anything" in html
    for absent in ("412", "1,204", "94%"):
        assert absent not in html, "a hardcoded figure survived into an empty build"


def test_every_number_on_the_page_comes_from_the_log(log, tmp_path):
    out = tmp_path / "site"
    obs = build(log, out)
    html = (out / "index.html").read_text()
    assert f">{obs['settled']}<" in html
    assert f">{obs['agents']}<" in html
    scores = json.loads((out / "scores.json").read_text())
    claims = [json.loads(p.read_text()) for p in (log / "claims").glob("*.json")]
    verdicts = [json.loads(p.read_text()) for p in (log / "verdicts").glob("*.json")]
    assert scores == core.score(claims, verdicts)


def test_claim_pages_are_findable(log, tmp_path):
    """The claim pages are the discovery surface, so they carry real metadata."""
    out = tmp_path / "site"
    build(log, out)
    pages = list(out.glob("claims/*/index.html"))
    assert pages, "no claim pages were written"
    html = pages[0].read_text()
    assert '<link rel="canonical"' in html
    assert '<meta name="description"' in html
    assert "sha256:" in html, "the full content address belongs on the page"
    assert (out / "sitemap.xml").exists() and (out / "robots.txt").exists()


def test_a_settled_claim_carries_structured_data(log, tmp_path):
    out = tmp_path / "site"
    build(log, out)
    found = [p for p in out.glob("claims/*/index.html") if "ClaimReview" in p.read_text()]
    assert found, "no settled claim emitted ClaimReview JSON-LD"


def test_urls_carry_keywords_not_just_a_hash():
    claim = {"claim_id": "sha256:" + "ab" * 32,
             "proposition": "Advisory D lists package P as affected at version V."}
    url = claim_url(claim)
    assert url.startswith("claims/abababababab-")
    assert "advisory" in url and "package" in url


@pytest.mark.parametrize("text,expected", [
    ("The quick brown fox", "quick-brown-fox"),
    ("A, B and C: 1,847 entries", "b-c-1-847-entries"),
    ("...", "claim"),
])
def test_slugs(text, expected):
    assert slug(text) == expected


def test_schemas_are_published(log, tmp_path):
    """A second implementation validates against a file, not against prose."""
    out = tmp_path / "site"
    build(log, out)
    schema = json.loads((out / "schema" / "claim.json").read_text())
    assert "proposition" in schema["properties"]
    assert schema.get("additionalProperties") is False


def test_the_observatory_flags_without_interpreting(log, tmp_path):
    out = tmp_path / "site"
    obs = build(log, out)
    assert isinstance(obs["what_looks_wrong"], list)
    assert obs["decided_by_human"] == 0
    assert obs["independence"] == "distinct-keypair-only"
