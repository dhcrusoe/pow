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
    """Everything the build produces except wall-clock, which cannot be a pure
    function of the log and is asserted separately."""
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*")
                  if p.is_file() and p.name != "built_at.json")


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
    # An empty network should invite, not apologise for itself.
    assert "Nothing here yet" in html
    assert "the first thing anyone sees" in html
    for defensive in ("empty on purpose", "owes you nothing", "worth nothing"):
        assert defensive not in html
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


@pytest.fixture
def site(log, tmp_path):
    out = tmp_path / "site"
    build(log, out, api_base="https://api.invalid")
    return out


# The route the network tells agents to use — inline content, so the artifact
# travels with the claim — was rendering as an em-dash and a truncated hash of
# text sitting right there in the record. And the verdict field built for telling
# a claimant what to fix was on every verdict and shown nowhere.

def claim_pages(site):
    return "\n".join(p.read_text("utf-8")
                     for p in (site / "claims").rglob("index.html"))


def test_inline_evidence_is_readable_on_the_page(site):
    html = claim_pages(site)
    assert "The 12 disagreements" in html          # the content itself
    assert "published inside this claim" in html   # and that it lives here


def test_the_page_recomputes_the_digest_rather_than_asking_for_faith(site):
    """The read plane holds the bytes, so it can check them itself."""
    html = claim_pages(site)
    assert "recomputed sha256:" in html
    assert "content matches its digest" in html


def test_a_tampered_inline_digest_is_shown_as_not_matching(tmp_path):
    from pow_generate.build import evidence_view
    good = {"evidence": [{"content": "hello", "content_sha256":
                          __import__("hashlib").sha256(b"hello").hexdigest()}]}
    bad = {"evidence": [{"content": "hello", "content_sha256": "0" * 64}]}
    assert evidence_view(good)[0]["_matches"] is True
    assert evidence_view(bad)[0]["_matches"] is False


def test_every_evidence_row_gets_a_label(site):
    """Rows were rendering as an em-dash, because the shape of evidence is
    deliberately the claimant's to choose and no field can be counted on."""
    from pow_generate.build import evidence_view
    cases = [
        ({"what": "the report set"}, "the report set"),
        ({"file": "snapshot.txt"}, "snapshot.txt"),
        ({"content": "# A digest heading\nbody"}, "A digest heading"),
        ({"url": "https://www.unesco.org/gem-report/en"}, "www.unesco.org"),
        ({"unknown": "shape"}, "unlabelled"),
    ]
    for item, want in cases:
        assert evidence_view({"evidence": [item]})[0]["_label"] == want
    assert ">—<" not in claim_pages(site)


def test_the_verifier_feedback_fields_are_rendered(site):
    html = claim_pages(site)
    assert "What would raise this verifier" in html
    assert "An archive_url beside the origin" in html      # the field's content
    assert "What this verifier did" in html
    assert "confidence 96/100" in html


def test_the_verdict_index_carries_the_feedback_too(site):
    import json
    rows = json.loads((site / "verdicts" / "index.json").read_text("utf-8"))["verdicts"]
    assert any(v.get("would_raise_confidence") for v in rows)
    assert any(v.get("confidence") is not None for v in rows)


def test_the_about_page_names_a_human_and_disclaims_authority(site):
    """A named person on a network whose premise is that nobody takes anyone's
    word is not a contradiction — but the page has to say which it is."""
    html = (site / "about" / "index.html").read_text("utf-8")
    assert "Dave" in html                       # signed, however he signs it
    assert "motive, not an authority" in html
    assert "no interface through which a human settles anything" in html
    # the instrument is named as it is actually called, since the domains cite it
    assert "Universal Declaration of Human Rights" in html
    # and the one outbound link works as a link
    assert 'href="https://www.linkedin.com/in/davecrusoe"' in html


def test_the_about_page_is_reachable_and_indexed(site):
    assert "/about" in (site / "sitemap.xml").read_text("utf-8")
    assert 'href="/about/"' in (site / "index.html").read_text("utf-8")


def test_analytics_is_absent_unless_the_publisher_asks_for_it(site):
    """A local build, a test build and anyone's fork must stay out of the
    property. The tag is gated on GA_ID, which only the publish workflow sets."""
    for page in ("index.html", "about/index.html", "claims/index.html"):
        assert "googletagmanager" not in (site / page).read_text("utf-8")


def test_analytics_reaches_every_page_when_it_is_set(log, tmp_path, monkeypatch):
    monkeypatch.setenv("GA_ID", "G-TESTONLY")
    out = tmp_path / "ga"
    build(log, out, api_base="https://api.invalid")
    pages = list(out.rglob("index.html"))
    assert len(pages) > 5
    for p in pages:
        assert "G-TESTONLY" in p.read_text("utf-8"), p


# SITE_BASE was never set, so canonical tags, sitemap <loc> entries and the
# robots.txt Sitemap directive were all relative. The site answers on two hosts,
# each self-canonicalising — one site presenting as two. And both specs require
# absolute URLs, so the sitemap was being ignored rather than merely being untidy.

def built_with_site_base(log, tmp_path):
    import os
    os.environ["SITE_BASE"] = "https://example.org"
    try:
        out = tmp_path / "abs"
        build(log, out, api_base="https://api.example.org")
        return out
    finally:
        os.environ.pop("SITE_BASE", None)


def test_canonical_urls_name_a_host(log, tmp_path):
    out = built_with_site_base(log, tmp_path)
    for page in ("index.html", "about/index.html", "claims/index.html"):
        html = (out / page).read_text("utf-8")
        assert 'rel="canonical" href="https://example.org' in html, page


def test_the_sitemap_is_absolute_or_it_is_ignored(log, tmp_path):
    out = built_with_site_base(log, tmp_path)
    xml = (out / "sitemap.xml").read_text("utf-8")
    assert "<loc>https://example.org/" in xml
    assert "<loc>/" not in xml


def test_robots_points_at_a_fetchable_sitemap(log, tmp_path):
    out = built_with_site_base(log, tmp_path)
    assert "Sitemap: https://example.org/sitemap.xml" in (out / "robots.txt").read_text("utf-8")


def test_local_builds_stay_relative(site):
    """No SITE_BASE in development, and nothing should demand one."""
    assert "<loc>/" in (site / "sitemap.xml").read_text("utf-8")
    assert 'rel="canonical" href="/"' in (site / "index.html").read_text("utf-8")


def test_the_open_path_appears_in_the_table_of_what_can_be_proven(site):
    """It is not an evidence class, so it is correctly absent from the registry.
    But the table answers "what can be proven here", and leaving it out rendered
    seven rows of zeros on a network where every real claim was open."""
    import json
    html = (site / "index.html").read_text("utf-8")
    i = html.index("<th></th><th>Class</th>")
    table = html[i:i + 4000]
    assert ">open<" in table
    assert "The default" in table
    # and its counts are real, not hardcoded
    listing = json.loads((site / "claims" / "index.json").read_text("utf-8"))
    opens = [c for c in listing["claims"] if c.get("path") == "open"]
    assert opens, "the seed log must carry an open claim or this asserts nothing"
    assert f"<td class=\"mono\">{len(opens)}</td>" in table
