"""The instructions agents actually read, checked against each other.

An agent meets this network through several documents, and for a while they did
not agree. The verifier safety contract existed in three places with three
different rule sets: `llms.txt` had lost the rule about following links a claim
vouches for, and the ChatGPT app instructions had lost the one about attaching
credentials to a claimant-supplied fetch. Whether an agent was protected against
a given attack depended on which document it happened to have read.

Nothing asserted that they matched, so nothing noticed. These tests are that
assertion. `pow_core.contract` is the one source; every surface renders it.
"""
from __future__ import annotations

import json
import pathlib

import pytest

import pow_core as core

DEPLOY = pathlib.Path(__file__).resolve().parents[1] / "deploy"


def normalise(text: str) -> str:
    """Compare content, not line wrapping or markdown emphasis."""
    return " ".join(text.lower().replace("`", "").split())


@pytest.mark.parametrize("rule", core.VERIFIER_CONTRACT["do_not"])
def test_llms_txt_carries_every_do_not_rule(rule, site):
    """llms.txt is what an agent reads BEFORE its first assignment, so a rule
    that lives only in the assignment payload arrives too late to prevent the
    thing it warns about."""
    assert normalise(rule) in normalise((site / "llms.txt").read_text("utf-8"))


@pytest.mark.parametrize("rule", core.VERIFIER_CONTRACT["do_not"])
def test_the_chatgpt_app_instructions_carry_every_do_not_rule(rule):
    """A hosted assistant is configured from this file once and may never read
    llms.txt again, so a partial copy here is permanent for that deployment."""
    assert normalise(rule) in normalise((DEPLOY / "chatgpt-app.md").read_text("utf-8"))


def test_the_contract_is_served_inline_with_every_assignment(tmp_path, keys, claim_factory):
    """Never a link. A link is one failed fetch from an agent that never learned
    the rule, in the payload handed to a process about to fetch things a stranger
    chose."""
    from pow_api.backends import LocalBackend
    from pow_api.main import create_app

    backend = LocalBackend(tmp_path / "log")
    app = create_app(backend)
    app.config["TESTING"] = True
    client = app.test_client()

    for name, kp in keys.items():
        rec = {"pseudonym": name, "public_key": kp["public"],
               "enrolled_at": "2026-09-01T09:00:00Z"}
        rec["signature"] = core.sign(rec, kp["private"])
        client.post("/v0/agents", data=core.canonicalize(rec),
                    content_type="application/json")

    claim = claim_factory()
    client.post("/v0/claims", data=core.canonicalize(claim),
                content_type="application/json")

    body = client.get("/v0/assignment?pseudonym=slate").get_json()
    contract = body["contract"]
    assert contract == core.VERIFIER_CONTRACT, "the assignment must carry the one source"
    # Equality alone would be satisfied by a contract someone had emptied.
    assert contract["do_not"] and contract["the_line"] and contract["the_bound"]
    # Inline, not referenced.
    assert not any(str(v).startswith("http") for v in contract.values())


def test_the_document_and_the_payload_cannot_drift_apart(site):
    """The rendered paragraph is generated, so this asserts the wiring, not the
    wording — if someone re-hardcodes the sentence, the rules stop matching."""
    rendered = core.do_not_prose()
    txt = (site / "llms.txt").read_text("utf-8")
    assert normalise(rendered) in normalise(txt)


def test_every_endpoint_the_api_serves_is_reachable_from_the_documents(site):
    """An endpoint an agent cannot find is an endpoint that does not exist.

    /v0/seals was served, described in openapi.json, and named nowhere in the
    607 lines of llms.txt — while a seal gates E4, one of the three classes.
    """
    from pow_api.openapi import document

    spec = document("https://site.invalid", "https://api.invalid")
    txt = (site / "llms.txt").read_text("utf-8")
    well_known = json.loads((site / ".well-known" / "pow.json").read_text("utf-8"))
    discoverable = txt + json.dumps(well_known)

    # /v0/health is infrastructure, not instruction: render.yaml points its
    # healthCheckPath at it and no agent ever needs to call it. Everything else
    # the API serves is something an agent is expected to use.
    operational = {"/v0/health"}

    for path in spec["paths"]:
        if "{" in path or path in operational:
            continue  # parameterised reads are reachable through their collection
        assert path in discoverable, f"{path} is served but named in no document"


def test_the_privacy_page_exists_and_says_the_thing_that_matters(site):
    """The field said "privacy policy" and pointed at a page of motive.

    What a privacy policy has to disclose here is unusual and more important than
    the usual list: writes are permanent, public, and irreversible by anyone
    including the operator. That is the product, not a gap.
    """
    page = (site / "privacy" / "index.html").read_text("utf-8")
    for must in ("append-only", "cannot be edited", "permanent", "256KB"):
        assert must in page, f"the privacy page never mentions {must!r}"
    # Derived from the protocol, not retyped: every boundary is on the page.
    for boundary in set(core.BOUNDARIES.values()):
        assert boundary in page, f"boundary {boundary!r} missing"
    # Linked, or nobody finds it.
    assert 'href="/privacy/"' in (site / "index.html").read_text("utf-8")


def test_the_chatgpt_privacy_field_points_at_a_page_that_exists(site):
    """A directory submission that declares a privacy policy at a URL with no
    privacy content is a listed field that does not contain what it claims."""
    import re
    from urllib.parse import urlparse

    text = (DEPLOY / "chatgpt-app.md").read_text("utf-8")
    field = re.search(r"\*\*Privacy policy\*\*\s*—\s*(\S+)", text)
    assert field, "chatgpt-app.md declares no privacy policy field"
    path = urlparse(field.group(1)).path.strip("/")
    assert path, "the privacy field names an origin with no path"
    target = site / path / "index.html"
    assert target.is_file(), (
        f"privacy field points at /{path}/, which the build does not produce")

    # Existing is not enough — the field previously pointed at /about/, which is
    # a real page with no privacy content. What makes a page answer this field is
    # that it discloses what cannot be undone.
    page = target.read_text("utf-8")
    for must in ("append-only", "cannot be edited", "permanent"):
        assert must in page, (
            f"/{path}/ is named as the privacy policy but never says {must!r}")


# --- Privacy and terms ------------------------------------------------------
#
# The privacy page used to be an essay about permanence: honest, well written,
# and missing most of what a privacy policy is required to disclose. It named no
# controller, no recipients and no complaint route, while data flowed through
# four companies. These assert the standard disclosures are present, and that the
# two things which can silently go false — the cookie statement and the licence
# grant — cannot drift from what the build actually does.

ART13 = {
    "a controller": "responsible",
    "a contact route": "contact",
    "a legal basis": "Legitimate interest",
    "named recipients": "Cloudflare",
    "the log host": "GitHub",
    "third-country transfer": "United States",
    "retention": "Kept",
    "the complaint right": "supervisory authority",
    "automated decisions": "automated",
    "an effective date": "in effect",
}


@pytest.mark.parametrize("what,needle", sorted(ART13.items()))
def test_the_privacy_policy_makes_the_standard_disclosures(site, what, needle):
    page = (site / "privacy" / "index.html").read_text("utf-8")
    assert needle in page, f"the privacy policy discloses no {what}"


def test_the_privacy_policy_discloses_the_one_third_party_who_never_came_here(site):
    """E6 stores a counterparty's reply whole, headers and all, and publishes it.

    It is the only place this network holds an identified person's data on behalf
    of somebody who never visited it and agreed to nothing.
    """
    page = (site / "privacy" / "index.html").read_text("utf-8")
    assert "E6" in page and "headers" in page, (
        "E6 publishes a third party's raw email; the privacy policy must say so")


@pytest.mark.parametrize("ga", ["", "G-TESTONLY"])
def test_the_cookie_statement_cannot_contradict_the_build(log, tmp_path, ga, monkeypatch):
    """The page claimed "no cookies set by this service" while Analytics was live
    in production, setting _ga. Derived from GA_ID now, so it cannot say the
    wrong one: a wording fix would have gone stale the next time the tag moved.
    """
    from pow_generate.build import build

    monkeypatch.setenv("GA_ID", ga)
    out = tmp_path / ("ga" if ga else "noga")
    build(log, out)
    page = (out / "privacy" / "index.html").read_text("utf-8")
    if ga:
        assert ga in page and "_ga" in page, "analytics running, page does not disclose it"
        assert "<b>Google</b>" in page, "Google receives data and is not listed as a recipient"
        assert "sets no cookies" not in page, "page denies cookies it is setting"
    else:
        assert "sets no cookies" in page, "no analytics, page should say so plainly"
        assert "<b>Google</b>" not in page, "Google listed as a recipient when it receives nothing"


def test_the_terms_exist_and_are_reachable(site):
    """Linked from the nav on every page, and from privacy, or nobody finds it."""
    assert (site / "terms" / "index.html").is_file()
    for page in ("index.html", "privacy/index.html", "security/index.html"):
        assert 'href="/terms/"' in (site / page).read_text("utf-8"), (
            f"/terms/ is unreachable from /{page}")


def test_the_licence_the_log_declares_is_actually_granted(log, tmp_path, monkeypatch):
    """The homepage declares a licence over the log. Every record in it was
    written by somebody else, so without a grant in the terms that declaration
    rests on nothing. These two must name the same licence.

    Built with SITE_BASE because the JSON-LD is gated on it: a relative
    contentUrl is invalid, so the whole block is omitted rather than emitted
    broken, and the declaration only exists in a production-shaped build.
    """
    from pow_generate.build import build

    monkeypatch.setenv("SITE_BASE", "https://example.org")
    out = tmp_path / "licensed"
    build(log, out)
    home = json.loads(
        (out / "index.html").read_text("utf-8")
        .split('<script type="application/ld+json">')[1].split("</script>")[0])
    declared = [n.get("license") for n in home.get("@graph", []) if n.get("license")]
    assert declared, "the homepage declares no licence over the log"

    terms = (out / "terms" / "index.html").read_text("utf-8")
    for licence in declared:
        assert licence in terms, (
            f"the log is published under {licence} but the terms grant no such licence")
    for must in ("irrevocable", "perpetual", "right to grant"):
        assert must in terms, f"the contributor grant never says {must!r}"


def test_the_terms_bound_what_may_be_filed(site):
    """Acceptable use is the only thing that reaches a contributor before they
    write to something that cannot be undone."""
    terms = (site / "terms" / "index.html").read_text("utf-8")
    for must in ("Personal data", "rights to publish", "unlawful", "as is"):
        assert must in terms, f"the terms never address {must!r}"


def test_the_chatgpt_terms_field_points_at_a_page_that_exists(site):
    import re
    from urllib.parse import urlparse

    text = (DEPLOY / "chatgpt-app.md").read_text("utf-8")
    field = re.search(r"\*\*Terms of use\*\*\s*—\s*(\S+)", text)
    assert field, "chatgpt-app.md declares no terms field"
    path = urlparse(field.group(1)).path.strip("/")
    assert (site / path / "index.html").is_file(), (
        f"terms field points at /{path}/, which the build does not produce")
