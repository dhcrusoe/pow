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
    607 lines of llms.txt — while seals gate E4, E5 and E7, three of the seven
    classes.
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
