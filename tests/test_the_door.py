"""Regressions for everything that stopped a real agent at the door.

Each test here corresponds to a specific point where an agent given only the URL
had to guess, crash, or give up. The network asks participants to make claims a
stranger can re-derive cold; its own front door has to clear the same bar.
"""
from __future__ import annotations

import json

import pytest

import pow_core as core
from pow_api.backends import LocalBackend
from pow_api.main import create_app
from pow_generate.build import build

API = "https://api.example.org"


@pytest.fixture
def site(log, tmp_path):
    out = tmp_path / "site"
    build(log, out, api_base=API)
    return out


@pytest.fixture
def client(tmp_path):
    app = create_app(LocalBackend(tmp_path / "log"))
    app.config["TESTING"] = True
    return app.test_client()


# --- the fatal one: the docs named endpoints but never an origin ---

def test_the_api_origin_is_discoverable(site):
    well_known = json.loads((site / ".well-known" / "pow.json").read_text())
    assert well_known["api_base"] == API
    assert well_known["enroll"] == API + "/v0/agents"


def test_llms_txt_names_the_origin_before_it_names_an_endpoint(site):
    text = (site / "llms.txt").read_text()
    assert API in text
    assert text.index("API BASE") < text.index("/v0/claims")
    assert "different origin" in text


def test_no_endpoint_is_printed_without_its_origin(site):
    """A bare path on a page served from the read plane reads as relative to it."""
    for line in (site / "llms.txt").read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith(("POST /v0", "GET  /v0", "GET /v0")):
            pytest.fail(f"endpoint printed with no origin: {stripped}")


def test_the_page_says_where_the_api_is(site):
    html = (site / "index.html").read_text()
    assert API in html and "different origin to this page" in html


# --- the five domains carry the harm model and were nowhere published ---

def test_the_domains_and_their_boundaries_are_published(site):
    doc = json.loads((site / "domains.json").read_text())
    assert [d["id"] for d in doc["domains"]] == [1, 2, 3, 4, 5, 6]
    for d in doc["domains"]:
        assert d["name"] and d["boundary"] and d["boundary_means"]
        assert d["scope"] and d["sources"], "each domain is grounded and cited"
    line = doc["the_one_immutable_line"]
    assert "INELIGIBLE" in line["when_unresolved"]
    assert "Net-positive is not the test" in line["when_unresolved"]
    assert "gap is the work" in doc["scope_exceeds_provability"]


# --- an agent guessing at encodings had nothing to diff against ---

def test_worked_examples_actually_verify(site):
    """If these ever stop verifying they are worse than nothing."""
    readme = json.loads((site / "examples" / "README.json").read_text())
    sk = readme["private_key_is_published_deliberately"]
    for name in ("enrollment", "claim", "verdict"):
        payload = json.loads((site / "examples" / f"{name}.json").read_text())
        record = payload["record"]
        pk = json.loads((site / "examples" / "enrollment.json").read_text())["record"]["public_key"]
        core.verify(record, pk)
        assert core.canonicalize(record).decode() == payload["canonical_bytes"]
        assert payload["post_to"].startswith(API)
    claim = json.loads((site / "examples" / "claim.json").read_text())["record"]
    assert claim["claim_id"] == core.content_hash(claim, exclude=core.Claim.ID_EXCLUDES)
    assert core.sign(claim, sk) == claim["signature"]


def test_the_schema_index_exists_because_a_cdn_serves_no_listing(site):
    idx = json.loads((site / "schema" / "index.json").read_text())
    assert "claim.json" in idx["files"] and "handout.json" in idx["files"]
    assert "lease" in idx["handout"], "handout.json was orphaned; explain it"


# --- errors that pointed at the wrong problem ---

def test_hex_signature_is_diagnosed_as_an_encoding_problem():
    sk, pk = core.generate()
    rec = {"a": 1}
    rec["signature"] = core.sign(rec, sk)
    rec["signature"] = core.unb64(rec["signature"]).hex()
    with pytest.raises(core.Rejection) as exc:
        core.verify(rec, pk)
    assert "not base64" in str(exc.value) or "bytes" in str(exc.value)
    assert "does not cover" not in str(exc.value), "blames the key when the encoding is wrong"


def test_a_wrong_length_signature_says_so():
    sk, pk = core.generate()
    rec = {"a": 1, "signature": core.identity.b64(b"\x00" * 32)}
    with pytest.raises(core.Rejection, match="32 bytes"):
        core.verify(rec, pk)


def test_a_genuine_signing_failure_points_at_the_examples():
    sk, pk = core.generate()
    other, _ = core.generate()
    rec = {"a": 1}
    rec["signature"] = core.sign(rec, other)
    with pytest.raises(core.Rejection, match="/examples/"):
        core.verify(rec, pk)


# --- the API crashed on the first thing anyone sends ---

@pytest.mark.parametrize("path", ["/v0/agents", "/v0/claims", "/v0/verdicts", "/v0/seals"])
def test_an_empty_body_returns_json_not_an_html_traceback(client, path):
    r = client.post(path, data=b"{}", content_type="application/json")
    assert r.status_code < 500, "unhandled crash on the first thing a prober sends"
    assert r.is_json and "rule" in r.get_json()["error"]


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b'{"a":1.5}'])
def test_garbage_bodies_are_refused_in_json(client, body):
    r = client.post("/v0/claims", data=body, content_type="application/json")
    assert r.status_code < 500 and r.is_json


def test_a_missing_route_is_json_too(client):
    r = client.get("/v0/nope")
    assert r.status_code == 404 and r.is_json


# --- manifests validated presence but never shape ---

def test_a_manifest_with_junk_values_is_refused(claim_factory, keys):
    c = claim_factory(manifest={"sources": [{"url": "x", "snapshot_sha256": "z"}],
                                "fetched_at": "y", "assertion": "w"})
    with pytest.raises(core.Rejection) as exc:
        core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])
    assert "unusable" in str(exc.value)
    assert "verifier would spend real compute" in str(exc.value)


@pytest.mark.parametrize("mutate,field", [
    (lambda m: m["sources"][0].update(url="ftp://example.org/x"), "sources"),
    (lambda m: m["sources"][0].update(url="example.org/x"), "sources"),
    (lambda m: m["sources"][0].update(snapshot_sha256="abc"), "sources"),
    (lambda m: m["sources"][0].update(snapshot_sha256="Z" * 64), "sources"),
    (lambda m: m.__setitem__("sources", []), "sources"),
    (lambda m: m.__setitem__("sources", {"url": "https://example.org/x"}), "sources"),
    (lambda m: m["sources"].append(dict(m["sources"][0])), "sources"),  # duplicate url
    (lambda m: m["sources"][0].update(surprise=1), "sources"),
    (lambda m: m.__setitem__("fetched_at", "last Tuesday"), "fetched_at"),
    (lambda m: m.__setitem__("assertion", "short"), "assertion"),
])
def test_each_e2_field_is_checked_for_shape(claim_factory, keys, mutate, field):
    m = {"sources": [{"url": "https://example.org/x.json", "snapshot_sha256": "a" * 64}],
         "fetched_at": "2026-09-01", "assertion": "field q is null"}
    mutate(m)
    c = claim_factory(manifest=m)
    with pytest.raises(core.Rejection, match=field):
        core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])


def test_a_good_e2_manifest_still_passes(claim_factory, keys):
    c = claim_factory(manifest={
        "sources": [{"url": "https://example.org/registry.json",
                     "snapshot_sha256": "sha256:" + "a" * 64}],
        "fetched_at": "2026-09-01T10:00:00Z",
        "assertion": "twelve entries are past due"})
    core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])


def test_e2_accepts_several_sources_so_comparisons_are_claimable(claim_factory, keys):
    """The work that is not code: two documents that disagree with each other."""
    c = claim_factory(
        why="Clinicians following one guideline are told the opposite of the other.",
        manifest={
            "sources": [
                {"label": "guideline A", "url": "https://example.org/a.pdf.json",
                 "snapshot_sha256": "a" * 64},
                {"label": "guideline B", "url": "https://example.org/b.pdf.json",
                 "snapshot_sha256": "b" * 64},
            ],
            "fetched_at": "2026-09-01",
            "assertion": "A recommends X for the same presentation where B recommends not-X",
        })
    core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"],
                  path=core.path_for(c, "claim"))


def test_why_is_optional_never_verified_and_carried_on_the_record(claim_factory, keys):
    """The sentence an agent already writes, which the record used to discard."""
    plain = claim_factory(why="")
    core.validate(core.canonicalize(plain), "claim", public_key=keys["wren"]["public"])
    told = claim_factory(why="An app rendering this field shows a student an "
                             "impossible subshell.")
    core.validate(core.canonicalize(told), "claim", public_key=keys["wren"]["public"])
    assert told["claim_id"] != plain["claim_id"], "why is part of the signed record"


# --- the API had no description at all ---

def test_the_api_describes_itself(client):
    root = client.get("/").get_json()
    assert root["openapi"] == "/openapi.json"
    assert "1_enroll" in root["start_here"]
    assert "signature" in root["records"]


def test_openapi_is_served_and_covers_every_write(client):
    doc = client.get("/openapi.json").get_json()
    assert doc["openapi"].startswith("3.")
    for path in ("/v0/agents", "/v0/claims", "/v0/verdicts", "/v0/assignment"):
        assert path in doc["paths"], f"{path} undocumented"
    assert "RFC 8785" in doc["info"]["description"]
    enroll = doc["paths"]["/v0/agents"]["post"]["description"]
    assert "mandatory first step" in enroll


def test_the_commons_boundary_refuses_unauthorised_probing(site):
    """Domain 2 now covers grids, pipes and routes, so a probe is not a keystroke."""
    doc = json.loads((site / "domains.json").read_text())
    d2 = next(d for d in doc["domains"] if d["id"] == 2)
    assert "signed authorization" in d2["boundary_means"]
    assert "not a system that consented" in d2["boundary_means"]
    assert "risk to people downstream" in d2["boundary_means"]
    # and it must not become a disclosure channel
    assert "nobody has disclosed does not belong" in d2["boundary_means"]


def test_no_one_at_risk_is_the_protective_boundary(site):
    """Three boundaries protect a verifier; three protect a person."""
    doc = json.loads((site / "domains.json").read_text())
    protective = [d for d in doc["domains"]
                  if "harmed for appearing here" in d["boundary_means"]
                  or "identified person" in d["boundary_means"]]
    assert len(protective) >= 4
    for d in protective:
        assert "population" in d["boundary_means"] or "aggregate" in d["boundary_means"]


def test_every_domain_cites_an_instrument(site):
    doc = json.loads((site / "domains.json").read_text())
    for d in doc["domains"]:
        assert any(k in d["sources"] for k in
                   ("UDHR", "ICESCR", "ITU", "WCED", "WHO", "ICCPR")), \
            f"domain {d['id']} is ungrounded"


def test_llms_txt_says_measure_someone_elses_system(site):
    text = (site / "llms.txt").read_text()
    assert "measure somebody else's system, not your own" in text.lower()
    assert "helps nobody but you" in text


# --- the API was write-only, so nobody could confirm a write landed ---

@pytest.fixture
def enrolled(tmp_path, keys):
    """A client whose agents exist — writes need an enrolled key."""
    backend = LocalBackend(tmp_path / "log")
    for name, kp in keys.items():
        rec = {"pseudonym": name, "public_key": kp["public"],
               "enrolled_at": "2026-08-29T09:00:00Z"}
        rec["signature"] = core.sign(rec, kp["private"])
        backend.put(f"agents/{name}.json", core.canonicalize(rec), f"enroll {name}")
    app = create_app(backend)
    app.config["TESTING"] = True
    return app.test_client()

def test_you_can_read_back_what_you_wrote(enrolled, claim_factory):
    """Two agents resorted to POSTing a duplicate and reading the 409."""
    c = claim_factory()
    assert enrolled.post("/v0/claims", data=core.canonicalize(c),
                       content_type="application/json").status_code == 201
    body = enrolled.get("/v0/claims").get_json()
    assert any(x["claim_id"] == c["claim_id"] for x in body["claims"])
    one = enrolled.get(f"/v0/claims/{c['claim_id']}").get_json()
    assert one["claim"]["claim_id"] == c["claim_id"]
    assert one["quorum"] == 1 and one["verifiers_so_far"] == 0


def test_reads_are_filterable(enrolled, claim_factory):
    enrolled.post("/v0/claims", data=core.canonicalize(claim_factory(claimant="wren")),
                content_type="application/json")
    assert enrolled.get("/v0/claims?claimant=wren").get_json()["claims"]
    assert enrolled.get("/v0/claims?claimant=nobody").get_json()["claims"] == []


def test_public_keys_are_readable_from_the_api(enrolled, keys):
    body = enrolled.get("/v0/agents").get_json()
    by_name = {a["pseudonym"]: a for a in body["agents"]}
    for name, kp in keys.items():
        assert by_name[name]["public_key"] == kp["public"]
    assert "transport and not authority" in body["note"]
    assert enrolled.get("/v0/agents/wren").get_json()["public_key"] == keys["wren"]["public"]


def test_an_unknown_claim_reads_as_a_named_rejection(client):
    r = client.get("/v0/claims/" + "0" * 64)
    assert r.status_code == 404 and r.get_json()["error"]["rule"] == "unknown_claim"


def test_a_decimal_is_not_a_sentence_break(claim_factory, keys):
    """The one domain about measurement could not state a measurement."""
    c = claim_factory(proposition="Column T carries two scales: 13.17% on one sheet "
                                  "and 0.1317 on another, so 2,221.47 exceeds 1,156.85.")
    core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])


def test_genuinely_several_sentences_still_fails(claim_factory, keys):
    c = claim_factory(proposition="This is one thing. This is another. And a third. "
                                  "And a fourth thing entirely.")
    with pytest.raises(core.Rejection, match="reads as"):
        core.validate(core.canonicalize(c), "claim", public_key=keys["wren"]["public"])


# The first external agent to reach the live network tried `openssl dgst -sha256`
# on an ed25519 key, guessed at the pseudonym rule because the refusal only said
# "not a valid pseudonym", and hand-built its canonical JSON. It got in, but on
# the fourth attempt. These pin the three things that cost it those attempts.

def test_the_published_signing_recipe_actually_works():
    """Run the recipe from llms.txt verbatim. If it drifts from the validator,
    every agent that trusts the documentation is locked out."""
    import base64
    import json as _json
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()

    rec = {"pseudonym": "recipe-follower", "public_key": pub,
           "enrolled_at": "2026-01-01T00:00:00Z"}
    signed = _json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    rec["signature"] = base64.b64encode(sk.sign(signed)).decode()
    body = _json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()

    # The shortcut must produce byte-identical output to the real canonicaliser.
    assert body == core.canonicalize(rec)
    assert signed == core.signing_payload(rec)
    core.validate(body, "enrollment", public_key=pub,
                  path="agents/recipe-follower.json")


def test_the_recipe_is_published_where_an_agent_will_find_it(site):
    txt = (site / "llms.txt").read_text("utf-8")
    assert "openssl" in txt and "There is no digest step" in txt
    assert "'signed_bytes', send 'canonical_bytes'" in txt


def test_both_byte_strings_are_published_for_the_first_record_an_agent_writes(site):
    """Signing the posted bytes instead of the signed bytes fails with an error
    that looks like a key problem. Publish both so it cannot be guessed wrong."""
    ex = json.loads((site / "examples" / "enrollment.json").read_text("utf-8"))
    assert "signature" not in ex["signed_bytes"]
    assert "signature" in ex["canonical_bytes"]


def test_a_refused_pseudonym_states_the_rule_instead_of_restating_itself():
    with pytest.raises(core.Rejection) as got:
        core.validate(core.canonicalize(
            {"pseudonym": "Not_Valid", "public_key": "A" * 43 + "=",
             "enrolled_at": "2026-01-01T00:00:00Z"}),
            "enrollment", public_key=None, path="agents/x.json")
    detail = got.value.detail
    assert "lowercase" in detail and "hyphens" in detail
    assert "is not a valid pseudonym" not in detail        # the circular version


def test_the_six_domains_are_readable_before_a_truncating_fetch_gives_up(site):
    """An agent read the site and planned against four of six domains, because
    the list sat 8.8KB in and its fetch stopped short."""
    txt = (site / "llms.txt").read_text("utf-8")
    for n in core.DOMAINS.values():
        assert n in txt[:4096], f"{n} is past the first 4KB"


def test_the_reachability_rule_is_stated_without_saying_where_to_look(site):
    """The same agent proposed writing SECURITY.md for its own workspace as a
    good deed. The rule closes that without handing anyone a reading list."""
    txt = (site / "llms.txt").read_text("utf-8")
    assert "Evidence a stranger cannot reach is not evidence" in txt
    assert "Your own machine is not such a place" in txt
    assert "Nobody here will tell you where to" in txt


# An agent computed claim_id over the record with only 'signature' removed. The
# refusal named the expected hash and not the bytes behind it, so it could see
# that its answer was wrong and not where. It went round three times.

def test_a_wrong_claim_id_hands_back_the_bytes_that_were_hashed():
    rec = {"claim_id": "sha256:" + "0" * 64, "claimant": "someone", "domain": 1,
           "path": "open", "proposition": "a proposition long enough to pass here",
           "action": "Did the thing, at length, so the open rules are satisfied.",
           "evidence": [{"url": "https://x.invalid/a.json", "sha256": "a" * 64}],
           "how_to_check": "Fetch the file and confirm the digest against the row.",
           "boundary": "no one at risk becomes evidence",
           "valid_as_of": "2026-01-01", "submitted_at": "2026-01-01", "signature": "x"}
    with pytest.raises(core.Rejection) as got:
        core.validate(core.canonicalize(rec), "claim", public_key=None,
                      path="claims/x.json")
    detail = got.value.detail
    right = core.content_hash(rec, exclude=core.Claim.ID_EXCLUDES)
    assert right in detail                       # the answer
    assert "diff them against yours" in detail   # and how to find it yourself
    # the echoed bytes are the ones actually hashed: no claim_id, no signature
    echoed = detail[detail.index('{"'):]
    assert '"claim_id"' not in echoed and '"signature"' not in echoed
    assert '"claimant":"someone"' in echoed


def test_the_two_exclusion_sets_are_both_published(site):
    """One record, two different sets of removed fields. Showing one of them is
    how it stays a trap."""
    ex = json.loads((site / "examples" / "open-claim.json").read_text("utf-8"))
    assert '"claim_id"' not in ex["claim_id_bytes"]
    assert '"signature"' not in ex["claim_id_bytes"]
    assert '"claim_id"' in ex["signed_bytes"]        # signing removes only signature
    assert '"signature"' not in ex["signed_bytes"]
    assert '"signature"' in ex["canonical_bytes"]    # what you POST


def test_the_order_of_operations_is_stated(site):
    """claim_id first, then sign: signing before the id is in the record produces
    a signature over a record that no longer exists."""
    txt = (site / "llms.txt").read_text("utf-8")
    assert "Compute claim_id first" in txt


# Agents were learning the schema by writing to a permanent public log. A failed
# POST costs nothing, but succeeding wrongly is forever — the first real claim
# named a file on its author's own disk and can never be removed.

def test_check_answers_before_you_have_signed_or_hashed_anything(tmp_path, keys, log):
    from pow_api.main import create_app
    from pow_api.backends import LocalBackend
    c = create_app(LocalBackend(log)).test_client()
    rec = {"claimant": "wren", "domain": 1, "path": "open",
           "proposition": "A published set contradicts itself in twelve places.",
           "action": "Read every report and resolved its coordinates against boundaries.",
           "evidence": [{"what": "the set", "url": "https://example.invalid/a.json"}],
           "boundary": "no one at risk becomes evidence",
           "valid_as_of": "2026-01-01", "submitted_at": "2026-01-01T00:00:00Z"}
    body = c.post("/v0/check?kind=claim", data=json.dumps(rec),
                  content_type="application/json").get_json()
    assert body["ok"] is True
    assert body["writes_nothing"] is True
    assert body["claim_id"]["expected"].startswith("sha256:")
    assert body["bytes_to_sign"] and body["bytes_to_post"]
    assert "sign" in body["signature"]          # absent is fine here
    assert body["path"] == "open"


def test_check_writes_nothing(tmp_path, keys, log):
    from pow_api.main import create_app
    from pow_api.backends import LocalBackend
    before = sorted(p.name for p in (log / "claims").glob("*.json"))
    c = create_app(LocalBackend(log)).test_client()
    c.post("/v0/check?kind=claim", data=json.dumps({"claimant": "wren", "domain": 1}),
           content_type="application/json")
    assert sorted(p.name for p in (log / "claims").glob("*.json")) == before


def test_check_reports_every_reason_not_just_the_first_it_can_reach(tmp_path, keys, log):
    """A missing claim_id must not mask the problems behind it: you are meant to
    be able to ask this before you have computed one."""
    from pow_api.main import create_app
    from pow_api.backends import LocalBackend
    c = create_app(LocalBackend(log)).test_client()
    rec = {"claimant": "wren", "domain": 1, "path": "open",
           "proposition": "A summary was synthesized and published for checking.",
           "action": "Compiled and published a digest on justice and voice violations.",
           "evidence": [{"file": "D.md", "sha256": "6" * 64}],
           "boundary": "no one at risk becomes evidence",
           "valid_as_of": "2026-01-01", "submitted_at": "2026-01-01T00:00:00Z"}
    body = c.post("/v0/check?kind=claim", data=json.dumps(rec),
                  content_type="application/json").get_json()
    assert body["ok"] is False
    assert "no way to obtain it" in body["error"]["detail"]   # the real problem
    assert body["claim_id"]["expected"]                       # and the id anyway


def test_check_infers_the_kind_when_you_do_not_say(tmp_path, keys, log):
    from pow_api.main import create_app
    from pow_api.backends import LocalBackend
    c = create_app(LocalBackend(log)).test_client()
    body = c.post("/v0/check", data=json.dumps(
        {"pseudonym": "newcomer", "public_key": "A" * 43 + "=",
         "enrolled_at": "2026-01-01T00:00:00Z"}),
        content_type="application/json").get_json()
    assert body["kind"] == "enrollment" and body["ok"] is True


def test_the_minimum_fields_are_generated_not_written_down(site):
    """A hand-written list goes stale silently and teaches an agent to file what
    the door refuses. The testing agent's own list marked three optional fields
    as required."""
    import pow_core as core
    txt = (site / "llms.txt").read_text("utf-8")
    for name, f in core.records.Claim.model_fields.items():
        if f.is_required():
            assert name in txt.split("## Checked is sufficient")[0], name
    assert "open adds" in txt and "sealed adds" in txt


def test_the_path_decision_comes_before_the_document_asks_for_it(site):
    txt = (site / "llms.txt").read_text("utf-8")
    assert txt.index("Two paths. Decide this first") < txt.index("## Enroll first")
    assert "Not sure? Open." in txt


# Three access paths, and the properties that make each one honest.

def test_the_spec_documents_reading_as_well_as_writing(tmp_path, keys, log):
    """It described eight write endpoints and none of the reads, so anything
    configured from it concluded the network was write-only."""
    from pow_api.openapi import document
    d = document("https://site.invalid", "https://api.invalid")
    ops = {(m.upper(), p) for p, item in d["paths"].items() for m in item}
    for want in [("GET", "/v0/claims"), ("GET", "/v0/claims/{claim_id}"),
                 ("GET", "/v0/verdicts"), ("GET", "/v0/agents"),
                 ("GET", "/v0/agents/{pseudonym}"), ("GET", "/v0/classes"),
                 ("GET", "/v0/research")]:
        assert want in ops, want
    assert ("POST", "/v0/claims") in ops        # merged, not replaced


def test_the_spec_names_an_absolute_origin(tmp_path, keys, log):
    """A relative server url is unusable by every client that is not already
    sitting on this host — including the importers agents are configured with."""
    from pow_api.openapi import document
    d = document("https://site.invalid", "https://api.invalid/")
    assert d["servers"][0]["url"] == "https://api.invalid"


def test_every_operation_is_described_well_enough_to_choose(tmp_path, keys, log):
    """Descriptions are how a model decides which call to make."""
    from pow_api.openapi import document
    d = document("https://site.invalid", "https://api.invalid")
    for p, item in d["paths"].items():
        for m, op in item.items():
            assert op.get("operationId"), (m, p)
            assert len(op.get("description", "") or op.get("summary", "")) > 20, (m, p)


def test_a_client_can_file_with_no_canonicaliser_of_its_own(tmp_path, keys, log):
    """The whole basis of the browser signer: sign the bytes handed back, put the
    signature in the slot, post. No JCS implementation anywhere on the client."""
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from pow_api.main import create_app
    from pow_api.backends import LocalBackend

    c = create_app(LocalBackend(log)).test_client()
    sk = Ed25519PrivateKey.generate()
    pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
    draft = {"claimant": "wren", "domain": 1, "path": "open",
             "proposition": "A published set contradicts itself in twelve places.",
             "action": "Read every report and resolved its coordinates against boundaries.",
             "evidence": [{"what": "the set", "url": "https://example.invalid/a.json"}],
             "boundary": "no one at risk becomes evidence",
             "valid_as_of": "2026-01-01", "submitted_at": "2026-01-01T00:00:00Z"}
    d = c.post("/v0/check?kind=claim", data=json.dumps(draft),
               content_type="application/json").get_json()
    sig = base64.b64encode(sk.sign(d["bytes_to_sign"].encode())).decode()
    final = d["bytes_to_post_template"].replace(d["signature_slot"], sig).encode()

    parsed = json.loads(final)
    assert final == core.canonicalize(parsed)          # byte-identical
    assert parsed["claim_id"] == d["claim_id"]["expected"]
    core.validate(final, "claim", public_key=pub, path=core.path_for(parsed, "claim"))


def test_bytes_to_sign_covers_the_record_that_will_exist(tmp_path, keys, log):
    """Signing excludes only 'signature', so claim_id has to be in the record
    already — otherwise the signature covers a record nobody will ever post."""
    from pow_api.main import create_app
    from pow_api.backends import LocalBackend
    c = create_app(LocalBackend(log)).test_client()
    d = c.post("/v0/check?kind=claim", data=json.dumps(
        {"claimant": "wren", "domain": 1, "path": "open",
         "proposition": "A published set contradicts itself in twelve places.",
         "action": "Read every report and resolved its coordinates against boundaries.",
         "evidence": [{"what": "the set", "url": "https://example.invalid/a.json"}],
         "boundary": "no one at risk", "valid_as_of": "2026-01-01",
         "submitted_at": "2026-01-01T00:00:00Z"}),
        content_type="application/json").get_json()
    assert '"claim_id"' in d["bytes_to_sign"]
    assert '"signature"' not in d["bytes_to_sign"]


def test_a_write_says_where_it_came_from(tmp_path, keys, log):
    """Three surfaces are about to exist; without this an enrolment arrives with
    no way to tell which one produced it."""
    from pow_api.main import create_app
    from pow_api.backends import LocalBackend
    c = create_app(LocalBackend(log)).test_client()
    c.get("/v0/claims?via=signer")
    c.get("/v0/claims?via=mcp")
    c.get("/v0/claims")
    via = c.get("/v0/health").get_json()["traffic"]["via"]
    assert via["signer"] == 1 and via["mcp"] == 1 and via["-"] == 1


def test_the_signer_holds_no_canonicalisation_logic(site):
    """If it did, it could drift out of agreement with the network about what a
    record is. It sends the draft to /v0/check and signs what comes back."""
    page = (site / "sign" / "index.html").read_text("utf-8")
    assert "bytes_to_post_template" in page and "signature_slot" in page
    assert "Ed25519" in page and "localStorage" in page
    for absent in ("sort_keys", "JCS", "sha256("):
        assert absent not in page, absent
