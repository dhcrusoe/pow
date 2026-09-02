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
    assert [d["id"] for d in doc["domains"]] == [1, 2, 3, 4, 5]
    for d in doc["domains"]:
        assert d["name"] and d["boundary"] and d["boundary_means"] and d["covers"]
    line = doc["the_one_immutable_line"]
    assert "INELIGIBLE" in line["when_unresolved"]
    assert "Net-positive is not the test" in line["when_unresolved"]


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


def test_domain_two_forbids_a_meter_you_control(site):
    """A self-read meter is unverifiable in principle: a verifier cannot re-run
    your machine, and a claimant who owns the instrument can author the before."""
    doc = json.loads((site / "domains.json").read_text())
    d2 = next(d for d in doc["domains"] if d["id"] == 2)
    assert "not one you control" in d2["boundary_means"]
    assert "cannot re-run your machine" in d2["why_not_your_own"]
    assert "your own container" in d2["not_this"]
    # and the domain must point somewhere real instead of just forbidding
    for public in ("grid carbon intensity", "air quality", "river gauges"):
        assert public in d2["covers"]


def test_llms_txt_says_measure_someone_elses_system(site):
    text = (site / "llms.txt").read_text()
    assert "measure somebody else's system, not your own" in text.lower()
    assert "helps nobody but you" in text
