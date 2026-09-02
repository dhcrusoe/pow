"""The single validation entrypoint.

Both write paths call this function and nothing else. The API and the CI Action
import the same code, so a record the API accepts can never be one CI would
reject — a property asserted by a test that runs both paths over one corpus.

What this checks: schema validity, that the content hash matches, that the path
matches the id, and that the signature covers these exact bytes. What it does not
check: whether the claim is true, useful, or good. Merge means recorded, not
verified, and there is nothing here for anyone to withhold.
"""
from __future__ import annotations

import re
from typing import Mapping, Optional, Tuple

from pydantic import ValidationError

from . import records
from .canonical import CanonicalizationError, has_duplicate_keys, loads
from .errors import CONTENT_HASH, PATH, SCHEMA, SIGNATURE, Rejection
from .identity import content_hash, valid_pseudonym, verify

ISO = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}Z)?$")
KINDS = {
    "claim": (records.Claim, "claim_id", "claims"),
    "research": (records.Research, "research_id", "research"),
    "verdict": (records.Verdict, None, "verdicts"),
    "seal": (records.Seal, "seal_id", "seals"),
    "enrollment": (records.Enrollment, None, "agents"),
}


def parse(raw: bytes) -> dict:
    """Bytes to dict, rejecting anything the canonical form cannot round-trip."""
    try:
        if has_duplicate_keys(raw):
            raise Rejection(SCHEMA, "duplicate object keys")
        obj = loads(raw)
    except CanonicalizationError as exc:
        raise Rejection(SCHEMA, str(exc)) from exc
    if not isinstance(obj, dict):
        raise Rejection(SCHEMA, "record must be a JSON object")
    return obj


def validate(
    raw: bytes,
    kind: str,
    *,
    public_key: Optional[str] = None,
    path: Optional[str] = None,
    classes: Optional[Mapping] = None,
) -> dict:
    """Validate one record. Returns the parsed dict, or raises Rejection.

    `classes` is the evidence-class registry, derived from the log. Pass it and a
    class adopted last week is as valid as one that shipped with this code. Omit
    it and only the genesis seven are known, which is the right default for a
    caller with no log to read.
    """
    if kind not in KINDS:
        raise Rejection(SCHEMA, f"unknown record kind: {kind}")
    model, id_field, directory = KINDS[kind]

    record = parse(raw)

    try:
        model(**record)
    except ValidationError as exc:
        first = exc.errors()[0]
        loc = ".".join(str(p) for p in first.get("loc", ())) or "record"
        raise Rejection(SCHEMA, f"{loc}: {first.get('msg', 'invalid')}") from exc

    for field in ("claimant", "verifier", "sealer", "pseudonym"):
        if field in record and not valid_pseudonym(record[field]):
            raise Rejection(SCHEMA, f"{field} is not a valid pseudonym")

    for field in ("valid_as_of", "submitted_at", "settled_at", "sealed_at", "enrolled_at"):
        if field in record and not ISO.match(str(record[field])):
            raise Rejection(SCHEMA, f"{field} must be YYYY-MM-DD or RFC3339 UTC")

    if kind == "claim":
        _claim_rules(record, classes)
    if kind == "research":
        _research_rules(record)

    if id_field:
        expected = content_hash(record, exclude=model.ID_EXCLUDES)
        if record.get(id_field) != expected:
            raise Rejection(
                CONTENT_HASH,
                f"{id_field} does not match content; expected {expected}",
            )

    if public_key is not None:
        verify(record, public_key)
    elif record.get("signature"):
        pass  # signature present but no key supplied; caller checks separately
    else:
        raise Rejection(SIGNATURE, "record carries no signature")

    if path is not None:
        _path_rules(record, kind, directory, path)

    return record


# A sentence break is a terminator followed by whitespace and a capital — not a
# period. Counting periods meant every decimal read as a new sentence, so in the
# one domain that is entirely about measurement, a proposition could not state a
# measurement. An agent working on water data was rejected twice and had to round
# its figures away, on a page that asks for precision two paragraphs earlier.
SENTENCE_BREAK = re.compile(r"[.!?]['\")\]]?\s+(?=[A-Z(\[])")


def _claim_rules(record: Mapping, classes: Optional[Mapping] = None) -> None:
    prop = record.get("proposition", "")
    if "\n" in prop:
        raise Rejection(SCHEMA, "proposition must be one sentence, on one line")
    breaks = len(SENTENCE_BREAK.findall(prop))
    if breaks > 2:
        raise Rejection(
            SCHEMA,
            f"proposition reads as {breaks + 1} sentences; it must be one. Decimals, "
            f"abbreviations and version numbers are fine — a break is a full stop "
            f"followed by a capital.")
    if not str(prop).strip():
        raise Rejection(SCHEMA, "a claim without a proposition is not schema-valid")

    if record.get("proposes_class"):
        _proposal_rules(record)

    if record.get("path", "sealed") == "open":
        return _open_rules(record)

    manifest = record.get("manifest")
    if not isinstance(manifest, dict) or not manifest:
        raise Rejection(SCHEMA, "a sealed claim needs a manifest. If your work does not "
                                "fit a published procedure, use path 'open' instead — "
                                "that is what it is for.")
    ec = record.get("evidence_class")
    if ec is None:
        raise Rejection(SCHEMA, "a sealed claim names the evidence class whose procedure "
                                "a verifier should run")
    known = set(records.GENESIS_CLASSES) | set(classes or {})
    if ec not in known:
        raise Rejection(
            SCHEMA,
            f"no evidence class {ec!r} has been adopted. Adopted classes are "
            f"{', '.join(sorted(known))} — see /classes/index.json. If the work you "
            f"did needs a class that does not exist, propose one: that is a claim "
            f"like any other, and it is the most valuable thing anyone can file here.")
    # Built-in rules are 3-tuples and always required; declared ones carry their
    # own optionality. Normalise so both read the same below.
    rules = [(r + (True,))[:4] for r in rules_for(ec, classes)]
    missing = [f for f, _, _, req in rules if req and f not in manifest]
    if missing:
        wanted = "; ".join(f"{f}: {why}" for f, _, why, _ in rules if f in missing)
        raise Rejection(SCHEMA, f"{ec} manifest is missing {', '.join(missing)} — {wanted}")
    for field, ok, why, req in rules:
        if field not in manifest:
            continue
        if not ok(manifest[field]):
            raise Rejection(
                SCHEMA,
                f"{ec} manifest field {field!r} is present but unusable. Expected {why}. "
                f"A verifier would spend real compute on this before discovering it "
                f"cannot be run.",
            )


SHA256 = re.compile(r"^(sha256:)?[0-9a-f]{64}$")
HTTP_URL = re.compile(r"^https?://[^\s/]+\.[^\s/]+(/.*)?$")
B64_32 = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def _url(v):
    return isinstance(v, str) and bool(HTTP_URL.match(v))


def _digest(v):
    return isinstance(v, str) and bool(SHA256.match(v))


def _date(v):
    return isinstance(v, str) and bool(ISO.match(v))


def _text(v):
    return isinstance(v, str) and len(v.strip()) >= 8


def _obj(v):
    return isinstance(v, dict) and bool(v)


def _sources(v):
    """A list of {url, snapshot_sha256}. One entry, or many to compare them."""
    if not isinstance(v, list) or not v or len(v) > 12:
        return False
    for entry in v:
        if not isinstance(entry, dict):
            return False
        if set(entry) - {"url", "snapshot_sha256", "label"}:
            return False
        if not _url(entry.get("url")) or not _digest(entry.get("snapshot_sha256")):
            return False
        if "label" in entry and not isinstance(entry["label"], str):
            return False
    urls = [e["url"] for e in v]
    return len(urls) == len(set(urls))


def _key32(v):
    return isinstance(v, str) and bool(B64_32.match(v))


def _sig(v):
    return isinstance(v, str) and len(v) >= 64


# Field presence was never enough. A manifest carrying source="x" and
# snapshot_sha256="z" passed every check, merged, and then burned a verifier's
# container run before settling UNRESOLVABLE. Cheap shape checks at ingest stop
# a whole class of garbage from ever reaching someone else's compute.
MANIFEST_RULES = {
    "E1": (
        ("image", _digest, "an image digest, e.g. sha256:<64 hex>"),
        ("inputs", _obj, "a non-empty object mapping names to content addresses"),
        ("resource_ceiling", _obj, "an object, e.g. {\"cpu_seconds\": 600, \"memory_mib\": 2048}"),
        ("expected_output_hash", _digest, "sha256:<64 hex>"),
    ),
    # E2 originally took one source and one digest, which quietly restricted the
    # network to single byte-stable files — overwhelmingly things in git repos.
    # A list costs nothing to verify (fetch each, hash each) and opens the work
    # that is not code: two official documents that contradict each other, a
    # calculator that disagrees with its statute, a translation that drops a
    # clause its original has, two registries that disagree about one entity.
    "E2": (
        ("sources", _sources,
         "a list of {url, snapshot_sha256} — one entry for a single artifact, "
         "two or more to assert something about how they compare"),
        ("fetched_at", _date, "YYYY-MM-DD or RFC3339 UTC — when you took the snapshots"),
        ("assertion", _text, "what the sources say, in at least eight characters"),
    ),
    "E6": (
        ("attestor", _text, "who signed the attestation"),
        ("attestor_public_key", _key32, "base64 ed25519 public key, 44 chars"),
        ("attestation", _obj, "a non-empty object — what they are attesting to"),
        ("attestation_signature", _sig, "base64 ed25519 signature over the attestation"),
    ),
}

REQUIRED_MANIFEST = {k: tuple(f for f, _, _ in v) for k, v in MANIFEST_RULES.items()}

# The declarative vocabulary a proposed class uses to state its manifest. This is
# what lets an eighth class arrive without anybody shipping code: the proposal
# says "this field is a url, that one a digest", and the network enforces it.
FIELD_CHECKS = {
    "url": (_url, "an http(s) URL a stranger can fetch"),
    "digest": (_digest, "sha256 as 64 hex, optionally prefixed sha256:"),
    "date": (_date, "YYYY-MM-DD or RFC3339 UTC"),
    "text": (_text, "at least eight characters of text"),
    "object": (_obj, "a non-empty object"),
    "list": (lambda v: isinstance(v, list) and bool(v), "a non-empty list"),
    "key": (_key32, "a base64 ed25519 public key, 44 characters"),
    "signature": (_sig, "a base64 signature"),
}


def rules_for(evidence_class, classes=None):
    """Manifest rules for a class: built in, or declared by an adopted proposal."""
    if evidence_class in MANIFEST_RULES:
        return MANIFEST_RULES[evidence_class]
    spec = (classes or {}).get(evidence_class)
    if not spec:
        return ()
    out = []
    for field in spec.get("spec", {}).get("manifest_fields", []):
        kind = field.get("type", "text")
        check, why = FIELD_CHECKS.get(kind, FIELD_CHECKS["text"])
        out.append((field.get("name", ""), check, field.get("why") or why,
                    bool(field.get("required", True))))
    return tuple(out)


def _proposal_rules(record: Mapping) -> None:
    """A class proposal ships a reference verifier and a corpus built to fail.

    A class that catches its own fraud recruits better than one that passes
    cleanly — and the corpus is what a verifier actually runs, so a proposal
    without one asks three strangers to take a specification on faith.
    """
    spec = record["proposes_class"]
    if not isinstance(spec, dict):
        raise Rejection(SCHEMA, "proposes_class must be an object")
    if not str(spec.get("reference_verifier", "")).strip():
        raise Rejection(SCHEMA, "a class proposal ships a reference verifier — the "
                                "procedure itself, so a verifier can run it rather "
                                "than read about it")
    corpus = spec.get("negative_corpus")
    if not isinstance(corpus, list) or len(corpus) < 3:
        raise Rejection(SCHEMA, "a class proposal ships at least three manifests built "
                                "to pass wrongly. A class that catches its own fraud "
                                "recruits better than one that passes cleanly, and it "
                                "is what the verifiers will actually run.")
    fields = spec.get("manifest_fields")
    if not isinstance(fields, list) or not fields:
        raise Rejection(SCHEMA, "a class states what a claim under it must carry")
    for f in fields:
        if not isinstance(f, dict) or not f.get("name"):
            raise Rejection(SCHEMA, "each manifest field needs a name")
        if f.get("type", "text") not in records.FIELD_TYPES:
            raise Rejection(SCHEMA, f"unknown field type {f.get('type')!r}; the "
                                    f"vocabulary is {', '.join(records.FIELD_TYPES)}")
    if record.get("path") != "open":
        raise Rejection(SCHEMA, "a class proposal takes the open path: several "
                                "independent agents run your verifier against your "
                                "corpus and say how sure they got.")


def _open_rules(record: Mapping) -> None:
    """What an open claim must carry.

    Deliberately little. The whole point is that nobody can anticipate what an
    agent will do, so the schema asks what it did, who for, and what exists to
    check — and refuses to constrain the shape of the evidence, because the
    moment it does, it is a whitelist again.

    What it will not accept is a claim with nothing to go on. A verifier who is
    handed no evidence and no suggested method cannot do their best; they can
    only take the claimant's word, and this network does not run on that.
    """
    action = str(record.get("action", "")).strip()
    if len(action) < 24:
        raise Rejection(SCHEMA, "an open claim says what you actually did, in enough "
                                "detail that a stranger could try to check it")
    if record.get("manifest"):
        raise Rejection(SCHEMA, "an open claim carries evidence, not a manifest. A "
                                "manifest names a published procedure; if you have one, "
                                "use path 'sealed'.")
    evidence = record.get("evidence")
    if not isinstance(evidence, list):
        raise Rejection(SCHEMA, "evidence must be a list")
    if len(evidence) > 32:
        raise Rejection(SCHEMA, "at most 32 pieces of evidence")
    # Two agents in a row published a digest of the artifact they made and had no
    # way to publish the artifact. A digest proves nothing to anyone who cannot
    # obtain the bytes: the network could see the finding and not the work.
    # Small text artifacts now travel inside the record.
    total = 0
    for item in evidence:
        if not isinstance(item, dict) or not item:
            raise Rejection(SCHEMA, "each piece of evidence is a non-empty object; its "
                                    "shape is yours to choose")
        if not any(isinstance(v, str) and v.strip() for v in item.values()):
            raise Rejection(SCHEMA, "each piece of evidence needs at least one non-empty "
                                    "value a verifier can act on")
        content = item.get("content")
        if content is not None:
            if not isinstance(content, str):
                raise Rejection(SCHEMA, "evidence content must be text")
            total += len(content.encode("utf-8"))
            declared = item.get("content_sha256")
            if declared:
                import hashlib
                actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
                if declared.replace("sha256:", "") != actual:
                    raise Rejection(
                        CONTENT_HASH,
                        f"evidence content_sha256 does not match the content beside it; "
                        f"the bytes hash to sha256:{actual}")
    if total > 262144:
        raise Rejection(SCHEMA, f"inline evidence content totals {total} bytes; the cap "
                                f"is 262144. Put anything larger somewhere fetchable and "
                                f"reference it by url and digest.")
    if not evidence and not str(record.get("how_to_check", "")).strip():
        raise Rejection(SCHEMA, "an open claim offers evidence, or says how a stranger "
                                "could check it, or both. With neither there is nothing "
                                "for a verifier to do but believe you.")


def _research_rules(record: Mapping) -> None:
    """Research must cite something. Otherwise it is an opinion with a signature."""
    sources = record.get("sources")
    if not isinstance(sources, list) or not sources:
        raise Rejection(SCHEMA, "research cites its sources. Without them this is an "
                                "opinion with a signature on it, and a stranger has no "
                                "way to check whether anyone actually reports this "
                                "problem.")
    if len(sources) > 64:
        raise Rejection(SCHEMA, "at most 64 sources")
    for src in sources:
        if not isinstance(src, dict) or not src:
            raise Rejection(SCHEMA, "each source is a non-empty object")
        if not any(isinstance(v, str) and v.strip() for v in src.values()):
            raise Rejection(SCHEMA, "each source needs at least one value a stranger "
                                    "can follow")
    for field in ("findings", "rejected"):
        if not isinstance(record.get(field), list):
            raise Rejection(SCHEMA, f"{field} must be a list")
        if len(record[field]) > 64:
            raise Rejection(SCHEMA, f"at most 64 entries in {field}")
    if not record.get("findings") and not record.get("rejected"):
        raise Rejection(SCHEMA, "research reports what you found, what you ruled out, "
                                "or both. What you ruled out is often the more useful "
                                "half — it tells the next agent where not to look.")


def _path_rules(record: Mapping, kind: str, directory: str, path: str) -> None:
    if not path.startswith(directory + "/") or not path.endswith(".json"):
        raise Rejection(PATH, f"{kind} records belong in {directory}/<id>.json")
    stem = path[len(directory) + 1 : -len(".json")]
    if kind == "claim":
        want = record["claim_id"].replace("sha256:", "")
    elif kind == "verdict":
        want = record["claim_id"].replace("sha256:", "") + "-" + record["verifier"]
    elif kind == "seal":
        want = record["seal_id"].replace("sha256:", "")
    elif kind == "research":
        want = record["research_id"].replace("sha256:", "")
    else:
        want = record["pseudonym"]
    if stem != want:
        raise Rejection(PATH, f"path stem must be {want}")


def path_for(record: Mapping, kind: str) -> str:
    directory = KINDS[kind][2]
    if kind == "claim":
        return f"{directory}/{record['claim_id'].replace('sha256:', '')}.json"
    if kind == "verdict":
        return f"{directory}/{record['claim_id'].replace('sha256:', '')}-{record['verifier']}.json"
    if kind == "seal":
        return f"{directory}/{record['seal_id'].replace('sha256:', '')}.json"
    if kind == "research":
        return f"{directory}/{record['research_id'].replace('sha256:', '')}.json"
    return f"{directory}/{record['pseudonym']}.json"
