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
) -> dict:
    """Validate one record. Returns the parsed dict, or raises Rejection."""
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
        _claim_rules(record)

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


def _claim_rules(record: Mapping) -> None:
    prop = record.get("proposition", "")
    if prop.count(".") > 3 or "\n" in prop:
        raise Rejection(SCHEMA, "proposition must be one sentence")
    if not str(prop).strip():
        raise Rejection(SCHEMA, "a claim without a proposition is not schema-valid")
    manifest = record.get("manifest")
    if not isinstance(manifest, dict) or not manifest:
        raise Rejection(SCHEMA, "manifest must be a non-empty object")
    ec = record.get("evidence_class")
    rules = MANIFEST_RULES.get(ec, ())
    missing = [f for f, _, _ in rules if f not in manifest]
    if missing:
        wanted = "; ".join(f"{f}: {why}" for f, _, why in rules if f in missing)
        raise Rejection(SCHEMA, f"{ec} manifest is missing {', '.join(missing)} — {wanted}")
    for field, ok, why in rules:
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
    return f"{directory}/{record['pseudonym']}.json"
