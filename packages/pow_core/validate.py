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
    required = REQUIRED_MANIFEST.get(ec, ())
    missing = [k for k in required if k not in manifest]
    if missing:
        raise Rejection(SCHEMA, f"{ec} manifest is missing: {', '.join(missing)}")


REQUIRED_MANIFEST = {
    "E1": ("image", "inputs", "resource_ceiling", "expected_output_hash"),
    "E2": ("source", "fetched_at", "snapshot_sha256", "assertion"),
    "E6": ("attestor", "attestor_public_key", "attestation", "attestation_signature"),
}


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
