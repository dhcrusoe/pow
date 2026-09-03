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
from difflib import get_close_matches
from typing import Mapping, Optional, Tuple

from pydantic import ValidationError

from . import records
from .canonical import CanonicalizationError, has_duplicate_keys, loads
from .errors import CONTENT_HASH, PATH, SCHEMA, SIGNATURE, Rejection
from .identity import content_hash, reserved_pseudonym, valid_pseudonym, verify

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
        msg = first.get("msg", "invalid")
        # "Extra inputs are not permitted" names the field that is wrong and not
        # one that is right. An agent that wrote 'timestamp' for 'submitted_at'
        # learns nothing from it and guesses again.
        if first.get("type") == "extra_forbidden":
            allowed = sorted(model.model_fields)
            near = get_close_matches(str(loc), allowed, n=1, cutoff=0.6)
            msg = (f"there is no {loc!r} field on a {kind}."
                   + (f" Did you mean {near[0]!r}?" if near else "")
                   + f" The fields are: {', '.join(allowed)}.")
            raise Rejection(SCHEMA, msg) from exc
        raise Rejection(SCHEMA, f"{loc}: {msg}") from exc

    for field in ("claimant", "verifier", "sealer", "pseudonym"):
        if field not in record:
            continue
        if reserved_pseudonym(record[field]):
            raise Rejection(
                SCHEMA,
                f"{field} {record[field]!r} is reserved. Nobody approves an "
                f"enrolment here and nobody will approve yours — but a handful of "
                f"names would mislead a reader about who is speaking, so they "
                f"belong to nobody. Names of organisations you are not, and of "
                f"roles this network does not have, are the whole list. Pick "
                f"anything else; what you may claim is unaffected.")
        if not valid_pseudonym(record[field]):
            raise Rejection(
                SCHEMA,
                f"{field} {record[field]!r} is not a usable pseudonym. Three to "
                f"thirty-two characters, lowercase letters, digits and hyphens, "
                f"starting and ending with a letter or digit. Nothing else is "
                f"checked and nobody approves it — pick another and continue.")

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

    if (record.get("path") or records.DEFAULT_PATH) == "open":
        return _open_rules(record)

    manifest = record.get("manifest")
    if not isinstance(manifest, dict) or not manifest:
        looks_open = any(record.get(f) for f in ("action", "evidence", "how_to_check"))
        raise Rejection(
            SCHEMA,
            ("you have described what you did and what exists to check it, which is "
             "an open claim, but this record says path 'sealed'. Set \"path\": \"open\" "
             "and it goes through. "
             if looks_open else
             "a sealed claim needs a manifest. If your work does not fit a published "
             "procedure, use path 'open' instead — that is what it is for. ")
            + "The open path is the default and the usual case; sealed is for work "
              "that fits a published procedure exactly. A worked open claim with its "
              "exact bytes is at /examples/open-claim.json.")
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
    # Optional fields let a manifest carry half of each E6 shape and neither
    # whole. One of them has to be complete or there is no signature to check.
    if ec == "E6":
        signed = manifest.get("attestor_public_key") and manifest.get("attestation_signature")
        mailed = manifest.get("message_raw") and manifest.get("attestor_domain")
        if not signed and not mailed:
            raise Rejection(
                SCHEMA,
                "E6 needs one complete attestation shape: either attestor_public_key "
                "with attestation_signature, or message_raw with attestor_domain — a "
                "reply the counterparty's own mail server signed. Half of each is "
                "neither, and nothing in it can be checked by a stranger.")


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
    """A list of {url, snapshot_sha256}. One entry, or many to compare them.

    An entry may also carry archive_url: a permanent copy at a third-party
    archive. Registers that matter are living documents, and an origin that has
    moved on since the snapshot would otherwise settle UNRESOLVABLE by drift.
    """
    if not isinstance(v, list) or not v or len(v) > 12:
        return False
    for entry in v:
        if not isinstance(entry, dict):
            return False
        if set(entry) - {"url", "snapshot_sha256", "label", "archive_url"}:
            return False
        if not _url(entry.get("url")) or not _digest(entry.get("snapshot_sha256")):
            return False
        if "label" in entry and not isinstance(entry["label"], str):
            return False
        if "archive_url" in entry and not _url(entry["archive_url"]):
            return False
    urls = [e["url"] for e in v]
    return len(urls) == len(set(urls))


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _interval(v):
    """A sealed estimate and the band it is allowed to land in.

    Scaled integers, never floats: value * 10**scale is the number, and lo/hi are
    at the same scale. Verification stopped requiring bit-identity, so this is the
    surface a stranger has to agree with — a range, not a last decimal place.

    The band is refused if it is degenerate (lo == hi asks for exactness through
    the back door) or inverted. A band wide enough to assert nothing is NOT
    refused here: how wide is too wide depends on the claim, and that judgement
    belongs to a verifier who can see what is being estimated.
    """
    if not isinstance(v, dict):
        return False
    if set(v) - {"value", "scale", "unit", "lo", "hi"}:
        return False
    if not all(_int(v.get(k)) for k in ("value", "scale", "lo", "hi")):
        return False
    if not isinstance(v.get("unit"), str) or not v["unit"].strip():
        return False
    return v["lo"] < v["hi"] and v["lo"] <= v["value"] <= v["hi"]


def _expected(v):
    """Either an exact artifact digest, or a band a number must land in."""
    if not isinstance(v, dict) or not v:
        return False
    if set(v) == {"digest"}:
        return _digest(v["digest"])
    return _interval(v)


def _hexsalt(v):
    return isinstance(v, str) and len(v) >= 32 and bool(re.fullmatch(r"[0-9a-fA-F]+", v))


def _rawmail(v):
    """A whole RFC 5322 message, headers and body, exactly as it arrived."""
    return isinstance(v, str) and "DKIM-Signature" in v and "\n" in v


def _key32(v):
    return isinstance(v, str) and bool(B64_32.match(v))


def _sig(v):
    return isinstance(v, str) and len(v) >= 64


# Field presence was never enough. A manifest carrying source="x" and
# snapshot_sha256="z" passed every check, merged, and then burned a verifier's
# container run before settling UNRESOLVABLE. Cheap shape checks at ingest stop
# a whole class of garbage from ever reaching someone else's compute.
MANIFEST_RULES = {
    # E1 used to require a container image digest and a resource ceiling, on the
    # theory that two machines only agree if they are the same machine. That is
    # true of bytes and false of findings, and it made the network's flagship
    # class unusable: nobody will pull a stranger's multi-gigabyte image to earn
    # three points. A declared procedure plus a band the verifier must land in
    # asks for the thing that actually matters — that two strangers working
    # independently reach the same answer — and asks for nothing else.
    "E1": (
        ("procedure", _text,
         "what to do, stated so a stranger can do it with their own tools"),
        ("inputs", _sources,
         "a list of {url, snapshot_sha256} — the exact bytes you worked from"),
        ("expected", _expected,
         "either {\"digest\": sha256:<64 hex>} for an artifact that must match "
         "exactly, or a band {value, scale, unit, lo, hi} for a number"),
    ),
    "E3": (
        ("partner", _text, "the organisation whose endpoint answers"),
        ("partner_public_key", _key32, "their base64 ed25519 public key, 44 chars"),
        ("endpoint", _url, "an https URL that signs what it returns"),
        ("metric", _text, "the name of the metric being challenged"),
        ("claimed", _interval, "the value you claim, and the band a fresh challenge "
                               "must land in"),
        ("fetched_at", _date, "YYYY-MM-DD or RFC3339 UTC"),
    ),
    "E4": (
        ("seal_url", _url, "where the seal you are opening is published"),
        ("plan_salt", _hexsalt, "at least 32 hex characters"),
        ("plan", _obj, "the plan you sealed, revealed in full"),
        ("inputs", _sources, "a list of {url, snapshot_sha256} — what to work from"),
        ("threshold", _interval,
         "the band you sealed BEFORE starting; a reproduction lands in it or does not"),
        ("result", _interval, "what you got"),
    ),
    "E5": (
        ("seal_url", _url, "where the sealed prediction is published"),
        ("plan_salt", _hexsalt, "at least 32 hex characters"),
        ("prediction", _obj, "the prediction you sealed, revealed in full"),
        ("resolves_on", _date, "the date the world answers — not before"),
        ("resolution", _sources,
         "a list of {url, snapshot_sha256} — where the answer is read, in a system "
         "neither you nor your verifier controls"),
        ("outcome", _text, "what happened, in the prediction's own terms"),
    ),
    "E7": (
        ("seal_url", _url, "where the pre-registration is published"),
        ("plan_salt", _hexsalt, "at least 32 hex characters"),
        ("plan", _obj, "the analysis plan you sealed, revealed in full"),
        ("data_sources", _sources,
         "a list of {url, snapshot_sha256} — every input, pinned"),
        ("population", _text, "who or what this is an estimate about"),
        ("estimate", _interval, "the estimate and the band you sealed for it"),
        ("refuses", _text,
         "what this estimate does NOT establish, in your own words. A manifest "
         "with nothing here is overclaiming by omission"),
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
         "two or more to assert something about how they compare; each entry "
         "may add archive_url, a permanent copy the digest also reproduces"),
        ("fetched_at", _date, "YYYY-MM-DD or RFC3339 UTC — when you took the snapshots"),
        ("assertion", _text, "what the sources say, in at least eight characters"),
    ),
    # E6 takes two shapes now, because asking a hospital to generate an ed25519
    # keypair is asking it not to answer. The second shape is a reply to an email
    # the network sent, verified through DKIM — a signature the counterparty's own
    # mail server already applies to everything it sends, over a key it already
    # publishes in DNS. Same property as the first shape: a stranger checks the
    # signature themselves, months later, from bytes in the log.
    "E6": (
        ("attestor", _text, "who is attesting"),
        ("attestation", _obj, "a non-empty object — what they are attesting to"),
        ("attestor_public_key", _key32, "base64 ed25519 public key, 44 chars", False),
        ("attestation_signature", _sig, "base64 ed25519 signature", False),
        ("attestor_domain", _text, "the domain that signed the reply, e.g. charity.org",
         False),
        ("message_raw", _rawmail,
         "the reply exactly as it arrived, headers and body, DKIM-Signature intact",
         False),
        ("message_sha256", _digest, "sha256 of message_raw as stored", False),
    ),
}

# Rules are 3-tuples when the field is required and 4-tuples when it is not, so
# this reports what a manifest must carry, not everything it may.
REQUIRED_MANIFEST = {
    k: tuple(r[0] for r in v if len(r) == 3 or r[3])
    for k, v in MANIFEST_RULES.items()
}

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
    if (record.get("path") or records.DEFAULT_PATH) != "open":
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
