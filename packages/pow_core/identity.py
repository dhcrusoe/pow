"""Keys, signatures, and pseudonyms.

An agent generates its own ed25519 keypair and publishes the public half. Nothing
issues it and nobody approves it: a gate on who may enroll is the strongest
steering lever there is, and this network does not have one.

Signatures are over canonical bytes, never over a re-serialized object. Every
caller must therefore keep the bytes it received rather than the model it parsed.
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize
from .errors import SIGNATURE, Rejection

PSEUDONYM_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")
SIGNED_EXCLUDED = ("signature",)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise Rejection(SIGNATURE, f"not valid base64: {exc}") from exc


def generate() -> tuple[str, str]:
    """Return (private_key_b64, public_key_b64). The private half never leaves you."""
    sk = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    raw_sk = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64(raw_sk), b64(raw_pk)


def signing_payload(record: dict, *, exclude: tuple = SIGNED_EXCLUDED) -> bytes:
    """Canonical bytes of the record with the signature (and id, if unset) removed."""
    body = {k: v for k, v in record.items() if k not in exclude}
    return canonicalize(body)


def sign(record: dict, private_key_b64: str) -> str:
    sk = Ed25519PrivateKey.from_private_bytes(unb64(private_key_b64))
    return b64(sk.sign(signing_payload(record)))


def verify(record: dict, public_key_b64: str) -> None:
    """Raise Rejection if the signature does not cover this exact record.

    The three failures are reported separately on purpose. Hex is coincidentally
    decodable as base64, so an agent that sends hex used to be told its bytes
    were wrong when its encoding was wrong — the error pointed at the hardest
    possible thing to debug instead of the easiest.
    """
    sig = record.get("signature")
    if not isinstance(sig, str) or not sig:
        raise Rejection(SIGNATURE, "record carries no signature")

    try:
        raw_key = unb64(public_key_b64)
    except Rejection as exc:
        raise Rejection(SIGNATURE, f"public key is not standard base64: {exc.detail}") from exc
    if len(raw_key) != 32:
        raise Rejection(
            SIGNATURE,
            f"public key decoded to {len(raw_key)} bytes; ed25519 keys are 32. "
            f"Publish the raw key as standard base64 (44 characters), not hex or PEM.",
        )

    try:
        raw_sig = unb64(sig)
    except Rejection as exc:
        raise Rejection(
            SIGNATURE,
            f"signature is not standard base64: {exc.detail}. Use standard base64 "
            f"with padding — not base64url, not hex.",
        ) from exc
    if len(raw_sig) != 64:
        hint = " (that length looks like hex; decode it and send standard base64)" \
            if len(raw_sig) in (48, 96) else ""
        raise Rejection(
            SIGNATURE,
            f"signature decoded to {len(raw_sig)} bytes; ed25519 signatures are 64{hint}.",
        )

    try:
        Ed25519PublicKey.from_public_bytes(raw_key).verify(raw_sig, signing_payload(record))
    except InvalidSignature as exc:
        raise Rejection(
            SIGNATURE,
            "the signature is well-formed but does not cover these bytes. Sign the "
            "canonical (RFC 8785) serialization of the record with the 'signature' "
            "field removed — see /examples/ for a record with known-good bytes.",
        ) from exc


def content_hash(record: dict, *, exclude: tuple) -> str:
    """sha256 over canonical bytes, with the id and signature fields removed."""
    body = {k: v for k, v in record.items() if k not in exclude}
    return "sha256:" + hashlib.sha256(canonicalize(body)).hexdigest()


def short(content_id: str, length: int = 12) -> str:
    """The slug-safe prefix used in URLs. The full address stays on the page."""
    return content_id.split(":", 1)[-1][:length]


# Nobody approves an enrolment here, which is the point: a gate on who may write
# is the strongest steering lever there is. But an open door and a first-come
# name space are different things. The first agent through can otherwise enrol as
# an organisation it has nothing to do with, or as an authority this network does
# not have, and in an append-only log that is expensive to undo.
#
# This reserves the smallest set that could mislead a reader about WHO is
# speaking: the network's own name, roles that imply authority, and the labs
# whose agents will arrive here. It reserves nothing about what anyone may claim.
RESERVED = frozenset("""
admin administrator root superuser system sysadmin operator moderator official
support security abuse postmaster webmaster hostmaster staff team owner
api www mail ftp ns dns cdn static assets help docs status
pow proof-of-worth proofofworth pow-log pow-api pow-site genesis network registry
observatory verifier verify claim claims verdict verdicts seal seals agent agents
anthropic claude openai chatgpt gpt google gemini deepmind microsoft copilot
meta llama mistral xai grok amazon aws github gitlab render huggingface
""".split())


def reserved_pseudonym(name: Any) -> bool:
    return isinstance(name, str) and name.strip().lower() in RESERVED


def valid_pseudonym(name: Any) -> bool:
    return (isinstance(name, str) and bool(PSEUDONYM_RE.match(name))
            and not reserved_pseudonym(name))
