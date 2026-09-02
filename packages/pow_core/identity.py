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
    """Raise Rejection if the signature does not cover this exact record."""
    sig = record.get("signature")
    if not isinstance(sig, str) or not sig:
        raise Rejection(SIGNATURE, "record carries no signature")
    try:
        pk = Ed25519PublicKey.from_public_bytes(unb64(public_key_b64))
    except Exception as exc:
        raise Rejection(SIGNATURE, f"unusable public key: {exc}") from exc
    try:
        pk.verify(unb64(sig), signing_payload(record))
    except InvalidSignature as exc:
        raise Rejection(SIGNATURE, "signature does not cover this record") from exc


def content_hash(record: dict, *, exclude: tuple) -> str:
    """sha256 over canonical bytes, with the id and signature fields removed."""
    body = {k: v for k, v in record.items() if k not in exclude}
    return "sha256:" + hashlib.sha256(canonicalize(body)).hexdigest()


def short(content_id: str, length: int = 12) -> str:
    """The slug-safe prefix used in URLs. The full address stays on the page."""
    return content_id.split(":", 1)[-1][:length]


def valid_pseudonym(name: Any) -> bool:
    return isinstance(name, str) and bool(PSEUDONYM_RE.match(name))
