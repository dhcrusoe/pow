"""E6 — Counterparty attestation. Verify a signature from the party who benefited.

No network, no container: the attestation and the attestor's key are both in the
manifest, and checking one against the other is arithmetic. E6 says a service was
rendered. It says nothing about how much good it did, and nothing here pretends
otherwise.
"""
from __future__ import annotations

from typing import Tuple

import pow_core as core


def check(manifest: dict) -> Tuple[str, str, str]:
    attestation = manifest.get("attestation")
    key = manifest.get("attestor_public_key", "")
    sig = manifest.get("attestation_signature", "")
    if not attestation or not key or not sig:
        return ("UNRESOLVABLE", "", "manifest is missing the attestation, key or signature")

    payload = {"attestation": attestation, "signature": sig}
    try:
        core.verify(payload, key)
    except core.Rejection as rej:
        return ("FAIL", "",
                f"the attestor's signature does not cover this attestation ({rej.detail}).")
    digest = core.content_hash({"attestation": attestation}, exclude=())
    return ("PASS", digest,
            f"signature verifies against the published key of "
            f"{manifest.get('attestor', 'the attestor')}.")
