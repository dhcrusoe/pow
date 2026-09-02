"""E2 — Third-party ledger. Fetch the source, compare to the snapshot.

Three HTTP calls and no container. This is why E2 should be the first claim
rather than E1: it is the class an agent can reach with nothing but a fetch tool,
and it has no cross-machine determinism problem to lose a week to.

The three-way distinction is the whole judgement here, so it is made explicit:

  PASS          the source still says what the claimant recorded
  FAIL          the source is reachable and says something else
  UNRESOLVABLE  the source could not be read at all

The last one is not a failure and it is not a shrug. It says the environment
could not be reconstructed, costs the claimant nothing, and carries a diagnosis
so it reads as a repair instruction.
"""
from __future__ import annotations

import hashlib
from typing import Tuple

import httpx

TIMEOUT = 20.0


def check(manifest: dict) -> Tuple[str, str, str]:
    """Return (verdict, output_hash, diagnosis)."""
    source = manifest.get("source")
    expected = manifest.get("snapshot_sha256", "")
    if not source or not expected:
        return ("UNRESOLVABLE", "", "manifest is missing source or snapshot_sha256")

    try:
        r = httpx.get(source, timeout=TIMEOUT, follow_redirects=True)
    except httpx.HTTPError as exc:
        return ("UNRESOLVABLE", "",
                f"source could not be fetched ({type(exc).__name__}). The claim may well "
                f"be true; it cannot be checked from here. Nothing is owed by the claimant.")

    if r.status_code >= 400:
        return ("UNRESOLVABLE", "",
                f"source returned HTTP {r.status_code}. Link rot is not a false claim: "
                f"re-snapshot the source and resubmit.")

    got = hashlib.sha256(r.content).hexdigest()
    if got == expected:
        return ("PASS", f"sha256:{got}",
                f"re-fetched {source}; bytes identical to the snapshot recorded on "
                f"{manifest.get('fetched_at', 'the stated date')}.")

    return ("FAIL", f"sha256:{got}",
            f"source is reachable but has changed since the claim was sealed. "
            f"Expected sha256:{expected}, observed sha256:{got}. If the change is "
            f"incidental, the claim needs a narrower assertion than whole-document bytes.")
