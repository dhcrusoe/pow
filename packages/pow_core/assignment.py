"""The draw.

The specification says verifiers are drawn at random and also says the queue is
oldest-first. A public log makes the oldest claim computable by anyone, so
first-in-first-out is a schedule rather than a draw, and the largest verifier
decides what settles and when.

Resolved in favour of randomness, made auditable: the draw is a pure function of
the verifier's own key and the current head commit. Anyone can recompute it, and
nobody can shop the queue, because your draw is fixed by who you are.
"""
from __future__ import annotations

import hashlib
from typing import Iterable, List, Mapping, Optional

LEASE_SECONDS = 72 * 3600


def eligible(
    claims: Iterable[Mapping],
    verdicts: Iterable[Mapping],
    handouts: Iterable[Mapping],
    verifier: str,
    now: str,
) -> List[str]:
    """Claim ids this verifier may be assigned, in deterministic order."""
    settled = {v.get("claim_id") for v in verdicts}
    leased = {
        h.get("claim_id")
        for h in handouts
        if h.get("expires_at", "") > now and h.get("verifier") != verifier
    }
    out = [
        c["claim_id"]
        for c in claims
        if c.get("claim_id") not in settled
        and c.get("claim_id") not in leased
        and c.get("claimant") != verifier
    ]
    return sorted(out)


def draw(candidates: List[str], verifier_pubkey: str, head_commit: str) -> Optional[str]:
    """Pick one candidate. Deterministic, recomputable, unshoppable.

    Ordering by H(pubkey || head || claim_id) means the verifier cannot influence
    which claim it receives without changing its own identity, and any observer
    can confirm the result was not chosen for them.
    """
    if not candidates:
        return None
    seed = (verifier_pubkey + "|" + head_commit + "|").encode("utf-8")
    ranked = sorted(candidates, key=lambda cid: hashlib.sha256(seed + cid.encode()).digest())
    return ranked[0]


def assign(
    claims: Iterable[Mapping],
    verdicts: Iterable[Mapping],
    handouts: Iterable[Mapping],
    verifier: str,
    verifier_pubkey: str,
    head_commit: str,
    now: str,
) -> Optional[str]:
    return draw(eligible(claims, verdicts, handouts, verifier, now), verifier_pubkey, head_commit)
