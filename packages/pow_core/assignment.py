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


def draw_seed(verifier_pubkey: str, head_commit: str, claim_id: str) -> bytes:
    """The exact bytes hashed for one candidate. Specified, not implied.

    A verifier could not previously recompute its own draw: "sha256(pubkey|head|
    claim_id)" left the concatenation undefined, and four plausible readings all
    fit the observed result. This is the reading, and it is the only one:

        UTF-8 of  <public_key_base64> "|" <head_commit_hex> "|" <claim_id>

    with claim_id including its "sha256:" prefix, and literal pipe separators.
    """
    return f"{verifier_pubkey}|{head_commit}|{claim_id}".encode("utf-8")


def draw(candidates: List[str], verifier_pubkey: str, head_commit: str) -> Optional[str]:
    """Pick one candidate: lowest sha256(draw_seed) wins.

    Recomputable by anyone holding the public key, the head and the queue. Note
    that this alone does NOT make the draw unshoppable — head moves on every
    write by anyone, so re-requesting is a re-roll. The lease is what closes
    that; see assign().
    """
    if not candidates:
        return None
    ranked = sorted(
        candidates,
        key=lambda cid: hashlib.sha256(draw_seed(verifier_pubkey, head_commit, cid)).digest(),
    )
    return ranked[0]


def held_lease(handouts: Iterable[Mapping], verdicts: Iterable[Mapping],
               verifier: str, now: str) -> Optional[Mapping]:
    """The verifier's own unexpired, unsettled handout, if it has one."""
    settled = {v.get("claim_id") for v in verdicts}
    mine = [
        h for h in handouts
        if h.get("verifier") == verifier
        and h.get("expires_at", "") > now
        and h.get("claim_id") not in settled
    ]
    return sorted(mine, key=lambda h: h.get("issued_at", ""))[-1] if mine else None


def assign(
    claims: Iterable[Mapping],
    verdicts: Iterable[Mapping],
    handouts: Iterable[Mapping],
    verifier: str,
    verifier_pubkey: str,
    head_commit: str,
    now: str,
) -> Optional[str]:
    """Return the claim this verifier should check.

    The draw is seeded on the current head, which moves whenever anyone writes.
    Left there, re-requesting would be a re-roll: an agent could poll until it
    drew a claim it preferred, which is exactly the queue-shopping the
    documentation promises is impossible.

    So the lease is sticky. While you hold an unexpired handout you are handed
    the same claim every time. You get a new draw when you settle it, or when it
    expires and returns to the pool for everyone.
    """
    handouts = list(handouts)
    verdicts = list(verdicts)
    lease = held_lease(handouts, verdicts, verifier, now)
    if lease is not None:
        return lease["claim_id"]
    return draw(eligible(claims, verdicts, handouts, verifier, now),
                verifier_pubkey, head_commit)
