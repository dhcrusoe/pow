"""Fetching a manifest's sources, honouring archive pins.

Five classes now pin their inputs by digest, and every one of them wants the same
three-way answer: the bytes are what was recorded, the bytes are something else,
or the bytes could not be read at all. That last case is an environment problem
and never the claimant's fault — filing FAIL on it costs them 15 points for link
rot. Written once here so the rule cannot drift between classes.
"""
from __future__ import annotations

import hashlib
from typing import List, Mapping, Optional, Tuple

import httpx

TIMEOUT = 20.0


def fetch(url: str) -> Tuple[str, str]:
    """Return (sha256_hex, "") or ("", reason)."""
    if not url:
        return "", "no url"
    try:
        r = httpx.get(url, timeout=TIMEOUT, follow_redirects=True)
    except httpx.HTTPError as exc:
        return "", f"not fetchable ({type(exc).__name__})"
    if r.status_code >= 400:
        return "", f"HTTP {r.status_code}"
    return hashlib.sha256(r.content).hexdigest(), ""


def check_sources(sources: List[Mapping]) -> Tuple[Optional[str], str, List[str]]:
    """Return (verdict_or_None, diagnosis, digests).

    None means every source held: either the origin still matches, or the archive
    pin reproduced the digest the origin has moved past.
    """
    if not sources:
        return ("UNRESOLVABLE", "the manifest pins no sources, so there is nothing "
                                "to check the work against.", [])

    matched, changed, unreadable, digests = [], [], [], []
    for entry in sources:
        url = entry.get("url", "")
        pin = entry.get("archive_url", "")
        expected = str(entry.get("snapshot_sha256", "")).replace("sha256:", "")
        label = entry.get("label") or url

        got, why = fetch(url)
        if got and got == expected:
            digests.append(got)
            matched.append(f"{label}: identical")
            continue

        pinned, pin_why = fetch(pin) if pin else ("", "no archive_url given")
        if pinned and pinned == expected:
            digests.append(pinned)
            matched.append(f"{label}: origin "
                           f"{'changed' if got else 'unreadable'}, reproduced from the pin")
            continue

        if got:
            digests.append(got)
            changed.append(f"{label}: expected sha256:{expected[:12]}…, observed "
                           f"sha256:{got[:12]}… at the origin")
        else:
            unreadable.append(f"{label}: {why}; pin: {pin_why or 'differs'}")

    if unreadable:
        return ("UNRESOLVABLE",
                f"{len(unreadable)} of {len(sources)} source(s) could not be read: "
                + "; ".join(unreadable)
                + ". The claim may well be true; it cannot be checked from here. "
                  "Re-snapshot and resubmit. Nothing is owed by the claimant.",
                digests)
    if changed:
        return ("FAIL",
                f"{len(changed)} of {len(sources)} source(s) are reachable and no "
                f"longer say what was recorded: " + "; ".join(changed)
                + ". An archive_url on each source would have separated a document "
                  "that moved on from a claim that was wrong.",
                digests)

    pins = sum(1 for m in matched if "from the pin" in m)
    note = "" if not pins else f" {pins} verified from the pin rather than the origin."
    return (None, f"all {len(sources)} source(s) match the recorded snapshots.{note}",
            digests)


def combined(digests: List[str]) -> str:
    return "sha256:" + hashlib.sha256("".join(sorted(digests)).encode()).hexdigest()


def in_band(value: int, band: Mapping) -> bool:
    return isinstance(value, int) and band.get("lo") <= value <= band.get("hi")


def render(band: Mapping) -> str:
    """A band as text, for a diagnosis. Integers and a scale, never a float."""
    return (f"{band.get('value')}e{band.get('scale')} {band.get('unit','')} "
            f"[{band.get('lo')}, {band.get('hi')}]").strip()
