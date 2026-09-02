"""E2 — Third-party ledger. Fetch each source, compare to its snapshot.

Pure HTTP, no container. This is why E2 is the first claim rather than E1: it is
the class an agent can reach with nothing but a fetch tool, and it has no
cross-machine determinism problem to lose a week to.

A manifest carries a LIST of sources. One entry asserts something about a single
artifact. Two or more assert something about how they compare — which is where
most work that is not code lives: two official documents that contradict each
other, a calculator that disagrees with the statute it implements, a translation
that drops a clause its original has, two registries that disagree about one
entity. Verification is the same either way: fetch each, hash each, compare.

The three-way distinction is the whole judgement, so it is explicit:

  PASS          every source still says what the claimant recorded
  FAIL          a source is reachable and says something else
  UNRESOLVABLE  a source could not be read at all

The last is not a failure and not a shrug. It says the environment could not be
reconstructed, costs the claimant nothing, and carries a diagnosis so it reads as
a repair instruction. Filing FAIL on a probably-true claim with a broken manifest
costs that agent 15 points for a packaging defect.
"""
from __future__ import annotations

import hashlib
from typing import List, Tuple

import httpx

TIMEOUT = 20.0


def _normalise(manifest: dict) -> List[dict]:
    """Accept the list form; tolerate the single-source form for old records."""
    if isinstance(manifest.get("sources"), list):
        return manifest["sources"]
    if manifest.get("source") and manifest.get("snapshot_sha256"):
        return [{"url": manifest["source"], "snapshot_sha256": manifest["snapshot_sha256"]}]
    return []


def check(manifest: dict) -> Tuple[str, str, str]:
    """Return (verdict, output_hash, diagnosis)."""
    sources = _normalise(manifest)
    if not sources:
        return ("UNRESOLVABLE", "",
                "manifest carries no sources to fetch. Expected a 'sources' list of "
                "{url, snapshot_sha256}.")

    matched, changed, unreadable, digests = [], [], [], []

    for entry in sources:
        url = entry.get("url", "")
        expected = str(entry.get("snapshot_sha256", "")).replace("sha256:", "")
        label = entry.get("label") or url
        try:
            r = httpx.get(url, timeout=TIMEOUT, follow_redirects=True)
        except httpx.HTTPError as exc:
            unreadable.append(f"{label}: not fetchable ({type(exc).__name__})")
            continue
        if r.status_code >= 400:
            unreadable.append(f"{label}: HTTP {r.status_code}")
            continue
        got = hashlib.sha256(r.content).hexdigest()
        digests.append(got)
        (matched if got == expected else changed).append(
            f"{label}: expected sha256:{expected[:12]}…, observed sha256:{got[:12]}…"
            if got != expected else f"{label}: identical"
        )

    # A source we could not read says nothing about the claimant. Report it as an
    # environment problem and let them resubmit, rather than charging them 15.
    if unreadable:
        return ("UNRESOLVABLE", "",
                f"{len(unreadable)} of {len(sources)} source(s) could not be read: "
                + "; ".join(unreadable)
                + ". The claim may well be true; it cannot be checked from here. "
                  "Re-snapshot and resubmit. Nothing is owed by the claimant.")

    combined = "sha256:" + hashlib.sha256("".join(sorted(digests)).encode()).hexdigest()

    if changed:
        return ("FAIL", combined,
                f"{len(changed)} of {len(sources)} source(s) are reachable but have "
                f"changed since the claim was sealed: " + "; ".join(changed)
                + ". If the change is incidental, the claim needs a narrower assertion "
                  "than whole-document bytes.")

    plural = "source" if len(sources) == 1 else "sources"
    note = ("" if len(sources) == 1 else
            " The comparison the claimant asserts is between these bytes; a stranger "
            "re-runs it from the snapshots alone.")
    return ("PASS", combined,
            f"re-fetched {len(sources)} {plural}; all bytes identical to the snapshots "
            f"recorded on {manifest.get('fetched_at', 'the stated date')}.{note}")
