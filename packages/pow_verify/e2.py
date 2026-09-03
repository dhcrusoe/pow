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

An entry may also carry archive_url — a permanent copy at a third-party archive.
The registers worth checking are living documents: a law is amended, a sanctions
list updates hourly, an agency overwrites its quarterly file. Under bytes-at-the-
origin alone, the correct verdict on most good work here is UNRESOLVABLE by drift,
and the verifier filing it would be right. So provenance is satisfied by either
copy: the origin, or the pin. What the pin cannot do is rescue a claim whose
origin is reachable and disagrees with both.

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


def _fetch(url: str) -> Tuple[str, str]:
    """Return (sha256_hex, "") or ("", reason)."""
    try:
        r = httpx.get(url, timeout=TIMEOUT, follow_redirects=True)
    except httpx.HTTPError as exc:
        return "", f"not fetchable ({type(exc).__name__})"
    if r.status_code >= 400:
        return "", f"HTTP {r.status_code}"
    return hashlib.sha256(r.content).hexdigest(), ""


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
        pin = entry.get("archive_url", "")
        expected = str(entry.get("snapshot_sha256", "")).replace("sha256:", "")
        label = entry.get("label") or url

        got, why = _fetch(url)
        if got == expected and got:
            digests.append(got)
            matched.append(f"{label}: identical")
            continue

        # The origin either moved on or could not be read. Try the pin before
        # charging anyone: it exists precisely for this.
        pinned, pin_why = _fetch(pin) if pin else ("", "no archive_url given")
        if pinned == expected and pinned:
            digests.append(pinned)
            matched.append(
                f"{label}: origin {'changed' if got else 'unreadable'}, "
                f"digest reproduced from the pin")
            continue

        if got:
            digests.append(got)
            changed.append(
                f"{label}: expected sha256:{expected[:12]}…, observed "
                f"sha256:{got[:12]}… at the origin" +
                (f", and the pin did not match either ({pin_why or 'differs'})"
                 if pin else ", and no archive_url was given"))
        else:
            unreadable.append(f"{label}: {why}; pin: {pin_why or 'differs'}")

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
    # Say so when provenance came from an archive rather than the origin. A
    # reader of the log should never have to guess which copy was checked.
    pinned = [m for m in matched if "from the pin" in m]
    via = ("" if not pinned else
           f" {len(pinned)} of {len(sources)} verified from the pin rather than the "
           f"origin: " + "; ".join(pinned) + ".")
    return ("PASS", combined,
            f"re-fetched {len(sources)} {plural}; all bytes identical to the snapshots "
            f"recorded on {manifest.get('fetched_at', 'the stated date')}.{note}{via}")
