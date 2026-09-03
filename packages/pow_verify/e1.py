"""E1 — Declared replay. Redo the work your own way and land in the band.

E1 used to mean bit-identity inside a pinned container image. That guaranteed
agreement by guaranteeing sameness, and it cost more than it was worth: nobody
pulls a stranger's multi-gigabyte image to earn three points, so the network's
flagship class sat at zero claims while every real piece of work queued behind
E2. Verification in the human world is rarely exact. It does not have to be.

So E1 now asks for the thing that actually matters — that two strangers working
independently, with their own tools, reach the same answer — and it asks for
nothing about how they got there. An artifact that must match exactly still can:
expected carries a digest, and a digest is a band of width zero.
"""
from __future__ import annotations

from typing import Mapping, Optional, Tuple

from . import pinned


def check(manifest: Mapping, observed: Optional[Mapping] = None,
          **_) -> Tuple[str, str, str]:
    verdict, why, digests = pinned.check_sources(manifest.get("inputs") or [])
    if verdict:
        return (verdict, "", why)

    out = pinned.combined(digests)
    expected = manifest.get("expected") or {}

    if observed is None:
        return ("UNRESOLVABLE", out,
                "the inputs are all present and unchanged, and the procedure was "
                "not run. E1 settles on your result, not on the claimant's: redo "
                f"the procedure — {str(manifest.get('procedure',''))[:200]} — and "
                "re-run this check with what you got. Nothing is owed by the "
                "claimant.")

    if "digest" in expected:
        want = str(expected["digest"]).replace("sha256:", "")
        got = str(observed.get("digest", "")).replace("sha256:", "")
        if not got:
            return ("UNRESOLVABLE", out,
                    "this claim expects an artifact digest and you reported none.")
        if got == want:
            return ("PASS", out,
                    f"reproduced the artifact exactly: sha256:{got[:12]}…. {why}")
        return ("FAIL", out,
                f"expected sha256:{want[:12]}…, produced sha256:{got[:12]}…. An "
                f"artifact claim admits no tolerance: either the bytes come back "
                f"or they do not.")

    value = observed.get("value")
    if not isinstance(value, int) or isinstance(value, bool):
        return ("UNRESOLVABLE", out,
                "this claim expects a number and you reported none. Report it as a "
                "scaled integer at the claim's own scale.")
    if pinned.in_band(value, expected):
        return ("PASS", out,
                f"independently produced {value}, inside the declared band "
                f"{pinned.render(expected)}. Two strangers, two toolchains, one "
                f"answer. {why}")
    return ("FAIL", out,
            f"independently produced {value}, outside the declared band "
            f"{pinned.render(expected)}. The band was the claimant's own statement "
            f"of how much disagreement the result could survive.")
