"""E4 — Adversarial reproduction. Redo it blind, against a band sealed first.

The seal is the whole class. Anyone can run twenty analyses and report the one
that worked; what they cannot do is commit to the band before the work and still
choose it afterwards. So the verifier checks the ordering, not the arithmetic:
that a commitment merged, that the revealed plan opens it, and that an
independent redo lands where the claimant said it would have to.

A reproduction landing outside the band is a FAIL for the CLAIM, not a defect in
the verifier's work. That is the bargain the claimant made when they sealed it.
"""
from __future__ import annotations

from typing import Mapping, Optional, Tuple

from pow_core import seals

from . import pinned


def check(manifest: Mapping, observed: Optional[Mapping] = None,
          seal: Optional[Mapping] = None, claimant: str = "",
          **_) -> Tuple[str, str, str]:
    bad, why = seals.check_seal(manifest, seal, claimant, "E4")
    if bad:
        return (bad, "", why)

    verdict, src_why, digests = pinned.check_sources(manifest.get("inputs") or [])
    if verdict:
        return (verdict, "", src_why)
    out = pinned.combined(digests)

    threshold = manifest.get("threshold") or {}
    plan_threshold = (manifest.get("plan") or {}).get("threshold")
    if plan_threshold is not None and plan_threshold != threshold:
        return ("FAIL", out,
                "the band in the manifest is not the band inside the sealed plan. "
                "Widening a threshold after seeing the result is the exact move the "
                "seal exists to prevent.")

    result = manifest.get("result") or {}
    if not pinned.in_band(result.get("value"), threshold):
        return ("FAIL", out,
                f"the claimant's own result {pinned.render(result)} falls outside "
                f"the band they sealed, {pinned.render(threshold)}. The claim fails "
                f"on its own terms before anyone reproduces anything.")

    if observed is None:
        return ("UNRESOLVABLE", out,
                "the seal opens, the inputs are unchanged, and the work has not "
                "been redone. E4 settles on an independent reproduction: do the "
                "work without reading the claimant's result, then re-run this check "
                "with what you got. Nothing is owed by the claimant.")

    value = observed.get("value")
    if not isinstance(value, int) or isinstance(value, bool):
        return ("UNRESOLVABLE", out,
                "report your reproduction as a scaled integer at the claim's scale.")
    if pinned.in_band(value, threshold):
        return ("PASS", out,
                f"reproduced independently at {value}, inside the band "
                f"{pinned.render(threshold)} sealed before the work began. {src_why}")
    return ("FAIL", out,
            f"reproduced independently at {value}, outside the sealed band "
            f"{pinned.render(threshold)}. The claimant fixed that band in advance "
            f"and a blind redo did not land in it.")
