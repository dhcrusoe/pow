"""E7 — Aggregate study. A pre-registered estimate about a population.

This is the class the network has been missing, and it is the one every domain
asked for: not "these two documents disagree" but "this is how big the thing is".
It is E4's machinery pointed at a population instead of a task, with two
additions that matter.

The first is that the seal must precede the DATA, not merely the work. Sealing a
plan against numbers already published proves only that you can hash. The
inversion is what makes historical subjects usable: a 2022 policy is a fine thing
to study in 2026, so long as the outcome vintage you rely on had not been
released when you sealed.

The second is `refuses`. An aggregate estimate is the easiest record on this
network to over-read — a number with a band looks like a finding about the world.
The claimant has to write down what it does not establish, and a verifier reads
the proposition against that. A pass here says a pre-committed analysis reproduces
from data the claimant could not have seen. It does not say the intervention
caused anything, and it never will.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Mapping, Optional, Tuple

from pow_core import seals

from . import pinned


def _as_date(v: str) -> Optional[date]:
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).date()
    except (TypeError, ValueError):
        return None


def check(manifest: Mapping, observed: Optional[Mapping] = None,
          seal: Optional[Mapping] = None, claimant: str = "",
          **_) -> Tuple[str, str, str]:
    bad, why = seals.check_seal(manifest, seal, claimant, "E7")
    if bad:
        return (bad, "", why)

    plan = manifest.get("plan") or {}
    sealed_on = _as_date((seal or {}).get("sealed_at", ""))
    vintage = _as_date(plan.get("data_published_on", ""))
    if vintage and sealed_on and vintage <= sealed_on:
        return ("FAIL", "",
                f"the outcome data was published on {vintage} and the plan was "
                f"sealed on {sealed_on}. A plan sealed against numbers already in "
                f"the world commits to nothing: every specification could have been "
                f"tried first and the winning one sealed afterwards.")

    verdict, src_why, digests = pinned.check_sources(manifest.get("data_sources") or [])
    if verdict:
        return (verdict, "", src_why)
    out = pinned.combined(digests)

    estimate = manifest.get("estimate") or {}
    plan_estimate = plan.get("estimate_band")
    if plan_estimate is not None and plan_estimate != {
            k: estimate.get(k) for k in ("scale", "unit", "lo", "hi")}:
        return ("FAIL", out,
                "the band reported is not the band inside the sealed plan. The band "
                "is the pre-registration; a band chosen after the estimate is a "
                "description of the estimate.")

    specs = plan.get("specifications")
    reported = manifest.get("specifications")
    if specs is not None:
        if not isinstance(reported, list) or len(reported) != len(specs):
            return ("FAIL", out,
                    f"the plan sealed {len(specs)} specification(s) and the claim "
                    f"reports {0 if not isinstance(reported, list) else len(reported)}. "
                    f"Every specification you sealed is reported, or the one you show "
                    f"is the one that worked.")

    if not str(manifest.get("refuses", "")).strip():
        return ("FAIL", out,
                "refuses is empty. An estimate published without a statement of what "
                "it does not establish will be read as more than it is, and that "
                "reading is the claimant's responsibility, not the reader's.")

    if observed is None:
        return ("UNRESOLVABLE", out,
                "the pre-registration opens, it precedes the data vintage, the "
                "inputs are unchanged, and the analysis has not been re-run. E7 "
                "settles on your own estimate: run the sealed plan over the pinned "
                "data with your own tools and re-run this check with the number you "
                "get. Nothing is owed by the claimant.")

    value = observed.get("value")
    if not isinstance(value, int) or isinstance(value, bool):
        return ("UNRESOLVABLE", out,
                "report your estimate as a scaled integer at the claim's own scale.")
    if pinned.in_band(value, estimate):
        return ("PASS", out,
                f"re-ran the pre-registered analysis and estimated {value}, inside "
                f"the sealed band {pinned.render(estimate)}. This says the analysis "
                f"reproduces. It does not say the effect is real, and the claim's "
                f"own refuses says so. {src_why}")
    return ("FAIL", out,
            f"re-ran the pre-registered analysis and estimated {value}, outside the "
            f"sealed band {pinned.render(estimate)}.")
