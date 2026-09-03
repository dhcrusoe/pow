"""E5 — Prospective settlement. Say it first, then let the world answer.

No execution anywhere in this class. A prediction is sealed, a date passes, and a
public record says what happened. The only thing that makes it worth anything is
the ordering — sealed before the answer existed — and that is a hash and a date.

The last step is judgement: did the sealed statement come true. Code cannot read
a prediction against the world, and pretending otherwise would be the dishonest
part of this class. So the code establishes everything that CAN be established —
the commitment opens, the date has arrived, the resolution sources are pinned and
unchanged — and hands a verifier the one question only they can answer, which is
what three of them and a confidence score are for.
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
          now: Optional[date] = None, **_) -> Tuple[str, str, str]:
    bad, why = seals.check_seal(manifest, seal, claimant, "E5")
    if bad:
        return (bad, "", why)

    resolves = _as_date(manifest.get("resolves_on", ""))
    if resolves is None:
        return ("FAIL", "", "resolves_on is not a date, so there is no moment at "
                            "which this prediction was ever going to be wrong.")

    sealed_on = _as_date((seal or {}).get("sealed_at", ""))
    if sealed_on and sealed_on >= resolves:
        return ("FAIL", "",
                f"the prediction was sealed on {sealed_on} and resolves on "
                f"{resolves}. A prediction sealed after its own resolution date is "
                f"a report.")

    today = now or datetime.now(timezone.utc).date()
    if today < resolves:
        return ("UNRESOLVABLE", "",
                f"this resolves on {resolves} and today is {today}. Not wrong yet, "
                f"and not right yet. Come back after the date; nothing is owed by "
                f"the claimant, and nothing is earned by asking early.")

    verdict, src_why, digests = pinned.check_sources(manifest.get("resolution") or [])
    if verdict:
        return (verdict, "", src_why)
    out = pinned.combined(digests)

    if observed is None:
        return ("UNRESOLVABLE", out,
                "the seal opens, the date has passed, and the resolution sources "
                "are unchanged. What remains is the one thing a program cannot do: "
                "read the sealed prediction against what the sources say, and "
                "decide. Re-run with resolved true or false, and say in your "
                "confidence how clear-cut it was.")

    if not isinstance(observed.get("resolved"), bool):
        return ("UNRESOLVABLE", out,
                "report resolved as true or false. A prediction that cannot be "
                "called either way from its own sources was not falsifiable, and "
                "the honest verdict is this one.")

    if observed["resolved"]:
        return ("PASS", out,
                f"sealed before {resolves} and borne out by the pinned sources. "
                f"{src_why} {str(observed.get('note',''))[:300]}".strip())
    return ("FAIL", out,
            f"sealed before {resolves} and not borne out by the pinned sources. "
            f"{str(observed.get('note',''))[:300]}".strip())
