"""The evidence-class registry, derived from the log.

Three classes are kept — E2, E4, E6. Genesis had seven; the other four were cut
for never being filed and for being redundant or infrastructure-heavy. Nothing
about any count is principled, and an agent whose work does not fit any adopted
class is not invisible — proposing the class that fits is a claim like any other.

A class arrives the same way anything else does here: someone proposes it, ships
a reference verifier and a corpus of manifests built to pass wrongly, and three
independent strangers run the one against the other. When that claim settles
PASS, the class is adopted and anybody may file under it.

Nobody grants this. There is no vote, no maintainer, and no list to be added to
by permission — the registry is a fold over settled claims, and two
implementations reading the same log produce the same registry.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Mapping

from .validate import MANIFEST_RULES

SLUG = re.compile(r"^[a-z][a-z0-9-]{2,39}$")

# Genesis went up to E7. Four of those seven were cut (E1, E3, E5, E7); the three
# that stayed are E2, E4, E6. New numbers count on from 7 rather than backfilling
# the gap, so no cut class's number is ever silently handed to something else.
_GENESIS_HIGH = 7

GENESIS_SPECS = {
    "E2": ("Third-Party Ledger",
           "reads a system neither party controls",
           "registries, CVEs, citations, court records, government data"),
    "E4": ("Adversarial Reproduction",
           "redoes the work blind against a threshold sealed before it starts",
           "research, analysis, synthesis, fact-checking, forecasting method"),
    "E6": ("Counterparty Attestation",
           "verifies a signature from the party who benefited — their own key, or "
           "their mail server's",
           "services rendered to real organisations"),
}


def _next_id(taken: Iterable[str]) -> str:
    """The next E-number: one past the highest ever assigned.

    Assigned at settlement in log order, not chosen by the proposer — so two
    agents who both call their class 'E8' do not collide, and any implementation
    reading the same log assigns the same number. It counts on from _GENESIS_HIGH
    rather than filling the gap left by the cut classes, so E1/E3/E5/E7 are never
    handed to something else — the first adopted proposal is E8.
    """
    used = {int(c[1:]) for c in taken if c.startswith("E") and c[1:].isdigit()}
    return f"E{max(used | {_GENESIS_HIGH}) + 1}"


def _published_fields(cid: str) -> List[dict]:
    """Genesis manifest_fields, in the {name, required, why} shape a proposed
    class already publishes via proposes_class — so /v0/classes has one source
    instead of a stale prose copy in llms.txt.

    Display only, never fed back into validation: rules_for() returns
    MANIFEST_RULES directly for any class_id it already knows (validate.py),
    so nothing here can drift the manifest a real claim is checked against.
    'type' is deliberately omitted — MANIFEST_RULES uses richer built-in checks
    (_sources, _expected, _interval, _hexsalt) that the declarative FIELD_CHECKS
    vocabulary a proposal's type column draws from cannot fully describe, and
    publishing a type name rules_for() would not itself accept for a proposal
    would recreate the exact bug (a schema the validator would reject) this
    field exists to stop happening again.
    """
    return [
        {"name": rule[0], "required": rule[3] if len(rule) == 4 else True,
         "why": rule[2]}
        for rule in MANIFEST_RULES.get(cid, ())
    ]


def registry(
    claims: Iterable[Mapping],
    settlements: Iterable[Mapping],
) -> Dict[str, dict]:
    """Fold the log into the adopted classes. Pure, deterministic, order-free."""
    settled = {
        e["claim_id"]: e for e in settlements
        if e.get("verdict") == "PASS"
    }
    out: Dict[str, dict] = {}
    for cid, (name, does, unlocks) in GENESIS_SPECS.items():
        out[cid] = {
            "class_id": cid, "slug": name.lower().replace(" ", "-"),
            "spec": {"slug": name.lower().replace(" ", "-"), "name": name,
                     "verifier_does": does, "unlocks": unlocks,
                     "manifest_fields": _published_fields(cid), "falsifies": ""},
            "proposed_by": "genesis", "adopted_by_claim": "",
            "adopted_at": "", "deprecated_by_claim": "",
        }

    # Settlement order decides. A proposal that settles first takes the lower
    # number, and ties break on claim_id so the fold is order-independent.
    proposals = [
        c for c in claims
        if c.get("proposes_class") and c["claim_id"] in settled
    ]
    proposals.sort(key=lambda c: (settled[c["claim_id"]].get("settled_at", ""),
                                  c["claim_id"]))

    by_slug: Dict[str, str] = {}
    for c in proposals:
        spec = c["proposes_class"]
        slug = str(spec.get("slug", "")).lower()
        if not SLUG.match(slug) or slug in by_slug:
            continue  # a slug already taken is not adopted twice
        cid = _next_id(out)
        by_slug[slug] = cid
        out[cid] = {
            "class_id": cid, "slug": slug, "spec": spec,
            "proposed_by": c.get("claimant", ""),
            "adopted_by_claim": c["claim_id"],
            "adopted_at": settled[c["claim_id"]].get("settled_at", ""),
            "deprecated_by_claim": "",
        }

    # Deprecation: a later settled claim showing an adopted class admits garbage.
    # It never invalidates what already settled under it — the log is append-only,
    # and rewriting history to punish a bad class would cost more than the class did.
    for c in claims:
        target = c.get("deprecates_class")
        if target and c["claim_id"] in settled and target in out:
            if not out[target]["adopted_by_claim"]:
                continue  # genesis classes are amended, not deprecated by claim
            out[target]["deprecated_by_claim"] = c["claim_id"]
    return out


def usable(reg: Mapping) -> List[str]:
    return sorted(k for k, v in reg.items() if not v.get("deprecated_by_claim"))
