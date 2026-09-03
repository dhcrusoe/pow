"""The evidence-class registry, derived from the log.

Seven classes existed at genesis because seven people thought of them. Nothing
about that number is principled, and an agent whose work does not fit any of them
was, until now, simply invisible — a failure of imagination encoded as a schema.

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
from typing import Dict, Iterable, List, Mapping, Optional

from .records import GENESIS_CLASSES

SLUG = re.compile(r"^[a-z][a-z0-9-]{2,39}$")

GENESIS_SPECS = {
    "E1": ("Declared Replay",
           "redoes a declared procedure with its own tools and lands in the "
           "claimant's band",
           "code, datasets, proofs, benchmarks, audits, translations"),
    "E2": ("Third-Party Ledger",
           "reads a system neither party controls",
           "registries, CVEs, citations, court records, government data"),
    "E3": ("Attested Partner Metric",
           "challenges a self-enrolled partner's signed API with a fresh nonce",
           "private infrastructure metrics, organisational outcomes"),
    "E4": ("Adversarial Reproduction",
           "redoes the work blind against a threshold sealed before it starts",
           "research, analysis, synthesis, fact-checking, forecasting method"),
    "E5": ("Prospective Settlement",
           "waits for the world to resolve a sealed prediction",
           "early warning, foresight, risk detection"),
    "E6": ("Counterparty Attestation",
           "verifies a signature from the party who benefited — their own key, or "
           "their mail server's",
           "services rendered to real organisations"),
    "E7": ("Aggregate Study",
           "runs a pre-registered population-level analysis",
           "pooled campaigns, diffuse impact"),
}


def _next_id(taken: Iterable[str]) -> str:
    """The next free E-number.

    Assigned at settlement in log order, not chosen by the proposer — so two
    agents who both call their class 'E8' do not collide, and any implementation
    reading the same log assigns the same number.
    """
    used = {int(c[1:]) for c in taken if c.startswith("E") and c[1:].isdigit()}
    n = 1
    while n in used:
        n += 1
    return f"E{n}"


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
                     "manifest_fields": [], "falsifies": ""},
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
