"""Harness-resolved randomization for what to look into.

Models asked to pick their own "random" angle aren't random — the fix is
structural: the harness resolves a seed to a concrete instruction before the
model ever sees it, so the model never picks its own wording. See
VERIFIER_CONTRACT / MANIFEST_RULES for the same preference elsewhere in this
codebase for declarative, code-enforced rules over asking nicely.

Served live at GET /v0/seed — real entropy, not derived from the log, so it
never needs to be deterministic the way pow_generate's build() does. It also
never gets written anywhere: nothing here is a record, nothing is signed,
and nothing scores. Same category as POST /v0/check — ephemeral computation
handed back to whoever asked, never persisted.
"""
from __future__ import annotations

import hashlib
import os

from .records import DOMAINS

SOURCE_TYPE = [
    "regulatory or government filings/dockets",
    "practitioner/professional forums (trade associations, listservs)",
    "grassroots/community forums (local subreddits, neighborhood apps, mutual-aid groups)",
    "local journalism (small-market news, not national outlets)",
    "standards-body or technical specification documents",
    "academic preprints/gray literature (not the top textbook results)",
]

# Pure region, independent of SETTING below — any context can pair with any
# place rather than one being fixed to the other.
LOCATION = [
    "Eastern Europe / post-Soviet space",
    "Pacific Island nations",
    "North America",
    "Sub-Saharan Africa",
    "Latin America",
    "Southeast Asia",
    "South Asia",
    "Western Europe",
    "Middle East / North Africa",
    "East Asia",
]

# Population / economic / urban context. Independent of LOCATION.
SETTING = [
    "informal economy — unlicensed, unregistered, cash-based work",
    "migrant-labor or displaced-population communities",
    "Indigenous or first-nations communities",
    "secondary or non-capital cities",
    "rural or remote, far from any urban center",
    "institutional settings — a prison, long-term care facility, refugee camp, "
    "or detention center",
    "urban core / capital city",
]

# Bronfenbrenner's ecological-systems levels, minus chronosystem (that's
# HORIZON's job). Each entry is (level, description); resolve() surfaces both
# so a batch of draws can be checked for level coverage the way domain
# coverage already can be. Two entries per level, kept even on purpose — an
# uneven split silently draws one level more often than the others.
LENS = [
    ("MICRO", "the person the system is done to (the recipient/subject)"),
    ("MICRO", "the frontline worker who administers the system, not its beneficiary"),
    ("MESO", "a family member or caregiver bridging home and the system"),
    ("MESO", "an intermediary or case worker bridging two institutions the person "
             "depends on"),
    ("EXO", "the regulator or auditor charged with overseeing this"),
    ("EXO", "a funder, competitor, or adjacent provider whose decisions ripple in "
            "unseen"),
    ("MACRO", "a comparative outsider: how a different place or era handles the "
              "same need"),
    ("MACRO", "the legal/cultural framework itself: what it assumes is normal, and "
              "whether that assumption is the actual gap"),
]

# Temporal shape, not age — spans past, present and future. IN_REMEDIATION
# asks the researcher to find out what happened rather than telling them
# ("stalled") before they've looked.
HORIZON = [
    "right now — an active, current state; not framed by its age or trend, just "
    "what's true today",
    "chronic — long-standing, steady-state, normalized as unremarkable",
    "emerging — new or intensifying, not yet a named category",
    "cyclical — recurs on a season or cycle, invisible outside it",
    "in remediation — someone already tried to fix this; find out whether it "
    "worked, partly worked, stalled, or reversed",
    "anticipated — a known future transition or deadline whose consequences "
    "haven't landed yet, worth acting on before they do",
]

DOMAIN_IDS = sorted(DOMAINS)

# Changes whenever any table above does, so a recorded seed plus this names
# one draw exactly — a seed alone stops reproducing its draw the moment a
# table changes shape, and a stored seed has no other way to say so.
TABLES_VERSION = hashlib.sha256(str(
    [SOURCE_TYPE, LOCATION, SETTING, LENS, HORIZON, DOMAIN_IDS]).encode()).hexdigest()[:12]

# One copy, referenced everywhere a draw is served — GET /v0/seed and the
# place a draw rides along on (POST /v0/agents). Three hand-typed copies is
# exactly how the verifier contract once drifted into three different rule
# sets across three documents.
NOTE = ("An angle to start from, not a conclusion to reach. Look here first; "
        "real research still has to find something true wherever it points, "
        "in the language(s) actually used there, not just English coverage. "
        "If it turns up nothing claimable, file what you rejected and roll "
        "again.")


def resolve(seed: int) -> dict:
    """Deterministically map one seed to one axis-value combination.

    Same seed always resolves to the same draw, so a run is reproducible from
    the seed alone — the record for that is `tables` below, since the mapping
    only holds while the tables it resolved against do. `idx` is hashed before
    decoding, not decoded from `seed` directly: decoded raw, domain is the
    highest-order digit and changes only every 18,144 seeds, so seeds 1-5 —
    exactly the small, sequential values an A/B round would reach for — would
    all land on domain 1. Hashing first spreads any seed, structured or not,
    across every axis before the same mixed-radix `take()` decodes it — each
    call consumes `idx`'s low-order digit in that axis's own base and divides
    the rest forward, so no two axes can end up correlated regardless of how
    many tables share a length or how many get added later.
    """
    idx = int.from_bytes(hashlib.sha256(str(seed).encode()).digest(), "big")

    def take(table):
        nonlocal idx
        idx, i = divmod(idx, len(table))
        return table[i]

    source_type = take(SOURCE_TYPE)
    location = take(LOCATION)
    setting = take(SETTING)
    lens_level, lens = take(LENS)
    horizon = take(HORIZON)
    domain = take(DOMAIN_IDS)

    return {
        "seed": seed,
        "tables": TABLES_VERSION,
        "domain": domain,
        "domain_label": DOMAINS[domain],
        "source_type": source_type,
        "location": location,
        "setting": setting,
        "lens": lens,
        "lens_level": lens_level,
        "horizon": horizon,
    }


def roll(n: int = 1) -> list[dict]:
    """Roll n fresh seeds from real entropy and resolve each."""
    return [resolve(int.from_bytes(os.urandom(4), "big")) for _ in range(n)]
