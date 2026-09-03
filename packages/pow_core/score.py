"""Score: a pure fold over verdicts.

Deliberately dull. Flat weights, no magnitude, no decay, nothing to spend it on.
A small proven good and a large one score alike, because only one of them is
currently provable.

The function takes lists and returns integers. No I/O, no clock, no ordering
assumptions: shuffle the input and the totals are identical. That property is the
whole decomposability claim, and it is property-tested rather than asserted.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Mapping, Tuple

from .records import DEFAULT_PATH, DEFAULT_QUORUM

WEIGHTS: Dict[str, int] = {
    "PASS": 10,
    "FAIL": -15,
    "INELIGIBLE": -5,
    "UNRESOLVABLE": 0,
}
VERIFICATION = 3
FRAUD_CAUGHT = 8

# A claim settles once, on its first verdict. Later verdicts over the same claim
# are re-runs under "verifiers are verified": they pay the re-runner for the work
# and never move the claimant's total a second time.
#
# "Repeat claims over the same artifact collapse to one" is enforced on the
# canonical bytes of the manifest: the same manifest from the same claimant scores
# once, however many times it is submitted. The specification does not define
# artifact identity more tightly than this, and this is the reading that a second
# implementation can reproduce without judgement.


def _manifest_key(claim: Mapping) -> Tuple[str, str]:
    """What makes two claims 'the same artifact' for the collapse rule.

    Sealed claims collapse on the manifest. Open claims have no manifest, so they
    collapse on the action and the evidence offered — which is the closest a
    second implementation can get to the same answer without judgement.
    """
    from .canonical import canonicalize
    import hashlib

    if (claim.get("path") or DEFAULT_PATH) == "open":
        body = {"action": claim.get("action", ""),
                "evidence": claim.get("evidence", [])}
    else:
        body = claim.get("manifest", {})
    digest = hashlib.sha256(canonicalize(body)).hexdigest()
    return (claim.get("claimant", ""), digest)


def quorum_for(claim: Mapping) -> int:
    """How many independent verifiers a claim needs before it settles.

    A sealed claim needs one: the procedure is published, so a second run tells
    you nothing the first did not. An open claim needs several, because there is
    no procedure to re-run — only strangers improvising, and the thing that
    substitutes for certainty is their independent agreement.
    """
    return DEFAULT_QUORUM.get(claim.get("path") or DEFAULT_PATH,
                              DEFAULT_QUORUM[DEFAULT_PATH])


def settle(
    claims: Iterable[Mapping],
    verdicts: Iterable[Mapping],
) -> List[dict]:
    """Return one settlement event per settled claim, in claim_id order.

    Sealed: the first verdict settles it. Open: the claim settles once quorum is
    reached, and the outcome is the majority verdict among those verifiers —
    with ties, and any claim short of quorum, left unsettled and scoring nothing.

    The spread is kept, not collapsed. Five verifiers agreeing at high confidence
    and five disagreeing are different facts, and a single enum would destroy the
    difference. Score reads only `verdict`; everything else here is for the
    record and the observatory.
    """
    by_claim: Dict[str, List[Mapping]] = defaultdict(list)
    for v in verdicts:
        by_claim[v.get("claim_id", "")].append(v)

    events: List[dict] = []
    for claim in sorted(claims, key=lambda c: c.get("claim_id", "")):
        cid = claim.get("claim_id", "")
        vs = sorted(
            by_claim.get(cid, []),
            key=lambda v: (v.get("settled_at", ""), v.get("verifier", "")),
        )
        # One verifier, one voice: a re-run by the same agent is not independence.
        seen, unique = set(), []
        for v in vs:
            who = v.get("verifier", "")
            if who not in seen:
                seen.add(who)
                unique.append(v)

        need = quorum_for(claim)
        if len(unique) < need:
            continue

        deciding = unique[:need]
        tally = Counter(v.get("verdict") for v in deciding)
        top, count = tally.most_common(1)[0]
        if len([v for v, n in tally.items() if n == count]) > 1:
            continue  # a tied quorum has not decided anything

        confidences = [v["confidence"] for v in deciding
                       if isinstance(v.get("confidence"), int)]
        agreeing = [v for v in deciding if v.get("verdict") == top]

        events.append({
            "claim_id": cid,
            "claimant": claim.get("claimant", ""),
            "path": claim.get("path") or DEFAULT_PATH,
            "verdict": top,
            "settled_at": deciding[-1].get("settled_at", ""),
            "settled_by": deciding[-1].get("verifier", ""),
            "verifiers": [v.get("verifier", "") for v in deciding],
            "quorum": need,
            "agreement": round(100 * count / need),
            "unanimous": count == need,
            "confidence_mean": round(sum(confidences) / len(confidences))
                               if confidences else None,
            "confidence_low": min(confidences) if confidences else None,
            "confidence_high": max(confidences) if confidences else None,
            "dissent": [{"verifier": v.get("verifier", ""), "verdict": v.get("verdict"),
                         "diagnosis": v.get("diagnosis", "")}
                        for v in deciding if v.get("verdict") != top],
            "manifest_key": _manifest_key(claim)[1],
            "reruns": len(unique) - need,
        })
    return events


def score(
    claims: Iterable[Mapping],
    verdicts: Iterable[Mapping],
) -> Dict[str, int]:
    """Total score per pseudonym. Pure, order-independent, integer."""
    claims = list(claims)
    verdicts = list(verdicts)
    totals: Dict[str, int] = defaultdict(int)

    # Claimant side: first verdict settles, duplicate manifests collapse to one.
    counted: set = set()
    for event in settle(claims, verdicts):
        key = (event["claimant"], event["manifest_key"])
        if key in counted:
            continue
        counted.add(key)
        totals[event["claimant"]] += WEIGHTS.get(event["verdict"], 0)

    # Verifier side: every completed verification earns, including re-runs and
    # verdicts on claims that never reached quorum. The work was done either way,
    # and a verifier cannot control whether four other agents show up.
    for v in verdicts:
        verifier = v.get("verifier", "")
        if not verifier:
            continue
        totals[verifier] += VERIFICATION
        if v.get("fraud_caught"):
            totals[verifier] += FRAUD_CAUGHT

    # Ensure every claimant appears, even at zero or negative.
    for c in claims:
        totals.setdefault(c.get("claimant", ""), 0)

    return dict(sorted(totals.items()))


def breakdown(claims: Iterable[Mapping], verdicts: Iterable[Mapping]) -> Dict[str, dict]:
    """Per-agent detail. Every number here traces to a record; nothing is stored."""
    claims = list(claims)
    verdicts = list(verdicts)
    events = settle(claims, verdicts)
    settled_by_claim = {e["claim_id"]: e for e in events}

    out: Dict[str, dict] = {}

    def row(name: str) -> dict:
        return out.setdefault(name, {
            "score": 0, "claims_submitted": 0, "settled": 0,
            "PASS": 0, "FAIL": 0, "INELIGIBLE": 0, "UNRESOLVABLE": 0,
            "verifications": 0, "fraud_caught": 0,
            "evidence_classes": [], "domains": [],
        })

    for c in claims:
        r = row(c.get("claimant", ""))
        r["claims_submitted"] += 1
        ec, dom = c.get("evidence_class"), c.get("domain")
        if ec and ec not in r["evidence_classes"]:
            r["evidence_classes"].append(ec)
        if dom and dom not in r["domains"]:
            r["domains"].append(dom)
        event = settled_by_claim.get(c.get("claim_id", ""))
        if event:
            r["settled"] += 1
            r[event["verdict"]] += 1

    for v in verdicts:
        r = row(v.get("verifier", ""))
        r["verifications"] += 1
        if v.get("fraud_caught"):
            r["fraud_caught"] += 1

    totals = score(claims, verdicts)
    for name, r in out.items():
        r["score"] = totals.get(name, 0)
        r["evidence_classes"].sort()
        r["domains"].sort()
        decided = r["PASS"] + r["FAIL"] + r["INELIGIBLE"]
        r["failure_rate"] = round(100 * (r["FAIL"] + r["INELIGIBLE"]) / decided) if decided else None
    return dict(sorted(out.items()))
