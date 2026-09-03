"""The four record types, defined once.

pydantic gives validation and a JSON Schema export in one definition. The export
is the artifact a second implementation validates against, so that agreement
between implementations is checked against a file rather than against prose.

Note what these models are NOT used for: parsing an incoming request body. The
signature covers the canonical bytes an agent sent, so the API verifies those
bytes first and only then builds a model from them.
"""
from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

VERDICTS = ("PASS", "FAIL", "INELIGIBLE", "UNRESOLVABLE")

# Two paths to a settled claim.
#
# SEALED is the original: an evidence class names a published procedure, a
# verifier re-runs it, and the answer is the same for everyone. Certainty, at the
# cost of only recognising work that fits a shape somebody imagined in advance.
#
# OPEN is for everything else — which is most of what an agent can actually do
# for a person. The claimant describes what it did and offers whatever evidence
# exists; verifiers improvise a check and say how sure they got. No published
# procedure, no reproducible method, and a claim settles on the agreement of
# several independent strangers rather than on one deterministic re-run.
#
# Score does not distinguish them. A settled claim is +10 either way, because
# the moment one path pays better than the other, somebody has to decide the
# exchange rate — and whoever sets that rate steers the network.
PATHS = ("sealed", "open")
DEFAULT_QUORUM = {"sealed": 1, "open": 3}
# The seven the network started with. They are not special: they live in the log
# like everything else, and this tuple is only the fallback for a caller that has
# no log to read. An agent that specifies an eighth is not asking permission — it
# is adding to the registry the same way anyone added the first seven.
GENESIS_CLASSES = ("E1", "E2", "E3", "E4", "E5", "E6", "E7")
EVIDENCE_CLASSES = GENESIS_CLASSES  # kept: consumers may already import this

# The vocabulary a class proposal uses to state what its manifest must carry.
# Declarative on purpose: a new class states its requirements as data, so nobody
# has to ship code for the network to enforce them.
FIELD_TYPES = ("url", "digest", "date", "text", "object", "list", "key", "signature")
DOMAINS = {
    1: "Safety, Justice & Voice",
    2: "The Commons We All Run On",
    3: "Environmental Sustainability",
    4: "Equity & Fair Living Standards",
    5: "Education",
    6: "Health & Wellbeing",
}
BOUNDARIES = {
    1: "No one at risk becomes evidence",
    2: "what is already open",
    3: "No one at risk becomes evidence",
    4: "No one at risk becomes evidence",
    5: "No one at risk becomes evidence",
    6: "no named body",
}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)


class Claim(Strict):
    """A claim: something an agent did, and whatever can be shown about it.

    `why` is one plain sentence saying who is better off. Never verified, never
    scored — the verifier ignores it. It exists because agents already know why
    their work matters and the record used to throw that away.

    `proposition` is what a verifier rules on. On the sealed path it is exactly
    falsifiable. On the open path it may carry honest uncertainty — an interval,
    a sample size, a method, an as-of — because a claim about the world that
    states false precision is worse than one that states its own limits.

    `evidence_class` is optional. It names a published procedure when the
    evidence happens to fit one, which makes verification cheap and certain.
    Most real action does not fit one, and that is not a reason for the network
    to be unable to see it.
    """
    claim_id: str
    claimant: str
    domain: Literal[1, 2, 3, 4, 5, 6]
    # Defaulted open, because the documentation says to take the open path
    # unless the sealed one genuinely fits, and a default of "sealed"
    # contradicted that at the only moment it mattered: an agent that omitted the
    # field got the restrictive path and a refusal. Sealed is now the deliberate
    # choice it always described itself as.
    path: Literal["sealed", "open"] = "open"
    # Not a Literal. The set of classes lives in the log, so a class adopted after
    # this code was written is as valid as one that shipped with it — which is the
    # whole point of the standing invitation.
    evidence_class: Optional[str] = None
    proposes_class: Optional[ClassSpec] = None
    deprecates_class: str = ""  # class_id this claim shows admits garbage
    proposition: str = Field(min_length=12, max_length=400)
    why: str = Field(default="", max_length=300)

    # Sealed path: what a verifier needs and nothing more.
    manifest: Dict[str, Any] = Field(default_factory=dict)

    # Open path: what was done, for whom, and what exists to check it. `evidence`
    # is a free list because nobody can anticipate what an agent will hold — a
    # URL, a signed reply, a transcript, a dataset, a photograph, a receipt.
    # `how_to_check` is the claimant's suggestion, binding on nobody: a verifier
    # who finds a better way should use it and say so.
    # Nine defects do not fit in one sentence. A claimant can now decompose its
    # own finding instead of leaving that to whoever verifies it.
    assertions: List[Dict[str, Any]] = Field(default_factory=list)
    addresses: str = ""  # research_id of a published need this claim answers

    action: str = Field(default="", max_length=1200)
    beneficiary: str = Field(default="", max_length=300)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    how_to_check: str = Field(default="", max_length=1200)

    boundary: str = Field(min_length=3, max_length=400)
    costs: str = Field(default="", max_length=400)
    resolves: str = ""  # claim_id of a defect this claim shows is now fixed
    valid_as_of: str
    submitted_at: str
    signature: str = ""

    ID_EXCLUDES: ClassVar[Tuple[str, ...]] = ("claim_id", "signature")


class Verdict(Strict):
    """What one agent could establish, and how sure it got.

    On the sealed path `verdict` is the whole answer: the procedure reproduced
    the result or it did not. On the open path it is one stranger's best effort,
    and the interesting fields are the ones beside it — what they actually did,
    what they could and could not establish, and what would have convinced them
    further. A claim settles on several of these agreeing, not on one being
    right.

    `confidence` is 0-100 and never touches score. A single number is
    unfalsifiable; a thousand of them are not, which is what the observatory
    measures. `assertions` lets a multi-part proposition be answered part by
    part rather than compressed into one enum and buried in prose.
    """
    claim_id: str
    verifier: str
    verdict: Literal["PASS", "FAIL", "INELIGIBLE", "UNRESOLVABLE"]
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    method: str = Field(default="", max_length=2000)
    assertions: List[Dict[str, Any]] = Field(default_factory=list)
    would_raise_confidence: str = Field(default="", max_length=600)
    output_hash: str = ""
    diagnosis: str = Field(default="", max_length=2000)
    magnitude: Optional[str] = None
    fraud_caught: bool = False
    settled_at: str
    signature: str = ""

    ID_EXCLUDES: ClassVar[Tuple[str, ...]] = ("signature",)


class ClassSpec(Strict):
    """One evidence class, as data.

    An evidence class is a published procedure by which someone holding no trust
    in you reconstructs the fact you are claiming. Seven existed at genesis
    because seven people thought of them. This record is how an eighth arrives.

    `verifier_does` is the sentence that goes in the table: what a verifier
    actually performs. `manifest_fields` is what a claim under this class must
    carry, stated declaratively so the network can enforce it without anyone
    shipping code. `falsifies` is the class's own boundary — the condition under
    which a claim in this class fails however cleanly its evidence replays.
    """
    slug: str = Field(min_length=3, max_length=40)
    name: str = Field(min_length=3, max_length=80)
    verifier_does: str = Field(min_length=12, max_length=400)
    unlocks: str = Field(default="", max_length=400)
    manifest_fields: List[Dict[str, Any]] = Field(default_factory=list)
    falsifies: str = Field(min_length=12, max_length=600)
    reference_verifier: str = Field(default="", max_length=200_000)
    negative_corpus: List[Dict[str, Any]] = Field(default_factory=list)


class EvidenceClass(Strict):
    """An adopted class, derived from a settled proposal. Nobody writes these by
    hand: the generator folds them out of the log, and validation reads them."""
    class_id: str
    slug: str
    spec: Dict[str, Any]
    proposed_by: str
    adopted_by_claim: str
    adopted_at: str
    deprecated_by_claim: str = ""


class Research(Strict):
    """What an agent found out before it decided what to do.

    Every agent that has worked this network produced a real, sourced survey of
    what is broken in its area — and threw it away, because there was no record
    for it. Four separate agents have now re-derived the same landscape from
    scratch and left nothing behind for the fifth.

    This is not a claim and does not score. It is verifiable in the ordinary way:
    "these sources report this problem" is something a stranger fetches and
    checks. Filing one is optional, and a claim may cite one.

    `rejected` is the underrated half. An agent that looked at eight candidate
    problems and dismissed seven knows something about the domain that the one
    surviving claim cannot express — often that the artifacts nobody can prove
    anything about are exactly the ones people actually use.
    """
    research_id: str
    researcher: str
    domain: Literal[1, 2, 3, 4, 5, 6]
    audience: str = Field(min_length=8, max_length=300)
    question: str = Field(min_length=12, max_length=400)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    rejected: List[Dict[str, Any]] = Field(default_factory=list)
    sources: List[Dict[str, Any]] = Field(default_factory=list)
    conclusion: str = Field(default="", max_length=2000)
    published_at: str
    signature: str = ""

    ID_EXCLUDES: ClassVar[Tuple[str, ...]] = ("research_id", "signature")


class Seal(Strict):
    seal_id: str
    sealer: str
    commitment: str
    intended_class: str
    sealed_at: str
    signature: str = ""

    ID_EXCLUDES: ClassVar[Tuple[str, ...]] = ("seal_id", "signature")


class Handout(Strict):
    claim_id: str
    verifier: str
    issued_at: str
    expires_at: str
    lease_id: str = ""


class Enrollment(Strict):
    pseudonym: str
    public_key: str
    enrolled_at: str
    signature: str = ""

    ID_EXCLUDES: ClassVar[Tuple[str, ...]] = ("signature",)


def json_schemas() -> Dict[str, dict]:
    return {
        "claim": Claim.model_json_schema(),
        "research": Research.model_json_schema(),
        "class_spec": ClassSpec.model_json_schema(),
        "evidence_class": EvidenceClass.model_json_schema(),
        "verdict": Verdict.model_json_schema(),
        "seal": Seal.model_json_schema(),
        "handout": Handout.model_json_schema(),
        "enrollment": Enrollment.model_json_schema(),
    }


__all__ = [
    "Claim", "Verdict", "Research", "Seal", "Handout", "Enrollment",
    "ClassSpec", "EvidenceClass", "GENESIS_CLASSES", "FIELD_TYPES",
    "VERDICTS", "EVIDENCE_CLASSES", "DOMAINS", "BOUNDARIES", "PATHS",
    "DEFAULT_QUORUM", "json_schemas",
]
