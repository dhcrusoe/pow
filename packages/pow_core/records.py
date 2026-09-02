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
EVIDENCE_CLASSES = ("E1", "E2", "E3", "E4", "E5", "E6", "E7")
DOMAINS = {
    1: "Securing the internet",
    2: "Energy, water and waste",
    3: "Who gets left out",
    4: "Learning",
    5: "Health and wellbeing",
}
BOUNDARIES = {
    1: "standing",
    2: "the meter",
    3: "no subject acts as evidence",
    4: "the answer key",
    5: "no named body",
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
    domain: Literal[1, 2, 3, 4, 5]
    path: Literal["sealed", "open"] = "sealed"
    evidence_class: Optional[Literal["E1", "E2", "E3", "E4", "E5", "E6", "E7"]] = None
    proposition: str = Field(min_length=12, max_length=400)
    why: str = Field(default="", max_length=300)

    # Sealed path: what a verifier needs and nothing more.
    manifest: Dict[str, Any] = Field(default_factory=dict)

    # Open path: what was done, for whom, and what exists to check it. `evidence`
    # is a free list because nobody can anticipate what an agent will hold — a
    # URL, a signed reply, a transcript, a dataset, a photograph, a receipt.
    # `how_to_check` is the claimant's suggestion, binding on nobody: a verifier
    # who finds a better way should use it and say so.
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


class Seal(Strict):
    seal_id: str
    sealer: str
    commitment: str
    intended_class: Literal["E1", "E2", "E3", "E4", "E5", "E6", "E7"]
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
        "verdict": Verdict.model_json_schema(),
        "seal": Seal.model_json_schema(),
        "handout": Handout.model_json_schema(),
        "enrollment": Enrollment.model_json_schema(),
    }


__all__ = [
    "Claim", "Verdict", "Seal", "Handout", "Enrollment",
    "VERDICTS", "EVIDENCE_CLASSES", "DOMAINS", "BOUNDARIES", "PATHS",
    "DEFAULT_QUORUM", "json_schemas",
]
