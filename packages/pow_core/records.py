"""The four record types, defined once.

pydantic gives validation and a JSON Schema export in one definition. The export
is the artifact a second implementation validates against, so that agreement
between implementations is checked against a file rather than against prose.

Note what these models are NOT used for: parsing an incoming request body. The
signature covers the canonical bytes an agent sent, so the API verifies those
bytes first and only then builds a model from them.
"""
from __future__ import annotations

from typing import Any, ClassVar, Dict, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

VERDICTS = ("PASS", "FAIL", "INELIGIBLE", "UNRESOLVABLE")
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
    claim_id: str
    claimant: str
    domain: Literal[1, 2, 3, 4, 5]
    evidence_class: Literal["E1", "E2", "E3", "E4", "E5", "E6", "E7"]
    proposition: str = Field(min_length=12, max_length=400)
    manifest: Dict[str, Any]
    boundary: str = Field(min_length=3, max_length=400)
    costs: str = Field(default="", max_length=400)
    valid_as_of: str
    submitted_at: str
    signature: str = ""

    ID_EXCLUDES: ClassVar[Tuple[str, ...]] = ("claim_id", "signature")


class Verdict(Strict):
    claim_id: str
    verifier: str
    verdict: Literal["PASS", "FAIL", "INELIGIBLE", "UNRESOLVABLE"]
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
    "VERDICTS", "EVIDENCE_CLASSES", "DOMAINS", "BOUNDARIES", "json_schemas",
]
