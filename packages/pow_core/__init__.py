"""pow_core — the specification, executable.

Zero I/O. Zero network. Zero clock. Everything here is a pure function over bytes
and dicts, so it can be tested exhaustively without infrastructure and reproduced
exactly by a second implementation in another language.
"""
from . import identity
from .assignment import assign, draw, draw_seed, eligible, held_lease
from .canonical import CanonicalizationError, canonicalize, loads
from .classes import GENESIS_HIGH, registry, usable
from .contract import VERIFIER_CONTRACT, do_not_prose
from .errors import Rejection
from .identity import (
    b64,
    content_hash,
    generate,
    reserved_pseudonym,
    short,
    sign,
    signing_payload,
    unb64,
    valid_pseudonym,
    verify,
)
from .records import (
    BOUNDARIES,
    DEFAULT_PATH,
    DEFAULT_QUORUM,
    DOMAINS,
    EVIDENCE_CLASSES,
    FIELD_TYPES,
    GENESIS_CLASSES,
    PATHS,
    VERDICTS,
    Claim,
    ClassSpec,
    Enrollment,
    EvidenceClass,
    Handout,
    Research,
    Seal,
    Verdict,
    json_schemas,
)
from .score import (
    FRAUD_CAUGHT,
    FRAUD_CONFIRMATIONS,
    VERIFICATION,
    WEIGHTS,
    breakdown,
    quorum_for,
    score,
    settle,
)
from .validate import parse, path_for, validate

__version__ = "0.1.0"
__all__ = [
    "BOUNDARIES",
    "DEFAULT_PATH",
    "DEFAULT_QUORUM",
    "DOMAINS",
    "EVIDENCE_CLASSES",
    "FIELD_TYPES",
    "FRAUD_CAUGHT",
    "FRAUD_CONFIRMATIONS",
    "GENESIS_CLASSES",
    "GENESIS_HIGH",
    "PATHS",
    "VERDICTS",
    "VERIFICATION",
    "VERIFIER_CONTRACT",
    "WEIGHTS",
    "CanonicalizationError",
    "Claim",
    "ClassSpec",
    "Enrollment",
    "EvidenceClass",
    "Handout",
    "Rejection",
    "Research",
    "Seal",
    "Verdict",
    "assign",
    "b64",
    "breakdown",
    "canonicalize",
    "content_hash",
    "do_not_prose",
    "draw",
    "draw_seed",
    "eligible",
    "generate",
    "held_lease",
    "identity",
    "json_schemas",
    "loads",
    "parse",
    "path_for",
    "quorum_for",
    "registry",
    "reserved_pseudonym",
    "score",
    "settle",
    "short",
    "sign",
    "signing_payload",
    "unb64",
    "usable",
    "valid_pseudonym",
    "validate",
    "verify",
]
