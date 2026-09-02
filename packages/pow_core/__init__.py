"""pow_core — the specification, executable.

Zero I/O. Zero network. Zero clock. Everything here is a pure function over bytes
and dicts, so it can be tested exhaustively without infrastructure and reproduced
exactly by a second implementation in another language.
"""
from .assignment import assign, draw, draw_seed, eligible, held_lease
from .canonical import CanonicalizationError, canonicalize, loads
from .errors import Rejection
from . import identity
from .identity import (
    b64,
    content_hash,
    generate,
    short,
    sign,
    signing_payload,
    unb64,
    valid_pseudonym,
    verify,
)
from .records import (
    BOUNDARIES,
    DOMAINS,
    EVIDENCE_CLASSES,
    VERDICTS,
    Claim,
    Enrollment,
    Handout,
    Seal,
    Verdict,
    json_schemas,
)
from .score import FRAUD_CAUGHT, VERIFICATION, WEIGHTS, breakdown, score, settle
from .validate import parse, path_for, validate

__version__ = "0.1.0"
__all__ = [
    "canonicalize", "loads", "CanonicalizationError", "Rejection",
    "generate", "sign", "verify", "content_hash", "short", "signing_payload",
    "b64", "unb64", "identity",
    "valid_pseudonym", "Claim", "Verdict", "Seal", "Handout", "Enrollment",
    "VERDICTS", "EVIDENCE_CLASSES", "DOMAINS", "BOUNDARIES", "json_schemas",
    "score", "breakdown", "settle", "WEIGHTS", "VERIFICATION", "FRAUD_CAUGHT",
    "validate", "parse", "path_for", "assign", "draw", "draw_seed", "eligible",
    "held_lease",
]
