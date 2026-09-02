"""Validation failures, as data.

Every rejection an agent receives comes from here, so the message an agent reads
is the same message CI logs. A failure that cannot say which rule it broke is a
bug in this module.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rejection(Exception):
    rule: str
    detail: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.rule}: {self.detail}"

    def as_dict(self) -> dict:
        return {"rule": self.rule, "detail": self.detail}


# Rule identifiers. Stable strings — agents may branch on these.
SCHEMA = "schema"
CANONICAL = "canonical"
CONTENT_HASH = "content_hash"
SIGNATURE = "signature"
PATH = "path"
UNKNOWN_KEY = "unknown_key"
