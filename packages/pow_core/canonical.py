"""RFC 8785 JSON Canonicalization Scheme, vendored deliberately.

This is the most protocol-critical code in the system: two implementations that
disagree here produce different claim_ids for the same record, and every score in
the network stops being re-derivable. It is vendored rather than imported so that
it is auditable in a diff and so pow_core has no runtime dependency for the one
thing a second implementation must reproduce exactly.

Floats are rejected. ECMAScript number serialization is the only genuinely hard
part of JCS, and no record in this protocol needs a float — money is integer
minor units, measurements carry their own precision as strings. Refusing floats
removes an entire class of cross-implementation disagreement at zero cost.
"""
from __future__ import annotations

import json
import re
from typing import Any

_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}

# Keys are ordered by UTF-16 code unit, which differs from Python's default
# code-point ordering only above the BMP. Surrogate expansion makes it exact.
def _utf16_key(s: str) -> tuple:
    return tuple(s.encode("utf-16-be"))


class CanonicalizationError(ValueError):
    pass


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp in _ESCAPES:
            out.append(_ESCAPES[cp])
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(n: Any) -> str:
    if isinstance(n, bool):  # bool is a subclass of int; caught earlier, guard anyway
        raise CanonicalizationError("bool reached number serialization")
    if isinstance(n, float):
        raise CanonicalizationError(
            "floats are not permitted in canonical records; use integers or strings"
        )
    if not isinstance(n, int):
        raise CanonicalizationError(f"unsupported number type: {type(n).__name__}")
    return str(n)


def _value(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, int):
        return _number(v)
    if isinstance(v, float):
        return _number(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_value(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: _utf16_key(kv[0]))
        for k, _ in items:
            if not isinstance(k, str):
                raise CanonicalizationError("object keys must be strings")
        return "{" + ",".join(_string(k) + ":" + _value(x) for k, x in items) + "}"
    raise CanonicalizationError(f"unserializable type: {type(v).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return the canonical UTF-8 bytes for a JSON-compatible value."""
    return _value(value).encode("utf-8")


def loads(data: bytes) -> Any:
    """Parse JSON, rejecting anything canonicalize() could not reproduce."""
    try:
        parsed = json.loads(data.decode("utf-8"), parse_float=_reject_float)
    except UnicodeDecodeError as exc:
        raise CanonicalizationError(f"not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CanonicalizationError(f"not valid JSON: {exc}") from exc
    return parsed


def _reject_float(raw: str):
    raise CanonicalizationError(f"floats are not permitted in records: {raw}")


_DUPLICATE_KEY = re.compile(rb'"([^"\\]*)"\s*:')


def has_duplicate_keys(data: bytes) -> bool:
    """Cheap guard: json.loads silently keeps the last of duplicate keys."""
    obj = json.loads(data.decode("utf-8"), object_pairs_hook=lambda pairs: pairs)

    def walk(node) -> bool:
        if isinstance(node, list) and node and isinstance(node[0], tuple):
            keys = [k for k, _ in node]
            if len(keys) != len(set(keys)):
                return True
            return any(walk(v) for _, v in node)
        if isinstance(node, list):
            return any(walk(v) for v in node)
        return False

    return walk(obj)
