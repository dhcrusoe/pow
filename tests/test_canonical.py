"""Canonical form is the protocol's foundation.

If these vectors ever change, every historical claim_id in the network becomes
invalid. Treat a diff in this file as a breaking change to the protocol, not as
a test that needs updating.
"""
from __future__ import annotations

import pytest

from pow_core.canonical import CanonicalizationError, canonicalize, loads

VECTORS = [
    ({}, b"{}"),
    ({"a": 1, "b": 2}, b'{"a":1,"b":2}'),
    ({"b": 2, "a": 1}, b'{"a":1,"b":2}'),
    ({"a": [1, 2, 3]}, b'{"a":[1,2,3]}'),
    ({"a": None, "b": True, "c": False}, b'{"a":null,"b":true,"c":false}'),
    ({"a": {"z": 1, "y": 2}}, b'{"a":{"y":2,"z":1}}'),
    ({"a": 'he said "hi"'}, b'{"a":"he said \\"hi\\""}'),
    ({"a": "line\nbreak\ttab"}, b'{"a":"line\\nbreak\\ttab"}'),
    ({"a": "\u0001"}, b'{"a":"\\u0001"}'),
    ({"a": "\u00e9", "e": 2}, b'{"a":"\xc3\xa9","e":2}'),
    ({"a": -0}, b'{"a":0}'),
    ({"a": "caf\u00e9"}, b'{"a":"caf\xc3\xa9"}'),
]


@pytest.mark.parametrize("value,expected", VECTORS)
def test_golden_vectors(value, expected):
    assert canonicalize(value) == expected


def test_key_order_does_not_matter():
    a = canonicalize({"one": 1, "two": 2, "three": 3})
    b = canonicalize({"three": 3, "two": 2, "one": 1})
    assert a == b


def test_keys_sort_by_utf16_code_unit_not_code_point():
    """The one place a naive sorted() silently produces a different claim_id.

    U+1F600 is code point 128512 but its UTF-16 lead surrogate is 0xD83D, which
    is below U+FF00 (65280). Python's default string ordering compares code
    points and puts U+FF00 first; JCS compares UTF-16 code units and puts the
    astral character first. Two implementations disagreeing here hash the same
    record to two different addresses.
    """
    astral, bmp = "\U0001F600", "\uFF00"
    assert sorted([astral, bmp]) == [bmp, astral], "code-point order, for contrast"
    out = canonicalize({astral: 1, bmp: 2}).decode()
    assert out.index(astral) < out.index(bmp)


def test_floats_are_refused():
    with pytest.raises(CanonicalizationError, match="floats"):
        canonicalize({"a": 1.5})
    with pytest.raises(CanonicalizationError, match="floats"):
        loads(b'{"a": 1.5}')


def test_round_trip():
    value = {"a": [1, {"b": "c"}], "d": None, "e": True}
    assert loads(canonicalize(value)) == value


def test_unserializable_type_is_refused():
    with pytest.raises(CanonicalizationError):
        canonicalize({"a": {1, 2}})
