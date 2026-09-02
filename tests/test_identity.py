from __future__ import annotations

import pytest

import pow_core as core


def test_sign_and_verify_round_trip():
    sk, pk = core.generate()
    rec = {"a": 1, "b": "two"}
    rec["signature"] = core.sign(rec, sk)
    core.verify(rec, pk)


def test_tampering_breaks_the_signature():
    sk, pk = core.generate()
    rec = {"a": 1}
    rec["signature"] = core.sign(rec, sk)
    rec["a"] = 2
    with pytest.raises(core.Rejection, match="signature"):
        core.verify(rec, pk)


def test_another_key_does_not_verify():
    sk, _ = core.generate()
    _, other = core.generate()
    rec = {"a": 1}
    rec["signature"] = core.sign(rec, sk)
    with pytest.raises(core.Rejection):
        core.verify(rec, other)


def test_key_order_does_not_change_the_signature_payload():
    """The signature covers canonical bytes, so field order is irrelevant.

    This is why the API reads the raw body: any framework that reparsed and
    re-serialized the record would still verify here, but would lose the bytes
    the agent actually signed.
    """
    sk, pk = core.generate()
    one = {"a": 1, "b": 2}
    one["signature"] = core.sign(one, sk)
    two = {"b": 2, "a": 1, "signature": one["signature"]}
    core.verify(two, pk)


def test_content_hash_is_stable_and_excludes_its_own_field():
    rec = {"claim_id": "whatever", "x": 1, "signature": "s"}
    h1 = core.content_hash(rec, exclude=("claim_id", "signature"))
    rec["claim_id"] = h1
    assert core.content_hash(rec, exclude=("claim_id", "signature")) == h1


@pytest.mark.parametrize("name,ok", [
    ("wren", True), ("a-b-c", True), ("wren2", True),
    ("W", False), ("a", False), ("-wren", False), ("wren-", False),
    ("Wren", False), ("wr en", False), ("", False), (None, False),
])
def test_pseudonym_rules(name, ok):
    assert core.valid_pseudonym(name) is ok
