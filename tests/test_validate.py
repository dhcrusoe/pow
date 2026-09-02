"""The negative corpus.

Records built to pass wrongly. Test both directions: the ones that must be
rejected, and correct-but-unusual ones that must NOT be flagged. The second set
finds more bugs than the first, which is why it is here at all.
"""
from __future__ import annotations

import json

import pytest

import pow_core as core


def blob(rec) -> bytes:
    return core.canonicalize(rec)


def test_a_good_claim_validates(claim_factory, keys):
    c = claim_factory()
    core.validate(blob(c), "claim", public_key=keys["wren"]["public"],
                  path=core.path_for(c, "claim"))


@pytest.mark.parametrize("mutate,rule", [
    (lambda c: c.update(signature="A" * 88), "signature"),
    (lambda c: c.update(claim_id="sha256:" + "0" * 64), "content_hash"),
    (lambda c: c.update(domain=9), "schema"),
    (lambda c: c.update(evidence_class="E9"), "schema"),
    (lambda c: c.update(claimant="Not A Pseudonym"), "schema"),
    (lambda c: c.update(manifest={}), "schema"),
    (lambda c: c.update(valid_as_of="last Tuesday"), "schema"),
    (lambda c: c.update(extra_field="surprise"), "schema"),
])
def test_records_built_to_pass_wrongly_are_rejected(claim_factory, keys, mutate, rule):
    c = claim_factory()
    mutate(c)
    with pytest.raises(core.Rejection) as exc:
        core.validate(blob(c), "claim", public_key=keys["wren"]["public"])
    assert exc.value.rule == rule, f"rejected for the wrong reason: {exc.value}"


def test_an_empty_proposition_is_not_schema_valid(claim_factory, keys):
    c = claim_factory()
    c["proposition"] = ""
    with pytest.raises(core.Rejection, match="schema"):
        core.validate(blob(c), "claim", public_key=keys["wren"]["public"])


def test_a_float_anywhere_is_refused(claim_factory, keys):
    c = claim_factory()
    c["manifest"] = {**c["manifest"], "ceiling_gb": 2.5}
    with pytest.raises(core.Rejection, match="floats"):
        core.validate(json.dumps(c).encode(), "claim", public_key=keys["wren"]["public"])


def test_duplicate_keys_are_refused(keys):
    raw = b'{"claimant":"wren","claimant":"slate","domain":1}'
    with pytest.raises(core.Rejection, match="duplicate"):
        core.validate(raw, "claim", public_key=keys["wren"]["public"])


def test_the_path_must_match_the_id(claim_factory, keys):
    c = claim_factory()
    with pytest.raises(core.Rejection) as exc:
        core.validate(blob(c), "claim", public_key=keys["wren"]["public"],
                      path="claims/something-else.json")
    assert exc.value.rule == "path"


def test_e1_manifest_must_carry_what_a_stranger_needs(claim_factory, keys):
    c = claim_factory(evidence_class="E1", manifest={"image": "sha256:x"})
    c["claim_id"] = core.content_hash(c, exclude=core.Claim.ID_EXCLUDES)
    c["signature"] = core.sign(c, keys["wren"]["private"])
    with pytest.raises(core.Rejection, match="inputs"):
        core.validate(blob(c), "claim", public_key=keys["wren"]["public"])


# --- the direction that finds more bugs: correct but unusual ---

@pytest.mark.parametrize("field,value", [
    ("costs", "Points at a snapshot, so it says nothing about the live system."),
    ("boundary", "no subject acts as evidence: every profile is synthetic"),
    ("proposition", "Registry R lists 1,847 entries past their due date (n=1,847)."),
])
def test_unusual_but_correct_records_are_not_flagged(claim_factory, keys, field, value):
    c = claim_factory(**{field: value})
    core.validate(blob(c), "claim", public_key=keys["wren"]["public"],
                  path=core.path_for(c, "claim"))


def test_an_empty_costs_field_is_fine(claim_factory, keys):
    """Most claims trade nothing. Absence must not read as an omission."""
    c = claim_factory(costs="")
    core.validate(blob(c), "claim", public_key=keys["wren"]["public"])


def test_unicode_in_a_proposition_survives_the_round_trip(claim_factory, keys):
    c = claim_factory(proposition="Le référentiel R répertorie 12 entrées périmées.")
    core.validate(blob(c), "claim", public_key=keys["wren"]["public"],
                  path=core.path_for(c, "claim"))
