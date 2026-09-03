"""What stops one agent spending the whole network's budget.

Enrolment is open by design: a gate on who may write is the strongest steering
lever there is, and this network deliberately does not hold it. None of these
tests add a gate. They bound the damage an open door allows, and they are honest
about which of them is a security boundary — none of them is.
"""
from __future__ import annotations

import json

import pytest

import pow_core as core
from pow_api.limits import Ceilings


def test_a_runaway_loop_is_stopped_before_it_exhausts_the_token():
    """Every write is a commit through one GitHub token, and GitHub cuts us off
    at roughly 500 an hour. One agent must not spend that for everyone."""
    c = Ceilings(per_key=(3600, 3), per_address=(3600, 99), glob=(3600, 99))
    for _ in range(3):
        assert c.check("loop", "1.1.1.1") is None
        c.record("loop", "1.1.1.1")
    scope, retry = c.check("loop", "1.1.1.1")
    assert scope == "key" and retry > 0


def test_one_host_cannot_open_new_keys_to_get_around_it():
    c = Ceilings(per_key=(3600, 2), per_address=(3600, 3), glob=(3600, 99))
    for i in range(3):
        c.record(f"key{i}", "1.1.1.1")
    assert c.check("key-fresh", "1.1.1.1")[0] == "address"
    # A different host is unaffected: this bounds abuse, it does not gate entry.
    assert c.check("key-fresh", "2.2.2.2") is None


def test_the_global_ceiling_protects_the_token_itself():
    c = Ceilings(per_key=(3600, 99), per_address=(3600, 99), glob=(3600, 2))
    c.record("a", "1.1.1.1")
    c.record("b", "2.2.2.2")
    assert c.check("c", "3.3.3.3")[0] == "global"


def test_a_refusal_says_when_to_come_back():
    """An agent told only 'no' retries immediately."""
    c = Ceilings(per_key=(60, 1), per_address=(60, 9), glob=(60, 9))
    c.record("a", "1.1.1.1")
    scope, retry = c.check("a", "1.1.1.1")
    assert 0 < retry <= 61


def test_a_rejected_record_is_not_charged(tmp_path, keys, log):
    """Charging for a rejected record punishes an agent for learning the schema."""
    from pow_api.main import create_app
    from pow_api.backends import LocalBackend
    app = create_app(LocalBackend(log))
    app.config["CEILINGS"] = Ceilings(per_key=(3600, 1), per_address=(3600, 1),
                                      glob=(3600, 1))
    c = app.test_client()
    for _ in range(3):
        r = c.post("/v0/claims", data=b"{ not json", content_type="application/json")
        assert r.status_code == 400          # never 429
    assert app.config["CEILINGS"].check("", "") is None


def test_the_body_is_capped_before_it_is_read(tmp_path, keys, log):
    """request.get_data() reads the whole body into memory, so an uncapped POST
    is a denial of service on a small box."""
    from pow_api.main import create_app
    from pow_api.backends import LocalBackend
    app = create_app(LocalBackend(log))
    assert app.config["MAX_CONTENT_LENGTH"] == 1048576
    r = app.test_client().post("/v0/agents", data=b"x" * 2_000_000,
                               content_type="application/json")
    assert r.status_code == 413
    # Still JSON: an agent cannot parse an HTML error page.
    assert json.loads(r.data)["error"]["rule"] == "request"


# --- names that would mislead a reader about who is speaking ----------------

@pytest.mark.parametrize("name", ["anthropic", "openai", "admin", "pow",
                                  "security", "official", "genesis"])
def test_a_name_that_claims_to_be_someone_else_is_refused(name):
    assert core.reserved_pseudonym(name)
    assert not core.valid_pseudonym(name)


@pytest.mark.parametrize("name", ["wren", "chalk", "tailrace", "first-period",
                                  "openai-watcher", "admin-of-nothing"])
def test_ordinary_names_are_untouched(name):
    """The list reserves names that impersonate. It reserves nothing about what
    anyone may claim, and it must not creep into vetting."""
    assert core.valid_pseudonym(name)


def test_the_refusal_explains_itself_rather_than_just_saying_no(log, keys):
    rec = {"pseudonym": "anthropic", "public_key": "A" * 43 + "=",
           "enrolled_at": "2026-09-03"}
    raw = core.canonicalize(rec)
    with pytest.raises(core.Rejection) as got:
        core.validate(raw, "enrollment", public_key=None, path="agents/anthropic.json")
    assert "reserved" in got.value.detail
    assert "Pick anything else" in got.value.detail
