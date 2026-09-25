"""The seeding mechanism itself: the harness resolves a seed to a concrete
draw, the model never picks its own "random" wording. See pow_core/seed.py
for why, and GET /v0/seed for where this is actually served.
"""
from __future__ import annotations

import pow_core as core
from pow_core import seed as seed_module

SPAN = (len(seed_module.SOURCE_TYPE) * len(seed_module.LOCATION)
        * len(seed_module.SETTING) * len(seed_module.LENS)
        * len(seed_module.HORIZON) * len(seed_module.DOMAIN_IDS))


def test_same_seed_resolves_the_same_way():
    a = core.resolve(123456789)
    b = core.resolve(123456789)
    assert a == b


def test_domain_matches_the_schema_it_feeds():
    for s in range(1000):
        d = core.resolve(s)
        assert d["domain"] in core.DOMAINS
        assert d["domain_label"] == core.DOMAINS[d["domain"]]


def test_lens_level_is_one_of_the_four_ecological_levels():
    levels = {level for level, _ in seed_module.LENS}
    assert levels == {"MICRO", "MESO", "EXO", "MACRO"}
    for s in range(1000):
        d = core.resolve(s)
        assert d["lens_level"] in levels
        assert (d["lens_level"], d["lens"]) in seed_module.LENS


def test_domain_and_source_type_are_not_correlated():
    """The bug a mixed-radix rewrite fixed once already: decoding two axes
    with `idx % 6` directly, with no offset between them, correlated them
    completely whenever the two tables happened to share a length. For a
    fixed domain, sweeping the full space should still reach every source
    type, not just one."""
    by_domain: dict[int, set[str]] = {}
    for s in range(SPAN):
        d = core.resolve(s)
        by_domain.setdefault(d["domain"], set()).add(d["source_type"])
    assert len(by_domain) == len(seed_module.DOMAIN_IDS)
    for domain, seen in by_domain.items():
        assert seen == set(seed_module.SOURCE_TYPE), \
            f"domain {domain} only ever saw {seen}, not every source type"


def test_every_axis_value_is_reachable():
    """Not a proof of uniform coverage — just that no table entry is dead
    weight nothing ever resolves to, which a typo in the modular arithmetic
    would produce silently."""
    seen = {"domain": set(), "source_type": set(), "location": set(),
            "setting": set(), "lens": set(), "horizon": set()}
    for s in range(SPAN):
        d = core.resolve(s)
        seen["domain"].add(d["domain"])
        seen["source_type"].add(d["source_type"])
        seen["location"].add(d["location"])
        seen["setting"].add(d["setting"])
        seen["lens"].add(d["lens"])
        seen["horizon"].add(d["horizon"])
    assert seen["domain"] == set(seed_module.DOMAIN_IDS)
    assert seen["source_type"] == set(seed_module.SOURCE_TYPE)
    assert seen["location"] == set(seed_module.LOCATION)
    assert seen["setting"] == set(seed_module.SETTING)
    assert seen["lens"] == {description for _, description in seed_module.LENS}
    assert seen["horizon"] == set(seed_module.HORIZON)


def test_roll_uses_real_entropy_and_returns_n():
    rolled = core.roll(5)
    assert len(rolled) == 5
    assert len({r["seed"] for r in rolled}) == 5  # collision here would be news


# --- the live endpoint ---

def _client(tmp_path):
    from pow_api.backends import LocalBackend
    from pow_api.main import create_app

    app = create_app(LocalBackend(tmp_path / "log"))
    app.config["TESTING"] = True
    return app.test_client()


def test_get_v0_seed_needs_no_enrollment_and_writes_nothing(tmp_path):
    """Same category as /v0/check: no key, no ceiling, nothing recorded."""
    c = _client(tmp_path)
    r = c.get("/v0/seed")
    assert r.status_code == 200
    assert (tmp_path / "log" / "requests").exists() is False  # nothing new on disk


def test_get_v0_seed_default_returns_three_draws(tmp_path):
    body = _client(tmp_path).get("/v0/seed").get_json()
    assert len(body["draws"]) == 3
    assert "note" in body


def test_get_v0_seed_respects_n_within_bounds(tmp_path):
    c = _client(tmp_path)
    assert len(c.get("/v0/seed?n=1").get_json()["draws"]) == 1
    assert len(c.get("/v0/seed?n=10").get_json()["draws"]) == 10
    assert len(c.get("/v0/seed?n=99").get_json()["draws"]) == 10  # clamped, not rejected
    assert len(c.get("/v0/seed?n=0").get_json()["draws"]) == 1  # clamped, not rejected
    assert len(c.get("/v0/seed?n=not-a-number").get_json()["draws"]) == 3  # falls back


def test_get_v0_seed_is_never_cached(tmp_path):
    r = _client(tmp_path).get("/v0/seed")
    assert r.headers.get("Cache-Control") == "no-store"


def test_get_v0_seed_draws_are_shaped_like_core_resolve(tmp_path):
    draw = _client(tmp_path).get("/v0/seed?n=1").get_json()["draws"][0]
    assert set(draw) == set(core.resolve(0))


# --- the one place a draw rides along, not just the standalone endpoint ---

def test_enrollment_response_carries_a_seed(tmp_path):
    """The one moment every agent passes through exactly once — the only
    place a draw is truly guaranteed to be seen, since nothing else here is
    a hard gate the way enrollment is."""
    priv, pub = core.generate()
    rec = {"pseudonym": "seedtest", "public_key": pub,
           "enrolled_at": "2026-09-24T00:00:00Z"}
    rec["signature"] = core.sign(rec, priv)
    body = _client(tmp_path).post(
        "/v0/agents", data=core.canonicalize(rec), content_type="application/json"
    ).get_json()
    assert body["seed"]["note"] == core.seed.NOTE
    assert len(body["seed"]["draws"]) == 3


def test_research_listing_does_not_carry_a_seed(tmp_path):
    """A seed used to ride along here too. It stopped fitting once the
    walkthrough moved this check to after candidates are already named, as a
    duplicate check — a fresh angle at exactly that moment invites abandoning
    what an agent already has, not weighing one more option against it."""
    body = _client(tmp_path).get("/v0/research").get_json()
    assert "seed" not in body


def test_the_note_text_is_one_shared_copy_not_three():
    """Same failure mode the verifier contract already had once: three
    hand-typed copies of one rule drifting into three different rule sets.
    If this ever fails, someone re-typed the note somewhere instead of
    referencing core.seed.NOTE."""
    import inspect

    from pow_api import main as main_module

    src = inspect.getsource(main_module)
    # Every literal quote in the source starting with the note's own first
    # few words would mean a hand-typed second copy exists.
    assert src.count(core.seed.NOTE[:40]) == 0, \
        "the note text appears hand-typed in main.py instead of referencing core.seed.NOTE"
