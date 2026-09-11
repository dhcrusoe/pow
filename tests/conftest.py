from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "packages"), str(ROOT)]

import pow_core as core

from scripts.seed_log import build


@pytest.fixture(scope="session")
def seeded(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("log")
    build(root / "pow-log")
    return root


@pytest.fixture(scope="session")
def log(seeded) -> Path:
    return seeded / "pow-log"


@pytest.fixture(scope="session")
def keys(seeded) -> dict:
    return json.loads((seeded / "keys.json").read_text())


@pytest.fixture
def claim_factory(keys):
    """Build a signed, self-consistent claim. Overrides re-sign automatically."""
    def make(claimant: str = "wren", **over) -> dict:
        rec = {
            # Sealed is stated, not assumed. The default is open, so a record
            # that carries a manifest and an evidence class has to say so — which
            # is the whole point of the default matching the advice.
            "claim_id": "", "claimant": claimant, "domain": 1, "path": "sealed",
            "evidence_class": "E2",
            "proposition": "Source S asserts X at version V, and it does not.",
            "manifest": {"sources": [{"url": "https://example.invalid/x.json",
                                      "snapshot_sha256": "a" * 64}],
                         "fetched_at": "2026-09-01",
                         "assertion": "field q is null"},
            "why": "Anyone reading this source is shown a value that is wrong.",
            "boundary": "standing: public artifact", "costs": "", "resolves": "",
            "valid_as_of": "2026-09-01", "submitted_at": "2026-09-01T10:00:00Z",
            "signature": "",
        }
        rec.update(over)
        rec["claim_id"] = core.content_hash(rec, exclude=core.Claim.ID_EXCLUDES)
        rec["signature"] = core.sign(rec, keys[claimant]["private"])
        return rec
    return make


@pytest.fixture(scope="session")
def site(log, tmp_path_factory) -> Path:
    """The built read plane. Session-scoped: the build is a pure function of the
    log, so rebuilding it per test bought nothing and cost seconds."""
    from pow_generate.build import build
    out = tmp_path_factory.mktemp("agent-surfaces") / "site"
    build(log, out, api_base="https://api.example.org")
    return out
