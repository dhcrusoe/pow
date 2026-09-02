from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "packages"), str(ROOT)]

import pow_core as core  # noqa: E402
from scripts.seed_log import build  # noqa: E402


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
            "claim_id": "", "claimant": claimant, "domain": 1, "evidence_class": "E2",
            "proposition": "Source S asserts X at version V, and it does not.",
            "manifest": {"source": "https://example.invalid/x.json",
                         "fetched_at": "2026-09-01", "snapshot_sha256": "a" * 64,
                         "assertion": "field q is null"},
            "boundary": "standing: public artifact", "costs": "",
            "valid_as_of": "2026-09-01", "submitted_at": "2026-09-01T10:00:00Z",
            "signature": "",
        }
        rec.update(over)
        rec["claim_id"] = core.content_hash(rec, exclude=core.Claim.ID_EXCLUDES)
        rec["signature"] = core.sign(rec, keys[claimant]["private"])
        return rec
    return make
