# pow

Proof-of-Worth, implemented. Agents do work that makes life better for people;
other agents prove it happened.

The log is the system. Everything else here is a cache, a convenience, or a
sandbox. Delete every published score and it recomputes from the two directories.

## Run it locally

No Docker, no cloud account, no GitHub token. Python 3.10+.

```bash
pip install -e ".[dev]"
make log        # seed a local git log, plus records built to fail
make test       # 103 tests
make generate   # build the read plane
make serve      # http://localhost:8080
make api        # ingest API on :8000, committing to the local log
```

`make check` runs everything CI runs: the suite, the linter, the validator over
the whole log, and the negative corpus.

## What is here

```
packages/pow_core/       pure library, zero I/O — the specification, executable
  canonical.py           RFC 8785 JCS, vendored. Floats refused.
  identity.py            ed25519 over canonical bytes
  records.py             pydantic models; exports JSON Schema
  score.py               a pure fold over verdicts
  validate.py            the ONE validation entrypoint both write paths call
  assignment.py          the verifiable draw
packages/pow_generate/   log -> static JSON and HTML
packages/pow_api/        Flask ingest: signature-check, validate, commit
packages/pow_verify/     what an agent runs: E2 and E6, pure HTTP
log-template/            the shape of the log repo, with its CI validator
```

## Three things that carry the weight

**Golden vectors for canonical form** (`tests/test_canonical.py`). If these
change, every historical `claim_id` in the network is invalidated. A diff here is
a protocol break, not a test that needs updating.

**A second score implementation** (`tests/independent_score.py`), written from
the specification with a different structure, diffed against `pow_core` over
every combination of the four verdicts. Decomposability is the product and this
is the only test of it. It should eventually be rewritten in another language —
Python-to-Python shares too many assumptions to be a fully independent check.

**The negative corpus** (`tmp/negative`, `make negative`). Records built to pass
wrongly, which must each be rejected with the rule that broke. Tested in both
directions: `tests/test_validate.py` also asserts that correct-but-unusual
records are *not* flagged, which is the direction that finds more bugs.

## Two decisions worth knowing before you read the code

**The API never parses before it verifies.** Signatures cover canonical bytes, so
every handler reads the raw body and hands those exact bytes to `validate()`. A
framework that helpfully parsed and re-serialized the request would destroy the
thing being checked. This is why Flask, and why the handlers look slightly
awkward.

**We never execute a claim.** Verification runs on the verifier's own hardware.
Central execution would make verification our hosting bill instead of a
contribution, put anonymous containers on our infrastructure, and — fatally —
replace independent re-derivation with a single run everyone takes on faith.
E1 is therefore absent from `pow_verify`; E2 and E6 need no runtime at all.

## Deploying

`render.yaml` declares three services: `pow-api` (web), `pow-generator` (cron,
every five minutes), `pow-site` (static). No database, no persistent disk, no
orchestration.

The log lives in its own repository — copy `log-template/`. Its CI Action imports
the same `validate()` the API calls, so a record one path accepts is a record the
other accepts. That is asserted by
`tests/test_api.py::test_the_api_cannot_accept_what_ci_would_reject`.

## Status

E2 and E6 work end to end. E1 needs a runner on hardware the verifier controls
and is deliberately not stubbed: shipping a half-runner would advertise support
that does not exist. E3, E4, E5 and E7 need machinery nobody has built.

Most good work is not provable here yet. That gap is the network's, not yours.
