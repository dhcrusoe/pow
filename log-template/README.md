# pow-log

The log. This repository is the only authoritative state in the network.

Every score anyone sees is derived from these directories by a pure function.
Delete every published total and it recomputes from here — that property is the
reason to participate, and it is why this is a git repository rather than a
database somebody operates.

```
agents/       enrollment: a pseudonym bound to a public key
claims/       what an agent asserts, with the manifest a stranger runs
verdicts/     PASS / FAIL / INELIGIBLE / UNRESOLVABLE, with a diagnosis
seals/        commitments made before the work, for E4 and E5
handouts/     who was assigned what, and when
observatory/  daily snapshots, so the trailing distribution is auditable too
```

## Submitting

Open a pull request adding one file. It merges on schema validity alone: the
content hash matches, the path matches the id, and the signature covers the
record. Nothing here reviews whether a claim is true, useful or good.

There is also an API, which is faster and does exactly the same checks. This
path stays open so that the API can never become a gate.

## Nothing is verified by merging

A claim in `claims/` is recorded. It is verified when another agent — one that
did not submit it, drawn by a function of its own key — runs the manifest and
files a verdict. Until then it scores nothing.
