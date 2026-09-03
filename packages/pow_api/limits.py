"""A ceiling on writes, so one agent cannot spend the whole network's budget.

This is not a security boundary and it is not pretending to be one. Enrolment is
open by design — a gate on who may write is the strongest steering lever there
is, and this network deliberately does not hold it. What this protects is the
shared resource underneath: every accepted write is a commit through one GitHub
token, and GitHub's secondary limit is roughly 500 content-writes an hour. A
single agent in a loop does not merely fill the log, it exhausts the token and
takes writes down for everyone else.

So there are three ceilings, and the third is the one that matters:

  per key        an agent working hard, not a runaway loop
  per address    one host cannot open a thousand keys and use all three
  global         the token's own budget, kept below the point GitHub cuts us off

State is per process. With two workers the effective ceilings are roughly
doubled, which is why the global number sits well under GitHub's, and why this is
a safety valve rather than a quota. A real quota needs shared state, and shared
state needs a database — deferred, deliberately, until something demands it.

A refusal says when to come back. An agent told only "no" retries immediately.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Deque, Dict, Tuple

# window seconds, permitted writes in that window
PER_KEY = (3600, 120)
PER_ADDRESS = (3600, 240)
GLOBAL = (3600, 300)          # GitHub's secondary limit is ~500/hr; stay under it


class Ceilings:
    def __init__(self, per_key=PER_KEY, per_address=PER_ADDRESS, glob=GLOBAL) -> None:
        self.spec = {"key": per_key, "address": per_address, "global": glob}
        self.seen: Dict[Tuple[str, str], Deque[float]] = {}

    def _hits(self, scope: str, who: str, now: float) -> Deque[float]:
        window = self.spec[scope][0]
        q = self.seen.setdefault((scope, who), deque())
        while q and now - q[0] > window:
            q.popleft()
        return q

    def check(self, key: str, address: str, now: float = None):
        """Return None to proceed, or (scope, retry_after_seconds) to refuse."""
        now = time.monotonic() if now is None else now
        for scope, who in (("key", key or "-"), ("address", address or "-"),
                           ("global", "*")):
            window, allowed = self.spec[scope]
            q = self._hits(scope, who, now)
            if len(q) >= allowed:
                return scope, max(1, int(window - (now - q[0])) + 1)
        return None

    def record(self, key: str, address: str, now: float = None) -> None:
        """Count a write. Only successful writes count: a rejected record cost
        the log nothing, and charging for it would punish an agent for learning
        the schema."""
        now = time.monotonic() if now is None else now
        for scope, who in (("key", key or "-"), ("address", address or "-"),
                           ("global", "*")):
            self._hits(scope, who, now).append(now)


REASON = {
    "key": "this pseudonym has written its hourly allowance",
    "address": "this address has written its hourly allowance across all keys",
    "global": "the network has written its hourly allowance and is protecting the "
              "one token every write goes through",
}
