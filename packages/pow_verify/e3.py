"""E3 — Attested partner metric. Challenge the partner yourself.

The number lives inside an organisation's own systems, where nobody outside can
read it. What can be checked is that the organisation's endpoint, challenged with
a nonce it has never seen, signs the same answer for a stranger that it signed
for the claimant. That is why the nonce is generated HERE and never taken from
the manifest: a challenge the claimant could have pre-computed is a recording.

The partner is trusted about their own metric. They are not trusted to have said
it only once, to one person, in advance.
"""
from __future__ import annotations

import secrets
from typing import Mapping, Tuple

import httpx

import pow_core as core

from . import pinned

TIMEOUT = 20.0


def check(manifest: Mapping, **_) -> Tuple[str, str, str]:
    endpoint = manifest.get("endpoint", "")
    key = manifest.get("partner_public_key", "")
    metric = manifest.get("metric", "")
    claimed = manifest.get("claimed") or {}
    partner = manifest.get("partner", "the partner")

    nonce = secrets.token_hex(16)
    try:
        r = httpx.get(endpoint, params={"nonce": nonce, "metric": metric},
                      timeout=TIMEOUT, follow_redirects=True)
    except httpx.HTTPError as exc:
        return ("UNRESOLVABLE", "",
                f"{partner}'s endpoint could not be reached ({type(exc).__name__}). "
                f"An endpoint that is down says nothing about the claimant. "
                f"Nothing is owed by the claimant.")
    if r.status_code >= 400:
        return ("UNRESOLVABLE", "",
                f"{partner}'s endpoint answered HTTP {r.status_code}. Nothing is "
                f"owed by the claimant.")
    try:
        body = r.json()
    except ValueError:
        return ("UNRESOLVABLE", "",
                f"{partner}'s endpoint did not return JSON, so nothing in it can "
                f"be checked against their key.")

    if body.get("nonce") != nonce:
        return ("FAIL", "",
                "the endpoint did not echo the nonce it was challenged with. A "
                "reply that does not answer THIS challenge is a recording, and a "
                "recording proves the metric was true once, to somebody, at a time "
                "the claimant chose.")

    payload = {k: body.get(k) for k in ("metric", "value", "scale", "nonce")}
    payload["signature"] = body.get("signature", "")
    try:
        core.verify(payload, key)
    except core.Rejection as rej:
        return ("FAIL", "",
                f"the reply is not signed by the key {partner} published "
                f"({rej.detail}). Anyone can stand up an endpoint; only the partner "
                f"can sign as the partner.")

    if body.get("metric") != metric:
        return ("FAIL", "",
                f"challenged for {metric!r} and the endpoint signed for "
                f"{body.get('metric')!r}.")

    value, scale = body.get("value"), body.get("scale")
    if not isinstance(value, int) or isinstance(value, bool):
        return ("UNRESOLVABLE", "",
                "the endpoint signed a value that is not an integer, so it cannot "
                "be compared to the claim's band without inventing precision.")
    if scale != claimed.get("scale"):
        return ("FAIL", "",
                f"the endpoint signed at scale {scale} and the claim is at scale "
                f"{claimed.get('scale')}. Two different units wearing one name.")

    digest = core.content_hash({"metric": metric, "value": value, "scale": scale},
                               exclude=())
    if pinned.in_band(value, claimed):
        return ("PASS", digest,
                f"{partner} signed {value} for a nonce they had never seen, inside "
                f"the claimed band {pinned.render(claimed)}.")
    return ("FAIL", digest,
            f"{partner} signed {value} for a fresh nonce, outside the claimed band "
            f"{pinned.render(claimed)}.")
