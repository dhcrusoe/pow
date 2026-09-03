"""E6 — Counterparty attestation. Verify a signature from the party who benefited.

Two shapes, because the first one asked too much. Requesting that a clinic or a
council generate an ed25519 keypair to confirm a fix landed is requesting that
they not reply. So the second shape is a reply to an email the NETWORK sent, and
the signature is one their own mail server already applies to everything it sends,
under a key their domain already publishes in DNS. DKIM was built to answer
exactly this question — did this domain really send these bytes — and every
organisation worth attesting to already runs it.

The property that matters is unchanged either way: a stranger checks the
signature themselves, months later, from bytes in the log. Which is why the raw
message is stored whole, headers and all, rather than a transcript of what it
said. A transcript is the claimant's word for it.

The network sends the request, never the claimant, because whoever holds the
mailbox holds the transcript. And a counterparty who does not answer settles
UNRESOLVABLE at no cost to anyone — silence is not a verdict, and an incentive to
keep asking is an incentive to spam people.

E6 says a service was rendered. It says nothing about how much good it did.
"""
from __future__ import annotations

import hashlib
from typing import Tuple

import pow_core as core


def _dkim(manifest: dict, dnsfunc=None) -> Tuple[str, str, str]:
    """The email shape: verify DKIM over the raw reply, then read it."""
    raw = manifest.get("message_raw", "")
    domain = str(manifest.get("attestor_domain", "")).lower().strip()
    stored = str(manifest.get("message_sha256", "")).replace("sha256:", "")

    body = raw.encode("utf-8", "surrogateescape")
    got = hashlib.sha256(body).hexdigest()
    if stored and got != stored:
        return ("FAIL", "",
                f"message_sha256 is sha256:{stored[:12]}… and the stored message "
                f"hashes to sha256:{got[:12]}…. The bytes a verifier checks must be "
                f"the bytes that were signed.")

    try:
        import dkim as dkimlib
    except ImportError:
        return ("UNRESOLVABLE", "",
                "no DKIM implementation is available here, so the reply's signature "
                "could not be checked. Install dkimpy and re-run. Nothing is owed by "
                "the claimant.")

    try:
        ok = (dkimlib.verify(body, dnsfunc=dnsfunc) if dnsfunc
              else dkimlib.verify(body))
    except Exception as exc:                     # dkimpy raises broadly on junk
        return ("UNRESOLVABLE", "",
                f"the reply could not be parsed as a signed message "
                f"({type(exc).__name__}). Nothing is owed by the claimant.")

    if not ok:
        # A rotated selector and a forgery look identical from here, and only one
        # of them is the claimant's fault. Do not charge 15 points for the other.
        return ("UNRESOLVABLE", "",
                f"the DKIM signature on this reply did not verify against a key "
                f"published for {domain or 'the sending domain'} today. That is what "
                f"a forgery looks like AND what a rotated selector looks like, and "
                f"from here they are the same. If the key was recorded at ingest, "
                f"check against that; otherwise nothing is owed by the claimant.")

    signing = ""
    for line in raw.splitlines():
        if line.lower().startswith("dkim-signature") or (signing and line[:1] in " \t"):
            signing += line
        elif signing:
            break
    tags = dict(t.strip().split("=", 1) for t in signing.split(";")
                if "=" in t and t.strip())
    signed_domain = tags.get("d", "").strip().lower()

    if domain and signed_domain and signed_domain != domain \
            and not signed_domain.endswith("." + domain):
        return ("FAIL", "",
                f"the reply is validly signed, but by {signed_domain}, and the "
                f"attestation is claimed from {domain}. A real signature from the "
                f"wrong party attests to nothing.")

    return ("PASS", "sha256:" + got,
            f"{signed_domain or domain} signed this reply with its own mail key, "
            f"and the signature verifies over the stored bytes. A stranger can "
            f"repeat this check without asking anyone.")


def check(manifest: dict, dnsfunc=None, **_) -> Tuple[str, str, str]:
    if manifest.get("message_raw"):
        return _dkim(manifest, dnsfunc)
    attestation = manifest.get("attestation")
    key = manifest.get("attestor_public_key", "")
    sig = manifest.get("attestation_signature", "")
    if not attestation or not key or not sig:
        return ("UNRESOLVABLE", "", "manifest is missing the attestation, key or signature")

    payload = {"attestation": attestation, "signature": sig}
    try:
        core.verify(payload, key)
    except core.Rejection as rej:
        return ("FAIL", "",
                f"the attestor's signature does not cover this attestation ({rej.detail}).")
    digest = core.content_hash({"attestation": attestation}, exclude=())
    return ("PASS", digest,
            f"signature verifies against the published key of "
            f"{manifest.get('attestor', 'the attestor')}.")
