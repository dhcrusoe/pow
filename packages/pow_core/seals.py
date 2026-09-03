"""Opening a seal.

A seal is a commitment hash with no content: the log learns that a plan existed,
never what it said. Opening one is the whole anti-fishing mechanism on this
network, and it is a single hash comparison — sha256(salt || canonical(plan))
against the commitment that merged.

Two properties matter, and they are different:

  the commitment opens   the plan you are showing me is the plan you sealed
  the seal came first    you sealed it before you could have seen the answer

The second is the one that bites. A commitment that opens proves only that the
claimant can do arithmetic; it is the ORDERING against something the claimant did
not control — a merge commit, a publisher's release date, a resolution date in
the future — that makes a sealed plan worth more than a stated one.

Neither property says the plan was any good. That is what verifiers are for.
"""
from __future__ import annotations

import hashlib
import re
from typing import Mapping, Optional, Tuple

from .canonical import canonicalize

HEX = re.compile(r"^[0-9a-f]+$")


def commitment(plan: Mapping, salt: str) -> str:
    """sha256(salt_bytes || canonical(plan)) as 64 hex.

    The salt exists because a plan drawn from a small space — six designs, four
    windows — is brute-forceable from its commitment alone. Without it the seal
    leaks what it was meant to hide.
    """
    if not isinstance(salt, str) or len(salt) < 32 or not HEX.match(salt.lower()):
        raise ValueError("salt must be at least 32 hex characters")
    return hashlib.sha256(bytes.fromhex(salt.lower()) + canonicalize(plan)).hexdigest()


def opens(plan: Mapping, salt: str, sealed: str) -> bool:
    """Does this plan, under this salt, reproduce the commitment that merged?"""
    try:
        return commitment(plan, salt) == str(sealed or "").replace("sha256:", "").lower()
    except (ValueError, TypeError):
        return False


def check_seal(manifest: Mapping, seal: Optional[Mapping],
               claimant: str = "", intended_class: str = "") -> Tuple[str, str]:
    """Return ("", "") when the seal holds, or (verdict, diagnosis) when it does not.

    UNRESOLVABLE where the seal could not be read: an unreachable log says nothing
    about the claimant. FAIL where it was read and does not open, because a
    commitment that does not open is not a packaging defect — it is the claimant
    showing a different plan from the one they committed to.
    """
    if seal is None:
        return ("UNRESOLVABLE",
                "the sealed plan could not be fetched, so its priority is unchecked. "
                "Without the seal record this claim is a stated plan, not a sealed "
                "one, and the difference is the entire class. Fetch seal_url and "
                "re-run. Nothing is owed by the claimant.")

    if claimant and seal.get("sealer") and seal["sealer"] != claimant:
        return ("FAIL",
                f"the seal was placed by {seal['sealer']}, not by {claimant}. "
                f"A plan somebody else sealed is not this claimant's commitment.")

    if intended_class and seal.get("intended_class") not in ("", None, intended_class):
        return ("FAIL",
                f"the seal was placed for {seal['intended_class']}, and this claim "
                f"is {intended_class}. A commitment is to one procedure, not to "
                f"whichever one turns out to work.")

    plan = manifest.get("plan") or manifest.get("prediction")
    salt = manifest.get("plan_salt", "")
    if not isinstance(plan, Mapping) or not plan:
        return ("FAIL", "the manifest reveals no plan, so there is nothing to open "
                        "the commitment with.")
    if not opens(plan, salt, seal.get("commitment", "")):
        return ("FAIL",
                "the revealed plan does not reproduce the commitment that was "
                "sealed. Either the plan changed after sealing or the salt is "
                "wrong; from outside they are the same thing, and both mean the "
                "commitment did not bind.")
    return ("", "")
