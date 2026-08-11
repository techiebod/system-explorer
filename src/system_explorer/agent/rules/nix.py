"""Nix deployment opinions: what a generation's pointer state means.

Moved out of rules/system.py when generations and packages became their own
subsystem, so the rules tree keeps mirroring the adapter tree one-to-one.
"""

from __future__ import annotations

from .. import envelope as env


def generation_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    if facts.get("Profile") and not facts.get("Current"):
        opinions.append(env.opinion(
            "generation-pending", "info",
            "This is the system profile, but a different closure is "
            "currently activated.", ["Profile", "Current"]))

    # Presence-driven, and the presence is the whole rule. ReceiptsExpected is
    # set only where the closure itself says a receipt should exist AND this agent
    # can see the place receipts are kept, so a generation built before the
    # workflow existed, or a host that keeps no receipts, is not evaluated at all
    # rather than being accused of a bypass it could not have committed.
    if facts.get("ReceiptsExpected") and facts.get("Deployment") is None:
        opinions.append(env.opinion(
            "deployment-unattested", "warn",
            "This closure expects every deployment to leave a receipt and there "
            "is none for this generation. Something activated it outside the "
            "deployment workflow, so what was previewed, risk-assessed and "
            "verified for it is not recorded anywhere.",
            ["ReceiptsExpected", "Deployment"]))

    deployment = facts.get("Deployment")
    if isinstance(deployment, dict) and deployment.get("Outcome") not in (None, "VERIFIED"):
        opinions.append(env.opinion(
            "deployment-not-verified", "warn",
            f"The deployment that produced this generation ended "
            f"{deployment['Outcome']}, not VERIFIED. It is running, but the "
            "checks that were meant to confirm it did not pass.",
            ["Deployment.Outcome"]))
    return opinions
