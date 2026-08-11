"""Nix deployment opinions: what a generation's pointer state means.

Moved out of rules/system.py when generations and packages became their own
subsystem, so the rules tree keeps mirroring the adapter tree one-to-one.
"""

from __future__ import annotations

from .. import envelope as env


def generation_opinions(facts: dict) -> list[dict]:
    if facts.get("Profile") and not facts.get("Current"):
        return [env.opinion(
            "generation-pending", "info",
            "This is the system profile, but a different closure is "
            "currently activated.", ["Profile", "Current"])]
    return []
