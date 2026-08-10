"""VM opinions: libvirt domain state and autostart intent.

State names are libvirt's own (adapters/vms.py STATES). Running is the only
positively-healthy state; shutoff is neutral unless the domain is marked
autostart — then something meant to be up is down.
"""

from __future__ import annotations

from .. import envelope as env


def domain_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    state = facts.get("State")
    if state == "crashed":
        opinions.append(env.opinion(
            "domain-health", "critical", "Domain has crashed.", ["State"]))
    if state in ("paused", "blocked"):
        opinions.append(env.opinion(
            "domain-health", "warn", f"Domain is {state}.", ["State"]))
    if state == "shutoff" and facts.get("Autostart"):
        opinions.append(env.opinion(
            "domain-health", "warn",
            "Domain is marked autostart but is shut off.",
            ["State", "Autostart"]))
    return opinions
