"""kea rules: DHCP pool arithmetic from the daemon's own counters.

A pool running dry is the LAN failure that presents as "the wifi is
broken": new devices get nothing while every existing lease keeps
working, so nothing on any dashboard moves. The daemon states total and
assigned per subnet; the ladder is the estate's one capacity ladder,
restated (rulebooks import only the envelope) and pinned to storage's
values by conformance. Declined addresses are the daemon reporting
poisoned ground — addresses it offered and something on the wire
refused, usually a squatter — and any at all is worth a look.
"""

from __future__ import annotations

from .. import envelope as env

CAPACITY_WARN = 90
CAPACITY_CRITICAL = 95


def subnet_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    total = facts.get("TotalAddresses")
    assigned = facts.get("AssignedAddresses")
    if isinstance(total, int) and total > 0 and isinstance(assigned, int):
        used_percent = round(assigned * 100 / total)
        if used_percent >= CAPACITY_WARN:
            opinions.append(env.opinion(
                "kea-pool-capacity",
                "critical" if used_percent >= CAPACITY_CRITICAL else "warn",
                f"The pool is {used_percent}% assigned — new devices get"
                " nothing while every existing lease keeps working, so this"
                " fails silently.", ["TotalAddresses", "AssignedAddresses"]))
    declined = facts.get("DeclinedAddresses")
    if isinstance(declined, int) and declined > 0:
        opinions.append(env.opinion(
            "kea-declined", "warn",
            f"{declined} address(es) stand declined — offered, then refused"
            " on the wire, which usually means something is squatting on"
            " them.", ["DeclinedAddresses"]))
    return opinions
