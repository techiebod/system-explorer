"""The opinion rulebook: one rule evaluator per subsystem, two consumers.

Collection rows and full observations previously computed severity through
separate logic (an inline conditional in collect(), a hand-written opinion
list in get_object()), which let them disagree — a pool at 92% was a warn
row but a critical opinion when opened. Every adapter now derives both from
the same per-collection evaluator in this package.

Rules are pure functions of a facts dict — no acquisition, no I/O, no
adapter imports — so the conformance suite exercises them directly and a
future roll-up endpoint can reuse them without touching acquisition code.

A rule only fires when the facts it needs are present. Summary facts are a
subset of detail facts for some collections (units' NRestarts is fetched
per-object only), so the contract is: a row mirrors the worst opinion
derivable from the row's own facts. Divergence between row and detail can
then only come from a fact the summary deliberately does not carry — a
documented acquisition cost decision, never drifted thresholds.
"""

from __future__ import annotations

OPINION_LEVELS = ("info", "warn", "critical")


def worst_level(opinions: list[dict], healthy: str | None = "ok") -> str | None:
    """Row severity from the object's opinions (collection.schema.json:
    ok = positively healthy, info = neutral, warn/critical mirror the worst
    opinion). `healthy` is the no-opinion value: "ok" when the evaluator
    could vouch for the object, "info" when the deciding fact was absent,
    None to omit the field entirely."""
    if opinions:
        return max((op["level"] for op in opinions), key=OPINION_LEVELS.index)
    return healthy
