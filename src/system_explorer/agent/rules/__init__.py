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

# Re-exported, not defined here: env.opinion() validates against the
# vocabulary, and every module in this package imports the envelope, so
# defining these here and importing them there would be a cycle. These names
# are how the rulebook and its consumers (including the operator UI, via a
# conformance lint) refer to the vocabulary and its ranking function —
# worst_level moved to the envelope in 0.6 when item_summary() started
# deriving row severity itself, and kept this address so the rulebook still
# reads as owning its own ranking.
from ..envelope import OPINION_LEVELS, worst_level  # noqa: F401
