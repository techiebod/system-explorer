"""Which findings may resolve, and which freeze because nobody could look.

DESIGN 06, carried forward from the shipping hub's own rule and given the
one state the new architecture adds. **Absence only resolves where the
host could look.** A finding stops being current when a source that COULD
look stopped deriving it, and at no other time — because "the host
stopped saying it" and "the host could not look" are different statements
and only the first is resolution. Reporting the second as the first is
this product's founding failure, written into the permanent record at the
moment of least attention: a hub restarts, holds findings and no facts,
and every condition in the estate clears at once.

The new state is `unswept`. A collator that has not reconnected since the
hub started has told us nothing, which is not the same as having told us
and stopped, and only the second is evidence about the host. Both freeze,
and they freeze for different stated reasons, because an operator reading
a frozen finding needs to know which silence they are looking at.

**A finding remembers every input that produced it** — each contributing
host, collection, generation and arrival — rather than a single batch id.
One generation cannot say whether the two other collections that fed a
cross-host answer have come back yet, and a finding that cannot enumerate
its own contributors cannot tell "all my evidence returned and the
condition is gone" from "one third of my evidence returned".

Coverage, stated rather than implied: this decides current, resolved and
frozen from evidence. It does not own acknowledgement, first-seen, or the
transition log — those are lifecycle, they survive this decision
untouched, and freezing deliberately leaves them alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from .checkpoint import Estate, Reach


class Verdict(str, Enum):
    CURRENT = "current"
    RESOLVED = "resolved"
    FROZEN = "frozen"


class Blindness(str, Enum):
    """Why one contributor could not look. Never collapsed into a single
    "unknown": an operator acting on a frozen finding needs to know
    whether nobody has called in, a host went away, a collector could not
    read, or the evidence simply has not moved."""

    UNSWEPT = "unswept"
    DARK = "dark"
    COLLECTION_STALE = "collection-stale"
    COLLECTION_ABSENT = "collection-absent"
    NEVER_APPLIED = "never-applied"
    NOT_RE_READ = "not-re-read"


@dataclass(frozen=True)
class Contributor:
    """One input a finding was derived from.

    generation is the collection generation the evidence was read at, and
    it is what makes "has this been re-read?" answerable: a collection
    still sitting at the generation that raised a finding has produced no
    new evidence, so its silence is the old reading rather than a new one.
    """

    host: str
    collection: str
    generation: int


@dataclass(frozen=True)
class Judgement:
    verdict: Verdict
    #: Empty unless frozen. One entry per contributor that could not look,
    #: so the reason travels with the finding rather than being recomputed
    #: by whatever renders it.
    blind: tuple[tuple[Contributor, Blindness], ...] = ()

    @property
    def reasons(self) -> tuple[Blindness, ...]:
        return tuple(sorted({b for _, b in self.blind}, key=lambda b: b.value))


def _blindness(estate: Estate, contributor: Contributor) -> Blindness | None:
    """Why this contributor could not produce new evidence, or None if it
    could. The order matters: a host nobody has heard from is unswept
    whatever its collections once said, and a stale collection is stale
    whatever its generation."""
    # Asked in this order because the two questions share one answer: a
    # host has a promoted snapshot exactly when it is not unswept, so
    # testing reach for UNSWEPT and visible() for None would be the same
    # branch written twice — and a redundant guard is one a reversion
    # cannot falsify, which is how it was found on 2026-08-20.
    snapshot = estate.visible(contributor.host)
    if snapshot is None:
        return Blindness.UNSWEPT
    if estate.reach(contributor.host) is Reach.DARK:
        return Blindness.DARK
    collection = snapshot.collections.get(contributor.collection)
    if collection is None:
        # The collator no longer names the collection at all. Its absence
        # from the manifest is a statement about the collator, never
        # evidence that the condition cleared.
        return Blindness.COLLECTION_ABSENT
    if collection.generation == 0:
        return Blindness.NEVER_APPLIED
    if collection.freshness != "current":
        # A decline other than `absent` leaves prior state standing and
        # marked: nothing was established, so nothing may resolve.
        return Blindness.COLLECTION_STALE
    if collection.generation <= contributor.generation:
        # The evidence has not moved. The same reading cannot both raise a
        # finding and clear it, and this is the guard that catches a
        # changed RULE quietly resolving findings on unchanged facts.
        return Blindness.NOT_RE_READ
    return None


def judge(
    contributors: Mapping[str, Iterable[Contributor]],
    derived: Iterable[str],
    estate: Estate,
) -> dict[str, Judgement]:
    """Judge every known finding against what this evaluation derived.

    `contributors` maps a finding key to the inputs that produced it;
    `derived` is the set of keys this evaluation raised. A key in
    `derived` is current whatever its contributors say — it was just
    derived, so something could plainly look. Everything else is resolved
    only if EVERY contributor could look and none of them still says it.
    """
    still = set(derived)
    out: dict[str, Judgement] = {}
    for key, inputs in contributors.items():
        if key in still:
            out[key] = Judgement(Verdict.CURRENT)
            continue
        blind = tuple(
            (c, reason)
            for c in inputs
            if (reason := _blindness(estate, c)) is not None
        )
        out[key] = Judgement(Verdict.FROZEN, blind) if blind else Judgement(Verdict.RESOLVED)
    # A derived key nobody has contributors for is new: current, and the
    # caller records its contributors. Returned rather than skipped, so a
    # caller cannot mistake "new" for "not judged".
    for key in still - set(contributors):
        out[key] = Judgement(Verdict.CURRENT)
    return out
