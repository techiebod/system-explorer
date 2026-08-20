"""Re-testing a collator's relations against the estate (DESIGN 13, 16).

Resolution is two-stage because each tier may only test what it can see.
At the collator the whole test is *does anything on this host claim the
name* — intent never reaches a host, so nothing else is available there.
An unresolved target is minted anyway, marked `asserted`, and carried as
the bare name: that is not a dangling pointer, it is the condition the
model exists to express.

At the hub every asserted relation is re-tested against the intent
declaration's objects and the names other hosts publish, and its
resolution is upgraded where a match exists.

**An upgrade never changes the key.** The key is derived from the source
object's id, the type, the declared discriminator and the target's name
AS PUBLISHED — never from the resolved id, because resolution is a
property that changes and a key that changed with it would reset the
relation's lifecycle every time the estate learned something. So an
upgrade flips `resolved` and attaches an id, and the lifecycle carries on
uninterrupted. That is the property acceptance item 6 names, and it is
asserted directly below rather than inferred.

**Matching is declaration-mediated, never correlation.** A name resolves
because intent denotes it, and for no other reason. Two hosts using the
same string for different things is the ordinary case — silence is not
an invitation to join them — so a name intent has not denoted stays
asserted, which is the founding condition preserved at estate scope.

What this does NOT do, stated because the boundary matters: it does not
mint relations, which are minted where their source resolves; and it
computes observability only from assertions the hub actually holds, so a
far end nobody has checkpointed leaves the relation asserted rather than
being guessed at either way.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Mapping

from .intent import Intent


@dataclass(frozen=True)
class Assertion:
    """One directed relation as a collator published it."""

    key: str
    source_host: str
    source_id: str
    type: str
    target_name: str
    resolved: bool
    observability: str
    target_id: str | None = None
    source_instance: str | None = None
    #: The estate object the SOURCE denotes, when intent says so. Filled by
    #: the hub, never by a collator: a host cannot know it.
    source_estate_id: str | None = None


class Ambiguity(str):
    """Why a target could not be resolved, carried rather than logged."""


def _resolve_target(intent: Intent, assertion: Assertion) -> tuple[str | None, str | None]:
    """(estate object id, why-not). Two routes, tried in this order.

    First the source host's own name for the thing, which is the ordinary
    case. Then the name as ANY host denotes it, because a source often
    publishes the far end's name — a backup job's configured destination
    is the remote path, spelled the way the remote spells it. Both routes
    go through intent, so neither is correlation.
    """
    denotations = intent.denotations()
    direct = denotations.get(
        (assertion.source_host, assertion.source_instance, assertion.target_name)
    )
    if direct is not None:
        return direct, None
    matches = {
        object_id
        for (_host, _instance, name), object_id in denotations.items()
        if name == assertion.target_name
    }
    if len(matches) == 1:
        return matches.pop(), None
    if len(matches) > 1:
        # Refused rather than chosen between: picking one would merge two
        # estate objects on the strength of a shared string, which is the
        # failure the declaration mechanism exists to prevent.
        return None, (
            f"{assertion.target_name!r} is denoted by "
            f"{', '.join(sorted(matches))}; a hub does not choose"
        )
    return None, None


def _observability(
    assertion: Assertion,
    resolved_id: str | None,
    inverse: Mapping[tuple[str, str], list[Assertion]],
) -> str:
    """asserted / confirmed / contradicted, over every assertion the hub
    holds about the pair.

    Confirmation is a claim about an end no single vantage can see, so it
    is computed here and never taken from a collector — a collector
    claiming `confirmed` would be minting a fact about a machine it
    cannot reach.
    """
    if resolved_id is None or assertion.source_estate_id is None:
        return "asserted"
    reciprocal = inverse.get((resolved_id, assertion.type), [])
    back = [
        other for other in reciprocal
        if other.target_id == assertion.source_estate_id
        or other.target_name == assertion.source_id
    ]
    if not back:
        # The far end has never been looked at. Not a degraded confirmed:
        # an asserted relation carries a positive claim about what was
        # NOT observed, and rendering it as confirmed is the founding
        # failure with a solid line drawn through it.
        return "asserted"
    if all(other.observability != "contradicted" for other in back):
        return "confirmed"
    return "contradicted"


def retest(assertions: Iterable[Assertion], intent: Intent) -> tuple[Assertion, ...]:
    """Upgrade what the estate can now resolve, and change nothing else."""
    held = list(assertions)
    denotations = intent.denotations()
    # Stamp each source with the estate object it denotes, so the inverse
    # index below can be keyed on estate identity rather than on one
    # host's spelling of it.
    stamped = [
        replace(
            a,
            source_estate_id=denotations.get(
                (a.source_host, a.source_instance, a.source_id)
            ),
        )
        for a in held
    ]
    inverse: dict[tuple[str, str], list[Assertion]] = {}
    for a in stamped:
        if a.source_estate_id is not None:
            inverse.setdefault((a.source_estate_id, a.type), []).append(a)

    out: list[Assertion] = []
    for a in stamped:
        if a.resolved:
            out.append(replace(a, observability=_observability(a, a.target_id, inverse)))
            continue
        resolved_id, _why = _resolve_target(intent, a)
        upgraded = replace(
            a,
            resolved=resolved_id is not None,
            target_id=resolved_id,
            observability=_observability(a, resolved_id, inverse),
        )
        assert upgraded.key == a.key, "an upgrade must never change the key"
        out.append(upgraded)
    return tuple(out)
