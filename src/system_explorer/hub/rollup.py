"""The estate view: what one hub can say about every host at once.

Three things assembled here, and each is a gate-4 acceptance item rather
than a convenience.

**Objects merge only where intent says they are one** (DESIGN 16,
acceptance item 1). Two collators publishing the same native name mint
the same string, and nothing about the string says they are the same
thing. So a host object becomes an estate object exactly when the intent
document denotes it, and stays host-scoped otherwise — declaration, never
correlation, and silence is not an invitation to correlate.

**An undeclared fact reaches no roll-up** (acceptance item 7). A fact the
hub holds no declaration for has no axis: no kind, no unit, no sentence,
nothing that says whether it is a counter or a reading. Carrying it
anyway would put a value on a page with no way to interpret it, and would
let a collector introduce a fact the product has never seen simply by
emitting it. Dropped and NAMED, never dropped silently — an operator
looking for a fact they know a collector emits must be able to see that
it was refused and why.

**Coverage is identities, never counts** (DESIGN 23). "Six of six" tells
a reader nothing they can check; a list they can read tells them
immediately that the host they were thinking of is not in it. And the
estate is not "the hosts in the declaration": it carries declared,
discovered-but-not-declared and unclassified, plus which discovery
sources were readable, because a registry cannot detect that it is
incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .checkpoint import Estate, Reach
from .intent import Intent
from .session import Declarations


@dataclass(frozen=True)
class Member:
    """One host-local object contributing to an estate row."""

    host: str
    collection: str
    object_id: str
    instance: str | None


@dataclass(frozen=True)
class EstateRow:
    id: str
    kind: str | None
    estate_scoped: bool
    members: tuple[Member, ...]
    facts: Mapping[str, Any]
    #: Facts refused for having no declared axis, named per member so the
    #: reason can be shown beside the row rather than recomputed.
    undeclared: tuple[str, ...] = ()


@dataclass(frozen=True)
class Coverage:
    declared: tuple[str, ...]
    discovered_not_declared: tuple[str, ...]
    unclassified: tuple[str, ...]
    sources_readable: tuple[str, ...]
    sources_unreadable: tuple[str, ...]


@dataclass(frozen=True)
class EstateView:
    rows: tuple[EstateRow, ...]
    reach: Mapping[str, Reach]
    coverage: Coverage

    def row(self, id: str) -> EstateRow | None:
        for row in self.rows:
            if row.id == id:
                return row
        return None


def _declared_facts(
    declarations: Declarations, host: str, collection: str, facts: Mapping[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    axes = declarations.facts(host, collection)
    if axes is None:
        # Nobody has declared this pair at all. Every fact is refused, and
        # the whole set is named: "no declaration" and "no facts declared"
        # are different states and this is the first.
        return {}, sorted(facts)
    kept = {name: value for name, value in facts.items() if name in axes}
    refused = sorted(name for name in facts if name not in axes)
    return kept, refused


def assemble(
    estate: Estate,
    intent: Intent,
    declarations: Declarations,
    discovered: Iterable[str] = (),
    sources_readable: Iterable[str] = (),
    sources_unreadable: Iterable[str] = (),
) -> EstateView:
    """Fold every promoted host into one view.

    Only promoted snapshots contribute: a checkpoint in flight is
    invisible by construction, and an unswept host contributes nothing
    while still appearing in reach — which is the difference between an
    answer that is narrow and one that is wrong.
    """
    denotations = intent.denotations()
    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for host in estate.hosts():
        snapshot = estate.visible(host)
        if snapshot is None:
            continue
        for collection in sorted(snapshot.collections):
            state = snapshot.collections[collection]
            for obj in state.objects:
                native = obj.get("name", obj.get("id", ""))
                instance = obj.get("instance")
                estate_id = denotations.get((host, instance, native))
                if estate_id is None:
                    # Host-scoped, and its id carries the host so two
                    # collators' identical native names cannot collide in
                    # this mapping — which is where they would merge.
                    row_id = f"{host}/{obj.get('id', native)}"
                    if instance is not None:
                        row_id = f"{host}/{instance}/{obj.get('id', native)}"
                    scoped = False
                    kind = None
                else:
                    row_id = estate_id
                    scoped = True
                    kind = next(
                        (o.kind for o in intent.objects if o.id == estate_id), None
                    )
                kept, refused = _declared_facts(
                    declarations, host, collection, obj.get("facts") or {}
                )
                if row_id not in grouped:
                    order.append(row_id)
                    grouped[row_id] = {
                        "kind": kind, "scoped": scoped,
                        "members": [], "facts": {}, "undeclared": set(),
                    }
                entry = grouped[row_id]
                entry["members"].append(
                    Member(host=host, collection=collection,
                           object_id=obj.get("id", native), instance=instance)
                )
                entry["facts"].update(kept)
                entry["undeclared"].update(refused)

    rows = tuple(
        EstateRow(
            id=row_id,
            kind=grouped[row_id]["kind"],
            estate_scoped=grouped[row_id]["scoped"],
            members=tuple(grouped[row_id]["members"]),
            facts=dict(grouped[row_id]["facts"]),
            undeclared=tuple(sorted(grouped[row_id]["undeclared"])),
        )
        for row_id in sorted(order)
    )

    declared = set(intent.declared_hosts())
    seen = set(discovered)
    not_hosts = {
        d["name"]
        for entry in intent.not_hosts
        for d in entry.get("denoted_by", ())
        if "name" in d
    }
    coverage = Coverage(
        declared=tuple(sorted(declared)),
        # Everything a discovery source saw that intent does not declare —
        # INCLUDING the ones somebody has ruled are not hosts, because the
        # list is the evidence and the ruling is the answer to it.
        discovered_not_declared=tuple(sorted(seen - declared)),
        # A candidate nobody has ruled on at all: seen, not declared, and
        # not written off. Held rather than tidied away, because dropping
        # it silently is how a host that appeared for one afternoon leaves
        # no trace, and it is the set that says the registry is incomplete.
        unclassified=tuple(sorted(seen - declared - not_hosts)),
        sources_readable=tuple(sorted(sources_readable)),
        sources_unreadable=tuple(sorted(sources_unreadable)),
    )
    return EstateView(rows=rows, reach=estate.reaches(), coverage=coverage)
