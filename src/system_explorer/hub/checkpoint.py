"""Receiving a collator's checkpoint, and promoting it all at once.

DESIGN 06. A hub that only receives has no way of its own to know when it
knows enough to answer, so nothing a checkpoint carries is visible until
its terminal record arrives: not to a roll-up, not to a problem domain,
not to a projection. Without that the failure is specific and quiet —
the hub receives one collection, considers the host swept, recomputes an
estate finding over a subset and RESOLVES it, which is a finding cleared
by partial knowledge arriving during recovery when nobody is looking.

Three host states, and telling the middle one from the last is the whole
reason this module keeps any state at all:

- `unswept` — no checkpoint has completed since this hub started. Nobody
  has told us. It is NOT evidence about the host.
- `connected` — a collator is streaming now, and a checkpoint of its has
  completed at some point since the hub started.
- `dark` — it told us things and stopped. That IS evidence about the host.

What this module validates and what it does not, stated because a guard
whose edge is unwritten gets trusted for the half it cannot see. It
checks the cross-record rules no single-record schema can express — the
checkpoint id, the manifest/state agreement, the terminal's count — plus
the members it must read to act. It does NOT re-implement
contract/se.checkpoint.1.json: the schema is the contract's judge and
conformance is where it judges. A record that satisfies this module and
violates the schema is a conformance failure, not a hub that lied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class Reach(str, Enum):
    UNSWEPT = "unswept"
    CONNECTED = "connected"
    DARK = "dark"


class CheckpointRefused(Exception):
    """One checkpoint refused, with the reason carried rather than logged.

    A refusal discards the whole checkpoint. There is no partial promote,
    because promoting a mixture would promote a state that existed at no
    moment — and the caller needs the reason on the wire, not in a
    traceback, so a collator can be told what it got wrong.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class CollectionSnapshot:
    """One collection as a completed checkpoint left it."""

    name: str
    generation: int
    freshness: str
    stale_reason: str | None
    objects: tuple[dict[str, Any], ...]
    #: None when the collection declared no rule table at all; an empty
    #: tuple when it declared one and nothing fired. Different readings:
    #: the first is "nobody could judge this", the second is "judged, and
    #: nothing is wrong", and collapsing them would be the product's own
    #: absence-as-health failure inside its opinion channel.
    opinions: tuple[dict[str, Any], ...] | None = None


@dataclass(frozen=True)
class HostSnapshot:
    """A whole host's state, promoted in one step.

    boot_id travels with the snapshot rather than with each object: one
    checkpoint is one collator's state at one moment, and a hub comparing
    ages across a reboot must compare clock domains and never subtract
    across them.
    """

    host: str
    checkpoint: str
    boot_id: str
    collections: dict[str, CollectionSnapshot]
    declarations: tuple[str, ...]
    history_gap: dict[str, float] | None

    @property
    def unapplied(self) -> tuple[str, ...]:
        """Collections declared but never applied — generation 0.

        Named rather than counted, and kept rather than dropped: this is
        the set that tells a collection nobody has ever run from one that
        ran and holds nothing, which is the distinction the manifest
        exists to carry.
        """
        return tuple(sorted(n for n, c in self.collections.items() if c.generation == 0))


class _Open:
    """A checkpoint mid-flight. Nothing here is visible to anything."""

    def __init__(self, manifest: dict[str, Any]) -> None:
        self.id: str = manifest["checkpoint"]
        self.host: str = manifest["host"]
        self.boot_id: str = manifest["boot_id"]
        self.declarations: tuple[str, ...] = tuple(manifest["declarations"])
        self.entries: dict[str, dict[str, Any]] = {}
        for entry in manifest["collections"]:
            name = entry["collection"]
            if name in self.entries:
                raise CheckpointRefused(
                    "manifest-repeats-collection",
                    f"{name} appears twice; one collection has one state",
                )
            self.entries[name] = entry
        self.states: dict[str, CollectionSnapshot] = {}


def _members(record: dict[str, Any], required: Iterable[str], where: str) -> None:
    missing = [m for m in required if m not in record]
    if missing:
        raise CheckpointRefused(
            "record-incomplete", f"{where} carries no {', '.join(sorted(missing))}"
        )


class Receiver:
    """Drives one connection's checkpoint, record by record.

    `ingest` returns None while the checkpoint is in flight and a
    HostSnapshot exactly once, when its terminal completes it. Any
    refusal discards what has accumulated: a receiver that kept the
    fragment would be one restart away from promoting it.
    """

    def __init__(self) -> None:
        self._open: _Open | None = None

    def ingest(self, record: dict[str, Any]) -> HostSnapshot | None:
        kind = record.get("record")
        if kind == "manifest":
            return self._manifest(record)
        if kind == "collection_state":
            return self._state(record)
        if kind == "terminal":
            return self._terminal(record)
        self._open = None
        raise CheckpointRefused("unknown-record", f"{kind!r} is not a checkpoint record")

    def _echo(self, record: dict[str, Any], where: str) -> _Open:
        if self._open is None:
            self._open = None
            raise CheckpointRefused(
                "no-manifest", f"{where} arrived before any manifest opened a checkpoint"
            )
        if record.get("checkpoint") != self._open.id:
            expected, got = self._open.id, record.get("checkpoint")
            self._open = None
            raise CheckpointRefused(
                "checkpoint-interleaved",
                f"{where} carries {got!r} while {expected!r} is open; promoting a "
                "mixture would promote a state that existed at no moment",
            )
        return self._open

    def _manifest(self, record: dict[str, Any]) -> None:
        _members(record, ("checkpoint", "host", "boot_id", "collections", "declarations"),
                 "manifest")
        if not record["collections"]:
            self._open = None
            raise CheckpointRefused(
                "manifest-empty",
                "a manifest naming no collection cannot tell 'I have nothing' "
                "from 'I sent you nothing'",
            )
        if not record["declarations"]:
            self._open = None
            raise CheckpointRefused(
                "manifest-undeclared",
                "no declaration hash, so no fact axis can be resolved for anything "
                "this checkpoint carries",
            )
        # A manifest arriving while one is open ends the first: two
        # checkpoints on one connection is a protocol error, and the
        # earlier one is abandoned rather than merged into the later.
        self._open = _Open(record)
        return None

    def _state(self, record: dict[str, Any]) -> None:
        _members(record, ("checkpoint", "collection", "generation", "objects"),
                 "collection_state")
        open_ = self._echo(record, "collection_state")
        name = record["collection"]
        entry = open_.entries.get(name)
        if entry is None:
            self._open = None
            raise CheckpointRefused(
                "state-undeclared",
                f"{name} sent state and the manifest does not name it",
            )
        if name in open_.states:
            self._open = None
            raise CheckpointRefused(
                "state-repeated", f"{name} sent state twice in one checkpoint"
            )
        if entry["generation"] == 0:
            self._open = None
            raise CheckpointRefused(
                "state-never-applied",
                f"{name} is manifested at generation 0 and sent state anyway; "
                "never-applied and empty are different readings",
            )
        if record["generation"] != entry["generation"]:
            self._open = None
            raise CheckpointRefused(
                "state-generation-moved",
                f"{name} sent generation {record['generation']} against a manifest "
                f"claiming {entry['generation']}: the checkpoint moved while it was "
                "being sent",
            )
        objects = record["objects"]
        promised = entry.get("objects")
        if promised is not None and promised != len(objects):
            self._open = None
            raise CheckpointRefused(
                "state-truncated",
                f"{name} promised {promised} objects and sent {len(objects)}",
            )
        opinions = record.get("opinions")
        if opinions is not None:
            known = {obj.get("id") for obj in objects}
            for opinion in opinions:
                if opinion.get("object") not in known:
                    self._open = None
                    raise CheckpointRefused(
                        "opinion-orphaned",
                        f"{name} carries an opinion about {opinion.get('object')!r}, "
                        "which this collection did not send; an opinion whose subject "
                        "nobody can open is a verdict with nothing to go and look at",
                    )
        open_.states[name] = CollectionSnapshot(
            name=name,
            generation=record["generation"],
            freshness=entry["freshness"],
            stale_reason=entry.get("stale_reason"),
            objects=tuple(objects),
            opinions=None if opinions is None else tuple(opinions),
        )
        return None

    def _terminal(self, record: dict[str, Any]) -> HostSnapshot:
        _members(record, ("checkpoint", "collections", "history_gap"), "terminal")
        open_ = self._echo(record, "terminal")
        if record["collections"] != len(open_.states):
            self._open = None
            raise CheckpointRefused(
                "terminal-count-mismatch",
                f"terminal counts {record['collections']} state records against "
                f"{len(open_.states)} received: a checkpoint whose middle was lost "
                "is not one that finished",
            )
        owed = {
            name for name, entry in open_.entries.items()
            if entry["generation"] > 0 and name not in open_.states
        }
        if owed:
            self._open = None
            raise CheckpointRefused(
                "state-missing",
                f"{', '.join(sorted(owed))} manifested as applied and sent no state",
            )
        collections = dict(open_.states)
        for name, entry in open_.entries.items():
            if name in collections:
                continue
            # Generation 0: named by the manifest, carrying no objects, and
            # kept as a row rather than dropped — a hub that dropped it
            # could not tell a collection nobody has ever run from one it
            # was never told about.
            collections[name] = CollectionSnapshot(
                name=name,
                generation=0,
                freshness=entry["freshness"],
                stale_reason=entry.get("stale_reason"),
                objects=(),
            )
        snapshot = HostSnapshot(
            host=open_.host,
            checkpoint=open_.id,
            boot_id=open_.boot_id,
            collections=collections,
            declarations=open_.declarations,
            history_gap=record["history_gap"],
        )
        self._open = None
        return snapshot


@dataclass
class _HostRecord:
    snapshot: HostSnapshot | None = None
    connected: bool = False
    #: When the host last completed a checkpoint here — the first of the
    #: two ages a sibling must see (DESIGN 06: the sibling's measurement,
    #: carried verbatim). None where nothing stamped the promote, and an
    #: unstamped arrival serves an UNSTATED age rather than a zero.
    told_at: str | None = None


@dataclass
class Estate:
    """What the hub knows about each host, and how sure it is.

    Declared hosts are named at construction from intent, so a host that
    has never dialled in is `unswept` rather than absent: the estate's
    founding failure was a registry that could not detect its own gaps,
    and a hub that only knew the hosts that called it would reproduce it.
    """

    declared: tuple[str, ...] = ()
    _hosts: dict[str, _HostRecord] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        for host in self.declared:
            self._hosts.setdefault(host, _HostRecord())

    def _record(self, host: str) -> _HostRecord:
        return self._hosts.setdefault(host, _HostRecord())

    def connected(self, host: str) -> None:
        self._record(host).connected = True

    def disconnected(self, host: str) -> None:
        self._record(host).connected = False

    def promote(self, snapshot: HostSnapshot, at: str | None = None) -> None:
        """Make a completed checkpoint visible, wholesale.

        Replacement rather than merge: the checkpoint is the collator's
        CURRENT state, so a collection it no longer names is one this
        host no longer has, and keeping the old row would serve a fact
        whose source has stopped claiming it.

        `at` is when this hub received it — the one age that is this
        hub's to measure, and the origin half of the pair a sibling is
        served with.
        """
        record = self._record(snapshot.host)
        record.snapshot = snapshot
        record.connected = True
        record.told_at = at

    def reach(self, host: str) -> Reach:
        record = self._hosts.get(host)
        if record is None or record.snapshot is None:
            # Never completed a checkpoint since this hub started. Not
            # dark: nobody-has-told-us is a different claim from
            # told-us-and-stopped, and only one is about the host.
            return Reach.UNSWEPT
        return Reach.CONNECTED if record.connected else Reach.DARK

    def visible(self, host: str) -> HostSnapshot | None:
        """The promoted snapshot, or None while the host is unswept.

        A checkpoint in flight is invisible here by construction: nothing
        reaches an Estate until its terminal has completed it.
        """
        record = self._hosts.get(host)
        return record.snapshot if record else None

    def told_at(self, host: str) -> str | None:
        """When this host last completed a checkpoint here, or None where
        nothing stamped it — unstated, never zero."""
        record = self._hosts.get(host)
        return record.told_at if record else None

    def hosts(self) -> tuple[str, ...]:
        return tuple(sorted(self._hosts))

    def reaches(self) -> dict[str, Reach]:
        """Every known host and its state — the input a roll-up's `reach`
        is built from, and the reason an answer can say what it could not
        see instead of quietly answering over what it could."""
        return {host: self.reach(host) for host in self.hosts()}
