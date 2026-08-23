"""Finding lifecycle transitions: the product's first write (DESIGN 06).

Ruled 2026-08-23. Acknowledgement is not an edit of a finding — it is a
record appended beside it, and the finding's own state is folded from the
records rather than stored. Three properties, and each closes a specific
way this goes wrong.

**Appended, never overwritten.** The store takes INSERTs and nothing
else: no UPDATE, no DELETE, no upsert. A finding's acknowledgement
history is therefore the whole of what happened to it, and "who silenced
this, and when" has an answer that does not depend on anybody having
thought to keep one. An acknowledgement that overwrote its predecessor
would answer that question only for the most recent actor.

**Attributed, or refused.** A transition carries an actor, and the actor
is established by the listener from a credential — never taken from the
request body, because a self-declared actor is a claim rather than an
attribution and the two would render identically once stored. This module
requires the actor to be present and non-empty; establishing it is the
write listener's (`writes.py`).

**Reversible by appending, not by forgetting.** Un-acknowledging is a
transition of its own, so the record still shows that somebody
acknowledged and then changed their mind. A reversal that deleted its
target would make the log agree with a history that did not happen.

**An acknowledgement dies with the finding it acted on.** A finding's
key is scope/instance/object/opinion and carries no episode, so the same
condition clearing and recurring six weeks later renders the same string
— and a log keyed on that string alone would hand the new occurrence an
acknowledgement made by somebody who never saw it, with a stale note
telling the next person it is handled. That is suppression created by
the acknowledgement plane with nobody acknowledging anything, which is
the failure this whole product is organised against and the ruling's own
clause arriving inverted. So the registry records the resolution it
OBSERVED, `fold` treats it as ending the episode, and the history still
shows every transition. The superseded implementation guarded the same
hazard by making its INSERT conditional on the finding existing
(findings.py `append_transition`, whose docstring names it exactly); the
rewrite dropped the guard and an audit found it the day after.

**And the property the ruling exists to protect: acknowledgement changes
what is SHOUTED, not what is known.** Nothing here removes a finding from
anything. `fold` reports an acknowledgement state to sit beside a finding;
a surface that dropped acknowledged findings would be reporting absence
where somebody had only said "I have seen this", which is the failure
this whole product is organised around. `test_acknowledgement.py` holds
that as its own assertion, because it is a property of every consumer
rather than of this module.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

#: The transitions a finding may take. Closed, and small: each member is
#: a verb somebody performs on a finding, and the set is deliberately not
#: "resolve" — resolution is OBSERVED (a source that could look stopped
#: deriving the finding), never declared, and a route that let an
#: operator declare it would be the one write that makes the product lie
#: about the system rather than about its own noise.
ACKNOWLEDGE = "acknowledge"
UNACKNOWLEDGE = "unacknowledge"
ACTIONS = (ACKNOWLEDGE, UNACKNOWLEDGE)

#: Recorded when the registry OBSERVES a finding resolve. Deliberately
#: not in ACTIONS: an operator may not declare it, and the write listener
#: validates against ACTIONS, so this action is unreachable from the
#: route. Recording an observation is not declaring one — the registry
#: saw a source that could look stop deriving the finding, and the log
#: keeps that fact because the acknowledgement's whole meaning depends on
#: it.
RESOLVED = "resolved"


class TransitionRefused(Exception):
    """A transition that will not be recorded, with the reason named.

    Both members are for a person: `reason` is the stable token a caller
    switches on, `detail` says which value was wrong. A refusal that said
    only "invalid" would send an operator to read this file.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Transition:
    """One appended record. Nothing here is ever mutated."""

    #: The finding's rendered key, as `lifecycle.Key.rendered()` produces
    #: it. Stored as the rendering rather than as its parts because a
    #: transition outlives the finding it acts on — a condition that
    #: clears and returns is a NEW finding by law, and the log must not
    #: silently reattach an old acknowledgement to it.
    finding: str
    action: str
    #: Established by the listener from a credential, never from the body.
    actor: str
    at: str
    #: Why, in the actor's own words. Optional, and worth having: "known,
    #: replacing the disk on Friday" is the sentence that stops the next
    #: person re-investigating.
    note: str = ""

    def as_wire(self) -> dict[str, str]:
        return {"finding": self.finding, "action": self.action,
                "actor": self.actor, "at": self.at, "note": self.note}


@dataclass(frozen=True)
class Acknowledgement:
    """A finding's acknowledgement state, FOLDED from the log.

    Never stored: storing it would make the log and the state two things
    that can disagree, and the log is the one that is true.
    """

    acknowledged: bool
    #: Who and when for the transition that produced the current state,
    #: so a surface can say "acknowledged by X, 3 days ago" without
    #: reading the history itself.
    by: str | None = None
    at: str | None = None
    note: str = ""
    #: How many transitions this finding has seen. A finding acknowledged
    #: and un-acknowledged four times is a different thing from one
    #: acknowledged once, and a surface that showed only the current
    #: state could not tell them apart.
    transitions: int = 0


_TABLE = """CREATE TABLE IF NOT EXISTS transitions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    finding TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    at TEXT NOT NULL,
    note TEXT NOT NULL
)"""

#: Reading the log for one finding is the common case (a surface drawing
#: a row) and a scan per row would make the estate page O(findings²).
_INDEX = "CREATE INDEX IF NOT EXISTS transitions_finding ON transitions (finding, seq)"


@dataclass
class Log:
    """The append-only transition log.

    `store` is a path, or None for a log that lives only as long as the
    process — which is a test's shape and never a deployment's, since a
    transition that did not survive a restart is a silence somebody will
    have to explain. Store idioms are the estate's settled ones
    (agent/history.py, hub/lifecycle.py): stdlib sqlite3, per-call
    connections, WAL, fixed-width UTC ISO so lexicographic comparison is
    chronological.

    **Ordering is the sequence, not the stamp.** Two transitions inside
    one second are ordinary — an operator acknowledging a page of
    findings produces them — and folding by timestamp would make the
    result depend on which row sqlite happened to return first. The
    autoincrement is the order things happened in, and it is the only
    thing fold reads.
    """

    store: Path | str | None = None
    _memory: list[Transition] | None = None

    def __post_init__(self) -> None:
        if self.store is None:
            self._memory = []
            return
        with closing(self._connect()) as db, db:
            db.execute(_TABLE)
            db.execute(_INDEX)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.store)
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def append(self, transition: Transition,
               derived: Iterable[str] | None = None) -> Transition:
        """Record one transition, or refuse it whole.

        Validation is here rather than at the listener because this is
        the party that stores: a rule enforced only at one caller is a
        rule the second caller does not have.

        `derived` is the set of findings the estate currently holds. A
        transition attaches to a finding the estate has actually derived,
        never to a speculative identity — otherwise an acknowledgement
        can be filed against a condition nobody has ever seen and sit
        waiting to silence its first occurrence. Passing None skips the
        check and is for callers that have no registry to consult; the
        write listener always passes one.
        """
        if transition.action == RESOLVED:
            raise TransitionRefused(
                "not-declarable",
                "resolution is OBSERVED, never declared: this action is "
                "recorded by the registry when a source that could look "
                "stopped deriving the finding, and a caller that could "
                "declare it would be the one write that makes the product lie "
                "about the system rather than about its own noise")
        if transition.action not in ACTIONS:
            raise TransitionRefused(
                "unknown-action",
                f"{transition.action!r} is not a lifecycle transition; this hub "
                f"records {' and '.join(ACTIONS)}, and resolution is observed "
                "rather than declared")
        if not transition.actor.strip():
            raise TransitionRefused(
                "unattributed",
                "a transition carries the actor who made it; an unattributed "
                "acknowledgement answers 'who silenced this' with nothing, which "
                "is the question the log exists for")
        if not transition.finding.strip():
            raise TransitionRefused(
                "no-finding", "a transition names the finding it acts on")
        if not transition.at.strip():
            raise TransitionRefused(
                "unstamped", "a transition carries the moment it was made")
        if derived is not None and transition.finding not in set(derived):
            raise TransitionRefused(
                "no-such-finding",
                f"no open finding is rendered {transition.finding!r}; a "
                "transition attaches to a finding the estate has derived, "
                "never to an identity nobody has observed — an "
                "acknowledgement filed against one would sit waiting to "
                "silence its first occurrence")
        return self._store(transition)

    def _store(self, transition: Transition) -> Transition:
        if self._memory is not None:
            self._memory.append(transition)
            return transition
        with closing(self._connect()) as db, db:
            db.execute(
                "INSERT INTO transitions (finding, action, actor, at, note) "
                "VALUES (?, ?, ?, ?, ?)",
                (transition.finding, transition.action, transition.actor,
                 transition.at, transition.note))
        return transition

    def history(self, finding: str) -> tuple[Transition, ...]:
        """Every transition on one finding, oldest first."""
        if self._memory is not None:
            return tuple(t for t in self._memory if t.finding == finding)
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT finding, action, actor, at, note FROM transitions "
                "WHERE finding = ? ORDER BY seq", (finding,)).fetchall()
        return tuple(Transition(*row) for row in rows)

    def all(self) -> tuple[Transition, ...]:
        if self._memory is not None:
            return tuple(self._memory)
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT finding, action, actor, at, note FROM transitions "
                "ORDER BY seq").fetchall()
        return tuple(Transition(*row) for row in rows)

    def observe_resolution(self, finding: str, at: str) -> None:
        """Record that the registry saw this finding resolve.

        Appended rather than deleted, so the history still shows that
        somebody acknowledged it and that it later cleared — and so the
        store stays append-only, which is what makes it the record it
        claims to be.
        """
        self._store(Transition(finding=finding, action=RESOLVED,
                               actor="the registry", at=at,
                               note="observed: no source that could look is "
                                    "deriving this finding any more"))

    def fold(self, findings: Iterable[str]) -> dict[str, Acknowledgement]:
        """The acknowledgement state of each named finding.

        Every finding asked about gets an entry, including one with no
        transitions at all: an absent key and an un-acknowledged finding
        would render the same at a careless caller, and that is this
        product's founding error in miniature.
        """
        wanted = list(findings)
        histories: dict[str, list[Transition]] = {key: [] for key in wanted}
        for transition in self.all():
            if transition.finding in histories:
                histories[transition.finding].append(transition)
        folded: dict[str, Acknowledgement] = {}
        for key, history in histories.items():
            if not history:
                folded[key] = Acknowledgement(acknowledged=False)
                continue
            last = history[-1]
            if last.action == RESOLVED:
                # The episode ended. A later recurrence renders the same
                # key and must arrive unacknowledged, carrying nobody's
                # name and nobody's note: it is a new condition, and the
                # person who acknowledged the old one never saw it.
                folded[key] = Acknowledgement(
                    acknowledged=False, transitions=len(history))
                continue
            folded[key] = Acknowledgement(
                acknowledged=last.action == ACKNOWLEDGE,
                by=last.actor,
                at=last.at,
                note=last.note,
                transitions=len(history))
        return folded


def render(folded: Mapping[str, Acknowledgement]) -> dict[str, object]:
    """The wire shape a surface reads. One spelling, shared by the read
    route and whatever draws a row, for the reason every other renderer in
    this hub is hoisted: two spellings drift."""
    return {"acknowledgements": {
        key: {"acknowledged": ack.acknowledged, "by": ack.by, "at": ack.at,
              "note": ack.note, "transitions": ack.transitions}
        for key, ack in sorted(folded.items())}}


def as_json(transitions: Iterable[Transition]) -> str:
    return json.dumps([t.as_wire() for t in transitions], separators=(",", ":"))
