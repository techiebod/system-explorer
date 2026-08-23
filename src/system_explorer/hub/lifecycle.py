"""Findings lifecycle at estate scope, re-keyed for the new architecture.

DESIGN 06. A finding's identity used to be `(machine_id, container, app,
object_id, opinion_key)` — the shipping product's rule 15 — and the
rewrite changes every part of what a scope is: a collator names its own
host, an instance is carried beside the object rather than inside its id,
and estate-scoped findings exist at all for the first time. So the key
changes, and a key change is a lifecycle reset whether or not anybody
planned one.

**The reset is displayed rather than absorbed.** `first_seen` restarts,
and a finding carrying a restarted `first_seen` says so — because a
post-cut finding whose age reads as minutes old is indistinguishable from
a condition that appeared minutes ago, and an operator triaging by age
would work the wrong end of the list. No mapping from old keys to new is
attempted: that is machinery for protecting an estate this product does
not yet have, and a wrong mapping would be worse than a stated reset.

**Lifecycle survives freezing, deliberately.** A frozen finding keeps its
`first_seen`, its acknowledgement and its transitions untouched — freezing
is a statement that nobody could look, and nothing about it is a reason to
forget what was already known. Only a RESOLVED finding closes.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable, Mapping

from .resolution import Contributor, Judgement, Verdict, judge


@dataclass(frozen=True)
class Key:
    """A finding's identity in the new architecture.

    `scope` is the host for a host-scoped finding and the literal
    "estate" for one no host could mint. `instance` is beside the object
    rather than inside its id, so two instances publishing one native
    name carry two findings — acceptance item 1, at the lifecycle.
    """

    scope: str
    object_id: str
    opinion: str
    instance: str | None = None

    def rendered(self) -> str:
        parts = [self.scope]
        if self.instance is not None:
            parts.append(self.instance)
        parts += [self.object_id, self.opinion]
        return "/".join(parts)


@dataclass
class Finding:
    key: Key
    first_seen: str
    last_seen: str
    verdict: Verdict = Verdict.CURRENT
    contributors: tuple[Contributor, ...] = ()
    #: True while first_seen is the reset rather than the condition's own
    #: age. Carried on the finding rather than computed by whatever draws
    #: it, so every surface says the same thing.
    reset: bool = False
    blind: tuple[str, ...] = ()

    def age_is_the_conditions(self) -> bool:
        return not self.reset


#: One row per open finding, whole-set replaced inside one transaction on
#: every fold: an estate's open findings are tens, not thousands, and a
#: replace is atomic where per-key upserts would let a crash mid-write
#: leave a set no fold ever produced. Store idioms are the estate's
#: settled ones (agent/history.py): stdlib sqlite3, per-call connections,
#: WAL, fixed-width UTC ISO so lexicographic comparison is chronological.
_TABLE = """CREATE TABLE IF NOT EXISTS findings (
    rendered TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    object_id TEXT NOT NULL,
    opinion TEXT NOT NULL,
    instance TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reset INTEGER NOT NULL,
    blind TEXT NOT NULL,
    contributors TEXT NOT NULL
)"""


@dataclass
class Registry:
    """Every finding this hub knows, keyed the new way.

    `reset_at` is the moment the re-key happened. A finding first seen at
    exactly that moment has an age that is the reset's, not the
    condition's, and says so for as long as it stays open.

    `store` makes the registry survive restart, which is what makes a
    restart honest rather than the founding failure: a hub that restarts
    holds findings and no facts, so the next fold sees an unswept estate
    and every persisted finding FREEZES — lifecycle intact, reasons
    stated — instead of every condition in the estate clearing at once.
    Contributors persist with the finding because "has this been
    re-read?" is a generation comparison, and a finding that forgot its
    generations across a restart would take any reconnect as new
    evidence. What persists is lifecycle metadata in the design's sense:
    deleting the store loses first_seen and the transitions to come with
    the acknowledgement ruling, never an observation about a host.
    """

    reset_at: str
    store: Path | str | None = None
    _findings: dict[str, Finding] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        if self.store is None:
            return
        with closing(self._connect()) as db:
            db.execute(_TABLE)
            rows = db.execute(
                "SELECT scope, object_id, opinion, instance, first_seen, "
                "last_seen, verdict, reset, blind, contributors "
                "FROM findings").fetchall()
        for (scope, object_id, opinion, instance, first_seen, last_seen,
             verdict, reset, blind, contributors) in rows:
            key = Key(scope=scope, object_id=object_id, opinion=opinion,
                      instance=instance)
            self._findings[key.rendered()] = Finding(
                key=key,
                first_seen=first_seen,
                last_seen=last_seen,
                verdict=Verdict(verdict),
                contributors=tuple(
                    Contributor(host=h, collection=c, generation=g)
                    for h, c, g in json.loads(contributors)),
                reset=bool(reset),
                blind=tuple(json.loads(blind)),
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.store)
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def _persist(self) -> None:
        if self.store is None:
            return
        with closing(self._connect()) as db, db:
            db.execute(_TABLE)
            db.execute("DELETE FROM findings")
            db.executemany(
                "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(finding.key.rendered(), finding.key.scope,
                  finding.key.object_id, finding.key.opinion,
                  finding.key.instance, finding.first_seen, finding.last_seen,
                  finding.verdict.value, int(finding.reset),
                  json.dumps(list(finding.blind)),
                  json.dumps([[c.host, c.collection, c.generation]
                              for c in finding.contributors]))
                 for finding in self._findings.values()])

    def fold(
        self,
        now: str,
        derived: Mapping[Key, Iterable[Contributor]],
        estate,
    ) -> dict[str, Finding]:
        """Fold one evaluation in and return every finding still open.

        Resolution is observed, never declared: nothing here writes a
        resolved state on request. A finding closes when a source that
        COULD look stopped deriving it, which is what `judge` decides.
        """
        rendered = {key.rendered(): key for key in derived}
        contributors = {
            rendered_key: tuple(finding.contributors)
            for rendered_key, finding in self._findings.items()
        }
        for rendered_key, key in rendered.items():
            contributors[rendered_key] = tuple(derived[key])

        verdicts = judge(contributors, derived=list(rendered), estate=estate)

        for rendered_key, judgement in verdicts.items():
            existing = self._findings.get(rendered_key)
            if judgement.verdict is Verdict.RESOLVED:
                # Observed resolution closes it. Nothing else does.
                self._findings.pop(rendered_key, None)
                continue
            if existing is None:
                key = rendered.get(rendered_key)
                if key is None:
                    continue
                self._findings[rendered_key] = Finding(
                    key=key,
                    first_seen=now,
                    last_seen=now,
                    verdict=judgement.verdict,
                    contributors=contributors[rendered_key],
                    reset=now == self.reset_at,
                    blind=_blind(judgement),
                )
                continue
            self._findings[rendered_key] = replace(
                existing,
                # Frozen keeps its last_seen: the hub did not see it, so
                # stamping it now would claim an observation nobody made.
                last_seen=now if judgement.verdict is Verdict.CURRENT else existing.last_seen,
                verdict=judgement.verdict,
                contributors=contributors[rendered_key],
                blind=_blind(judgement),
            )
        self._persist()
        return dict(self._findings)

    def adopt(self, findings: Iterable[Finding]) -> None:
        """Take findings across the re-key, marking every one as reset.

        Their keys are the new ones; their ages are not the conditions'.
        Adopting rather than mapping is the decision: no old key is
        translated, because a wrong translation is worse than a stated
        reset and this product does not yet have an estate to protect.
        """
        for finding in findings:
            self._findings[finding.key.rendered()] = replace(
                finding, first_seen=self.reset_at, reset=True
            )
        self._persist()

    def open(self) -> dict[str, Finding]:
        return dict(self._findings)


def _blind(judgement: Judgement) -> tuple[str, ...]:
    return tuple(reason.value for reason in judgement.reasons)
