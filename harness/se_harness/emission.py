"""One emission core, shared by the replayed reference and the live one.

The reference implementation now runs in two places: against captured payloads
(``se-reference-collector``, which is what the corpus is made of) and against a
real machine (``se-live-reference``, which is what the comparator diffs a port
against). Those two differ in exactly three things — where the native documents
come from, what the clock reads, and what identifies the run — and in nothing
else.

Keeping the record shapes here rather than in both callers is not tidiness. A
second copy of the emission logic would drift, and the first thing it would
drift on is the channel a statement lands in: which reading is a fact, which is
an absence, which is an unobservable, which is an assertion. A comparator whose
reference disagreed with the corpus's reference about that would report a
defect in the port every time it was the harness that had moved.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import TextIO


class Emitter:
    """The collector contract's stdout side: NDJSON, one record per line.

    Every record this product's reference emits goes through one of the
    methods below, so the set of record shapes it can produce is enumerable by
    reading this class.
    """

    def __init__(
        self,
        stream: TextIO,
        generations: dict[str, int],
        begin_fields: dict[str, object],
        stamp: Callable[[int], float],
        costs: Callable[[], tuple[float, float]],
    ) -> None:
        self._stream = stream
        self._generations = generations
        self._begin = {
            "record": "begin",
            **begin_fields,
            "generations": generations,
        }
        self._stamp = stamp
        self._costs = costs
        self._emitted = 0

    def _write(self, record: dict) -> None:
        print(
            json.dumps(record, sort_keys=True, separators=(",", ":")),
            file=self._stream,
        )

    def begin(self) -> None:
        self._write(self._begin)

    def decline(self, collection: str, reason: str, detail: str) -> None:
        self._write(
            {
                "record": "decline",
                "collection": collection,
                "reason": reason,
                "detail": detail,
            }
        )

    def commit(
        self, collection: str, objects: int, assertions: int, unobservable: int
    ) -> None:
        """All three counts, always, zero when zero (DESIGN 19).

        They are required members precisely so a subject cannot disable the
        truncation check by omitting the count, and that applies to the
        reference as much as to anything it is the reference for.
        """
        self._write(
            {
                "record": "commit",
                "collection": collection,
                "generation": self._generations[collection],
                "objects": objects,
                "assertions": assertions,
                "unobservable": unobservable,
            }
        )

    def end(self) -> None:
        """`end` echoes what `begin` opened — never restates it, so the two
        cannot drift into naming two different batches."""
        cpu_ms, wall_ms = self._costs()
        self._write(
            {
                "record": "end",
                "request": self._begin["request"],
                "batch": self._begin["batch"],
                "cpu_ms": cpu_ms,
                "wall_ms": wall_ms,
            }
        )

    def items(self, collection: str, items: Iterable[dict]) -> tuple[int, int, int]:
        """One collection's objects, with their three side channels.

        Returns the counts the commit must carry. The channels ride the item
        exactly as the adapter attached them — names is law 1's obligation,
        absent and unobservable are DESIGN 19's two non-value statements, and
        assertions are §13's directed claims — because lifting them back out
        of the facts dict here is how a hardcoded key list once meant no
        committed object carried names at all.
        """
        objects = assertions = unobservable = 0
        for item in items:
            record = {
                "record": "object",
                "collection": collection,
                "name": item["native_id"],
                "facts": item["facts"],
                "at": self._stamp(self._emitted),
            }
            self._emitted += 1
            if item.get("names"):
                record["names"] = item["names"]
            if item.get("absent"):
                record["absent"] = item["absent"]
            self._write(record)
            objects += 1

            # The three members an item cannot supply: record, collection, and
            # the source object's NAME — which is the same native_id the
            # object record was published under, because a relation's key
            # derives from the source object's id and the target's name as
            # published (DESIGN 13). An assertion naming its source any other
            # way keys against an object that does not exist.
            for assertion in item.get("assertions", []):
                self._write(
                    {
                        "record": "relation_assertion",
                        "collection": collection,
                        "name": item["native_id"],
                        "vantage": collection,
                        **assertion,
                    }
                )
                assertions += 1

            for missing in item.get("unobservable", []):
                self._write(
                    {
                        "record": "unobservable",
                        "collection": collection,
                        "name": item["native_id"],
                        **missing,
                    }
                )
                unobservable += 1
        return objects, assertions, unobservable


async def materialise(adapter, collection: str, page: dict | None = None) -> list[dict]:
    """One collection's rows, through whichever verb the adapter actually has.

    Sixteen adapters materialise a whole collection with ``acquire()``, and the
    two reference drivers called it directly. ``logs`` has no ``acquire()`` at
    all, and that is the design rather than an omission: a bounded journal
    query has no "all items" to hand over — the journal is unbounded and the
    adapter's whole job is to bound it — so its only materialising verb is
    ``collect(collection, query, limit, cursor)``.

    Driving ``collect()`` there is a second DISPATCH SHAPE, not an
    inconsistency, and the distinction is worth stating because it looks like
    one. The shim asks each adapter the question that adapter can answer:
    calling ``acquire()`` on ``logs`` is an AttributeError, and driving a page
    against ``storage`` would put THIS module's choice of limit and cursor
    between the reference and the corpus — the pagination would become part of
    the captured answer, and every ported collector would have to reproduce a
    harness decision rather than a reading of the machine. Which shape a
    collector takes is therefore declared in the seam table beside it, not
    inferred here from whether an attribute happens to exist: an adapter that
    lost ``acquire()`` to a refactor would otherwise be silently re-driven as a
    page and the corpus would move under it.

    It lives here, in the module both drivers share, for the reason this file
    exists at all — a second copy would drift, and the first thing it would
    drift on is which rows a collection contains.
    """
    if page is None:
        return await adapter.acquire(collection)
    result = await adapter.collect(
        collection, dict(page["query"]), page["limit"], page["cursor"]
    )
    # An error envelope carries items=[] and status="error", and committing
    # that would be authoritative-empty (DESIGN 19) — a batch that retires
    # every object over a request THIS side composed. The page driven here has
    # no filters and no cursor, so a refusal means the seam and the adapter
    # disagree about what is askable, which is "I could not run".
    if result.get("status") != "ok":
        raise RuntimeError(
            f"{collection}: the adapter refused the filterless page this shim "
            f"drives ({result.get('errors')}), and an error envelope's empty "
            "item list must never be committed as an authoritative emptiness"
        )
    return result["items"]


def parse_generations(tokens: list[str], fail: Callable[[str], None]) -> dict[str, int]:
    """collect <collection>:<generation>… (DESIGN 18).

    The generation is everything after the LAST colon, because names in this
    product legitimately contain colons. The collator issued it and this side
    only echoes it — in begin's map and on the collection's commit — which is
    the whole of the newest-wins mechanism (DESIGN 19). A token without an
    integer generation is a malformed request: exit 2 is "I could not run",
    and a request this side cannot parse genuinely was not.
    """
    if not tokens:
        fail("empty collect: the request line is 'collect <collection>:<generation>…'")
    generations: dict[str, int] = {}
    for token in tokens:
        name, _, generation = token.rpartition(":")
        if not name or not generation.isdigit():
            fail(f"malformed token {token!r}: expected <collection>:<generation>")
        generations[name] = int(generation)
    return generations
