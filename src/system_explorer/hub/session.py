"""One collator connection, in the order DESIGN 06 fixes.

    declarations → checkpoint → the ordinary stream

Nothing about a hub that only receives makes it obvious when it knows
enough to answer, so the order is not a convention: the declarations
carry the fact axes without which the hub can render nothing and serve no
MCP tool, the checkpoint carries the state and says when it is complete,
and only then does the stream mean anything.

**The phase is what discriminates the records, not a member on them.**
Three schemas share one connection and two of them spell their record
kind the same way; asking "which phase is this connection in" is the
question the protocol actually answers, and sniffing shapes would be a
second, weaker copy of the ordering rule.

**A declaration arrives framed, and its digest is a JOIN KEY at this hop
rather than an integrity check.** The collator computed it over the exact
bytes the collector emitted and already refused the batch if
`begin.declaration` disagreed — integrity belongs to that hop, where the
bytes are. What the hub needs is a key to join a manifest entry to the
axes it names, so the framing carries the document parsed and the digest
beside it, and re-hashing here would commit to a re-serialisation the
collector never made.

**On a reversed connection an unknown declaration hash cannot be
fetched.** The contract's own note says an unknown one is fetched rather
than guessed, which was written before the connection reversed: a hub has
no way to reach a collator, by construction, and that is the property the
reversal exists to provide. The declarations travel first precisely so
nothing needs fetching, so a manifest naming a hash the hub does not hold
is a collator that skipped a step — refused, with the hash named, rather
than promoted against axes nobody has. Recorded in appendix C.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

from .checkpoint import CheckpointRefused, Estate, HostSnapshot, Receiver


class Phase(str, Enum):
    DECLARATIONS = "declarations"
    CHECKPOINT = "checkpoint"
    STREAM = "stream"


class SessionRefused(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass
class Declarations:
    """Every declaration the hub holds, by hash and by collection.

    Keyed by hash because that is what a manifest names, and indexed by
    collection because that is what a roll-up asks. A collection is
    declared by exactly one collector on one host; two hosts may declare
    the same collection name from different collectors, and the axes are
    per (host, collection) for that reason — merging them would let one
    host's declaration vouch for another's facts.
    """

    _by_hash: dict[str, Mapping[str, Any]] = field(default_factory=dict, init=False)
    _facts: dict[tuple[str, str], frozenset[str]] = field(default_factory=dict, init=False)

    def add(self, host: str, document: Mapping[str, Any], digest: str) -> None:
        if document.get("schema") != "se.declaration/1":
            raise SessionRefused(
                "not-a-declaration",
                f"a record in the declaration phase carries schema "
                f"{document.get('schema')!r}",
            )
        self._by_hash[digest] = document
        for collection in document.get("collections") or ():
            self._facts[(host, collection["name"])] = frozenset(
                (collection.get("facts") or {}).keys()
            )

    def holds(self, digest: str) -> bool:
        return digest in self._by_hash

    def facts(self, host: str, collection: str) -> frozenset[str] | None:
        """The declared fact names, or None when the hub holds no
        declaration for this pair. None is not an empty set: one means
        "nothing is declared here" and the other means "nobody has said",
        and a roll-up must treat them differently."""
        return self._facts.get((host, collection))

    def declares(self, host: str, collection: str, fact: str) -> bool:
        declared = self.facts(host, collection)
        return declared is not None and fact in declared


@dataclass
class Session:
    """Drives one connection. `ingest` returns a HostSnapshot exactly once,
    when the checkpoint's terminal completes it, and None otherwise."""

    estate: Estate
    declarations: Declarations
    host: str | None = None
    phase: Phase = Phase.DECLARATIONS
    _receiver: Receiver = field(default_factory=Receiver, init=False)
    _pending: list[tuple[Mapping[str, Any], str]] = field(default_factory=list, init=False)

    def ingest(self, record: Mapping[str, Any], digest: str | None = None) -> HostSnapshot | None:
        if self.phase is Phase.DECLARATIONS:
            if record.get("record") == "manifest":
                return self._open_checkpoint(record)
            document, digest = self._unframe(record, digest)
            # Held rather than indexed: a declaration belongs to a host and
            # the host's name is not known until the manifest names it. The
            # transport's idea of who dialled is not a reading of the
            # machine, and a NAT-mode dial makes it wrong.
            self._pending.append((document, digest))
            return None
        if self.phase is Phase.CHECKPOINT:
            snapshot = self._receiver.ingest(dict(record))
            if snapshot is None:
                return None
            self.phase = Phase.STREAM
            self.estate.promote(snapshot)
            return snapshot
        raise SessionRefused(
            "stream-unimplemented",
            "the ordinary stream after a checkpoint is not built yet",
        )

    @staticmethod
    def _unframe(
        record: Mapping[str, Any], digest: str | None
    ) -> tuple[Mapping[str, Any], str]:
        """Take the declaration and its digest out of the session framing.

        Two shapes are accepted and they are one shape: a framed record
        from the wire, and a bare document with its digest passed beside
        it, which is how a caller drives a session without a socket. The
        second exists for tests and for anything that already holds the
        pair — never as a second wire format.
        """
        if record.get("record") == "declaration":
            document = record.get("document")
            framed = record.get("digest")
            if not isinstance(document, Mapping) or not framed:
                raise SessionRefused(
                    "declaration-unframed",
                    "a framed declaration carries `document` and `digest`",
                )
            return document, framed
        kind = record.get("record")
        if kind in {"collection_state", "terminal"}:
            # A checkpoint record with no manifest ahead of it. Named for
            # what it is rather than for the member it happens to lack:
            # "unhashed" would send somebody looking at the collator's
            # hashing when the fault is the order.
            raise SessionRefused(
                "out-of-order",
                f"a {kind} record arrived in the declaration phase; the order is "
                "declarations, then a checkpoint, and a checkpoint opens with its "
                "manifest",
            )
        if digest is None:
            raise SessionRefused(
                "declaration-unhashed",
                "a declaration arrives with the digest the collator computed over the "
                "collector's own bytes; computing one here would commit to a "
                "re-serialisation the collector never made",
            )
        return record, digest

    def _open_checkpoint(self, manifest: Mapping[str, Any]) -> None:
        host = manifest.get("host")
        if not host:
            raise SessionRefused("manifest-hostless", "a manifest names its own scope")
        if not self._pending:
            raise SessionRefused(
                "no-declarations",
                "a checkpoint arrived before any declaration; the hub can render "
                "nothing and serve no tool without the fact axes",
            )
        for document, digest in self._pending:
            self.declarations.add(host, document, digest)
        self._pending.clear()
        unknown = [
            digest for digest in manifest.get("declarations") or ()
            if not self.declarations.holds(digest)
        ]
        if unknown:
            raise SessionRefused(
                "declaration-unknown",
                f"the manifest names {', '.join(sorted(unknown))}, which this hub does "
                "not hold and cannot fetch — a hub has no way to reach a collator",
            )
        self.host = host
        self.phase = Phase.CHECKPOINT
        self.estate.connected(host)
        result = self._receiver.ingest(dict(manifest))
        return result

    def disconnected(self) -> None:
        if self.host is not None:
            self.estate.disconnected(self.host)
