"""Snapshot history: the store and the pure diff behind /v1/changes.

SPEC section 10: history is stored snapshots plus diff-on-read (section 2,
rule 11), not an event stream. The agent's in-process snapshot task writes
materialised collection item summaries to SQLite under $STATE_DIRECTORY;
"what changed" is computed on request by diffing the newest stored snapshot
at-or-before `since` against a live collection of the same shape.

Module-level imports stay stdlib-only so the conformance suite exercises
the diff functions directly on any platform, the way it exercises
agent/rules/. Async wrapping is the caller's job (main.py runs every store
method through anyio.to_thread): sqlite3 is synchronous and its connections
must stay on the thread that made them, which is also why each method opens
and closes its own connection instead of holding one.
"""

from __future__ import annotations

import json
import re
import sqlite3
import zlib
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Same rendering as envelope.utc_now(): fixed-width UTC ISO with Z, so
# lexicographic comparison in SQL is chronological comparison.
_ISO = "%Y-%m-%dT%H:%M:%SZ"

_RELATIVE = re.compile(r"^-(\d+)([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _maybe_expand(items) -> str:
    """A stored items column, whichever era wrote it.

    Rows written since compression landed are zlib BLOBs (first byte 0x78,
    the deflate header every zlib level emits); rows before it are plain
    JSON text. Sniffing beats a schema migration: both shapes stay readable
    forever, and an over-eager migration of a 94 MB store on a fanless host
    is exactly the work this change exists to avoid.
    """
    if isinstance(items, bytes):
        return zlib.decompress(items).decode()
    return items


def read_boot_id() -> str:
    """The kernel's boot UUID, dashes stripped to match the system adapter's
    rendering. Deliberately our own read rather than the adapter's: history
    must not depend on one subsystem's availability to mark boot boundaries.
    """
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    except OSError:
        return "unknown"


def parse_since(value: str, now: datetime | None = None) -> str:
    """A since= parameter — UTC ISO Z out; ValueError on nonsense in.

    Accepts ISO 8601 (naive timestamps are taken as UTC) or a relative
    offset like -24h (-N followed by s/m/h/d, always ago, never ahead).
    `now` is injectable for tests only.
    """
    value = value.strip()
    match = _RELATIVE.match(value)
    if match:
        delta = timedelta(seconds=int(match.group(1)) * _UNIT_SECONDS[match.group(2)])
        return ((now or datetime.now(timezone.utc)) - delta).strftime(_ISO)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"since must be ISO 8601 or relative like -24h, got {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime(_ISO)


def iso_age_seconds(timestamp: str, now: datetime | None = None) -> float:
    """Seconds elapsed since a stored UTC ISO Z timestamp."""
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return ((now or datetime.now(timezone.utc)) - parsed).total_seconds()


def changed_paths(before: Any, after: Any) -> list[str]:
    """Dotted paths at which two JSON-shaped values differ.

    The path language is the evidence-path language (SPEC section 5;
    conformance resolve_fact_path): dict keys joined with dots, list
    indices as digits — so a change entry cites facts the way an opinion
    does. Semantics, kept simple and honest:

    - dicts recurse per key; a key present on only one side differs at
      that key's path;
    - lists whose members are all dicts compare positionally (vdev trees,
      SMART attribute tables) — an insertion shifts every later member
      and reports them all, which is simple over clever;
    - any other list is one value: order matters, and a difference is
      reported at the list's own path;
    - a type change is a difference at the node's path.
    """
    out: list[str] = []
    _walk(before, after, "", out)
    return out


def _walk(before: Any, after: Any, prefix: str, out: list[str]) -> None:
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(before.keys() | after.keys()):
            path = f"{prefix}.{key}" if prefix else key
            if key not in before or key not in after:
                out.append(path)
            else:
                _walk(before[key], after[key], path, out)
    elif (isinstance(before, list) and isinstance(after, list)
          and _all_dicts(before) and _all_dicts(after)):
        for index in range(max(len(before), len(after))):
            path = f"{prefix}.{index}" if prefix else str(index)
            if index >= len(before) or index >= len(after):
                out.append(path)
            else:
                _walk(before[index], after[index], path, out)
    elif before != after:
        out.append(prefix)


def _all_dicts(values: list) -> bool:
    return all(isinstance(value, dict) for value in values)


def diff_items(before: list[dict], after: list[dict]) -> dict:
    """Diff two materialised collections of item summaries by object id.

    Object IDs are stable for unchanged objects (SPEC section 11, rule 7),
    so identity carries the diff: ids only in `after` are added, ids only
    in `before` are removed, and objects present in both are compared with
    changed_paths(). Returns {} when nothing changed; empty sections are
    omitted, matching changes.schema.json.
    """
    before_by_id = {item["id"]: item for item in before}
    after_by_id = {item["id"]: item for item in after}
    added = sorted(after_by_id.keys() - before_by_id.keys())
    removed = sorted(before_by_id.keys() - after_by_id.keys())
    changed = []
    for object_id in sorted(before_by_id.keys() & after_by_id.keys()):
        paths = changed_paths(before_by_id[object_id], after_by_id[object_id])
        if paths:
            changed.append({"id": object_id, "paths": paths})
    out: dict = {}
    if added:
        out["added"] = added
    if removed:
        out["removed"] = removed
    if changed:
        out["changed"] = changed
    return out


class HistoryStore:
    """The snapshot store: one SQLite file, one table, one row per
    (snapshot_id, subsystem, collection) holding that collection's item
    summaries (all pages) as JSON. All methods are synchronous; the HTTP
    layer wraps them in anyio.to_thread.
    """

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        # WAL lets /v1/changes read a baseline while the snapshot task writes.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS snapshots ("
            " snapshot_id INTEGER NOT NULL,"
            " subsystem TEXT NOT NULL,"
            " collection TEXT NOT NULL,"
            " taken_at TEXT NOT NULL,"
            " boot_id TEXT NOT NULL,"
            " items TEXT NOT NULL,"
            " PRIMARY KEY (snapshot_id, subsystem, collection))"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS snapshots_taken_at ON snapshots (taken_at)")
        return conn

    def newest_snapshot_at(self) -> str | None:
        """taken_at of the most recent snapshot — the startup staleness check."""
        with closing(self._connect()) as conn:
            return conn.execute("SELECT MAX(taken_at) FROM snapshots").fetchone()[0]

    def write_snapshot(self, taken_at: str, boot_id: str,
                       data: dict[str, dict[str, list[dict]]],
                       retention_days: float) -> None:
        """One snapshot in, expired snapshots out, one transaction — a crash
        mid-write never leaves a half-snapshot as somebody's baseline.
        Retention rides every write (SPEC section 10) so pruning needs no
        second schedule. The snapshot being written is exempt from its own
        prune: an over-tight retention setting must degrade history to
        latest-only, never to nothing."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).strftime(_ISO)
        with closing(self._connect()) as conn, conn:
            snapshot_id = conn.execute(
                "SELECT COALESCE(MAX(snapshot_id), 0) + 1 FROM snapshots").fetchone()[0]
            # Compressed at rest: a snapshot is the same fact names and mostly
            # the same values 96 times a day, which is what zlib eats — the
            # store had reached 94 MB in three days on one host (~30 MB/day,
            # projecting ~900 MB at the 30-day retention default), acceptable
            # on a NAS and not on a fanless NUC. Reads sniff the zlib magic,
            # so rows written before this stay readable and no migration runs.
            conn.executemany(
                "INSERT INTO snapshots VALUES (?, ?, ?, ?, ?, ?)",
                [(snapshot_id, subsystem, collection, taken_at, boot_id,
                  zlib.compress(json.dumps(items, separators=(",", ":")).encode()))
                 for subsystem, collections in data.items()
                 for collection, items in collections.items()])
            conn.execute("DELETE FROM snapshots WHERE taken_at < ? AND snapshot_id != ?",
                         (cutoff, snapshot_id))

    def baseline(self, at_or_before: str | None,
                 subsystem: str | None = None) -> dict | None:
        """The newest snapshot taken at or before the given instant.

        No snapshot that old -> the oldest stored one, flagged fallback=True
        so the envelope can say so. at_or_before None means "everything since
        history began": the oldest snapshot, not a fallback. None when the
        store is empty. Data comes back {subsystem: {collection: items}},
        optionally narrowed to one subsystem.
        """
        with closing(self._connect()) as conn:
            row = None
            fallback = False
            if at_or_before is not None:
                row = conn.execute(
                    "SELECT snapshot_id, taken_at, boot_id FROM snapshots"
                    " WHERE taken_at <= ?"
                    " ORDER BY taken_at DESC, snapshot_id DESC LIMIT 1",
                    (at_or_before,)).fetchone()
                fallback = row is None
            if row is None:
                row = conn.execute(
                    "SELECT snapshot_id, taken_at, boot_id FROM snapshots"
                    " ORDER BY taken_at ASC, snapshot_id ASC LIMIT 1").fetchone()
            if row is None:
                return None
            snapshot_id, taken_at, boot_id = row
            query = "SELECT subsystem, collection, items FROM snapshots WHERE snapshot_id = ?"
            params: tuple = (snapshot_id,)
            if subsystem is not None:
                query += " AND subsystem = ?"
                params += (subsystem,)
            data: dict[str, dict[str, list[dict]]] = {}
            for sub, collection, items in conn.execute(query, params):
                data.setdefault(sub, {})[collection] = json.loads(_maybe_expand(items))
        return {"snapshot_at": taken_at, "boot_id": boot_id,
                "fallback": fallback, "data": data}
