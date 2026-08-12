"""Findings registry: lifecycle metadata over the estate's findings (SPEC
section 6.3), and the pure assembly behind /hub/findings.

This is the hub's first persistent state beyond view documents, and the
table behind its first write route. The four section 6.3 decisions are
load-bearing in the code, not just the prose:

1. **Writes are a grant.** Nothing here checks it — the server registers
   the transition route only when the deployment enables it, so a registry
   with writes off is not reachable to mutate at all.
2. **Transitions are appended, attributed, reversible.** The transitions
   table has no UPDATE and no DELETE short of retention; un-acknowledging
   is another row; `by` is mandatory free text, stored as given.
3. **Acknowledgement removes nothing.** assemble() keeps acknowledged
   findings in the list, marked — there is no code path that drops one.
4. **Resolution is observed, not declared.** Nothing writes a "resolved"
   state. A finding is current when this sweep derived it, and stops being
   current only when an agent that COULD look stopped deriving it. The
   `unobserved` list every se.findings/1 envelope carries is honoured by
   freezing: a collection that could not be evaluated leaves its findings'
   lifecycle untouched and their `current` unstated, because "the host
   stopped saying it" and "the host could not look" are different
   statements and only the first is resolution.

Store idioms are agent/history.py's: stdlib-only module, per-method
connections (sqlite3 connections stay on their thread; the server wraps
calls in anyio.to_thread), WAL, fixed-width UTC ISO so lexicographic
comparison is chronological. The registry is metadata in section 6.1's
sense — deleting it loses first_seen and the acknowledgement record, never
an observation and never a truth about a host.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA_HUB_FINDINGS = "se.hub-findings/1"
SCHEMA_TRANSITIONS = "se.hub-transitions/1"
# The agent surface this registry folds (agent/findings.py declares it too;
# restated here so the hub package needs no agent import).
SCHEMA_FINDINGS_AGENT = "se.findings/1"
ACKNOWLEDGED = "acknowledged"
UNACKNOWLEDGED = "unacknowledged"
TRANSITIONS = (ACKNOWLEDGED, UNACKNOWLEDGED)


def envelope_problem(body: object) -> str | None:
    """The first structural reason a /v1/findings answer cannot be folded,
    or None (views.view_problem's stance). Checks exactly the members
    record_sweep and assemble dereference, because the hub folds these
    envelopes rather than proxying them: one agent answering HTTP 200 with
    garbage must cost that agent's sweep — the same "could not be swept"
    entry a dark host gets — never a 500 on the estate's roll-up
    (adversarial review, 2026-08-12, found by three reviewers
    independently)."""
    if not isinstance(body, dict):
        return "not a JSON object"
    if body.get("schema") != SCHEMA_FINDINGS_AGENT:
        return f"schema is {body.get('schema')!r}, not {SCHEMA_FINDINGS_AGENT}"
    if body.get("status") not in ("ok", "partial"):
        return "status is not ok|partial"
    host = body.get("host")
    if host is not None and not isinstance(host, dict):
        return "host is not an object"
    errors = body.get("errors")
    if errors is not None and (not isinstance(errors, list) or any(
            not isinstance(entry, str) for entry in errors)):
        return "errors is not a list of strings"
    findings = body.get("findings")
    if not isinstance(findings, list):
        return "findings is not a list"
    for index, record in enumerate(findings):
        if not isinstance(record, dict):
            return f"findings.{index}: not an object"
        obj, opinion = record.get("object"), record.get("opinion")
        if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
            return f"findings.{index}: object.id missing"
        if not isinstance(opinion, dict) or not isinstance(opinion.get("key"), str):
            return f"findings.{index}: opinion.key missing"
        for member in ("subsystem", "collection"):
            if not isinstance(record.get(member), str) or not record[member]:
                return f"findings.{index}: missing {member}"
    unobserved = body.get("unobserved")
    if not isinstance(unobserved, list):
        return "unobserved is not a list"
    for index, item in enumerate(unobserved):
        if not isinstance(item, dict) \
                or not isinstance(item.get("subsystem"), str) \
                or not isinstance(item.get("collection"), str):
            return f"unobserved.{index}: missing subsystem/collection"
    return None

_ISO = "%Y-%m-%dT%H:%M:%SZ"
_KEY_COLUMNS = "machine_id, container, app, object_id, opinion_key"

# The rule-15 tuple, with absent locator members stored as "" because SQL
# NULLs never equal each other and the composite must be a usable primary
# key. The JSON surfaces keep absence as absence; only the store flattens.
Key = tuple[str, str, str, str, str]


def identity_key(machine_id: str, object_id: str, opinion_key: str,
                 container: str | None = None, app: str | None = None) -> Key:
    return (machine_id, container or "", app or "", object_id, opinion_key)


class FindingsRegistry:
    def __init__(self, db_path: Path | str) -> None:
        self.db_path = str(db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS findings ("
            " machine_id TEXT NOT NULL, container TEXT NOT NULL,"
            " app TEXT NOT NULL, object_id TEXT NOT NULL,"
            " opinion_key TEXT NOT NULL,"
            " agent TEXT NOT NULL, subsystem TEXT NOT NULL,"
            " collection TEXT NOT NULL,"
            " first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,"
            " record TEXT NOT NULL, host TEXT NOT NULL,"
            f" PRIMARY KEY ({_KEY_COLUMNS}))")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS transitions ("
            " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
            " machine_id TEXT NOT NULL, container TEXT NOT NULL,"
            " app TEXT NOT NULL, object_id TEXT NOT NULL,"
            " opinion_key TEXT NOT NULL,"
            " transition TEXT NOT NULL, by_whom TEXT NOT NULL,"
            " note TEXT, at TEXT NOT NULL)")
        return conn

    def record_sweep(self, now: str, sweeps: list[dict],
                     retention_days: float) -> None:
        """Fold one estate sweep in: new findings open with first_seen=now,
        recurring ones advance last_seen and refresh their stored record
        (the message text tracks the condition; the identity is the key).
        Reappearance within retention is therefore the same finding
        recurring, section 6.3's rule. The hub's clock stamps lifecycle —
        one clock for the estate, rather than N host clocks compared.

        Retention prunes findings whose last_seen fell behind the horizon —
        but ONLY where this sweep could have seen them: a row ages out when
        its locator was swept and its collection was evaluable, never when
        it is frozen (adversarial review, 2026-08-12: an adapter broken for
        retention_days used to erase the finding AND its acknowledgement
        history without any observation of absence — "could not look"
        becoming total disappearance, with the record's decision-2
        append-only promise deleted alongside it). Transitions go first so
        an acknowledgement cannot outlive the finding it attached to."""
        cutoff = (datetime.strptime(now, _ISO).replace(tzinfo=timezone.utc)
                  - timedelta(days=retention_days)).strftime(_ISO)
        swept_locators, unobserved = _sweep_visibility(sweeps)
        with closing(self._connect()) as conn, conn:
            for sweep in sweeps:
                envelope = sweep["envelope"]
                host = envelope.get("host") or {}
                machine_id = host.get("machine_id")
                if not machine_id:
                    continue
                for record in envelope.get("findings") or []:
                    key = identity_key(machine_id, record["object"]["id"],
                                       record["opinion"]["key"],
                                       host.get("container"), host.get("app"))
                    conn.execute(
                        f"INSERT INTO findings ({_KEY_COLUMNS}, agent,"
                        " subsystem, collection, first_seen, last_seen,"
                        " record, host)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                        f" ON CONFLICT ({_KEY_COLUMNS}) DO UPDATE SET"
                        " last_seen = excluded.last_seen,"
                        " agent = excluded.agent,"
                        " subsystem = excluded.subsystem,"
                        " collection = excluded.collection,"
                        " record = excluded.record, host = excluded.host",
                        (*key, sweep["agent"], record["subsystem"],
                         record["collection"], now, now,
                         json.dumps(record), json.dumps(host)))
            stale = conn.execute(
                f"SELECT {_KEY_COLUMNS}, subsystem, collection FROM findings"
                " WHERE last_seen < ?", (cutoff,)).fetchall()
            for row in stale:
                key, place = tuple(row[0:5]), (row[5], row[6])
                if key[0:3] not in swept_locators or \
                        place in unobserved.get(key[0:3], set()):
                    continue  # frozen: absence was not observable this sweep
                conn.execute(
                    "DELETE FROM transitions WHERE machine_id = ? AND"
                    " container = ? AND app = ? AND object_id = ? AND"
                    " opinion_key = ?", key)
                conn.execute(
                    "DELETE FROM findings WHERE machine_id = ? AND"
                    " container = ? AND app = ? AND object_id = ? AND"
                    " opinion_key = ?", key)

    def rows(self) -> list[dict]:
        with closing(self._connect()) as conn:
            fetched = conn.execute(
                f"SELECT {_KEY_COLUMNS}, agent, first_seen, last_seen,"
                " record, host FROM findings").fetchall()
        return [{
            "key": tuple(row[0:5]),
            "agent": row[5],
            "first_seen": row[6],
            "last_seen": row[7],
            "record": json.loads(row[8]),
            "host": json.loads(row[9]),
        } for row in fetched]

    def transitions(self) -> dict[Key, list[dict]]:
        """Every finding's transition history, appended order preserved."""
        with closing(self._connect()) as conn:
            fetched = conn.execute(
                f"SELECT {_KEY_COLUMNS}, transition, by_whom, note, at"
                " FROM transitions ORDER BY seq").fetchall()
        out: dict[Key, list[dict]] = {}
        for row in fetched:
            entry = {"transition": row[5], "by": row[6], "at": row[8]}
            if row[7]:
                entry["note"] = row[7]
            out.setdefault(tuple(row[0:5]), []).append(entry)
        return out

    def append_transition(self, now: str, key: Key, transition: str,
                          by: str, note: str | None) -> list[dict] | None:
        """Append one attributed transition; None when no such finding
        exists in the registry (transitions attach to findings the estate
        has actually derived, never to speculative identities). The
        existence check and the append are ONE statement, so a concurrent
        retention prune between them cannot leave an orphaned transition
        waiting to pre-acknowledge the identity's next recurrence."""
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute(
                f"INSERT INTO transitions ({_KEY_COLUMNS}, transition,"
                " by_whom, note, at)"
                " SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?"
                " WHERE EXISTS (SELECT 1 FROM findings WHERE"
                " machine_id = ? AND container = ? AND app = ? AND"
                " object_id = ? AND opinion_key = ?)",
                (*key, transition, by, note, now, *key))
            if cursor.rowcount == 0:
                return None
        return self.transitions().get(key, [])


# ── pure assembly ─────────────────────────────────────────────────────────

_LEVEL_RANK = {"critical": 0, "warn": 1}

Locator = tuple[str, str, str]


def _sweep_visibility(sweeps: list[dict]) -> tuple[set, dict]:
    """(swept locators, unobserved (subsystem, collection) pairs per
    locator) from the envelopes in hand. Keyed on the rule-15 locator —
    (machine_id, container, app), the identity key's first three members —
    and never on the config-level agent NAME, because renaming or
    repointing an agent entry must not change which findings count as
    lookable-at (adversarial review, 2026-08-12: name-keyed visibility let
    a repointed entry resolve one host's findings on the strength of a
    different host's sweep)."""
    swept: set[Locator] = set()
    unobserved: dict[Locator, set] = {}
    for sweep in sweeps:
        envelope = sweep.get("envelope")
        if not envelope:
            continue
        host = envelope.get("host") or {}
        machine_id = host.get("machine_id")
        if not machine_id:
            continue
        locator: Locator = (machine_id, host.get("container") or "",
                            host.get("app") or "")
        swept.add(locator)
        unobserved[locator] = {
            (item["subsystem"], item["collection"])
            for item in envelope.get("unobserved") or []}
    return swept, unobserved


def _order(entry: dict) -> tuple:
    # Attention first: current findings, then frozen ones (possibly still
    # true, nobody can currently say), then resolved history. Critical
    # before warn within each band; the rest is a stable address.
    band = 0 if entry.get("current") else (1 if not entry["observable"] else 2)
    return (band, _LEVEL_RANK.get(entry["opinion"]["level"], 9),
            entry["agent"], entry["subsystem"], entry["collection"],
            entry["object"]["id"], entry["opinion"]["key"])


def assemble(now: str, site: str | None, writes_enabled: bool,
             sweeps: list[dict], registry_rows: list[dict] | None = None,
             transitions: dict[Key, list[dict]] | None = None,
             registry_note: str | None = None) -> dict:
    """One se.hub-findings/1 envelope from a sweep and the registry.

    `sweeps` is one entry per configured agent: {"agent", "envelope"} when
    its /v1/findings answered, {"agent", "error"} when it could not be
    swept — a dark host and an agent predating the findings surface both
    land there, distinguished by the error text, and both freeze rather
    than resolve their registry rows. Pure over its inputs so conformance
    exercises every lifecycle shape with a pinned clock and no HTTP.
    """
    hosts: dict[str, dict] = {}
    seen: dict[Key, dict] = {}
    for sweep in sweeps:
        name = sweep["agent"]
        envelope = sweep.get("envelope")
        if not envelope:
            hosts[name] = {"swept": False,
                           "error": sweep.get("error") or "unswept"}
            continue
        sweep_entry: dict = {"swept": True}
        # Only the members the envelope actually carried: a null host or
        # status would fail the hub's own published schema, and omission is
        # the honest shape for an envelope that named neither.
        for member in ("host", "status", "unobserved", "errors"):
            if envelope.get(member):
                sweep_entry[member] = envelope[member]
        hosts[name] = sweep_entry
        host = envelope.get("host") or {}
        machine_id = host.get("machine_id")
        if not machine_id:
            continue
        for record in envelope.get("findings") or []:
            key = identity_key(machine_id, record["object"]["id"],
                               record["opinion"]["key"],
                               host.get("container"), host.get("app"))
            seen[key] = {"agent": name, "record": record, "host": host}
    swept_locators, unobserved_by_locator = _sweep_visibility(sweeps)

    transitions = transitions or {}
    entries: list[dict] = []
    covered: set[Key] = set()
    for row in registry_rows or []:
        key = row["key"]
        covered.add(key)
        live = seen.get(key)
        source = live or row
        entry = {"agent": source["agent"], "host": source["host"],
                 **source["record"]}
        if live:
            entry["current"] = True
            entry["observable"] = True
        elif key[0:3] not in swept_locators:
            # This host (this locator, not this config name) could not be
            # swept: nobody can say whether the condition holds, so
            # `current` is honestly absent (rule 7).
            entry["observable"] = False
        elif (row["record"]["subsystem"], row["record"]["collection"]) \
                in unobserved_by_locator.get(key[0:3], set()):
            entry["observable"] = False
        else:
            # The host looked where this finding lives and no longer
            # derives it — resolution, observed (section 6.3, decision 4).
            entry["observable"] = True
            entry["current"] = False
        entry["first_seen"] = row["first_seen"]
        entry["last_seen"] = row["last_seen"]
        history = transitions.get(key) or []
        entry["acknowledged"] = bool(history) and \
            history[-1]["transition"] == ACKNOWLEDGED
        if history:
            entry["transitions"] = history
        entries.append(entry)
    for key, live in seen.items():
        # Live findings the registry does not hold — the registry-disabled
        # deployment, honestly lifecycle-less rather than absent.
        if key not in covered:
            entries.append({"agent": live["agent"], "host": live["host"],
                            **live["record"],
                            "current": True, "observable": True})
    entries.sort(key=_order)
    out: dict = {
        "schema": SCHEMA_HUB_FINDINGS,
        "site": site,
        "observed_at": now,
        "writes_enabled": writes_enabled,
        "hosts": hosts,
        "findings": entries,
    }
    if registry_note:
        out["errors"] = [registry_note]
    return out
