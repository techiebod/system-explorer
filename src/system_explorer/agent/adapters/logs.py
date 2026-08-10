"""logs subsystem: bounded journal queries via journalctl -o json.

Structured output (SPEC section 2 rule 8, tier: structured CLI). Bounded
only — no follow mode (SPEC section 12). Recognised filters: unit, priority,
since. The page cursor is the journal's own cursor, so pagination is native.

Pages run newest-first and page BACKWARD through history: journalctl -r
starts at the newest entry (or at --cursor when given, which repeats the
cursor entry itself — dropped here) and walks older. The previous
--after-cursor scheme asked for entries newer than the newest already
shown, so "next page" was empty; caught by an external review.

journalctl rejects --since combined with --cursor (exit 1), so time bounds
go on the first page only — the cursor already encodes where to resume.
Passing both silently truncated bounded queries at one page (a "24h" query
covered 15.5h; audit 2026-08-10).
"""

from __future__ import annotations

import json
import subprocess

import anyio

from .. import envelope as env
from ..rules import worst_level
from ..rules.logs import journal_opinions

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000

FACT_FIELDS = {
    "MESSAGE": "Message",
    "PRIORITY": "Priority",
    "SYSLOG_IDENTIFIER": "SyslogIdentifier",
    "_SYSTEMD_UNIT": "SystemdUnit",
    "_COMM": "Command",
    "_PID": "PID",
}

REFERENCE = ["journalctl -o json -n 100", "journalctl -u <unit> --since -1h"]


def _run_journalctl(args: list[str]) -> list[dict]:
    proc = subprocess.run(
        ["journalctl", "-o", "json", "--no-pager", "-q", *args],
        capture_output=True, text=True, timeout=15, check=True,
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def _entry_facts(record: dict) -> dict:
    facts = {label: record.get(field) for field, label in FACT_FIELDS.items() if field in record}
    ts = record.get("__REALTIME_TIMESTAMP")
    if ts is not None:
        facts["Timestamp"] = env.usec_to_iso(int(ts))
    if isinstance(facts.get("Priority"), str):
        facts["Priority"] = int(facts["Priority"])
    return facts


def _entry_item(record: dict) -> dict:
    cursor = record["__CURSOR"]
    facts = _entry_facts(record)
    # Same evaluator as get_object (agent/rules/logs.py) — a red row and its
    # opened observation cannot disagree. Entries are neutral, never "ok".
    level = worst_level(journal_opinions(facts), healthy="info")
    return env.item_summary(f"entry:{cursor}", "entry", cursor, facts, worst_opinion_level=level)


class Adapter:
    subsystem = "logs"

    def collections(self) -> list[str]:
        return ["journal"]

    async def capability(self) -> dict:
        return {"available": True, "collections": self.collections()}

    def _check(self, collection: str) -> None:
        if collection != "journal":
            raise env.UnknownCollection(collection)

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        self._check(collection)
        applied = min(limit or DEFAULT_LIMIT, MAX_LIMIT)

        args: list[str] = []
        native = {k: v for k, v in query.items() if k in ("unit", "priority", "since")}
        if "unit" in native:
            args += ["-u", native["unit"]]
        if "priority" in native:
            args += ["-p", native["priority"]]
        if "since" in native and not cursor:
            # First page only: journalctl rejects --since with --cursor
            # (see file header); the cursor encodes where to resume.
            args += ["--since", native["since"]]
        args += ["-r"]
        if cursor:
            # -r --cursor starts AT the cursor and walks older; the first
            # record repeats the entry the previous page ended on.
            args += ["--cursor", cursor, "-n", str(applied + 1)]
        else:
            args += ["-n", str(applied)]

        records = await anyio.to_thread.run_sync(_run_journalctl, args)
        if cursor and records and records[0].get("__CURSOR") == cursor:
            records = records[1:]
        full_page = len(records) == applied
        items = [_entry_item(r) for r in records]
        leftover = {k: v for k, v in query.items() if k not in native}
        if leftover:
            items = env.apply_fact_filters(items, leftover)

        next_cursor = records[-1]["__CURSOR"] if full_page and records else None
        return env.collection_page(
            self.subsystem, collection,
            env.source("journal-json", "systemd-journal", REFERENCE, method="journalctl -o json"),
            items, applied, next_cursor, requested_limit=limit, filters=query or None,
        )

    async def _record(self, object_id: str) -> dict:
        if not object_id.startswith("entry:"):
            raise env.UnknownObject(object_id)
        cursor = object_id.split(":", 1)[1]
        records = await anyio.to_thread.run_sync(
            _run_journalctl, ["--cursor", cursor, "-n", "1"])
        if not records:
            raise env.UnknownObject(object_id)
        return records[0]

    async def get_object(self, collection: str, object_id: str) -> dict:
        self._check(collection)
        record = await self._record(object_id)
        facts = _entry_facts(record)
        relationships = []
        if record.get("_SYSTEMD_UNIT"):
            relationships.append(env.rel("member-of", "out",
                                         f"unit:{record['_SYSTEMD_UNIT']}", subsystem="units"))
        return env.observation(
            self.subsystem, env.obj_ref(object_id, "entry", record["__CURSOR"]),
            env.source("journal-json", "systemd-journal", REFERENCE, method="journalctl -o json --cursor"),
            facts, opinions=journal_opinions(facts), relationships=relationships,
            evidence_ref=f"/v1/logs/journal/{object_id}/evidence",
        )

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        self._check(collection)
        record = await self._record(object_id)
        return {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": "systemd-journal",
            "method": "journalctl -o json --cursor",
            "payload": record,
        }
