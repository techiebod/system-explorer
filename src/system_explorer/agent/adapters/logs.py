"""logs subsystem: bounded journal queries via journalctl -o json.

Structured output (SPEC section 2 rule 8, tier: structured CLI). Bounded
only — no follow mode (SPEC section 12). Recognised filters: unit, priority,
since. The page cursor is the journal's own cursor, so pagination is native.

Pages run newest-first and page BACKWARD through history: journalctl -r
starts at the newest entry (or at --cursor when given, which repeats the
cursor entry itself — dropped here) and walks older. The previous
--after-cursor scheme asked for entries newer than the newest already
shown, so "next page" was empty; caught by an external review.

journalctl rejects --since combined with --cursor (exit 1), so a time bound
cannot be handed to journalctl on a cursor page. Passing both truncated
bounded queries at one page (a "24h" query covered 15.5h); dropping --since
on later pages instead made the bound vanish while `filters` still advertised
it — measured 2026-08-10, page 2 of a -30m query returned entries 83 minutes
old. Returning too much and mislabelling it is the worse of the two.

So the agent owns the bound: since= is resolved to an absolute floor once,
that floor travels inside our own cursor, and every page drops records below
it. A since= spelling this adapter cannot resolve is an error envelope rather
than a bound silently not applied (SPEC section 6: the server never silently
truncates, the client never infers truncation).
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone

import anyio

from .. import envelope as env
from ..rules import worst_level
from ..rules.logs import journal_opinions

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000

FACT_FIELDS = {
    "MESSAGE": "Message",
    # The emitter's own catalog id for a message TYPE, so entries differing
    # only in interpolated values (a PID, a path) share it. Absent from
    # plenty of emitters, which is why repetition falls back to the text.
    "MESSAGE_ID": "MessageId",
    "PRIORITY": "Priority",
    "SYSLOG_IDENTIFIER": "SyslogIdentifier",
    # Which stream the entry arrived on. A container's stderr is mapped to
    # priority err by the journald log driver, so this is what distinguishes
    # "the application said this is an error" from "the application wrote to
    # stderr" — the single biggest source of misleading err entries.
    "_TRANSPORT": "Transport",
    "_SYSTEMD_UNIT": "SystemdUnit",
    "_SYSTEMD_USER_UNIT": "SystemdUserUnit",
    "CONTAINER_NAME": "Container",
    "_COMM": "Command",
    "_PID": "PID",
}

# Fact name back to journald field, so a fact filter can become a journalctl
# match and be applied AT THE SOURCE. Derived rather than written twice: a new
# entry in FACT_FIELDS becomes filterable for free, and the two cannot drift.
FIELD_BY_FACT = {fact: field for field, fact in FACT_FIELDS.items()}

# since= must be resolvable to an absolute floor HERE, because journalctl
# applies --since only on the first page and a bound that does not survive
# pagination is a lie.
_SINCE_RELATIVE = re.compile(
    r"^-(\d+)(s|sec|secs|second|seconds|m|min|mins|minute|minutes|"
    r"h|hr|hrs|hour|hours|d|day|days|w|week|weeks)$")
_SINCE_UNIT_SECONDS = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
    "w": 604800, "week": 604800, "weeks": 604800,
}

# <floor_usec>@<journal cursor>. Journal cursors are s=..;i=..;b=..;m=..;t=..;x=..
# — only [a-z0-9=;] — so "@" cannot collide, and a bare cursor stays valid.
CURSOR_SEP = "@"

# One message identity this often within a single page is a pattern rather
# than an event. Repetition is the signal priority cannot give.
REPEAT_WINDOW_NOTE = ("RepeatCount/RepeatWindow are scoped to the entries this "
                      "page read, not to the entry: they answer \"is this line "
                      "spam\", which no single record can.")


def _since_floor_usec(expr: str, now: datetime | None = None) -> int | None:
    """Absolute microsecond floor for a since= expression, or None when the
    spelling is one this adapter cannot enforce across pages."""
    now = now or datetime.now(timezone.utc)
    text = expr.strip()
    lowered = text.lower()
    if lowered == "now":
        return int(now.timestamp() * 1_000_000)
    if lowered in ("today", "yesterday"):
        midnight = now.astimezone().replace(hour=0, minute=0, second=0, microsecond=0)
        if lowered == "yesterday":
            midnight -= timedelta(days=1)
        return int(midnight.timestamp() * 1_000_000)
    match = _SINCE_RELATIVE.match(lowered.replace(" ", ""))
    if match:
        seconds = int(match.group(1)) * _SINCE_UNIT_SECONDS[match.group(2)]
        return int((now.timestamp() - seconds) * 1_000_000)
    if lowered.startswith("@"):                      # journalctl's epoch form
        try:
            return int(float(lowered[1:]) * 1_000_000)
        except ValueError:
            return None
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.astimezone()                   # journalctl reads bare stamps as local
    return int(stamp.timestamp() * 1_000_000)


def _decode_cursor(cursor: str | None) -> tuple[int | None, str | None]:
    if not cursor:
        return None, None
    floor, sep, journal_cursor = cursor.partition(CURSOR_SEP)
    if sep and floor.isdigit():
        return int(floor), journal_cursor
    return None, cursor


def _encode_cursor(floor_usec: int | None, journal_cursor: str) -> str:
    return (f"{floor_usec}{CURSOR_SEP}{journal_cursor}"
            if floor_usec is not None else journal_cursor)


def _repeat_identity(record: dict) -> str:
    """What "the same message" means for repetition counting."""
    message_id = record.get("MESSAGE_ID")
    if isinstance(message_id, str) and message_id:
        return f"id:{message_id}"
    message = record.get("MESSAGE")
    return "msg:" + (message if isinstance(message, str) else repr(message))

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


def _entry_item(record: dict, repeats: Counter | None = None,
                window: int | None = None) -> dict:
    cursor = record["__CURSOR"]
    facts = _entry_facts(record)
    if repeats is not None and window is not None:
        # Page-scoped, and the only facts a row carries that get_object cannot
        # — a single entry has no window to count within. SPEC rule 14 permits
        # the divergence and requires it documented: the repeat opinion is
        # info, and info is also the neutral row default, so
        # worst_opinion_level is provably identical on both surfaces.
        facts["RepeatCount"] = repeats[_repeat_identity(record)]
        facts["RepeatWindow"] = window
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

        # Fact filters become journalctl FIELD=value matches, which is the only
        # way they can mean anything here. They used to be applied client-side to
        # the page that had already been fetched — so a filter for one container
        # read the N newest entries in the whole journal, kept the ones that
        # happened to match, and almost always returned NOTHING while reporting
        # status ok and echoing the filter back as though it had been applied.
        # The most useful query an operator has ("show me this container's logs")
        # silently answered empty. Same shape as the generations lie: a confident
        # clean answer to a question that was never asked.
        #
        # journalctl ANDs matches on different fields and ORs them on the same
        # field, which is exactly fact-filter semantics for the single-value case
        # here. Matches also let it SEEK rather than scan.
        pushed = {}
        for key, value in query.items():
            if key in native:
                continue
            field = FIELD_BY_FACT.get(key)
            if field:
                pushed[key] = value
                args.append(f"{field}={value}")
        src = env.source("journal-json", "systemd-journal", REFERENCE,
                         method="journalctl -o json")
        floor_usec, page_cursor = _decode_cursor(cursor)
        notes = ["pages walk newest to oldest; next_cursor resumes at the journal's "
                 "own cursor and carries the since= floor with it"]
        if "since" in native and page_cursor is None:
            floor_usec = _since_floor_usec(native["since"])
            if floor_usec is None:
                # Errors are observations (SPEC section 6): a bound this adapter
                # cannot enforce past page 1 must be refused, not accepted and
                # quietly dropped.
                return env.collection_page(
                    self.subsystem, collection, src, [], applied, None,
                    requested_limit=limit, filters=query or None, status="error",
                    errors=[f"since={native['since']!r} is not a time expression this "
                            "agent can enforce across pages; use a relative offset "
                            "(-24h), a UTC timestamp (2026-08-10T12:00:00Z), "
                            "@<epoch-seconds>, now, today or yesterday"])
            # First page: let journalctl seek, which is far cheaper than reading
            # the whole journal and filtering.
            args += ["--since", native["since"]]
        args += ["-r"]
        if page_cursor:
            # -r --cursor starts AT the cursor and walks older; the first
            # record repeats the entry the previous page ended on.
            args += ["--cursor", page_cursor, "-n", str(applied + 1)]
        else:
            args += ["-n", str(applied)]

        records = await anyio.to_thread.run_sync(_run_journalctl, args)
        if page_cursor and records and records[0].get("__CURSOR") == page_cursor:
            records = records[1:]
        # Judged on what journalctl returned, BEFORE the floor filter: it answers
        # "is there more in the journal", which the filter must not change.
        full_page = len(records) == applied
        exhausted = False
        if floor_usec is not None:
            inside = [r for r in records
                      if int(r.get("__REALTIME_TIMESTAMP", 0)) >= floor_usec]
            exhausted = len(inside) < len(records)
            if exhausted:
                notes.append(
                    f"the since= window ends inside this page: {len(records) - len(inside)} "
                    "older entries were read and not returned, so next_cursor is null")
            records = inside
            notes.append(f"since={native.get('since', '')} resolved to "
                         f"{env.usec_to_iso(floor_usec)} and is enforced on every page")

        # Counted after the floor filter, so the window is what the page kept.
        repeats = Counter(_repeat_identity(r) for r in records)
        items = [_entry_item(r, repeats, len(records)) for r in records]
        notes.append(REPEAT_WINDOW_NOTE)
        # Anything neither journalctl nor a known field can carry. Refused
        # rather than quietly applied to one page, because a filter that only
        # searches the newest N entries is the lie this pushdown just removed.
        leftover = {k: v for k, v in query.items()
                    if k not in native and k not in pushed}
        if leftover:
            return env.collection_page(
                self.subsystem, collection, src, [], applied, None,
                requested_limit=limit, filters=query or None, status="error",
                errors=[f"cannot filter the journal by {sorted(leftover)}: only "
                        "journald's own fields can be matched at the source, and "
                        "filtering one page client-side would search just the "
                        f"newest {applied} entries. Filterable: "
                        f"{sorted(FIELD_BY_FACT)}, plus unit, priority and since"])

        next_cursor = (_encode_cursor(floor_usec, records[-1]["__CURSOR"])
                       if full_page and records and not exhausted else None)
        return env.collection_page(
            self.subsystem, collection,
            env.source("journal-json", "systemd-journal", REFERENCE,
                       method="journalctl -o json", notes=notes),
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
            evidence_ref=env.evidence_ref("logs", "journal", object_id),
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
