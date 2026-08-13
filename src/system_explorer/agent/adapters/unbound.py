"""unbound subsystem: the recursive resolver, asked over its own socket.

Host-scoped like kea, and the same no-subprocess posture: unbound's
local control socket speaks a line protocol whose replies are strict
machine key=value records (`total.num.queries=42`) — procfs's shape, not
prose, so reading it is kernel-interface-tier acquisition (rule 8), and
`stats_noreset` is the deliberately chosen command: the _noreset suffix
is what keeps this adapter read-only, because plain `stats` ZEROES the
counters as a side effect of reading them.

One collection: `daemon` — version and uptime from `status`, and the
cumulative counters from `stats_noreset`: queries, cache hits and
misses, and the daemon's own precomputed average recursion time.
Counters, never rates (the house rule): the agent holds no previous
sample, so a client derives rates across the window it actually
observed. Configuration is a deployment receipt: SE_UNBOUND_SOCKET
(the NixOS module's unboundSocket + grantUnboundAccess pair).
"""

from __future__ import annotations

import asyncio
import os

from .. import envelope as env

REFERENCE = [
    "unbound-control -c /etc/unbound/unbound.conf status",
    "unbound-control -c /etc/unbound/unbound.conf stats_noreset",
]

_COUNTERS = {"total.num.queries": "NumQueries",
             "total.num.cachehits": "CacheHits",
             "total.num.cachemiss": "CacheMiss",
             "total.num.prefetch": "Prefetches",
             "total.requestlist.current.all": "RequestListCurrent",
             "total.recursion.time.avg": "RecursionTimeAvgSeconds"}

_GLOSSARY = {
    "Version": "The unbound release answering the control socket.",
    "Uptime": "Seconds since the daemon started, by its own statement.",
    "NumQueries": "Queries answered since start — a counter, never a rate: derive rates across your own observation window.",
    "CacheHits": "Queries answered from cache since start; against NumQueries this is the cache doing its job.",
    "CacheMiss": "Queries that needed recursion since start.",
    "Prefetches": "Cache entries refreshed ahead of expiry since start, where prefetch is enabled.",
    "RequestListCurrent": "Queries in flight right now, waiting on recursion — the closest thing to a live load number the daemon states.",
    "RecursionTimeAvgSeconds": "The daemon's own average time to resolve a cache miss, precomputed by unbound rather than derived here.",
}


def parse_status(text: str) -> dict:
    """`status` output: 'version: 1.20.0' style lines. Only the members
    with envelope homes are lifted; the rest stay in evidence."""
    facts: dict = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "version" and value:
            facts["Version"] = value
        elif key == "uptime" and value.split():
            head = value.split()[0]
            if head.isdigit():
                facts["Uptime"] = int(head)
    return facts


def parse_stats(text: str) -> dict:
    """`stats_noreset` output: strict key=value records, one per line —
    machine format, not prose. Values are ints where they parse as ints,
    floats where unbound writes decimals (its own averages)."""
    facts: dict = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        fact = _COUNTERS.get(key.strip())
        if not fact:
            continue
        value = value.strip()
        try:
            facts[fact] = int(value)
        except ValueError:
            try:
                facts[fact] = float(value)
            except ValueError:
                continue
    return facts


class Adapter:
    subsystem = "unbound"

    def __init__(self) -> None:
        self.socket_path = os.environ.get("SE_UNBOUND_SOCKET") or None

    def collections(self) -> list[str]:
        return ["daemon"]

    async def capability(self) -> dict:
        if not self.socket_path:
            return {"available": False, "reason": (
                "SE_UNBOUND_SOCKET is not configured — this host observes"
                " no unbound (the NixOS module option is unboundSocket,"
                " with grantUnboundAccess for the socket's group)")}
        # Absence, permission and a dead listener are different failures
        # (the docker /_ping discipline): probe the connection so the
        # reason names the real one instead of a permissions gap reading
        # as no-resolver-here.
        try:
            _, writer = await asyncio.open_unix_connection(self.socket_path)
            writer.close()
            await writer.wait_closed()
        except FileNotFoundError:
            return {"available": False, "reason": (
                f"no control socket at {self.socket_path}")}
        except PermissionError:
            return {"available": False, "reason": (
                f"the control socket at {self.socket_path} exists but"
                " permission was denied — grantUnboundAccess supplies the"
                " group membership that makes it connectable")}
        except OSError as exc:
            return {"available": False, "reason": env.reason(
                f"{self.socket_path} exists but connecting failed:"
                f" {type(exc).__name__}: {exc}")}
        return {"available": True, "collections": self.collections(),
                "socket": self.socket_path}

    def fact_glossary(self, collection: str) -> dict:
        return _GLOSSARY if collection == "daemon" else {}

    def _source(self) -> dict:
        return env.source("unbound-control", "unbound control socket",
                          REFERENCE, method="status + stats_noreset")

    async def _command(self, command: str) -> str:
        """One command, one connection, the unbound control framing: the
        UBCT1 preamble, the command line, then the reply until EOF."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            writer.write(f"UBCT1 {command}\n".encode())
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(), timeout=10.0)
        finally:
            writer.close()
            await writer.wait_closed()
        text = raw.decode(errors="replace")
        if text.startswith("error"):
            raise RuntimeError(f"unbound {command} answered: {text.strip()}")
        return text

    async def _daemon_items(self) -> list[dict]:
        facts = parse_status(await self._command("status"))
        facts.update(parse_stats(await self._command("stats_noreset")))
        return [env.item_summary("daemon:unbound", "unbound-daemon",
                                 "unbound", facts, opinions=[],
                                 healthy="ok")]

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection != "daemon":
            raise env.UnknownCollection(collection)
        return await self._daemon_items()

    async def collect(self, collection: str, query: dict, limit: int | None,
                      cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, self._source(),
                                   page, applied, next_cursor,
                                   requested_limit=limit, total=total,
                                   filters=query or None)

    async def get_object(self, collection: str, object_id: str) -> dict:
        matches = [item for item in await self.acquire(collection)
                   if item["id"] == object_id]
        if not matches:
            raise env.UnknownObject(object_id)
        item = matches[0]
        return env.observation(
            self.subsystem,
            env.obj_ref(item["id"], item["type"], item["native_id"]),
            self._source(), item["facts"],
            evidence_ref=env.evidence_ref(self.subsystem, collection,
                                          item["id"]))

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        if collection != "daemon":
            raise env.UnknownCollection(collection)
        if object_id != "daemon:unbound":
            raise env.UnknownObject(object_id)
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "unbound control socket",
                "payload": {"status": await self._command("status"),
                            "stats_noreset": await self._command("stats_noreset")}}
