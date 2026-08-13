"""kea subsystem: the DHCP server, asked over its own control socket.

Host-scoped (Kea runs as a host service beside this agent, not behind an
app instance), and rule 8's cleanest tier: the control channel IS a
native JSON interface — one unix-socket connection per command, a JSON
command in, a JSON answer out, nothing parsed but JSON. No subprocess
exists to allow-list.

Two collections: `daemon` (one row — version, uptime, the daemon's own
liveness statement) and `subnets` (one row per subnet4 with the pool
arithmetic that fails silently when it runs out: total, assigned,
declined, from statistic-get-all joined to config-get's subnet list so
each row wears its CIDR, not just an id).

Configuration is a deployment receipt: SE_KEA_SOCKET names the control
socket (the NixOS module's grantKeaAccess supplies the group membership
that makes it connectable; an unreadable socket declines with the
errno, which is how a permissions gap says itself instead of reading as
no-DHCP-here).
"""

from __future__ import annotations

import asyncio
import json
import os
import re

from .. import envelope as env
from ..rules.kea import subnet_opinions

REFERENCE = [
    "echo '{\"command\": \"status-get\"}' | socat - UNIX-CONNECT:<socket>",
    "echo '{\"command\": \"statistic-get-all\"}' | socat - UNIX-CONNECT:<socket>",
]

# subnet[<id>].<statistic> — the spelling Kea uses in statistic-get-all.
_SUBNET_STAT = re.compile(r"^subnet\[(\d+)\]\.(.+)$")
_WANTED_STATS = {"total-addresses": "TotalAddresses",
                 "assigned-addresses": "AssignedAddresses",
                 "declined-addresses": "DeclinedAddresses"}

_DAEMON_GLOSSARY = {
    "Version": "The Kea release answering the control socket.",
    "Uptime": "Seconds since the daemon started, by its own clock.",
    "QueueDepthAverages": "Average inbound queue depth over the last 10, 100 and 1000 packets, when multi-threading states them.",
}

_SUBNET_GLOSSARY = {
    "Subnet": "The subnet's CIDR as configured, joined from config-get so the row names the network, not just Kea's internal id.",
    "SubnetId": "Kea's own id for the subnet — the key its statistics are filed under.",
    "TotalAddresses": "How many addresses the subnet's pools can hand out in total.",
    "AssignedAddresses": "How many are currently leased; against the total this is the pool arithmetic that fails silently when it runs out.",
    "DeclinedAddresses": "Addresses offered and then refused on the wire — usually something squatting on them.",
}


def subnet_rows(statistics: dict, subnets_by_id: dict[str, str]) -> list[dict]:
    """Per-subnet facts from statistic-get-all's flat key space. Kea files
    every statistic as [[value, timestamp]] lists; the newest value is the
    first element, and only the three pool statistics are folded."""
    by_subnet: dict[str, dict] = {}
    for key, samples in statistics.items():
        match = _SUBNET_STAT.match(key)
        if not match or match.group(2) not in _WANTED_STATS:
            continue
        if not (isinstance(samples, list) and samples
                and isinstance(samples[0], list) and samples[0]):
            continue
        holder = by_subnet.setdefault(match.group(1), {})
        holder[_WANTED_STATS[match.group(2)]] = samples[0][0]
    rows = []
    for subnet_id in sorted(by_subnet, key=int):
        facts: dict = {"SubnetId": int(subnet_id)}
        cidr = subnets_by_id.get(subnet_id)
        if cidr:
            facts["Subnet"] = cidr
        facts.update(by_subnet[subnet_id])
        rows.append(facts)
    return rows


class Adapter:
    subsystem = "kea"

    def __init__(self) -> None:
        self.socket_path = os.environ.get("SE_KEA_SOCKET") or None

    def collections(self) -> list[str]:
        return ["daemon", "subnets"]

    async def capability(self) -> dict:
        if not self.socket_path:
            return {"available": False, "reason": (
                "SE_KEA_SOCKET is not configured — this host observes no"
                " Kea (the NixOS module option is keaSocket, with"
                " grantKeaAccess for the socket's group)")}
        # Absence, permission and a dead listener are different failures
        # (the docker /_ping discipline): probe the connection so the
        # reason names the real one — Kea's runtime dir is 0750, so an
        # EACCES here is the FIRST failure mode on the deployment
        # target, and it must never read as no-DHCP-here.
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
                " permission was denied — grantKeaAccess supplies the"
                " group membership that makes it connectable")}
        except OSError as exc:
            return {"available": False, "reason": env.reason(
                f"{self.socket_path} exists but connecting failed:"
                f" {type(exc).__name__}: {exc}")}
        return {"available": True, "collections": self.collections(),
                "socket": self.socket_path}

    def fact_glossary(self, collection: str) -> dict:
        return {"daemon": _DAEMON_GLOSSARY,
                "subnets": _SUBNET_GLOSSARY}.get(collection, {})

    def _source(self, collection: str) -> dict:
        method = {"daemon": "status-get + version-get",
                  "subnets": "statistic-get-all + config-get"}[collection]
        return env.source("kea-control", "Kea control socket (JSON)",
                          REFERENCE, method=method)

    async def _command(self, command: str) -> dict:
        """One command, one connection — Kea's own conversation shape. The
        answer's result member is Kea's status code; 0 is success and
        anything else carries its text."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            writer.write(json.dumps({"command": command}).encode())
            await writer.drain()
            writer.write_eof()
            raw = await asyncio.wait_for(reader.read(), timeout=10.0)
        finally:
            writer.close()
            await writer.wait_closed()
        answer = json.loads(raw)
        if isinstance(answer, list):
            answer = answer[0] if answer else {}
        if answer.get("result") != 0:
            # Every real Kea answer carries result; a reply that never
            # said success in Kea's own vocabulary must not read as one.
            raise RuntimeError(
                f"kea {command} answered {answer.get('result')}:"
                f" {answer.get('text')}")
        return answer

    async def _daemon_items(self) -> list[dict]:
        version = await self._command("version-get")
        status = await self._command("status-get")
        arguments = status.get("arguments") or {}
        facts: dict = {}
        if version.get("text"):
            facts["Version"] = version["text"]
        if isinstance(arguments.get("uptime"), int):
            facts["Uptime"] = arguments["uptime"]
        # packet-queue-size is the configured CAPACITY, not occupancy —
        # the statistics list (moving averages over the last 10/100/1000
        # packets) is the only live queue signal status-get states.
        queue = arguments.get("packet-queue-statistics")
        if isinstance(queue, list) and queue:
            facts["QueueDepthAverages"] = queue
        return [env.item_summary("daemon:kea-dhcp4", "kea-daemon",
                                 "kea-dhcp4", facts, opinions=[],
                                 healthy="ok")]

    async def _subnet_items(self) -> list[dict]:
        stats = (await self._command("statistic-get-all")).get("arguments") or {}
        config = (await self._command("config-get")).get("arguments") or {}
        subnets_by_id = {
            str(subnet.get("id")): subnet.get("subnet")
            for subnet in (config.get("Dhcp4") or {}).get("subnet4") or []
            if subnet.get("id") is not None}
        items = []
        for facts in subnet_rows(stats, subnets_by_id):
            native = facts.get("Subnet") or str(facts["SubnetId"])
            items.append(env.item_summary(
                f"subnet:{facts['SubnetId']}", "dhcp-subnet", native, facts,
                name=facts.get("Subnet"),
                opinions=subnet_opinions(facts)))
        return items

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection == "daemon":
            return await self._daemon_items()
        if collection == "subnets":
            return await self._subnet_items()
        raise env.UnknownCollection(collection)

    async def collect(self, collection: str, query: dict, limit: int | None,
                      cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection,
                                   self._source(collection),
                                   page, applied, next_cursor,
                                   requested_limit=limit, total=total,
                                   filters=query or None)

    async def get_object(self, collection: str, object_id: str) -> dict:
        matches = [item for item in await self.acquire(collection)
                   if item["id"] == object_id]
        if not matches:
            raise env.UnknownObject(object_id)
        item = matches[0]
        opinions = (subnet_opinions(item["facts"])
                    if collection == "subnets" else [])
        return env.observation(
            self.subsystem,
            env.obj_ref(item["id"], item["type"], item["native_id"],
                        name=item.get("name")),
            self._source(collection), item["facts"],
            opinions=opinions or None,
            evidence_ref=env.evidence_ref(self.subsystem, collection,
                                          item["id"]))

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        """Membership comes from the same documents the payload serves
        (fetch once, check in place), and a subnet's evidence carries
        BOTH halves its source method declares — the counters and the
        config document that gives the row its CIDR."""
        if collection not in self.collections():
            raise env.UnknownCollection(collection)
        if collection == "daemon":
            if object_id != "daemon:kea-dhcp4":
                raise env.UnknownObject(object_id)
            payload: object = {"status": await self._command("status-get"),
                               "version": await self._command("version-get")}
        else:
            stats = (await self._command("statistic-get-all")).get("arguments") or {}
            config = (await self._command("config-get")).get("arguments") or {}
            known = {f"subnet:{facts['SubnetId']}"
                     for facts in subnet_rows(stats, {})}
            if object_id not in known:
                raise env.UnknownObject(object_id)
            payload = {"statistics": stats, "config": config}
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "Kea control socket (JSON)", "payload": payload}
