"""kea subsystem: the DHCP server, asked over its own control socket.

Host-scoped (Kea runs as a host service beside this agent, not behind an
app instance), and rule 8's cleanest tier: the control channel IS a
native JSON interface — one unix-socket connection per command, a JSON
command in, a JSON answer out, nothing parsed but JSON. No subprocess
exists to allow-list.

Four collections, each owning one admin question:

- `daemon` — Answers: is the DHCP service itself up and which release
  answers. One row: version, uptime, the daemon's own liveness
  statement.
- `subnets` — Answers: how full is each pool and what does it hand out.
  One row per subnet4 with the pool arithmetic that fails silently when
  it runs out (total, assigned, declined, the rounded UsedPercent), from
  statistic-get-all joined to config-get so each row wears its CIDR,
  its lease time and the routers/DNS options a client is handed.
- `reservations` — Answers: which addresses are pinned to which
  machines. One row per host reservation in the config document.
- `leases` — Answers: who holds an address right now. One row per
  lease4-get-all record — a hook command, not core Kea, so capability()
  gates the collection on the lease_cmds hook and its absence names the
  hook instead of erroring every collect.

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
from collections import Counter

from .. import envelope as env
from ..rules.kea import subnet_opinions

REFERENCE = [
    "echo '{\"command\": \"status-get\"}' | socat - UNIX-CONNECT:<socket>",
    "echo '{\"command\": \"version-get\"}' | socat - UNIX-CONNECT:<socket>",
    "echo '{\"command\": \"statistic-get-all\"}' | socat - UNIX-CONNECT:<socket>",
    "echo '{\"command\": \"config-get\"}' | socat - UNIX-CONNECT:<socket>",
    "echo '{\"command\": \"list-commands\"}' | socat - UNIX-CONNECT:<socket>",
    "echo '{\"command\": \"lease4-get-all\"}' | socat - UNIX-CONNECT:<socket>",
]

# subnet[<id>].<statistic> — the spelling Kea uses in statistic-get-all.
_SUBNET_STAT = re.compile(r"^subnet\[(\d+)\]\.(.+)$")
_WANTED_STATS = {"total-addresses": "TotalAddresses",
                 "assigned-addresses": "AssignedAddresses",
                 "declined-addresses": "DeclinedAddresses"}

# option-data entries matched by name (config-get states name AND code;
# the name is the stable spelling). Only the two options an admin reads
# off a lease first: the gateway and the resolvers a client is handed.
_WANTED_OPTIONS = {"routers": "Routers",
                   "domain-name-servers": "DnsServers"}

# lease4 state in Kea's OWN vocabulary (its lease-cmds documentation:
# 0 default, 1 declined, 2 expired-reclaimed). An unmapped number passes
# through as itself — never renamed into words Kea does not use.
_LEASE_STATES = {0: "default", 1: "declined", 2: "expired-reclaimed"}

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
    "UsedPercent": "Assigned as a rounded share of total — how far through its pool this subnet already is.",
    "LeaseTimeSeconds": "How long a granted lease lasts, from the subnet's own valid-lifetime, else its shared network's, else the global one.",
    "Routers": "The default gateway handed out with each lease — subnet option-data over its shared network's over the global statement, comma-separated when there are several; absent when never-send suppresses the option.",
    "DnsServers": "The DNS resolver addresses clients are told to use, exactly as Kea's option-data states them at the most specific scope, comma-separated when there are several; absent when never-send suppresses the option.",
    "ReservationCount": "How many host reservations this subnet carries — addresses pinned to particular machines rather than pooled — including any the reservations collection cannot list for want of an ip-address.",
    "UnlistedReservations": "How many of this subnet's reservations state no ip-address (hostname- or class-only pins) and so appear in no reservations row — the remainder that reconciles ReservationCount with the rows listed.",
}

_RESERVATION_GLOSSARY = {
    "IpAddress": "The address the reservation pins — handed to its machine every time it asks, never to anyone else.",
    "HwAddress": "The MAC address that identifies which machine the pinned address belongs to.",
    "Hostname": "The name the reservation hands the client along with its address, when the configuration states one.",
    "Subnet": "The CIDR of the subnet the reservation lives in, so the row names its network, not just an id; a global reservation is not subnet-scoped and carries none.",
}

_LEASE_GLOSSARY = {
    "IpAddress": "The address this lease grants right now — the live answer to who holds what.",
    "HwAddress": "The MAC address of the machine currently holding the lease.",
    "Hostname": "The name the client stated when it asked, when Kea recorded one.",
    "State": "The lease's condition in Kea's own vocabulary: default is a live lease, declined was refused on the wire, expired-reclaimed has lapsed and been recovered.",
    "Subnet": "The CIDR the lease was drawn from, joined from the config document via its subnet id.",
    "ExpiresAt": "When the lease lapses unless renewed — allocation time plus valid lifetime, as UTC; 'never' for a lease granted DHCP's infinite lifetime (valid-lft 4294967295).",
}


def _option_values(option_data: list) -> dict[str, str | None]:
    """Wanted option values at one configuration scope. None marks a
    never-send suppression: Kea withholds the option entirely, so the
    marker must mask any wider-scope value instead of letting it fall
    through — plain dict-update ordering then matches Kea's
    most-specific-instance-wins merge. The flag is checked before data
    because an entry carrying both never-send and data is still never
    sent."""
    out: dict[str, str | None] = {}
    for option in option_data or []:
        if not isinstance(option, dict):
            continue
        name = option.get("name")
        fact = _WANTED_OPTIONS.get(name) if isinstance(name, str) else None
        if not fact:
            continue
        if option.get("never-send") is True:
            out[fact] = None
            continue
        data = option.get("data")
        if isinstance(data, str) and data:
            out[fact] = data
    return out


def _subnet_scopes(dhcp4: dict):
    """Every subnet4 wherever the config document declares it, as
    (subnet, enclosing shared network) — {} for a top-level subnet.
    config-get keeps subnets where they were written, so a walker that
    reads only Dhcp4.subnet4 loses every subnet declared inside
    shared-networks: their statistics rows would still appear (Kea
    files subnet[id].* regardless of membership) but with no CIDR, no
    options and no reservations — absence masked as a healthy row."""
    for subnet in dhcp4.get("subnet4") or []:
        if isinstance(subnet, dict):
            yield subnet, {}
    for network in dhcp4.get("shared-networks") or []:
        if not isinstance(network, dict):
            continue
        for subnet in network.get("subnet4") or []:
            if isinstance(subnet, dict):
                yield subnet, network


def config_subnet_facts(dhcp4: dict) -> dict[str, dict]:
    """Per-subnet facts the config document states on its own: the CIDR,
    the lease time (valid-lifetime: subnet override, else the enclosing
    shared network's, else the global value), the handed-out options
    folded in Kea's inheritance order (subnet over shared network over
    global, a never-send suppression masking every wider scope), and
    how many host reservations pin addresses. Keyed by subnet id as a
    string — the spelling the statistic keys use."""
    global_options = _option_values(dhcp4.get("option-data") or [])
    global_lifetime = dhcp4.get("valid-lifetime")
    out: dict[str, dict] = {}
    for subnet, network in _subnet_scopes(dhcp4):
        if subnet.get("id") is None:
            continue
        facts: dict = {}
        if subnet.get("subnet"):
            facts["Subnet"] = subnet["subnet"]
        lifetime = subnet.get("valid-lifetime",
                              network.get("valid-lifetime", global_lifetime))
        if isinstance(lifetime, int):
            facts["LeaseTimeSeconds"] = lifetime
        facts.update(global_options)
        facts.update(_option_values(network.get("option-data") or []))
        facts.update(_option_values(subnet.get("option-data") or []))
        for fact in _WANTED_OPTIONS.values():
            # None survived the merge: the most specific scope says
            # never-send, so the row must not state a value the client
            # is never handed.
            if fact in facts and facts[fact] is None:
                del facts[fact]
        reservations = subnet.get("reservations") or []
        facts["ReservationCount"] = len(reservations)
        unlisted = sum(1 for r in reservations
                       if not (isinstance(r, dict) and r.get("ip-address")))
        if unlisted:
            facts["UnlistedReservations"] = unlisted
        out[str(subnet["id"])] = facts
    return out


def subnet_cidrs(dhcp4: dict) -> dict[str, str]:
    """subnet id (as the string other documents spell it) -> CIDR,
    wherever the config document declares the subnet."""
    return {str(subnet["id"]): subnet["subnet"]
            for subnet, _network in _subnet_scopes(dhcp4)
            if subnet.get("id") is not None and subnet.get("subnet")}


def subnet_rows(statistics: dict, config_facts: dict[str, dict]) -> list[dict]:
    """Per-subnet facts from statistic-get-all's flat key space, merged
    with the per-subnet config facts. Kea files every statistic as
    [[value, timestamp]] lists; the newest value is the first element,
    and only the three pool statistics are folded. UsedPercent exists
    only when a positive total makes the division meaningful."""
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
        facts.update(config_facts.get(subnet_id) or {})
        facts.update(by_subnet[subnet_id])
        total = facts.get("TotalAddresses")
        assigned = facts.get("AssignedAddresses")
        if isinstance(total, int) and total > 0 and isinstance(assigned, int):
            facts["UsedPercent"] = round(assigned * 100 / total)
        rows.append(facts)
    return rows


def _reservation_facts(reservation) -> dict | None:
    """The facts one reservation entry states, or None for an entry that
    cannot mint a stable id (no ip-address: hostname- or class-only)."""
    if not isinstance(reservation, dict) or not reservation.get("ip-address"):
        return None
    facts: dict = {"IpAddress": reservation["ip-address"]}
    if reservation.get("hw-address"):
        facts["HwAddress"] = reservation["hw-address"]
    if reservation.get("hostname"):
        facts["Hostname"] = reservation["hostname"]
    return facts


def _disambiguated(rows: list[tuple[str, dict]]) -> list[tuple[str, dict]]:
    """ip-reservations-unique: false lets one address carry several
    reservations, which would mint one object id for several rows —
    duplicate rows in the collection and every row after the first
    unreachable by id. Colliding ids gain the hw-address that tells the
    machines apart, or the row's ordinal within its collision group
    when hw-address is absent or itself repeated. Unique (subnet, ip)
    ids pass through exactly as minted, so existing ids never churn."""
    counts = Counter(object_id for object_id, _ in rows)
    if not any(count > 1 for count in counts.values()):
        return rows
    hw_counts: dict[str, Counter] = {}
    for object_id, facts in rows:
        if counts[object_id] > 1:
            hw_counts.setdefault(object_id, Counter())[facts.get("HwAddress")] += 1
    ordinal: Counter = Counter()
    out = []
    for object_id, facts in rows:
        if counts[object_id] == 1:
            out.append((object_id, facts))
            continue
        ordinal[object_id] += 1
        hw = facts.get("HwAddress")
        if hw and hw_counts[object_id][hw] == 1:
            out.append((f"{object_id}/{hw}", facts))
        else:
            out.append((f"{object_id}/#{ordinal[object_id]}", facts))
    return out


def reservation_rows(dhcp4: dict) -> list[tuple[str, dict]]:
    """(object id, facts) per host reservation in the config document:
    subnet-scoped reservations wherever their subnet is declared (top
    level or inside a shared network), then global Dhcp4.reservations
    as reservation:global/<ip> with no Subnet fact — a global
    reservation is not subnet-scoped, so the fact stays absent rather
    than invented. A reservation stating no ip-address cannot mint a
    stable id, so it is skipped rather than given an invented one;
    ReservationCount and UnlistedReservations on the subnet row still
    account for it."""
    rows = []
    for subnet, _network in _subnet_scopes(dhcp4):
        if subnet.get("id") is None:
            continue
        for reservation in subnet.get("reservations") or []:
            facts = _reservation_facts(reservation)
            if facts is None:
                continue
            if subnet.get("subnet"):
                facts["Subnet"] = subnet["subnet"]
            rows.append(
                (f"reservation:{subnet['id']}/{facts['IpAddress']}", facts))
    for reservation in dhcp4.get("reservations") or []:
        facts = _reservation_facts(reservation)
        if facts is None:
            continue
        rows.append((f"reservation:global/{facts['IpAddress']}", facts))
    return _disambiguated(rows)


def lease_rows(leases: list, cidrs: dict[str, str]) -> list[dict]:
    """Facts per lease4-get-all record. The id is lease:<ip>, so a
    record with no ip-address is skipped — no stable id can be minted.
    State keeps Kea's own names; ExpiresAt is cltt (allocation time)
    plus valid-lft, and absent when either half is unstated."""
    rows = []
    for lease in leases or []:
        if not isinstance(lease, dict):
            continue
        ip = lease.get("ip-address")
        if not ip:
            continue
        facts: dict = {"IpAddress": ip}
        if lease.get("hw-address"):
            facts["HwAddress"] = lease["hw-address"]
        if lease.get("hostname"):
            facts["Hostname"] = lease["hostname"]
        state = lease.get("state")
        if state is not None:
            facts["State"] = _LEASE_STATES.get(state, state)
        cidr = cidrs.get(str(lease.get("subnet-id")))
        if cidr:
            facts["Subnet"] = cidr
        cltt, valid = lease.get("cltt"), lease.get("valid-lft")
        if valid == 0xFFFFFFFF:
            # DHCP's infinite lifetime (RFC 2131): the lease never
            # lapses, and arithmetic would assert a concrete year-2162
            # date for it instead.
            facts["ExpiresAt"] = "never"
        elif isinstance(cltt, int) and isinstance(valid, int):
            expires = env.usec_to_iso((cltt + valid) * 1_000_000)
            if expires:
                facts["ExpiresAt"] = expires
        rows.append(facts)
    return rows


def gated_collections(commands: list) -> dict[str, str]:
    """lease4-get-all is a hook command, not core Kea: where the
    lease_cmds hook library is not loaded the leases collection is
    declared unavailable with the hook named, and every other collection
    stays up — a config gap must not read as an outage."""
    if "lease4-get-all" in (commands or []):
        return {}
    return {"leases": (
        "the libdhcp_lease_cmds hook is not loaded — lease4-get-all is"
        " not offered")}


class Adapter:
    subsystem = "kea"

    def __init__(self) -> None:
        self.socket_path = os.environ.get("SE_KEA_SOCKET") or None

    def collections(self) -> list[str]:
        return ["daemon", "subnets", "reservations", "leases"]

    async def capability(self) -> dict:
        if not self.socket_path:
            return {"available": False, "reason": (
                "SE_KEA_SOCKET is not configured — this host observes no"
                " Kea (the NixOS module option is keaSocket, with"
                " grantKeaAccess for the socket's group)")}
        # Absence, permission and a dead listener are different failures
        # (the docker /_ping discipline): the probe is list-commands, so
        # one connection both proves the channel and names the command
        # surface the leases gate reads. Kea's runtime dir is 0750, so
        # an EACCES here is the FIRST failure mode on the deployment
        # target, and it must never read as no-DHCP-here.
        try:
            answer = await self._command("list-commands")
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
        except (RuntimeError, ValueError) as exc:
            # _command can now raise past the OSError family: ValueError
            # covers json.JSONDecodeError (an empty or truncated reply —
            # Kea restarting mid-reload accepts then closes) and a
            # non-UTF-8 reply; RuntimeError is a non-ok result. The
            # reason must still name the socket and the failure class
            # instead of escaping to the blanket capability handler.
            return {"available": False, "reason": env.reason(
                f"the control socket at {self.socket_path} accepted the"
                f" connection but list-commands did not answer cleanly:"
                f" {type(exc).__name__}: {exc}")}
        unavailable = gated_collections(answer.get("arguments") or [])
        out: dict = {"available": True,
                     "collections": [c for c in self.collections()
                                     if c not in unavailable],
                     "socket": self.socket_path}
        if unavailable:
            out["unavailable_collections"] = unavailable
        return out

    def fact_glossary(self, collection: str) -> dict:
        return {"daemon": _DAEMON_GLOSSARY,
                "subnets": _SUBNET_GLOSSARY,
                "reservations": _RESERVATION_GLOSSARY,
                "leases": _LEASE_GLOSSARY}.get(collection, {})

    def _source(self, collection: str) -> dict:
        method = {"daemon": "status-get + version-get",
                  "subnets": "statistic-get-all + config-get",
                  "reservations": "config-get",
                  "leases": "lease4-get-all + config-get"}[collection]
        # Rule 7: the unlistable remainder is stated on the wire, not in
        # a docstring — otherwise ReservationCount and this collection's
        # total quietly disagree and only source-reading explains why.
        notes = (["a reservation stating no ip-address (hostname- or"
                  " class-only) mints no stable id and is not listed"
                  " here; the subnet row's ReservationCount still counts"
                  " it and UnlistedReservations states the remainder"]
                 if collection == "reservations" else None)
        return env.source("kea-control", "Kea control socket (JSON)",
                          REFERENCE, method=method, notes=notes)

    async def _command(self, command: str, ok: tuple[int, ...] = (0,)) -> dict:
        """One command, one connection — Kea's own conversation shape. The
        answer's result member is Kea's status code; 0 is success,
        anything else carries its text, and a caller expecting Kea's 3
        (empty: the command ran and nothing matched) says so."""
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
        if answer.get("result") not in ok:
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
        config_facts = config_subnet_facts(config.get("Dhcp4") or {})
        items = []
        for facts in subnet_rows(stats, config_facts):
            native = facts.get("Subnet") or str(facts["SubnetId"])
            items.append(env.item_summary(
                f"subnet:{facts['SubnetId']}", "dhcp-subnet", native, facts,
                name=facts.get("Subnet"),
                opinions=subnet_opinions(facts)))
        return items

    async def _reservation_items(self) -> list[dict]:
        config = (await self._command("config-get")).get("arguments") or {}
        return [env.item_summary(object_id, "dhcp-reservation",
                                 facts["IpAddress"], facts,
                                 name=facts.get("Hostname"),
                                 opinions=[], healthy=None)
                for object_id, facts in reservation_rows(
                    config.get("Dhcp4") or {})]

    async def _lease_items(self) -> list[dict]:
        # ok=(0, 3): Kea answers 3 (CONTROL_RESULT_EMPTY) for a lease
        # table with nothing in it — an answer, not a failure.
        answer = await self._command("lease4-get-all", ok=(0, 3))
        leases = (answer.get("arguments") or {}).get("leases") or []
        config = (await self._command("config-get")).get("arguments") or {}
        cidrs = subnet_cidrs(config.get("Dhcp4") or {})
        return [env.item_summary(f"lease:{facts['IpAddress']}", "dhcp-lease",
                                 facts["IpAddress"], facts,
                                 name=facts.get("Hostname"),
                                 opinions=[], healthy=None)
                for facts in lease_rows(leases, cidrs)]

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection == "daemon":
            return await self._daemon_items()
        if collection == "subnets":
            return await self._subnet_items()
        if collection == "reservations":
            return await self._reservation_items()
        if collection == "leases":
            return await self._lease_items()
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
        (fetch once, check in place): a subnet's evidence carries BOTH
        halves its source method declares — the counters and the config
        document that gives the row its CIDR — reservations serve the
        config document their rows are folded from, and leases serve the
        lease4-get-all answer."""
        if collection not in self.collections():
            raise env.UnknownCollection(collection)
        if collection == "daemon":
            if object_id != "daemon:kea-dhcp4":
                raise env.UnknownObject(object_id)
            payload: object = {"status": await self._command("status-get"),
                               "version": await self._command("version-get")}
        elif collection == "subnets":
            stats = (await self._command("statistic-get-all")).get("arguments") or {}
            config = (await self._command("config-get")).get("arguments") or {}
            known = {f"subnet:{facts['SubnetId']}"
                     for facts in subnet_rows(stats, {})}
            if object_id not in known:
                raise env.UnknownObject(object_id)
            payload = {"statistics": stats, "config": config}
        elif collection == "reservations":
            config = (await self._command("config-get")).get("arguments") or {}
            known = {row_id for row_id, _ in reservation_rows(
                config.get("Dhcp4") or {})}
            if object_id not in known:
                raise env.UnknownObject(object_id)
            payload = {"config": config}
        else:
            answer = await self._command("lease4-get-all", ok=(0, 3))
            leases = (answer.get("arguments") or {}).get("leases") or []
            known = {f"lease:{facts['IpAddress']}"
                     for facts in lease_rows(leases, {})}
            if object_id not in known:
                raise env.UnknownObject(object_id)
            payload = answer
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "Kea control socket (JSON)", "payload": payload}
