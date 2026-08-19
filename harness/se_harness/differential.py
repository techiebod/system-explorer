"""Differential replay: the corpus as a seed set (DESIGN 20, the third trap).

Replay equivalence proves a collector right about the machines the corpus
holds, and nothing else — a port that hardcodes its way through the captured
cases is green by construction, and every added variant only moves the
frontier. So this module stops asking "does the challenger reproduce the
committed pair" and asks the only question the uncovered space admits: **run
the reference and the challenger over the same mutated payloads and let
disagreement be the verdict.** Agreement proves consistency with the
reference, never truth; truth on the reference rests on the corpus anchors
and the adjudication rule (DESIGN 20), which is the same layering, reused.

**A mutator, not a fuzzer.** Every operator below is a structural
transformation a real machine could exhibit — an extra address family, a
second caller, a mixed vdev layout, a scrub running right now, a member
marshalled as null — so the reference must handle every mutated payload
meaningfully. A payload the reference rejects tests nothing: the run's
verdict would be about a parser, not about the machine, which is why the
reference-vs-reference control is asserted for every operator and a broken
operator fails THERE rather than counting as a catch.

**No randomness anywhere.** A fixed operator list is applied to fixed seed
variants; every choice an operator makes (which chain, which vdev, which
handle) is derived from the document in sorted or document order. Two runs
agree byte for byte, so a disagreement is always the challenger's and never
the dice's.

What this module deliberately does NOT claim, because DESIGN 19's ownership
law places it elsewhere: the harness authenticates what varies within one
stream, the collator what varies across streams, and the live comparator
what varies with time itself. A constant `at` and a constant-but-valid
boot id are invisible here BY PHYSICS — replay pins the clock — and the
tests execute that deferral (wrong bytes on the wire, verdict still AGREE)
rather than leaving it as a comment.
"""

from __future__ import annotations

import copy
import json
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import replay
from .corpus import Variant


class MutatorError(Exception):
    """A seed this operator cannot mutate — a mutator bug, never a verdict."""


# The verdicts, spelled once. REFUSED outranks DISAGREE: a stream that breaks
# the batch rules is not a reading to compare, it is a protocol violation,
# and diffing it anyway would report facts about records the collator would
# never have applied.
AGREE = "AGREE"
DISAGREE = "DISAGREE"
REFUSED = "REFUSED"

# One seed per collector, and the smallest that exercises every operator:
# healthy captures, because every operator ADDS the shape it exposes — a
# degraded seed would entangle each operator's disagreement with the staged
# defect the degraded variant exists for.
SEEDS = {
    "network": "network/healthy",
    "storage": "storage/healthy",
    "vms": "vms/healthy",
    "packages": "packages/healthy",
    "unbound": "unbound/healthy",
    "docker": "docker/healthy",
    "bazarr": "bazarr/healthy",
    "traefik": "traefik/healthy",
    "servarr": "servarr/healthy",
    "kea": "kea/no-lease-hook",
    "resources": "resources/healthy",
    "downloaders": "downloaders/healthy",
}

# Names the operators mint. Constants rather than inline literals so the
# tests can bind their evidence to the exact spelling without restating it —
# a test that retyped the string would drift silently when an operator was
# edited. All hex WWNs, because the mutated document must stay a document
# zpool could have produced.
STRIPE_DISK = "wwn-0x3aa40000c0ffee01"
LOG_DISK = "wwn-0x3d1c0000badcafe0"
SPARE_DISK = "wwn-0x3e990000feedface"
CACHE_DISK = "wwn-0x3f0a0000cac4e001"
MAP_NAME = "mut-dispatch"
LANDING_CHAIN = "mut-landing"
NETDEV_CHAIN = "netdev filter ingress"
BRIDGE_BASE_CHAIN = "bridge filter FORWARD"
BRIDGE_ISLAND_CHAIN = "bridge filter island"
ARP_CHAIN = "arp filter input"
# libvirt's own default network hands out 192.168.122.0/24, so a leased guest
# on a stock host answers on an address from it. In its own space, like every
# other address this repository writes down (DESIGN 21).
GUEST_ADDRESS = "192.168.122.50"
# A real Debian-family package that a machine plausibly removed and kept the
# configuration of: ifupdown is what netplan replaced, so `rc  ifupdown` is an
# ordinary line in `dpkg -l` on an upgraded Ubuntu guest.
REMOVED_PACKAGE = "ifupdown"
# The two containers the docker operators mint, and the scope units the daemon
# gives them. Sixty-four hex characters, because a docker id is what the scope
# name is derived from and a short one would exercise the wrong branch. The
# names carry the `mut-` prefix every minted object in this module uses, so a
# reader of a failing diff can tell a staged row from a captured one.
RESTARTING_CONTAINER = "mut-restarting"
RESTARTING_ID = "d0c1e2a3b4956677889900aabbccddeeff00112233445566778899aabbccddee"
RESTARTING_SCOPE = f"docker-{RESTARTING_ID}.scope"
PAUSED_CONTAINER = "mut-paused"
PAUSED_ID = "c1a2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
PAUSED_SCOPE = f"docker-{PAUSED_ID}.scope"
# The second resolver thread the unbound operator mints, and what it has been
# doing: one thread's own share of the traffic, in the records `stats_noreset`
# keeps per thread. Its cache hits and misses sum to its queries, because a
# document whose members disagree with each other is not one unbound produces.
UNBOUND_THREAD1 = {
    "num.queries": 37,
    "num.cachehits": 20,
    "num.cachemiss": 17,
    "num.prefetch": 3,
    "requestlist.current.all": 1,
}
# The two spellings the disagreement lands on: the resolver's query total,
# which only an implementation reading `total.` can produce, and the first
# thread's share, which is what a thread-blind one publishes in its place.
# Read off the committed seed — 21 queries — plus the thread minted above; a
# re-stage of corpus/unbound/healthy moves both, exactly as it moves that
# variant's anchors, and the case that binds to them fails by name when it does.
UNBOUND_QUERY_TOTAL = "'NumQueries': 58"
UNBOUND_THREAD_SHARE = "'NumQueries': 21"
# The two managers the bazarr operator wires this instance to. Real release
# strings from the two projects, because the mutated document must be one
# bazarr could have answered with — and these facts are pass-through, so an
# invented shape would be exercising the wrong thing. The evidence spellings
# below carry the fact and its value together, which is how a facts-dict
# difference renders, and they are built FROM the releases the operator writes
# so the two cannot drift into disagreeing about what was minted.
BAZARR_SONARR_RELEASE = "4.0.15.2941"
BAZARR_RADARR_RELEASE = "5.27.5.10198"
BAZARR_SONARR_VERSION = f"'SonarrVersion': '{BAZARR_SONARR_RELEASE}'"
BAZARR_RADARR_VERSION = f"'RadarrVersion': '{BAZARR_RADARR_RELEASE}'"
# What a dynamic provider brings to a Traefik that had none. Every value below
# was measured on a live Traefik 3.1.7 on 2026-08-19 — a file provider with one
# TLS'd application, two backends and one deliberately broken rule — and is
# carried in that spelling, because the operator's contract is a document the
# interface produces and not one that resembles it. The two backend addresses
# are docker's own bridge space, synthetic and in their own space like every
# other address this repository writes down (DESIGN 21); the hostname is IANA's
# documentation domain for the same reason.
TRAEFIK_APP = "labapp@file"
TRAEFIK_REJECTED_ROUTER = "broken@file"
TRAEFIK_UP_BACKEND = "http://172.19.0.4:8080"
TRAEFIK_DOWN_BACKEND = "http://172.19.0.5:8080"
TRAEFIK_CERT_RESOLVER = "lab"
# Traefik's own words for the rule it refused, quoted exactly as the API
# returned them: the rule text is in the message, which is what makes a rejected
# route actionable rather than merely counted.
TRAEFIK_ROUTER_ERROR = (
    "error while parsing rule Hostx(`nope.example.com`): unsupported function: Hostx"
)
# The one figure that only exists if the serverStatus map was folded at all.
TRAEFIK_SERVERS_DOWN = "'ServersDown': 1"
# The one acquisition the servarr operator puts through an idle fleet, in the
# three places a real one appears at once: the grab in the asking app's trail,
# the download it created in that app's queue, and the indexer proxy's own
# audit of the same release. Every string carries the `mut-` prefix or the
# `Mut.` release-name convention this module uses for minted objects, so a
# reader of a failing diff can tell a staged row from a captured one — and no
# value here is anybody's media: the title is a release name that never existed.
SERVARR_TITLE = "Mut.Release.2026.1080p.WEB-DL.MUTGRP"
SERVARR_DOWNLOAD_ID = "3ab0000000000000000000000000000000c0ffee"
SERVARR_INDEXER = "mut-indexer"
SERVARR_CLIENT = "mut-transmission"
# The two sentences the app writes to say WHY a completed download will not
# import, and the error line beside them. They are the difference between a
# row that says `warning` and a row that says what to do, and they are the only
# members of the stuck shape a payload can take away without making the
# reference publish a null — which is what the blind fixture rewrites.
SERVARR_STUCK_MESSAGE = "Not an upgrade for existing movie file(s)"
SERVARR_ERROR_MESSAGE = "The download is missing files"
# The hostname-only reservation the kea operator mints, and the two spellings the
# disagreement lands on. A reservation that pins a NAME and no address is an
# ordinary Kea configuration — it exists to hand a client its hostname, or to put
# it in a class — and it is exactly the entry that can be counted and cannot be
# listed. The counts are read off the committed seed (six reservations, all of
# them addressed) plus the entry minted below; a re-stage of corpus/kea moves
# both, exactly as it moves that variant's anchors, and the case that binds to
# them fails by name when it does.
KEA_UNLISTED_HOST = "printer-loft"
KEA_RESERVATION_COUNT = "'ReservationCount': 7"
KEA_UNLISTED_REMAINDER = "'UnlistedReservations': 1"
# The workload the cgroup operator gives an OOM record to, and the payload
# holding it. The payload name is the seam's own addressing — the resources
# collector's reads are dispatched on their PATH, so the stem is slug(path) —
# and it is spelled out rather than derived, because a stem this operator got
# wrong would raise a mutator error a reader can act on instead of silently
# rewriting some other cgroup's counters.
OOM_KILLED_UNIT = "cron.service"
OOM_KILLED_PAYLOAD = "sys-fs-cgroup-system.slice-cron.service-memory.events"
# Three times at the limit, one process killed. oom_kill <= oom is a kernel
# invariant — a kill implies an event — so the two are not equal here, which is
# the whole shape: an implementation that read one for the other agrees with
# the reference on every capture where both are zero, and reports killings that
# never happened the moment they are not.
OOM_EVENTS = 3
OOM_KILLS = 1
# The two spellings the disagreement lands on: the number of processes the
# kernel actually killed, and the number of times the limit was merely hit,
# which is what a port that read `oom` publishes in its place.
OOM_KILLS_TRUE = f"'MemoryOomKills': {OOM_KILLS}"
OOM_KILLS_BLIND = f"'MemoryOomKills': {OOM_EVENTS}"
# The tracker failure the downloaders operator mints. transmission's own error
# vocabulary numbers a tracker error 2, and the text is what a tracker that has
# forgotten a torrent actually answers — a shape every seedbox meets and no
# committed capture holds, because a staged lab torrent announces to a host
# that does not resolve and never gets a reply to be refused by.
TRANSFER_ERROR_CODE = 2
TRANSFER_ERROR_TEXT = "Tracker gave HTTP response code 404 (Not Found)"


# ── nftables helpers, grammar-aware ──────────────────────────────────────


def _nft_objects(doc: dict, kind: str) -> list[dict]:
    return [entry[kind] for entry in doc.get("nftables", []) if kind in entry]


def _max_handle(doc: dict) -> int:
    """The largest handle in the document, so minted objects extend the
    kernel's numbering instead of colliding with it."""
    handles = [
        obj.get("handle")
        for entry in doc.get("nftables", [])
        for obj in entry.values()
        if isinstance(obj, dict) and isinstance(obj.get("handle"), int)
    ]
    return max(handles, default=0)


def _verdict_refs(node: object) -> list[tuple[str, str]]:
    """(verb, target) for every jump/goto anywhere in an expression tree —
    the same full descent the reference uses, because an operator that read
    only the surface would mis-pick its subject on exactly the rulesets the
    vmap defect lived in."""
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for verb in ("jump", "goto"):
            body = node.get(verb)
            if isinstance(body, dict) and body.get("target"):
                found.append((verb, str(body["target"])))
        for value in node.values():
            found.extend(_verdict_refs(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_verdict_refs(value))
    return found


def _callers(doc: dict) -> dict[tuple[str, str, str], list[str]]:
    """(family, table, target) -> caller chains, one entry per REFERENCE, in
    document order. Occurrences matter, not just the caller set: converting
    'the' jump to a target that is jumped to twice would leave the first
    jump standing and expose nothing."""
    refs: dict[tuple[str, str, str], list[str]] = {}
    for rule in _nft_objects(doc, "rule"):
        for _verb, target in _verdict_refs(rule.get("expr") or []):
            refs.setdefault(
                (rule.get("family"), rule.get("table"), target), []
            ).append(rule.get("chain"))
    return refs


# ── the operators ────────────────────────────────────────────────────────
#
# Each one is a transformation a real machine could exhibit, and each
# declares the collector-defect CLASS it exposes: the family of wrong
# implementations that agree with the reference on every committed pair and
# stop agreeing on this shape. The class names are the contract the tests
# bind to.


def _add_netdev_ingress(payloads: dict) -> dict:
    """CLASS family-enum: a walk whose address families are an enum over the
    ones its author had met. netdev is the family such a port has usually
    never seen — its ingress base chains hook the driver itself and are the
    first thing a packet meets, so dropping the family silently drops the
    machine's outermost filter. The reference carries the chain like any
    other; a family-enum port emits nothing for it."""
    doc = payloads["nft"]
    handle = _max_handle(doc)
    doc["nftables"] += [
        {"table": {"family": "netdev", "name": "filter", "handle": handle + 1}},
        {
            "chain": {
                "family": "netdev",
                "table": "filter",
                "name": "ingress",
                "handle": handle + 2,
                "type": "filter",
                "hook": "ingress",
                "dev": "lab0",
                "prio": -500,
                "policy": "accept",
            }
        },
        {
            "rule": {
                "family": "netdev",
                "table": "filter",
                "chain": "ingress",
                "handle": handle + 3,
                "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "ether",
                                                 "field": "type"}},
                            "right": "arp",
                        }
                    },
                    {"accept": None},
                ],
            }
        },
    ]
    return payloads


def _add_bridge_family(payloads: dict) -> dict:
    """CLASS family-enum, the bridge spelling: the second family the enum
    port drops, staged separately because an enum that learned netdev the
    hard way still drops bridge. One base chain and one regular chain, so
    both the hooked and the Unreferenced shapes go missing at once."""
    doc = payloads["nft"]
    handle = _max_handle(doc)
    doc["nftables"] += [
        {"table": {"family": "bridge", "name": "filter", "handle": handle + 1}},
        {
            "chain": {
                "family": "bridge",
                "table": "filter",
                "name": "FORWARD",
                "handle": handle + 2,
                "type": "filter",
                "hook": "forward",
                "prio": -200,
                "policy": "accept",
            }
        },
        {
            "chain": {
                "family": "bridge",
                "table": "filter",
                "name": "island",
                "handle": handle + 3,
            }
        },
    ]
    return payloads


def _add_arp_family(payloads: dict) -> dict:
    """CLASS family-enum, the arp spelling: arp is the family the enum reaches
    LAST and no operator minted until this one — which is precisely how it
    stayed an uncovered member of a class the guard claimed to close family by
    family. nftables declares six families (network.py's Family glossary: ip,
    ip6, inet, arp, bridge, netdev); netdev and bridge each had an operator and
    arp had none, so an enum port that had learned those two the hard way still
    drops the machine's whole arp table and the guard could not see it. One arp
    base chain on the input hook with a rule, so a hooked arp chain — a real
    shape the reference reads like any other — goes missing when the family
    does. Minted, not exempted, because an arp table CAN be produced and read:
    the residual ledger is for members that genuinely cannot, and this is not
    one."""
    doc = payloads["nft"]
    handle = _max_handle(doc)
    doc["nftables"] += [
        {"table": {"family": "arp", "name": "filter", "handle": handle + 1}},
        {
            "chain": {
                "family": "arp",
                "table": "filter",
                "name": "input",
                "handle": handle + 2,
                "type": "filter",
                "hook": "input",
                "prio": -150,
                "policy": "accept",
            }
        },
        {
            "rule": {
                "family": "arp",
                "table": "filter",
                "chain": "input",
                "handle": handle + 3,
                "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "arp",
                                                 "field": "operation"}},
                            "right": "request",
                        }
                    },
                    {"accept": None},
                ],
            }
        },
    ]
    return payloads


def _second_caller(payloads: dict) -> dict:
    """CLASS single-caller: JumpedFrom held as one value per chain —
    map[key]string where a set was needed, the shape a port reaches for when
    every chain it has ever seen had one caller. Duplicate an existing jump
    from another chain in the same (family, table): the reference reports
    both callers, a single-caller port keeps whichever it read last."""
    doc = payloads["nft"]
    chains_by_ft: dict[tuple[str, str], list[str]] = {}
    for chain in _nft_objects(doc, "chain"):
        chains_by_ft.setdefault(
            (chain.get("family"), chain.get("table")), []
        ).append(chain.get("name"))
    single = sorted(
        key for key, callers in _callers(doc).items() if len(set(callers)) == 1
    )
    for family, table, target in single:
        existing = set(_callers(doc)[(family, table, target)])
        others = sorted(
            name
            for name in chains_by_ft.get((family, table), [])
            if name != target and name not in existing
        )
        if others:
            doc["nftables"].append(
                {
                    "rule": {
                        "family": family,
                        "table": table,
                        "chain": others[0],
                        "handle": _max_handle(doc) + 1,
                        "expr": [{"jump": {"target": target}}],
                    }
                }
            )
            return payloads
    raise MutatorError(
        "no single-caller jump target with a second chain available in its "
        "(family, table) — this seed cannot stage a second caller"
    )


def _swap_first_jump_to_goto(node: object, target: str) -> bool:
    """Rewrite the FIRST {"jump": {"target": target}} met in document order
    into a goto, in place. First-only, because the operator's contract is
    'convert a jump', singular — a sweep would also rewrite jumps the
    operator did not pick and widen the mutation past its declaration."""
    if isinstance(node, dict):
        body = node.get("jump")
        if isinstance(body, dict) and body.get("target") == target:
            node["goto"] = node.pop("jump")
            return True
        for value in node.values():
            if _swap_first_jump_to_goto(value, target):
                return True
    elif isinstance(node, list):
        for value in node:
            if _swap_first_jump_to_goto(value, target):
                return True
    return False


def _jump_to_goto(payloads: dict) -> dict:
    """CLASS goto-blind: a reachability walk that reads `jump` and not
    `goto`. goto differs from jump in where control RETURNS, never in
    whether it ARRIVES, so for reachability they are one fact — and a
    goto-blind walk publishes the target as Unreferenced, the one answer an
    operator acts on by deleting the chain. The subject: a REGULAR chain
    reached by exactly one jump reference, so after conversion the word
    `jump` no longer reaches it at all."""
    doc = payloads["nft"]
    hooked = {
        (c.get("family"), c.get("table"), c.get("name"))
        for c in _nft_objects(doc, "chain")
        if c.get("hook")
    }
    chains = {
        (c.get("family"), c.get("table"), c.get("name"))
        for c in _nft_objects(doc, "chain")
    }
    for key, callers in sorted(_callers(doc).items()):
        if len(callers) != 1 or key in hooked or key not in chains:
            continue
        family, table, target = key
        for rule in _nft_objects(doc, "rule"):
            if rule.get("family") != family or rule.get("table") != table:
                continue
            if _swap_first_jump_to_goto(rule.get("expr") or [], target):
                return payloads
    raise MutatorError(
        "no regular chain reached by exactly one jump — this seed cannot "
        "stage a goto conversion"
    )


def _add_verdict_map(payloads: dict) -> dict:
    """CLASS map-blind: a walk that descends rule expressions in full and
    never reads top-level `map` objects. A NAMED verdict map keeps its jumps
    in the map object's elem list — the dispatching rule carries only the
    string "@name" — so a map-blind walk publishes the landing chain as
    {RuleCount: 0, Unreferenced: true}. Minted beside the first base chain
    (sorted), which hosts the dispatching rule."""
    doc = payloads["nft"]
    bases = sorted(
        (c.get("family"), c.get("table"), c.get("name"))
        for c in _nft_objects(doc, "chain")
        if c.get("hook")
    )
    if not bases:
        raise MutatorError("no base chain to host the vmap dispatch rule")
    family, table, host = bases[0]
    handle = _max_handle(doc)
    doc["nftables"] += [
        {
            "map": {
                "family": family,
                "table": table,
                "name": MAP_NAME,
                "handle": handle + 1,
                "type": "inet_proto",
                "map": "verdict",
                "elem": [
                    ["tcp", {"jump": {"target": LANDING_CHAIN}}],
                    ["udp", {"drop": None}],
                ],
            }
        },
        {
            "chain": {
                "family": family,
                "table": table,
                "name": LANDING_CHAIN,
                "handle": handle + 2,
            }
        },
        {
            "rule": {
                "family": family,
                "table": table,
                "chain": host,
                "handle": handle + 3,
                "expr": [
                    {
                        "vmap": {
                            "key": {"meta": {"key": "l4proto"}},
                            "data": f"@{MAP_NAME}",
                        }
                    }
                ],
            }
        },
    ]
    return payloads


# ── zpool helpers ────────────────────────────────────────────────────────


def _first_pool(status: dict) -> dict:
    pools = status.get("pools") or {}
    if not pools:
        raise MutatorError("status payload carries no pools")
    return next(iter(pools.values()))


def _root_children(pool: dict) -> dict:
    root = next(iter((pool.get("vdevs") or {}).values()), None)
    if not isinstance(root, dict) or root.get("vdev_type") != "root":
        raise MutatorError("first vdev is not the root container")
    return root.setdefault("vdevs", {})


def _prop_entry(value: object) -> dict:
    """zpool list -j spells every property as {value, source} with string
    values; minted properties keep that spelling or the payload stops being
    a document zpool could have produced."""
    return {"value": str(value), "source": {"type": "NONE", "data": "-"}}


def _leaf_disk(name: str, guid: int, state: str = "ONLINE") -> dict:
    """A disk vdev as zpool status -j reports one, error counters included —
    zeroed, not omitted, because an omitted counter is the nested-null
    operator's job and no other operator may smuggle that shape in."""
    return {
        "name": name,
        "vdev_type": "disk",
        "guid": guid,
        "path": f"/dev/disk/by-id/{name}-part1",
        "devid": f"scsi-3{name.removeprefix('wwn-0x')}-part1",
        "class": "normal",
        "state": state,
        "read_errors": 0,
        "write_errors": 0,
        "checksum_errors": 0,
        "slow_ios": 0,
    }


STRIPE_DISK_SIZE = 8_001_553_432_576
STRIPE_DISK_ALLOC = 1_073_741_824


def _append_stripe_vdev(payloads: dict) -> dict:
    """CLASS first-vdev-redundancy: a redundancy walk that reports the
    layout it met first and stops looking. Append a bare-disk stripe vdev
    beside the existing raidz1: the pool is now only as redundant as its
    weakest data vdev — losing that one disk loses the pool — so the
    reference reports the mixed layout ("raidz1 + stripe") tolerating zero
    failures, and a first-vdev port keeps reporting raidz1 tolerating one.
    The list payload is recomputed consistently: the new vdev carries its
    own capacity properties and the pool totals grow by them, because a
    document whose totals disagree with its members is not a document zpool
    produces."""
    status, listing = payloads["status"], payloads["list"]
    pool = _first_pool(status)
    _root_children(pool)[STRIPE_DISK] = _leaf_disk(STRIPE_DISK, 4242424242424242)
    root = next(iter(pool["vdevs"].values()))
    for member, growth in (
        ("total_space", STRIPE_DISK_SIZE),
        ("def_space", STRIPE_DISK_SIZE),
        ("alloc_space", STRIPE_DISK_ALLOC),
    ):
        if isinstance(root.get(member), int):
            root[member] += growth

    lpool = _first_pool(listing)
    lpool.setdefault("vdevs", {})[STRIPE_DISK] = {
        "name": STRIPE_DISK,
        "vdev_type": "disk",
        "guid": "4242424242424242",
        "class": "normal",
        "state": "ONLINE",
        "properties": {
            "size": _prop_entry(STRIPE_DISK_SIZE),
            "allocated": _prop_entry(STRIPE_DISK_ALLOC),
            "free": _prop_entry(STRIPE_DISK_SIZE - STRIPE_DISK_ALLOC),
            "capacity": _prop_entry(STRIPE_DISK_ALLOC * 100 // STRIPE_DISK_SIZE),
        },
    }
    props = lpool.get("properties") or {}
    size = int(props["size"]["value"]) + STRIPE_DISK_SIZE
    alloc = int(props["allocated"]["value"]) + STRIPE_DISK_ALLOC
    free = int(props["free"]["value"]) + STRIPE_DISK_SIZE - STRIPE_DISK_ALLOC
    props["size"] = _prop_entry(size)
    props["allocated"] = _prop_entry(alloc)
    props["free"] = _prop_entry(free)
    props["capacity"] = _prop_entry(alloc * 100 // size)
    return payloads


def _scan_running_now(payloads: dict) -> dict:
    """CLASS epoch-zero-scan: `zpool status --json-int` renders a scan in
    progress as end_time 0, and 0 is an int — so a port that formats any int
    as an epoch reports a pool that is scrubbing RIGHT NOW as last scrubbed
    1970-01-01, twenty thousand days ago. The reference reads 0 as
    "no end yet": no end time, no age, state SCANNING."""
    scan = _first_pool(payloads["status"]).setdefault("scan_stats", {})
    scan["function"] = "SCRUB"
    scan["state"] = "SCANNING"
    scan["end_time"] = 0
    return payloads


def _resilver_overwrote_the_scrub(payloads: dict) -> dict:
    """CLASS scan-function-blind: a collector that reads the pool's single
    scan record without asking WHICH scan it is. ZFS keeps only the most
    recent, so a resilver REPLACES the scrub's record — and a port that
    reports ScanAgeDays from it says the pool was scrubbed however many days
    ago the resilver finished. That is not hypothetical: it was observed on a
    foreign host whose shelf read ScanAgeDays 9 from a resilver while its last
    real scrub was months old, and the stale-scrub rule guarded on
    ScanFunction and simply went silent — absence-as-health, beside the
    figure that looked reassuring.

    So the reference publishes LastScrubEndTime as an unobservable record with
    the reason in its sibling fact: the value exists and this pool cannot
    report it (DESIGN 19's third channel). Both facts were declared,
    implemented and reachable by NO committed capture and no operator until
    this one — found by the contract-verification check asking which declared
    facts a corpus never produces. Turn the healthy pool's scan record into a
    finished resilver; a scan-function-blind port emits neither the
    unobservable nor the reason, and its commit's unobservable count is short
    by one.
    """
    scan = _first_pool(payloads["status"]).setdefault("scan_stats", {})
    scan["function"] = "RESILVER"
    scan["state"] = "FINISHED"
    # A plausible finish inside the corpus's pinned clock, so the reading is a
    # resilver that completed rather than one still running — this operator's
    # subject is which scan the record describes, and a running scan would
    # entangle it with zpool-scan-running's zero-end-time case.
    scan["end_time"] = 1786550000
    return payloads


def _add_spares_and_logs(payloads: dict) -> dict:
    """CLASS spare-as-unhealthy: a spare sits AVAIL — attached to nothing,
    protecting nothing yet — and a log device is a data-path helper, not a
    data vdev. A port whose health test is `state != ONLINE` reports the
    AVAIL spare as an unhealthy member of a pool it is merely standing by
    for; a port whose redundancy walk counts group members would grade the
    layout by devices that hold no pool data. The reference does neither."""
    pool = _first_pool(payloads["status"])
    # TOP-LEVEL keys on the pool, beside "vdevs" and not inside it, because
    # that is where zpool status -j actually puts them — measured on a live
    # pool with a spare, a log and a cache attached. This operator minted
    # them nested under the root until then, a shape zpool does not produce,
    # so the class it claims to close was closed against a placement that
    # does not exist while both implementations were blind to the real one.
    pool["logs"] = {LOG_DISK: _leaf_disk(LOG_DISK, 5151515151515151)}
    pool["spares"] = {
        SPARE_DISK: _leaf_disk(SPARE_DISK, 6161616161616161, state="AVAIL")
    }
    return payloads


def _add_cache_vdev(payloads: dict) -> dict:
    """CLASS group-enum: a vdev walk whose GROUP vdevs are an enum over the
    ones its author met — the storage twin of family-enum. storage.py declares
    the closed set ZFS_GROUP_VDEVS = {logs, l2cache, spares}; the spare-and-log
    operator mints logs and spares as a side effect of its health case, and
    l2cache was minted by nothing — so it sat outside the guard's reach exactly
    as arp did. l2cache is the group a port forgets soonest: a cache device
    holds no pool data, so dropping the group leaves the pool reading healthy
    while a whole member vanishes. Append an l2cache group with one ONLINE cache
    disk — a member the reference labels Group=l2cache like any other, and a
    groups-by-enum port emits no row for. One disk, ONLINE, so the disagreement
    is the dropped GROUP and nothing about health rides along to blur it."""
    # Top-level, like the other two groups — see _add_spares_and_logs.
    pool = _first_pool(payloads["status"])
    pool["l2cache"] = {CACHE_DISK: _leaf_disk(CACHE_DISK, 7171717171717171)}
    return payloads


# The catalogue prose `zpool status` prints for a corrected read error, kept
# byte-for-byte as OpenZFS emits it (tabs and the doubled space included) so the
# mutated document stays one zpool could have produced — and so StatusMessage,
# the member a health-blind port never reads, carries real text to erase.
POOL_FAULT_MESSAGE = (
    "One or more devices has experienced an unrecoverable error.  An\n"
    "\tattempt was made to correct the error.  Applications are unaffected."
)


def _fault_leaf(payloads: dict) -> dict:
    """CLASS health-stub: a collector that reads the pool's health from struct
    defaults instead of from the document — State the zero-value "ONLINE",
    StatusMessage never read, the two unhealthy lists initialised empty, every
    member row ONLINE with zero counters. On a healthy pool all of that is
    TRUE, which is why replay equivalence over the healthy captures cannot see
    it and the round-a5 subject stood as a deferral until corpus/storage/
    degraded was staged. This is that same fault as a MUTATION, so the class is
    regression on every healthy seed rather than one committed degraded pair:
    degrade the first pool exactly as `zpool status -j` renders a corrected
    error — pool and its raidz vdev DEGRADED, one leaf OFFLINE, another
    carrying checksum errors, the catalogue prose on the pool. The reference
    reads all of it; a health-stub port reports the pool ONLINE with empty
    unhealthy lists and no message, and the diff names every erased fact."""
    status = payloads["status"]
    pool = _first_pool(status)
    root = next(iter((pool.get("vdevs") or {}).values()), None)
    if not isinstance(root, dict) or root.get("vdev_type") != "root":
        raise MutatorError("first vdev is not the root container")
    top = next((v for v in (root.get("vdevs") or {}).values()
                if isinstance(v, dict) and v.get("vdevs")), None)
    if top is None:
        raise MutatorError("no top-level vdev with leaves to fault")
    leaves = [v for v in top["vdevs"].values() if isinstance(v, dict)]
    if len(leaves) < 2:
        raise MutatorError(
            "a health-stub needs one leaf to offline and one to error, and this "
            "pool's first vdev has fewer than two"
        )
    pool["state"] = "DEGRADED"
    pool["status"] = POOL_FAULT_MESSAGE
    root["state"] = "DEGRADED"
    top["state"] = "DEGRADED"
    leaves[0]["state"] = "OFFLINE"  # -> UnhealthyVdevs
    leaves[1]["checksum_errors"] = 3  # -> VdevsWithErrors
    return payloads


def _null_nested_member(payloads: dict) -> dict:
    """CLASS nested-null: one nested vdev member marshalled as null — what a
    struct with a nil field does in any language with a marshaller. The
    reference drops the member (null is no statement; DESIGN 19); a port
    that carries it emits a null INSIDE a fact value, one level below where
    a top-level sweep looks, and the judge must now REFUSE the stream — this
    operator exercises the recursive null rule, not the diff. The subject is
    the first leaf of the first top-level vdev, in document order."""
    for vdev in _root_children(_first_pool(payloads["status"])).values():
        for leaf in (vdev.get("vdevs") or {}).values():
            if "state" in leaf:
                leaf["state"] = None
                return payloads
    raise MutatorError("no nested leaf with a state member to null")


# ── libvirt domains ──────────────────────────────────────────────────────


def _first_nic_mac(definition: str) -> str:
    """The first NIC's MAC, read from the domain XML the way the reference
    reads it — `./devices/interface`, then the `mac` child's `address`.

    Parsed rather than pattern-matched because the payload's XML is the
    reference's own input: an operator that invented a MAC would key the lease
    map on an interface the domain does not have, which is a document libvirt
    cannot produce.
    """
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(definition)
    except ET.ParseError as exc:
        raise MutatorError(f"the domain definition does not parse: {exc}") from exc
    for iface in root.findall("./devices/interface"):
        mac = iface.find("mac")
        if mac is not None and mac.get("address"):
            return mac.get("address")
    raise MutatorError("the first domain has no interface with a MAC to lease to")


def _running_guest(payloads: dict) -> dict:
    """CLASS address-blind: a domain row that never answers "where".

    Every committed capture is of a STOPPED guest, and a stopped guest has no
    address because it is off — so the reference omits the address fact and a
    port that never implemented it emits exactly the same row. The blindness
    is invisible under replay by construction, which is DESIGN 20's third
    trap, and it is the one question an operator opens this collection to ask:
    which guest is 192.168.122.50.

    So bring the guest up and give it the lease libvirt's own default network
    would hand it. The reference reads `ips_by_mac` and publishes the address;
    an address-blind port publishes the same row without it. State moves with
    it because the two are one shape — an address on a shut-off guest is not a
    document libvirt produces, and the reference's own rule 7 arm turns on the
    state.
    """
    domains = payloads.get("domains")
    if not isinstance(domains, list) or not domains:
        raise MutatorError("the payload carries no domains")
    domain = domains[0]
    if not isinstance(domain.get("xml"), str):
        raise MutatorError("the first domain carries no XML definition")
    domain["state"] = "running"
    domain["ips_by_mac"] = {_first_nic_mac(domain["xml"]): [GUEST_ADDRESS]}
    # The note is what the adapter sets when a source ANSWERED, which is null:
    # it exists to explain a blank, and there is no blank here.
    domain["ip_note"] = None
    return payloads


# ── dpkg rows ────────────────────────────────────────────────────────────


def _removed_but_configured_row(payloads: dict) -> dict:
    """CLASS status-blind: an inventory that reports what dpkg REMEMBERS.

    dpkg keeps a row for a package that was removed with its configuration
    left behind — `rc` in `dpkg -l`, `config-files` in the status field this
    collector's format string asks for — and half a package is not an
    installed one. Every row of every committed capture is `installed`, so the
    filter that the dpkg branch exists to apply is exercised by nothing: a
    port that published every row dpkg hands over reproduces the pair exactly.
    That is DESIGN 20's third trap, and this is the shape that springs it.

    ifupdown is the specimen because a real machine produces it: netplan
    replaced it, and an upgraded Ubuntu guest carries exactly this row. It is
    inserted at its sorted position rather than appended, because
    `dpkg-query -W` lists in name order and a document out of order is not one
    dpkg could have produced — and because appending would let a port that
    published it still sort it into place, blurring which defect the
    disagreement names.

    The reference drops the row and commits 963; a status-blind port publishes
    it and commits 964, so the disagreement arrives twice over — an unexpected
    object, and the port's own count betraying it.
    """
    rows = payloads.get("dpkg")
    if not isinstance(rows, list) or not rows:
        raise MutatorError("the payload carries no dpkg rows")
    if any(row and row[0] == REMOVED_PACKAGE for row in rows):
        raise MutatorError(
            f"{REMOVED_PACKAGE} is already in this capture, so a minted row "
            "would be a duplicate rather than a removed-but-configured one"
        )
    row = [REMOVED_PACKAGE, "0.8.41ubuntu1", "amd64", "config-files"]
    at = next((i for i, existing in enumerate(rows)
               if existing and existing[0] > REMOVED_PACKAGE), len(rows))
    rows.insert(at, row)
    return payloads


# ── unbound's control socket ─────────────────────────────────────────────

# Records whose total is not a sum over the threads: an average across two
# identical threads is that average, and a high-water mark across them is that
# mark. Raising either by addition would produce a figure unbound cannot report.
_NOT_SUMMED_OVER_THREADS = (".avg", ".median", ".max")


def _keep_trailing_newline(original: str, lines: list[str]) -> str:
    """Rejoin rewritten lines without moving the document's final byte.

    The replay seam serves these payloads verbatim, and a mutation that also
    reformatted would put the harness's whitespace into the comparison.
    """
    return "\n".join(lines) + ("\n" if original.endswith("\n") else "")


def _second_resolver_thread(payloads: dict) -> dict:
    """CLASS thread-share-blind: a stats parse that cannot tell the resolver's
    TOTAL from one thread's share of it.

    `stats_noreset` reports every counter twice — once per thread as
    `threadN.…`, once summed as `total.…` — and on the single-threaded resolver
    every committed capture holds, the two are the same number on every line.
    So a port that reads `thread0.` outright, or that keys a record on its tail
    and keeps the first match it meets, reproduces the committed pair exactly
    while being wrong about every multi-threaded resolver there is. Wrong in the
    direction that matters, too: it under-reports the query load of the busiest
    hosts, because more than one thread is what a busy resolver is configured
    with.

    So give this resolver a second thread. Its traffic is minted (UNBOUND_THREAD1),
    the records that are not per-thread sums are copied rather than added, and
    every summed total rises by what the new thread did. The status document
    moves with it: `threads: 1` beside a thread1 block is not a document unbound
    produces, and the mutator's contract is a machine that could exist.
    """
    stats = payloads["stats_noreset"]
    lines = stats.splitlines()
    thread0 = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and key.startswith("thread0."):
            thread0[key[len("thread0."):]] = value
    if not thread0:
        raise MutatorError(
            "the stats payload carries no thread0 records, so there is no "
            "per-thread block to add a thread to"
        )

    def thread1(tail: str) -> str:
        return str(UNBOUND_THREAD1.get(tail, thread0[tail]))

    out: list[str] = []
    added = False
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and key.startswith("thread0."):
            out.append(line)
            continue
        if not added:
            # The first line past the thread0 block is where unbound writes the
            # next thread's, so that is where this one goes.
            out.extend(f"thread1.{tail}={thread1(tail)}" for tail in thread0)
            added = True
        if sep and key.startswith("total."):
            tail = key[len("total."):]
            if tail in thread0 and not tail.endswith(_NOT_SUMMED_OVER_THREADS):
                line = f"{key}={int(value) + int(thread1(tail))}"
        out.append(line)
    payloads["stats_noreset"] = _keep_trailing_newline(stats, out)

    status = payloads["status"]
    payloads["status"] = _keep_trailing_newline(status, [
        "threads: 2" if line.partition(":")[0].strip() == "threads" else line
        for line in status.splitlines()
    ])
    return payloads


# ── cgroupfs: the workload that was killed ───────────────────────────────


def _oom_killed_workload(payloads: dict) -> dict:
    """CLASS oom-counter-blind: an OOM KILL reported as an OOM event.

    `memory.events` keeps two counters that read almost the same and mean
    entirely different things. `oom` is how many times the workload hit its
    limit and had to reclaim or block; `oom_kill` is how many of its processes
    the kernel then killed. On any machine at rest both are 0, so a collector
    that lifted one under the other's name reproduces every committed capture
    exactly — and on the machine an operator is actually asking about, it
    reports killings that never happened, or misses the ones that did.

    That is DESIGN 20's third trap, and this is the shape that springs it. It
    matters more here than the arithmetic suggests: an OOM kill is the loudest
    thing that happens to a workload and it leaves no other trace — systemd
    restarts the service, the unit returns to active, and this counter is the
    only survivor.

    `max` moves with them because the kernel could not have produced the
    document otherwise: a limit that was never reached cannot have invoked the
    OOM killer, and the mutator's contract is a machine that could exist.

    The reference publishes MemoryOomKills 1 beside MemoryOomEvents 3; a blind
    port publishes 3 for both, so the disagreement arrives on the one row and
    names the workload it is about.
    """
    text = payloads.get(OOM_KILLED_PAYLOAD)
    if not isinstance(text, str):
        raise MutatorError(
            f"the capture has no {OOM_KILLED_PAYLOAD!r} payload, so there is "
            f"no {OOM_KILLED_UNIT} memory.events to give an OOM record to"
        )
    values = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2:
            values[fields[0]] = fields[1]
    if values.get("oom") != "0" or values.get("oom_kill") != "0":
        raise MutatorError(
            f"{OOM_KILLED_UNIT} already carries an OOM record "
            f"({values.get('oom')}/{values.get('oom_kill')}), so a minted one "
            "would be a second reading rather than the first"
        )
    minted = {"max": str(OOM_EVENTS), "oom": str(OOM_EVENTS),
              "oom_kill": str(OOM_KILLS)}
    out = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in minted:
            line = f"{fields[0]} {minted[fields[0]]}"
        out.append(line)
    payloads[OOM_KILLED_PAYLOAD] = _keep_trailing_newline(text, out)
    return payloads


# ── docker containers ────────────────────────────────────────────────────


def _container_entry(identifier: str, name: str, state: str, status: str) -> dict:
    """One /containers/json?all=1 row, as dockerd spells one.

    The members are the ones adapters/docker.py reads plus the ones every
    listing entry carries, because a row missing Image or HostConfig is not a
    document dockerd produces and the mutated payload has to stay one. No
    Labels: the minted containers belong to no compose project, which keeps the
    disagreement about the scope alone.
    """
    return {
        "Id": identifier,
        "Names": [f"/{name}"],
        "Image": "busybox:latest",
        "ImageID": "sha256:" + identifier,
        "Command": "sh -c 'while :; do sleep 3600; done'",
        # Inside the corpus's own window, so the row reads as one taken beside
        # the captured containers rather than at some unrelated moment.
        "Created": 1787128180,
        "Ports": [],
        "Labels": {},
        "State": state,
        "Status": status,
        "HostConfig": {"NetworkMode": "bridge"},
        "NetworkSettings": {"Networks": {}},
        "Mounts": [],
    }


def _append_container(payloads: dict, entry: dict) -> dict:
    listing = payloads.get("containers-json-all-1")
    if not isinstance(listing, list):
        raise MutatorError("the payload carries no container listing")
    if any(isinstance(row, dict) and row.get("Id") == entry["Id"] for row in listing):
        raise MutatorError(
            f"{entry['Id']} is already in this capture, so a minted row would be "
            "a duplicate rather than a new container"
        )
    listing.append(entry)
    return payloads


def _restarting_container(payloads: dict) -> dict:
    """CLASS scoped-state-enum: a scope name derived from the states its author
    met. adapters/docker.py declares the closed set _SCOPED_STATES — the states
    that HAVE processes and therefore a live scope cgroup — and `running` is
    only one of its three. A port whose rule is `state == "running"`, which is
    the simplification anybody writes first, is right about every container in
    every committed capture and wrong about a crash-looping one.

    That is the container an operator most wants to find. A restarting container
    is burning CPU right now, its scope is where the kernel keeps the accounting
    that says so, and a port that omits ScopeUnit there breaks the only edge
    from units/units back to a name a person recognises — precisely when
    somebody is looking.

    The Status string is dockerd's own spelling for the state, because a
    document whose Status disagrees with its State is not one dockerd produces
    and the reference's opinion evaluator reads both.
    """
    return _append_container(
        payloads,
        _container_entry(RESTARTING_ID, RESTARTING_CONTAINER, "restarting",
                         "Restarting (1) 3 seconds ago"),
    )


def _paused_container(payloads: dict) -> dict:
    """CLASS scoped-state-enum, the paused spelling: the third member of
    _SCOPED_STATES and the one an enum reaches last.

    Staged separately for the same reason the nftables families are: an enum
    port that has learned `restarting` the hard way still drops `paused`, and a
    closed set is closed member by member or not at all. A paused container is
    frozen by the freezer cgroup with every process still resident — its scope
    is very much alive, which is exactly what makes the omission look
    defensible and be wrong.
    """
    return _append_container(
        payloads,
        _container_entry(PAUSED_ID, PAUSED_CONTAINER, "paused", "Up 4 minutes (Paused)"),
    )


# ── bazarr's managers ────────────────────────────────────────────────────


def _wired_managers(payloads: dict) -> dict:
    """CLASS manager-version-blind: an instance row that never says what it is
    wired to.

    `/api/system/status` reports the sonarr and radarr this bazarr fetches its
    metadata from, and reports them as EMPTY STRINGS when it is wired to
    neither. The captured instance is wired to neither, so both members are
    present and empty, the reference's truthiness gate drops both, and a port
    that never implemented either fact emits exactly the same row. The
    blindness is invisible under replay by construction, which is DESIGN 20's
    third trap — and it is blindness about the thing bazarr exists to do,
    since a subtitle manager wired to no manager has nothing to fetch
    subtitles for.

    So wire it to both. The reference lifts each member because it is now
    truthy and publishes two more facts; a manager-blind port publishes the
    same row without them. Both at once rather than one operator each: the
    two members are read by one loop over one pairing, so a port blind to
    either is blind to both, and splitting them would claim a member-by-member
    closure this class does not have.
    """
    status = payloads.get("api-system-status")
    if not isinstance(status, dict):
        raise MutatorError("the payload carries no status document")
    data = status.get("data")
    if not isinstance(data, dict):
        raise MutatorError("the status document carries no data mapping")
    for member in ("sonarr_version", "radarr_version"):
        if data.get(member):
            raise MutatorError(
                f"{member} is already populated in this capture, so wiring a "
                "manager in would be overwriting a reading rather than "
                "minting the shape no capture holds"
            )
    data["sonarr_version"] = BAZARR_SONARR_RELEASE
    data["radarr_version"] = BAZARR_RADARR_RELEASE
    return payloads


# ── traefik's ingress tier ───────────────────────────────────────────────


def _sorted_insert(listing: list, entry: dict, what: str) -> None:
    """Put one API entry at the position Traefik would have listed it.

    The listing endpoints answer in name order, so an appended entry is a
    document Traefik could not have produced — and it would also let a
    challenger that publishes the entry still sort it into place, blurring which
    defect the disagreement names. Same reasoning as the dpkg row above.
    """
    if any(isinstance(row, dict) and row.get("name") == entry["name"] for row in listing):
        raise MutatorError(
            f"{entry['name']} is already in this capture, so a minted {what} "
            "would be a duplicate rather than a new one"
        )
    at = next((i for i, row in enumerate(listing)
               if isinstance(row, dict) and str(row.get("name", "")) > entry["name"]),
              len(listing))
    listing.insert(at, entry)


def _bump_count(overview: dict, family: str, member: str, by: int) -> None:
    counts = ((overview.get("http") or {}).get(family) or {})
    if member not in counts:
        raise MutatorError(
            f"the overview payload carries no http.{family}.{member} to move, so "
            "the mutated document's totals would disagree with its listings"
        )
    counts[member] += by


def _dynamic_provider(payloads: dict) -> dict:
    """CLASS dynamic-provider-blind: a collector written against a proxy that
    fronts nothing.

    A Traefik with no dynamic providers publishes only its own internal routers
    and services, and that is the whole committed capture — it is the universal
    shape, present on every install, and it is also the shape in which nine of
    this collector's declared facts are unreachable. An internal service carries
    no `type`, no `loadBalancer` and no `serverStatus`; an internal router
    carries no `tls` and no `error`; an overview with no providers carries no
    `providers`. So a port that never implemented any of them reproduces the
    committed pair exactly while being blind to everything the collector exists
    to say about a real ingress tier. That is DESIGN 20's third trap, and this
    is the transformation that springs it.

    One deploy, and the whole of what a deploy brings: a file provider appears
    with one TLS'd application on two backends — one of which is down — and one
    route whose rule Traefik refused. The counts on the overview move with it,
    the provider list appears, the entries land at their sorted positions, and
    the rejected router's own words ride on its row. Measured on a live Traefik
    3.1.7 rather than composed from the documentation: `serverStatus` is emitted
    for any loadbalancer service and not only for a health-checked one, `tls`
    carries `options` beside the resolver, and the refused router keeps its rule
    while losing its `ruleSyntax`.

    The disagreement it exposes is the one that matters at this tier. A
    green router over ServersDown is a front door onto nothing — the route
    exists, the service loaded, the proxy is up, and every request 502s — and a
    rejected route is configuration somebody wrote that carries no traffic. A
    blind port publishes both as ordinary healthy rows, with the overview's own
    error count beside them saying one router is broken and nothing saying
    which.
    """
    overview = payloads["api-overview"]
    routers = payloads["api-http-routers"]
    services = payloads["api-http-services"]
    if not isinstance(routers, list) or not isinstance(services, list):
        raise MutatorError("the routers and services payloads are not listings")
    if "providers" in overview:
        raise MutatorError(
            "this capture already names its providers, so the seed is not the "
            "no-dynamic-provider shape this operator adds one to"
        )

    _sorted_insert(routers, {
        "entryPoints": ["web"],
        "service": "labapp",
        "rule": "Host(`labapp.example.com`)",
        "priority": 26,
        "tls": {"options": "default", "certResolver": TRAEFIK_CERT_RESOLVER},
        "status": "enabled",
        "using": ["web"],
        "name": TRAEFIK_APP,
        "provider": "file",
    }, "router")
    _sorted_insert(routers, {
        "entryPoints": ["web"],
        "service": "labapp",
        "rule": "Hostx(`nope.example.com`)",
        "priority": 25,
        "error": [TRAEFIK_ROUTER_ERROR],
        "status": "disabled",
        "using": ["web"],
        "name": TRAEFIK_REJECTED_ROUTER,
        "provider": "file",
    }, "router")
    _sorted_insert(services, {
        "loadBalancer": {
            "servers": [{"url": TRAEFIK_UP_BACKEND}, {"url": TRAEFIK_DOWN_BACKEND}],
            "healthCheck": {"mode": "http", "path": "/", "interval": "3s",
                            "timeout": "2s", "followRedirects": True},
            "passHostHeader": True,
            "responseForwarding": {"flushInterval": "100ms"},
        },
        "status": "enabled",
        # Both routers point at this service, the refused one included: Traefik
        # records the reference whether or not the router it came from routes.
        "usedBy": [TRAEFIK_REJECTED_ROUTER, TRAEFIK_APP],
        "serverStatus": {TRAEFIK_UP_BACKEND: "UP", TRAEFIK_DOWN_BACKEND: "DOWN"},
        "name": TRAEFIK_APP,
        "provider": "file",
        "type": "loadbalancer",
    }, "service")

    # A document whose totals disagree with its listings is not one Traefik
    # produces, and the error count in particular is the figure a blind port
    # keeps reporting while no row explains it.
    _bump_count(overview, "routers", "total", 2)
    _bump_count(overview, "routers", "errors", 1)
    _bump_count(overview, "services", "total", 1)
    # Traefik writes the provider list after `features`, and only once a
    # provider other than its internal one is configured.
    overview["providers"] = ["File"]
    return payloads


# ── the servarr fleet ────────────────────────────────────────────────────


def _servarr_document(payloads: dict, stem: str) -> dict:
    document = payloads.get(stem)
    if not isinstance(document, dict):
        raise MutatorError(f"the payload set carries no {stem} document")
    return document


def _grab_in_flight(payloads: dict) -> dict:
    """CLASS stuck-reason-blind: a queue row that says `warning` and not why.

    The captured fleet has never downloaded anything: its queue holds no
    records, its trail holds no events, and /queue/status reports zero. So
    every fact the queue and history collections publish is reached by no
    committed capture, and a port that implemented neither collection's row
    beyond its name reproduces the pair exactly. That is DESIGN 20's third
    trap, and an idle fleet is the purest form of it — the collections that
    answer the question are the two with nothing in them.

    So put ONE acquisition through the fleet, in the three places a real one
    appears at once, because a document whose members disagree with each other
    is not one these apps produce:

      · the grab in radarr's own trail, with the indexer and client that
        carried it and the quality it was graded;
      · the download it created in radarr's queue — completed, zero bytes
        left, and the app's own verdict that it will not import, which is the
        shape this collection exists to surface;
      · the queue SUMMARY moving with it, because totalCount 0 beside a
        record is not a reading any app produces;
      · and the same release in prowlarr's history as `releaseGrabbed`, which
        is what the indexer proxy files when it hands a link over. The
        reference never reads that document — prowlarr excludes itself from
        the trail by its own appName — so it is inert to both sides today and
        is minted anyway: it is the tempting document a port that keyed the
        exclusion on the instance name would read, and leaving it out would
        make the mutated fleet a machine that could not exist.

    The defect class this EXPOSES is narrower than what it mints, and
    deliberately so. The stuck verdict itself rides members the reference
    writes unconditionally, so a payload cannot take one away without making
    the reference publish a null fact — unlawful under the contract's
    recursive fact_value, and a REFUSED verdict about the reference rather
    than a disagreement about the port. What a payload CAN take away is the
    app's own explanation: statusMessages and errorMessage are conditional,
    and a port that publishes the verdict without them leaves an operator
    holding `warning` and no reason.
    """
    queue = _servarr_document(payloads, "radarr-api-v3-queue")
    if queue.get("records"):
        raise MutatorError(
            "the captured queue already holds records, so a minted one would "
            "be a second download rather than the first"
        )
    queue["records"] = [{
        "id": 91,
        "title": SERVARR_TITLE,
        "status": "completed",
        "trackedDownloadStatus": "warning",
        "trackedDownloadState": "importPending",
        "downloadClient": SERVARR_CLIENT,
        "indexer": SERVARR_INDEXER,
        "protocol": "torrent",
        "downloadId": SERVARR_DOWNLOAD_ID,
        "size": 8589934592,
        "sizeleft": 0,
        "errorMessage": SERVARR_ERROR_MESSAGE,
        "statusMessages": [{
            "title": SERVARR_TITLE,
            "messages": [SERVARR_STUCK_MESSAGE],
        }],
    }]
    queue["totalRecords"] = 1

    summary = _servarr_document(payloads, "radarr-api-v3-queue-status")
    summary["totalCount"] = 1
    summary["count"] = 1
    summary["warnings"] = True

    trail = _servarr_document(payloads, "radarr-api-v3-history")
    trail["records"] = [{
        "id": 4711,
        "eventType": "grabbed",
        "sourceTitle": SERVARR_TITLE,
        "downloadId": SERVARR_DOWNLOAD_ID,
        "date": "2026-08-19T09:58:11Z",
        "quality": {"quality": {"id": 7, "name": "Bluray-1080p"},
                    "revision": {"version": 1, "real": 0, "isRepack": False}},
        "data": {"indexer": SERVARR_INDEXER, "downloadClient": SERVARR_CLIENT,
                 "releaseGroup": "MUTGRP"},
    }]
    trail["totalRecords"] = 1

    audit = _servarr_document(payloads, "prowlarr-api-v1-history")
    audit["records"] = [{
        "id": 812,
        "eventType": "releaseGrabbed",
        "date": "2026-08-19T09:58:10Z",
        "data": {"source": "Prowlarr", "grabTitle": SERVARR_TITLE},
    }]
    audit["totalRecords"] = 1
    return payloads


# ── kea reservations ─────────────────────────────────────────────────────


def _addressless_reservation(payloads: dict) -> dict:
    """CLASS unlistable-remainder: an inventory that lists what it counts.

    A Kea host reservation does not have to pin an address. One that states a
    hostname alone hands a client its NAME — which is what a DHCP server is for
    on a network where DNS is fed from leases — and one that states only
    client-classes pins a class. Both are ordinary configuration, and neither
    can mint a stable id: `reservation:<subnet>/<ip>` has no ip to be keyed on.

    So the reference COUNTS them and does not LIST them, and says so on the wire
    rather than in a docstring: the subnet row carries ReservationCount over
    every entry the configuration holds and UnlistedReservations over the ones no
    row can carry, so a reader who subtracts gets the number of rows. That is
    rule 7's stated remainder, and it exists because the two would otherwise
    quietly disagree and only source-reading would explain why.

    A port that filters the list once, at the top, and then counts what survived
    reproduces every committed pair exactly: every reservation in the only kea
    capture states an address, so the filter removes nothing and the remainder is
    nil. Its ReservationCount is the number of rows BY CONSTRUCTION and can never
    disagree with the listing — which reads as consistency and is under-reporting
    the machine's configuration. That is DESIGN 20's third trap, and this is the
    shape that springs it.

    Inserted at the end of the subnet's own reservations rather than globally,
    because a global reservation exercises a different arm of the walk, and the
    hostname is a plausible one: a printer somebody pinned a name to and never
    an address.
    """
    subnets = ((payloads.get("config-get") or {}).get("arguments") or {}) \
        .get("Dhcp4", {}).get("subnet4")
    if not isinstance(subnets, list) or not subnets:
        raise MutatorError("the config payload declares no top-level subnet4")
    reservations = subnets[0].setdefault("reservations", [])
    if any(isinstance(r, dict) and r.get("hostname") == KEA_UNLISTED_HOST
           for r in reservations):
        raise MutatorError(
            f"{KEA_UNLISTED_HOST} is already in this capture, so a minted entry "
            "would be a duplicate rather than an unlistable reservation"
        )
    # The members Kea normalises onto every reservation, so the mutated document
    # stays one config-get could have produced — an entry missing them is not a
    # reservation this daemon would hand back.
    reservations.append({
        "boot-file-name": "",
        "client-classes": [],
        "client-id": "01ANON7F3C21",
        "hostname": KEA_UNLISTED_HOST,
        "next-server": "0.0.0.0",
        "option-data": [],
        "server-hostname": "",
    })
    return payloads


# ── download clients ─────────────────────────────────────────────────────


def _transmission_tracker_error(payloads: dict) -> dict:
    """CLASS error-text-blind: a transfer row that carries the error CODE and
    never the client's own words.

    This subsystem exists for the invisible middle — a manager says "grabbed",
    a library says "missing", and nothing shows the transfer erroring in
    between — and ErrorString is the only fact in it that says WHAT went wrong.
    It is also the fact no committed capture can reach: every torrent in
    corpus/downloaders/healthy reports error 0 with an empty errorString,
    because a staged lab torrent announces to a host that does not resolve and
    therefore never gets a reply to be refused by. So the reference's own guard
    — publish the line only when the code is non-zero AND the member is
    non-empty — is exercised by nothing, and a port that never implemented the
    arm at all reproduces every committed pair exactly.

    Give the first torrent, in document order, a tracker that has forgotten it.
    Code and text move together because a document with one and not the other
    is not one transmission produces: the code is what the daemon assigns and
    the text is what it stored beside it, and the reference reads both before
    it publishes either.
    """
    document = payloads.get("torrent-get")
    torrents = document.get("torrents") if isinstance(document, dict) else None
    if not isinstance(torrents, list) or not torrents:
        raise MutatorError("the payload carries no torrents to fault")
    first = torrents[0]
    if first.get("error"):
        raise MutatorError(
            "the first torrent already carries a non-zero error, so this "
            "operator would overwrite a staged fault rather than mint one"
        )
    first["error"] = TRANSFER_ERROR_CODE
    first["errorString"] = TRANSFER_ERROR_TEXT
    return payloads


@dataclass(frozen=True)
class Operator:
    """One structural transformation, bound to the defect class it exposes."""

    name: str
    collector: str  # whose payload grammar it rewrites
    exposes: str  # the collector-defect class, the contract tests bind to
    apply: Callable[[dict], dict]


OPERATORS: tuple[Operator, ...] = (
    Operator("nft-netdev-ingress", "network", "family-enum", _add_netdev_ingress),
    Operator("nft-bridge-family", "network", "family-enum", _add_bridge_family),
    Operator("nft-arp-family", "network", "family-enum", _add_arp_family),
    Operator("nft-second-caller", "network", "single-caller", _second_caller),
    Operator("nft-jump-to-goto", "network", "goto-blind", _jump_to_goto),
    Operator("nft-named-map", "network", "map-blind", _add_verdict_map),
    Operator("zpool-mixed-stripe", "storage", "first-vdev-redundancy",
             _append_stripe_vdev),
    Operator("zpool-scan-running", "storage", "epoch-zero-scan",
             _scan_running_now),
    Operator("zpool-resilver-overwrote-scrub", "storage", "scan-function-blind",
             _resilver_overwrote_the_scrub),
    Operator("zpool-spares-and-logs", "storage", "spare-as-unhealthy",
             _add_spares_and_logs),
    Operator("zpool-cache-vdev", "storage", "group-enum", _add_cache_vdev),
    Operator("zpool-nulled-member", "storage", "nested-null",
             _null_nested_member),
    Operator("zpool-faulted-leaf", "storage", "health-stub", _fault_leaf),
    Operator("libvirt-running-guest", "vms", "address-blind", _running_guest),
    Operator("dpkg-removed-config-row", "packages", "status-blind",
             _removed_but_configured_row),
    Operator("unbound-second-thread", "unbound", "thread-share-blind",
             _second_resolver_thread),
    Operator("cgroup-oom-kill", "resources", "oom-counter-blind",
             _oom_killed_workload),
    Operator("docker-restarting-container", "docker", "scoped-state-enum",
             _restarting_container),
    Operator("docker-paused-container", "docker", "scoped-state-enum",
             _paused_container),
    Operator("bazarr-wired-managers", "bazarr", "manager-version-blind",
             _wired_managers),
    Operator("traefik-dynamic-provider", "traefik", "dynamic-provider-blind",
             _dynamic_provider),
    Operator("servarr-grab-in-flight", "servarr", "stuck-reason-blind",
             _grab_in_flight),
    Operator("kea-addressless-reservation", "kea", "unlistable-remainder",
             _addressless_reservation),
    Operator("transmission-errored-transfer", "downloaders", "error-text-blind",
             _transmission_tracker_error),
)


# ── the closed classes: finite spaces the guard promises to cover ────────
#
# An `exposes=` label that names a FINITE, DECLARED set makes a promise the
# operators alone cannot keep: that the guard closes that set member by member.
# family-enum says it; group-enum says it. The promise is kept only if EVERY
# declared member is OWNED — by a committed capture (the replay judge sees it
# without mutation), by an operator (this guard mints it), or by a named
# residual (it genuinely cannot be minted, and the live comparator is the venue
# that catches it instead). A member owned by none is the subset guard the
# label hides: two operators carrying `exposes="family-enum"` asserted the
# whole family class was covered while `arp` was minted by nothing and named
# nowhere — a walk enumerating the families its author met, one level up.
#
# So the guard does not TRUST the operator author to have minted the whole set.
# It derives the full membership from the PRODUCT'S own authority (the
# conformance test reads network.py's Family glossary and storage.py's
# ZFS_GROUP_VDEVS — never a list retyped here, which would drift into agreement
# with a broken walk), partitions it, and fails by NAME on any orphan. The
# extractors below read the SAME structures the operators mint and the
# reference walks — a family off every nft object, a name off every vdev — so
# "present in this payload" is answered the one way the product answers it.
#
# The audit that fixed the set at two: only family-enum and group-enum name a
# finite declared member space. single-caller, goto-blind, map-blind,
# first-vdev-redundancy, epoch-zero-scan, spare-as-unhealthy, nested-null and
# health-stub each name a structural or semantic defect shape, not an
# enumerable set with a per-member operator obligation — there is no roster to
# leave a hole in. The residual ledgers are empty because arp and l2cache CAN
# be minted (the operators above do), and a residual is only for a member that
# cannot: an entry here must be a true "no operator can stage this", with the
# live comparator named as where it is caught instead.


def nft_families_in(payloads: dict) -> frozenset[str]:
    """Every address family named on any nft object in a network payload — the
    raw tokens present, for the closure guard to intersect with the family set
    network.py declares. Reads `family` off every table, chain, rule and map,
    the same member the operators mint and _nft_chains walks."""
    doc = payloads.get("nft") or {}
    return frozenset(
        obj["family"]
        for entry in doc.get("nftables", [])
        for obj in entry.values()
        if isinstance(obj, dict) and isinstance(obj.get("family"), str)
    )


def zpool_vdev_names_in(payloads: dict) -> frozenset[str]:
    """Every vdev name anywhere in a storage status payload — the raw tokens
    the closure guard intersects with storage.py's ZFS_GROUP_VDEVS.

    Both places, because zpool uses both. A group vdev is named by the KEY it
    sits under, and `zpool status -j` carries spares, logs and l2cache as
    TOP-LEVEL keys on the pool object rather than as nodes inside its vdevs
    tree — so this walked pool["vdevs"] alone and, handed a real payload
    holding all three, reported that none of them were present. The closure
    guard over `group-enum` was therefore vacuous against reality and
    substantive only against the fabricated placement the operators minted,
    which is the subset-guard shape reading the wrong address: the extractor
    that decides what a payload contains was looking where the defect was,
    not where the data is.
    """
    names: set[str] = set()

    def _walk(nodes: object) -> None:
        if not isinstance(nodes, dict):
            return
        for name, vdev in nodes.items():
            names.add(name)
            if isinstance(vdev, dict):
                _walk(vdev.get("vdevs"))

    for pool in (payloads.get("status") or {}).get("pools", {}).values():
        if not isinstance(pool, dict):
            continue
        _walk(pool.get("vdevs"))
        # The group keys themselves are the members of the declared set, so
        # their presence is the key's presence — the nodes beneath are the
        # devices, whose names are not group names.
        for group in ZFS_GROUP_KEYS:
            if isinstance(pool.get(group), dict):
                names.add(group)
                _walk(pool[group])
    return frozenset(names)


# The group keys as zpool spells them at pool level. Not retyped from the
# product's ZFS_GROUP_VDEVS by accident: the conformance test reads the
# product's set as the authority and this is only where to LOOK for them, so
# a set that drifted would be caught by the closure test rather than hidden.
ZFS_GROUP_KEYS = ("logs", "l2cache", "spares")


def container_states_in(payloads: dict) -> frozenset[str]:
    """Every State any container row in a docker payload names — the raw tokens
    present, for the closure guard to intersect with the scope-bearing set
    adapters/docker.py declares. Reads the same member the operators mint and
    _scope_unit branches on, which is the one way the product answers it."""
    listing = payloads.get("containers-json-all-1")
    if not isinstance(listing, list):
        return frozenset()
    return frozenset(
        row["State"]
        for row in listing
        if isinstance(row, dict) and isinstance(row.get("State"), str)
    )


@dataclass(frozen=True)
class ClosedClass:
    """One `exposes=` label that claims to close a finite declared set. The
    conformance test reads `authority` to get the full membership from the
    product, calls `members_in` to find which members a payload carries, and
    holds the partition {judge ∪ guard ∪ residual} exhaustive over the whole."""

    label: str  # the exposes= label whose promise this makes checkable
    collector: str
    authority: str  # where the product declares the set, for the test and a human
    members_in: Callable[[dict], frozenset[str]]  # raw tokens present in a payload
    residual: dict[str, str]  # member -> true reason it cannot be minted (venue: live comparator)


CLOSED_CLASSES: tuple[ClosedClass, ...] = (
    ClosedClass(
        label="family-enum",
        collector="network",
        authority="system_explorer.agent.adapters.network, the nft Family glossary",
        members_in=nft_families_in,
        residual={},
    ),
    ClosedClass(
        label="group-enum",
        collector="storage",
        authority="system_explorer.agent.adapters.storage.ZFS_GROUP_VDEVS",
        members_in=zpool_vdev_names_in,
        residual={},
    ),
    ClosedClass(
        label="scoped-state-enum",
        collector="docker",
        authority="system_explorer.agent.adapters.docker._SCOPED_STATES",
        members_in=container_states_in,
        residual={},
    ),
)


def mutated_payloads(operator: Operator, variant: Variant) -> dict:
    """The operator applied to a deep copy of the seed's payloads, so the
    in-process corpus is never edited under another test's feet."""
    if variant.meta["collector"] != operator.collector:
        raise MutatorError(
            f"{operator.name} rewrites {operator.collector} payloads; "
            f"{variant.name} is a {variant.meta['collector']} variant"
        )
    return operator.apply(copy.deepcopy(variant.payloads))


def write_payloads(payloads: dict, directory: Path, suffixes: dict[str, str]) -> None:
    """Write a mutated payload set back out the way the loader reads it.

    Keyed by stem, and the extension comes from the VARIANT
    (corpus.Variant.payload_suffixes) rather than from the value's type: a
    `.json` payload round-trips through json.dumps, and a text payload —
    os-release, a hostname, a boot id — is written back as raw bytes under its
    bare stem, because the native format IS the payload (DESIGN 20).

    Writing every stem as `.json` was silent and total: a text-payload
    collector routed through this guard would be handed `os-release.json`
    holding a JSON-quoted string, a directory its own replay seam cannot
    read, and the run would report REFUSED about the collector rather than
    about the harness.

    Deciding on the value's TYPE instead was the same defect one layer in, and
    the packages collector is where it surfaced: manager.json is a JSON
    document whose whole content is the string "dpkg", so a type test writes it
    as a bare `manager` file the seam does not glob, and the collector replays
    with no manager at all. The suffix is the half load_variant throws away, so
    it is a required argument — a caller that cannot say which form a payload
    was committed in has no business writing one back.
    """
    directory.mkdir(parents=True, exist_ok=True)
    for stem, document in payloads.items():
        if stem not in suffixes:
            raise MutatorError(
                f"payload {stem!r} is not one the seed committed, so nothing "
                "here knows what file it should be — an operator that mints a "
                "payload states its form"
            )
        path = directory / f"{stem}{suffixes[stem]}"
        if suffixes[stem] == ".json":
            path.write_text(json.dumps(document, indent=1))
        else:
            path.write_text(document)


@dataclass
class DifferentialRun:
    """One (challenger, seed, operator) run, with everything the verdict
    rests on kept inspectable — a verdict a test cannot interrogate is a
    verdict a test can only trust."""

    operator: Operator
    variant_name: str
    verdict: str
    differences: list[str] = field(default_factory=list)
    reference_problems: list[str] = field(default_factory=list)
    challenger_problems: list[str] = field(default_factory=list)
    reference_emitted: list[dict] = field(default_factory=list)
    challenger_emitted: list[dict] = field(default_factory=list)

    def report(self) -> str:
        head = f"{self.variant_name} × {self.operator.name}: {self.verdict}"
        lines = [
            *(f"  reference: {p}" for p in self.reference_problems[:10]),
            *(f"  challenger: {p}" for p in self.challenger_problems[:10]),
            *(f"  - {d}" for d in self.differences[:10]),
        ]
        return "\n".join([head, *lines])


def _side(proc, issued: dict[str, int]) -> tuple[list[dict], list[str]]:
    """One collector's stream and its stream-rule problems. A crash or an
    empty stream is a problem in the same channel: 'I could not run' is not
    a reading, so it can never reach the diff as one."""
    if proc.returncode != 0:
        return [], [
            f"collector exited {proc.returncode}; non-zero means "
            f'"I could not run", never a verdict about the machine: '
            f"{proc.stderr.strip()[:500]}"
        ]
    emitted = replay.parse_stream(proc.stdout)
    if not emitted:
        return [], ["collector emitted nothing"]
    return emitted, replay.check_stream(emitted, issued)


def run_differential(
    challenger: list[str],
    variant: Variant,
    operator: Operator,
    workdir: Path | None = None,
) -> DifferentialRun:
    """Reference and challenger over the same mutated payloads; disagreement
    is the verdict (DESIGN 20).

    The issuance is seeded per (variant, operator) — every run gets its own
    generation map, so a challenger that bakes in a number instead of
    parsing the request line is refused on every operator alike, by the same
    no-constant-passes-everywhere property the committed corpus already
    enforces.

    REFUSED is raised by EITHER side's stream-rule problems: a run whose
    reference half is unlawful proves nothing about the challenger, and the
    control test (reference as its own challenger) is what pins every
    refusal on the correct side.
    """
    payloads = mutated_payloads(operator, variant)
    issued = replay.issue_generations(
        variant.collections(), seed=f"{variant.name}::{operator.name}"
    )

    def _run(directory: Path) -> DifferentialRun:
        write_payloads(payloads, directory, variant.payload_suffixes)
        reference = replay.run_collector(
            replay.reference_binary(), variant, payload_dir=directory,
            issued=issued,
        )
        challenged = replay.run_collector(
            challenger, variant, payload_dir=directory, issued=issued
        )
        reference_emitted, reference_problems = _side(reference, issued)
        challenger_emitted, challenger_problems = _side(challenged, issued)
        differences = (
            replay.diff(reference_emitted, challenger_emitted)
            if reference_emitted and challenger_emitted
            else []
        )
        if reference_problems or challenger_problems:
            verdict = REFUSED
        elif differences:
            verdict = DISAGREE
        else:
            verdict = AGREE
        return DifferentialRun(
            operator=operator,
            variant_name=variant.name,
            verdict=verdict,
            differences=differences,
            reference_problems=reference_problems,
            challenger_problems=challenger_problems,
            reference_emitted=reference_emitted,
            challenger_emitted=challenger_emitted,
        )

    if workdir is not None:
        return _run(workdir)
    with tempfile.TemporaryDirectory(prefix="se-differential-") as tmp:
        return _run(Path(tmp))
