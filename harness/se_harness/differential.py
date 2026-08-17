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
SEEDS = {"network": "network/healthy", "storage": "storage/healthy"}

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


def _add_spares_and_logs(payloads: dict) -> dict:
    """CLASS spare-as-unhealthy: a spare sits AVAIL — attached to nothing,
    protecting nothing yet — and a log device is a data-path helper, not a
    data vdev. A port whose health test is `state != ONLINE` reports the
    AVAIL spare as an unhealthy member of a pool it is merely standing by
    for; a port whose redundancy walk counts group members would grade the
    layout by devices that hold no pool data. The reference does neither."""
    children = _root_children(_first_pool(payloads["status"]))
    children["logs"] = {
        "name": "logs",
        "vdevs": {LOG_DISK: _leaf_disk(LOG_DISK, 5151515151515151)},
    }
    children["spares"] = {
        "name": "spares",
        "vdevs": {
            SPARE_DISK: _leaf_disk(SPARE_DISK, 6161616161616161, state="AVAIL")
        },
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
    children = _root_children(_first_pool(payloads["status"]))
    children["l2cache"] = {
        "name": "l2cache",
        "vdevs": {CACHE_DISK: _leaf_disk(CACHE_DISK, 7171717171717171)},
    }
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
    Operator("zpool-spares-and-logs", "storage", "spare-as-unhealthy",
             _add_spares_and_logs),
    Operator("zpool-cache-vdev", "storage", "group-enum", _add_cache_vdev),
    Operator("zpool-nulled-member", "storage", "nested-null",
             _null_nested_member),
    Operator("zpool-faulted-leaf", "storage", "health-stub", _fault_leaf),
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
    the closure guard intersects with storage.py's ZFS_GROUP_VDEVS. A group
    vdev is told from a data vdev by its NAME and nothing else (storage.py's
    _flatten_vdevs keys `name in ZFS_GROUP_VDEVS`), so the name is exactly what
    is collected, descending the vdevs tree the way that walk does."""
    names: set[str] = set()

    def _walk(nodes: object) -> None:
        if not isinstance(nodes, dict):
            return
        for name, vdev in nodes.items():
            names.add(name)
            if isinstance(vdev, dict):
                _walk(vdev.get("vdevs"))

    for pool in (payloads.get("status") or {}).get("pools", {}).values():
        if isinstance(pool, dict):
            _walk(pool.get("vdevs"))
    return frozenset(names)


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


def write_payloads(payloads: dict, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for stem, document in payloads.items():
        (directory / f"{stem}.json").write_text(json.dumps(document, indent=1))


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
        write_payloads(payloads, directory)
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
