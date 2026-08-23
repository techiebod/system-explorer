#!/usr/bin/env python3
"""Adversary fixture — the eight-defect port: green under replay, forever.

A second implementation of the collector contract, written from scratch: it
reads the native documents from SE_REPLAY_DIR, parses them itself, and speaks
DESIGN 18's request/stream contract on stdin/stdout, sharing no code with the
reference. It is also wrong about the machine in EIGHT ways, each marked
DEFECT below — and every committed corpus pair judges it correct.

That is not a staging gap to close with one more variant; it is DESIGN 20's
third trap made flesh. Replay equivalence proves a collector right about the
machines the corpus holds and nothing else, so a port whose blind spots fall
outside the captured shapes is green by construction, and every variant added
only moves the frontier. test_adversaries_stay_red.py therefore carries this
fixture as an ADJUDICATED GREEN — the honest verdict of the replay judge —
and its red lives in conformance/test_differential.py, where the differential
guard mutates the corpus payloads into shapes a real machine could exhibit
and requires each defect class to visibly disagree with the reference, or be
refused outright.

The roster, and the operator that exposes each class:

  1  single-caller JumpedFrom      -> nft-second-caller        (DISAGREE)
  2  family enum {ip, ip6, inet}   -> nft-netdev-ingress,
                                      nft-bridge-family        (DISAGREE)
  3  first-vdev redundancy         -> zpool-mixed-stripe       (DISAGREE)
  4  epoch-zero scan end time      -> zpool-scan-running       (DISAGREE)
  5  constant `at`                 -> NO operator — a pinned clock cannot
                                      authenticate a reading; the live
                                      comparator owns time itself (DESIGN 19,
                                      the ownership law). The deferral is
                                      executed, not assumed:
                                      test_differential.py proves the wrong
                                      bytes are on the wire AND the verdict
                                      stays AGREE.
  6  spare counted unhealthy       -> zpool-spares-and-logs    (DISAGREE)
  7  unparsed request line         -> any operator's issuance  (REFUSED) —
                                      gated behind SE_PORT_NO_REQUEST_PARSE
                                      because always-on it would refuse every
                                      run and un-attribute the other seven
  8  nested null members           -> zpool-nulled-member      (REFUSED)

Every one of these is the kind of thing an ordinary port produces — a Go
map[string]string where a set was needed, an enum over the families the
author had met, a struct marshalled with its nil members — which is what
makes the mutated payloads fair: the reference handles each one meaningfully,
so a disagreement is a defect and never a fuzzer tripping a parser.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# DEFECT 5: `at` is a constant. The judge drops it from the byte diff and
# rules it for shape only — finite, boot-scale, non-decreasing — so a port
# that never reads a monotonic clock passes, and must: replay pins the clock,
# so no replay-side rule can tell this constant from a reading (DESIGN 19).
AT = 1.0

# DEFECT 2: an enum over the families this port's author had met. A chain in
# the bridge, arp or netdev family is dropped on the floor — including the
# netdev ingress chains that are the first thing a packet meets.
KNOWN_FAMILIES = {"ip", "ip6", "inet"}

GROUP_VDEVS = {"logs", "l2cache", "spares"}
PARITY = re.compile(r"^(raidz|draid)(\d)")


def fail(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def emit(record: dict) -> None:
    sys.stdout.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def now() -> float:
    pinned = os.environ.get("SE_REPLAY_NOW")
    if pinned:
        return datetime.fromisoformat(pinned.replace("Z", "+00:00")).timestamp()
    import time

    return time.time()


# ── nftables ─────────────────────────────────────────────────────────────


def _verdict_targets(node) -> list[str]:
    """Every jump/goto target anywhere in an expression tree."""
    found: list[str] = []
    if isinstance(node, dict):
        for verb in ("jump", "goto"):
            if verb in node and isinstance(node[verb], dict):
                target = node[verb].get("target")
                if target:
                    found.append(str(target))
        for value in node.values():
            found.extend(_verdict_targets(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_verdict_targets(value))
    return found


def _map_references(node) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for value in node.values():
            found.extend(_map_references(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_map_references(value))
    elif isinstance(node, str) and node.startswith("@"):
        found.append(node[1:])
    return found


def nft_tables(document: dict) -> list[dict]:
    """One row per table, correct: family-keyed, chains labelled with their
    policies in document order, rules counted. Added when nft-tables joined
    the corpus at R3d, because every judged variant now requests it."""
    order: list[tuple] = []
    chain_labels: dict[tuple, list] = {}
    rule_counts: dict[tuple, int] = {}
    for entry in document.get("nftables", []):
        if "table" in entry:
            t = entry["table"]
            key = (t.get("family"), t.get("name"))
            if key not in chain_labels:
                order.append(key)
                chain_labels[key] = []
                rule_counts[key] = 0
        elif "chain" in entry:
            c = entry["chain"]
            key = (c.get("family"), c.get("table"))
            if key in chain_labels:
                label = c.get("name") or ""
                if c.get("policy"):
                    label += f" ({c['policy']})"
                chain_labels[key].append(label)
        elif "rule" in entry:
            r = entry["rule"]
            key = (r.get("family"), r.get("table"))
            if key in rule_counts:
                rule_counts[key] += 1
    return [
        {"native_id": f"{family} {name}", "type": "table",
         "facts": {"Family": family, "Chains": chain_labels[(family, name)],
                   "ChainCount": len(chain_labels[(family, name)]),
                   "RuleCount": rule_counts[(family, name)]}}
        for family, name in order
    ]


def nft_chains(doc: dict) -> list[dict]:
    chains: dict[tuple, dict] = {}
    rule_counts: dict[tuple, int] = {}
    # DEFECT 1: one caller per chain, not a set of them. map[key]string is the
    # shape a port reaches for when every chain it has ever seen had one.
    jumped: dict[tuple, str] = {}
    map_targets: dict[tuple, list[str]] = {}
    map_users: dict[tuple, str] = {}
    for entry in doc.get("nftables", []):
        if "chain" in entry:
            c = entry["chain"]
            if c.get("family") not in KNOWN_FAMILIES:
                continue  # DEFECT 2
            chains[(c.get("family"), c.get("table"), c.get("name"))] = c
        elif "rule" in entry:
            r = entry["rule"]
            if r.get("family") not in KNOWN_FAMILIES:
                continue  # DEFECT 2
            key = (r.get("family"), r.get("table"), r.get("chain"))
            rule_counts[key] = rule_counts.get(key, 0) + 1
            for target in _verdict_targets(r.get("expr") or []):
                jumped[(r.get("family"), r.get("table"), target)] = r.get("chain")
            for ref in _map_references(r.get("expr") or []):
                map_users[(r.get("family"), r.get("table"), ref)] = r.get("chain")
        elif "map" in entry:
            m = entry["map"]
            if m.get("family") not in KNOWN_FAMILIES:
                continue
            map_targets[(m.get("family"), m.get("table"), m.get("name"))] = (
                _verdict_targets(m.get("elem") or [])
            )
    for (family, table, mname), targets in map_targets.items():
        user = map_users.get((family, table, mname))
        if not user:
            continue
        for target in targets:
            jumped.setdefault((family, table, target), user)

    items = []
    for (family, table, name), chain in chains.items():
        key = (family, table, name)
        base = bool(chain.get("hook"))
        facts: dict = {
            "Family": family,
            "Table": table,
            "Name": name,
            "BaseChain": base,
        }
        if chain.get("handle") is not None:
            facts["Handle"] = chain["handle"]
        for fact, member in (
            ("Hook", "hook"),
            ("Type", "type"),
            ("Priority", "prio"),
            ("Policy", "policy"),
        ):
            if chain.get(member) is not None:
                facts[fact] = chain[member]
        facts["RuleCount"] = rule_counts.get(key, 0)
        caller = jumped.get(key)
        if caller is not None:
            facts["JumpedFrom"] = [caller]
        elif not base:
            facts["Unreferenced"] = True
        items.append({
            "type": "chain",
            "native_id": f"{family} {table} {name}", "facts": facts,
            # The chain's table edge. This subject's declared defects are
            # about family enums and caller sets, not about relations, so it
            # asserts the edge faithfully — otherwise it would fail replay
            # for a ninth reason and stop testing the other eight.
            "assertions": [{
                "type": "member-of",
                "target": {"kind": "nft-table", "name": f"{family} {table}"},
            }],
        })
    return items


# ── zfs pools ────────────────────────────────────────────────────────────


def _int_or_none(raw):
    try:
        return int(str(raw))
    except (TypeError, ValueError):
        return None


def _epoch_iso(raw):
    seconds = _int_or_none(raw)
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _flatten(nodes, out, links, group="data", depth=1, parent=None, edges=None):
    for name, vdev in (nodes or {}).items():
        container = vdev.get("vdev_type") == "root" or name in GROUP_VDEVS
        next_group = name if name in GROUP_VDEVS else group
        child_depth = depth
        if not container:
            vtype = vdev.get("vdev_type")
            if vtype is None and not vdev.get("vdevs"):
                vtype = "disk"
            entry = {
                "Name": name,
                "Depth": depth,
                "Type": vtype,
                "State": vdev.get("state"),
            }
            if vtype == "disk":
                kname = None
                if links is not None:
                    path = vdev.get("path")
                    if path:
                        kname = links.get(str(path))
                    if kname is None:
                        for tree in ("/dev/disk/by-id", "/dev/disk/by-partuuid"):
                            kname = links.get(f"{tree}/{name}")
                            if kname:
                                break
                if kname:
                    entry["Device"] = f"block-device:{kname}"
                stable = {}
                if vdev.get("guid") is not None:
                    stable["guid"] = str(vdev["guid"])
                if str(name).startswith("wwn-"):
                    stable["wwn"] = str(name)
                if vdev.get("devid"):
                    stable["devid"] = vdev["devid"]
                names = {}
                if stable:
                    names["stable"] = stable
                if kname:
                    names["ephemeral"] = {"kernel": f"/dev/{kname}"}
                if names:
                    entry["Names"] = names
            if next_group != "data":
                entry["Group"] = next_group
            entry.update(
                {
                    "ReadErrors": _int_or_none(vdev.get("read_errors")),
                    "WriteErrors": _int_or_none(vdev.get("write_errors")),
                    "ChecksumErrors": _int_or_none(vdev.get("checksum_errors")),
                }
            )
            # DEFECT 8: a member zpool did not report stays on the row as a
            # null — which is what marshalling a struct with a nil field does.
            # DESIGN 19 forbids it at any depth; these nulls live one level
            # down, inside the Vdevs rows.
            out.append(entry)
            # The pool's backed-by edge per disk leaf, discriminated by the
            # vdev it sits in. Emitted so this subject stays a faithful port
            # apart from its EIGHT DECLARED DEFECTS: a subject that simply
            # stopped asserting relations would fail replay for a ninth
            # reason and stop testing the other eight.
            if edges is not None and vtype == "disk" and parent:
                edges.append({
                    "type": "backed-by",
                    "target": {"kind": "block-device", "name": str(name)},
                    "facts": {"VdevPath": str(parent)},
                })
            child_depth = depth + 1
        _flatten(vdev.get("vdevs"), out, links, next_group, child_depth,
                 str(name), edges)


def _redundancy(vdevs):
    """DEFECT 3: the FIRST data vdev decides.

    A pool is only as redundant as its weakest data vdev — a raidz1 striped
    with a bare disk survives nothing — but this port reports the layout it
    met first and stops looking.
    """
    for vdev in vdevs:
        if vdev.get("Group") or vdev.get("Depth") != 1:
            continue
        kind = str(vdev.get("Type") or "").lower()
        if kind == "disk":
            return "stripe", 0
        if kind == "mirror":
            members = sum(
                1
                for v in vdevs
                if v.get("Depth") == 2 and str(v.get("Type") or "") == "disk"
            )
            return "mirror", max(members - 1, 0)
        parity = PARITY.match(str(vdev.get("Name") or ""))
        if parity and kind in ("raidz", "draid"):
            return parity.group(0), int(parity.group(2))
        return None, None
    return None, None


def _prop(props, key):
    return ((props.get(key) or {}).get("value")) or None


def pools(status: dict, listing, links):
    items = []
    for name, pool in (status.get("pools") or {}).items():
        absent: list[str] = []
        unobservable: list[dict] = []
        vdevs: list[dict] = []
        edges = []
        _flatten(pool.get("vdevs"), vdevs, links, edges=edges)
        if links is None:
            for entry in vdevs:
                if entry.get("Type") == "disk":
                    unobservable.append(
                        {
                            "fact": f"Vdevs/{entry['Name']}/Device",
                            "reason": "unavailable",
                            "detail": "no device alias tree could be read, so "
                            "the member's kernel name cannot be resolved",
                        }
                    )
        props = ((listing or {}).get(name) or {}).get("properties") or {}
        caps: dict[str, dict] = {}

        def collect(nodes, caps=caps):
            for vname, vd in (nodes or {}).items():
                vprops = vd.get("properties") or {}
                alloc = _int_or_none(_prop(vprops, "allocated"))
                if alloc is not None:
                    caps[str(vname)] = {
                        "SizeBytes": _int_or_none(_prop(vprops, "size")),
                        "AllocatedBytes": alloc,
                        "CapacityPercent": _int_or_none(_prop(vprops, "capacity")),
                    }
                collect(vd.get("vdevs"), caps)

        collect(((listing or {}).get(name) or {}).get("vdevs"))
        for entry in vdevs:
            cap = caps.get(str(entry["Name"]))
            if cap:
                entry.update({k: v for k, v in cap.items() if v is not None})

        scan = pool.get("scan_stats") or {}
        # DEFECT 4: end_time 0 means "this scan has not ended", and this port
        # reads it as the epoch — so a pool that is scrubbing right now reports
        # ScanEndTime 1970-01-01 and an age of twenty thousand days.
        end_time = scan.get("end_time")
        sfacts = {
            "ScanFunction": scan.get("function"),
            "ScanState": scan.get("state"),
            "ScanEndTime": (
                _epoch_iso(end_time) if isinstance(end_time, int) else end_time
            ),
        }
        if isinstance(end_time, int):
            sfacts["ScanAgeDays"] = int((now() - end_time) // 86400)
        else:
            absent.append("ScanAgeDays")

        # DEFECT 6: a leaf zpool did not report a state for (a stripe pool's
        # members) and a spare sitting AVAIL are both counted as unhealthy
        # here — protection that is not attached to anything yet, reported as
        # a failure of the pool it is standing by for.
        unhealthy = [v["Name"] for v in vdevs if v.get("State") != "ONLINE"]
        with_errors = [
            v["Name"]
            for v in vdevs
            if any(
                (v.get(k) or 0)
                for k in ("ReadErrors", "WriteErrors", "ChecksumErrors")
            )
        ]
        facts = {
            "State": pool.get("state"),
            "StatusMessage": (pool.get("status") or "").strip() or None,
            "Errors": pool.get("error_count"),
            **sfacts,
            "SizeBytes": _int_or_none(_prop(props, "size")),
            "AllocatedBytes": _int_or_none(_prop(props, "allocated")),
            "FreeBytes": _int_or_none(_prop(props, "free")),
            "CapacityPercent": _int_or_none(_prop(props, "capacity")),
            "FragmentationPercent": _int_or_none(_prop(props, "fragmentation")),
            "Vdevs": vdevs,
            "UnhealthyVdevs": unhealthy,
            "VdevsWithErrors": with_errors,
        }
        layout, tolerated = _redundancy(vdevs)
        if layout:
            facts["Redundancy"] = layout
            facts["DeviceFailuresTolerated"] = tolerated
        absent += sorted(k for k, v in facts.items() if v is None)
        # Top-level nulls are swept — which is exactly why DEFECT 8's nested
        # ones survive: the sweep this port wrote covers the level its author
        # was looking at.
        facts = {k: v for k, v in facts.items() if v is not None}

        item = {"type": "pool", "native_id": name, "facts": facts}
        leaves = [v for v in vdevs if v.get("Type") == "disk"]
        stable = {}
        if pool.get("pool_guid") is not None:
            stable["guid"] = str(pool["pool_guid"])
        devices = [str(v["Name"]) for v in leaves]
        if devices:
            stable["devices"] = devices
        kernels = [
            v["Names"]["ephemeral"]["kernel"]
            for v in leaves
            if "ephemeral" in v.get("Names", {})
        ]
        if stable:
            item["names"] = {"stable": stable}
            if kernels:
                item["names"]["ephemeral"] = {"kernel": kernels}
        if absent:
            item["absent"] = sorted(absent)
        if unobservable:
            item["unobservable"] = sorted(unobservable, key=lambda u: u["fact"])
        if edges:
            item["assertions"] = edges
        items.append(item)
    return items


# ── the contract ─────────────────────────────────────────────────────────

INTERFACE = {"network": "nft", "storage": "zpool"}


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        fail("SE_REPLAY_DIR is unset")
    directory = Path(replay_dir)
    if not directory.is_dir():
        fail(f"SE_REPLAY_DIR={replay_dir} is not a directory")
    collector = os.environ.get("SE_REFERENCE_COLLECTOR")
    if not collector:
        fail("SE_REFERENCE_COLLECTOR must name the collector")

    line = sys.stdin.readline().strip()
    if not line:
        fail("no request line on stdin")
    parts = line.split()
    if parts[0] != "collect":
        fail(f"this collector serves collect only, not {parts[0]!r}")
    generations: dict[str, int] = {}
    if os.environ.get("SE_PORT_NO_REQUEST_PARSE"):
        # DEFECT 7: the request line is never parsed. This port knows which
        # collection it serves from its own declaration, and takes the
        # generation to be 100 — the base the old fixed issuance handed every
        # single-collection variant, so this once passed every channel. The
        # varied issuance (103..997, seeded, 100 excluded) is what refuses it
        # now, on every operator's run alike — which is why the defect is
        # gated: always-on it would refuse everything and un-attribute the
        # other seven.
        generations = {
            {"network": "nft-chains", "storage": "pools"}[collector]: 100
        }
    else:
        for token in parts[1:]:
            name, _, gen = token.rpartition(":")
            if not name or not gen.isdigit():
                fail(f"malformed token {token!r}")
            generations[name] = int(gen)
    if not generations:
        fail("empty collect")

    payloads = {
        p.stem: json.loads(p.read_text()) for p in sorted(directory.glob("*.json"))
    }

    emit(
        {
            "record": "begin",
            "request": "rq-port-0001",
            "batch": "batch-port-0001",
            "declaration": "sha256:replay",
            # A constant VALID boot id: the adjudicated single-capture
            # deferral (DESIGN 19), not one of this fixture's defects.
            "boot_id": "9d1f7c34-6a2b-4e55-b0d1-77c4a2e91f08",
            "timens": 0,
            "instance": None,
            "generations": generations,
        }
    )

    if collector == "network":
        present = ["nft"] if "nft" in payloads else []
    elif collector == "storage":
        present = [n for n in ("status", "list") if n in payloads]
    else:
        fail(f"unknown collector {collector!r}")

    if not present:
        for collection in generations:
            emit(
                {
                    "record": "decline",
                    "collection": collection,
                    "reason": "absent",
                    "detail": f"no {INTERFACE[collector]} on this host",
                }
            )
            emit(
                {
                    "record": "commit",
                    "collection": collection,
                    "generation": generations[collection],
                    "objects": 0,
                    "assertions": 0,
                    "unobservable": 0,
                }
            )
        emit(
            {
                "record": "end",
                "request": "rq-port-0001",
                "batch": "batch-port-0001",
                "cpu_ms": 0.4,
                "wall_ms": 0.9,
            }
        )
        return

    for collection in generations:
        if collector == "network" and collection == "nft-tables":
            # A correct tables serving: this subject's defects are the
            # numbered envelope ones, and answering a collection it never
            # read with chain rows would be a second, scope-shaped wrongness
            # — the lie the a5 fixtures' own history names.
            items = nft_tables(payloads["nft"])
        elif collector == "network":
            items = nft_chains(payloads["nft"])
        else:
            items = pools(
                payloads.get("status") or {},
                payloads.get("list", {}).get("pools") if "list" in payloads else None,
                payloads.get("devlinks"),
            )
        unobservable = 0
        assertions = 0
        for item in items:
            record = {
                "record": "object",
                "collection": collection,
                # Carried as the seam carries it: this subject's defects
                # are the numbered ones, and shape members are not among
                # them.
                **({"type": item["type"]} if item.get("type") else {}),
                "name": item["native_id"],
                "facts": item["facts"],
                "at": AT,  # DEFECT 5
            }
            if item.get("names"):
                record["names"] = item["names"]
            if item.get("absent"):
                record["absent"] = item["absent"]
            emit(record)
            for assertion in item.get("assertions", []):
                emit({
                    "record": "relation_assertion",
                    "collection": collection,
                    "name": item["native_id"],
                    "vantage": collection,
                    **assertion,
                })
                assertions += 1
            for missing in item.get("unobservable", []):
                emit(
                    {
                        "record": "unobservable",
                        "collection": collection,
                        "name": item["native_id"],
                        **missing,
                    }
                )
                unobservable += 1
        emit(
            {
                "record": "commit",
                "collection": collection,
                "generation": generations[collection],
                "objects": len(items),
                "assertions": assertions,
                "unobservable": unobservable,
            }
        )

    emit(
        {
            "record": "end",
            "request": "rq-port-0001",
            "batch": "batch-port-0001",
            "cpu_ms": 0.4,
            "wall_ms": 0.9,
        }
    )


if __name__ == "__main__":
    main()
