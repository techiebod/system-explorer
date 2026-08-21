#!/usr/bin/env python3
"""Adversary fixture — fleet round a5: the hardcoded-healthy port.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. This is round a5's wrong-collector, adopted
with its lab paths removed. Expected verdict: RED, forever — a subject whose
every health claim is a struct default must never satisfy the judge, however
healthy the capture it is replayed against happens to be.

A plausible port of the storage and network collectors, written from the
corpus payloads and the published fact names the way a porting engineer would:
read the JSON, fill the struct, emit the stream. It speaks the stream contract
exactly — request line on stdin, NDJSON on stdout, SE_REPLAY_DIR for the
payloads. It is wrong about the machine in six ways, every one the kind of
thing a port produces by accident:

  N1  JumpedFrom is built from `jump` only. `goto` also transfers control.
  S1  Pool State is not read; the struct field is initialised "ONLINE".
  S2  StatusMessage is not read (the healthy pools it was tested on have none).
  S3  Errors is not read.
  S4  UnhealthyVdevs / VdevsWithErrors are stubs returning empty slices.
  S5  Per-vdev State and error counters are hardcoded ONLINE / 0.
  S6  DeviceFailuresTolerated is 1 whenever the layout is redundant-looking.

The envelope is stubbed too — boot_id "replay", `at` 0.0, generations minted
as 1 — and it predates the tokenised `<collection>:<generation>` request line,
so under the current wire its collection names are wrong as well. Left as
captured: the fixture is the round's artefact, and each individual guard is
proven by its own reversion in test_guards_discriminate.py, not by this file
staying red for any one reason.
"""

from __future__ import annotations

import datetime
import json
import os
import sys
from pathlib import Path


def emit(record):
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))


def now_epoch():
    when = os.environ.get("SE_REPLAY_NOW")
    if when:
        return datetime.datetime.fromisoformat(when.replace("Z", "+00:00")).timestamp()
    return datetime.datetime.now(datetime.UTC).timestamp()


def iso(epoch):
    return (datetime.datetime.fromtimestamp(int(epoch), datetime.UTC)
            .strftime("%Y-%m-%dT%H:%M:%SZ"))


# ── network / nft-chains ────────────────────────────────────────────────────

def nft_chains(payloads):
    doc = payloads["nft"]
    chains, counts, jumped = {}, {}, {}
    for entry in doc.get("nftables", []):
        if "chain" in entry:
            c = entry["chain"]
            chains[(c.get("family"), c.get("table"), c.get("name"))] = c
        elif "rule" in entry:
            r = entry["rule"]
            key = (r.get("family"), r.get("table"), r.get("chain"))
            counts[key] = counts.get(key, 0) + 1
            for st in r.get("expr") or []:
                if not isinstance(st, dict):
                    continue
                # N1: only `jump`. A goto arrives at the chain just the same.
                body = st.get("jump")
                if isinstance(body, dict) and body.get("target"):
                    jumped.setdefault(
                        (r.get("family"), r.get("table"), body["target"]),
                        set()).add(r.get("chain"))
    items = []
    for (family, table, name), chain in chains.items():
        key = (family, table, name)
        base = bool(chain.get("hook"))
        facts = {"Family": family, "Table": table, "Name": name, "BaseChain": base}
        if chain.get("handle") is not None:
            facts["Handle"] = chain["handle"]
        for fact, member in (("Hook", "hook"), ("Type", "type"),
                             ("Priority", "prio"), ("Policy", "policy")):
            if chain.get(member) is not None:
                facts[fact] = chain[member]
        facts["RuleCount"] = counts.get(key, 0)
        callers = sorted(jumped.get(key, ()))
        if callers:
            facts["JumpedFrom"] = callers
        elif not base:
            facts["Unreferenced"] = True
        items.append((f"{family} {table} {name}", facts))
    return items


# ── storage / pools ─────────────────────────────────────────────────────────

GROUPS = {"logs", "l2cache", "spares", "dedup", "special"}


def flatten(nodes, out, group="data", depth=1):
    for name, vdev in (nodes or {}).items():
        container = vdev.get("vdev_type") == "root" or name in GROUPS
        next_group = name if name in GROUPS else group
        child_depth = depth
        if not container:
            vtype = vdev.get("vdev_type")
            if vtype is None and not vdev.get("vdevs"):
                vtype = "disk"
            entry = {
                "Name": name,
                "Depth": depth,
                "Type": vtype,
                # S5: the capture this was written against was all ONLINE.
                "State": "ONLINE",
                "Device": None,
                "ReadErrors": 0,
                "WriteErrors": 0,
                "ChecksumErrors": 0,
            }
            if next_group != "data":
                entry["Group"] = next_group
            out.append(entry)
            child_depth = depth + 1
        flatten(vdev.get("vdevs"), out, next_group, child_depth)


def prop(props, key):
    value = ((props.get(key) or {}).get("value")) or None
    if value in (None, "-"):
        return None
    try:
        return int(value)
    except ValueError:
        return None


def pools(payloads):
    status = payloads.get("status") or {}
    listing = (payloads.get("list") or {}).get("pools") or {}
    items = []
    for name, pool in (status.get("pools") or {}).items():
        vdevs = []
        flatten(pool.get("vdevs"), vdevs)
        props = (listing.get(name) or {}).get("properties") or {}

        caps = {}

        # The late-binding lint is waived below: walk_caps is defined and
        # fully consumed inside one loop iteration, so the closure over this
        # iteration's `caps` is the intended behaviour — preserved as the
        # round shipped it.
        def walk_caps(nodes):
            for vname, vd in (nodes or {}).items():
                vprops = vd.get("properties") or {}
                alloc = prop(vprops, "allocated")
                if alloc is not None:
                    caps[str(vname)] = {  # noqa: B023
                        "SizeBytes": prop(vprops, "size"),
                        "AllocatedBytes": alloc,
                        "CapacityPercent": prop(vprops, "capacity"),
                    }
                walk_caps(vd.get("vdevs"))

        walk_caps((listing.get(name) or {}).get("vdevs"))
        for entry in vdevs:
            if entry["Name"] in caps:
                entry.update(caps[entry["Name"]])

        scan = pool.get("scan_stats") or {}
        end_time = scan.get("end_time") or None
        facts = {
            # S1/S2/S3: never read from the document.
            "State": "ONLINE",
            "StatusMessage": None,
            "Errors": 0,
            "ScanFunction": scan.get("function"),
            "ScanState": scan.get("state"),
            "ScanEndTime": iso(end_time) if end_time else None,
            "SizeBytes": prop(props, "size"),
            "AllocatedBytes": prop(props, "allocated"),
            "FreeBytes": prop(props, "free"),
            "CapacityPercent": prop(props, "capacity"),
            "FragmentationPercent": prop(props, "fragmentation"),
            "Vdevs": vdevs,
            # S4: stubs.
            "UnhealthyVdevs": [],
            "VdevsWithErrors": [],
        }
        if end_time:
            facts["ScanAgeDays"] = int((now_epoch() - end_time) // 86400)
        top = [v for v in vdevs if v["Depth"] == 1 and not v.get("Group")]
        if top:
            layout = str(top[0]["Name"]).rsplit("-", 1)[0]
            facts["Redundancy"] = layout
            # S6: "redundant means it survives a disk" — close enough.
            facts["DeviceFailuresTolerated"] = 0 if top[0]["Type"] == "disk" else 1
        items.append((name, facts))
    return items


# The third member of each COLLECTORS row and the object type below are
# what a correct subject carries; this fixture's defects are the S/N list
# in the header and nothing else, so shape members ride along verbatim.
OBJECT_TYPES = {"pools": "pool", "nft-chains": "chain"}

COLLECTORS = {
    "storage": ("pools", pools, "zpool"),
    "network": ("nft-chains", nft_chains, "nft"),
}


def main():
    directory = Path(os.environ["SE_REPLAY_DIR"])
    if not directory.is_dir():
        print(f"no such payload dir {directory}", file=sys.stderr)
        raise SystemExit(2)
    which = os.environ["SE_REFERENCE_COLLECTOR"]
    collection, build, interface = COLLECTORS[which]
    line = sys.stdin.readline().strip().split()
    wanted = line[1:] or [collection]

    payloads = {p.stem: json.loads(p.read_text())
                for p in sorted(directory.glob("*.json"))}

    emit({"record": "begin", "request": "replay", "batch": "replay",
          "declaration": "sha256:replay", "boot_id": "replay", "timens": 0,
          "instance": None, "generations": {c: 1 for c in wanted}})
    for c in wanted:
        if not payloads:
            emit({"record": "decline", "collection": c, "reason": "absent",
                  "detail": f"no {interface} on this host"})
            emit({"record": "commit", "collection": c, "generation": 1,
                  "objects": 0})
            continue
        items = build(payloads)
        for name, facts in items:
            record = {"record": "object", "collection": c, "name": name,
                      "facts": facts, "at": 0.0}
            # .get, because `wanted` is the request line's token list and a
            # collection this table does not know is served untyped rather
            # than crashing a fixture whose defects are the declared ones.
            if OBJECT_TYPES.get(c):
                record["type"] = OBJECT_TYPES[c]
            emit(record)
        emit({"record": "commit", "collection": c, "generation": 1,
              "objects": len(items)})
    emit({"record": "end", "request": "replay", "batch": "replay"})


if __name__ == "__main__":
    main()
