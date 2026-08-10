"""units subsystem: systemd units over org.freedesktop.systemd1.

One collection ('units'), filterable by type and summary facts — matching how
an administrator uses systemctl list-units. Relationships come from the
dependency properties, including the cross-subsystem edge every compose stack
gives us for free via its compose-stack-<project>.service unit.

The default listing order is the slice/cgroup tree an administrator sees at
the top of `systemctl status`: slices nest, services and scopes hang from
their slice, and everything else (sockets, timers, targets, …) follows flat,
grouped by type. Slice membership is one pipelined property read per
service/scope; the hierarchy itself is native, not invented here.
"""

from __future__ import annotations

import asyncio
import os

import anyio

from .. import envelope as env
from ..rules import worst_level
from ..rules.units import unit_opinions
from ..sysbus import BUS, PROPERTIES, SYSTEMD, SYSTEMD_MANAGER, SYSTEMD_PATH

UNIT_IFACE = "org.freedesktop.systemd1.Unit"

# ── per-unit pressure ────────────────────────────────────────────────
#
# /proc/pressure says THIS HOST is stalled. It cannot say what is stalling
# it, which is the difference between an alarm and a diagnosis: an operator
# looking at "all non-idle tasks were stalled on I/O 55% of the last minute"
# has nowhere to go next. The kernel keeps the same PSI accounting per
# cgroup, and systemd gives every service, scope and slice its own cgroup —
# so the same numbers, per unit, name the workload responsible.
#
# Read from cgroupfs rather than systemd's ControlGroup property because the
# property costs a D-Bus round trip per unit, while a cgroup directory is
# named for its unit. One walk answers for every unit at once, which is what
# makes this affordable on the collection page — and the list is where
# attribution actually happens, since the operator does not know which unit
# to open.
#
# Kernel-precomputed decaying averages, so this stays inside SPEC section 12:
# no rate is derived here from counters.
CGROUP_ROOT = "/sys/fs/cgroup"
PRESSURE_RESOURCES = ("io", "cpu", "memory")
# Unit types that get a cgroup. Slices are included: a slice's pressure is
# the aggregate of everything under it, which is how an operator narrows from
# "the host" to "user.slice" to one service.
CGROUP_UNIT_SUFFIXES = (".service", ".scope", ".slice", ".mount", ".socket", ".swap")
# cgroup nesting is shallow in practice (slice → slice → unit); the bound
# stops a pathological tree from turning a page render into a filesystem walk.
CGROUP_MAX_DEPTH = 6


def _read_pressure(path: str) -> dict:
    """One resource's PSI file as facts, or {} if it is not there.

    A kernel without CONFIG_PSI, or a cgroup that predates the controller,
    simply has no file — the facts are then absent, never zero, because zero
    would read as a measured absence of stalling.
    """
    try:
        with open(path) as handle:
            text = handle.read()
    except OSError:
        return {}
    facts: dict = {}
    resource = os.path.basename(path).split(".")[0].capitalize()
    for line in text.splitlines():
        fields = line.split()
        # The kernel defines cpu "full" as always zero; carrying it would
        # look like a measurement. Same rule as the host overview.
        if not fields or (resource == "Cpu" and fields[0] == "full"):
            continue
        share = fields[0].capitalize()
        for token in fields[1:]:
            key, _, value = token.partition("=")
            if key.startswith("avg"):
                try:
                    facts[f"Psi{resource}{share}Avg{key[3:]}"] = float(value)
                except ValueError:
                    pass
    return facts


def _unit_pressure(name: str) -> dict:
    """PSI for one unit, without walking the tree — the object path knows the
    unit it wants, so it only needs to find that unit's cgroup."""
    if not name.endswith(CGROUP_UNIT_SUFFIXES):
        return {}
    root_depth = CGROUP_ROOT.rstrip("/").count("/")
    for dirpath, dirnames, _files in os.walk(CGROUP_ROOT):
        if dirpath.count("/") - root_depth >= CGROUP_MAX_DEPTH:
            dirnames[:] = []
            continue
        if os.path.basename(dirpath) != name:
            continue
        facts: dict = {}
        for resource in PRESSURE_RESOURCES:
            facts.update(_read_pressure(f"{dirpath}/{resource}.pressure"))
        return facts
    return {}


def _pressure_by_unit() -> dict[str, dict]:
    """{unit name: PSI facts} for every unit with a cgroup, in one walk."""
    out: dict[str, dict] = {}
    root_depth = CGROUP_ROOT.rstrip("/").count("/")
    for dirpath, dirnames, _files in os.walk(CGROUP_ROOT):
        if dirpath.count("/") - root_depth >= CGROUP_MAX_DEPTH:
            dirnames[:] = []
            continue
        name = os.path.basename(dirpath)
        if not name.endswith(CGROUP_UNIT_SUFFIXES):
            continue
        facts: dict = {}
        for resource in PRESSURE_RESOURCES:
            facts.update(_read_pressure(f"{dirpath}/{resource}.pressure"))
        if facts:
            # A unit name is unique across the tree, so last-writer-wins is
            # not a real case; merging keeps the deepest read either way.
            out.setdefault(name, {}).update(facts)
    return out


# What a collection row carries. The full set belongs on the object; a row
# needs exactly the number that answers "is this the unit stalling the host",
# and it is the one the rule judges.
ROW_PRESSURE_FACTS = ("PsiIoFullAvg60", "PsiCpuSomeAvg60", "PsiMemoryFullAvg60")

# Unit types that live in the cgroup tree, and where their Slice lives.
SLICE_IFACES = {
    "service": "org.freedesktop.systemd1.Service",
    "scope": "org.freedesktop.systemd1.Scope",
}

# Presentation order for units outside the cgroup tree — most diagnostic
# first, the device-unit wall last.
TAIL_ORDER = ["socket", "timer", "path", "mount", "automount", "swap", "target", "device"]

# (property, relationship type, direction) — SPEC section 3 closed set.
DEPENDENCY_RELS = [
    ("Requires", "requires", "out"),
    ("Wants", "wants", "out"),
    ("RequiredBy", "requires", "in"),
    ("WantedBy", "wants", "in"),
    ("PartOf", "member-of", "out"),
    ("After", "after", "out"),
]

# Type-specific interfaces worth a second GetAll in v1.
TYPED_IFACES = {
    "service": "org.freedesktop.systemd1.Service",
    "scope": "org.freedesktop.systemd1.Scope",
    "timer": "org.freedesktop.systemd1.Timer",
}

SERVICE_FACTS = ["MainPID", "NRestarts", "Result", "TasksCurrent"]

REFERENCE = ["systemctl list-units --all", "systemctl status <unit>", "systemctl show <unit>"]


def _unit_type(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _slice_parent(name: str) -> str | None:
    """A slice's parent is encoded in its name: system-getty.slice lives in
    system.slice, top-level slices live in -.slice, -.slice is the root.
    Escaped dashes (\\x2d) are not separators and survive rsplit."""
    if name == "-.slice":
        return None
    stem = name[: -len(".slice")]
    if "-" in stem:
        return stem.rsplit("-", 1)[0] + ".slice"
    return "-.slice"


def _source(method: str) -> dict:
    return env.source("systemd-dbus", SYSTEMD, REFERENCE, method=method)


class Adapter:
    subsystem = "units"

    def collections(self) -> list[str]:
        return ["units"]

    async def capability(self) -> dict:
        return {"available": True, "collections": self.collections()}

    def _check(self, collection: str) -> None:
        if collection != "units":
            raise env.UnknownCollection(collection)

    async def _slice_of(self, name: str, path: str) -> tuple[str, str | None]:
        try:
            value = await BUS.call(SYSTEMD, path, PROPERTIES, "Get", "ss",
                                   [SLICE_IFACES[_unit_type(name)], "Slice"])
            return name, value[0] or None
        except Exception:  # noqa: BLE001 - unit may vanish mid-walk
            return name, None

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        self._check(collection)
        listed = await BUS.call(SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER, "ListUnits")
        # Threaded: hundreds of small procfs-style reads must not sit on the
        # event loop (SPEC async hygiene).
        pressure = await anyio.to_thread.run_sync(_pressure_by_unit)
        items_by_name: dict[str, dict] = {}
        paths: dict[str, str] = {}
        for name, description, load, active, sub, _following, path, *_job in sorted(listed[0]):
            facts = {"LoadState": load, "ActiveState": active, "SubState": sub,
                     "Description": description}
            # Attribution on the row, not just the object: an operator staring
            # at host I/O pressure needs to sort the list, not open 300 units.
            for key in ROW_PRESSURE_FACTS:
                value = pressure.get(name, {}).get(key)
                if value is not None:
                    facts[key] = value
            # Same evaluator as get_object (agent/rules/units.py) — a failed
            # unit is a critical opinion, so the row derives critical; an
            # active unit with no opinions is positively ok, anything else
            # (inactive, activating, …) is neutral.
            items_by_name[name] = env.item_summary(
                f"unit:{name}", _unit_type(name), name, facts,
                worst_opinion_level=worst_level(
                    unit_opinions(facts),
                    healthy="ok" if active == "active" else "info"),
            )
            paths[name] = path

        # Slice membership for every service and scope, concurrently — the
        # replies interleave on one bus connection.
        slice_of = dict(await asyncio.gather(
            *(self._slice_of(name, path) for name, path in paths.items()
              if _unit_type(name) in SLICE_IFACES)))

        children: dict[str, list[str]] = {}
        orphans: list[str] = []
        for name in items_by_name:
            unit_type = _unit_type(name)
            if unit_type == "slice":
                parent = _slice_parent(name)
            elif unit_type in SLICE_IFACES:
                parent = slice_of.get(name)
                if parent:
                    items_by_name[name]["facts"]["Slice"] = parent
            else:
                continue
            if parent in items_by_name:
                children.setdefault(parent, []).append(name)
            elif name != "-.slice":
                orphans.append(name)

        # Depth-first walk from the root slice: the systemctl-status tree.
        ordered: list[dict] = []
        seen: set[str] = set()

        def walk(name: str, depth: int) -> None:
            if name in seen:
                return
            seen.add(name)
            item = items_by_name[name]
            item["depth"] = depth
            ordered.append(item)
            for child in sorted(children.get(name, [])):
                walk(child, depth + 1)

        for root in (["-.slice"] if "-.slice" in items_by_name else []) + sorted(orphans):
            walk(root, 0)
        tail = sorted((item for name, item in items_by_name.items() if name not in seen),
                      key=lambda item: (TAIL_ORDER.index(item["type"])
                                        if item["type"] in TAIL_ORDER else len(TAIL_ORDER),
                                        item["type"], item["native_id"]))

        items = env.apply_fact_filters(ordered + tail, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection,
                                   _source("ListUnits + Slice per service/scope + cgroup PSI"),
                                   page, applied, next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    async def _unit_props(self, object_id: str) -> tuple[str, dict, dict]:
        if not object_id.startswith("unit:"):
            raise env.UnknownObject(object_id)
        name = object_id.split(":", 1)[1]
        path = (await BUS.call(SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER, "LoadUnit", "s", [name]))[0]
        unit = await BUS.get_all(SYSTEMD, path, UNIT_IFACE)
        if unit.get("LoadState") == "not-found":
            raise env.UnknownObject(object_id)
        typed: dict = {}
        iface = TYPED_IFACES.get(_unit_type(name))
        if iface:
            try:
                typed = await BUS.get_all(SYSTEMD, path, iface)
            except RuntimeError:
                typed = {}
        return name, unit, typed

    async def get_object(self, collection: str, object_id: str) -> dict:
        self._check(collection)
        name, unit, typed = await self._unit_props(object_id)
        unit_type = _unit_type(name)

        facts = {
            "LoadState": unit.get("LoadState"),
            "ActiveState": unit.get("ActiveState"),
            "SubState": unit.get("SubState"),
            "Description": unit.get("Description"),
            "UnitFileState": unit.get("UnitFileState"),
            "FragmentPath": unit.get("FragmentPath"),
            "ActiveEnterTimestamp": env.usec_to_iso(unit.get("ActiveEnterTimestamp")),
        }
        if unit_type == "service":
            for key in SERVICE_FACTS:
                facts[key] = env.norm_u64(typed.get(key))
            facts["ExecMainStartTimestamp"] = env.usec_to_iso(typed.get("ExecMainStartTimestamp"))
        elif unit_type == "timer":
            facts["NextElapse"] = env.usec_to_iso(typed.get("NextElapseUSecRealtime"))
            facts["LastTrigger"] = env.usec_to_iso(typed.get("LastTriggerUSec"))

        # Per-unit pressure: the same kernel accounting the host overview
        # reports, scoped to this unit's cgroup. Every window here (the row
        # carries only the judged one), because on the detail view the shape
        # over 10s/60s/300s is what separates a spike from a sustained stall.
        facts.update(await anyio.to_thread.run_sync(_unit_pressure, name))

        # Shared verbatim with the summary path, plus the detail-only
        # restart-churn rule (NRestarts is fetched per-unit, never in
        # ListUnits — see agent/rules/units.py).
        opinions = unit_opinions(facts)

        relationships = [
            env.rel(rel_type, direction, f"unit:{dep}")
            for prop, rel_type, direction in DEPENDENCY_RELS
            for dep in unit.get(prop) or []
        ]
        # The cgroup/slice hierarchy is the tree an administrator expects
        # units to hang from; expose it as a member-of edge.
        slice_unit = typed.get("Slice") if typed else None
        if slice_unit and slice_unit != name:
            facts["Slice"] = slice_unit
            relationships.append(env.rel("member-of", "out", f"unit:{slice_unit}"))

        return env.observation(
            self.subsystem, env.obj_ref(object_id, unit_type, name),
            _source("LoadUnit + org.freedesktop.DBus.Properties.GetAll"),
            facts, opinions=opinions, relationships=relationships,
            evidence_ref=f"/v1/units/units/{object_id}/evidence",
        )

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        self._check(collection)
        name, unit, typed = await self._unit_props(object_id)
        return {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": SYSTEMD,
            "method": "org.freedesktop.DBus.Properties.GetAll",
            "payload": {UNIT_IFACE: unit, **({TYPED_IFACES[_unit_type(name)]: typed} if typed else {})},
        }
