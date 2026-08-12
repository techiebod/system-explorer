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

Evidence redaction: a service's Environment= carries credentials as a matter
of routine, so evidence keeps the variable names and redacts the values, and
the envelope records which paths were altered — the same contract the docker
adapter applies to Config.Env.
"""

from __future__ import annotations

import asyncio
import os
import re

import anyio

from .. import envelope as env
from ..rules import worst_level
from ..rules.units import mount_unit_opinions, unit_opinions
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

# ── naming the workload behind a transient scope ─────────────────────
#
# Container and VM runtimes register their workloads as transient scopes whose
# names carry an id and nothing an operator recognises. This mattered the first
# time per-unit PSI worked: a docker-59286b95bc5b….scope showed the highest
# I/O stall on the host, and there was no way to tell it was syncthing. The
# unit itself holds no name — Description is dockerd's own "libcontainer
# container <the same id>" — so each runtime gets exactly the handle its own
# naming actually supports, and no more.
#
# docker: the short id, published under the SAME fact name the docker adapter
#   already uses (ContainerID), so the two collections join on a shared value.
#   No relationship is emitted: an edge needs container:<name>, and this
#   adapter cannot know the name without talking to Docker, which is not its
#   acquisition path.
# libvirt: the domain name is recoverable in full, because libvirt names the
#   scope qemu-<domid>-<domain> and systemd escapes it. So this one CAN form
#   domain:<name> and does — a real edge, not a join key.
DOCKER_SCOPE_RE = re.compile(r"^docker-([0-9a-f]{12})[0-9a-f]*\.scope$")
MACHINE_SCOPE_RE = re.compile(r"^machine-qemu\\x2d\d+\\x2d(.+)\.scope$")


def _unescape_unit_name(name: str) -> str:
    r"""systemd's C-escaping of unit names: \x2d for '-', and so on. Only the
    \xNN form appears in machine and mount unit names."""
    return re.sub(r"\\x([0-9a-fA-F]{2})",
                  lambda m: chr(int(m.group(1), 16)), name)


def _workload_facts(unit_name: str) -> dict:
    """Whatever the scope's own name can prove about the workload inside it."""
    docker = DOCKER_SCOPE_RE.match(unit_name)
    if docker:
        return {"ContainerID": docker.group(1)}
    machine = MACHINE_SCOPE_RE.match(unit_name)
    if machine:
        return {"MachineName": _unescape_unit_name(machine.group(1))}
    return {}

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

REFERENCE = ["systemctl list-units --all", "systemctl status <unit>", "systemctl show <unit>",
             # Per-unit pressure is read from cgroupfs, not from systemd: the
             # D-Bus interface does not carry it. Named here because rule 5's
             # promise is about what the observation actually comes from, and
             # the comment above _walk_cgroups explaining why was the only
             # place it was written down.
             "cat /sys/fs/cgroup/<unit-cgroup>/{io,cpu,memory}.pressure"]


# Unit properties whose values are secrets-adjacent by construction. A
# service's Environment= is the obvious one: sops-provisioned credentials,
# API tokens and database URLs land there routinely, and the raw D-Bus
# property was being served verbatim on an unauthenticated API — the exact
# exposure the docker adapter already refuses for Config.Env.
#
# Same contract as docker.py: keep the variable NAMES, which are what make
# evidence diagnostically useful ("is DATABASE_URL even set?"), redact the
# values, and declare in the envelope that redaction happened. Redaction
# that hides its own existence would break the provenance contract.
SECRET_LIST_PROPERTIES = ("Environment", "UnsetEnvironment", "PassEnvironment")
# EnvironmentFiles carries (path, ignore-errors) tuples — paths are not
# secret and naming them is how an operator finds the credential source.
#
# The redactor itself lives in envelope.py: system/boot serves the same D-Bus
# shape for org.freedesktop.systemd1.Manager, whose Environment is the
# manager-wide block, and a private copy here is how that one went unredacted
# while this one did not. PassEnvironment is by systemd's definition a list of
# bare NAMES, so it can never withhold anything — it stays listed because the
# property could carry an assignment, and env.redact_assignments now declines
# to claim a redaction that did not happen.


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


# The units collection has no full dictionary yet; this documents the one fact
# whose name explains nothing on its own, and which an opinion cites. The rest
# of units' cited facts are on conformance's UNDOCUMENTED_EVIDENCE register —
# a stated gap rather than a silent one.
_UNIT_GLOSSARY = {
    "RuntimeSynthesised": (
        "Present when systemd made this mount unit up from the mount table "
        "rather than reading a unit file for it, which happens whenever "
        "something outside systemd performed the mount. Such a unit reports "
        "the mount accurately but has no fragment, and RequiresMountsFor= "
        "against a fragmentless mount does not become a real dependency — so "
        "a service naming the path may start before the filesystem is there. "
        "Common and harmless for container overlay and netns mounts, which "
        "nothing declares; it matters where something does."
    ),
}


def _source(method: str) -> dict:
    return env.source("systemd-dbus", SYSTEMD, REFERENCE, method=method)


class Adapter:
    subsystem = "units"

    def collections(self) -> list[str]:
        return ["units"]

    def fact_glossary(self, collection: str) -> dict[str, str]:
        return _UNIT_GLOSSARY if collection == "units" else {}

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

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        """The full materialisation, shared: collect() pages it, and main.py's
        status/snapshot/changes sweeps consume it directly instead of paying
        ListUnits, ListUnitFiles, the cgroup walk and the slice gather once
        per page. Single-flighted so a sweep and a concurrent UI poll ride one
        acquisition (envelope.single_flight — coalescing, not caching). The
        slice-membership gather and the tree ordering live here too: the
        systemctl-status order is part of what the collection IS, not a
        presentation step collect() adds."""
        self._check(collection)
        listed = await BUS.call(SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER, "ListUnits")
        # Which units exist as a FILE, in one call rather than a FragmentPath
        # Get per unit (there are 300+ on an ordinary host). The distinction is
        # the point: systemd synthesises a .mount unit from /proc/self/mountinfo
        # for anything mounted outside its control, and such a unit has no
        # fragment — so RequiresMountsFor= against it degrades to an ordering
        # hint or nothing at all, silently. A generator-written unit is a file
        # and appears here; a synthesised one does not.
        have_file: set[str] = set()
        try:
            for entry in (await BUS.call(SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER,
                                         "ListUnitFiles"))[0]:
                have_file.add(entry[0].rsplit("/", 1)[-1])
        except Exception:  # noqa: BLE001 - older systemd, or a denied call
            have_file = set()
        # Threaded: hundreds of small procfs-style reads must not sit on the
        # event loop (SPEC async hygiene).
        pressure = await anyio.to_thread.run_sync(_pressure_by_unit)
        items_by_name: dict[str, dict] = {}
        paths: dict[str, str] = {}
        for name, description, load, active, sub, _following, path, *_job in sorted(listed[0]):
            facts = {"LoadState": load, "ActiveState": active, "SubState": sub,
                     "Description": description}
            # On the row for the same reason the pressure numbers are: the
            # operator sorting by stall has to recognise the winner in the
            # list, not open it to find out what it is.
            # Mounts only, deliberately. A .scope or .slice is runtime by
            # nature and flagging those would be noise; a .mount that nothing
            # wrote a file for is the case where a dependency quietly does not
            # exist. Only claimed when the file list was actually read, so a
            # denied ListUnitFiles stays silent instead of accusing every unit.
            if have_file and name.endswith(".mount") and name not in have_file:
                facts["RuntimeSynthesised"] = True
            facts.update(_workload_facts(name))
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
                    unit_opinions(facts) + mount_unit_opinions(facts),
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
        return ordered + tail

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        items = env.apply_fact_filters(fetched, query)
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
        facts.update(_workload_facts(name))
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
        opinions = unit_opinions(facts) + mount_unit_opinions(facts)

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
        # libvirt's scope name yields the domain name in full, so this edge is
        # real rather than a join hint. Docker's does not (see _workload_facts),
        # which is why only one of the two gets a relationship.
        if facts.get("MachineName"):
            relationships.append(env.rel("runs", "out",
                                         f"domain:{facts['MachineName']}",
                                         subsystem="vms"))

        return env.observation(
            self.subsystem, env.obj_ref(object_id, unit_type, name),
            _source("LoadUnit + org.freedesktop.DBus.Properties.GetAll"),
            facts, opinions=opinions, relationships=relationships,
            evidence_ref=env.evidence_ref("units", "units", object_id),
        )

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        self._check(collection)
        name, unit, typed = await self._unit_props(object_id)
        payload = {UNIT_IFACE: unit,
                   **({TYPED_IFACES[_unit_type(name)]: typed} if typed else {})}
        payload, redacted = env.redact_list_properties(payload, SECRET_LIST_PROPERTIES)
        out = {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": SYSTEMD,
            "method": "org.freedesktop.DBus.Properties.GetAll",
            "payload": payload,
        }
        if redacted:
            out["redacted"] = redacted
        return out
