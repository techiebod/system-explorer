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
from ..rules.units import (mount_unit_opinions, slice_unit_opinions,
                           unit_opinions)
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


def _pressure_nodes() -> dict[str, dict]:
    """{unit name: node} for every unit cgroup in the tree, in one walk.

    A node is {"facts": PSI facts, "parent": enclosing cgroup's name or None,
    "depth": nesting below the root, "pruned": children left unread at the
    depth bound}. The parent link is what makes a slice's stall attributable
    at all: the kernel aggregates PSI over the CGROUP tree, so that tree is
    the join, and it costs nothing beyond the walk the row facts already need.

    A node is recorded even when it yielded no readings. Presence and
    readability are different answers — a member whose pressure could not be
    read must not be counted as a member that is quiet — and only a walk that
    keeps the empty ones can tell them apart.

    Unit names are NOT unique across the tree: a user manager runs its own
    init.scope, app.slice and dbus.service inside user@<uid>.service, and
    those names collide with system units. The shallowest occurrence wins,
    because the system manager's own units are the rows this collection
    serves; merging by name let whichever the walk reached last decide, which
    is a coin toss over whose pressure a row reports.
    """
    nodes: dict[str, dict] = {}
    root_depth = CGROUP_ROOT.rstrip("/").count("/")
    for dirpath, dirnames, _files in os.walk(CGROUP_ROOT):
        depth = dirpath.count("/") - root_depth
        if depth >= CGROUP_MAX_DEPTH:
            dirnames[:] = []
            continue
        name = os.path.basename(dirpath)
        if not name.endswith(CGROUP_UNIT_SUFFIXES):
            continue
        if name in nodes and nodes[name]["depth"] <= depth:
            continue
        facts: dict = {}
        for resource in PRESSURE_RESOURCES:
            facts.update(_read_pressure(f"{dirpath}/{resource}.pressure"))
        parent = os.path.basename(os.path.dirname(dirpath))
        nodes[name] = {
            "facts": facts,
            "parent": parent if parent.endswith(CGROUP_UNIT_SUFFIXES) else None,
            "depth": depth,
            # The children this walk will refuse to descend into. A slice
            # whose subtree was cut short cannot be said to have no member
            # explaining its stall, so the cut has to be recorded where the
            # attribution can see it.
            "pruned": depth + 1 >= CGROUP_MAX_DEPTH and bool(dirnames),
        }
    return nodes


def _pressure_by_unit(nodes: dict[str, dict]) -> dict[str, dict]:
    """{unit name: PSI facts} — the row-facing half of the walk."""
    return {name: node["facts"] for name, node in nodes.items() if node["facts"]}


def _pressure_and_attribution() -> tuple[dict[str, dict], dict[str, dict]]:
    """Both halves of one walk: the per-unit readings, and what a slice's
    reading is explained by. Derived together so the two cannot describe
    different moments in the tree."""
    nodes = _pressure_nodes()
    return _pressure_by_unit(nodes), _stall_attribution(nodes)


def _unit_pressure(name: str) -> dict:
    """PSI for one unit on the object path, plus — for a slice — the
    attribution of that stall to the unit inside it responsible.

    The whole tree is walked rather than stopped at the wanted unit: a slice's
    number is a statement about its subtree, so the subtree is what has to be
    read to say anything about it, and the same walk settles the name
    collision above for every other type. Units that never get a cgroup —
    targets, devices, timers, paths — still cost nothing.
    """
    if not name.endswith(CGROUP_UNIT_SUFFIXES):
        return {}
    nodes = _pressure_nodes()
    node = nodes.get(name)
    if node is None:
        return {}
    return {**node["facts"], **_stall_attribution(nodes, only=name).get(name, {})}


# What a collection row carries. The full set belongs on the object; a row
# needs exactly the number that answers "is this the unit stalling the host",
# and it is the one the rule judges.
ROW_PRESSURE_FACTS = ("PsiIoFullAvg60", "PsiCpuSomeAvg60", "PsiMemoryFullAvg60")

# ── attributing a slice's stall to the unit inside it ────────────────
#
# A cgroup's "full" share is the time in which every non-idle task in it AND
# ITS DESCENDANTS was stalled, so a sibling making progress LOWERS the number
# above it: a slice cannot normally exceed the member responsible for it, and
# a slice row is therefore the same condition stated less specifically and
# smaller. Seen live 2026-08-13 on a host overview — a container's scope at
# 65.27% listed directly beneath the system.slice containing it at 56.35%,
# one stall reported twice, the second time with the culprit's name removed.
#
# Attribution covers the FULL shares only. "some" is the share of time at
# least one task was stalled, and that aggregates as a union up the tree: a
# parent is normally at least its children, so "a member reads at least as
# high" would be true of almost every slice and would mean nothing.
# PsiCpuSomeAvg60 is carried on the row and never attributed.
ATTRIBUTED_PRESSURE_FACTS = {"PsiIoFullAvg60": "I/O",
                             "PsiMemoryFullAvg60": "memory"}

# The comparison is not exact >=. Both numbers are independently decaying
# kernel averages, printed to two decimals and read from two files while each
# cgroup's own averaging tick runs on its own schedule, so a member that
# genuinely accounts for its slice can print a hair below it. Exact >= would
# call that slice unexplained and manufacture the interesting case out of
# rounding. The allowance is the larger of an absolute floor — well above the
# 0.01 the two roundings can cost between them — and a share of the slice's
# own number, because tick skew scales with the value.
ATTRIBUTION_ABSOLUTE_SLACK = 0.05
ATTRIBUTION_RELATIVE_SLACK = 0.05


def _slice_members(name: str, nodes: dict[str, dict],
                   children: dict[str, list[str]]) -> tuple[list[tuple[str, int]], list[str]]:
    """(members with their depth below the slice, slices whose subtree was cut).

    Descent stops at anything that is not a slice. A .service or .scope with
    a cgroup subtree of its own has been DELEGATED that subtree — user@<uid>
    .service runs a whole second systemd, a container scope runs a container's
    own hierarchy — and the units in it belong to that manager, not this one.
    Naming one would be a reference this collection cannot resolve, and worse,
    those names collide with system units (dbus.service exists in both), so
    the reference could resolve to the wrong object entirely. The delegating
    unit's own cgroup already carries their aggregate, and it IS a row here.
    """
    found: list[tuple[str, int]] = []
    cut: list[str] = []
    queue = [(name, 0)]
    seen = {name}
    while queue:
        parent, depth = queue.pop()
        if nodes[parent]["pruned"]:
            cut.append(parent)
        for child in sorted(children.get(parent, ())):
            if child in seen:
                continue
            seen.add(child)
            found.append((child, depth + 1))
            if child.endswith(".slice"):
                queue.append((child, depth + 1))
    return found, cut


def _stall_attribution(nodes: dict[str, dict],
                       only: str | None = None) -> dict[str, dict]:
    """{slice name: attribution facts}, per pressure reading.

    Exactly one of three states is stated for each resource a slice reports a
    stall on, and each is stated POSITIVELY, because the three are what a
    reader would otherwise have to infer from an absence:

      StallExplainedBy               a member reads at least as high
      StallUnexplained               every member was read and none does
      StallAttributionUnobservable   a member could not be read, so neither
                                     of the above can be claimed

    The third exists because the alternative is the failure this product is
    built against: a cgroup whose pressure files could not be read looks
    exactly like a cgroup that is not stalling, and counting it as quiet
    would turn "we did not see it" into "nothing inside explains this" — the
    most interesting finding here, manufactured out of a gap in the reading.
    """
    children: dict[str, list[str]] = {}
    for name, node in nodes.items():
        if node["parent"]:
            children.setdefault(node["parent"], []).append(name)

    out: dict[str, dict] = {}
    for name, node in nodes.items():
        if not name.endswith(".slice") or (only is not None and name != only):
            continue
        members, cut = _slice_members(name, nodes, children)
        facts: dict = {}
        for fact, resource in ATTRIBUTED_PRESSURE_FACTS.items():
            value = node["facts"].get(fact)
            if not isinstance(value, (int, float)) or value <= 0:
                continue
            readings = [(nodes[member]["facts"].get(fact), member, depth)
                        for member, depth in members]
            unread = sorted(member for reading, member, _depth in readings
                            if not isinstance(reading, (int, float)))
            slack = max(ATTRIBUTION_ABSOLUTE_SLACK,
                        value * ATTRIBUTION_RELATIVE_SLACK)
            # Highest first, then deepest, then by name. Highest because the
            # worst member is the one whose own row already carries the
            # warning; deepest to break the tie a nested slice creates, since
            # a slice and its single busy child print the same number and the
            # child is the specific answer; by name so two identical readings
            # do not reorder between polls.
            accounts = sorted(
                ((reading, depth, member) for reading, member, depth in readings
                 if isinstance(reading, (int, float)) and reading >= value - slack),
                key=lambda entry: (-entry[0], -entry[1], entry[2]))
            if accounts:
                facts.setdefault("StallExplainedBy", {})[fact] = accounts[0][2]
            elif cut:
                facts.setdefault("StallAttributionUnobservable", {})[fact] = (
                    f"the cgroup tree below {', '.join(sorted(cut))} is deeper "
                    "than this walk reads, so a member in it could still "
                    "account for this.")
            elif unread:
                facts.setdefault("StallAttributionUnobservable", {})[fact] = (
                    f"no {resource} pressure reading for {len(unread)} of the "
                    f"{len(members)} member cgroups under this slice "
                    f"({', '.join(unread[:3])}"
                    f"{f' and {len(unread) - 3} more' if len(unread) > 3 else ''}"
                    "), so a member could still account for this.")
            elif not members:
                facts.setdefault("StallAttributionUnobservable", {})[fact] = (
                    "no member cgroup was found under this slice, so there is "
                    "nothing here to attribute the stall to or rule out.")
            else:
                worst = max(readings)
                facts.setdefault("StallUnexplained", {})[fact] = (
                    f"every member cgroup under this slice was read for "
                    f"{resource} pressure ({len(members)} of them) and the "
                    f"highest, {worst[1]} at {worst[0]}%, is below this "
                    f"slice's own {value}%.")
        if facts:
            out[name] = facts
    return out

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
    "StallExplainedBy": (
        "Names, for each pressure reading, the unit nested inside this slice "
        "whose own stall accounts for the slice's. A slice's number is the "
        "share of the minute in which every non-idle task under it was "
        "stalled, so a member that is making progress only lowers it and a "
        "member that caused it reads at least as high: the unit named here "
        "is the same condition stated specifically, and this slice is the "
        "vaguer, smaller version of it."
    ),
    "StallUnexplained": (
        "Present for each pressure reading no unit inside this slice accounts "
        "for, stating how many members were read and how high the worst of "
        "them got. This is the case worth someone's time — the stall belongs "
        "to the slice as a whole rather than to one workload in it, which no "
        "member's own row will ever say."
    ),
    "StallAttributionUnobservable": (
        "Present for each pressure reading that could neither be traced to a "
        "member of this slice nor ruled out of every one of them, naming what "
        "could not be read. A member whose pressure is unreadable is not a "
        "member that is quiet, so this stands in place of a finding rather "
        "than beside one."
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
        # event loop (SPEC async hygiene). Attribution is derived in the same
        # thread call because it reads nothing the walk did not already hold.
        pressure, attribution = await anyio.to_thread.run_sync(_pressure_and_attribution)
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
            # And, for a slice, what its number is explained by — a join
            # inside this one collection, since the cgroup tree the kernel
            # aggregates over is the tree the walk above already read. On the
            # row because that is where the duplicate finding appears: the
            # rule below reads these to decide whether the slice is restating
            # a member's stall or reporting one nothing inside it accounts for.
            facts.update(attribution.get(name) or {})
            # Same evaluator as get_object (agent/rules/units.py) — a failed
            # unit is a critical opinion, so the row derives critical; an
            # active unit with no opinions is positively ok, anything else
            # (inactive, activating, …) is neutral.
            items_by_name[name] = env.item_summary(
                f"unit:{name}", _unit_type(name), name, facts,
                opinions=(slice_unit_opinions(facts)
                          if _unit_type(name) == "slice"
                          else unit_opinions(facts) + mount_unit_opinions(facts)),
                healthy="ok" if active == "active" else "info",
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
        # A slice gets its attribution facts from the same call: the rule
        # below is shared with the row path, and a detail view that omitted
        # them would leave it judging the same slice on less than the list
        # did — the two views disagreeing about one unit.
        facts.update(await anyio.to_thread.run_sync(_unit_pressure, name))

        # Shared verbatim with the summary path, plus the detail-only
        # restart-churn rule (NRestarts is fetched per-unit, never in
        # ListUnits — see agent/rules/units.py).
        opinions = (slice_unit_opinions(facts) if unit_type == "slice"
                    else unit_opinions(facts) + mount_unit_opinions(facts))

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
