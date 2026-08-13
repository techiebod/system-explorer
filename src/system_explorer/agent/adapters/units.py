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
import re
from collections.abc import Iterable


from .. import envelope as env
from ..rules.units import (absent_dependency_opinions, mount_unit_opinions,
                           slice_unit_opinions, unit_opinions)
from ..sysbus import BUS, PROPERTIES, SYSTEMD, SYSTEMD_MANAGER, SYSTEMD_PATH

UNIT_IFACE = "org.freedesktop.systemd1.Unit"


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


# ── references to units that are not present on this host ────────────
#
# A unit ordered After=, wanting, or requiring a unit that does not exist here
# reads today as silent success. The referenced name turns up in ListUnits with
# LoadState not-found, inactive, no other facts, owned by nobody — and no row
# anywhere says that something asked for it. The finding belongs to the unit
# doing the REFERENCING: that one has a fragment, an owner and a fix, where the
# absent name has none of the three and nothing to be told.
#
# The arrow is walked BACKWARDS, which is the whole reason this is affordable.
# After=/Wants=/Requires= are per-unit D-Bus properties, and this adapter reads
# Slice from cgroupfs precisely to avoid paying one round trip per unit (see
# CGROUP_ROOT); probing every unit for its dependencies would reinstate exactly
# that cost, several hundred calls, on a page render. But systemd stores each
# dependency together with its inverse, and a not-found unit still has a Unit
# object on the bus with the inverse side populated — that is WHY systemd lists
# it at all. So the probe is one GetAll per NOT-FOUND unit against the object
# path ListUnits already handed over, and it yields precisely the map wanted:
# absent name -> the real units that name it.
#
# Confirmed on a live bus before this was designed around (systemd 260):
# Properties.GetAll on org.freedesktop.systemd1.Unit for a unit whose LoadState
# is not-found returns WantedBy and Before populated with real unit names and
# RequiredBy empty, matching what `systemctl show <unit> -p WantedBy,RequiredBy`
# prints for the same name.
#
# The consequence classes are three different findings wearing one shape, and
# flattening them would be an averaging this collection refuses:
#
#   Requires= / Requisite= / BindsTo=  the referencing unit cannot start. A
#       start job for it fails before the unit runs.
#   Wants= / Upholds=                  a soft dependency systemd documents
#       itself as ignoring when it cannot resolve it. The unit starts; what
#       its file asks to be pulled in with it simply never is.
#   After= / Before=                   ordering against a unit that is not
#       there orders nothing. No effect at all.
#
# Conflicts= and PartOf= are deliberately not probed. Both say what to do when
# the other unit starts or stops, and a unit that does not exist never does
# either — there is no consequence to state, so a row carrying it would gain a
# fact and no fix.
#
# Why the ordering class gets a fact and no opinion is a measurement, not a
# taste. Across five hosts (2026-08-13) carrying 23 to 42 not-found units each,
# the units referencing an absent name numbered: under a HARD directive, zero,
# on every host; under a soft one, two or three; under an ordering one, 31 to
# 59. And most of that last figure is systemd's own machinery rather than
# anything anybody authored — blockdev@<device>.target barriers the mount and
# swap unit code adds implicitly, landing on mount units that have no fragment
# for anyone to edit. An opinion there would fire dozens of times per host on a
# defect nobody wrote and nobody can fix, and a permanently red board trains an
# operator to stop reading it (the same audit rules/logs.py records for journal
# priority 3, and the same call mount_unit_opinions already makes about
# RuntimeSynthesised). The fact is carried, filterable and readable; no opinion
# is drawn from it.

# The directive an author writes -> the fact its unresolvable references land
# in. Grouped by consequence, because that is what separates a start-blocking
# defect from a documented no-op; the exact directive stays in the VALUE, so
# nothing about which word was written is lost.
ABSENT_REFERENCE_FACTS = {
    "Requires": "MissingRequirements",
    "Requisite": "MissingRequirements",
    "BindsTo": "MissingRequirements",
    "Wants": "MissingWants",
    "Upholds": "MissingWants",
    "After": "MissingOrdering",
    "Before": "MissingOrdering",
}

# The property on the ABSENT unit that names who wrote each directive. This is
# the backwards arrow: WantedBy on a name systemd could not load lists the
# units whose files say Wants= that name.
ABSENT_REFERENCE_INVERSE = {
    "RequiredBy": "Requires",
    "RequisiteOf": "Requisite",
    "BoundBy": "BindsTo",
    "WantedBy": "Wants",
    "UpheldBy": "Upholds",
    "Before": "After",
    "After": "Before",
}

# Every reverse property that names a unit which wrote SOMETHING about this
# name, used only for the absent name's own page. Deliberately a superset of
# ABSENT_REFERENCE_INVERSE, because the two maps answer different questions:
# that one is "what did an author write that has a consequence they can fix",
# which is why Conflicts= and PartOf= are excluded from it; this one is "why is
# this inert entry in the listing at all", and for a name whose only referrers
# conflict with it those two directives are the entire answer. Observed live: a
# not-found unit referenced by nothing but ConflictedBy, whose page could
# otherwise say only that it was absent and unwanted, which is exactly the
# honest-but-useless row this page exists to avoid being.
#
# Socket, path and timer activation (TriggeredBy) is not here: there is no
# directive to name — the pairing is by unit name — and the activating unit
# already appears through the ordering edge systemd adds alongside it.
REFERRER_PROPERTIES = {**ABSENT_REFERENCE_INVERSE,
                       "ConsistsOf": "PartOf",
                       "ConflictedBy": "Conflicts"}

# The bound: one probe per not-found unit, so the cost is len(not-found), which
# was 23-42 on every host measured and is far below the ~180 slice reads this
# same acquisition already makes. The cap is defensive rather than expected —
# a host with a pathological dependency graph, or a generator gone wrong, must
# not turn a collection page into hundreds of round trips. Units beyond it are
# NOT quietly dropped: each one is stated as unobservable, because "not probed"
# and "nothing references it" are the two answers this module exists to keep
# apart.
MISSING_UNIT_PROBE_LIMIT = 200


def _absent_reference_facts(pairs: Iterable[tuple[str, str]]) -> dict:
    """{fact: ["<absent unit> (<Directive>=)", ...]} for ONE referencing unit.

    One formatter, two callers, deliberately: the collection row derives its
    pairs from the reverse properties of every absent unit, and the detail view
    derives them from this unit's own forward properties filtered to the names
    systemd could not load. Those are the two ends of the same edges — systemd
    stores a dependency and its inverse together — so they must produce the
    same fact, and routing both through here is what stops the list and the
    opened object coming to describe one unit differently.

    Sorted so two collections of an unchanged host do not reorder the value.
    """
    out: dict[str, set[str]] = {}
    for directive, absent in pairs:
        fact = ABSENT_REFERENCE_FACTS.get(directive)
        if fact:
            out.setdefault(fact, set()).add(f"{absent} ({directive}=)")
    return {fact: sorted(values) for fact, values in sorted(out.items())}


def _referenced_by_facts(props: dict) -> dict:
    """{"ReferencedBy": [...]} — the same edges read from the absent name's end.

    This is the answer to the only question a reader can arrive at one of these
    rows with. A unit systemd could not load has no fragment, no cgroup and no
    runtime of any kind; what it HAS is the reason it is listed at all, which is
    that other units name it. Stated as "<referencing unit> (<Directive>=)", so
    the page says who and under which word in one line.

    Not a duplicate of the relationships: the dependency edges this adapter
    emits (DEPENDENCY_RELS) carry no Before, so the commonest case by far — a
    unit ordered After= this name — would appear nowhere in the graph.
    Confirmed live: an absent unit referenced only that way had one line of
    facts and an empty relationship list. It has to be a fact, and the fact has
    to name the directive, for the same reason the referencing row's does:
    Wants= here and Requires= here are one shape with two consequences.

    Deliberately carries no opinion. The defect belongs to the unit that wrote
    the reference, which has a file and an owner; this row is where a reader
    finds out which unit that is, not where the finding is restated without a
    fix attached.
    """
    found = {f"{referrer} ({directive}=)"
             for prop, directive in REFERRER_PROPERTIES.items()
             for referrer in props.get(prop) or []}
    return {"ReferencedBy": sorted(found)} if found else {}


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
             "cat /sys/fs/cgroup/<unit-cgroup>/{io,cpu,memory}.pressure",
             # The backwards arrow. Run against a name `systemctl list-units
             # --all` shows as not-found, this prints the very lists the
             # absent-reference facts are built from — which is the point: an
             # operator must be able to check the claim that something on this
             # host references a unit that is not here.
             "systemctl show <unit> -p RequiredBy,RequisiteOf,BoundBy,"
             "WantedBy,UpheldBy,Before,After"]


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


def _row_health(name: str, active: str, facts: dict) -> str:
    """The severity a row takes when its evaluator says nothing.

    "ok" is a VOUCH — envelope's positively-healthy value, painted as a green
    dot — so it may only be given where the evaluator actually looked and
    found nothing. This row is now about a unit's declaration and state
    alone: the deferred-stall case that used to be handled here moved with
    the measurement to resources/workloads, where the slice carrying the
    number is the row that has to decline to vouch for it.
    """
    return "ok" if active == "active" else "info"


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
    "ReferencedBy": (
        "Names the units that point at this one and the directive each wrote, "
        "carried on rows for names systemd could not load. Such a unit is "
        "listed at all only because something references it, so this is both "
        "the reason it appears and the only thing about it worth reading — a "
        "reader who arrives wondering what an inert, fileless entry is doing "
        "in the listing is asking exactly this. The finding, where there is "
        "one, belongs to the units named here, because those have a file and "
        "an owner and this has neither."
    ),
    "LoadError": (
        "Carries systemd's own reason for failing to load a unit, in its own "
        "words. It separates the two situations that read identically from "
        "outside: no file of that name anywhere, versus a file that exists and "
        "could not be parsed or was rejected. Present only when systemd "
        "recorded a reason, so a unit that loaded cleanly does not carry an "
        "empty one."
    ),
    "MissingRequirements": (
        "Names the units this one hard-depends on — Requires=, Requisite= or "
        "BindsTo= — for which systemd can load nothing of that name on this "
        "host, each with the directive that was written. A dependency systemd "
        "cannot resolve is not skipped the way a soft one is: the start job "
        "for the unit carrying this fact fails before the unit runs, so this "
        "is a defect that stops something rather than one that quietly does "
        "less than its file claims."
    ),
    "MissingWants": (
        "Names the units this one asks for — Wants= or Upholds= — for which "
        "systemd can load nothing of that name on this host, each with the "
        "directive that was written. systemd documents these as soft and "
        "ignores one it cannot resolve, so nothing fails and nothing will; "
        "what the unit file asks to be pulled in alongside it simply never "
        "is, and has not been for as long as the file has said so."
    ),
    "MissingOrdering": (
        "Names the units this one is ordered against — After= or Before= — "
        "for which systemd can load nothing of that name on this host, each "
        "with the directive that was written. Ordering against something that "
        "is not there orders nothing at all, so the sequence the file "
        "describes is not the sequence that runs. Mostly this is systemd's "
        "own implicit device and quota barriers on units nobody wrote a "
        "fragment for, which is why no opinion is drawn from it."
    ),
    "MissingReferenceUnobservable": (
        "Present when what this row can say about references between it and "
        "units that are not present on this host is incomplete, naming what "
        "stood in the way: a dependency property that could not be read, a "
        "unit that went away between the listing and the probe, or a listing "
        "too large for one collection to probe in full. An unread reference "
        "is not an absent one, so this stands in place of the reference facts "
        "rather than beside them."
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

    async def _probe_absent_unit(self, name: str, path: str) -> tuple[str, dict | None, str]:
        """(name, its Unit properties, why they could not be read).

        A not-found unit is the one thing on this bus most likely to disappear
        between being listed and being asked about: systemd keeps its Unit
        object only while something references it, so a reload landing in that
        window collects it and the path 404s. That is a reading that did not
        happen, never a unit nothing references — hence a reason string rather
        than an empty dict. The error NAME is kept, not the message: it is the
        part that distinguishes a denied call from a vanished one, and it is
        the part that carries no interpolated payload.
        """
        try:
            return name, await BUS.get_all(SYSTEMD, path, UNIT_IFACE), ""
        except Exception as error:  # noqa: BLE001 - unit may vanish mid-walk
            return name, None, (getattr(error, "error_name", None)
                                or type(error).__name__)

    async def _absent_unit_references(
            self, listed: list) -> tuple[dict[str, dict], dict[str, dict]]:
        """({referencing unit: its absent-reference facts},
            {absent unit: the facts for ITS row}).

        The backwards walk described above CGROUP_ROOT's neighbour comment.
        Only units systemd listed but could not load are probed, so a host with
        none of them — the common case this must not tax — makes no call at all
        and returns two empty maps.

        The two returns are different subjects on purpose. Facts about a
        reference land on the unit that WROTE it, which is the row with a
        fragment and an owner. The absent name's own row gets the other half of
        the same walk: who references it when the probe worked, and why that is
        unknown when it did not. Those two are mutually exclusive by
        construction — one dict, never both keys — because "nobody references
        this" and "nobody could be asked" are the pair this module exists to
        keep apart, and a shape that could carry both at once would let a
        reader take the empty one for an answer.
        """
        absent = sorted((row[0], row[6]) for row in listed
                        if row[2] == "not-found")
        by_absent: dict[str, dict] = {}
        for name, _path in absent[MISSING_UNIT_PROBE_LIMIT:]:
            by_absent[name] = {"MissingReferenceUnobservable": (
                f"this host lists {len(absent)} units it could not load, more "
                f"than the {MISSING_UNIT_PROBE_LIMIT} one collection will "
                "probe, and this name was not among those probed — so which "
                "units reference it is unread here, not none")}
        pairs: dict[str, list] = {}
        for name, props, error in await asyncio.gather(
                *(self._probe_absent_unit(name, path)
                  for name, path in absent[:MISSING_UNIT_PROBE_LIMIT])):
            if props is None:
                by_absent[name] = {"MissingReferenceUnobservable": (
                    "the dependency properties of this absent name could not "
                    f"be read ({error}), so which units reference it is "
                    "unknown rather than none")}
                continue
            # Same formatter the opened object uses, so the row and the page
            # cannot come to answer "who asked for this?" differently. Stored
            # only when it found something: a probe that ran and turned up no
            # referrer leaves BOTH facts absent, and that pair is itself the
            # answer — the unobservable fact is what marks the reading that
            # never happened, so its absence beside an absent ReferencedBy says
            # the question was asked and came back empty.
            found = _referenced_by_facts(props)
            if found:
                by_absent[name] = found
            for prop, directive in ABSENT_REFERENCE_INVERSE.items():
                for referrer in props.get(prop) or []:
                    pairs.setdefault(referrer, []).append((directive, name))
        return ({referrer: _absent_reference_facts(found)
                 for referrer, found in pairs.items()}, by_absent)

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
        # Before the row loop, because a row's severity is derived from its
        # facts inside the same item_summary call that builds it — a fact
        # merged afterwards would reach the screen with no opinion behind it.
        absent_refs, absent_facts = await self._absent_unit_references(listed[0])
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
            # What this unit names that systemd could not load — on the row,
            # because the operator sorting a units page for configuration debt
            # cannot open eight hundred units to find the four that carry it.
            facts.update(absent_refs.get(name) or {})
            # And, on a row for a name systemd could not load, who asked for
            # it — the only thing such a row can say beyond the fact of its own
            # absence, and the reason the operator keeps these rows at all.
            facts.update(absent_facts.get(name) or {})
            # Same evaluator as get_object (agent/rules/units.py) — a failed
            # unit is a critical opinion, so the row derives critical; an
            # active unit with no opinions is positively ok, anything else
            # (inactive, activating, …) and any slice whose stall the rulebook
            # left to a member's row (_row_health) is neutral.
            items_by_name[name] = env.item_summary(
                f"unit:{name}", _unit_type(name), name, facts,
                opinions=((slice_unit_opinions(facts)
                           if _unit_type(name) == "slice"
                           else unit_opinions(facts) + mount_unit_opinions(facts))
                          + absent_dependency_opinions(facts)),
                healthy=_row_health(name, active, facts),
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

    async def _unit_props(self, object_id: str) -> tuple[str, dict, dict, set[str], str]:
        """(name, Unit properties, type-specific properties, the names this
        host lists but could not load, why that listing is unknown).

        LoadUnit SYNTHESISES a Unit object for any name at all, so it can never
        decide on its own whether an object exists: asking for a name nobody
        ever wrote gets back a complete, inert, not-found unit that would
        otherwise serve as a 200. That is what the not-found refusal here has
        always been protecting, and it still is.

        What changed is the discriminator. The collection SERVES the units
        systemd listed and could not load — deliberately, because systemctl
        reports them and their very emptiness can be what tells an
        administrator something — and a row a collection serves that 404s when
        opened is the product contradicting itself. So the question is no
        longer "did this load" but "was this name in the listing", which is a
        different question with a different answer for exactly the invented
        names. The listing is fetched once here and handed back, because the
        opened object needs the same set again to say which of a LOADED unit's
        dependencies are absent — one manager call either way, never two.

        Where the listing itself could not be read the refusal stands, and that
        is the deliberate direction: unprovable existence must fail closed, or
        a degraded manager becomes the way an invented name gets served. Such a
        host has already failed the collection page that would have offered the
        link, so the 404 is consistent with the rest of what it can answer.
        """
        if not object_id.startswith("unit:"):
            raise env.UnknownObject(object_id)
        name = object_id.split(":", 1)[1]
        path = (await BUS.call(SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER, "LoadUnit", "s", [name]))[0]
        unit = await BUS.get_all(SYSTEMD, path, UNIT_IFACE)
        unloadable, unreadable = await self._unloadable_units()
        absent = unit.get("LoadState") == "not-found"
        if absent and name not in unloadable:
            raise env.UnknownObject(object_id)
        typed: dict = {}
        iface = TYPED_IFACES.get(_unit_type(name))
        # Not for a unit that did not load. The type-specific interfaces answer
        # GetAll for one of those too, with several hundred DEFAULTS — a
        # not-found .service reports Result "success", NRestarts 0, MainPID 0,
        # Restart "no" — and every one of those is a property of nothing. Facts
        # that read as a healthy idle service, on a unit with no file, is
        # precisely the manufacture this product exists to refuse; the honest
        # answer is that these do not apply, which is silence.
        if iface and not absent:
            try:
                typed = await BUS.get_all(SYSTEMD, path, iface)
            except RuntimeError:
                typed = {}
        return name, unit, typed, unloadable, unreadable

    async def _unloadable_units(self) -> tuple[set[str], str]:
        """(the names this host lists but could not load, why that is unknown).

        One ListUnits, not a property read per referenced name. The detail view
        already holds this unit's own Requires=/Wants=/After= in the property
        set it fetched, so all it lacks is which of those names systemd failed
        to load — and asking per name would be one round trip per dependency,
        dozens on a target, where the listing answers for the whole host in
        one. This view already walks the entire cgroup tree for its pressure
        facts; a single manager call beside that is not the expensive part.
        """
        try:
            listed = await BUS.call(SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER, "ListUnits")
        except Exception as error:  # noqa: BLE001 - degraded manager, denied call
            reason = getattr(error, "error_name", None) or type(error).__name__
            return set(), (
                "the unit listing this host would be checked against could "
                f"not be read ({reason}), so whether the units this one names "
                "are present here is unknown rather than settled")
        return {row[0] for row in listed[0] if row[2] == "not-found"}, ""

    async def get_object(self, collection: str, object_id: str) -> dict:
        self._check(collection)
        name, unit, typed, unloadable, unreadable = await self._unit_props(object_id)
        unit_type = _unit_type(name)
        absent = unit.get("LoadState") == "not-found"

        facts = {
            "LoadState": unit.get("LoadState"),
            "ActiveState": unit.get("ActiveState"),
            "SubState": unit.get("SubState"),
            "Description": unit.get("Description"),
        }
        # systemd's own account of why a unit did not load, present only when
        # there is one. It is the most informative thing on the page for a name
        # with no file — and it separates the ordinary absence from a unit whose
        # fragment exists and is broken, which reads identically otherwise.
        load_error = unit.get("LoadError") or []
        if isinstance(load_error, list) and any(load_error):
            facts["LoadError"] = load_error[-1] or load_error[0]

        if absent:
            # Everything below this line describes a unit systemd loaded: a
            # file it came from, a state that file is installed in, a moment it
            # last started, a cgroup it accounts to. A name with no file has
            # none of them, and systemd answers for all of them anyway — with
            # "" and 0. Absent facts, because omission reads as does-not-apply
            # where an empty string reads as a measured emptiness.
            #
            # What such a unit does have is the reason it is listed at all,
            # which is that other units name it. That is the whole question a
            # reader arrives here with, so it is the whole answer this page
            # gives.
            facts.update(_referenced_by_facts(unit))
        else:
            facts["UnitFileState"] = unit.get("UnitFileState")
            facts["FragmentPath"] = unit.get("FragmentPath")
            facts["ActiveEnterTimestamp"] = env.usec_to_iso(
                unit.get("ActiveEnterTimestamp"))
            facts.update(_workload_facts(name))
            if unit_type == "service":
                for key in SERVICE_FACTS:
                    facts[key] = env.norm_u64(typed.get(key))
                facts["ExecMainStartTimestamp"] = env.usec_to_iso(
                    typed.get("ExecMainStartTimestamp"))
            elif unit_type == "timer":
                facts["NextElapse"] = env.usec_to_iso(typed.get("NextElapseUSecRealtime"))
                facts["LastTrigger"] = env.usec_to_iso(typed.get("LastTriggerUSec"))

            # What this unit CONSUMED is deliberately not here. It is the same
            # object under a second projection — resources/workloads, keyed by
            # this same id — because consumption is a third kind of fact
            # beside declaration and state: it changes continuously, it
            # aggregates up the cgroup tree, and diffing it made /v1/changes
            # report every cgroup-bearing unit as changed on every poll.

            # The same facts the row carries, read from the other end of the
            # same edges: this unit's own forward directives, filtered to the
            # names systemd could not load. The row has to walk backwards
            # because it cannot afford a property read per unit; here the
            # properties are already in hand, so the forward reading is both
            # cheaper and more direct — and both go through
            # _absent_reference_facts, so the list and the opened object cannot
            # come to say different things about one unit. A reference to a name
            # that is not listed AT ALL is deliberately not claimed: systemd
            # keeps a Unit object for every name something references, which is
            # exactly why the absent ones are listable, so a name missing from
            # the listing is a listing that moved under us.
            if unreadable:
                facts["MissingReferenceUnobservable"] = unreadable
            else:
                facts.update(_absent_reference_facts(
                    (directive, dep)
                    for directive in ABSENT_REFERENCE_FACTS
                    for dep in unit.get(directive) or []
                    if dep in unloadable))

        # Shared verbatim with the summary path, plus the detail-only
        # restart-churn rule (NRestarts is fetched per-unit, never in
        # ListUnits — see agent/rules/units.py).
        opinions = ((slice_unit_opinions(facts) if unit_type == "slice"
                     else unit_opinions(facts) + mount_unit_opinions(facts))
                    + absent_dependency_opinions(facts))

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
            _source("LoadUnit + org.freedesktop.DBus.Properties.GetAll + "
                    "ListUnits (does this name exist, and which of its "
                    "dependencies do not)"),
            facts, opinions=opinions, relationships=relationships,
            evidence_ref=env.evidence_ref("units", "units", object_id),
        )

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        """The raw properties behind the object, including for a unit systemd
        could not load.

        Evidence and the object share one contract deliberately: an object this
        adapter will serve must be able to show its own document, or the
        provenance promise has a hole exactly where a reader would go to check
        a surprising claim. There IS a document for these — the Unit interface
        answers GetAll for a not-found name with real values, which is how the
        reverse-reference facts are acquired in the first place — so the same
        gate in _unit_props admits both routes, and an invented name is refused
        by both.

        What it does NOT carry is the type-specific interface, for the reason
        _unit_props declines to fetch it: those properties are several hundred
        defaults describing nothing. Evidence is the place a reader goes to
        check what was really said, so it is the last place that may show them
        a fabricated Result "success".
        """
        self._check(collection)
        name, unit, typed, _unloadable, _unreadable = await self._unit_props(object_id)
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
