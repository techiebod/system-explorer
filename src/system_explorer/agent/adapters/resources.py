"""resources subsystem: what each workload consumed, and what it was
stalled on.

WHY CONSUMPTION IS ITS OWN PROJECTION. A unit row was carrying three kinds
of fact at once and they behave differently. Declaration changes when
somebody deploys; running state changes when an event happens; both are
discrete and diffable and belong to the configured thing. Consumption changes
continuously, aggregates up a tree, and has a total with a remainder that has
to be reconciled rather than assumed away. Mixing them made /v1/changes
useless on this host — a decaying kernel average diffed every fifteen minutes
reports every cgroup-bearing unit as changed, with the one real transition
buried in the middle of it — and it left the question an operator actually
arrives with, "what is eating this machine", answerable only by hunting
subsystem by subsystem.

So this is the same objects under a second projection: the ids are the ones
units/units already serves, the join is identity rather than an edge, and
units/units keeps declaration and state while everything here is measurement.

WHY THERE IS NO CGROUP OBJECT. On a systemd host every cgroup that matters
already has a unit name — a service, a scope, a slice — so a `cgroup:` id
would invent an identity where a native one exists (design rule 2). The keys
are systemd's own names, including `-.slice` for the root, which is what
systemd itself calls it. The one exception is a cgroup systemd never named:
it is kept in the walk, keyed by its path, because dropping it made its
consumption invisible to the member arithmetic above it — but it is never a
row and is never named as an explanation, because there is nothing for the
reading to be about.

TWO QUESTIONS, NOT ONE. Utilisation says who is CAUSING load; pressure says
who is SUFFERING from it. They are different measurements and they disagree
in exactly the interesting cases — a container pegging a core with no
contention stalls nobody, and a workload starved by someone else's I/O is
stalled while consuming almost nothing. The product had the second, for one
workload kind, on one page; both are read here on the same pass.

WHAT SUMS AND WHAT DOES NOT — and this corrected the design that preceded it.
The counters are additive, so a host total minus the top-level cgroups is a
real quantity and the unattributed remainder can be stated. PSI is a share of
wall time and is NOT additive: a slice at 55% is not the sum of anything, and
a "share of I/O time" per workload with a percentage remainder is a figure
with no denominator behind it. That figure was in this feature's own mockup
and is not implemented, because it cannot be measured. The honest
reconciliation for pressure is attribution — naming the member that accounts
for a stall, or stating positively that every member was read and none does —
which is why the root cgroup is now walked: a host stalled 54.55% whose worst
workload reads 5.14% had nowhere for that answer to live.

THE REMAINDER IS STATED FOR CPU ONLY, and the restraint is the point. CPU has
an unambiguous host denominator in /proc/stat, and subtracting the top-level
cgroups leaves work inside no slice: kernel threads, an md resync, a scrub.
Two corrections the live estate made to that figure, both invisible on the
machine it was written on — stolen time is not busy and is now its own fact,
and the leftover sits in the ROOT cgroup rather than in no cgroup at all.
Memory does not — page cache is charged to whoever first touched it
and kernel slab is charged to nobody, so "used" is a heuristic, not a total.
Block I/O does not either: /proc/diskstats counts a partition, its whole
disk, and the md or dm device stacked over them, so summing it double-counts
by an amount that depends on the storage layout. Publishing a remainder there
would be inventing precision, so those two are absent rather than wrong.
"""

from __future__ import annotations

import os

import anyio

from .. import envelope as env
from ..rules.resources import (slice_opinions, slice_stall_deferred,
                               workload_opinions)

CGROUP_ROOT = "/sys/fs/cgroup"
PRESSURE_RESOURCES = ("io", "cpu", "memory")
# Unit types that get a cgroup. Slices are included: a slice's consumption is
# the aggregate of everything under it, which is how an operator narrows from
# "the host" to "user.slice" to one service.
CGROUP_UNIT_SUFFIXES = (".service", ".scope", ".slice", ".mount", ".socket", ".swap")
# cgroup nesting is shallow in practice (slice → slice → unit); the bound
# stops a pathological tree from turning a page render into a filesystem walk.
CGROUP_MAX_DEPTH = 6

# systemd's own name for the root cgroup. Not an invention: `systemctl status
# -.slice` resolves, and the root is where the host's own total lives — the
# figure every member is a share of, and the one thing the previous walk
# deliberately skipped ("the root cgroup is inside nothing"), which is why the
# host's stall could never be reconciled against the workloads inside it.
ROOT_SLICE = "-.slice"

PROC_STAT = "/proc/stat"

# Every PSI fact this adapter will publish, spelled out. The names are BUILT
# from the file's own contents, so without this they would exist only as an
# f-string and the fact dictionary could not be checked against them — a fact
# nobody can document is a fact nobody can look up. Declaring the vocabulary
# also makes the filter below meaningful in the other direction: a kernel key
# outside this set is dropped rather than published under a name with no
# entry beside it. The three windows are kernel ABI and have not changed since
# PSI landed, and cpu "full" is deliberately absent because the kernel defines
# it as always zero.
PSI_FACTS = frozenset({
    "PsiIoSomeAvg10", "PsiIoSomeAvg60", "PsiIoSomeAvg300",
    "PsiIoFullAvg10", "PsiIoFullAvg60", "PsiIoFullAvg300",
    "PsiCpuSomeAvg10", "PsiCpuSomeAvg60", "PsiCpuSomeAvg300",
    "PsiMemorySomeAvg10", "PsiMemorySomeAvg60", "PsiMemorySomeAvg300",
    "PsiMemoryFullAvg10", "PsiMemoryFullAvg60", "PsiMemoryFullAvg300",
})

REFERENCE = [
    "systemd-cgls",
    "systemd-cgtop",
    "cat /sys/fs/cgroup/<unit-cgroup>/cpu.stat",
    "cat /sys/fs/cgroup/<unit-cgroup>/memory.current",
    "cat /sys/fs/cgroup/<unit-cgroup>/memory.peak",
    "cat /sys/fs/cgroup/<unit-cgroup>/memory.swap.current",
    "cat /sys/fs/cgroup/<unit-cgroup>/memory.events",
    "cat /sys/fs/cgroup/<unit-cgroup>/io.stat",
    "cat /sys/fs/cgroup/<unit-cgroup>/{io,cpu,memory}.pressure",
    "cat /sys/fs/cgroup/cgroup.controllers",
    # The host denominator the unattributed remainder is measured against.
    # Named because the subtraction is only checkable if both sides are.
    "cat /proc/stat",
]

_KINDS = {
    "Parent": "derived", "Depth": "derived", "Delegated": "derived",
    "UnattributedCpuUsec": "derived",
    # Which of a slice's own members account for its stall — a walk over the
    # tree, not a reading.
    "StallExplainedBy": "derived", "StallUnexplained": "derived",
    "StallAttributionUnobservable": "derived",
}

_GLOSSARY = {
    "Parent": "The cgroup this one sits directly inside, by systemd's name for it — the rung above on the ladder, and what makes a total decomposable rather than merely large.",
    "Depth": "How far below the root cgroup this workload sits; the root itself is 0.",
    "Delegated": "This unit was given its cgroup subtree to manage — a container runtime, a user manager, a VM supervisor — so its numbers are the aggregate of a hierarchy whose members are another manager's and have no rows here. It is why a figure on this row cannot be broken down further.",
    "CpuUsageUsec": "Total CPU time this workload and everything under it has consumed since the cgroup was created, in microseconds. A counter, never a rate: the window a rate needs belongs to whoever is watching, and this process has only one sample.",
    "CpuUserUsec": "The part of CpuUsageUsec spent in user code.",
    "CpuSystemUsec": "The part of CpuUsageUsec spent in the kernel on this workload's behalf.",
    "CpuThrottledUsec": "How long this workload has been held stopped by its own CPU quota. It is the answer to 'it is slow and nothing is contended' — a limit, not a shortage, and invisible to every pressure reading.",
    "CpuThrottledPeriods": "How many accounting periods ended with this workload throttled; against CpuThrottledUsec it separates brief frequent clipping from long stalls.",
    "MemoryCurrentBytes": "Memory charged to this workload right now, including the page cache it caused to be read. Absent rather than zero where the controller is off or the kernel does not keep it — a cgroup nobody measured is not a cgroup using nothing.",
    "MemoryPeakBytes": "The high-water mark of MemoryCurrentBytes since the cgroup was created; the figure a limit has to clear, which the current value hides.",
    "MemorySwapCurrentBytes": "Swap charged to this workload — memory it was given and then lost the fast copy of.",
    "MemoryOomKills": "How many processes the kernel has killed in this workload for exceeding memory. It survives what nothing else does: systemd restarts the service, the unit returns to active, and this counter is the only trace left that it happened.",
    "MemoryOomEvents": "How many times this workload hit its memory limit and had to reclaim or block, whether or not anything was killed.",
    "IoReadBytes": "Bytes read from block devices by this workload and everything under it, summed across devices — per-device detail belongs to storage, which owns the objects those devices are.",
    "IoWrittenBytes": "Bytes written to block devices by this workload and everything under it, summed across devices.",
    "IoReadOps": "Read requests issued to block devices by this workload.",
    "IoWriteOps": "Write requests issued to block devices by this workload.",
    "HostCpuBusyUsec": "Every microsecond of CPU this host actually spent doing work, from the kernel's own accounting rather than from any cgroup — the denominator the workloads below are a share of. Time stolen by a hypervisor is excluded and carried separately: the vCPU was not running, so counting it here would inflate the remainder below by however contended this machine's neighbours are.",
    "HostCpuStolenUsec": "CPU time a hypervisor gave to somebody else while this machine wanted it — present only on a virtualised host that has lost any, and absent rather than zero on bare metal. It is neither busy nor idle, which is why it is its own fact: it is the work this host did not get to do.",
    "UnattributedCpuUsec": "Host CPU spent inside no top-level slice, and therefore belonging to no workload row here: kernel threads, an md resync, a scrub, writeback. On most kernels those tasks do sit in a cgroup — the root one — so this is deliberately not called work in no cgroup at all. Stated for CPU alone, because it is the one resource whose host total has an unambiguous denominator: memory's is a heuristic and block I/O's double-counts every stacked device, and a remainder nobody can defend is worse than none.",
    "PsiIoFullAvg10": "The share of the last 10 seconds in which every task in this workload that had work to do was waiting on I/O.",
    "PsiIoFullAvg60": "The share of the last minute in which every task in this workload that had work to do was waiting on I/O. Tasks with nothing to do are not counted, so this is 'made no progress', not 'everything is stuck'.",
    "PsiIoFullAvg300": "The same share over the last five minutes, which is where a brief spike and a standing problem separate.",
    "PsiIoSomeAvg10": "The share of the last 10 seconds in which at least one task here was waiting on I/O.",
    "PsiIoSomeAvg60": "The share of the last minute in which at least one task here was waiting on I/O — it aggregates as a union up the tree, so a parent is normally at least its children and it is never used for attribution.",
    "PsiIoSomeAvg300": "The same share over the last five minutes.",
    "PsiCpuSomeAvg10": "The share of the last 10 seconds in which at least one task here was runnable but waiting for a CPU.",
    "PsiCpuSomeAvg60": "The share of the last minute in which at least one task here was runnable but waiting for a CPU — contention, which is a different thing from the CPU time this workload actually got.",
    "PsiCpuSomeAvg300": "The same share over the last five minutes.",
    "PsiMemoryFullAvg10": "The share of the last 10 seconds in which every task here that had work to do was waiting on memory reclaim.",
    "PsiMemoryFullAvg60": "The share of the last minute in which every task here that had work to do was waiting on memory reclaim.",
    "PsiMemoryFullAvg300": "The same share over the last five minutes.",
    "PsiMemorySomeAvg10": "The share of the last 10 seconds in which at least one task here was waiting on memory reclaim.",
    "PsiMemorySomeAvg60": "The share of the last minute in which at least one task here was waiting on memory reclaim.",
    "PsiMemorySomeAvg300": "The same share over the last five minutes.",
    "StallExplainedBy": "The workload inside this slice whose own stall accounts for the slice's, per resource. A slice only counts time in which every non-idle task under it was stalled, so a member that caused it reads at least as high — and the member's row is where the finding belongs, with a name on it.",
    "StallUnexplained": "Every member of this slice was read and none of them accounts for its stall, per resource. On the root slice this is the statement that the host's stall is not any workload's fault — it is kernel work in no cgroup, which no row here will ever carry.",
    "StallAttributionUnobservable": "Why this slice's stall could be neither attributed nor ruled out — a member that would not read, a subtree the walk did not reach the bottom of, or a member cgroup that is not a systemd unit and so has no row for its reading to belong to. A gap in the reading, never a finding about the slice.",
}


def _read_text(path: str) -> str | None:
    """One kernel file, or None where it does not exist or will not open.

    Every read in this module goes through here rather than calling open()
    directly, and that is a conformance requirement as much as a tidiness
    one: the reference-command lint resolves paths through a reviewed table
    of reader helpers, and a bare open() is invisible to it — the module
    would read /proc/stat while the lint reported it reads nothing.
    """
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return None


def _walk(root: str, onerror):
    """The cgroup tree's directory structure, and the module's ONE walk.

    Here for the same reason `_read_text` is, one level up: every read in this
    module goes through a named helper so a lint can see it, and until now the
    WALK went through a bare os.walk that no lint and no replay seam could
    reach. That asymmetry is what kept this collector out of the corpus. Its
    reads are stubbable and its tree was not, so a replayed run would have
    enumerated the cgroups of whichever machine was replaying — the seam
    escape that once put a workstation's filesystem into committed facts, and
    the one failure this repository has paid for twice.

    The interface a cgroup collector reads is a filesystem, so its native
    document is the filesystem transcribed: the listings this yields plus the
    contents `_read_text` returns. Both halves have to be capturable for that
    to be true of a replay, and a reader with the payload can `cat` any path
    and compare, which is the checkable-reading property the D-Bus ruling
    turns on (DESIGN's adjudication queue).

    A thin wrapper on purpose. It adds no behaviour — onerror still carries
    the unlistable-subtree reporting that os.walk would otherwise discard in
    silence — because a seam that changed what it wraps would be a second
    implementation rather than a seam.
    """
    return os.walk(root, onerror=onerror)


def _read_or_reason(path: str) -> str:
    """The same read for evidence, where a failure is itself the answer: a
    file that will not open is shown as the reason it did not, because
    omitting it would let an unreadable counter look like one the kernel
    does not keep."""
    try:
        with open(path) as handle:
            return handle.read()
    except OSError as exc:
        return env.reason(f"{type(exc).__name__}: {exc}")


def _read_pressure(path: str) -> dict:
    """One resource's PSI file as facts, or {} if it is not there.

    A kernel without CONFIG_PSI, or a cgroup that predates the controller,
    simply has no file — the facts are then absent, never zero, because zero
    would read as a measured absence of stalling.
    """
    text = _read_text(path)
    if text is None:
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
            fact = f"Psi{resource}{share}Avg{key[3:]}"
            if key.startswith("avg") and fact in PSI_FACTS:
                try:
                    facts[fact] = float(value)
                except ValueError:
                    pass
    return facts


def _read_int(path: str) -> int | None:
    """A single-value cgroup file, or None where it does not exist.

    None and 0 are different answers and the difference is load-bearing:
    memory.current is absent on the root cgroup by kernel design, absent
    where the controller is not enabled, and absent on kernels older than the
    file. Rendering any of those as 0 would report a workload consuming
    nothing, which is a measurement nobody took.
    """
    text = _read_text(path)
    try:
        return int((text or "").strip())
    except ValueError:
        return None


def _read_keyed(path: str) -> dict:
    """A flat `key value` cgroup file (cpu.stat, memory.events) as ints."""
    out: dict = {}
    text = _read_text(path)
    if text is None:
        return out
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2:
            try:
                out[fields[0]] = int(fields[1])
            except ValueError:
                pass
    return out


def _read_io(path: str) -> dict:
    """io.stat summed across every backing device.

    Per-device detail is dropped deliberately: this collection answers "which
    workload is doing the I/O", and a device breakdown belongs to storage,
    which already owns the objects those major:minor pairs name. Summing is
    safe here in a way it is not for a host denominator — every number comes
    from one cgroup's own accounting, so nothing is counted twice.
    """
    text = _read_text(path)
    if text is None:
        return {}
    totals: dict = {}
    for line in text.splitlines():
        for token in line.split()[1:]:
            key, _, value = token.partition("=")
            try:
                totals[key] = totals.get(key, 0) + int(value)
            except ValueError:
                pass
    facts: dict = {}
    for key, fact in (("rbytes", "IoReadBytes"), ("wbytes", "IoWrittenBytes"),
                      ("rios", "IoReadOps"), ("wios", "IoWriteOps")):
        if key in totals:
            facts[fact] = totals[key]
    return facts


def _read_counters(dirpath: str) -> dict:
    """What this cgroup has consumed since it was created.

    Counters, never rates. SPEC section 12 forbids deriving a rate here: the
    consumer knows the window it observed across and this process does not,
    and a rate computed from one sample is a number with a denominator nobody
    chose. Every fact below is a monotonic total the kernel maintains.
    """
    facts: dict = {}
    cpu = _read_keyed(f"{dirpath}/cpu.stat")
    for key, fact in (("usage_usec", "CpuUsageUsec"),
                      ("user_usec", "CpuUserUsec"),
                      ("system_usec", "CpuSystemUsec"),
                      # Throttling is the answer to "it is slow and nothing
                      # is contended": a workload under a quota is stopped by
                      # its own limit, which no pressure reading reports and
                      # no utilisation figure hints at.
                      ("throttled_usec", "CpuThrottledUsec"),
                      ("nr_throttled", "CpuThrottledPeriods")):
        if key in cpu:
            facts[fact] = cpu[key]
    for name, fact in (("memory.current", "MemoryCurrentBytes"),
                       ("memory.peak", "MemoryPeakBytes"),
                       ("memory.swap.current", "MemorySwapCurrentBytes")):
        value = _read_int(f"{dirpath}/{name}")
        if value is not None:
            facts[fact] = value
    events = _read_keyed(f"{dirpath}/memory.events")
    # An OOM kill is the loudest thing that happens to a workload and it
    # leaves no trace on a unit row: systemd restarts the service, ActiveState
    # returns to active, and the only survivor is this counter.
    for key, fact in (("oom_kill", "MemoryOomKills"), ("oom", "MemoryOomEvents")):
        if key in events:
            facts[fact] = events[key]
    facts.update(_read_io(f"{dirpath}/io.stat"))
    return facts


def _nodes() -> dict[str, dict]:
    """{key: node} for every cgroup in the tree, in one walk.

    A node is {"facts": readings, "path": the cgroup directory this node IS,
    "parent": the enclosing cgroup's key or None, "depth": nesting below the
    root, "unit": whether its name is a systemd unit's, "managed": whether
    every cgroup between this one and the root is a slice, which is what makes
    it THIS host's systemd's own, "pruned": children left unread — the depth
    bound, or a listing that failed part-way}. The parent link is what makes a
    slice's stall attributable at all: the kernel aggregates PSI over the
    CGROUP tree, so that tree is the join, and it costs nothing beyond the
    walk the row facts already need.

    A node is recorded even when it yielded no readings. Presence and
    readability are different answers — a member whose consumption could not
    be read must not be counted as a member that is quiet — and only a walk
    that keeps the empty ones can tell them apart.

    Unit names are NOT unique across the tree: a user manager runs its own
    init.scope, app.slice and dbus.service inside user@<uid>.service, and
    those names collide with system units. The shallowest occurrence wins,
    because the system manager's own units are the rows this collection
    serves; merging by name let whichever the walk reached last decide, which
    is a coin toss over whose consumption a row reports.

    Which is why parentage is resolved by PATH at the end rather than by the
    enclosing directory's basename. A cgroup that lost that collision is not
    in this map, so its basename names the WINNER, and its children would
    attach to that unrelated unit as direct members — the door through which a
    guest's postgresql.service, inside machine.slice, comes to be named as
    what explains the HOST's system.slice stall (reviewed 2026-08-13,
    reproduced under systemd-nspawn, systemd-in-docker and rootless podman).

    A cgroup no systemd named is kept too, keyed by its path because it has no
    name to be known by: a cgroupfs-driver runtime under --cgroup-parent puts
    one directly under a slice, and dropping it made its consumption invisible
    to the member count, so the slice above claimed every member had been read.
    """
    found: dict[str, dict] = {}
    root_depth = CGROUP_ROOT.rstrip("/").count("/")

    def place(dirpath: str, depth: int) -> dict | None:
        """The fresh node for this cgroup, or None where the name is already
        held at the same depth or shallower. Units are keyed by name — the
        collision rule above — and everything else by path."""
        name = ROOT_SLICE if depth == 0 else os.path.basename(dirpath)
        unit = name.endswith(CGROUP_UNIT_SUFFIXES)
        key = name if unit else dirpath
        held = found.get(key)
        if held is not None and held["depth"] <= depth:
            return None
        node: dict = {"facts": {}, "path": dirpath, "parent": None,
                      "depth": depth, "unit": unit, "pruned": False}
        found[key] = node
        return node

    def unlistable(error: OSError) -> None:
        """A cgroup directory the walk could not list — denied, or removed
        under it, which is the ordinary end of a transient scope. os.walk
        discards such a subtree without a word by default, and that silence is
        the failure this module exists to prevent: the member would be neither
        counted, nor named as unread, nor recorded as a cut, and the slice
        above it would go on to state positively that every member was read.
        Recorded as a member that yielded no readings, which is what it is."""
        path = str(getattr(error, "filename", "") or "").rstrip("/")
        depth = path.count("/") - root_depth
        # At or below the bound the cut is already carried by the parent's
        # `pruned`, and recording it would publish a node the successful path
        # deliberately omits.
        if not path or depth <= 0 or depth >= CGROUP_MAX_DEPTH:
            return
        if place(path, depth) is None:
            # os.walk also calls this when a directory it had already yielded
            # fails part-way through iteration: the node exists, and what is
            # missing is below it.
            held = found.get(os.path.basename(path)) or found.get(path)
            if held is not None and held["path"] == path:
                held["pruned"] = True

    for dirpath, dirnames, _files in _walk(CGROUP_ROOT, unlistable):
        depth = dirpath.count("/") - root_depth
        if depth >= CGROUP_MAX_DEPTH:
            dirnames[:] = []
            continue
        node = place(dirpath, depth)
        if node is None:
            continue
        for resource in PRESSURE_RESOURCES:
            node["facts"].update(_read_pressure(f"{dirpath}/{resource}.pressure"))
        node["facts"].update(_read_counters(dirpath))
        # The children this walk will refuse to descend into. A slice whose
        # subtree was cut short cannot be said to have no member explaining
        # its stall, so the cut has to be recorded where the attribution can
        # see it.
        node["pruned"] = depth + 1 >= CGROUP_MAX_DEPTH and bool(dirnames)

    by_path = {node["path"]: key for key, node in found.items()}
    for node in found.values():
        if node["depth"]:
            node["parent"] = by_path.get(os.path.dirname(node["path"]))

    # Which of these cgroups this host's systemd is the one that named. A
    # reading may only reach the row of the unit whose OWN cgroup it is, and
    # that is decided by the ancestry: systemd puts services and scopes in
    # slices and slices in slices, so a cgroup reached from the root through
    # slices alone is this manager's, and anything below a delegated .service
    # or .scope was named by whatever runs inside it. Same boundary
    # _slice_members refuses to descend past, applied to rows instead of
    # members — without it, a container's own nginx.service, unique enough to
    # survive the collision rule above, hands its readings to the host's
    # loaded-but-inactive unit of that name: a bare number on a row that is
    # not about it, with nothing to mark it.
    for node in sorted(found.values(), key=lambda entry: entry["depth"]):
        parent_key = node["parent"]
        if node["depth"] == 0:
            node["managed"] = True      # the root is this manager's by definition
        elif parent_key is None:
            # Not in the map: a cgroup that lost the name collision — a
            # hierarchy this walk declined to represent, so nothing under it
            # is. The root itself is handled above and never reaches here.
            node["managed"] = False
        else:
            parent = found[parent_key]
            node["managed"] = (parent["managed"] and parent["unit"]
                               and parent_key.endswith(".slice"))
    return found


def _by_unit(found: dict[str, dict]) -> dict[str, dict]:
    """{unit name: readings} — the row-facing half of the walk, and the one
    place a reading becomes a row's.

    Two things stop it. A cgroup systemd did not name has nothing here to be,
    and a cgroup below a delegated unit is another manager's ("managed"): the
    delegating unit's own cgroup already carries its aggregate and is already
    a row. So a unit that owns no cgroup gets no facts at all — absent, which
    reads as does-not-apply, rather than the zero that would read as measured
    calm.
    """
    return {name: node["facts"] for name, node in found.items()
            if node["facts"] and node["unit"] and node["managed"]}


# ── attributing a slice's stall to the workload inside it ────────────
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


def _slice_members(name: str, found: dict[str, dict],
                   children: dict[str, list[str]]) -> tuple[list[tuple[str, int]], list[str]]:
    """(members with their depth below the slice, slices whose subtree was cut).

    Descent stops at anything that is not a slice UNIT. A .service or .scope
    with a cgroup subtree of its own has been DELEGATED that subtree —
    user@<uid>.service runs a whole second systemd, a container scope runs a
    container's own hierarchy — and the units in it belong to that manager,
    not this one. Naming one would be a reference this collection cannot
    resolve, and worse, those names collide with system units (dbus.service
    exists in both), so the reference could resolve to the wrong object
    entirely. A cgroup systemd never named is delegated for the same reason
    and stops descent the same way. The delegating cgroup carries their
    aggregate, and where it is a unit it IS a row here.
    """
    members: list[tuple[str, int]] = []
    cut: list[str] = []
    queue = [(name, 0)]
    seen = {name}
    while queue:
        parent, depth = queue.pop()
        if found[parent]["pruned"]:
            cut.append(parent)
        for child in sorted(children.get(parent, ())):
            if child in seen:
                continue
            seen.add(child)
            members.append((child, depth + 1))
            if found[child]["unit"] and child.endswith(".slice"):
                queue.append((child, depth + 1))
    return members, cut


def _stall_attribution(found: dict[str, dict],
                       only: str | None = None) -> dict[str, dict]:
    """{slice name: attribution facts}, per pressure reading.

    Exactly one of three states is stated for each resource a slice reports a
    stall on, and each is stated POSITIVELY, because the three are what a
    reader would otherwise have to infer from an absence:

      StallExplainedBy               a member workload reads at least as high
      StallUnexplained               every member was read and none does
      StallAttributionUnobservable   a member could not be read, or could not
                                     be attributed, so neither of the above
                                     can be claimed

    The third exists because the alternative is the failure this product is
    built against: a cgroup whose pressure files could not be read looks
    exactly like a cgroup that is not stalling, and counting it as quiet
    would turn "we did not see it" into "nothing inside explains this" — the
    most interesting finding here, manufactured out of a gap in the reading.
    A member cgroup that is not a systemd unit is the same failure by another
    door: it was read, but it has no row for the reading to belong to.

    The root slice is judged like any other, and that is the point of it
    being walked at all: a host stalled 55% of the last minute whose worst
    workload reads 5% is the reconciliation an operator arrives needing, and
    until the root was included there was nowhere for the answer — "every
    workload was read and none of them accounts for this" — to be stated.
    """
    children: dict[str, list[str]] = {}
    for name, node in found.items():
        if node["parent"]:
            children.setdefault(node["parent"], []).append(name)

    out: dict[str, dict] = {}
    for name, node in found.items():
        # Keyed by name, and consumed by the row of that name: a slice inside
        # a delegated hierarchy would otherwise publish its members onto the
        # host's slice of the same name, naming units this collection cannot
        # resolve. Its own manager's aggregate is the delegating unit's row.
        if not (node["unit"] and node["managed"] and name.endswith(".slice")):
            continue
        if only is not None and name != only:
            continue
        members, cut = _slice_members(name, found, children)
        facts: dict = {}
        for fact, resource in ATTRIBUTED_PRESSURE_FACTS.items():
            value = node["facts"].get(fact)
            if not isinstance(value, (int, float)) or value <= 0:
                continue
            readings = [(found[member]["facts"].get(fact), member, depth)
                        for member, depth in members]
            unread = sorted(member for reading, member, _depth in readings
                            if not isinstance(reading, (int, float)))
            # A cgroup systemd never named has no row in this collection, so
            # its reading can be counted but never attributed — and it must
            # never be NAMED as the explanation, which is why it is kept out
            # of `accounts` below as well.
            foreign = sorted(member for _reading, member, _depth in readings
                             if not found[member]["unit"])
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
                 if found[member]["unit"]
                 and isinstance(reading, (int, float)) and reading >= value - slack),
                key=lambda entry: (-entry[0], -entry[1], entry[2]))
            if accounts:
                facts.setdefault("StallExplainedBy", {})[fact] = accounts[0][2]
            elif cut:
                # Worded for both reasons a subtree goes unread — the depth
                # bound and a directory listing that failed — because `pruned`
                # now carries both and only one of them is about depth.
                facts.setdefault("StallAttributionUnobservable", {})[fact] = (
                    f"the cgroup tree below {', '.join(sorted(cut))} was not "
                    "read to the bottom, so a member in it could still "
                    "account for this.")
            elif unread:
                facts.setdefault("StallAttributionUnobservable", {})[fact] = (
                    f"no {resource} pressure reading for {len(unread)} of the "
                    f"{len(members)} member cgroups under this slice "
                    f"({', '.join(unread[:3])}"
                    f"{f' and {len(unread) - 3} more' if len(unread) > 3 else ''}"
                    "), so a member could still account for this.")
            elif foreign:
                facts.setdefault("StallAttributionUnobservable", {})[fact] = (
                    f"{len(foreign)} of the {len(members)} member cgroups "
                    "under this slice are not systemd units, so their "
                    f"{resource} pressure belongs to no row here and can be "
                    f"neither attributed nor ruled out ({', '.join(foreign[:3])}"
                    f"{f' and {len(foreign) - 3} more' if len(foreign) > 3 else ''})."
                )
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


def _host_cpu_totals() -> tuple[int, int] | None:
    """(busy, stolen) microseconds from /proc/stat, as two separate answers.

    guest and guest_nice are deliberately not added: the kernel already
    counts them inside user and nice, so including them would inflate the
    denominator and make the remainder below larger than it is.

    STEAL IS NOT BUSY, and separating it corrects a figure this adapter
    published. Steal is time the hypervisor gave to somebody else — the vCPU
    was not running, so it is not work this host did and cannot be work
    belonging to no workload on it. Counting it as busy inflated the
    unattributed remainder by exactly the stolen time, which is invisible on
    bare metal and grows with how contended the host's neighbours are
    (measured 2026-08-13: 18.5 s of a 101 s remainder on the estate's one
    shared VPS, against 0.0 s on all four bare-metal hosts). Excluding it
    also makes the total agree with the root cgroup's own accounting on every
    host including the virtualised one, which is the check that says the
    definition is now right.

    Stolen time is returned rather than dropped, because "this VM lost 18.5 s
    to its neighbours" is a fact about the host that nothing else here says.
    """
    text = _read_text(PROC_STAT)
    if text is None:
        return None
    fields = text.split("\n", 1)[0].split()
    if not fields or fields[0] != "cpu" or len(fields) < 9:
        return None
    try:
        values = [int(value) for value in fields[1:9]]
    except ValueError:
        return None
    user, nice, system, _idle, _iowait, irq, softirq, steal = values
    per_tick = 1_000_000 // (os.sysconf("SC_CLK_TCK") or 100)
    return ((user + nice + system + irq + softirq) * per_tick, steal * per_tick)


def _unattributed_cpu(found: dict[str, dict]) -> dict:
    """Host CPU inside no top-level slice, and the total it came from.

    The subtraction is against the TOP-LEVEL cgroups rather than against the
    root's own cpu.stat, because what the root reports for itself varies by
    kernel version while the depth-1 sum does not: every cgroup on the host
    is inside exactly one of them, so the difference is precisely the work
    that is inside none — kernel threads, an md resync, a scrub, writeback.

    "In no top-level slice" and NOT "in no cgroup at all", which is how this
    was first worded. Measured across the estate 2026-08-13: on four of five
    hosts the root cgroup's own cpu.stat equals the host total to within
    rounding, so those kernel threads do sit in a cgroup — the root one. They
    sit in no slice below it, which is what makes them belong to no workload
    row, and that is the claim this fact can actually support.

    /proc/stat is read AFTER the walk, deliberately. Both sides are monotonic
    counters, so a total sampled later than its parts can only be larger:
    reading in this order makes a negative remainder impossible by
    construction, where clamping one to zero afterwards would hide a real
    inconsistency behind a plausible number.
    """
    attributed = 0
    seen = False
    for node in found.values():
        if node["depth"] != 1:
            continue
        value = node["facts"].get("CpuUsageUsec")
        if isinstance(value, int):
            attributed += value
            seen = True
    if not seen:
        return {}
    totals = _host_cpu_totals()
    if totals is None:
        return {}
    busy, stolen = totals
    facts = {"HostCpuBusyUsec": busy,
             "UnattributedCpuUsec": max(0, busy - attributed)}
    # Only where there is some: a bare-metal host would otherwise carry a
    # standing zero for a condition it cannot have, and this collection's
    # whole discipline is that a fact appears when it was measured.
    if stolen:
        facts["HostCpuStolenUsec"] = stolen
    return facts


# What a collection row carries. Consumption is the whole point of this
# collection, so a row keeps the figures an operator ranks by; the ten-second
# and five-minute PSI windows and the finer CPU split belong to the opened
# object, which is where a spike is separated from a standing problem.
ROW_FACTS = (
    "Parent", "Depth", "Delegated",
    "CpuUsageUsec", "CpuThrottledUsec",
    "MemoryCurrentBytes", "MemoryPeakBytes", "MemoryOomKills",
    "IoReadBytes", "IoWrittenBytes",
    "PsiIoFullAvg60", "PsiCpuSomeAvg60", "PsiMemoryFullAvg60",
    "HostCpuBusyUsec", "UnattributedCpuUsec",
    "StallExplainedBy", "StallUnexplained", "StallAttributionUnobservable",
)


def _row_health(name: str, facts: dict) -> str:
    """The severity a row takes when its evaluator says nothing.

    "ok" is a VOUCH — envelope's positively-healthy value, painted as a green
    dot — so it cannot be the answer for a slice whose stall this rulebook
    deliberately declined to judge (rules/resources.py: the member's row
    carries that condition, with the name on it). A green dot beside a
    measured 56.35% says the evaluator looked and found nothing wrong; neutral
    is the honest mark for a number nobody judged.

    Unchanged from the units collection this moved out of, deliberately: the
    value was argued once and a move is not the place to re-open it. What is
    gone is the inactive branch, because a row here exists only where a
    reading does and there is no ActiveState to consult.
    """
    if name.endswith(".slice") and slice_stall_deferred(facts):
        return "info"
    return "ok"


class Adapter:
    subsystem = "resources"

    def collections(self) -> list[str]:
        return ["workloads"]

    async def capability(self) -> dict:
        # cgroup.controllers exists only on a cgroup v2 mount, which is what
        # every fact here is read from. A v1 host, a container without the
        # host's cgroupfs, or a kernel built without it are all "this cannot
        # be observed here" and each says which — never an empty collection,
        # which would read as a host running nothing.
        controllers = f"{CGROUP_ROOT}/cgroup.controllers"
        if not os.path.exists(controllers):
            return {"available": False, "reason": (
                f"no {controllers}: this host does not present a unified"
                " cgroup v2 hierarchy, which is where per-workload CPU,"
                " memory, I/O and pressure accounting live. A cgroup v1 host"
                " keeps the same numbers in per-controller trees this adapter"
                " deliberately does not read.")}
        return {"available": True, "collections": self.collections()}

    def fact_glossary(self, collection: str) -> dict:
        return _GLOSSARY if collection == "workloads" else {}

    def fact_kinds(self, collection: str) -> dict[str, str] | None:
        """Every counter here is read from cgroupfs; every ATTRIBUTION is
        arithmetic on top of it. The remainder in particular — host busy
        time minus the sum of the top-level slices — is a subtraction across
        two files read moments apart, and it is the figure most likely to be
        quoted as though the kernel had stated it."""
        return _KINDS if collection == "workloads" else None

    def _source(self) -> dict:
        return env.source(
            "cgroup-v2", "cgroupfs", REFERENCE,
            method=f"walk {CGROUP_ROOT} + read {PROC_STAT}",
            notes=["Counters are totals since each cgroup was created, never"
                   " rates: the window a rate needs belongs to the consumer,"
                   " which knows what it observed across, and this process"
                   " has one sample.",
                   "An unattributed remainder is stated for CPU alone."
                   " Memory's host total is a heuristic and block I/O's"
                   " double-counts every stacked device, so a remainder for"
                   " those would be invented precision rather than a"
                   " measurement."])

    @staticmethod
    def _kind(name: str) -> str:
        """systemd's own unit type, so an id means the same thing in both
        projections: `unit:nginx.service` is a `service` here and a `service`
        in units/units, and a consumer joining the two never has to translate
        a vocabulary this collection made up."""
        return name.rpartition(".")[2] or "unit"

    def _items(self) -> list[dict]:
        found = _nodes()
        attribution = _stall_attribution(found)
        remainder = _unattributed_cpu(found)
        # Every cgroup below a unit that owns a subtree belongs to another
        # manager, so the delegating unit's own row is where that whole
        # hierarchy's numbers are — and saying so on the row is what stops a
        # figure that cannot be broken down here looking like one nobody
        # bothered to break down.
        delegating = {node["parent"] for node in found.values()
                      if node["parent"] is not None}
        rows = _by_unit(found)
        # The root earns a row on the remainder alone. _by_unit keeps only
        # cgroups that yielded readings, and the root legitimately yields
        # none on plenty of kernels — cgroup v2 gives it no memory.current
        # and a host without CONFIG_PSI gives it no pressure files — so
        # without this the host total and the work belonging to no workload
        # both disappear on exactly the hosts where the walk still worked.
        if remainder and ROOT_SLICE in found and ROOT_SLICE not in rows:
            rows = {**rows, ROOT_SLICE: found[ROOT_SLICE]["facts"]}
        items = []
        for name, readings in sorted(rows.items()):
            node = found[name]
            facts = dict(readings)
            if node["parent"]:
                facts["Parent"] = node["parent"]
            facts["Depth"] = node["depth"]
            if name in delegating and not name.endswith(".slice"):
                facts["Delegated"] = True
            facts.update(attribution.get(name, {}))
            if node["depth"] == 0:
                facts.update(remainder)
            is_slice = name.endswith(".slice")
            opinions = (slice_opinions(facts) if is_slice
                        else workload_opinions(facts))
            # Severity is derived from the FULL fact set, and the row is
            # trimmed afterwards in collect(). Judging the trimmed copy would
            # let a row's dot depend on which facts happened to be carried,
            # which is the drift rule 14 was made structural to stop.
            items.append(env.item_summary(
                f"unit:{name}", self._kind(name), name, facts,
                opinions=opinions, healthy=_row_health(name, facts)))
        return items

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection != "workloads":
            raise env.UnknownCollection(collection)
        return await anyio.to_thread.run_sync(self._items)

    async def collect(self, collection: str, query: dict, limit: int | None,
                      cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        # Trimmed here rather than at build time: the opened object needs the
        # full set, and filters must only see what a row actually carries, so
        # the trim has to happen before apply_fact_filters and after the
        # severity above.
        rows = [{**item, "facts": {fact: value for fact, value
                                   in item["facts"].items()
                                   if fact in ROW_FACTS}}
                for item in fetched]
        items = env.apply_fact_filters(rows, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, self._source(),
                                   page, applied, next_cursor,
                                   requested_limit=limit, total=total,
                                   filters=query or None)

    async def get_object(self, collection: str, object_id: str) -> dict:
        matches = [item for item in await self.acquire(collection)
                   if item["id"] == object_id]
        if not matches:
            raise env.UnknownObject(object_id)
        item = matches[0]
        facts = item["facts"]
        is_slice = item["native_id"].endswith(".slice")
        opinions = slice_opinions(facts) if is_slice else workload_opinions(facts)
        return env.observation(
            self.subsystem,
            env.obj_ref(item["id"], item["type"], item["native_id"]),
            self._source(), facts, opinions=opinions or None,
            evidence_ref=env.evidence_ref(self.subsystem, collection,
                                          item["id"]))

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        """The kernel files this row was folded from, verbatim.

        Membership is checked against the same walk the collection is built
        from rather than by joining the id back to a path: a name that only
        exists inside a delegated hierarchy has no row here, and evidence
        that vouched for it would be showing another manager's cgroup as
        though this collection had published it.
        """
        if collection != "workloads":
            raise env.UnknownCollection(collection)
        name = object_id.partition(":")[2]
        found = await anyio.to_thread.run_sync(_nodes)
        node = found.get(name)
        if node is None or not (node["unit"] and node["managed"]):
            raise env.UnknownObject(object_id)
        payload: dict = {}
        for filename in ("cpu.stat", "memory.current", "memory.peak",
                         "memory.swap.current", "memory.events", "io.stat",
                         "io.pressure", "cpu.pressure", "memory.pressure"):
            path = f"{node['path']}/{filename}"
            payload[path] = _read_or_reason(path)
        if node["depth"] == 0:
            # The root row is the only one carrying an unattributed
            # remainder, so it is the only one whose evidence owes the
            # denominator that remainder was computed against.
            payload[PROC_STAT] = _read_or_reason(PROC_STAT)
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "cgroupfs", "payload": payload}
