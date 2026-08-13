"""Resource opinions: who is stalled, and who nothing accounts for.

WHY ONLY PRESSURE IS JUDGED HERE. This module says nothing about the
utilisation counters beside it, and the omission is deliberate rather than
unfinished. A counter is a total since the cgroup was created, so any verdict
drawn from one alone is a verdict without a window: "this service has used
four hours of CPU" is not a finding, and "this workload was OOM-killed" is
true forever once it has happened once, which is the permanently-red board
that teaches an operator to stop reading the board. The consumer knows the
window it observed across and this process does not (SPEC section 12), so the
counters are published as facts and graded by whoever has two samples.

PSI is different and that is why it is judged: the kernel computes it over a
declared 60-second window, so the number already carries the denominator a
verdict needs. The facts and the opinions here are the same ones that were in
rules/units.py — a stall is a statement about consumption, not about a unit's
configuration, so it moved with the measurement rather than staying beside
the unit's declared state.
"""

from __future__ import annotations

from .. import envelope as env

# Per-workload stall shares, judged on the same 60-second window the host
# overview uses so the two agree about what "now" means.
#
# "full" is the share of time in which every NON-IDLE task was stalled, which
# is not the same as every task and must not be worded as if it were. A
# workload with ninety-nine sleeping tasks and one blocked on I/O is "full"
# for as long as that one is blocked, because nothing else wanted to run. The
# distinction is the whole difference between "this is making no progress"
# (true) and "everything in this is stuck" (usually false, and alarming).
#
# Deliberately warn, not critical — a stalled workload is a symptom whose
# cause is usually elsewhere (a saturated device, a degraded pool), and
# calling it critical would put the loudest level on the thing that is
# suffering rather than the thing that is wrong.
WORKLOAD_IO_STALL_WARN = 20.0
WORKLOAD_MEMORY_STALL_WARN = 10.0

# Below this share of the minute a slice states nothing at all. The gap
# between a slice and its members at that size is inside the slack the
# attribution already allows for two independently decaying averages, so a
# claim either way is a coin toss dressed as a finding — and the number stays
# on the row for anyone who wants it.
SLICE_STALL_FLOOR = 1.0

# The share at which a slice's own UNEXPLAINED stall claims attention, per
# resource: the same bar a single workload must clear. Nothing else in the
# product states this condition — every member was read and none accounts for
# it — so at info it is stripped by envelope.attention(), absent from
# /v1/findings and the estate roll-up, and visible only where it wins one of
# five magnitude-ranked overview slots against members whose own rows already
# warn. Between the floor and this bar it stays info, so the floor's
# reasoning is untouched and no new noise is manufactured.
SLICE_STALL_ATTENTION = {"PsiIoFullAvg60": WORKLOAD_IO_STALL_WARN,
                         "PsiMemoryFullAvg60": WORKLOAD_MEMORY_STALL_WARN}

# The readings a slice is judged on, with the wording each takes. One list, so
# the three tables keyed by these facts cannot come to disagree about which
# readings a slice states anything about.
SLICE_STALL_RESOURCES = (("PsiIoFullAvg60", "I/O"),
                         ("PsiMemoryFullAvg60", "memory reclaim"))

# Where to look when the slice cannot name the workload itself. Same
# collection, same fact: the member rows carry their own numbers, and the one
# actually stalling is where the number stays high. Keyed by the fact so the
# loop below picks the hint that matches the resource it is judging.
SLICE_STALL_LOOK = {
    "PsiIoFullAvg60": [{"subsystem": "resources", "collection": "workloads",
                        "fact": "PsiIoFullAvg60",
                        "label": "which workloads are waiting on I/O"}],
    "PsiMemoryFullAvg60": [{"subsystem": "resources", "collection": "workloads",
                            "fact": "PsiMemoryFullAvg60",
                            "label": "which workloads are waiting on memory "
                                     "reclaim"}],
}


def slice_stall_deferred(facts: dict) -> bool:
    """True where this evaluator declined to judge a stall the row CARRIES,
    because a member accounts for it.

    The finding belongs to the member's row and is not restated here (see
    slice_opinions). But silence reaches the row as the no-opinion severity,
    and that value is a positive vouch — so the caller deriving a row's
    severity has to know the difference between "nothing to say" and
    "somebody else says it", or a slice stalled 56.35% of the last minute
    paints the same green dot as an idle one.
    """
    explained = facts.get("StallExplainedBy") or {}
    return any(isinstance(facts.get(fact), (int, float))
               and facts[fact] >= SLICE_STALL_FLOOR and explained.get(fact)
               for fact, _resource in SLICE_STALL_RESOURCES)


def workload_opinions(facts: dict) -> list[dict]:
    """A leaf workload's own stall. Presence-driven: absent on a kernel
    without CONFIG_PSI and on anything with no cgroup, so no fact means no
    opinion, and never a zero standing in for a measurement nobody took."""
    opinions: list[dict] = []
    io_stall = facts.get("PsiIoFullAvg60")
    if isinstance(io_stall, (int, float)) and io_stall >= WORKLOAD_IO_STALL_WARN:
        opinions.append(env.opinion(
            "workload-io-stall", "warn",
            f"This workload made no progress for {io_stall}% of the last "
            "minute: every task in it that had work to do was waiting on I/O. "
            "Tasks with nothing to do are not counted.", ["PsiIoFullAvg60"]))
    memory_stall = facts.get("PsiMemoryFullAvg60")
    if isinstance(memory_stall, (int, float)) \
            and memory_stall >= WORKLOAD_MEMORY_STALL_WARN:
        opinions.append(env.opinion(
            "workload-memory-stall", "warn",
            f"This workload made no progress for {memory_stall}% of the last "
            "minute: every task in it that had work to do was waiting on "
            "memory reclaim. Tasks with nothing to do are not counted.",
            ["PsiMemoryFullAvg60"]))
    return opinions


def slice_opinions(facts: dict) -> list[dict]:
    """The evaluator for slices — the cgroup tree's INTERIOR nodes, where
    every number is an aggregate over the workloads nested under them.

    A slice's "full" share is the time in which every non-idle task under it
    was stalled, so a member making progress LOWERS it: the slice is both
    less specific than the member responsible and smaller than it (operator
    report, 2026-08-13 — a container scope at 65.27% listed directly beneath
    the slice containing it at 56.35%, one stall reported twice, the second
    time with the culprit's name removed). So a slice whose stall a member
    accounts for states nothing at all: the member's own row carries the
    condition, with the name on it.

    What survives is the case no member row can state — a slice stalling that
    nothing inside it accounts for — and, separately, the case where that
    could not be established because a member's pressure could not be read.
    The two are worded differently on purpose: an unread member is not a
    quiet one, and reporting it as "nothing explains this" would invent the
    interesting finding out of a gap in the reading.

    Each resource is judged on its own facts. A slice can be explained for
    I/O and unexplained for memory in the same minute, and one boolean across
    both would be false for one of them.

    Of the three the unexplained case is the only one that claims attention
    (SLICE_STALL_ATTENTION), because it is the only one no other row can
    state: a gap in the reading is not a finding, and a bare aggregate may
    still turn out to be explained.

    The root slice is judged by these same rules, and it is the reason the
    unexplained branch exists at all in its strongest form: a host stalled
    54.55% of the last minute whose worst workload reads 5.14% is not a
    mystery once something states that every workload WAS read and none of
    them accounts for it. Most of that stall is kernel work in no cgroup —
    an md resync, a scrub, writeback — which no row here will ever carry.
    """
    opinions: list[dict] = []
    explained = facts.get("StallExplainedBy") or {}
    unobservable = facts.get("StallAttributionUnobservable") or {}
    unexplained = facts.get("StallUnexplained") or {}
    for fact, resource in SLICE_STALL_RESOURCES:
        stall = facts.get(fact)
        if not isinstance(stall, (int, float)) or stall < SLICE_STALL_FLOOR:
            continue
        if explained.get(fact):
            continue
        if unobservable.get(fact):
            opinions.append(env.opinion(
                "slice-stall-unattributed", "info",
                f"Tasks in this slice were stalled on {resource} for {stall}%"
                " of the last minute, and whether a workload inside it"
                f" accounts for that could not be established:"
                f" {unobservable[fact]}"
                " Pressure that could not be read is not pressure that was"
                " absent, so this is a gap in the reading rather than a"
                " finding about the slice.",
                [fact, f"StallAttributionUnobservable.{fact}"],
                look=SLICE_STALL_LOOK[fact]))
        elif unexplained.get(fact):
            opinions.append(env.opinion(
                "slice-stall-unexplained",
                "warn" if stall >= SLICE_STALL_ATTENTION[fact] else "info",
                f"Tasks in this slice were stalled on {resource} for {stall}%"
                " of the last minute and no workload inside it accounts for"
                f" it: {unexplained[fact]} A member that was the cause would"
                " read at least as high, because a slice only counts the time"
                " in which every non-idle task under it was stalled — so this"
                " belongs to the slice as a whole, and no member row states"
                " it.",
                [fact, f"StallUnexplained.{fact}"],
                look=SLICE_STALL_LOOK[fact]))
        else:
            # No attribution facts at all: a consumer evaluating these rules
            # over facts this adapter did not build. The aggregate wording is
            # what can be said without the member readings, and it claims
            # nothing about them in either direction — silence here would
            # read as "a member explains it", which is exactly the inference
            # the branches above exist to stop being guessed.
            opinions.append(env.opinion(
                "slice-stall", "info",
                f"Tasks across this slice were collectively stalled on"
                f" {resource} for {stall}% of the last minute — an aggregate"
                " over every member workload; the member rows carry their own"
                " numbers, and the one actually stalling is where the number"
                " stays high.", [fact],
                look=SLICE_STALL_LOOK[fact]))
    return opinions
