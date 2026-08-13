"""Unit opinions: systemd unit health and restart churn.

One evaluator for both consumers: collect() derives each row's severity from
these opinions over the ListUnits summary facts, get_object() reports them
over the full property set. The acquisition-cost exception documented in the
package docstring lives here: NRestarts is a per-unit typed GetAll, not a
ListUnits column, and fetching it for every unit would turn one bus call
into hundreds — so restart-churn is presence-driven and fires on detail
facts only. A flapping-but-currently-active service therefore shows a warn
opinion when opened but an ok row; that is a stated cost decision, not
drifted thresholds.
"""

from __future__ import annotations

from .. import envelope as env

# Restarts since activation before a service counts as churning.
RESTART_CHURN_THRESHOLD = 3

# Per-unit stall shares, judged on the same 60-second window the host
# overview uses so the two agree about what "now" means.
#
# "full" is the share of time in which every NON-IDLE task was stalled, which
# is not the same as every task and must not be worded as if it were. A unit
# with ninety-nine sleeping tasks and one blocked on I/O is "full" for as long
# as that one is blocked, because nothing else wanted to run. The distinction
# is the whole difference between "this unit is making no progress" (true) and
# "everything in this unit is stuck" (usually false, and alarming).
#
# Deliberately warn, not critical — a stalled unit is a symptom whose cause is
# usually elsewhere (a saturated device, a degraded pool), and calling it
# critical would put the loudest level on the thing that is suffering rather
# than the thing that is wrong.
UNIT_IO_STALL_WARN = 20.0
UNIT_MEMORY_STALL_WARN = 10.0

# Below this share of the minute a slice states nothing at all. The gap
# between a slice and its members at that size is inside the slack the
# attribution already allows for two independently decaying averages, so a
# claim either way is a coin toss dressed as a finding — and the number stays
# on the row for anyone who wants it.
SLICE_STALL_FLOOR = 1.0

# Where to look when the slice cannot name the unit itself. Same collection,
# same fact: the member rows carry their own numbers, and the one actually
# stalling is where the number stays high. Keyed by the fact so the loop below
# picks the hint that matches the resource it is judging.
SLICE_STALL_LOOK = {
    "PsiIoFullAvg60": [{"subsystem": "units", "collection": "units",
                        "fact": "PsiIoFullAvg60",
                        "label": "which units are waiting on I/O"}],
    "PsiMemoryFullAvg60": [{"subsystem": "units", "collection": "units",
                            "fact": "PsiMemoryFullAvg60",
                            "label": "which units are waiting on memory "
                                     "reclaim"}],
}


def unit_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    if facts.get("ActiveState") == "failed":
        evidence = ["ActiveState", "SubState"] + (["Result"] if facts.get("Result") else [])
        opinions.append(env.opinion(
            "unit-health", "critical",
            f"Unit has failed ({facts.get('Result') or facts.get('SubState')}).",
            evidence))
    restarts = facts.get("NRestarts")
    if isinstance(restarts, int) and restarts >= RESTART_CHURN_THRESHOLD:
        opinions.append(env.opinion(
            "restart-churn", "warn",
            f"Service has restarted {restarts} times since activation.", ["NRestarts"]))
    # Absent on a kernel without CONFIG_PSI and on units with no cgroup, so
    # presence-driven: no fact, no opinion, never a zero standing in for a
    # measurement that was not taken.
    io_stall = facts.get("PsiIoFullAvg60")
    if isinstance(io_stall, (int, float)) and io_stall >= UNIT_IO_STALL_WARN:
        opinions.append(env.opinion(
            "unit-io-stall", "warn",
            f"This unit made no progress for {io_stall}% of the last minute: "
            "every task in it that had work to do was waiting on I/O. Tasks "
            "with nothing to do are not counted.", ["PsiIoFullAvg60"]))
    memory_stall = facts.get("PsiMemoryFullAvg60")
    if isinstance(memory_stall, (int, float)) and memory_stall >= UNIT_MEMORY_STALL_WARN:
        opinions.append(env.opinion(
            "unit-memory-stall", "warn",
            f"This unit made no progress for {memory_stall}% of the last "
            "minute: every task in it that had work to do was waiting on "
            "memory reclaim. Tasks with nothing to do are not counted.",
            ["PsiMemoryFullAvg60"]))
    return opinions


def slice_unit_opinions(facts: dict) -> list[dict]:
    """The evaluator for .slice units — the cgroup tree's INTERIOR nodes,
    where every number is an aggregate over the units nested under them.

    A slice's "full" share is the time in which every non-idle task under
    it was stalled, so a member making progress LOWERS it: the slice is
    both less specific than the member responsible and smaller than it
    (operator report, 2026-08-13 — a container scope at 65.27% listed
    directly beneath the slice containing it at 56.35%, one stall reported
    twice, the second time with the culprit's name removed). So a slice
    whose stall a member accounts for states nothing at all: the member's
    own row carries the condition, with the name on it.

    What survives is the case no member row can state — a slice stalling
    that nothing inside it accounts for — and, separately, the case where
    that could not be established because a member's pressure could not be
    read. The two are worded differently on purpose: an unread member is
    not a quiet one, and reporting it as "nothing explains this" would
    invent the interesting finding out of a gap in the reading.

    Each resource is judged on its own facts. A slice can be explained for
    I/O and unexplained for memory in the same minute, and one boolean
    across both would be false for one of them.

    A failed slice keeps its critical: that is the slice's own state, not
    an aggregate over anything."""
    opinions: list[dict] = []
    if facts.get("ActiveState") == "failed":
        evidence = ["ActiveState", "SubState"] + (["Result"] if facts.get("Result") else [])
        opinions.append(env.opinion(
            "unit-health", "critical",
            f"Slice has failed ({facts.get('Result') or facts.get('SubState')}).",
            evidence))
    explained = facts.get("StallExplainedBy") or {}
    unobservable = facts.get("StallAttributionUnobservable") or {}
    unexplained = facts.get("StallUnexplained") or {}
    for fact, resource in (("PsiIoFullAvg60", "I/O"),
                           ("PsiMemoryFullAvg60", "memory reclaim")):
        stall = facts.get(fact)
        if not isinstance(stall, (int, float)) or stall < SLICE_STALL_FLOOR:
            continue
        if explained.get(fact):
            continue
        if unobservable.get(fact):
            opinions.append(env.opinion(
                "slice-stall-unattributed", "info",
                f"Tasks in this slice were stalled on {resource} for {stall}%"
                " of the last minute, and whether a unit inside it accounts"
                f" for that could not be established: {unobservable[fact]}"
                " Pressure that could not be read is not pressure that was"
                " absent, so this is a gap in the reading rather than a"
                " finding about the slice.",
                [fact, f"StallAttributionUnobservable.{fact}"],
                look=SLICE_STALL_LOOK[fact]))
        elif unexplained.get(fact):
            opinions.append(env.opinion(
                "slice-stall-unexplained", "info",
                f"Tasks in this slice were stalled on {resource} for {stall}%"
                " of the last minute and no unit inside it accounts for it:"
                f" {unexplained[fact]} A member that was the cause would read"
                " at least as high, because a slice only counts the time in"
                " which every non-idle task under it was stalled — so this"
                " belongs to the slice as a whole, and no member row states"
                " it.",
                [fact, f"StallUnexplained.{fact}"],
                look=SLICE_STALL_LOOK[fact]))
        else:
            # No attribution facts at all: a consumer evaluating these rules
            # over facts the units adapter did not build. The aggregate
            # wording is what can be said without the member readings, and
            # it claims nothing about them in either direction — silence
            # here would read as "a member explains it", which is exactly
            # the inference the branches above exist to stop being guessed.
            opinions.append(env.opinion(
                "slice-stall", "info",
                f"Tasks across this slice were collectively stalled on"
                f" {resource} for {stall}% of the last minute — an"
                " aggregate over every member unit; the member rows carry"
                " their own numbers, and the one actually stalling is"
                " where the number stays high.", [fact],
                look=SLICE_STALL_LOOK[fact]))
    return opinions


def mount_unit_opinions(facts: dict) -> list[dict]:
    """Deliberately silent, and the fact it would have judged is worth keeping.

    RuntimeSynthesised is true of every mount systemd invented from the mount
    table, and on a container host that is overwhelmingly docker's own overlay
    and netns mounts: 50 of them on one host here, none of them anything an
    operator wants an opinion about. An info that fires on fifty uninteresting
    objects devalues the level for the ones that matter — the same audit that
    demoted journal priority 3 (see rules/logs.py).

    The interesting case is narrower than "has no fragment": it is a mount that
    something DECLARES a dependency on and therefore silently does not get,
    which needs the reverse dependency and so an acquisition this does not yet
    make. Until then the fact is on the row to be filtered and read, and no
    opinion is drawn from it. Reporting the fact is the honest half; judging it
    on this evidence would not be.
    """
    return []
