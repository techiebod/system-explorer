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
    where every number is an aggregate over member units. A slice's PSI
    stall is real and worth carrying, but it is the SUM of its children's
    stalls: system.slice going loud repeats whichever member is actually
    stuck, with wording that read as if every service in it was stalled
    (operator report, 2026-08-13 — one loaded service, a slice-wide
    claim, and the same condition alerting twice down the hierarchy). So
    slices mirror their stalls as info with aggregate-honest wording —
    visible on the slice's object, absent from the attention surface,
    where the MEMBER unit's own warn names the actual culprit — and a
    failed slice keeps its critical, because that is the slice's own
    state, not an aggregate."""
    opinions: list[dict] = []
    if facts.get("ActiveState") == "failed":
        evidence = ["ActiveState", "SubState"] + (["Result"] if facts.get("Result") else [])
        opinions.append(env.opinion(
            "unit-health", "critical",
            f"Slice has failed ({facts.get('Result') or facts.get('SubState')}).",
            evidence))
    for fact, resource in (("PsiIoFullAvg60", "I/O"),
                           ("PsiMemoryFullAvg60", "memory reclaim")):
        stall = facts.get(fact)
        if isinstance(stall, (int, float)) and stall > 0:
            opinions.append(env.opinion(
                "slice-stall", "info",
                f"Tasks across this slice were collectively stalled on"
                f" {resource} for {stall}% of the last minute — an"
                " aggregate over every member unit; the member rows carry"
                " their own numbers, and the one actually stalling is"
                " where the number stays high.", [fact]))
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
