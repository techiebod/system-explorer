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


def mount_unit_opinions(facts: dict) -> list[dict]:
    """A .mount unit systemd invented, which nothing can depend on.

    systemd synthesises a mount unit from /proc/self/mountinfo for anything
    mounted outside its control — a native ZFS mountpoint, most often. The unit
    reads `active` and looks identical to one that performed the mount, but it
    has no fragment, and systemd only promotes RequiresMountsFor= into a real
    Requires= when the target has one. So a service that names the path gets an
    ordering hint at best, and nothing at all if the mount is not present when
    the service loads.

    silo carried exactly this for two days: fs-media.mount had never executed a
    mount in its life — zfs-mount.service won every boot and systemd merely
    observed the result — while five compose stacks named /fs/media in
    requiresMountsFor and believed they depended on it. Nothing was failed and
    nothing could have shown it, because the row said active and carried no fact
    that distinguished the two cases.

    info rather than warn: on a host that never wanted the dependency this is
    simply how a mount looks, and saying so on every tmpfs would be the
    cry-wolf the level exists to avoid. It is a statement about what can be
    depended on, for the reader who is about to depend on it.
    """
    if not facts.get("RuntimeSynthesised"):
        return []
    return [env.opinion(
        "mount-unit-synthesised", "info",
        "systemd made this unit up from the mount table rather than reading a "
        "file for it, so it has no fragment. It reports the mount but nothing "
        "can be ordered against it: RequiresMountsFor= on this path becomes a "
        "real dependency only when the mount unit has a fragment. Declare the "
        "filesystem if anything needs to wait for it.",
        ["RuntimeSynthesised", "ActiveState"])]
