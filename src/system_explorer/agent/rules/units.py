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
# overview uses so the two agree about what "now" means. "full" is the
# unambiguous one: EVERY task in this cgroup was stalled, so the unit made
# no progress at all for that share of the minute. Deliberately warn, not
# critical — a stalled unit is a symptom whose cause is usually elsewhere
# (a saturated device, a degraded pool), and calling it critical would put
# the loudest level on the thing that is suffering rather than the thing
# that is wrong.
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
            f"Every task in this unit was stalled waiting for I/O {io_stall}% "
            "of the last minute.", ["PsiIoFullAvg60"]))
    memory_stall = facts.get("PsiMemoryFullAvg60")
    if isinstance(memory_stall, (int, float)) and memory_stall >= UNIT_MEMORY_STALL_WARN:
        opinions.append(env.opinion(
            "unit-memory-stall", "warn",
            f"Every task in this unit was stalled reclaiming memory "
            f"{memory_stall}% of the last minute.", ["PsiMemoryFullAvg60"]))
    return opinions
