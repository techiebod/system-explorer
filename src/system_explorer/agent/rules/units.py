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

# The share at which a slice's own UNEXPLAINED stall claims attention, per
# resource: the same bar a single unit must clear. Nothing else in the product
# states this condition — every member was read and none accounts for it — so
# at info it is stripped by envelope.attention(), absent from /v1/findings and
# the estate roll-up, and visible only where it wins one of five
# magnitude-ranked overview slots against members whose own rows already warn.
# Between the floor and this bar it stays info, so the floor's reasoning is
# untouched and no new noise is manufactured.
SLICE_STALL_ATTENTION = {"PsiIoFullAvg60": UNIT_IO_STALL_WARN,
                         "PsiMemoryFullAvg60": UNIT_MEMORY_STALL_WARN}

# The readings a slice is judged on, with the wording each takes. One list, so
# the three tables keyed by these facts cannot come to disagree about which
# readings a slice states anything about.
SLICE_STALL_RESOURCES = (("PsiIoFullAvg60", "I/O"),
                         ("PsiMemoryFullAvg60", "memory reclaim"))

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


def slice_stall_deferred(facts: dict) -> bool:
    """True where this evaluator declined to judge a stall the row CARRIES,
    because a member accounts for it.

    The finding belongs to the member's row and is not restated here (see
    slice_unit_opinions). But silence reaches the row as the no-opinion
    severity, and that value is a positive vouch — so the caller deriving a
    row's severity has to know the difference between "nothing to say" and
    "somebody else says it", or a slice stalled 56.35% of the last minute
    paints the same green dot as an idle one.
    """
    explained = facts.get("StallExplainedBy") or {}
    return any(isinstance(facts.get(fact), (int, float))
               and facts[fact] >= SLICE_STALL_FLOOR and explained.get(fact)
               for fact, _resource in SLICE_STALL_RESOURCES)


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

    Of the three the unexplained case is the only one that claims attention
    (SLICE_STALL_ATTENTION), because it is the only one no other row can
    state: a gap in the reading is not a finding, and a bare aggregate may
    still turn out to be explained.

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
                " of the last minute, and whether a unit inside it accounts"
                f" for that could not be established: {unobservable[fact]}"
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


def absent_dependency_opinions(facts: dict) -> list[dict]:
    """A unit that names another unit which is not present on this host.

    The shape is one defect and three severities, and the split is the whole
    of the reasoning. systemd's own documentation draws the line: a
    dependency it cannot resolve is FATAL to the start job under Requires=,
    Requisite= and BindsTo=, and explicitly IGNORED under Wants= and
    Upholds=. Those are not degrees of one condition — one stops a unit
    starting, the other means a unit file has been asking for something for
    years while everything worked. Collapsing them into a single level would
    be exactly the averaging this product refuses, in either direction:
    warning about the soft case buries the hard one, and stating the hard
    case softly hides a unit that cannot start.

    So:

      warn, not critical, for the hard directives. It is a genuine defect
        with an owner and a fix, and it is not hypothetical — the start job
        fails. But critical here is reserved for what has actually happened:
        if the unit was asked to start and could not, ActiveState is failed
        and unit-health above already says so at critical, on this same row.
        A second critical for the reason behind the first would double-count
        the loudest level the board has, and on a unit nothing ever starts
        the prediction has cost nobody anything yet.

      info for the soft directives. The unit runs; what its file asks to be
        pulled in with it never is. That is real configuration debt, worth
        recording and worth a name — and at info it is stripped by
        envelope.attention(), absent from /v1/findings and the estate
        roll-up, and read only by somebody who opened the unit. Which is the
        correct weight for something that has been true and harmless since
        the file was written.

      nothing at all for ordering. After= against a unit that is not there
        orders nothing, and the population is dominated by barriers systemd
        adds implicitly to units that have no fragment to fix (the counts are
        in adapters/units.py). The fact is carried so it can be filtered and
        read; an opinion on it would be dozens of permanently red rows per
        host, which is how an operator learns to ignore red — the same
        judgement mount_unit_opinions makes below, and the journal-priority
        audit in rules/logs.py before it.

    Presence-driven throughout, so a consumer evaluating these rules over
    facts the units adapter did not build says nothing rather than guessing,
    and the unobservable arm stands in place of the others rather than
    beside them: a reference that could not be read is not a reference that
    is not there.
    """
    unreadable = facts.get("MissingReferenceUnobservable")
    if isinstance(unreadable, str) and unreadable:
        return [env.opinion(
            "unit-absent-references-unobservable", "info",
            "What this row can say about references between it and units "
            f"that are not present on this host is incomplete: {unreadable}. "
            "An unread reference is not an absent one, so this stands in "
            "place of a finding rather than beside one.",
            ["MissingReferenceUnobservable"])]
    opinions: list[dict] = []
    required = facts.get("MissingRequirements")
    if isinstance(required, list) and required:
        opinions.append(env.opinion(
            "unit-requires-absent-unit", "warn",
            "This unit hard-depends on a unit that is not present on this "
            f"host: {', '.join(required)}. systemd can load nothing of that "
            "name, and a dependency it cannot resolve is not skipped the way "
            "a soft one is — the start job for THIS unit fails before the "
            "unit runs. The fix is in this unit's file, which somebody owns; "
            "the name it asks for has no file, no owner and nothing to "
            "change.",
            ["MissingRequirements"]))
    wanted = facts.get("MissingWants")
    if isinstance(wanted, list) and wanted:
        opinions.append(env.opinion(
            "unit-wants-absent-unit", "info",
            "This unit asks for a unit that is not present on this host: "
            f"{', '.join(wanted)}. systemd documents Wants= as soft and "
            "ignores one it cannot resolve, so nothing is failing and nothing "
            "will: the unit starts, and what its file asks to be pulled in "
            "alongside it simply never is. Recorded rather than raised "
            "because it has been true for as long as the file has said so — "
            "but it is a real gap between what that file describes and what "
            "this host does, and no other row can state it.",
            ["MissingWants"]))
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
    something DECLARES a dependency on and therefore silently does not get.
    That is NOT the case absent_dependency_opinions above now covers — a
    synthesised mount unit is loaded and present, so nothing about it is
    not-found, and the reverse probe that finds references to absent NAMES
    cannot see it. What it needs is RequiresMountsFor= resolved to unit names,
    an acquisition this adapter still does not make. Until then the fact is on
    the row to be filtered and read, and no opinion is drawn from it. Reporting
    the fact is the honest half; judging it on this evidence would not be.
    """
    return []
