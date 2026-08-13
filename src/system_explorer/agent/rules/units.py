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
    return opinions


def slice_unit_opinions(facts: dict) -> list[dict]:
    """The evaluator for .slice units — the cgroup tree's INTERIOR nodes.

    What a slice CONSUMES, and the attribution of a stall to the workload
    inside it responsible for it, moved to rules/resources.py with the
    measurement: an aggregate over a subtree is a statement about
    consumption, not about the slice's configuration, and it is judged on
    the row that carries the number.

    What stays is the slice's own state. A failed slice keeps its critical:
    that is the slice itself, not an aggregate over anything.
    """
    opinions: list[dict] = []
    if facts.get("ActiveState") == "failed":
        evidence = ["ActiveState", "SubState"] + (["Result"] if facts.get("Result") else [])
        opinions.append(env.opinion(
            "unit-health", "critical",
            f"Slice has failed ({facts.get('Result') or facts.get('SubState')}).",
            evidence))
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
