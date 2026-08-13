"""protection rules: the states, graded.

Declared, implemented, running-green, proven-by-restore and
tried-and-failed are different things, and the estate's own invariants
say so. The grading follows from which of them is broken rather than
from how alarming a word sounds:

- A hop that was never BUILT is admitted debt. It gets attention, not
  alarm, and deliberately not critical — the estate's own staleness
  checker keeps unbuilt work out of its exit code because a permanently
  red board trains an operator to ignore red, which costs more than the
  gap does. The exception that earns warn is the one that decides
  whether the data survives the site: an irreplaceable target whose
  independent destination is unbuilt has no durable copy at all, and
  nine of those hid behind green replication until the estate started
  asking per hop instead of per target.
- A job that was built and has NEVER succeeded is not debt, it is a
  broken promise: for irreplaceable data there is no copy, which is the
  one condition here that is critical. Where the declaration does not
  say what the job protects, the softer grade is stated as a softer
  grade rather than taken silently — an unjoined class is unknown, not
  known to be small.
- Running green while nothing has ever been restored is invariant 5's
  subject. It is stated as info on every irreplaceable target, because
  it is true of most of them and a tick would be this product's own
  absence-as-health failure wearing a backup's clothes. Per RUNG: a
  proof at one rung is a proof about one copy, and the rung reached for
  first shares the failure domain the destinations exist to survive.
- A restore somebody performed and could NOT read back is the state
  none of the above covers, and it is worse than never having tried.
  Folding it into the never-tried case renders the alarming reading as
  the ordinary one.
- And every verdict above is the checker's, computed at a moment that
  has passed. A verdict nobody has recomputed is stated as old rather
  than repeated as current, because the file keeps its last answer when
  the checker stops.
"""

from __future__ import annotations

from .. import envelope as env

# The checker's timer is hourly with a five-minute randomised delay, so
# three windows plus that delay is two missed runs — a checker that
# stopped, not one that is merely late.
VERDICT_STALE_SECONDS = 3 * 3600 + 300

# A target's verdicts are about promises; the jobs are what would keep
# them, and the target row names them in HopImplementedBy. Ordered by
# State, whose vocabulary sorts the unkept ones first (stale > ok).
LOOK_JOBS = [{"subsystem": "protection", "collection": "jobs",
              "fact": "State",
              "label": "the jobs that build this target's hops"}]

# No ordering fact: the claim is that ONE unit stopped writing, which is
# a filter, and look refuses filters. Ranking units by ActiveState would
# sort the estate's dead oneshots above the culprit (see rules/system.py).
LOOK_CHECKER_UNIT = [{"subsystem": "units", "collection": "units",
                      "label": "the staleness checker's own unit"}]


def _cited(facts: dict, *names: str) -> list[str]:
    """The named facts this row actually carries. An opinion may only
    cite what the reader can go and look at, and several of these facts
    are legitimately absent — an unreadable receipt leaves no
    LastSuccessAt, and a target with no declared rungs leaves no
    UnprovenRungs."""
    return [name for name in names if name in facts]


def target_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    missing = facts.get("UnimplementedHops") or []
    if missing:
        independent = set(facts.get("IndependentDestinations") or [])
        durable_gap = bool(independent) and independent.issubset(set(missing))
        irreplaceable = facts.get("Class") == "backup"
        listed = ", ".join(str(hop) for hop in missing)
        if irreplaceable and durable_gap:
            opinions.append(env.opinion(
                "protection-no-durable-copy", "warn",
                f"Irreplaceable, and every independent destination it"
                f" declares is unbuilt ({listed}) — whatever else is green,"
                f" nothing here survives losing the site.",
                ["Class", "UnimplementedHops", "IndependentDestinations"],
                look=LOOK_JOBS))
        else:
            opinions.append(env.opinion(
                "protection-hop-unimplemented", "info",
                f"Declared but unbuilt: {listed}. The target's other hops"
                f" can read green while this one has no job behind it.",
                ["UnimplementedHops"]))
    failed = facts.get("FailedProofRungs") or []
    if failed:
        # Tried and failed is not the never-tried case, and warn rather
        # than critical because a copy may still exist: this is evidence
        # about reading the artifact back, recorded by an operator, so it
        # sits beside protection-no-durable-copy rather than above it.
        listed = ", ".join(str(rung) for rung in failed)
        opinions.append(env.opinion(
            "protection-proof-failed",
            "warn" if facts.get("Class") == "backup" else "info",
            f"A restore was performed from {listed} and did not come back"
            f" intact, and no later proof has answered it — this target has"
            f" evidence its artifact could not be read back, which is not the"
            f" same as, and is worse than, never having tried.",
            _cited(facts, "Class", "FailedProofRungs", "LastFailedProofAt",
                   "ProofRecord"), look=LOOK_JOBS))
    # Per RUNG, never collapsed. The date a target was last proven is a
    # date about ONE rung: gating on a cross-rung maximum would let a
    # restore from the source's own snapshot history — which is not a
    # destination, and survives neither the disk nor the site — vouch for
    # the hops nothing has ever been read back from. That is the per-target
    # answer the declaration replaced with a per-rung one, inverted.
    unproven = facts.get("UnprovenRungs") or []
    proven = facts.get("ProvenRungs") or []
    if facts.get("Class") == "backup" and (unproven or not proven):
        listed = ", ".join(str(rung) for rung in unproven)
        named = ", ".join(str(rung) for rung in proven)
        if unproven and proven:
            message = (f"No restore has ever come back from {listed}: running"
                       f" green proves a job ran, never that its artifact can"
                       f" be read back, and the passing proof at {named}"
                       f" certifies that rung and no other.")
        elif unproven:
            message = (f"No restore has ever come back from {listed}: running"
                       f" green proves a job ran, never that its artifact can"
                       f" be read back.")
        else:
            message = ("Nothing has ever been restored from this target:"
                       " running green proves a job ran, never that its"
                       " artifact can be read back.")
        opinions.append(env.opinion(
            "protection-unproven", "info", message,
            _cited(facts, "Class", "ProvenRungs", "UnprovenRungs",
                   "Destinations"), look=LOOK_JOBS))
    return opinions


def job_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    # Outside the state ladder, and first: State is the reading this one
    # invalidates, so the green a frozen verdict produces must not shadow
    # it. warn rather than info deliberately — rows carry only the
    # warn/critical subset (rule 14), and a silent row is the defect.
    age = facts.get("CheckedAgeSeconds")
    if isinstance(age, (int, float)) and not isinstance(age, bool) \
            and age > VERDICT_STALE_SECONDS:
        opinions.append(env.opinion(
            "protection-verdict-stale", "warn",
            f"This row's verdict is {int(age) // 3600}h old: its state, basis"
            f" and age are what the checker saw when it last completed, not"
            f" what is true now. A checker that stops writing leaves its last"
            f" verdict in place, so green here says nothing until it runs"
            f" again.",
            _cited(facts, "CheckedAt", "CheckedAgeSeconds", "State",
                   "AgeSeconds", "LastSuccessAt"), look=LOOK_CHECKER_UNIT))
    stale = facts.get("State") == "stale"
    never = facts.get("Basis") == "registered-never-succeeded"
    if stale and never:
        known = facts.get("TargetClass")
        irreplaceable = known == "backup"
        if irreplaceable:
            message = ("This job has never succeeded since it was registered,"
                       " and its window has passed — for this target there is"
                       " no copy, only a unit that was supposed to make one.")
        elif known:
            message = ("This job has never succeeded since it was registered,"
                       " and its window has passed.")
        else:
            # The gentler grade is a consequence of a join that did not
            # happen, so the row says so: unknown is not "replaceable".
            message = ("This job has never succeeded since it was registered,"
                       " and its window has passed. No declared target names"
                       " this job, so the class of what it protects could not"
                       " be joined — this is graded as if it were replaceable"
                       " and may not be.")
        opinions.append(env.opinion(
            "protection-never-succeeded",
            "critical" if irreplaceable else "warn", message,
            _cited(facts, "State", "Basis", "AgeSeconds", "MaxAgeSeconds",
                   "TargetClass", "TargetClassUnjoined")))
    elif stale:
        opinions.append(env.opinion(
            "protection-stale", "warn",
            "No success inside this job's declared window — an older copy"
            " exists, and nothing has replaced it since. The staleness unit"
            " fails for the same reason; this row names which job.",
            _cited(facts, "State", "AgeSeconds", "MaxAgeSeconds",
                   "LastSuccessAt")))
    elif facts.get("LastResult") not in (None, "success"):
        # The two-receipt design exists for exactly this pair of rows, and
        # they are NOT one row: a failed run over a standing success still
        # leaves a copy, while a failed run over no success at all leaves
        # none — it is unstale only because its first window has not
        # passed yet. Asserting "an earlier success stands" for the second
        # is this product's own absence-as-health failure.
        if never:
            opinions.append(env.opinion(
                "protection-first-run-failed", "warn",
                f"The most recent run ended {facts['LastResult']}, and this"
                f" job has never succeeded since it was registered — it is"
                f" unstale only because its first window has not passed yet,"
                f" and there is no copy behind it.",
                _cited(facts, "Basis", "LastResult", "LastFinishedAt",
                       "AgeSeconds", "MaxAgeSeconds")))
        else:
            opinions.append(env.opinion(
                "protection-last-run-failed", "warn",
                f"The most recent run ended {facts['LastResult']}, though an"
                f" earlier success is still inside the window — the next"
                f" window is the one that goes stale.",
                _cited(facts, "LastResult", "LastFinishedAt",
                       "LastSuccessAt")))
    if facts.get("ReceiptsUnobservable"):
        # Its own `if`, not part of the ladder: the checker's verdict
        # still stands and keeps its own opinion. A job can be stale AND
        # have a receipt nobody can open.
        opinions.append(env.opinion(
            "protection-receipt-unreadable", "warn",
            f"A receipt this job has already written cannot be read"
            f" ({facts['ReceiptsUnobservable']}), so this row cannot say when"
            f" it last ran or last succeeded from its own evidence — an"
            f" unreadable receipt is a fault in the evidence, never evidence"
            f" that no run happened.",
            _cited(facts, "ReceiptsUnobservable", "State", "Basis")))
    return opinions
