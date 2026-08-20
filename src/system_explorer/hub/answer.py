"""The first problem-domain object: *are all hosts up to date?*

DESIGN 25. A problem domain is not a page template — it is an object,
minted at the hub, with an id, facts, opinions and relations like
anything else, and the page is its projection. This is the founding
failure's own question: it answered *yes* while the only internet-facing
host in the estate sat five revisions behind, because every host the
registry knew about was up to date and the registry was the problem.

The derivation is §24's revision comparison: every host's deployment
revision, held against each other. It is a hub derivation for the reason
every hub derivation is one — no tier below can see a second host.

**Health, knowledge and currency are three axes, not two.** `verdict`
says what the evidence says about the system; `epistemic` says how much
of the question the evidence covered; `freshness` says whether it is
still being said. A host that told us and then went dark has covered its
share of the question — its reading stands — and what changed is that
nobody is confirming it any more. Folding that into `epistemic` would put
staleness into the coverage axis, which is the same merge the first two
axes exist to prevent, one axis over. Merging them corrupts both directions: an unknown
estate becomes warning-level unhealthy, and a real defect gets softened
because coverage was partial. So a dark host never moves the verdict — it
makes the answer narrower, and saying so on a different axis is what lets
a reader tell a broken estate from an unobserved one at a glance.

**The monotonicity rule is the acceptance test for all of this**:
removing evidence, or making a source dark, must never improve either the
verdict or the epistemic status. It reads as obvious and ordinary-looking
code violates it constantly — this module's first draft did, on
2026-08-20, and the fix is the distinction below.

**A universally quantified question cannot answer `healthy` over a subset,
and that is not the two axes being merged.** "Is this pool healthy" is a
claim about one object: a host nobody could reach does not make that pool
sicker, so its verdict must not move and only `epistemic` narrows. "Are
ALL hosts up to date" is a claim over the estate, and a conjunction with
an unknown conjunct is not true — so an unreachable host leaves the
proposition unestablished, which is a fact about the answer rather than
a health claim softened by ignorance. Both rules are the same rule seen
from two question shapes, and the difference is the quantifier.

Getting it wrong in this direction is the founding failure itself:
*yes, all hosts are up to date* was true of every host the registry knew
about, and the registry was the problem. So any host declared and
unaccounted for, and any discovered candidate nobody has classified,
stops this answer being `healthy` — while the sentence and `epistemic`
say exactly which it was.

**Do not copy this rule into a per-object answer.** It belongs to the
quantifier, not to the template.
"""

from __future__ import annotations

from typing import Any, Mapping

from .checkpoint import Estate, Reach
from .intent import Intent
from .rollup import EstateView

QUESTION_ID = "question:estate-current"
REVISION_FACT = "ConfigurationRevision"
COLLECTION = "generations"
RULE = "membership.revision-divergence@1"


def _booted_revision(row_facts: Mapping[str, Any]) -> str | None:
    if row_facts.get("Booted") in (True, "true", "yes"):
        revision = row_facts.get(REVISION_FACT)
        return revision if isinstance(revision, str) and revision else None
    return None


def estate_current(
    view: EstateView,
    estate: Estate,
    intent: Intent,
    window: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the answer from a promoted estate view.

    Only booted generations count: what a host HAS BEEN is a list, and the
    question is about what it is running now. A host whose generations
    collection carries no booted row contributes no revision and is
    counted as unanswered rather than as agreeing.
    """
    revisions: dict[str, str] = {}
    consulted: list[str] = []
    basis: list[dict[str, Any]] = [{
        "claim": f"the estate declares {len(intent.declared_hosts())} hosts",
        "kind": "declared",
        "origin": f"intent@r{intent.revision}",
        "value_as_read": list(intent.declared_hosts()),
        "ref": f"/hub/intent/r{intent.revision}#membership/hosts",
    }]

    for row in view.rows:
        for member in row.members:
            if member.collection != COLLECTION:
                continue
            source = f"{member.host}/nix"
            if source not in consulted:
                consulted.append(source)
            revision = _booted_revision(row.facts)
            if revision is None:
                continue
            revisions[member.host] = revision
            basis.append({
                "claim": f"{member.host}'s booted generation was built from "
                         f"configuration revision {revision}",
                "kind": "observed",
                "origin": f"{member.host}/nix/{COLLECTION}",
                "value_as_read": revision,
                # The hub quotes what the collator sent and names where it
                # read it; it does not re-derive a digest it never saw.
                "batch": row.id,
                "generation": _generation(estate, member.host),
                "evidence_digest": "sha256:0",
                "from": f"/generations/{member.object_id}/{REVISION_FACT}",
                "ref": f"/v1/nix/{COLLECTION}/{member.object_id}",
            })

    declined: list[dict[str, str]] = []
    dark: list[dict[str, str]] = []
    unswept: list[str] = []
    for host, reach in view.reach.items():
        if reach is Reach.UNSWEPT:
            unswept.append(host)
        elif reach is Reach.DARK:
            dark.append({"host": host, "since": "unknown"})
    # Why each host contributed no reading, host by host. A dark host is
    # NOT skipped here: it went away, and the reason it had nothing to say
    # while it was here is a different fact from its going away. Reporting
    # only the reasons that fit the reach vocabulary and staying silent
    # about the rest is this estate's most repeated defect, and it hid two
    # different silences behind one count on a real host on 2026-08-20.
    silent: dict[str, str] = {}
    for host in sorted(set(view.reach) - set(revisions) - set(unswept)):
        snapshot = estate.visible(host)
        if snapshot is None:
            silent[host] = "nothing promoted"
            continue
        state = snapshot.collections.get(COLLECTION)
        if state is None:
            declined.append({"host": host, "collection": f"nix/{COLLECTION}",
                             "reason": "unsupported"})
            silent[host] = "runs no NixOS generations"
        elif state.generation == 0:
            declined.append({"host": host, "collection": f"nix/{COLLECTION}",
                             "reason": state.stale_reason or "unavailable"})
            silent[host] = "has never read its generations"
        elif state.freshness != "current" and state.stale_reason:
            declined.append({"host": host, "collection": f"nix/{COLLECTION}",
                             "reason": state.stale_reason})
            silent[host] = f"generations are stale ({state.stale_reason})"
        else:
            # It read its generations and none of them is BOTH booted and
            # carrying a revision. Not a decline — the collector answered
            # — so it belongs in the sentence rather than in `declined`,
            # and it must not be silently folded into a count. Measured on
            # a real guest: the booted generation carried no revision while
            # a later, unbooted one did, and answering from that one would
            # be reporting a revision the host is not running.
            silent[host] = "its booted generation carries no revision"

    distinct = sorted(set(revisions.values()))
    answered = len(revisions)
    # A host that has no reading at all is what narrows the question. A
    # DARK host with a reading is a different case and belongs on a
    # different axis: it told us, and then stopped, so the question is
    # fully covered and the evidence is last-known rather than current.
    # Counting it as unanswered would put staleness into `epistemic`,
    # which is the same merge the verdict/epistemic split exists to
    # prevent, one axis over.
    unanswered = len(set(view.reach) - set(revisions))
    stale_contributors = sorted(
        host for host in revisions if view.reach.get(host) is Reach.DARK
    )

    # Everything the estate could not account for. It bears on the VERDICT
    # here, and would not on a per-object question — see the module note
    # on the quantifier.
    unaccounted = unanswered + len(view.coverage.unclassified)

    if answered == 0:
        verdict, epistemic = "degraded", "unknown"
        sentence = ("Nothing could answer: no host reported a booted "
                    "configuration revision.")
    elif len(distinct) == 1 and unaccounted == 0:
        verdict = "healthy"
        sentence = f"Every declared host is running {distinct[0]}."
    elif len(distinct) == 1:
        # True of everything that answered, and the question was not about
        # everything that answered. Saying "healthy" here is the founding
        # failure in one word.
        verdict = "degraded"
        sentence = (f"Every host that could answer is running {distinct[0]}, "
                    f"and the estate is not fully accounted for.")
    else:
        verdict = "degraded"
        listed = ", ".join(f"{h} {r}" for h, r in sorted(revisions.items()))
        sentence = (f"{len(distinct)} configuration revisions are running "
                    f"across {answered} hosts: {listed}.")

    if answered:
        epistemic = "complete" if unaccounted == 0 \
            and not view.coverage.sources_unreadable else "partial"
    if unanswered:
        named = "; ".join(f"{host} {why}" for host, why in sorted(silent.items()))
        for host in sorted(unswept):
            named = f"{host} has not reported since this hub started" + (
                f"; {named}" if named else "")
        sentence += (
            f" {unanswered} of {len(view.reach)} declared hosts could not answer"
            + (f" — {named}." if named else ".")
        )
    if stale_contributors:
        sentence += (
            f" {', '.join(stale_contributors)} last said so before going dark."
        )
    if view.coverage.unclassified:
        sentence += (
            f" {len(view.coverage.unclassified)} discovered "
            f"{'candidate is' if len(view.coverage.unclassified) == 1 else 'candidates are'} "
            "unclassified."
        )

    if answered and len(distinct) > 1:
        basis.append({
            "claim": "the estate is not running one configuration revision",
            "kind": "derived",
            "origin": "hub",
            "rule": RULE,
            "observability": "confirmed",
            "consumed": [b["ref"] for b in basis if b["kind"] == "observed"],
            **({"window": dict(window)} if window else {}),
        })

    reach: dict[str, Any] = {"consulted": consulted}
    if declined:
        reach["declined"] = declined
    if dark:
        reach["dark"] = dark
    if unswept:
        reach["unswept"] = sorted(unswept)
    reach["coverage"] = {
        "declared": list(view.coverage.declared),
        "discovered_not_declared": list(view.coverage.discovered_not_declared),
        "unclassified": list(view.coverage.unclassified),
        "sources_readable": list(view.coverage.sources_readable),
        "sources_unreadable": list(view.coverage.sources_unreadable),
    }

    return {
        "id": QUESTION_ID,
        "scope": "estate",
        "question": "are all hosts up to date?",
        "answer": sentence,
        "verdict": verdict,
        "epistemic": epistemic,
        # Its own axis, and the one a dark contributor moves. Health is
        # what the evidence says, epistemic is how much of the question it
        # covered, and freshness is whether it is still being said.
        "freshness": "stale" if stale_contributors else "current",
        "basis": basis,
        "reach": reach,
        "contributors": [f"nix/{COLLECTION}"],
    }


def _generation(estate: Estate, host: str) -> int:
    snapshot = estate.visible(host)
    if snapshot is None:
        return 0
    state = snapshot.collections.get(COLLECTION)
    return state.generation if state else 0
