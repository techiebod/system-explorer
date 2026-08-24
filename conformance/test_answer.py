"""The first problem-domain object, end to end and schema-judged.

*Are all hosts up to date* is the founding failure's own question: it
answered yes while the only internet-facing host sat five revisions
behind, because every host the registry knew about WAS up to date. These
tests assemble it from a promoted estate and hold it against
contract/se.answer.1.json, then against the monotonicity rule DESIGN 25
calls the acceptance test for all of it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from system_explorer.hub.answer import estate_current
from system_explorer.hub.checkpoint import CollectionSnapshot, Estate, HostSnapshot
from system_explorer.hub.intent import Intent
from system_explorer.hub.rollup import assemble
from system_explorer.hub.session import Declarations

CONTRACT = Path(__file__).resolve().parent.parent / "contract"
BOOT = "5e000000-0000-4000-8000-000000000001"
VERDICT_RANK = {"healthy": 0, "degraded": 1, "critical": 2}
EPISTEMIC_RANK = {"complete": 0, "partial": 1, "conflicted": 2, "unknown": 3}


def validator() -> Draft202012Validator:
    registry = Registry()
    for path in sorted(CONTRACT.glob("*.json")):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return Draft202012Validator(
        json.loads((CONTRACT / "se.answer.1.json").read_text()), registry=registry
    )


NIX_DECLARATION = {
    "schema": "se.declaration/1", "collector": "nix", "version": "0.7.0",
    "collections": [{
        "name": "generations", "question": "?", "prefix": "generation",
        "freshness": "300s", "perishability": "reconstructible",
        "answer": ["ConfigurationRevision"],
        "facts": {name: {"type": "string", "temperament": "configuration",
                         "kind": "observed", "discloses": "nothing", "sentence": "."}
                  for name in ("ConfigurationRevision", "Booted", "Current")},
    }],
}


def host(name: str, revision: str | None, generation: int = 7,
         freshness: str = "current", reason: str | None = None) -> HostSnapshot:
    objects = ()
    if revision is not None:
        objects = ({"id": f"generation:{generation}", "name": str(generation),
                    "instance": None,
                    "facts": {"Booted": True, "ConfigurationRevision": revision}},)
    return HostSnapshot(
        host=name, checkpoint="cp", boot_id=BOOT,
        collections={"generations": CollectionSnapshot(
            name="generations", generation=generation, freshness=freshness,
            stale_reason=reason, objects=objects)},
        declarations=("sha256:nix",), history_gap=None,
    )


def build(*snapshots, declared=("storage-1", "edge-1"), **coverage):
    estate = Estate(declared=declared)
    declarations = Declarations()
    for snapshot in snapshots:
        declarations.add(snapshot.host, NIX_DECLARATION, "sha256:nix")
        estate.promote(snapshot)
    intent = Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": 41,
        "reviewed": "2026-08-20",
        "membership": {"hosts": {h: {} for h in declared}},
    })
    view = assemble(estate, intent, declarations, **coverage)
    return estate_current(view, estate, intent), estate, intent, view


def test_the_answer_validates_against_its_schema() -> None:
    answer, *_ = build(host("storage-1", "4f9c2e1"), host("edge-1", "9ab31d0"))
    errors = sorted(validator().iter_errors(answer), key=str)
    assert not errors, "\n".join(f"- {e.json_path}: {e.message}" for e in errors)


def test_divergence_is_degraded_and_says_which_hosts() -> None:
    answer, *_ = build(host("storage-1", "4f9c2e1"), host("edge-1", "9ab31d0"))
    assert answer["verdict"] == "degraded"
    assert "storage-1 4f9c2e1" in answer["answer"] and "edge-1 9ab31d0" in answer["answer"]
    derived = [b for b in answer["basis"] if b["kind"] == "derived"]
    assert len(derived) == 1 and derived[0]["origin"] == "hub", (
        "law 4: a derived claim names the tier that computed it, and no "
        "tier below the hub can see a second host"
    )
    assert derived[0]["consumed"], "a derived claim cites what it consumed"


def test_agreement_is_healthy() -> None:
    answer, *_ = build(host("storage-1", "4f9c2e1"), host("edge-1", "4f9c2e1"))
    assert answer["verdict"] == "healthy"
    assert answer["epistemic"] == "complete"
    assert not [b for b in answer["basis"] if b["kind"] == "derived"]


def test_the_founding_failure_cannot_recur() -> None:
    """Every host the registry knew about was up to date, and the registry
    was the problem. The verdict stays what the evidence says; the fact
    that a host never answered lands on epistemic."""
    answer, *_ = build(host("storage-1", "4f9c2e1"))  # edge-1 never dialled in
    assert answer["verdict"] != "healthy", (
        "the question is universally quantified over the estate, so a "
        "conjunct nobody could read leaves it unestablished — answering "
        "healthy over the hosts that replied IS the founding failure"
    )
    assert answer["epistemic"] == "partial"
    assert "not fully accounted for" in answer["answer"]
    assert answer["reach"]["unswept"] == ["edge-1"]
    assert "could not answer" in answer["answer"]


def test_an_unclassified_candidate_narrows_the_answer() -> None:
    answer, *_ = build(
        host("storage-1", "4f9c2e1"), host("edge-1", "4f9c2e1"),
        discovered=("storage-1", "edge-1", "gw-2"),
        sources_readable=("tailnet-control-plane",),
    )
    assert answer["verdict"] != "healthy", (
        "a registry cannot detect that it is incomplete, so a candidate "
        "nobody has ruled on is exactly the gap this question missed"
    )
    assert answer["epistemic"] == "partial"
    assert answer["reach"]["coverage"]["unclassified"] == ["gw-2"]


def test_a_stale_collection_declines_rather_than_agreeing() -> None:
    answer, *_ = build(
        host("storage-1", "4f9c2e1"),
        host("edge-1", None, freshness="stale", reason="unavailable"),
    )
    assert {d["reason"] for d in answer["reach"]["declined"]} == {"unavailable"}
    assert answer["epistemic"] == "partial"


def test_nothing_answering_is_unknown_not_healthy() -> None:
    answer, *_ = build(declared=("storage-1",))
    assert answer["epistemic"] == "unknown"
    assert answer["verdict"] != "healthy", (
        "an estate nobody could look at must not read as a well one"
    )


@pytest.mark.parametrize("removed", ["edge-1", "storage-1"])
def test_monotonicity_removing_evidence_never_improves_the_answer(removed) -> None:
    """DESIGN 25's acceptance test for all of this. It reads as obvious and
    ordinary-looking code violates it constantly: a host goes dark, its
    findings stop arriving, and the estate reads better than it did."""
    hosts = {"storage-1": host("storage-1", "4f9c2e1"),
             "edge-1": host("edge-1", "9ab31d0")}
    full, *_ = build(*hosts.values())
    fewer, *_ = build(*[s for name, s in hosts.items() if name != removed])
    assert VERDICT_RANK[fewer["verdict"]] >= VERDICT_RANK[full["verdict"]], (
        f"removing {removed} improved the verdict"
    )
    assert EPISTEMIC_RANK[fewer["epistemic"]] >= EPISTEMIC_RANK[full["epistemic"]], (
        f"removing {removed} improved the epistemic status"
    )


def test_going_dark_never_improves_the_answer() -> None:
    answer_before, estate, intent, view = build(
        host("storage-1", "4f9c2e1"), host("edge-1", "9ab31d0"))
    estate.disconnected("edge-1")
    declarations = Declarations()
    for name in ("storage-1", "edge-1"):
        declarations.add(name, NIX_DECLARATION, "sha256:nix")
    after = estate_current(assemble(estate, intent, declarations), estate, intent)
    assert VERDICT_RANK[after["verdict"]] >= VERDICT_RANK[answer_before["verdict"]]
    assert EPISTEMIC_RANK[after["epistemic"]] >= EPISTEMIC_RANK[answer_before["epistemic"]]


def test_an_undeclared_revision_reaches_no_answer() -> None:
    """Item 7 all the way through: a fact with no declared axis never
    becomes a claim in a basis."""
    snapshot = host("storage-1", "4f9c2e1")
    estate = Estate(declared=("storage-1",))
    estate.promote(snapshot)
    intent = Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": 41,
        "reviewed": "2026-08-20", "membership": {"hosts": {"storage-1": {}}},
    })
    view = assemble(estate, intent, Declarations())  # nothing declared at all
    answer = estate_current(view, estate, intent)
    assert not [b for b in answer["basis"] if b["kind"] == "observed"]
    assert answer["epistemic"] == "unknown"


def test_a_dark_contributor_moves_freshness_and_not_coverage() -> None:
    """PROVISIONAL, not a design ruling (register row 48): §25 does not
    say where darkness lands. This pins the current choice so it cannot
    drift silently — it does not settle it. A host that told us and then went dark has
    covered its share of the question — its reading stands — and what
    changed is that nobody is confirming it any more."""
    answer_live, estate, intent, _ = build(
        host("storage-1", "4f9c2e1"), host("edge-1", "4f9c2e1"))
    assert answer_live["freshness"] == "current"
    assert answer_live["epistemic"] == "complete"

    estate.disconnected("edge-1")
    declarations = Declarations()
    for name in ("storage-1", "edge-1"):
        declarations.add(name, NIX_DECLARATION, "sha256:nix")
    dark = estate_current(assemble(estate, intent, declarations), estate, intent)
    assert dark["freshness"] == "stale"
    assert dark["epistemic"] == "complete", (
        "folding staleness into coverage is the same merge the verdict and "
        "epistemic split exists to prevent, one axis over"
    )
    assert "before going dark" in dark["answer"]
    # And monotonicity still holds across the change.
    assert VERDICT_RANK[dark["verdict"]] >= VERDICT_RANK[answer_live["verdict"]]
    assert EPISTEMIC_RANK[dark["epistemic"]] >= EPISTEMIC_RANK[answer_live["epistemic"]]


def test_a_host_with_no_reading_at_all_still_narrows_coverage() -> None:
    answer, *_ = build(host("storage-1", "4f9c2e1"), host("edge-1", None))
    assert answer["epistemic"] == "partial"
    assert answer["verdict"] != "healthy"


def test_every_silent_host_says_why_it_was_silent() -> None:
    """Measured on a real lab guest, 2026-08-20: two hosts contributed no
    revision for two different reasons and the answer reported one count.
    Reporting the reasons that fit the reach vocabulary and staying silent
    about the rest is the estate's most repeated defect."""
    estate = Estate(declared=("storage-1", "edge-1", "nas-1"))
    declarations = Declarations()
    # storage-1 read its generations; none is booted-with-a-revision.
    unrevised = HostSnapshot(
        host="storage-1", checkpoint="cp", boot_id=BOOT,
        collections={"generations": CollectionSnapshot(
            name="generations", generation=7, freshness="current", stale_reason=None,
            objects=({"id": "generation:1", "name": "1", "instance": None,
                      "facts": {"Booted": True}},))},
        declarations=("sha256:nix",), history_gap=None)
    # edge-1 is not a NixOS host at all.
    no_nix = HostSnapshot(
        host="edge-1", checkpoint="cp", boot_id=BOOT, collections={},
        declarations=("sha256:x",), history_gap=None)
    for snapshot in (unrevised, no_nix):
        declarations.add(snapshot.host, NIX_DECLARATION, "sha256:nix")
        estate.promote(snapshot)
    estate.disconnected("storage-1")  # dark, and still owed an explanation

    intent = Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": 41,
        "reviewed": "2026-08-20",
        "membership": {"hosts": {h: {} for h in ("storage-1", "edge-1", "nas-1")}}})
    answer = estate_current(assemble(estate, intent, declarations), estate, intent)

    assert "booted generation carries no revision" in answer["answer"]
    assert "runs no NixOS generations" in answer["answer"]
    assert "has not reported since this hub started" in answer["answer"]
    # A dark host is still owed its reason: going away and having had
    # nothing to say are different facts.
    assert "storage-1" in answer["answer"] and "edge-1" in answer["answer"]
    assert {d["reason"] for d in answer["reach"]["declined"]} == {"unsupported"}
