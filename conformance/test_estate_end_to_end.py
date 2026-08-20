"""Two collators, one hub, one coherent view — gate 4's last clause.

Both sessions are written by the real Go collator and read by the real
Python hub: declarations, checkpoint, promotion, roll-up, and the estate's
founding question answered over the result. Nothing here is hand-built,
so a divergence between the two halves fails here rather than in an
estate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from system_explorer.hub.answer import estate_current
from system_explorer.hub.checkpoint import Estate, Reach
from system_explorer.hub.intent import Intent
from system_explorer.hub.rollup import assemble
from system_explorer.hub.session import Declarations, Session

from test_checkpoint_contract import emit_samples

CONTRACT = Path(__file__).resolve().parent.parent / "contract"
HOSTS = ("storage-1", "edge-1")


@pytest.fixture(scope="module")
def samples() -> dict[str, list[dict]]:
    return emit_samples()


def intent_for(hosts=HOSTS) -> Intent:
    return Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": 41,
        "reviewed": "2026-08-20",
        "membership": {"hosts": {h: {"roles": ["host"]} for h in hosts}},
    })


def run_estate(samples, hosts=HOSTS, declared=HOSTS):
    estate = Estate(declared=declared)
    declarations = Declarations()
    promoted = {}
    for host in hosts:
        records = samples[f"session:{host}"]
        session = Session(estate=estate, declarations=declarations)
        for record in records:
            snapshot = session.ingest(record)
            if snapshot is not None:
                promoted[host] = snapshot
    return estate, declarations, promoted


def test_two_collators_promote_into_one_estate(samples) -> None:
    estate, declarations, promoted = run_estate(samples)
    assert set(promoted) == set(HOSTS)
    assert estate.reaches() == {h: Reach.CONNECTED for h in HOSTS}
    # Each host's axes arrived with it, keyed to the host the manifest
    # named rather than to whoever the transport thought dialled.
    for host in HOSTS:
        assert declarations.facts(host, "generations") == frozenset(
            {"ConfigurationRevision", "Booted"}
        )


def test_the_estate_answers_its_founding_question(samples) -> None:
    estate, declarations, _ = run_estate(samples)
    intent = intent_for()
    view = assemble(estate, intent, declarations)
    answer = estate_current(view, estate, intent)

    registry = Registry()
    for path in sorted(CONTRACT.glob("*.json")):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    validator = Draft202012Validator(
        json.loads((CONTRACT / "se.answer.1.json").read_text()), registry=registry
    )
    errors = sorted(validator.iter_errors(answer), key=str)
    assert not errors, "\n".join(f"- {e.json_path}: {e.message}" for e in errors)

    # Two hosts, two revisions: the estate the founding failure said yes to.
    assert answer["verdict"] == "degraded"
    assert "4f9c2e1" in answer["answer"] and "9ab31d0" in answer["answer"]
    assert answer["epistemic"] == "complete", (
        "both declared hosts answered and nothing was unclassified"
    )
    observed = [b for b in answer["basis"] if b["kind"] == "observed"]
    assert {b["origin"] for b in observed} == {
        "storage-1/nix/generations", "edge-1/nix/generations"
    }
    derived = [b for b in answer["basis"] if b["kind"] == "derived"]
    assert len(derived) == 1 and derived[0]["origin"] == "hub"
    assert sorted(answer["reach"]["consulted"]) == ["edge-1/nix", "storage-1/nix"]


def test_a_host_that_never_dialled_in_narrows_rather_than_breaks(samples) -> None:
    """The estate view exists with one collator connected, and says so."""
    estate, declarations, _ = run_estate(samples, hosts=("storage-1",))
    intent = intent_for()
    view = assemble(estate, intent, declarations)
    answer = estate_current(view, estate, intent)
    assert view.reach == {"storage-1": Reach.CONNECTED, "edge-1": Reach.UNSWEPT}
    assert answer["reach"]["unswept"] == ["edge-1"]
    assert answer["verdict"] != "healthy"
    assert answer["epistemic"] == "partial"


def test_the_two_hosts_objects_never_merge(samples) -> None:
    """Item 1's hub half over real sessions: both collators publish
    generation:7 and nothing about the string says they are one thing."""
    estate, declarations, _ = run_estate(samples)
    view = assemble(estate, intent_for(), declarations)
    assert len(view.rows) == 2, [r.id for r in view.rows]
    assert {r.id for r in view.rows} == {
        "storage-1/generation:7", "edge-1/generation:7"
    }
    assert all(not row.estate_scoped for row in view.rows)
