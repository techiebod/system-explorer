"""The fixed order of a connection: declarations, checkpoint, then stream.

The order is not a convention. The declarations carry the fact axes
without which the hub can render nothing; the checkpoint carries the
state and says when it is complete; only then does the stream mean
anything. These tests hold the phases against records arriving out of it.
"""

from __future__ import annotations

import pytest

from system_explorer.hub.checkpoint import Estate, Reach
from system_explorer.hub.session import (
    Declarations,
    Phase,
    Session,
    SessionRefused,
)

from test_checkpoint_contract import emit_samples


@pytest.fixture(scope="module")
def samples() -> dict[str, list[dict]]:
    return emit_samples()


def declaration(collector: str, *collections: str) -> dict:
    return {
        "schema": "se.declaration/1", "collector": collector, "version": "0.7.0",
        "collections": [{
            "name": c, "question": "?", "prefix": c[:-1] or "x", "freshness": "60s",
            "perishability": "perishable", "answer": ["State"],
            "facts": {"State": {"type": "string", "temperament": "state",
                                "kind": "observed", "discloses": "nothing",
                                "sentence": "."}},
        } for c in collections],
    }


def session_for(records: list[dict], hashes: list[str] | None = None):
    """Run a real checkpoint through a session, declaring its hashes first."""
    estate = Estate()
    session = Session(estate=estate, declarations=Declarations())
    manifest = records[0]
    for digest in hashes if hashes is not None else manifest["declarations"]:
        session.ingest(declaration("c", *[e["collection"] for e in manifest["collections"]]),
                       digest=digest)
    promoted = [s for r in records if (s := session.ingest(r)) is not None]
    return session, estate, promoted


def test_the_happy_order(samples) -> None:
    records = samples["manifest-state-terminal"]
    session, estate, promoted = session_for(records)
    assert len(promoted) == 1
    assert session.phase is Phase.STREAM
    assert session.host == "storage-1"
    assert estate.reach("storage-1") is Reach.CONNECTED
    # And the fact axes arrived with the host they belong to, which the
    # manifest names — never the transport's idea of who dialled.
    assert session.declarations.facts("storage-1", "pools") == frozenset({"State"})


def test_a_checkpoint_before_any_declaration_is_refused(samples) -> None:
    session = Session(estate=Estate(), declarations=Declarations())
    with pytest.raises(SessionRefused) as caught:
        session.ingest(samples["manifest-state-terminal"][0])
    assert caught.value.reason == "no-declarations"


def test_a_manifest_naming_a_hash_the_hub_does_not_hold(samples) -> None:
    """On a reversed connection there is nothing to fetch: a hub has no
    way to reach a collator, which is the property the reversal exists to
    provide. So an unknown hash is a collator that skipped a step."""
    records = samples["manifest-state-terminal"]
    with pytest.raises(SessionRefused) as caught:
        session_for(records, hashes=["sha256:something-else"])
    assert caught.value.reason == "declaration-unknown"
    assert "cannot fetch" in caught.value.detail


def test_a_declaration_must_arrive_with_its_hash(samples) -> None:
    session = Session(estate=Estate(), declarations=Declarations())
    with pytest.raises(SessionRefused) as caught:
        session.ingest(declaration("c", "pools"))
    assert caught.value.reason == "declaration-unhashed"


def test_a_non_declaration_in_the_declaration_phase(samples) -> None:
    session = Session(estate=Estate(), declarations=Declarations())
    session.ingest({"schema": "se.stream/1", "record": "begin"}, digest="sha256:x")
    with pytest.raises(SessionRefused) as caught:
        session.ingest(samples["manifest-state-terminal"][0])
    assert caught.value.reason == "not-a-declaration"


def test_a_disconnection_before_the_terminal_leaves_the_host_unswept(samples) -> None:
    """Connected and never completed is not dark. Nobody has told us."""
    records = samples["manifest-state-terminal"]
    estate = Estate(declared=("storage-1",))
    session = Session(estate=estate, declarations=Declarations())
    for digest in records[0]["declarations"]:
        session.ingest(declaration("c", "pools", "leases"), digest=digest)
    session.ingest(records[0])
    assert estate.reach("storage-1") is Reach.UNSWEPT
    session.disconnected()
    assert estate.reach("storage-1") is Reach.UNSWEPT
    assert estate.visible("storage-1") is None


def test_one_hosts_declaration_is_not_anothers(samples) -> None:
    held = Declarations()
    held.add("storage-1", declaration("storage", "pools"), "sha256:a")
    assert held.facts("storage-1", "pools") == frozenset({"State"})
    assert held.facts("edge-1", "pools") is None, (
        "None is not an empty set: one means nothing is declared here, the "
        "other means nobody has said"
    )
    assert held.declares("storage-1", "pools", "State")
    assert not held.declares("edge-1", "pools", "State")


def test_the_hub_can_reach_the_axes_it_was_sent() -> None:
    """Declarations travel up because the hub cannot render or serve MCP
    without the fact axes. Holding them and exposing only the fact NAMES
    is the same as not having them: a renderer could tell a fact was
    declared and nothing about how to show it, which is how the estate
    page ended up joining every fact into one cell."""
    held = Declarations()
    document = {
        "schema": "se.declaration/1", "collector": "units", "version": "1.0.0",
        "collections": [{
            "name": "units", "question": "what is running?", "prefix": "unit",
            "freshness": "60s", "perishability": "perishable",
            "answer": ["ActiveState", "SubState", "Description"],
            "ceiling": {"records": 4096, "bytes": 1048576},
            "facts": {
                "ActiveState": {"type": "enum", "values": ["active", "failed"],
                                "temperament": "state", "kind": "observed",
                                "discloses": "nothing", "sentence": "systemd's own word."},
                "SubState": {"type": "string", "temperament": "state",
                             "kind": "observed", "discloses": "nothing", "sentence": "."},
                "Description": {"type": "string", "temperament": "configuration",
                                "kind": "observed", "discloses": "content",
                                "sentence": "."},
            },
        }],
    }
    held.add("storage-1", document, "sha256:u")

    # The columns, in the declared order — not sorted, not invented.
    assert held.answer("storage-1", "units") == (
        "ActiveState", "SubState", "Description")

    shape = held.shape("storage-1", "units")
    assert shape["prefix"] == "unit"
    assert shape["ceiling"]["records"] == 4096
    assert shape["facts"]["ActiveState"]["values"] == ["active", "failed"]
    assert shape["facts"]["ActiveState"]["sentence"] == "systemd's own word."

    # And a pair nobody declared reaches nothing, which a caller must not
    # render as a collection that declared no columns.
    assert held.answer("edge-1", "units") == ()
    assert held.shape("edge-1", "units") is None
