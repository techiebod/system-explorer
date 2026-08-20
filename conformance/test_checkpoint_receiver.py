"""The hub's side of the checkpoint: promote all at once, or not at all.

Driven by the SAME bytes the Go collator emits (test_checkpoint_contract
generates them), so the two halves of the protocol are proven against
each other rather than each against somebody's idea of the other. Where
a refusal cannot be produced by a correct emitter, the record is
hand-mutated from a real one rather than written from scratch — a
fabricated record proves the receiver rejects a thing no collator sends.

Coverage: this judges the receiver's rules and the estate's three reach
states. It does not judge the transport, which does not exist yet.
"""

from __future__ import annotations

import copy

import pytest

from system_explorer.hub.checkpoint import (
    CheckpointRefused,
    Estate,
    Reach,
    Receiver,
)

from test_checkpoint_contract import emit_samples


@pytest.fixture(scope="module")
def samples() -> dict[str, list[dict]]:
    return emit_samples()


def drive(records: list[dict]) -> object:
    receiver = Receiver()
    promoted = [snapshot for r in records if (snapshot := receiver.ingest(r)) is not None]
    assert len(promoted) == 1, "exactly one promotion, at the terminal"
    return promoted[0]


def test_a_real_checkpoint_promotes(samples) -> None:
    snapshot = drive(samples["manifest-state-terminal"])
    assert snapshot.host == "storage-1"
    assert snapshot.history_gap == {"from": 81422.5, "to": 98301.0}
    assert set(snapshot.collections) == {"pools", "leases"}
    assert len(snapshot.collections["pools"].objects) == 2
    # The never-applied collection survives promotion as a row, because a
    # hub that dropped it could not tell a collection nobody has run from
    # one it was never told about.
    assert snapshot.unapplied == ("leases",)
    leases = snapshot.collections["leases"]
    assert leases.generation == 0 and leases.freshness == "stale"
    assert leases.stale_reason == "unsupported" and leases.objects == ()


def test_nothing_is_visible_before_the_terminal(samples) -> None:
    """The rule the whole module exists for. A hub that could see a
    collection before the terminal could recompute an estate finding over
    a subset and resolve it — a finding cleared by partial knowledge."""
    records = samples["manifest-state-terminal"]
    estate = Estate(declared=("storage-1",))
    receiver = Receiver()
    for record in records[:-1]:
        assert receiver.ingest(record) is None
        assert estate.visible("storage-1") is None
        assert estate.reach("storage-1") is Reach.UNSWEPT
    snapshot = receiver.ingest(records[-1])
    assert snapshot is not None
    estate.promote(snapshot)
    assert estate.visible("storage-1") is snapshot
    assert estate.reach("storage-1") is Reach.CONNECTED


def test_first_connection_states_a_null_gap(samples) -> None:
    snapshot = drive(samples["first-connection-empty"])
    assert snapshot.history_gap is None
    # Applied and holding nothing is a reading, not an absence.
    assert snapshot.collections["pools"].generation == 1
    assert snapshot.collections["pools"].objects == ()
    assert snapshot.unapplied == ()


def test_two_instances_survive_promotion(samples) -> None:
    snapshot = drive(samples["two-instances"])
    objects = snapshot.collections["identity"].objects
    assert len(objects) == 2, "the hub must not merge what the collator kept apart"
    assert objects[0]["id"] == objects[1]["id"]
    assert {repr(o["instance"]) for o in objects} == {"None", "'radarr'"}


# --- refusals, each mutated from a checkpoint a real emitter produced ---

def refuse(records: list[dict]) -> CheckpointRefused:
    receiver = Receiver()
    with pytest.raises(CheckpointRefused) as caught:
        for record in records:
            receiver.ingest(record)
    return caught.value


def test_interleaved_checkpoints_are_refused(samples) -> None:
    records = copy.deepcopy(samples["manifest-state-terminal"])
    records[1]["checkpoint"] = "cp-other"
    assert refuse(records).reason == "checkpoint-interleaved"


def test_a_state_record_the_manifest_never_named(samples) -> None:
    records = copy.deepcopy(samples["manifest-state-terminal"])
    records[1]["collection"] = "ghosts"
    assert refuse(records).reason == "state-undeclared"


def test_a_generation_that_moved_mid_checkpoint(samples) -> None:
    records = copy.deepcopy(samples["manifest-state-terminal"])
    records[1]["generation"] += 1
    assert refuse(records).reason == "state-generation-moved"


def test_a_truncated_collection(samples) -> None:
    records = copy.deepcopy(samples["manifest-state-terminal"])
    records[1]["objects"].pop()
    assert refuse(records).reason == "state-truncated"


def test_a_terminal_that_counts_wrong(samples) -> None:
    records = copy.deepcopy(samples["manifest-state-terminal"])
    records[-1]["collections"] += 1
    assert refuse(records).reason == "terminal-count-mismatch"


def test_an_applied_collection_that_sent_no_state(samples) -> None:
    records = copy.deepcopy(samples["manifest-state-terminal"])
    del records[1]
    records[-1]["collections"] = 0
    assert refuse(records).reason == "state-missing"


def test_state_for_a_never_applied_collection(samples) -> None:
    records = copy.deepcopy(samples["manifest-state-terminal"])
    ghost = copy.deepcopy(records[1])
    ghost["collection"] = "leases"
    ghost["generation"] = 0
    records.insert(2, ghost)
    assert refuse(records).reason == "state-never-applied"


def test_state_before_any_manifest(samples) -> None:
    records = copy.deepcopy(samples["manifest-state-terminal"])
    assert refuse(records[1:]).reason == "no-manifest"


def test_a_repeated_collection(samples) -> None:
    records = copy.deepcopy(samples["manifest-state-terminal"])
    records.insert(2, copy.deepcopy(records[1]))
    assert refuse(records).reason == "state-repeated"


def test_a_manifest_with_no_declaration(samples) -> None:
    records = copy.deepcopy(samples["manifest-state-terminal"])
    records[0]["declarations"] = []
    assert refuse(records).reason == "manifest-undeclared"


def test_a_refusal_discards_the_fragment(samples) -> None:
    """A receiver that kept what it had accumulated would be one restart
    away from promoting a checkpoint it had already refused."""
    records = copy.deepcopy(samples["manifest-state-terminal"])
    receiver = Receiver()
    receiver.ingest(records[0])
    receiver.ingest(records[1])
    bad = copy.deepcopy(records[1])
    bad["checkpoint"] = "cp-other"
    with pytest.raises(CheckpointRefused):
        receiver.ingest(bad)
    # The terminal of the abandoned checkpoint finds nothing open.
    with pytest.raises(CheckpointRefused) as caught:
        receiver.ingest(records[-1])
    assert caught.value.reason == "no-manifest"


# --- the three reach states ---

def test_unswept_is_not_dark(samples) -> None:
    """Acceptance item 9's subject. A hub restart with only some collators
    reconnected must resolve nothing, and it can only refuse to if it can
    say which of the two silences it is looking at."""
    estate = Estate(declared=("storage-1", "edge-1"))
    assert estate.reaches() == {"storage-1": Reach.UNSWEPT, "edge-1": Reach.UNSWEPT}

    estate.promote(drive(samples["manifest-state-terminal"]))
    assert estate.reach("storage-1") is Reach.CONNECTED
    # edge-1 has still said nothing. Not dark: nobody has told us.
    assert estate.reach("edge-1") is Reach.UNSWEPT

    estate.disconnected("storage-1")
    assert estate.reach("storage-1") is Reach.DARK
    assert estate.visible("storage-1") is not None, (
        "a dark host keeps its last promoted state; blanking it would be "
        "absence rendered as health"
    )
    # A connection that opens and drops without completing a checkpoint
    # leaves the host unswept, never dark.
    estate.connected("edge-1")
    estate.disconnected("edge-1")
    assert estate.reach("edge-1") is Reach.UNSWEPT


def test_promotion_replaces_wholesale(samples) -> None:
    estate = Estate()
    estate.promote(drive(samples["manifest-state-terminal"]))
    assert set(estate.visible("storage-1").collections) == {"pools", "leases"}
    later = drive(samples["two-instances"])
    estate.promote(later)
    assert set(estate.visible("storage-1").collections) == {"identity"}, (
        "a collection the collator no longer names is one this host no "
        "longer has; keeping the old row would serve a fact whose source "
        "has stopped claiming it"
    )
