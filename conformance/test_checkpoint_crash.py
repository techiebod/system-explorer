"""Acceptance item 3 at the hub's three checkpoint boundaries.

Kill the hub or the collator at each point where state must be
all-or-nothing, and assert what harness/crash/boundaries.json says must
be true afterwards. The expectations are READ FROM that file rather than
restated here, so a boundary whose expectation drifts fails at the
assertion instead of quietly meaning something else.

"Killing the hub" is modelled by discarding what the hub holds in memory
and building it again, which is exactly what a restart is: DESIGN 06 says
the hub's observations are in memory and its findings are not, and that
asymmetry IS the hazard these boundaries exist for — a restarted hub
holds findings and no facts, which left alone reads as every condition in
the estate clearing at once.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from system_explorer.hub.checkpoint import Estate, Reach
from system_explorer.hub.resolution import (
    Blindness,
    Contributor,
    Verdict,
    judge,
)
from system_explorer.hub.session import Declarations, Session, SessionRefused

from test_checkpoint_contract import emit_samples

BOUNDARIES = json.loads(
    (Path(__file__).resolve().parent.parent / "harness" / "crash" / "boundaries.json").read_text()
)
BY_ID = {b["id"]: b for b in BOUNDARIES["boundaries"]}
CHECKPOINT_BOUNDARIES = ("mid-checkpoint", "post-manifest-pre-terminal",
                         "post-promote-pre-persist")


@pytest.fixture(scope="module")
def samples() -> dict[str, list[dict]]:
    return emit_samples()


def test_the_boundaries_this_suite_claims_all_exist() -> None:
    """Anti-vacuity: a renamed boundary would otherwise make every test
    below pass by testing nothing."""
    missing = [name for name in CHECKPOINT_BOUNDARIES if name not in BY_ID]
    assert not missing, f"boundaries.json no longer names {missing}"


def session_into(estate: Estate) -> Session:
    return Session(estate=estate, declarations=Declarations())


def test_mid_checkpoint(samples) -> None:
    boundary = BY_ID["mid-checkpoint"]
    assert boundary["kill"] == "hub"
    estate = Estate(declared=("storage-1", "edge-1"))
    session = session_into(estate)
    records = samples["session:storage-1"]
    # Everything except the terminal: declarations, manifest, some state.
    for record in records[:-1]:
        assert session.ingest(record) is None

    # The hub dies here. Its in-memory state is everything it had.
    restarted = Estate(declared=("storage-1", "edge-1"))

    assert restarted.visible("storage-1") is None, boundary["expect"]
    assert restarted.reach("storage-1") is Reach.UNSWEPT, boundary["expect"]
    # ...and resolves no finding.
    verdicts = judge(
        {"f1": [Contributor("storage-1", "generations", 6)]}, derived=[], estate=restarted
    )
    assert verdicts["f1"].verdict is Verdict.FROZEN
    assert verdicts["f1"].reasons == (Blindness.UNSWEPT,)


def test_post_manifest_pre_terminal(samples) -> None:
    boundary = BY_ID["post-manifest-pre-terminal"]
    assert boundary["kill"] == "collator"
    estate = Estate(declared=("storage-1",))
    session = session_into(estate)
    records = samples["session:storage-1"]
    for record in records[:-1]:
        session.ingest(record)
    # The collator dies. The connection drops with the checkpoint open.
    session.disconnected()

    assert estate.visible("storage-1") is None, boundary["expect"]
    assert estate.reach("storage-1") is Reach.UNSWEPT, boundary["expect"]

    # And the partial is discarded rather than completed by a later
    # terminal arriving on a new connection.
    fresh = session_into(estate)
    with pytest.raises(SessionRefused) as caught:
        fresh.ingest(records[-1])
    assert caught.value.reason == "out-of-order", (
        "a terminal with no manifest ahead of it cannot complete a checkpoint "
        "the hub already discarded"
    )


def test_post_promote_pre_persist(samples) -> None:
    boundary = BY_ID["post-promote-pre-persist"]
    assert boundary["kill"] == "hub"
    estate = Estate(declared=("storage-1", "edge-1"))
    session = session_into(estate)
    for record in samples["session:storage-1"]:
        session.ingest(record)
    assert estate.reach("storage-1") is Reach.CONNECTED

    # A finding was derived from the promoted state, and the hub dies
    # before its lifecycle is persisted. On restart the findings are what
    # survived and the facts are not — the exact asymmetry the freeze
    # exists for.
    contributors = {
        "storage-1/pool:tank/degraded": [Contributor("storage-1", "generations", 7)],
        "estate/coverage-gap": [Contributor("edge-1", "generations", 4)],
    }
    restarted = Estate(declared=("storage-1", "edge-1"))
    verdicts = judge(contributors, derived=[], estate=restarted)
    assert all(v.verdict is Verdict.FROZEN for v in verdicts.values()), boundary["expect"]
    assert all(v.reasons == (Blindness.UNSWEPT,) for v in verdicts.values()), (
        "unswept is not dark: nobody has told us is a different claim from "
        "told-us-and-stopped, and only one is evidence about the host"
    )
    # The distinction is load-bearing, so prove it discriminates: the same
    # findings against a hub that HAD heard and stopped freeze for the
    # other reason.
    estate.disconnected("storage-1")
    after_dark = judge(contributors, derived=[], estate=estate)
    assert after_dark["storage-1/pool:tank/degraded"].reasons == (Blindness.DARK,)


def test_a_checkpoint_that_completes_after_a_restart_promotes_normally(samples) -> None:
    """The other half of every boundary above: recovery must actually
    recover, or a hub that refused everything would pass all three."""
    estate = Estate(declared=("storage-1",))
    session = session_into(estate)
    for record in samples["session:storage-1"][:-1]:
        session.ingest(record)
    session.disconnected()

    reconnected = session_into(estate)
    promoted = [s for r in samples["session:storage-1"] if (s := reconnected.ingest(r))]
    assert len(promoted) == 1
    assert estate.reach("storage-1") is Reach.CONNECTED
    assert estate.visible("storage-1") is not None
