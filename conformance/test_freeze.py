"""Absence only resolves where the host could look — acceptance item 9.

The scenario the rule exists for is a hub restart with only some
collators reconnected: left alone that reads as every condition in the
estate clearing at once, written into the permanent record at the moment
of least attention. These tests hold each way a source can be unable to
look against the verdict it must produce.

Coverage: the resolution decision only. Acknowledgement, first-seen and
the transition log are lifecycle, they are untouched by freezing, and
nothing here asserts about them because nothing here may change them.
"""

from __future__ import annotations

import pytest

from system_explorer.hub.checkpoint import Estate, HostSnapshot, CollectionSnapshot
from system_explorer.hub.resolution import (
    Blindness,
    Contributor,
    Verdict,
    judge,
)

BOOT = "5e000000-0000-4000-8000-000000000001"


def snapshot(host: str, **collections: CollectionSnapshot) -> HostSnapshot:
    return HostSnapshot(
        host=host, checkpoint="cp-1", boot_id=BOOT,
        collections=dict(collections), declarations=("sha256:x",), history_gap=None,
    )


def collection(name: str, generation: int, freshness: str = "current",
               reason: str | None = None) -> CollectionSnapshot:
    return CollectionSnapshot(name=name, generation=generation, freshness=freshness,
                              stale_reason=reason, objects=())


def estate_with(*snapshots: HostSnapshot, declared: tuple[str, ...] = ()) -> Estate:
    estate = Estate(declared=declared)
    for s in snapshots:
        estate.promote(s)
    return estate


FINDING = "storage-1/pool:tank/zfs-degraded"


def test_a_condition_that_cleared_on_new_evidence_resolves() -> None:
    """The one case that MUST resolve, or the product cries wolf for ever."""
    estate = estate_with(snapshot("storage-1", pools=collection("pools", 9)))
    verdicts = judge({FINDING: [Contributor("storage-1", "pools", 8)]}, derived=[], estate=estate)
    assert verdicts[FINDING].verdict is Verdict.RESOLVED


def test_an_unswept_host_resolves_nothing() -> None:
    """Item 9 in one assertion. The hub restarted, this collator has not
    dialled back in, and the finding it raised must not clear because the
    hub has forgotten how to see it."""
    estate = Estate(declared=("storage-1",))
    verdicts = judge({FINDING: [Contributor("storage-1", "pools", 8)]}, derived=[], estate=estate)
    judgement = verdicts[FINDING]
    assert judgement.verdict is Verdict.FROZEN
    assert judgement.reasons == (Blindness.UNSWEPT,)


def test_a_dark_host_freezes_and_says_which_silence() -> None:
    estate = estate_with(snapshot("storage-1", pools=collection("pools", 9)))
    estate.disconnected("storage-1")
    verdicts = judge({FINDING: [Contributor("storage-1", "pools", 8)]}, derived=[], estate=estate)
    assert verdicts[FINDING].verdict is Verdict.FROZEN
    # Not the same reason as unswept: only one of the two is evidence
    # about the host, and an operator has to be able to tell them apart.
    assert verdicts[FINDING].reasons == (Blindness.DARK,)


@pytest.mark.parametrize(
    "collection_state,expected",
    [
        (collection("pools", 9, "stale", "unavailable"), Blindness.COLLECTION_STALE),
        (collection("pools", 0, "stale", "unsupported"), Blindness.NEVER_APPLIED),
    ],
)
def test_a_collection_that_could_not_be_evaluated_freezes(collection_state, expected) -> None:
    estate = estate_with(snapshot("storage-1", pools=collection_state))
    verdicts = judge({FINDING: [Contributor("storage-1", "pools", 8)]}, derived=[], estate=estate)
    assert verdicts[FINDING].verdict is Verdict.FROZEN
    assert verdicts[FINDING].reasons == (expected,)


def test_a_collection_the_collator_no_longer_names_freezes() -> None:
    """Its absence from the manifest is a statement about the collator,
    never evidence that the condition cleared."""
    estate = estate_with(snapshot("storage-1", units=collection("units", 3)))
    verdicts = judge({FINDING: [Contributor("storage-1", "pools", 8)]}, derived=[], estate=estate)
    assert verdicts[FINDING].reasons == (Blindness.COLLECTION_ABSENT,)


def test_unmoved_evidence_cannot_resolve_what_it_raised() -> None:
    """The same reading must not both raise a finding and clear it. This
    is the guard that catches a changed RULE quietly resolving findings
    over facts that never moved."""
    estate = estate_with(snapshot("storage-1", pools=collection("pools", 8)))
    verdicts = judge({FINDING: [Contributor("storage-1", "pools", 8)]}, derived=[], estate=estate)
    assert verdicts[FINDING].verdict is Verdict.FROZEN
    assert verdicts[FINDING].reasons == (Blindness.NOT_RE_READ,)


def test_one_third_of_the_evidence_returning_resolves_nothing() -> None:
    """Why a finding remembers every input rather than one batch id: two
    of three contributors came back and the third has not, which a single
    id could not have expressed."""
    estate = estate_with(
        snapshot("storage-1", pools=collection("pools", 9)),
        snapshot("edge-1", units=collection("units", 4)),
        declared=("storage-1", "edge-1", "nas-1"),
    )
    cross_host = "estate/question:data-protected/unconfirmed-copy"
    verdicts = judge(
        {cross_host: [
            Contributor("storage-1", "pools", 8),
            Contributor("edge-1", "units", 3),
            Contributor("nas-1", "pools", 2),
        ]},
        derived=[],
        estate=estate,
    )
    judgement = verdicts[cross_host]
    assert judgement.verdict is Verdict.FROZEN
    assert [c.host for c, _ in judgement.blind] == ["nas-1"], (
        "the two that returned are not blind; the one that has not is"
    )
    assert judgement.reasons == (Blindness.UNSWEPT,)


def test_a_finding_this_evaluation_derived_is_current() -> None:
    estate = Estate(declared=("storage-1",))
    verdicts = judge({FINDING: [Contributor("storage-1", "pools", 8)]},
                     derived=[FINDING], estate=estate)
    # Current beats every blindness: it was just derived, so something
    # could plainly look.
    assert verdicts[FINDING].verdict is Verdict.CURRENT
    assert verdicts[FINDING].blind == ()


def test_a_newly_derived_finding_is_returned_as_current() -> None:
    estate = estate_with(snapshot("storage-1", pools=collection("pools", 9)))
    verdicts = judge({}, derived=["brand-new"], estate=estate)
    assert verdicts["brand-new"].verdict is Verdict.CURRENT, (
        "returned rather than skipped, so a caller cannot mistake "
        "'new' for 'not judged'"
    )


def test_every_blindness_is_reachable() -> None:
    """Non-vacuity: the vocabulary is closed and every member is produced
    by some scenario above, so no member is enumeration without proof."""
    estate = estate_with(
        snapshot("a", c=collection("c", 5)),                       # re-read: not blind
        snapshot("b", c=collection("c", 5, "stale", "unavailable")),
        snapshot("c", c=collection("c", 0, "stale", "unsupported")),
        snapshot("d", other=collection("other", 5)),
        snapshot("e", c=collection("c", 5)),
        declared=("f",),
    )
    estate.disconnected("e")
    inputs = {
        "k": [Contributor("b", "c", 1), Contributor("c", "c", 1), Contributor("d", "c", 1),
              Contributor("e", "c", 1), Contributor("f", "c", 1), Contributor("a", "c", 5)],
    }
    reasons = set(judge(inputs, derived=[], estate=estate)["k"].reasons)
    assert reasons == set(Blindness), f"unreached: {set(Blindness) - reasons}"
