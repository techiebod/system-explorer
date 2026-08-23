"""Findings re-keyed for the new architecture, with the reset displayed.

A key change is a lifecycle reset whether or not anybody planned one, so
the question is not whether ages restart but whether a surface can tell
that they did. An operator triaging by age must not work the wrong end
of the list because every finding in the estate looks minutes old.
"""

from __future__ import annotations

import pytest

from system_explorer.hub.checkpoint import (
    CollectionSnapshot,
    Estate,
    HostSnapshot,
)
from system_explorer.hub.lifecycle import Finding, Key, Registry
from system_explorer.hub.resolution import Contributor, Verdict

BOOT = "5e000000-0000-4000-8000-000000000001"
CUT = "2026-08-20T09:00:00Z"


def estate_at(generation: int, host: str = "storage-1") -> Estate:
    estate = Estate(declared=(host,))
    estate.promote(HostSnapshot(
        host=host, checkpoint="cp", boot_id=BOOT,
        collections={"pools": CollectionSnapshot(
            name="pools", generation=generation, freshness="current",
            stale_reason=None, objects=())},
        declarations=("sha256:x",), history_gap=None,
    ))
    return estate


KEY = Key(scope="storage-1", object_id="pool:tank", opinion="zfs-degraded")


def test_the_key_carries_instance_beside_the_object() -> None:
    """Two instances publishing one native name carry two findings."""
    host_native = Key("storage-1", "identity:indexer:3", "unreachable")
    scoped = Key("storage-1", "identity:indexer:3", "unreachable", instance="radarr")
    assert host_native.rendered() != scoped.rendered()
    assert "radarr" in scoped.rendered()


def test_an_estate_scoped_finding_has_a_scope_no_host_could_mint() -> None:
    estate_key = Key(scope="estate", object_id="question:estate-current",
                     opinion="revision-divergence")
    assert estate_key.rendered().startswith("estate/")


def test_a_new_finding_opens_and_a_resolved_one_closes() -> None:
    registry = Registry(reset_at=CUT)
    contributors = [Contributor("storage-1", "pools", 8)]
    open_now = registry.fold("2026-08-20T10:00:00Z", {KEY: contributors}, estate_at(9))
    assert set(open_now) == {KEY.rendered()}
    assert open_now[KEY.rendered()].verdict is Verdict.CURRENT

    # Re-read at a newer generation, condition gone.
    after = registry.fold("2026-08-20T11:00:00Z", {}, estate_at(10))
    assert after == {}, "resolution is observed, and this one was observed"


def test_a_frozen_finding_keeps_its_lifecycle_and_its_last_seen() -> None:
    registry = Registry(reset_at=CUT)
    contributors = [Contributor("storage-1", "pools", 8)]
    registry.fold("2026-08-20T10:00:00Z", {KEY: contributors}, estate_at(9))
    # The host goes unswept: a restarted hub holding findings and no facts.
    frozen = registry.fold("2026-08-20T11:00:00Z", {}, Estate(declared=("storage-1",)))
    finding = frozen[KEY.rendered()]
    assert finding.verdict is Verdict.FROZEN
    assert finding.first_seen == "2026-08-20T10:00:00Z"
    assert finding.last_seen == "2026-08-20T10:00:00Z", (
        "the hub did not see it, so stamping last_seen now would claim an "
        "observation nobody made"
    )
    assert finding.blind == ("unswept",)


def test_an_adopted_finding_says_its_age_is_the_resets() -> None:
    registry = Registry(reset_at=CUT)
    registry.adopt([Finding(key=KEY, first_seen="2026-01-01T00:00:00Z",
                            last_seen="2026-08-19T00:00:00Z")])
    finding = registry.open()[KEY.rendered()]
    assert finding.first_seen == CUT
    assert finding.reset is True
    assert finding.age_is_the_conditions() is False, (
        "a post-cut finding whose age reads as minutes old is "
        "indistinguishable from a condition that appeared minutes ago"
    )


def test_a_finding_first_seen_after_the_reset_carries_its_own_age() -> None:
    registry = Registry(reset_at=CUT)
    registry.fold("2026-08-20T10:00:00Z", {KEY: [Contributor("storage-1", "pools", 8)]},
                  estate_at(9))
    finding = registry.open()[KEY.rendered()]
    assert finding.reset is False and finding.age_is_the_conditions()


def test_the_registry_survives_restart_with_its_lifecycle_intact(tmp_path) -> None:
    """Persistence is what makes a restart honest rather than the founding
    failure: the reopened registry holds the finding — first_seen,
    contributors and all — and the first fold after restart sees an
    unswept estate, so the finding FREEZES with its reason stated instead
    of every condition in the estate clearing at once."""
    store = tmp_path / "lifecycle.db"
    before = Registry(reset_at=CUT, store=store)
    before.fold("2026-08-20T10:00:00Z",
                {KEY: [Contributor("storage-1", "pools", 8)]}, estate_at(9))

    reopened = Registry(reset_at=CUT, store=store)
    finding = reopened.open()[KEY.rendered()]
    assert finding.first_seen == "2026-08-20T10:00:00Z"
    assert finding.contributors == (Contributor("storage-1", "pools", 8),), (
        "'has this been re-read?' is a generation comparison, and a finding "
        "that forgot its generations across a restart would take any "
        "reconnect as new evidence"
    )

    # The restarted hub holds findings and no facts: unswept, so frozen.
    frozen = reopened.fold("2026-08-20T12:00:00Z", {},
                           Estate(declared=("storage-1",)))
    assert frozen[KEY.rendered()].verdict is Verdict.FROZEN
    assert frozen[KEY.rendered()].blind == ("unswept",)
    assert frozen[KEY.rendered()].first_seen == "2026-08-20T10:00:00Z"


def test_an_observed_resolution_survives_restart_as_closed(tmp_path) -> None:
    store = tmp_path / "lifecycle.db"
    registry = Registry(reset_at=CUT, store=store)
    registry.fold("2026-08-20T10:00:00Z",
                  {KEY: [Contributor("storage-1", "pools", 8)]}, estate_at(9))
    registry.fold("2026-08-20T11:00:00Z", {}, estate_at(10))
    assert Registry(reset_at=CUT, store=store).open() == {}, (
        "a finding observed resolved must not rise from the store"
    )


def test_adoption_survives_restart_still_marked_reset(tmp_path) -> None:
    store = tmp_path / "lifecycle.db"
    registry = Registry(reset_at=CUT, store=store)
    registry.adopt([Finding(key=KEY, first_seen="2026-01-01T00:00:00Z",
                            last_seen="2026-08-19T00:00:00Z")])
    finding = Registry(reset_at=CUT, store=store).open()[KEY.rendered()]
    assert finding.reset is True and finding.first_seen == CUT


def test_a_storeless_registry_still_works_in_memory() -> None:
    registry = Registry(reset_at=CUT)
    registry.fold("2026-08-20T10:00:00Z",
                  {KEY: [Contributor("storage-1", "pools", 8)]}, estate_at(9))
    assert set(registry.open()) == {KEY.rendered()}


def test_no_old_key_is_translated() -> None:
    """Adopting rather than mapping is the decision: a wrong mapping is
    worse than a stated reset, and this product has no estate to protect
    from the churn yet."""
    registry = Registry(reset_at=CUT)
    registry.adopt([Finding(key=KEY, first_seen="2026-01-01T00:00:00Z",
                            last_seen="2026-08-19T00:00:00Z")])
    assert set(registry.open()) == {KEY.rendered()}, (
        "the key is the new one; nothing carries the old shape forward"
    )
