"""Acceptance item 6's hub half: cross-host re-testing against intent.

At the collator, `resolved-later` is one collator's two batches. At the
hub it is two different collators — host A asserted an edge into open
space and host B's checkpoint is what closes it. These tests hold that,
and the property the item names outright: an upgrade never re-keys.
"""

from __future__ import annotations

import pytest

from system_explorer.hub.intent import Intent
from system_explorer.hub.relations import Assertion, retest


def intent_for(objects=None, hosts=None) -> Intent:
    return Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": 1,
        "reviewed": "2026-08-20",
        "membership": {"hosts": hosts or {"storage-1": {}, "nas-1": {}}},
        "objects": objects or [],
    })


VAULT = {
    "id": "repository:offsite-vault", "kind": "restic-repository",
    "denoted_by": [{"host": "storage-1", "name": "b2:bucket/vault"},
                   {"host": "nas-1", "name": "/srv/restic/vault"}],
}


def job(target_name: str, key: str = "k1") -> Assertion:
    return Assertion(
        key=key, source_host="storage-1", source_id="job:nightly",
        type="copied-to", target_name=target_name, resolved=False,
        observability="asserted",
    )


def test_a_target_intent_denotes_resolves_without_re_keying() -> None:
    before = job("b2:bucket/vault")
    after = retest([before], intent_for([VAULT]))[0]
    assert after.resolved is True
    assert after.target_id == "repository:offsite-vault"
    assert after.key == before.key, (
        "the key is derived from the target's name AS PUBLISHED, never the "
        "resolved id — a key that changed would reset the lifecycle every "
        "time the estate learned something"
    )
    assert after.target_name == before.target_name


def test_the_far_ends_own_spelling_also_resolves() -> None:
    """A backup job's configured destination is the remote path, spelled
    the way the remote spells it — so the source publishes a name only the
    far host would recognise."""
    after = retest([job("/srv/restic/vault")], intent_for([VAULT]))[0]
    assert after.target_id == "repository:offsite-vault"


def test_a_name_nothing_denotes_stays_asserted() -> None:
    """The founding condition, preserved at estate scope: a repository
    nothing anywhere claims is asserted, and asserted is not a degraded
    confirmed."""
    after = retest([job("/tmp/somewhere-nobody-declared")], intent_for([VAULT]))[0]
    assert after.resolved is False
    assert after.target_id is None
    assert after.observability == "asserted"


def test_one_name_denoting_two_objects_is_refused_not_chosen() -> None:
    intent = intent_for([
        {"id": "repository:a", "kind": "r",
         "denoted_by": [{"host": "nas-1", "name": "shared"}]},
        {"id": "repository:b", "kind": "r",
         "denoted_by": [{"host": "edge-1", "name": "shared"}]},
    ])
    after = retest([job("shared")], intent)[0]
    assert after.resolved is False, (
        "picking one would merge two estate objects on the strength of a "
        "shared string"
    )


def test_resolved_later_across_two_collators() -> None:
    """The hub-half of the item, in one assertion. Nothing about host A's
    own checkpoint could have resolved this; host B's is what does."""
    intent = intent_for([VAULT])
    asserted = job("/srv/restic/vault")
    # Before intent denotes it, the edge points into open space.
    unlinked = retest([asserted], intent_for([]))[0]
    assert unlinked.resolved is False
    # With the estate object declared, the same key resolves.
    linked = retest([asserted], intent)[0]
    assert linked.resolved is True
    assert linked.key == unlinked.key == asserted.key


def test_both_ends_asserting_is_confirmed() -> None:
    intent = intent_for([
        VAULT,
        {"id": "host:storage", "kind": "host",
         "denoted_by": [{"host": "storage-1", "name": "job:nightly"}]},
    ])
    outward = Assertion(
        key="k1", source_host="storage-1", source_id="job:nightly",
        type="copied-to", target_name="/srv/restic/vault", resolved=False,
        observability="asserted",
    )
    inward = Assertion(
        key="k2", source_host="nas-1", source_id="/srv/restic/vault",
        type="copied-to", target_name="job:nightly", resolved=False,
        observability="asserted",
    )
    by_key = {a.key: a for a in retest([outward, inward], intent)}
    assert by_key["k1"].observability == "confirmed", (
        "both ends observed and agreeing is the state a single vantage "
        "cannot compute"
    )


def test_a_far_end_nobody_checkpointed_is_not_guessed() -> None:
    """Neither confirmed nor contradicted: the hub computes observability
    from assertions it actually holds."""
    after = retest([job("b2:bucket/vault")], intent_for([VAULT]))[0]
    assert after.resolved is True
    assert after.observability == "asserted"


def test_an_already_resolved_relation_keeps_its_key_and_id() -> None:
    resolved = Assertion(
        key="k9", source_host="storage-1", source_id="pool:tank",
        type="contains", target_name="vdev:a", resolved=True,
        target_id="storage-1/vdev:a", observability="confirmed",
    )
    after = retest([resolved], intent_for([VAULT]))[0]
    assert after.key == "k9" and after.target_id == "storage-1/vdev:a"
