"""The estate view: merge only where intent says, refuse undeclared facts,
and state coverage as identities.

Acceptance items 1 (hub half) and 7 (roll-up half) are judged here, plus
DESIGN 23's coverage claim.
"""

from __future__ import annotations

import pytest

from system_explorer.hub.checkpoint import (
    CollectionSnapshot,
    Estate,
    HostSnapshot,
    Reach,
)
from system_explorer.hub.intent import Intent
from system_explorer.hub.rollup import assemble
from system_explorer.hub.session import Declarations

BOOT = "5e000000-0000-4000-8000-000000000001"


def declaration(collector: str, collection: str, *facts: str) -> dict:
    return {
        "schema": "se.declaration/1",
        "collector": collector,
        "version": "0.7.0",
        "collections": [{
            "name": collection, "question": "?", "prefix": collection[:-1] or "x",
            "freshness": "60s", "perishability": "perishable",
            "answer": list(facts),
            "facts": {f: {"type": "string", "temperament": "state", "kind": "observed",
                          "discloses": "nothing", "sentence": "."} for f in facts},
        }],
    }


def declarations_for(*pairs) -> Declarations:
    held = Declarations()
    for host, doc in pairs:
        held.add(host, doc, f"sha256:{host}-{doc['collector']}")
    return held


def snapshot(host: str, collection: str, objects: list[dict], generation: int = 1) -> HostSnapshot:
    return HostSnapshot(
        host=host, checkpoint="cp", boot_id=BOOT,
        collections={collection: CollectionSnapshot(
            name=collection, generation=generation, freshness="current",
            stale_reason=None, objects=tuple(objects))},
        declarations=("sha256:x",), history_gap=None,
    )


def intent_for(**kwargs) -> Intent:
    document = {
        "schema": "se.intent/1", "estate": "home", "revision": 1,
        "reviewed": "2026-08-20",
        "membership": {"hosts": kwargs.pop("hosts", {"storage-1": {}, "edge-1": {}})},
    }
    document.update(kwargs)
    return Intent.load(document)


def test_two_collators_publishing_one_native_name_never_merge() -> None:
    """Acceptance item 1's hub half. The minted id is identical on both
    hosts and nothing about the string says they are the same thing."""
    estate = Estate()
    estate.promote(snapshot("storage-1", "pools",
                            [{"id": "pools:tank", "name": "tank", "facts": {"State": "ok"}}]))
    estate.promote(snapshot("edge-1", "pools",
                            [{"id": "pools:tank", "name": "tank", "facts": {"State": "degraded"}}]))
    view = assemble(
        estate, intent_for(),
        declarations_for(("storage-1", declaration("storage", "pools", "State")),
                         ("edge-1", declaration("storage", "pools", "State"))),
    )
    assert len(view.rows) == 2, f"two hosts, two objects: {[r.id for r in view.rows]}"
    assert {r.id for r in view.rows} == {"storage-1/pools:tank", "edge-1/pools:tank"}
    assert all(not r.estate_scoped for r in view.rows)
    # And the two facts did not blend into one row.
    assert {r.facts["State"] for r in view.rows} == {"ok", "degraded"}


def test_two_hosts_merge_exactly_when_intent_denotes_them() -> None:
    estate = Estate()
    estate.promote(snapshot("storage-1", "repos",
                            [{"id": "repo:vault", "name": "b2:bucket/vault", "facts": {"State": "ok"}}]))
    estate.promote(snapshot("edge-1", "repos",
                            [{"id": "repo:vault", "name": "/srv/restic/vault", "facts": {"Kind": "rest"}}]))
    intent = intent_for(objects=[{
        "id": "repository:offsite-vault", "kind": "restic-repository",
        "denoted_by": [{"host": "storage-1", "name": "b2:bucket/vault"},
                       {"host": "edge-1", "name": "/srv/restic/vault"}],
    }])
    view = assemble(
        estate, intent,
        declarations_for(("storage-1", declaration("protection", "repos", "State", "Kind")),
                         ("edge-1", declaration("protection", "repos", "State", "Kind"))),
    )
    assert len(view.rows) == 1
    row = view.rows[0]
    assert row.id == "repository:offsite-vault" and row.estate_scoped
    assert row.kind == "restic-repository"
    assert {m.host for m in row.members} == {"storage-1", "edge-1"}
    assert row.facts == {"State": "ok", "Kind": "rest"}


def test_two_instances_on_one_host_stay_two_rows() -> None:
    estate = Estate()
    estate.promote(snapshot("storage-1", "identity", [
        {"id": "identity:indexer:3", "name": "indexer:3", "instance": None,
         "facts": {"Port": "1"}},
        {"id": "identity:indexer:3", "name": "indexer:3", "instance": "radarr",
         "facts": {"Port": "2"}},
    ]))
    view = assemble(estate, intent_for(),
                    declarations_for(("storage-1", declaration("servarr", "identity", "Port"))))
    assert len(view.rows) == 2, [r.id for r in view.rows]
    assert {r.facts["Port"] for r in view.rows} == {"1", "2"}


def test_an_undeclared_fact_reaches_no_rollup() -> None:
    """Acceptance item 7's roll-up half. A fact with no declared axis has
    no kind, no unit and no sentence — nothing that says how to read it."""
    estate = Estate()
    estate.promote(snapshot("storage-1", "pools", [
        {"id": "pools:tank", "name": "tank",
         "facts": {"State": "ok", "SmuggledIn": "surprise"}},
    ]))
    view = assemble(estate, intent_for(),
                    declarations_for(("storage-1", declaration("storage", "pools", "State"))))
    row = view.rows[0]
    assert row.facts == {"State": "ok"}
    assert row.undeclared == ("SmuggledIn",), (
        "dropped and NAMED: an operator looking for a fact they know a "
        "collector emits must see that it was refused"
    )


def test_a_collection_with_no_declaration_contributes_no_facts() -> None:
    """No declaration at all and no facts declared are different states."""
    estate = Estate()
    estate.promote(snapshot("storage-1", "pools",
                            [{"id": "pools:tank", "name": "tank", "facts": {"State": "ok"}}]))
    view = assemble(estate, intent_for(), Declarations())
    assert view.rows[0].facts == {}
    assert view.rows[0].undeclared == ("State",)


def test_one_hosts_declaration_does_not_vouch_for_anothers() -> None:
    estate = Estate()
    estate.promote(snapshot("storage-1", "pools",
                            [{"id": "pools:tank", "name": "tank", "facts": {"State": "ok"}}]))
    estate.promote(snapshot("edge-1", "pools",
                            [{"id": "pools:tank", "name": "tank", "facts": {"State": "ok"}}]))
    # Only storage-1 declared it.
    view = assemble(estate, intent_for(),
                    declarations_for(("storage-1", declaration("storage", "pools", "State"))))
    by_id = {r.id: r for r in view.rows}
    assert by_id["storage-1/pools:tank"].facts == {"State": "ok"}
    assert by_id["edge-1/pools:tank"].facts == {}
    assert by_id["edge-1/pools:tank"].undeclared == ("State",)


def test_an_unswept_host_appears_in_reach_and_contributes_nothing() -> None:
    """The difference between an answer that is narrow and one that is
    wrong."""
    estate = Estate(declared=("storage-1", "nas-1"))
    estate.promote(snapshot("storage-1", "pools",
                            [{"id": "pools:tank", "name": "tank", "facts": {"State": "ok"}}]))
    view = assemble(estate, intent_for(hosts={"storage-1": {}, "nas-1": {}}),
                    declarations_for(("storage-1", declaration("storage", "pools", "State"))))
    assert view.reach == {"storage-1": Reach.CONNECTED, "nas-1": Reach.UNSWEPT}
    assert [r.id for r in view.rows] == ["storage-1/pools:tank"]


def test_coverage_is_identities_and_separates_ruled_from_unruled() -> None:
    intent = intent_for(
        hosts={"storage-1": {}, "edge-1": {}},
        membership_extra=None,
    )
    # not_hosts lives inside membership; build it directly.
    document = dict(intent.document)
    document["membership"] = {
        "hosts": {"storage-1": {}, "edge-1": {}},
        "not_hosts": [{"id": "nh-7", "denoted_by": [{"source": "network/tailscale",
                                                     "name": "phone-1"}],
                       "why": "a handset", "by": "estate-owner", "revision": 1}],
    }
    document.pop("membership_extra", None)
    intent = Intent.load(document)
    view = assemble(
        Estate(), intent, Declarations(),
        discovered=("storage-1", "edge-1", "phone-1", "gw-2"),
        sources_readable=("tailnet-control-plane",),
        sources_unreadable=("site-dhcp",),
    )
    c = view.coverage
    assert c.declared == ("edge-1", "storage-1")
    # The handset was seen and is not declared — the evidence stands.
    assert c.discovered_not_declared == ("gw-2", "phone-1")
    # But somebody ruled on it, so it is not unclassified. gw-2 is.
    assert c.unclassified == ("gw-2",), (
        "unclassified is the set that says the registry is incomplete; "
        "a ruled-out candidate is not evidence of a gap"
    )
    assert c.sources_readable == ("tailnet-control-plane",)
    assert c.sources_unreadable == ("site-dhcp",)


def test_two_instances_across_two_collators_stay_four_rows() -> None:
    """Gate 4's wording of item 1's hub half, exactly: identical native
    names, two instances, two collators. Every pair of these four is a
    merge somebody could plausibly write, and none of them may happen."""
    estate = Estate()
    for host in ("storage-1", "edge-1"):
        estate.promote(snapshot(host, "identity", [
            {"id": "identity:indexer:3", "name": "indexer:3", "instance": None,
             "facts": {"Port": f"{host}-host-native"}},
            {"id": "identity:indexer:3", "name": "indexer:3", "instance": "radarr",
             "facts": {"Port": f"{host}-radarr"}},
        ]))
    view = assemble(
        estate, intent_for(),
        declarations_for(("storage-1", declaration("servarr", "identity", "Port")),
                         ("edge-1", declaration("servarr", "identity", "Port"))),
    )
    assert len(view.rows) == 4, [r.id for r in view.rows]
    assert {r.facts["Port"] for r in view.rows} == {
        "storage-1-host-native", "storage-1-radarr",
        "edge-1-host-native", "edge-1-radarr",
    }
    # And every row is distinguishable by id alone, because a consumer
    # that had to read the facts to tell them apart has already merged
    # them everywhere it counts them.
    assert len({r.id for r in view.rows}) == 4
