"""Acceptance item 10: NAT mode, one hop, a forwarded request refused, and
versions checked beside the intent hash.

The refusals are read by an operator during a rolling deploy, when two
hubs legitimately disagree for a window — so every one of them names both
values, and these tests assert that rather than just the refusal.
"""

from __future__ import annotations

import copy

import pytest

from system_explorer.hub.federation import (
    DIAL_IN,
    DIAL_OUT,
    PROTOCOL_VERSION,
    SEMANTIC_VERSION,
    Handshake,
    SiblingAges,
    SiblingRequest,
    dial_agreement,
    offer,
    review,
    serve,
)
from system_explorer.hub.intent import Intent


def intent_for(revision: int = 41) -> Intent:
    return Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": revision,
        "reviewed": "2026-08-20",
        "membership": {"hosts": {"storage-1": {}, "edge-1": {}}},
    })


def test_two_hubs_holding_one_estate_may_merge() -> None:
    local = offer("site-a", intent_for())
    remote = offer("site-b", intent_for()).as_wire()
    assert review(local, remote) is None


def test_a_different_estate_is_refused_legibly() -> None:
    local = offer("site-a", intent_for(41))
    remote = offer("site-b", intent_for(42)).as_wire()
    refusal = review(local, remote)
    assert refusal is not None and refusal.reason == "intent-mismatch"
    # Both hashes named: "federation unavailable" is what nobody can act on.
    assert local.intent_hash in refusal.detail
    assert remote["intent_hash"] in refusal.detail
    assert "until they agree" in refusal.detail


def test_versions_are_checked_beside_the_hash() -> None:
    local = offer("site-a", intent_for())
    protocol = {**offer("site-b", intent_for()).as_wire(),
                "protocol_version": PROTOCOL_VERSION + 1}
    assert review(local, protocol).reason == "protocol-mismatch"

    semantic = {**offer("site-b", intent_for()).as_wire(),
                "semantic_version": SEMANTIC_VERSION + 1}
    refusal = review(local, semantic)
    assert refusal.reason == "semantic-mismatch", (
        "two hubs agreeing on what the estate IS while disagreeing on what "
        "a fact MEANS is the same wrong merge, quieter"
    )


@pytest.mark.parametrize("member",
                         ["site", "intent_hash", "protocol_version", "semantic_version"])
def test_an_unstated_version_is_not_a_matching_one(member) -> None:
    local = offer("site-a", intent_for())
    remote = offer("site-b", intent_for()).as_wire()
    remote.pop(member)
    assert review(local, remote).reason == "handshake-incomplete"


def test_a_hub_does_not_federate_with_itself() -> None:
    local = offer("site-a", intent_for())
    assert review(local, offer("site-a", intent_for()).as_wire()).reason == "same-site"


def test_nat_mode_states_which_side_dials() -> None:
    """A site behind NAT can only originate, which means the other member
    accepts — and that acceptance is not the forbidden inbound port."""
    assert dial_agreement(DIAL_OUT, DIAL_IN) is None
    assert dial_agreement(DIAL_IN, DIAL_OUT) is None
    both_out = dial_agreement(DIAL_OUT, DIAL_OUT)
    assert both_out is not None and both_out.reason == "dial-direction"
    both_in = dial_agreement(DIAL_IN, DIAL_IN)
    assert both_in is not None and both_in.reason == "dial-direction"
    assert "NAT-mode pair look broken" in both_in.detail


def test_one_hop_holds_and_a_forwarded_request_is_refused() -> None:
    """A hub answers for its own hosts from what they told it, and for a
    sibling's only by asking the sibling."""
    assert serve(SiblingRequest(origin_site="site-a", for_site="site-b"),
                 own_site="site-b") is None
    onward = serve(SiblingRequest(origin_site="site-a", for_site="third-site"),
                   own_site="site-b")
    assert onward is not None and onward.reason == "would-forward"
    assert "refused rather than relayed" in onward.detail


def test_a_loop_closing_through_the_federation_route_is_refused() -> None:
    loop = serve(SiblingRequest(origin_site="site-b", for_site="site-b"),
                 own_site="site-b")
    assert loop is not None and loop.reason == "origin-is-self"


def test_a_siblings_data_carries_two_ages() -> None:
    ages = SiblingAges(told_own_hub_s=12.0, told_this_hub_s=3.5).as_wire()
    assert ages == {"age_at_origin_s": 12.0, "age_in_transit_s": 3.5}, (
        "collapsing them into one figure is how doubly-stale data gets "
        "presented as current, and only the second is this hub's to measure"
    )
