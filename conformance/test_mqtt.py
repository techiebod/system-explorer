"""The home-automation projection: every way it could re-import the
founding failure at the transport layer.

Findings and never facts, discovery retained and state never, availability
driven by whether the hub could look, and a republish protocol without
which refusing retain is just silence.
"""

from __future__ import annotations

import json

import pytest

from system_explorer.hub.checkpoint import Reach
from system_explorer.hub.lifecycle import Finding, Key
from system_explorer.hub.mqtt import (
    Projection,
    birth,
    discovery,
    entity_availability,
    entity_id,
    removal,
    state,
    will,
)
from system_explorer.hub.resolution import Verdict

PREFIX, ESTATE = "homeassistant", "home"
KEY = Key(scope="storage-1", object_id="pool:tank", opinion="zfs-degraded")


def finding(verdict: Verdict = Verdict.CURRENT, blind=()) -> Finding:
    return Finding(key=KEY, first_seen="2026-08-20T10:00:00Z",
                   last_seen="2026-08-20T10:00:00Z", verdict=verdict, blind=tuple(blind))


def test_only_discovery_is_retained() -> None:
    """A retained state message is a stored observation served as current
    — precisely what the hub is forbidden to do — and a restarted broker
    would replay a green from before an outage."""
    assert discovery(PREFIX, ESTATE, finding()).retain is True
    for message in state(PREFIX, ESTATE, finding()):
        assert message.retain is False, message.topic
    assert birth(PREFIX, ESTATE).retain is False
    assert will(PREFIX, ESTATE).retain is False


def test_the_topic_carries_no_machine_identity() -> None:
    """Law 1 over a namespace this product does not own: a dataset path is
    not a legal topic, and machine identity does not belong in somebody
    else's broker in the clear."""
    messages = [discovery(PREFIX, ESTATE, finding()), *state(PREFIX, ESTATE, finding())]
    for message in messages:
        assert "storage-1" not in message.topic
        assert "pool:tank" not in message.topic
        assert "/" not in message.topic.split("/")[-1]
    # And the config payload names the opinion, which is not identity.
    config = json.loads(discovery(PREFIX, ESTATE, finding()).payload)
    assert config["name"] == "zfs-degraded"
    assert "storage-1" not in json.dumps(config)


def test_two_estates_on_one_broker_do_not_collide() -> None:
    assert entity_id("home", "k") != entity_id("other", "k")


def test_availability_follows_reach_not_health() -> None:
    """Absence-versus-health at the transport layer. A host going dark
    makes its entities unavailable, never leaves them at their last
    value."""
    assert entity_availability(PREFIX, ESTATE, "h", Reach.CONNECTED).payload == "online"
    for absent in (Reach.DARK, Reach.UNSWEPT):
        assert entity_availability(PREFIX, ESTATE, "h", absent).payload == "offline", absent


def test_a_frozen_finding_is_its_own_state_never_a_quiet_off() -> None:
    values = {f.verdict: state(PREFIX, ESTATE, f)[0].payload
              for f in (finding(Verdict.CURRENT), finding(Verdict.FROZEN))}
    assert values[Verdict.CURRENT] == "on"
    assert values[Verdict.FROZEN] == "frozen", (
        "the condition may still hold and nobody could look; an off would "
        "say it cleared"
    )


def test_acknowledgement_is_an_attribute_never_a_filter() -> None:
    attrs = json.loads(state(PREFIX, ESTATE, finding())[1].payload)
    assert "acknowledged" in attrs
    # And nothing in the projection drops a finding for being acknowledged.
    projection = Projection(PREFIX, ESTATE)
    messages = projection.republish({KEY.rendered(): finding()}, {"storage-1": Reach.CONNECTED})
    assert any("/config" in m.topic for m in messages)


def test_a_resolved_finding_has_its_discovery_entry_removed() -> None:
    """Removed, not set to a good value, or the entity list accumulates
    every condition the estate has ever had."""
    projection = Projection(PREFIX, ESTATE)
    projection.republish({KEY.rendered(): finding()}, {"storage-1": Reach.CONNECTED})
    after = projection.republish({}, {"storage-1": Reach.CONNECTED})
    removals = [m for m in after if m.topic.endswith("/config")]
    assert len(removals) == 1
    assert removals[0].payload == "", "an empty retained payload deletes the entry"
    assert removals[0].retain is True
    assert removals[0].topic == removal(PREFIX, ESTATE, KEY.rendered()).topic


def test_republish_says_everything_again() -> None:
    """Refusing retain is honest and needs this, or a subscriber that
    restarted stays unknown indefinitely — which is technically honest and
    practically useless."""
    projection = Projection(PREFIX, ESTATE)
    messages = projection.republish(
        {KEY.rendered(): finding()},
        {"storage-1": Reach.CONNECTED, "edge-1": Reach.UNSWEPT})
    topics = [m.topic for m in messages]
    assert any(t.endswith("/availability") and "host" not in t for t in topics), "birth"
    assert sum(1 for t in topics if "/host/" in t) == 2, "one per host"
    assert any(t.endswith("/config") for t in topics)
    assert any(t.endswith("/state") for t in topics)
    assert any(t.endswith("/attrs") for t in topics)


def test_a_second_republish_removes_nothing_that_still_holds() -> None:
    projection = Projection(PREFIX, ESTATE)
    live = {KEY.rendered(): finding()}
    projection.republish(live, {"storage-1": Reach.CONNECTED})
    again = projection.republish(live, {"storage-1": Reach.CONNECTED})
    assert not [m for m in again if m.topic.endswith("/config") and m.payload == ""]


def test_the_projection_carries_no_fact() -> None:
    """Findings, never facts. A fact has no lifecycle and would flap."""
    projection = Projection(PREFIX, ESTATE)
    messages = projection.republish({KEY.rendered(): finding()},
                                    {"storage-1": Reach.CONNECTED})
    blob = json.dumps([m.as_wire() for m in messages])
    for fact_ish in ("CapacityPercent", "State\":", "facts"):
        assert fact_ish not in blob, f"{fact_ish} is a fact reaching the broker"
