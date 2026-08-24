"""The home-automation projection (DESIGN 30).

**Findings, never facts.** A fact has no lifecycle and would flap; a
finding has one by design. This surface projects the findings registry
ONLY. §30's host roll-up entity and problem-domain entities are NOT
built, and `acknowledged` is hardcoded false rather than read from the
transitions log, so an automation watching it re-alerts on acknowledged
findings — both owed at register row 47. This docstring previously
claimed the roll-up was projected too; corrected 2026-08-24.

**Publish-only, into a broker somebody else owns.** The broker is never
the transport between tiers: a retained message is a stored observation
served as current, the broker would become a stateful third party the
observation path depends on, and half the wire is request-shaped anyway.

Four rules carry most of the weight, and each is a way the founding
failure could re-enter at the transport layer:

- **Retain discovery, never state.** A retained state message is exactly
  what the hub is forbidden to hold, and a restarted broker would replay
  a green from before an outage.
- **Availability is driven by whether the hub could look.** This is
  absence-versus-health at the transport layer: a host going dark makes
  its entities *unavailable*, and never leaves them at their last value.
- **Refusing retain needs a republish protocol or it is just silence.** A
  birth message on attach, a last-will that marks everything unavailable
  when the hub is not there, and a republish on demand and on the
  broker's own restart. Unknown must be a state you pass through in
  seconds, not one you live in.
- **A resolved finding has its discovery entry REMOVED**, not set to a
  good value, or the entity list accumulates every condition the estate
  has ever had.

**Acknowledgement is an attribute, never a filter.** An acknowledged
finding is still true, and suppression is the one power the findings
design refuses to create — a projection must not create it either.

The transport is injected. Everything here is a pure function of the
findings and the reach, so every rule above is assertable without a
broker, and the library that speaks MQTT stays a library.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Mapping

from .checkpoint import Reach
from .lifecycle import Finding
from .resolution import Verdict


@dataclass(frozen=True)
class Message:
    topic: str
    payload: str
    retain: bool = False

    def as_wire(self) -> dict[str, object]:
        return {"topic": self.topic, "payload": self.payload, "retain": self.retain}


def entity_id(estate: str, finding_key: str) -> str:
    """An opaque, topic-safe encoding of the finding key, scoped by estate.

    Law 1 over a namespace this product does not own. Two estates sharing
    one broker must not collide, a dataset path is not a legal topic, and
    **machine identity does not belong in somebody else's broker in the
    clear** — which is §21's `identity` disclosure rule applied to a
    transport rather than to a payload.
    """
    digest = hashlib.sha256(f"{estate}\x00{finding_key}".encode()).hexdigest()
    return f"se_{digest[:20]}"


def _root(prefix: str, estate: str) -> str:
    return f"{prefix}/{entity_id(estate, '')}"


def availability_topic(prefix: str, estate: str) -> str:
    return f"{_root(prefix, estate)}/availability"


def birth(prefix: str, estate: str) -> Message:
    """Published when the hub attaches. Not retained: it is a statement
    about now, and a retained one would outlive the process making it."""
    return Message(availability_topic(prefix, estate), "online")


def will(prefix: str, estate: str) -> Message:
    """Registered with the broker at connect, so the broker publishes it
    if the hub stops without saying goodbye. Without this, a hub that
    dies leaves every entity at its last value — absence rendered as
    health, at the transport layer."""
    return Message(availability_topic(prefix, estate), "offline")


def entity_availability(prefix: str, estate: str, host: str, reach: Reach) -> Message:
    """Per host, because reach is per host.

    Only `connected` is available. A dark host told us and stopped; an
    unswept one has not told us at all — and neither is evidence that the
    conditions it last reported are still true.
    """
    return Message(
        f"{_root(prefix, estate)}/host/{entity_id(estate, host)}/availability",
        "online" if reach is Reach.CONNECTED else "offline",
    )


def discovery(prefix: str, estate: str, finding: Finding) -> Message:
    """The retained half, and the only retained half."""
    key = finding.key.rendered()
    unique = entity_id(estate, key)
    return Message(
        f"{_root(prefix, estate)}/finding/{unique}/config",
        json.dumps({
            "unique_id": unique,
            "name": finding.key.opinion,
            "availability_topic": f"{_root(prefix, estate)}/host/"
                                  f"{entity_id(estate, finding.key.scope)}/availability",
            "state_topic": f"{_root(prefix, estate)}/finding/{unique}/state",
            "json_attributes_topic": f"{_root(prefix, estate)}/finding/{unique}/attrs",
        }, sort_keys=True),
        retain=True,
    )


def removal(prefix: str, estate: str, finding_key: str) -> Message:
    """An empty retained payload deletes the discovery entry.

    Removal rather than a good value: a resolved finding left in place
    accumulates, and an entity list holding every condition the estate has
    ever had is one nobody reads.
    """
    return Message(
        f"{_root(prefix, estate)}/finding/{entity_id(estate, finding_key)}/config",
        "", retain=True,
    )


def state(prefix: str, estate: str, finding: Finding) -> list[Message]:
    """State and attributes, neither retained.

    `frozen` is a state of its own and never a quiet `off`: the condition
    may still hold and nobody could look, which is the distinction this
    whole product exists to keep.
    """
    unique = entity_id(estate, finding.key.rendered())
    base = f"{_root(prefix, estate)}/finding/{unique}"
    value = {Verdict.CURRENT: "on", Verdict.FROZEN: "frozen"}.get(finding.verdict, "off")
    return [
        Message(f"{base}/state", value),
        Message(f"{base}/attrs", json.dumps({
            "first_seen": finding.first_seen,
            "last_seen": finding.last_seen,
            "verdict": finding.verdict.value,
            # An attribute, never a filter. An acknowledged finding is
            # still true, and a projection that hid one would create the
            # suppression the findings design refuses to.
            "acknowledged": False,
            "age_is_the_conditions": finding.age_is_the_conditions(),
            "blind": list(finding.blind),
        }, sort_keys=True)),
    ]


class Projection:
    """Tracks which discovery entries exist, so resolved findings are removed.

    Held here rather than read back from the broker: the broker is a third
    party this product does not observe, and asking it what it holds would
    make the projection's correctness depend on it.
    """

    def __init__(self, prefix: str, estate: str) -> None:
        self.prefix = prefix
        self.estate = estate
        self._published: set[str] = set()

    def republish(
        self, findings: Mapping[str, Finding], reach: Mapping[str, Reach]
    ) -> list[Message]:
        """Everything, from scratch. Called on attach, on demand, and when
        the broker restarts — because with no retained state a subscriber
        that restarted would otherwise stay unknown indefinitely, which is
        honest and useless."""
        messages = [birth(self.prefix, self.estate)]
        for host, state_of in sorted(reach.items()):
            messages.append(entity_availability(self.prefix, self.estate, host, state_of))
        for key, finding in sorted(findings.items()):
            messages.append(discovery(self.prefix, self.estate, finding))
            messages.extend(state(self.prefix, self.estate, finding))
        gone = self._published - set(findings)
        for key in sorted(gone):
            messages.append(removal(self.prefix, self.estate, key))
        self._published = set(findings)
        return messages
