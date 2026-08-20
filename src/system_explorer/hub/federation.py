"""Two site hubs, federated into an estate view (DESIGN 06).

An estate spans sites; a site is not a small estate. Naming a peer lets
one address reach every host an operator runs while keeping the property
that makes the design work: a site whose sibling is unreachable keeps
working alone and shows the rest as unreachable, because nothing it needs
lives at a sibling.

Four rules, and each is an acceptance clause rather than a preference.

**Hubs agree or refuse.** Two hubs federating from different intent
declarations are describing different estates, and merging them silently
mixes two worldviews. The hash is exchanged on connect and the refusal is
legible — not a connection error, but which document each side holds.
Versions ride beside it, because two hubs agreeing on what the estate IS
while disagreeing on what a fact MEANS is the same wrong merge, quieter.

**Exactly one hop**, and now by capability rather than by URL shape. A
collator dials its own site's hub and nothing else can reach it, so a hub
has no way to reach another site's collators even if it wanted to. What
remains representable is a hub forwarding to a THIRD hub, so a request
names its origin and is answered only from the receiving hub's own site.

**Which side dials is a deployment choice, stated per pair.** A site
behind NAT can only originate, which means the other member accepts — and
that acceptance is not the forbidden inbound port. The prohibition is on
inbound paths to collators and hosts; a hub may accept an authenticated
sibling session. Assuming symmetry is what makes a NAT-mode pair look
broken when it is working.

**Two ages travel with a sibling's data**: when the host told its own
hub, and when that hub told this one. Collapsing them into one figure is
how doubly-stale data gets presented as current, and only the second is
this hub's to measure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .intent import Intent

#: The wire protocol this hub speaks. Bumped when the shape of a session
#: changes; a mismatch refuses rather than negotiating down, because a
#: half-understood session is what promotes a state nobody described.
PROTOCOL_VERSION = 1

#: What the facts MEAN — vocabularies, decline authority, relation states.
#: Carried separately from the protocol because two hubs can agree
#: perfectly about the shape of a record and disagree about what
#: `absent` does to prior state, which is the quieter wrong merge.
SEMANTIC_VERSION = 1


class Dial(str):
    """Which side originates for one pair. Stated, never assumed."""


DIAL_OUT = Dial("out")
DIAL_IN = Dial("in")


@dataclass(frozen=True)
class Handshake:
    site: str
    intent_hash: str
    protocol_version: int = PROTOCOL_VERSION
    semantic_version: int = SEMANTIC_VERSION

    def as_wire(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "intent_hash": self.intent_hash,
            "protocol_version": self.protocol_version,
            "semantic_version": self.semantic_version,
        }


@dataclass(frozen=True)
class Refusal:
    reason: str
    detail: str


def offer(site: str, intent: Intent) -> Handshake:
    return Handshake(site=site, intent_hash=intent.hash)


def review(local: Handshake, remote: Mapping[str, Any]) -> Refusal | None:
    """Whether these two hubs may merge. None means they may.

    Every refusal names both values. "Federation unavailable" is what an
    operator cannot act on; "this site holds abc, the sibling holds def"
    is what they can — and during a rolling deploy the hubs legitimately
    disagree for a window, so this message is read often and by somebody
    who needs to know whether to wait or to fix something.
    """
    for member in ("site", "intent_hash", "protocol_version", "semantic_version"):
        if member not in remote:
            return Refusal(
                "handshake-incomplete",
                f"the sibling's handshake carries no {member}; an unstated version "
                "is not a matching one",
            )
    if remote["protocol_version"] != local.protocol_version:
        return Refusal(
            "protocol-mismatch",
            f"this site speaks protocol {local.protocol_version}, the sibling "
            f"{remote['protocol_version']}; a half-understood session promotes a "
            "state nobody described",
        )
    if remote["semantic_version"] != local.semantic_version:
        return Refusal(
            "semantic-mismatch",
            f"this site reads facts at semantics {local.semantic_version}, the "
            f"sibling {remote['semantic_version']}; agreeing about the shape of a "
            "record while disagreeing about what it means is the quieter wrong merge",
        )
    if remote["intent_hash"] != local.intent_hash:
        return Refusal(
            "intent-mismatch",
            f"this site holds intent {local.intent_hash}, the sibling holds "
            f"{remote['intent_hash']}; the estate view is unavailable until they agree",
        )
    if remote["site"] == local.site:
        return Refusal(
            "same-site",
            f"the sibling calls itself {remote['site']!r}, which is this site; a hub "
            "federating with itself would count every host twice",
        )
    return None


def dial_agreement(local: Dial, remote: Dial) -> Refusal | None:
    """One member originates and the other accepts. Stated per pair.

    Both dialling is a configuration that works by accident and fails
    when one side is behind NAT; neither dialling is a pair that never
    connects and reports nothing about why.
    """
    if local == remote:
        both = "originate" if local == DIAL_OUT else "wait to accept"
        return Refusal(
            "dial-direction",
            f"both members {both}; which side dials is a deployment choice and "
            "assuming symmetry is what makes a NAT-mode pair look broken when it "
            "is working",
        )
    return None


@dataclass(frozen=True)
class SiblingRequest:
    """A request arriving from a peer hub."""

    origin_site: str
    #: The site whose hosts are being asked about.
    for_site: str


def serve(request: SiblingRequest, own_site: str) -> Refusal | None:
    """Answer only from this hub's own site, and never forward onward."""
    if request.for_site != own_site:
        return Refusal(
            "would-forward",
            f"{request.origin_site} asked this hub ({own_site}) for {request.for_site}'s "
            "hosts; a hub answers for its own hosts from what they told it, and for a "
            "sibling's only by asking the sibling — so this request is refused rather "
            "than relayed",
        )
    if request.origin_site == own_site:
        return Refusal(
            "origin-is-self",
            f"a sibling request naming {own_site} as its own origin is a loop closing "
            "through the federation route",
        )
    return None


@dataclass(frozen=True)
class SiblingAges:
    """Two ages, never one.

    told_own_hub is the sibling's measurement and is carried verbatim;
    told_this_hub is the only one this hub can measure. Collapsing them
    is how doubly-stale data gets presented as current.
    """

    told_own_hub_s: float
    told_this_hub_s: float

    def as_wire(self) -> dict[str, float]:
        return {
            "age_at_origin_s": self.told_own_hub_s,
            "age_in_transit_s": self.told_this_hub_s,
        }
