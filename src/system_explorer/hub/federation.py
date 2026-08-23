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

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

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


def _age_s(then: str, now: str) -> float:
    """Seconds between two fixed-width UTC stamps. Arithmetic, not a
    clock read: both stamps are this hub's own, so no cross-hub skew can
    reach it — which is the whole reason ages travel as seconds."""
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    delta = (datetime.strptime(now, fmt).replace(tzinfo=timezone.utc)
             - datetime.strptime(then, fmt).replace(tzinfo=timezone.utc))
    return delta.total_seconds()


def site_answer(
    view_of: Callable[[], Any],
    own_site: str,
    told_of: Callable[[str], str | None],
    now_of: Callable[[], str],
) -> Callable[[SiblingRequest], Any]:
    """The answer a peer session serves: this hub's own site, rendered by
    the SAME functions the local surface uses — one spelling, not a
    second one to drift — plus the one age this hub can measure per host.

    age_at_origin_s is None where nothing stamped the host's arrival:
    an unstated age, never a zero standing in for a measurement nobody
    took.
    """
    from .routes import render_hosts, render_objects, render_opinions

    def answer(_request: SiblingRequest) -> Any:
        state = view_of()
        now = now_of()
        ages: dict[str, float | None] = {}
        for host in state.view.reach:
            told = told_of(host)
            ages[host] = _age_s(told, now) if told is not None else None
        return {"site": own_site,
                **render_hosts(state),
                **render_objects(state),
                **render_opinions(state),
                "age_at_origin_s": ages}

    return answer


def ask(
    stream_in,
    stream_out,
    local: Handshake,
    for_site: str,
) -> tuple[Any | None, Refusal | None]:
    """The dial-out half of a peer session: handshake, one request, one
    answer. BOTH sides review — a hub that accepted a mismatched sibling
    because the sibling accepted it first would merge the worldview it
    exists to refuse."""
    opening = _read(stream_in)
    if opening is None or opening.get("record") != "handshake":
        return None, Refusal("no-handshake", "the peer did not identify itself")
    refusal = review(local, opening)
    if refusal is not None:
        return None, refusal
    _write(stream_out, {"record": "handshake", **local.as_wire()})
    verdict = _read(stream_in)
    if verdict is None:
        return None, Refusal("peer-gone", "the peer closed during the handshake")
    if verdict.get("record") == "refused":
        return None, Refusal(verdict.get("reason", "refused"),
                             verdict.get("detail", ""))
    if verdict.get("record") != "agreed":
        return None, Refusal(
            "protocol",
            f"expected agreed or refused, got {verdict.get('record')!r}")
    _write(stream_out, {"record": "request",
                        "origin_site": local.site, "for_site": for_site})
    reply = _read(stream_in)
    if reply is None:
        return None, Refusal("peer-gone", "the peer closed before answering")
    if reply.get("record") == "refused":
        return None, Refusal(reply.get("reason", "refused"),
                             reply.get("detail", ""))
    return reply.get("body"), None


def surface_reader(
    connect: Callable[[], tuple[Any, Any] | None],
    local: Handshake,
    now_of: Callable[[], str],
) -> Callable[[str], Any]:
    """A `sibling_of` for the route table: ask the sibling LIVE per
    request — never from a store, because replicating observations
    between hubs is the shortcut that stays forbidden — and wrap the
    answer with the transit half of the two ages. The body's own
    age_at_origin_s stays the sibling's measurement, carried verbatim."""

    def read(site: str) -> Any:
        streams = connect()
        if streams is None:
            return {"error": "the sibling session could not be opened",
                    "site": site}
        stream_in, stream_out = streams
        asked_at = now_of()
        body, refusal = ask(stream_in, stream_out, local, site)
        if refusal is not None:
            return {"error": refusal.reason, "detail": refusal.detail,
                    "site": site}
        return {"origin": site, "asked_at": asked_at,
                "answered_at": now_of(), "answer": body}

    return read


# --- the federation session on a socket -------------------------------

def peer_session(
    stream_in,
    stream_out,
    local: Handshake,
    own_site: str,
    answer: Callable[[SiblingRequest], Any],
) -> Refusal | None:
    """Serve one peer: handshake, then requests, until the peer goes away.

    The handshake is first and its refusal is terminal — a hub that
    answered one request before checking would have merged two worldviews
    for exactly as long as it took to notice.
    """
    _write(stream_out, {"record": "handshake", **local.as_wire()})
    opening = _read(stream_in)
    if opening is None:
        return Refusal("no-handshake", "the peer closed before identifying itself")
    if opening.get("record") != "handshake":
        return Refusal(
            "handshake-expected",
            f"a peer session opens with a handshake, not {opening.get('record')!r}",
        )
    refusal = review(local, opening)
    if refusal is not None:
        _write(stream_out, {"record": "refused", "reason": refusal.reason,
                            "detail": refusal.detail})
        return refusal
    _write(stream_out, {"record": "agreed"})

    while (request := _read(stream_in)) is not None:
        if request.get("record") != "request":
            _write(stream_out, {"record": "refused", "reason": "unknown-record",
                                "detail": f"{request.get('record')!r} is not a request"})
            continue
        sibling = SiblingRequest(
            origin_site=request.get("origin_site", ""),
            for_site=request.get("for_site", ""),
        )
        denial = serve(sibling, own_site)
        if denial is not None:
            _write(stream_out, {"record": "refused", "reason": denial.reason,
                                "detail": denial.detail})
            continue
        _write(stream_out, {"record": "answer", "body": answer(sibling)})
    return None


def _write(stream, record: Mapping[str, Any]) -> None:
    """Write one record, treating a vanished peer as a vanished peer.

    A sibling that goes away mid-exchange is ordinary on a real network,
    and the transport reports it differently depending on the platform
    and on how the far side left: an orderly close surfaces as EOF, an
    abrupt one as a reset. Both mean the same thing here, so both are
    swallowed and the caller finds out on the next read.
    """
    line = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        stream.write(line)
        stream.flush()
    except (BrokenPipeError, ConnectionResetError, ValueError, OSError):
        return


def _read(stream) -> dict[str, Any] | None:
    """One record, or None when the peer is gone.

    **A reset is a departure, not a crash.** Found by CI on Linux, 2026-08-20:
    a peer that closes without a handshake makes `readline` return empty on
    darwin and raise ConnectionResetError on linux, and the unhandled raise
    killed the serving thread rather than reporting the sibling gone. A hub
    whose federation thread dies on an ordinary reset would lose the estate
    view to a sibling's reboot — the same shape as absence being reported as
    health, one layer down.
    """
    try:
        raw = stream.readline()
    except (ConnectionResetError, ConnectionAbortedError, TimeoutError, ValueError, OSError):
        return None
    if not raw:
        return None
    return json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
