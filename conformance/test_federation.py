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
    peer_session,
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


# --- two hubs, over real sockets --------------------------------------

def _pair():
    """A connected socket pair as two (in, out) file objects."""
    import socket as _socket

    a, b = _socket.socketpair()
    return (a.makefile("rb"), a.makefile("wb")), (b.makefile("rb"), b.makefile("wb")), (a, b)


def run_pair(local_a, local_b, site_a, site_b, requests):
    """Drive both sides of a peer session and return what each concluded."""
    import threading

    (a_in, a_out), (b_in, b_out), socks = _pair()
    outcome: dict[str, object] = {}

    def serve_b():
        outcome["b"] = peer_session(
            b_in, b_out, local_b, site_b,
            answer=lambda request: {"site": site_b, "hosts": ["storage-1"]},
        )

    thread = threading.Thread(target=serve_b)
    thread.start()

    replies = []
    try:
        # a plays the originating side: read b's handshake, send its own.
        theirs = _read_line(a_in)
        _write_line(a_out, {"record": "handshake", **local_a.as_wire()})
        verdict = _read_line(a_in)
        outcome["a_saw"] = (theirs, verdict)
        if verdict.get("record") == "agreed":
            for request in requests:
                _write_line(a_out, {"record": "request", **request})
                replies.append(_read_line(a_in))
    finally:
        # Shut the write side down rather than closing a file object: the
        # peer's loop ends on EOF, and another makefile on the same socket
        # keeps it alive, so a close alone leaves the peer reading for
        # ever. A test that waited out a join timeout instead would be a
        # test that passes slowly today and flakes later.
        import socket as _socket

        a_out.flush()
        socks[0].shutdown(_socket.SHUT_WR)
        thread.join(timeout=10)
        assert not thread.is_alive(), "the peer session did not end on EOF"
        for f in (a_in, a_out, b_in, b_out):
            try:
                f.close()
            except OSError:
                pass
        socks[0].close()
        socks[1].close()
    outcome["replies"] = replies
    return outcome


def _write_line(stream, record):
    import json as _json

    stream.write((_json.dumps(record, separators=(",", ":")) + "\n").encode())
    stream.flush()


def _read_line(stream):
    import json as _json

    raw = stream.readline()
    return _json.loads(raw.decode()) if raw else None


def test_two_hubs_holding_one_estate_agree_over_a_socket() -> None:
    intent = intent_for()
    outcome = run_pair(offer("site-a", intent), offer("site-b", intent),
                       "site-a", "site-b",
                       requests=[{"origin_site": "site-a", "for_site": "site-b"}])
    theirs, verdict = outcome["a_saw"]
    assert theirs["record"] == "handshake" and theirs["site"] == "site-b"
    assert verdict["record"] == "agreed"
    assert outcome["b"] is None
    assert outcome["replies"][0]["record"] == "answer"
    assert outcome["replies"][0]["body"]["hosts"] == ["storage-1"]


def test_two_hubs_holding_different_estates_refuse_over_a_socket() -> None:
    """And the refusal is terminal: a hub that answered one request before
    checking would have merged two worldviews for as long as it took to
    notice."""
    outcome = run_pair(offer("site-a", intent_for(41)), offer("site-b", intent_for(42)),
                       "site-a", "site-b",
                       requests=[{"origin_site": "site-a", "for_site": "site-b"}])
    _theirs, verdict = outcome["a_saw"]
    assert verdict["record"] == "refused"
    assert verdict["reason"] == "intent-mismatch"
    assert outcome["b"] is not None and outcome["b"].reason == "intent-mismatch"
    assert outcome["replies"] == [], "nothing is served after a refused handshake"


def test_a_third_sites_request_is_refused_over_a_socket() -> None:
    intent = intent_for()
    outcome = run_pair(offer("site-a", intent), offer("site-b", intent),
                       "site-a", "site-b",
                       requests=[{"origin_site": "site-a", "for_site": "site-c"}])
    reply = outcome["replies"][0]
    assert reply["record"] == "refused" and reply["reason"] == "would-forward", (
        "one hop holds: a hub answers for its own hosts and for a sibling's "
        "only by asking the sibling"
    )


def test_a_peer_that_closes_before_identifying_itself() -> None:
    import socket as _socket
    import threading

    a, b = _socket.socketpair()
    result: list[object] = []

    def serve_b():
        with b.makefile("rb") as bi, b.makefile("wb") as bo:
            result.append(peer_session(bi, bo, offer("site-b", intent_for()),
                                       "site-b", answer=lambda r: {}))

    thread = threading.Thread(target=serve_b)
    thread.start()
    a.shutdown(_socket.SHUT_RDWR)
    a.close()
    thread.join(timeout=10)
    assert not thread.is_alive(), "the peer session did not end when the peer left"
    b.close()
    assert result and result[0].reason == "no-handshake"


def test_a_peer_that_vanishes_mid_exchange_is_a_departure_not_a_crash() -> None:
    """A reset and an orderly close mean the same thing to a hub, and the
    platform decides which one it sees. CI on Linux caught this where
    darwin could not: an unhandled reset killed the serving thread, which
    would lose the estate view to a sibling's reboot.

    Forced here rather than hoped for: SO_LINGER with a zero timeout makes
    close() send RST, so both platforms take the reset path.
    """
    import socket as _socket
    import struct
    import threading

    a, b = _socket.socketpair()
    result: list[object] = []

    def serve_b():
        with b.makefile("rb") as bi, b.makefile("wb") as bo:
            result.append(peer_session(bi, bo, offer("site-b", intent_for()),
                                       "site-b", answer=lambda r: {}))

    thread = threading.Thread(target=serve_b)
    thread.start()
    a.setsockopt(_socket.SOL_SOCKET, _socket.SO_LINGER, struct.pack("ii", 1, 0))
    a.close()
    thread.join(timeout=10)
    assert not thread.is_alive(), "the serving thread must not die on a reset"
    assert result and result[0].reason == "no-handshake"
    b.close()


# --- serving: the sibling's site over the surface, live -----------------

def _site_b_state():
    """A real State for site-b: one host, promoted with a stamped arrival."""
    from system_explorer.hub.checkpoint import (
        CollectionSnapshot, Estate, HostSnapshot,
    )
    from system_explorer.hub.http import reading
    from system_explorer.hub.session import Declarations

    declaration = {
        "schema": "se.declaration/1", "collector": "c", "version": "1.0.0",
        "collections": [{
            "name": "pools", "question": "q", "prefix": "pool",
            "freshness": "60s", "perishability": "perishable",
            "answer": ["State"],
            "facts": {"State": {"type": "string", "temperament": "state",
                                "kind": "observed", "discloses": "nothing",
                                "sentence": "."}}}],
    }
    estate = Estate(declared=("storage-1",))
    declarations = Declarations()
    declarations.add("storage-1", declaration, "sha256:x")
    estate.promote(HostSnapshot(
        host="storage-1", checkpoint="cp",
        boot_id="5e000000-0000-4000-8000-000000000001",
        collections={"pools": CollectionSnapshot(
            name="pools", generation=3, freshness="current",
            stale_reason=None,
            objects=({"id": "pools:tank", "name": "tank", "instance": None,
                      "facts": {"State": "degraded"}},))},
        declarations=("sha256:x",), history_gap=None),
        at="2026-08-23T11:58:00Z")
    intent = intent_for()
    return estate, (lambda: reading(estate, intent, declarations))


def test_the_site_answer_carries_the_rows_and_the_origin_age() -> None:
    """The sibling's answer is rendered by the SAME functions the local
    surface uses, and age_at_origin_s is the sibling's own measurement —
    None where nothing stamped the arrival, never zero."""
    from system_explorer.hub.federation import site_answer

    estate, view_of = _site_b_state()
    answer = site_answer(view_of, "site-b", estate.told_at,
                         lambda: "2026-08-23T12:00:00Z")
    body = answer(SiblingRequest(origin_site="site-a", for_site="site-b"))
    assert body["site"] == "site-b"
    assert body["hosts"] == {"storage-1": "connected"}
    assert [row["id"] for row in body["objects"]] == ["storage-1/pools:tank"]
    assert body["age_at_origin_s"] == {"storage-1": 120.0}


def test_an_unstamped_arrival_serves_an_unstated_age() -> None:
    from system_explorer.hub.checkpoint import Estate
    from system_explorer.hub.federation import site_answer

    estate, view_of = _site_b_state()
    bare = Estate(declared=("storage-1",))
    answer = site_answer(view_of, "site-b", bare.told_at,
                         lambda: "2026-08-23T12:00:00Z")
    body = answer(SiblingRequest(origin_site="site-a", for_site="site-b"))
    assert body["age_at_origin_s"] == {"storage-1": None}, (
        "an unstamped arrival is an unstated age, never a zero standing in "
        "for a measurement nobody took"
    )


def test_sibling_reads_reach_the_surface_with_both_ages() -> None:
    """End to end: hub A's /v1/sites/site-b asks hub B live over a peer
    session — one hop, nothing stored — and the response carries both
    ages: the sibling's own per-host measurement, and the transit moments
    only this hub can stamp."""
    import json as _json
    import socket as _socket
    import threading
    import urllib.request

    from system_explorer.hub.federation import site_answer, surface_reader
    from system_explorer.hub.http import serve as http_serve

    intent = intent_for()
    estate_b, view_of_b = _site_b_state()
    answer_b = site_answer(view_of_b, "site-b", estate_b.told_at,
                           lambda: "2026-08-23T12:00:00Z")

    def connect():
        a, b = _socket.socketpair()
        threading.Thread(
            target=peer_session,
            args=(b.makefile("rb"), b.makefile("wb"),
                  offer("site-b", intent), "site-b", answer_b),
            daemon=True).start()
        return a.makefile("rb"), a.makefile("wb")

    sibling_of = surface_reader(connect, offer("site-a", intent),
                                lambda: "2026-08-23T12:00:01Z")

    estate_a, view_of_a = _site_b_state()
    server = http_serve(("127.0.0.1", 0), view_of_a, sibling_of=sibling_of)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        body = _json.loads(urllib.request.urlopen(
            f"{base}/v1/sites/site-b", timeout=10).read())
        assert body["origin"] == "site-b"
        assert body["asked_at"] == "2026-08-23T12:00:01Z"
        assert body["answer"]["site"] == "site-b"
        assert body["answer"]["age_at_origin_s"] == {"storage-1": 120.0}, (
            "the sibling's measurement, carried verbatim"
        )
        assert [row["id"] for row in body["answer"]["objects"]] == ["storage-1/pools:tank"]
    finally:
        server.shutdown()


def test_a_mismatched_sibling_surfaces_its_refusal_not_a_500() -> None:
    import json as _json
    import socket as _socket
    import threading
    import urllib.request

    from system_explorer.hub.federation import site_answer, surface_reader
    from system_explorer.hub.http import serve as http_serve

    estate_b, view_of_b = _site_b_state()
    answer_b = site_answer(view_of_b, "site-b", estate_b.told_at,
                           lambda: "2026-08-23T12:00:00Z")

    def connect():
        a, b = _socket.socketpair()
        threading.Thread(
            target=peer_session,
            args=(b.makefile("rb"), b.makefile("wb"),
                  offer("site-b", intent_for(42)), "site-b", answer_b),
            daemon=True).start()
        return a.makefile("rb"), a.makefile("wb")

    sibling_of = surface_reader(connect, offer("site-a", intent_for(41)),
                                lambda: "2026-08-23T12:00:01Z")
    estate_a, view_of_a = _site_b_state()
    server = http_serve(("127.0.0.1", 0), view_of_a, sibling_of=sibling_of)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        body = _json.loads(urllib.request.urlopen(
            f"{base}/v1/sites/site-b", timeout=10).read())
        assert body["error"] == "intent-mismatch"
        assert "41" not in body["error"]
        assert "site-b" == body["site"]
        assert "the sibling holds" in body["detail"], (
            "the refusal an operator can act on names both values"
        )
    finally:
        server.shutdown()
