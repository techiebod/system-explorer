"""Acknowledgement: the product's first write, and the four clauses it was
ruled on (DESIGN 06, 2026-08-23).

Each clause is one test, because each closes a different way this goes
wrong, and a single "it works" would pass with three of them broken:

1. **appended** — a transition never overwrites its predecessor, so "who
   silenced this, and when" has an answer for every actor rather than the
   most recent one;
2. **attributed** — an actor is established from a credential, and a body
   that supplies one is refused rather than quietly overridden;
3. **reversible** — un-acknowledging appends, so the log still shows that
   somebody acknowledged and changed their mind;
4. **never removes** — an acknowledged finding stays in every body it was
   in, because acknowledgement changes what is shouted rather than what
   is known.

And a fifth that is the reason the listener exists at all: the read
surface is still structurally read-only, and the write surface still
refuses reads.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from system_explorer.hub import writes
from system_explorer.hub.routes import table
from system_explorer.hub.transitions import (
    ACKNOWLEDGE,
    UNACKNOWLEDGE,
    Log,
    Transition,
    TransitionRefused,
)

FINDING = "storage-1/pool:tank/zfs-degraded"


def at(seconds: int) -> str:
    return f"2026-08-23T10:{seconds:02d}:00Z"


# --- the log itself ---------------------------------------------------

def test_a_transition_is_appended_never_overwritten(tmp_path) -> None:
    log = Log(store=tmp_path / "t.db")
    log.append(Transition(FINDING, ACKNOWLEDGE, "ada", at(1), "disk on order"))
    log.append(Transition(FINDING, UNACKNOWLEDGE, "grace", at(2), "still bad"))
    log.append(Transition(FINDING, ACKNOWLEDGE, "ada", at(3), "replacing Friday"))

    history = log.history(FINDING)
    assert [t.actor for t in history] == ["ada", "grace", "ada"]
    assert [t.action for t in history] == [ACKNOWLEDGE, UNACKNOWLEDGE, ACKNOWLEDGE]
    # The middle record is the one an overwriting store would have lost,
    # and it is the one that answers "why is this loud again".
    assert history[1].note == "still bad"


def test_the_state_is_folded_from_the_log_not_stored(tmp_path) -> None:
    log = Log(store=tmp_path / "t.db")
    log.append(Transition(FINDING, ACKNOWLEDGE, "ada", at(1)))
    log.append(Transition(FINDING, UNACKNOWLEDGE, "grace", at(2)))

    folded = log.fold([FINDING])[FINDING]
    assert folded.acknowledged is False
    assert folded.by == "grace"
    # Four transitions and one are different things, and a surface
    # showing only the current state could not tell them apart.
    assert folded.transitions == 2


def test_ordering_is_the_sequence_not_the_stamp(tmp_path) -> None:
    """The later APPEND wins, even carrying the earlier stamp.

    Written this way because the obvious case does not discriminate:
    two transitions inside one second are ordinary — acknowledging a
    page of findings produces them — but with equal stamps a fold
    ordered by stamp and one ordered by sequence agree, so asserting
    that case would report success about a property it never tested.
    Proven on 2026-08-23 by planting `ORDER BY at` and watching the
    same-second version stay green.

    A stamp can legitimately go backwards — a clock correction, an
    operator's note stamped by a different source — and when it does,
    what happened is still what happened in the order it happened.
    """
    log = Log(store=tmp_path / "t.db")
    log.append(Transition(FINDING, ACKNOWLEDGE, "ada", at(9)))
    log.append(Transition(FINDING, UNACKNOWLEDGE, "grace", at(3)))
    assert log.fold([FINDING])[FINDING].acknowledged is False
    assert log.fold([FINDING])[FINDING].by == "grace"

    # And the ordinary same-second case, which agrees under either rule
    # and is here as a regression rather than as the discriminator.
    log.append(Transition(FINDING, ACKNOWLEDGE, "ada", at(3)))
    assert log.fold([FINDING])[FINDING].acknowledged is True


def test_a_finding_with_no_transitions_is_stated_not_absent(tmp_path) -> None:
    # An absent key and an un-acknowledged finding render the same at a
    # careless caller, which is this product's founding error in
    # miniature.
    log = Log(store=tmp_path / "t.db")
    folded = log.fold([FINDING, "storage-1/pool:vol/zfs-degraded"])
    assert set(folded) == {FINDING, "storage-1/pool:vol/zfs-degraded"}
    assert all(a.acknowledged is False and a.transitions == 0
               for a in folded.values())


def test_an_unattributed_transition_is_refused(tmp_path) -> None:
    log = Log(store=tmp_path / "t.db")
    with pytest.raises(TransitionRefused) as refusal:
        log.append(Transition(FINDING, ACKNOWLEDGE, "  ", at(1)))
    assert refusal.value.reason == "unattributed"
    assert log.all() == ()


def test_resolution_cannot_be_declared(tmp_path) -> None:
    # Resolution is OBSERVED — a source that could look stopped deriving
    # the finding. A route that let an operator declare it would be the
    # one write that makes the product lie about the system rather than
    # about its own noise.
    log = Log(store=tmp_path / "t.db")
    with pytest.raises(TransitionRefused) as refusal:
        log.append(Transition(FINDING, "resolve", "ada", at(1)))
    assert refusal.value.reason == "unknown-action"


def test_the_log_survives_a_restart(tmp_path) -> None:
    store = tmp_path / "t.db"
    Log(store=store).append(Transition(FINDING, ACKNOWLEDGE, "ada", at(1), "seen"))
    reopened = Log(store=store)
    assert reopened.fold([FINDING])[FINDING].by == "ada"
    assert reopened.fold([FINDING])[FINDING].note == "seen"


# --- the surfaces -----------------------------------------------------

def test_the_read_surface_serves_acknowledgement_and_never_filters_on_it() -> None:
    """The clause the whole ruling exists to protect."""
    log = Log()
    log.append(Transition(FINDING, ACKNOWLEDGE, "ada", at(1)))

    class Row:
        id = "pool:tank"
        estate_scoped = False
        facts = {"State": "degraded"}
        undeclared = ()
        withheld = ()
        members = ()

    class Opinion:
        host, collection, object_id, instance = "storage-1", "pools", "pool:tank", None
        key, level, grounds = "zfs-degraded", "critical", "interface"
        sentence, cites = "the pool is degraded", ("State",)

    class View:
        rows = (Row(),)
        reach = {}

    class State:
        view = View()
        opinions = (Opinion(),)

    routes = table(lambda: State(),
                   acks_of=lambda: {"acknowledgements": {
                       key: {"acknowledged": a.acknowledged, "by": a.by,
                             "at": a.at, "note": a.note,
                             "transitions": a.transitions}
                       for key, a in log.fold([FINDING]).items()}})
    by_path = {r.path: r for r in routes}

    served = by_path["/v1/acknowledgements"].handler()
    assert served["acknowledgements"][FINDING]["acknowledged"] is True
    assert served["acknowledgements"][FINDING]["by"] == "ada"

    # And the acknowledged finding is still in every body it was in.
    assert by_path["/v1/opinions"].handler()["opinions"][0]["key"] == "zfs-degraded"
    assert by_path["/v1/objects"].handler()["objects"][0]["id"] == "pool:tank"


def test_no_write_route_ever_joins_the_read_table() -> None:
    routes = table(lambda: None)
    assert writes.TRANSITIONS_PATH not in {r.path for r in routes}


def _serve(handler_cls) -> tuple[str, object]:
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_port}", server


def _post(base: str, body: dict, token: str | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(
        base + writes.TRANSITIONS_PATH,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {token}"} if token else {})},
        method="POST")
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_the_write_listener_attributes_from_the_credential() -> None:
    log = Log()
    base, server = _serve(writes.handler_class(
        log, lambda: at(5), writes.actors_from("tok-ada ada\ntok-grace grace")))
    try:
        code, body = _post(base, {"finding": FINDING, "action": ACKNOWLEDGE},
                           token="tok-grace")
        assert code == 201, body
        # The actor is the credential's, and the caller could not have
        # chosen it: it never appeared in the request.
        assert body["recorded"]["actor"] == "grace"
        assert log.fold([FINDING])[FINDING].by == "grace"
    finally:
        server.shutdown()


def test_a_body_supplied_actor_is_refused_not_ignored() -> None:
    # Silently substituting the credential's actor would attribute a
    # record to somebody who did not know they were making it.
    log = Log()
    base, server = _serve(writes.handler_class(
        log, lambda: at(5), writes.actors_from("tok-ada ada")))
    try:
        code, body = _post(base, {"finding": FINDING, "action": ACKNOWLEDGE,
                                  "actor": "somebody-else"}, token="tok-ada")
        assert code == 400 and body["error"] == "actor-not-yours"
        assert log.all() == ()
    finally:
        server.shutdown()


def test_an_unknown_token_writes_nothing() -> None:
    log = Log()
    base, server = _serve(writes.handler_class(
        log, lambda: at(5), writes.actors_from("tok-ada ada")))
    try:
        assert _post(base, {"finding": FINDING, "action": ACKNOWLEDGE},
                     token="guessed")[0] == 401
        assert _post(base, {"finding": FINDING, "action": ACKNOWLEDGE})[0] == 401
        assert log.all() == ()
    finally:
        server.shutdown()


def test_an_unconfigured_write_plane_refuses_every_write() -> None:
    # A write plane that opens itself when unconfigured is the failure
    # mode of every write plane that has ever opened itself.
    log = Log()
    base, server = _serve(writes.handler_class(
        log, lambda: at(5), writes.actors_from("")))
    try:
        code, body = _post(base, {"finding": FINDING, "action": ACKNOWLEDGE},
                           token="anything")
        assert code == 503 and body["error"] == "no-actors-configured"
        assert log.all() == ()
    finally:
        server.shutdown()


def test_the_write_listener_refuses_reads() -> None:
    """Symmetric to the read surface's 405, and for the same reason: the
    split has to be legible from either side."""
    base, server = _serve(writes.handler_class(
        Log(), lambda: at(5), writes.actors_from("tok-ada ada")))
    try:
        with pytest.raises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(base + writes.TRANSITIONS_PATH)
        assert raised.value.code == 405
        assert json.loads(raised.value.read())["error"] == "this listener is write-only"
    finally:
        server.shutdown()


def test_the_read_surface_still_refuses_every_write_method() -> None:
    """The property the second listener exists to preserve."""
    from system_explorer.hub.http import handler_class

    handler = handler_class(lambda: None)
    for method in ("do_POST", "do_PUT", "do_PATCH", "do_DELETE"):
        assert hasattr(handler, method), method
    assert (handler.do_POST is handler.do_PUT
            is handler.do_PATCH is handler.do_DELETE)


def test_an_oversized_body_is_refused_unread() -> None:
    log = Log()
    base, server = _serve(writes.handler_class(
        log, lambda: at(5), writes.actors_from("tok-ada ada")))
    try:
        code, _ = _post(base, {"finding": FINDING, "action": ACKNOWLEDGE,
                               "note": "x" * (writes.MAX_BODY + 1)},
                        token="tok-ada")
        assert code == 413
        assert log.all() == ()
    finally:
        server.shutdown()


def test_the_credential_document_skips_comments_and_blanks() -> None:
    actors = writes.actors_from(
        "# who holds what\n\ntok-ada  ada lovelace \n\n# retired:\n")
    assert actors.identify("tok-ada") == "ada lovelace"
    assert actors.identify("nope") is None
    assert actors.configured()


# --- what an audit of this module found the day it was written -------

import socket


def _raw(port: int, request: bytes, deadline: float = 3.0) -> bytes:
    """One TCP connection, one write, read until the peer stops.

    urllib cannot see any of the defects below: it sends one
    fixed-length request per connection and reads exactly one response,
    which is the shape that made the module look correct.
    """
    sock = socket.create_connection(("127.0.0.1", port))
    sock.settimeout(deadline)
    try:
        sock.sendall(request)
        chunks = []
        try:
            while True:
                block = sock.recv(4096)
                if not block:
                    break
                chunks.append(block)
        except socket.timeout:
            pass
        return b"".join(chunks)
    finally:
        sock.close()


def _listener(log, actors="tok-ada ada"):
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        writes.handler_class(log, lambda: at(5), writes.actors_from(actors)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_a_refused_requests_body_is_never_executed_as_the_next_one() -> None:
    """Request smuggling on the one listener that accepts credentials.

    protocol_version is HTTP/1.1 so the socket stays open, and every
    refusal returned before touching rfile — so the unread body was
    parsed as the next request. Reproduced 2026-08-23: a POST with a
    wrong bearer token, whose body was itself a well-formed POST with a
    valid one, drew a 401 and then a 201 and wrote an attributed
    transition. Behind a proxy that pools upstream connections it is
    also response-queue poisoning, and it defeats attribution itself —
    a record can be attributed to the token that arrived on a desynced
    connection rather than the one that sent the request.
    """
    log = Log()
    server = _listener(log)
    try:
        smuggled = json.dumps({"finding": "SMUGGLED/o/k", "action": ACKNOWLEDGE})
        inner = (f"POST {writes.TRANSITIONS_PATH} HTTP/1.1\r\nHost: x\r\n"
                 f"Authorization: Bearer tok-ada\r\n"
                 f"Content-Length: {len(smuggled)}\r\n\r\n{smuggled}")
        outer = (f"POST {writes.TRANSITIONS_PATH} HTTP/1.1\r\nHost: x\r\n"
                 f"Authorization: Bearer WRONG\r\n"
                 f"Content-Length: {len(inner)}\r\n\r\n{inner}").encode()
        answer = _raw(server.server_port, outer)
        assert answer.count(b"HTTP/1.1") == 1, (
            "a refusal answers once and closes; a second response on the "
            f"same connection is the smuggled request executing: {answer!r}")
        assert b"401" in answer
        assert log.all() == (), "the smuggled transition must not be recorded"
    finally:
        server.shutdown()


def test_a_non_ascii_token_is_refused_rather_than_killing_the_request() -> None:
    """Reachable before any credential check, from any client, with one
    header byte: headers decode as latin-1, and hmac.compare_digest
    raises TypeError on a str carrying non-ASCII. The caller got no
    response at all."""
    log = Log()
    server = _listener(log)
    try:
        body = json.dumps({"finding": FINDING, "action": ACKNOWLEDGE})
        request = (f"POST {writes.TRANSITIONS_PATH} HTTP/1.1\r\nHost: x\r\n"
                   f"Authorization: Bearer \xe9vil\r\n"
                   f"Content-Length: {len(body)}\r\n\r\n{body}").encode("latin-1")
        answer = _raw(server.server_port, request)
        assert b"HTTP/1.1 401" in answer, (
            f"an unknown token is refused, never a dropped connection: {answer!r}")
        assert log.all() == ()
    finally:
        server.shutdown()


def test_a_chunked_body_is_refused_rather_than_read_as_empty() -> None:
    log = Log()
    server = _listener(log)
    try:
        request = (f"POST {writes.TRANSITIONS_PATH} HTTP/1.1\r\nHost: x\r\n"
                   f"Authorization: Bearer tok-ada\r\n"
                   f"Transfer-Encoding: chunked\r\n\r\n"
                   f"2d\r\n").encode()
        answer = _raw(server.server_port, request)
        assert b"411" in answer, answer
        # And no second response: the chunk-size line was parsed as a
        # request line before this fix.
        assert answer.count(b"HTTP/1.1") == 1, answer
    finally:
        server.shutdown()


def test_a_head_carries_no_body() -> None:
    server = _listener(Log())
    try:
        answer = _raw(server.server_port,
                      f"HEAD {writes.TRANSITIONS_PATH} HTTP/1.1\r\n"
                      f"Host: x\r\n\r\n".encode())
        assert b"405" in answer
        head, _, body = answer.partition(b"\r\n\r\n")
        assert body == b"", f"a HEAD with a body desyncs a conforming client: {body!r}"
    finally:
        server.shutdown()


def test_a_store_failure_answers_rather_than_dropping_the_connection(tmp_path) -> None:
    """This is the tier whose whole job is a durable attributed record.
    On a store failure the caller could not tell 'refused' from 'stored'
    from 'the store is broken' — it got nothing — and a retry after a
    partial failure is how the log stops being the record it claims to
    be."""
    class Broken(Log):
        def append(self, transition, derived=None):
            raise OSError("the store is gone")

    server = _listener(Broken())
    try:
        code, body = _post(f"http://127.0.0.1:{server.server_port}",
                           {"finding": FINDING, "action": ACKNOWLEDGE},
                           token="tok-ada")
        assert code == 500, body
        assert body["error"] == "OSError"
        # The type, never the message: acceptance item 11.
        assert "the store is gone" not in json.dumps(body)
    finally:
        server.shutdown()


def test_an_unreadable_credential_is_not_a_hub_that_accepts_no_writes(tmp_path) -> None:
    """Two comments claimed this distinction and the code did not make
    it: a chmod, or a systemd credential that failed to materialise,
    presented as a deliberate posture. Unobservable and healthy
    rendering the same, in the write plane."""
    missing = tmp_path / "nope"
    unreadable = writes.Actors(by_token={}, unreadable=str(missing))
    never = writes.actors_from("")

    from http.server import ThreadingHTTPServer
    answers = {}
    for name, actors in (("unreadable", unreadable), ("never", never)):
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            writes.handler_class(Log(), lambda: at(5), actors))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            answers[name] = _post(f"http://127.0.0.1:{server.server_port}",
                                  {"finding": FINDING, "action": ACKNOWLEDGE},
                                  token="anything")
        finally:
            server.shutdown()
    assert answers["unreadable"][0] == answers["never"][0] == 503
    assert answers["unreadable"][1]["error"] == "credential-unreadable"
    assert answers["never"][1]["error"] == "no-actors-configured"
    assert answers["unreadable"][1] != answers["never"][1], (
        "a deployment fault and a deliberate posture need different fixes")


def test_an_acknowledgement_does_not_outlive_its_findings_resolution() -> None:
    """A second disk degrading the same pool six weeks later is a NEW
    condition and must not arrive already acknowledged.

    A finding's key is scope/instance/object/opinion and carries no
    episode, so a condition that clears and returns renders the same
    string. A log keyed on that string alone hands the new occurrence an
    acknowledgement made by somebody who never saw it, with a stale note
    telling the next person it is handled — suppression created by the
    acknowledgement plane with nobody acknowledging anything, and the
    ruling's own clause ("changes what is shouted, not what is known")
    arriving inverted.

    The superseded implementation guarded the same hazard deliberately:
    findings.py's append_transition makes its INSERT conditional on the
    finding existing, and its docstring names the reason — "so a
    concurrent retention prune between them cannot leave an orphaned
    transition waiting to pre-acknowledge the identity's next
    recurrence". The rewrite dropped it; an audit found it the next day.
    """
    from system_explorer.hub.lifecycle import Key, Registry
    from system_explorer.hub.resolution import Contributor

    log = Log()
    key = Key(scope="storage-1", object_id="pool:tank", opinion="zfs-degraded")
    rendered = key.rendered()
    registry = Registry(reset_at="2026-08-01T00:00:00Z", transitions=log)

    class Estate:
        declared = ("storage-1",)

        def reach(self):
            return {}

    # Derived, then acknowledged by somebody who looked at it.
    contributor = Contributor(host="storage-1", collection="pools", generation=1)
    registry.fold("2026-08-20T10:00:00Z", {key: [contributor]}, _estate())
    log.append(Transition(rendered, ACKNOWLEDGE, "ada", "2026-08-20T10:05:00Z",
                          "known, disk on order"),
               derived=[rendered])
    assert log.fold([rendered])[rendered].acknowledged is True

    # A later generation stops deriving it: observed resolution.
    registry.fold("2026-08-21T10:00:00Z", {}, _estate(generation=2))
    assert rendered not in registry.open()

    # Six weeks later the same identity is derived again. It is a NEW
    # condition, and nobody has acknowledged it.
    registry.fold("2026-09-30T10:00:00Z",
                  {key: [Contributor(host="storage-1", collection="pools",
                                     generation=3)]},
                  _estate(generation=3))
    again = log.fold([rendered])[rendered]
    assert again.acknowledged is False, (
        "a new condition must not arrive already acknowledged, attributed to "
        "somebody who never saw it")
    assert again.by is None and again.note == "", (
        f"nobody's name and nobody's note ride onto a new condition: {again}")
    # And the history is intact: appended, never forgotten.
    actions = [t.action for t in log.history(rendered)]
    assert ACKNOWLEDGE in actions and "resolved" in actions, actions


def test_a_transition_cannot_be_filed_against_a_finding_nobody_derived() -> None:
    """Otherwise an acknowledgement sits in the log waiting to silence
    that condition's first occurrence."""
    log = Log()
    with pytest.raises(TransitionRefused) as refusal:
        log.append(Transition("storage-9/pool:never/zfs-degraded", ACKNOWLEDGE,
                              "ada", at(1)),
                   derived=["storage-1/pool:tank/zfs-degraded"])
    assert refusal.value.reason == "no-such-finding"
    assert log.all() == ()


def test_resolution_is_observed_and_cannot_be_declared() -> None:
    """The registry records what it saw. A caller that could declare it
    would be the one write that makes the product lie about the system
    rather than about its own noise."""
    log = Log()
    with pytest.raises(TransitionRefused) as refusal:
        log.append(Transition(FINDING, "resolved", "ada", at(1)))
    assert refusal.value.reason == "not-declarable"

    server = _listener(log)
    try:
        code, body = _post(f"http://127.0.0.1:{server.server_port}",
                           {"finding": FINDING, "action": "resolved"},
                           token="tok-ada")
        assert code == 422 and body["error"] == "not-declarable", body
    finally:
        server.shutdown()


def _estate(generation: int = 1):
    from system_explorer.hub.checkpoint import (
        CollectionSnapshot, Estate, HostSnapshot)
    estate = Estate(declared=("storage-1",))
    estate.promote(HostSnapshot(
        host="storage-1", checkpoint="cp",
        boot_id="5e000000-0000-4000-8000-000000000001",
        collections={"pools": CollectionSnapshot(
            name="pools", generation=generation, freshness="current",
            stale_reason=None, objects=())},
        declarations=("sha256:x",), history_gap=None))
    return estate
