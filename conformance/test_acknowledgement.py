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
