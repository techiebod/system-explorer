"""The write listener: one route, its own socket (DESIGN 06, ruled 2026-08-23).

**Why this is not a route on the read surface.** The hub's read surface
binds where it does purely on the strength of being read-only, and
`http.py` holds that structurally — only GET is routed, and every other
method is refused by the handler rather than by a policy somebody could
relax. A write verb answering on that socket repeals the property the
bind rests on, whatever the route's own authorization does. So the write
plane is a second listener, and how far it is exposed is a deployment
statement made per site rather than one inherited from the read bind.

The two listeners refuse each other's methods symmetrically, which is
what makes the split legible from either side: GET here is refused with
a pointer to the read surface, exactly as POST there is refused as
read-only.

**Attribution is why the separate door is worth having.** A transition
must name who made it, and an actor taken from the request body is a
claim rather than an attribution — the two would be indistinguishable
once stored. So the actor is established HERE, from a credential the
deployment supplies, and the body cannot influence it. A token that maps
to no actor is refused; a listener with no credentials configured refuses
every write, because a write plane that opens itself when unconfigured is
the failure mode of every write plane that has ever opened itself.

**What this does not do.** The transition annotates hub metadata and
reaches no operating-system write path, so §01's property — no component
here writes to the system — survives literally, and the collator still
reports the underlying condition whatever the hub was told about it. The
actuator's posture is a separate and larger question that this listener
does not pre-empt.
"""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .transitions import Log, Transition, TransitionRefused

#: The one path this listener answers. Named as a constant because the
#: read surface's route table must never grow it — a test asserts exactly
#: that, and it needs something to compare against.
TRANSITIONS_PATH = "/v1/findings/transitions"

#: A body larger than this is refused unread. The route carries a finding
#: key, a verb and an operator's note; nothing legitimate approaches it,
#: and reading an unbounded body from an unauthenticated socket is how a
#: listener becomes a memory exhaustion.
MAX_BODY = 8192


@dataclass(frozen=True)
class Actors:
    """Token to actor name, as the deployment supplied it.

    Empty means unconfigured, and unconfigured means every write is
    refused — never an open door.

    `unreadable` carries the path of a credential document that exists
    and could not be read, because "the credential is there and I cannot
    read it" and "this hub was never meant to accept writes" need
    different fixes and rendered identically until 2026-08-23. Both
    refuse; only one is a deployment fault. A comment claimed the
    distinction was made and the code did not make it, which is the
    over-claim this repository warns about twice — found by an audit of
    this module the day it was written.
    """

    by_token: dict[str, str]
    #: The credential document that exists and could not be read, if any.
    unreadable: str = ""

    def identify(self, token: str) -> str | None:
        """The actor a token names, compared in constant time.

        `hmac.compare_digest` over every candidate rather than a dict
        lookup: a dict lookup's timing is a function of the token, and an
        unauthenticated socket is exactly where that is measurable.

        Compared as BYTES, and that is not a detail. `compare_digest`
        raises TypeError on a str carrying non-ASCII, and
        BaseHTTPRequestHandler decodes headers as latin-1 — so one header
        byte from any unauthenticated client reached this line and killed
        the request before any credential check, with no response at all.
        Found by an audit of this module on 2026-08-23.
        """
        try:
            presented = token.encode("utf-8")
        except (UnicodeEncodeError, AttributeError):
            return None
        found: str | None = None
        for candidate, actor in self.by_token.items():
            if hmac.compare_digest(candidate.encode("utf-8"), presented):
                found = actor
        return found

    def configured(self) -> bool:
        return bool(self.by_token)


def actors_from(text: str) -> Actors:
    """Parse the credential document: one `token actor` pair per line.

    Whitespace-separated rather than `=`-separated because an actor name
    is a person's name and a token is opaque, and neither should have to
    be escaped. Blank lines and `#` comments are skipped so a deployment
    can annotate who holds what.
    """
    pairs: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        token, actor = parts
        pairs[token] = actor.strip()
    return Actors(by_token=pairs)


def deployed_actors() -> Actors:
    """The environmental default: a credential file.

    A FILE and never an environment variable, because a token in the
    environment is readable from `/proc` by anything that can see the
    process. Under socket activation systemd holds the credential and
    puts it in `$CREDENTIALS_DIRECTORY`, which is the arrangement
    COLLECTOR-DEPLOYMENT becomes input to.
    """
    path = os.environ.get("SE_TRANSITION_ACTORS_FILE")
    if not path:
        credentials = os.environ.get("CREDENTIALS_DIRECTORY")
        if credentials:
            candidate = Path(credentials) / "transition-actors"
            if candidate.exists():
                path = str(candidate)
    if not path:
        return Actors(by_token={})
    try:
        return actors_from(Path(path).read_text(encoding="utf-8"))
    except OSError:
        # Unreadable is not unconfigured, and it must become neither an
        # open door nor a silent closed one. It refuses like an
        # unconfigured hub and SAYS which of the two it is, because a
        # chmod or a systemd credential that failed to materialise
        # otherwise presents as a deliberate posture — unobservable and
        # healthy rendering the same, in the write plane.
        return Actors(by_token={}, unreadable=path)


def handler_class(log: Log,
                  now_of: Callable[[], str],
                  actors: Actors | None = None,
                  derived_of: Callable[[], list[str]] | None = None) -> type[BaseHTTPRequestHandler]:
    """`derived_of` returns the findings the estate currently holds.

    A transition attaches to a finding the estate has actually derived,
    never to a speculative identity: an acknowledgement filed against one
    nobody has observed would sit in the log waiting to silence that
    condition's first occurrence. The superseded implementation held this
    by making its INSERT conditional on the finding existing; passing
    None here skips the check, which is a test's shape and never a
    deployment's.
    """
    identities = actors if actors is not None else deployed_actors()

    class Handler(BaseHTTPRequestHandler):
        server_version = "se-hub-writes"
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: Any) -> None:  # noqa: D102
            # The transition log is the record of what happened here, and
            # it is attributed. A second, unattributed, unrotated copy in
            # the journal is not an audit trail, it is host names
            # accumulating somewhere nobody prunes.
            return

        def _send(self, code: int, payload: dict[str, Any],
                  body_unread: bool = False) -> None:
            """One response. A refusal that did not read the request body
            CLOSES the connection.

            **This is request smuggling if it does not.** protocol_version
            is HTTP/1.1, so the socket stays open, and every refusal path
            returned before touching rfile — so the unread body was then
            parsed as the next request on the same connection. Reproduced
            on 2026-08-23: one POST with a wrong bearer token, whose body
            was itself a well-formed POST with a valid one, drew a 401
            followed by a 201 and wrote an attributed transition. Behind
            any proxy that pools upstream connections that is also
            response-queue poisoning, on the one listener in the product
            that accepts credentials — and it defeats the property the
            separate door exists to buy, because a record can be
            attributed to the token that arrived on a desynced connection
            rather than the one that sent the request.

            Closing rather than draining is deliberate: draining means
            reading a body this handler has already decided not to trust,
            in whatever length it claims.
            """
            body = json.dumps(payload).encode()
            if body_unread:
                self.close_connection = True
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if body_unread:
                self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _actor(self) -> str | None:
            header = self.headers.get("Authorization", "")
            scheme, _, token = header.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                return None
            return identities.identify(token.strip())

        def do_POST(self) -> None:  # noqa: N802
            try:
                self._transition()
            except Exception as exc:  # noqa: BLE001
                # The TYPE, never the message — acceptance item 11, the
                # same posture http.py holds on the read surface. Without
                # this the caller got a closed connection and could not
                # tell "refused" from "stored" from "the store is broken",
                # on the one tier whose whole job is a durable attributed
                # record. An operator who cannot tell those apart cannot
                # know whether to retry, and a retry after a partial
                # failure is how the log stops being the record it claims
                # to be.
                self._send(500, {"error": type(exc).__name__,
                                 "detail": "this listener failed while "
                                           "recording; the transition may not "
                                           "have been stored"},
                           body_unread=True)

        def _transition(self) -> None:
            if self.path.split("?", 1)[0] != TRANSITIONS_PATH:
                self._send(404, {"error": "no such route",
                                 "detail": f"this listener answers {TRANSITIONS_PATH} "
                                           "and nothing else"}, body_unread=True)
                return
            if not identities.configured():
                # Deny by default, and say which of the two states this
                # is: an operator whose credential file is missing needs
                # a different fix from one who never meant to accept
                # writes at all.
                if identities.unreadable:
                    # A deployment fault, and it must not present as a
                    # deliberate posture: a chmod or a systemd credential
                    # that failed to materialise renders identically to
                    # "this hub was never meant to accept writes"
                    # otherwise, which is unobservable and healthy
                    # rendering the same, one tier down.
                    self._send(503, {
                        "error": "credential-unreadable",
                        "detail": "a credential document is configured for this "
                                  "listener and could not be read, so no actor "
                                  "can be established; this is a deployment "
                                  "fault rather than a hub that accepts no "
                                  "writes, and the two need different fixes"},
                        body_unread=True)
                    return
                self._send(503, {
                    "error": "no-actors-configured",
                    "detail": "this hub accepts no transitions: no credential "
                              "naming an actor was configured, and a write plane "
                              "that opens itself when unconfigured is not one"},
                    body_unread=True)
                return
            actor = self._actor()
            if actor is None:
                self._send(401, {
                    "error": "unattributed",
                    "detail": "a transition carries the actor who made it, and "
                              "the actor comes from the credential rather than "
                              "the request — a self-declared actor is a claim"},
                    body_unread=True)
                return
            if self.headers.get("Transfer-Encoding") is not None:
                # Refused on PRESENCE, not on a value.
                #
                # This tested `== "chunked"` for a few hours on
                # 2026-08-23, and that was the smuggling defect it was
                # written to close, still open one spelling over: RFC
                # 9112 permits a coding LIST, so `Transfer-Encoding:
                # gzip, chunked` missed the branch, fell through to a
                # Content-Length of 0, and the unread body was parsed as
                # the next request — reproduced, with a transition
                # recorded under a DIFFERENT actor's token than the one
                # the request presented. `chunked, gzip`, a trailing
                # space and a duplicate header did the same.
                #
                # The guard could not see it because it sent the one
                # spelling the code tested. Presence is the honest test:
                # this handler decodes NO transfer coding, so any of them
                # means a body it cannot read.
                self._send(411, {
                    "error": "length-required",
                    "detail": "this listener decodes no transfer coding; send "
                              "a transition with a Content-Length and no "
                              "Transfer-Encoding"},
                    body_unread=True)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self._send(413, {"error": "body-bounds",
                                 "detail": f"a transition body is at most {MAX_BODY} bytes"},
                           body_unread=True)
                return
            try:
                document = json.loads(self.rfile.read(length) or b"{}")
            except (json.JSONDecodeError, ValueError):
                self._send(400, {"error": "unparseable",
                                 "detail": "the body is not a JSON document"})
                return
            if not isinstance(document, dict):
                self._send(400, {"error": "unparseable",
                                 "detail": "the body is not a JSON object"})
                return
            if "actor" in document:
                # Refused rather than ignored: a caller who sent an actor
                # believes they set one, and silently substituting the
                # credential's would attribute a record to somebody who
                # did not know they were making it.
                self._send(400, {
                    "error": "actor-not-yours",
                    "detail": "the actor is established from the credential and "
                              "may not be supplied; remove it rather than have "
                              "this record attributed to a name you chose"})
                return
            transition = Transition(
                finding=str(document.get("finding", "")),
                action=str(document.get("action", "")),
                actor=actor,
                at=now_of(),
                note=str(document.get("note", "")))
            try:
                log.append(transition,
                           derived=derived_of() if derived_of else None)
            except TransitionRefused as refusal:
                self._send(422, {"error": refusal.reason, "detail": refusal.detail})
                return
            # The appended record back, so a caller sees exactly what was
            # stored — including the actor it did not choose and the
            # stamp it did not set.
            self._send(201, {"recorded": transition.as_wire()})

        def do_HEAD(self) -> None:  # noqa: N802
            # A 405 with no body: a HEAD carrying one desyncs any client
            # that obeys RFC 9110 and does not read it, which on a
            # keep-alive socket is the same class of defect as the
            # smuggling above.
            self.close_connection = True
            self.send_response(405)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        def _refuse_read(self) -> None:
            self._send(405, {
                "error": "this listener is write-only",
                "detail": "findings and their acknowledgement state are on the "
                          "read surface; this socket exists so that surface can "
                          "stay read-only"}, body_unread=True)

        # Symmetric to http.py's refusal, and for the same reason: named
        # rather than defaulted, because 501 is what a caller gets from a
        # handler that simply has no method, and 405 with a stated reason
        # is what an operator can act on.
        do_GET = do_PUT = do_PATCH = do_DELETE = _refuse_read

    return Handler


def serve(bind: tuple[str, int], log: Log, now_of: Callable[[], str],
          actors: Actors | None = None,
          derived_of: Callable[[], list[str]] | None = None) -> ThreadingHTTPServer:
    """A listener of its own. The caller supplies the bind, and that is
    the point: nothing here defaults to the read surface's."""
    return ThreadingHTTPServer(bind,
                               handler_class(log, now_of, actors, derived_of))
