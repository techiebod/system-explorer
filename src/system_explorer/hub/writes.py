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
    refused — never an open door. The distinction between "no credential
    was presented" and "this hub accepts no writes" is kept in the
    refusal text, because they need different fixes.
    """

    by_token: dict[str, str]

    def identify(self, token: str) -> str | None:
        """The actor a token names, compared in constant time.

        `hmac.compare_digest` over every candidate rather than a dict
        lookup: a dict lookup's timing is a function of the token, and an
        unauthenticated socket is exactly where that is measurable.
        """
        found: str | None = None
        for candidate, actor in self.by_token.items():
            if hmac.compare_digest(candidate, token):
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
        # Unreadable is not unconfigured, and it must not become an open
        # door NOR a silent closed one: no actor is identified, and the
        # refusal below says the credential could not be read.
        return Actors(by_token={})


def handler_class(log: Log,
                  now_of: Callable[[], str],
                  actors: Actors | None = None) -> type[BaseHTTPRequestHandler]:
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

        def _send(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _actor(self) -> str | None:
            header = self.headers.get("Authorization", "")
            scheme, _, token = header.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                return None
            return identities.identify(token.strip())

        def do_POST(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != TRANSITIONS_PATH:
                self._send(404, {"error": "no such route",
                                 "detail": f"this listener answers {TRANSITIONS_PATH} "
                                           "and nothing else"})
                return
            if not identities.configured():
                # Deny by default, and say which of the two states this
                # is: an operator whose credential file is missing needs
                # a different fix from one who never meant to accept
                # writes at all.
                self._send(503, {
                    "error": "no-actors-configured",
                    "detail": "this hub accepts no transitions: no credential "
                              "naming an actor was readable, and a write plane "
                              "that opens itself when unconfigured is not one"})
                return
            actor = self._actor()
            if actor is None:
                self._send(401, {
                    "error": "unattributed",
                    "detail": "a transition carries the actor who made it, and "
                              "the actor comes from the credential rather than "
                              "the request — a self-declared actor is a claim"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self._send(413, {"error": "body-bounds",
                                 "detail": f"a transition body is at most {MAX_BODY} bytes"})
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
                log.append(transition)
            except TransitionRefused as refusal:
                self._send(422, {"error": refusal.reason, "detail": refusal.detail})
                return
            # The appended record back, so a caller sees exactly what was
            # stored — including the actor it did not choose and the
            # stamp it did not set.
            self._send(201, {"recorded": transition.as_wire()})

        def _refuse_read(self) -> None:
            self._send(405, {
                "error": "this listener is write-only",
                "detail": "findings and their acknowledgement state are on the "
                          "read surface; this socket exists so that surface can "
                          "stay read-only"})

        # Symmetric to http.py's refusal, and for the same reason: named
        # rather than defaulted, because 501 is what a caller gets from a
        # handler that simply has no method, and 405 with a stated reason
        # is what an operator can act on.
        do_GET = do_HEAD = do_PUT = do_PATCH = do_DELETE = _refuse_read

    return Handler


def serve(bind: tuple[str, int], log: Log, now_of: Callable[[], str],
          actors: Actors | None = None) -> ThreadingHTTPServer:
    """A listener of its own. The caller supplies the bind, and that is
    the point: nothing here defaults to the read surface's."""
    return ThreadingHTTPServer(bind, handler_class(log, now_of, actors))
