"""The rewrite hub as a process (DESIGN §06, §07).

**Nothing served this tier until 2026-08-23.** `se-hub` runs the shipping
product's FastAPI app; the rewrite's routes, federation, views,
acknowledgement and lifecycle existed only under test. R3's own record
listed three things as unwired — no daemon binds the write listener, none
wires the lifecycle store path, none holds a sibling session — and an
audit found the larger fact underneath them: the three gaps presupposed a
daemon that did not exist. A tier proven only by its tests is a tier
whose wiring is proven by nothing, and every one of the defects that
audit found in this hub was in code the tests exercised and no process
ever ran.

**Two listeners, and that is the ruling rather than a preference.** The
read surface binds where a deployment puts it on the strength of being
read-only, which `http.py` holds structurally — only GET is routed. The
write plane answers on a socket of its own, so that licence stays
literally true and how far the write door is exposed is a deployment
statement made per site. This module never gives them one bind.

**And it ACCEPTS collator sessions, which is what gives it an estate at
all.** The first version of this daemon bound two listeners over an
Estate nothing could populate: no session listener, and nothing anywhere
in `src/` called `Registry.fold` — so `/v1/hosts` answered `{}`,
`/v1/acknowledgements` answered `{}`, and a well-formed acknowledgement
with a valid credential was refused `no-such-finding`, because the
derived set it is checked against is the registry's open set and the
registry was never written. Every test that got past it called
`registry.fold` from OUTSIDE the process, which is testing a copy of
what the daemon should do rather than the daemon.

**What persists is metadata, never an observation.** The findings
registry and the transition log are the hub's own record of what it
decided and what somebody said about it; the estate view is computed per
request from what hosts told this hub, and a remembered one would be
last-known-good in the one place the design forbids it.
"""

from __future__ import annotations

import os
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import http as read_surface
from . import writes as write_surface
from .checkpoint import Estate, HostSnapshot
from .intent import Intent
from .lifecycle import Key, Registry
from .listener import serve as serve_session
from .resolution import Contributor
from .rollup import opinions as held_opinions
from .session import Declarations
from .transitions import Log, render


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _state_dir() -> Path:
    """Where the hub keeps its metadata.

    $STATE_DIRECTORY is systemd's, and it is the one this deployment
    should use: the unit declares StateDirectory= and systemd creates it
    with the right owner before the process starts. The fallback exists
    so the daemon is runnable by hand on a laptop, which is how anybody
    reviews it.
    """
    configured = os.environ.get("SE_HUB_STATE_DIR") or os.environ.get("STATE_DIRECTORY")
    if configured:
        return Path(configured.split(":")[0])
    return Path.home() / ".local" / "state" / "se-hub"


def _load_intent(site: str) -> Intent:
    """The estate's account of what should be true, or the empty one.

    A deployment with no intent is a real and ordinary state — every
    intrinsic opinion and every default policy still holds, and only the
    intent-relative half is missing, which law 5 says the surface must
    state rather than read green. An unreadable or invalid document is
    NOT that state: it is refused loudly, because running on a document
    this hub could not parse would judge the estate against a purpose
    nobody stated.
    """
    path = os.environ.get("SE_INTENT_FILE")
    if not path:
        return Intent.load({
            "schema": "se.intent/1",
            "estate": site,
            "revision": 0,
            "reviewed": "",
            "membership": {"hosts": []},
        })
    import json
    return Intent.load(json.loads(Path(path).read_text(encoding="utf-8")))


class Hub:
    """One site's hub: the estate it has been told about, the metadata it
    keeps, and the two listeners."""

    def __init__(self, site: str | None = None, state_dir: Path | None = None) -> None:
        self.site = site or os.environ.get("SE_SITE", "")
        self.state = state_dir or _state_dir()
        self.state.mkdir(parents=True, exist_ok=True)

        declared = tuple(
            name.strip() for name in os.environ.get("SE_DECLARED_HOSTS", "").split(",")
            if name.strip())
        self.estate = Estate(declared=declared)
        self.declarations = Declarations()
        # Intent is loaded from a document or it is the empty estate —
        # never half-read, because a hub running on a half-read intent
        # would judge the estate against a purpose nobody stated.
        self.intent = _load_intent(self.site)

        # The transition log FIRST: the registry is told about it, so a
        # resolution it observes reaches the log and an acknowledgement
        # cannot outlive the finding it acted on.
        #: The accepting socket, once serve() has bound one. Held so a
        #: caller can report the port it landed on and close it.
        self.sessions: Any = None
        self.transitions = Log(store=self.state / "transitions.db")
        self.registry = Registry(
            reset_at=_now(),
            store=self.state / "findings.db",
            transitions=self.transitions,
        )

    # --- what a collator session drives -----------------------------

    def promoted(self, snapshot: HostSnapshot) -> None:
        """One host's checkpoint landed, so the estate is re-judged.

        The fold is HERE rather than on a timer: a finding's lifecycle is
        keyed to what hosts have told this hub, and folding on a clock
        would age findings against a schedule rather than against
        observation. Every promote is a re-read of that host, which is
        exactly what `judge` needs to tell a resolved finding from an
        unswept one.
        """
        self.fold()

    def fold(self) -> dict[str, object]:
        """Re-judge the estate and return the open findings.

        A finding is an opinion at warn or above WITH a lifecycle, so the
        derived set comes from the opinions the hub currently holds —
        filtered to the levels that carry one, because an info opinion is
        not a finding and giving it a lifecycle would put every
        observation in the registry.
        """
        derived: dict[Key, list[Contributor]] = {}
        for opinion in held_opinions(self.estate, self.declarations):
            if opinion.level not in ("warn", "critical"):
                continue
            key = Key(scope=opinion.host, object_id=opinion.object_id,
                      opinion=opinion.key, instance=opinion.instance)
            derived.setdefault(key, []).append(Contributor(
                host=opinion.host, collection=opinion.collection,
                generation=opinion.generation))
        return self.registry.fold(_now(), derived, self.estate)

    # --- what the surfaces read -------------------------------------

    def reading(self) -> read_surface.State:
        """One consistent reading of the estate, computed per request."""
        return read_surface.reading(self.estate, self.intent, self.declarations)

    def acknowledgements(self) -> dict[str, Any]:
        """The acknowledgement state of every finding the hub holds.

        Folded from the log over the registry's OPEN set, which is what
        makes /v1/acknowledgements a producer rather than an empty
        mapping — and what stops it reporting an acknowledgement for a
        finding the estate no longer derives.
        """
        return render(self.transitions.fold(self.registry.open()))

    def derived(self) -> list[str]:
        """The findings a transition may attach to. A transition filed
        against an identity nobody has observed would sit in the log
        waiting to silence that condition's first occurrence."""
        return list(self.registry.open())


def accept_sessions(listener, hub: "Hub") -> None:
    """Serve collator sessions until the socket closes.

    One connection at a time and each in full: a checkpoint is promoted
    or refused as a unit, and a refusal ends that connection and is
    RETURNED rather than raised — one collator getting the protocol wrong
    must not take the estate view down with it.
    """
    while True:
        try:
            connection, _peer = listener.accept()
        except OSError:
            return
        try:
            with connection, connection.makefile("rb") as stream:
                serve_session(stream, hub.estate, hub.declarations,
                              on_promote=hub.promoted)
        except Exception:  # noqa: BLE001
            # A session that dies takes its own connection and nothing
            # else. The host is left marked disconnected by the listener,
            # which is `unswept` rather than a session that looks open
            # for ever.
            continue


def serve(read_bind: tuple[str, int] | None = None,
          write_bind: tuple[str, int] | None = None,
          hub: Hub | None = None,
          session_bind: tuple[str, int] | None = None) -> tuple[Any, Any, Hub]:
    """Bind both listeners and return them with the hub, unstarted.

    Returned rather than started so a caller — a test, or `main` — owns
    the threads. The write listener is None where no bind is configured,
    which is a deployment that reads and does not accept transitions: a
    complete deployment, not a degraded one.
    """
    site = hub or Hub()

    read_bind = read_bind or (
        os.environ.get("SE_HUB_HOST", "127.0.0.1"),
        int(os.environ.get("SE_HUB_PORT", "8096")))
    read = read_surface.serve(read_bind, site.reading, acks_of=site.acknowledgements)

    # The session listener. Without it the hub serves an estate nothing
    # can populate — which is what it did until 2026-08-23: two listeners
    # over an empty Estate, every acknowledgement refused `no-such-finding`
    # because the derived set is the registry's open set and nothing ever
    # folded it.
    sessions = None
    configured_sessions = os.environ.get("SE_HUB_SESSION_PORT")
    if session_bind or configured_sessions:
        session_bind = session_bind or (
            os.environ.get("SE_HUB_SESSION_HOST", "127.0.0.1"),
            int(configured_sessions or "0"))
        sessions = socket.create_server(session_bind)
        threading.Thread(target=accept_sessions, args=(sessions, site),
                         daemon=True).start()

    write = None
    configured_write = os.environ.get("SE_HUB_WRITE_PORT")
    if write_bind or configured_write:
        write_bind = write_bind or (
            os.environ.get("SE_HUB_WRITE_HOST", "127.0.0.1"),
            int(configured_write or "0"))
        write = write_surface.serve(write_bind, site.transitions, _now,
                                    derived_of=site.derived)
    site.sessions = sessions
    return read, write, site


def main() -> None:
    """The console entry point.

    Named `se-hub-next` while the shipping hub still owns `se-hub`. The
    cut is a big bang (DESIGN §06) and this name retires at it — a
    temporary name is honest about a temporary state, where reusing
    `se-hub` now would make which product is running depend on which
    package was installed last.
    """
    read, write, site = serve()
    print(f"se-hub-next: site={site.site or '(unnamed)'} "
          f"state={site.state} read=http://{read.server_address[0]}:"
          f"{read.server_address[1]}")
    if site.sessions is not None:
        print(f"se-hub-next: collators dial "
              f"{site.sessions.getsockname()[0]}:{site.sessions.getsockname()[1]}")
    else:
        print("se-hub-next: no session listener; set SE_HUB_SESSION_PORT so "
              "collators can reach this hub — without one it serves an "
              "estate nothing can populate")
    if write is not None:
        print(f"se-hub-next: write listener on "
              f"http://{write.server_address[0]}:{write.server_address[1]} "
              f"— a separate bind, so the read surface stays read-only")
    else:
        print("se-hub-next: no write listener; set SE_HUB_WRITE_PORT to "
              "accept acknowledgements")
    if write is not None:
        threading.Thread(target=write.serve_forever, daemon=True).start()
    read.serve_forever()
