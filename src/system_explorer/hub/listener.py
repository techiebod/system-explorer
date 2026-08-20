"""The hub accepts collator sessions; it never dials one (DESIGN 06).

The connection reverses in the new architecture, and the direction is the
security property: nothing dials a host, so a site's hosts expose no
inbound port at all and a hub has no way to reach a collator even if it
wanted to. The federation rules then rest on that — one hop holds by
capability rather than by URL shape.

**The trade is stated rather than discovered.** Outbound-only removes the
network as a containment layer, so the hub's identity becomes the only
thing standing between it and every host's collectors. That is why the
client identity is mutual rather than decorative: the collator presents
its own certificate and the hub presents one back, and a session with
neither is a session with an unknown machine.

**TLS is an injected seam, not a hard-coded one.** `serve` reads records
off any file-like stream, which is what lets the protocol be judged
without a certificate authority in the test path — and what stops the
protocol's own rules from being provable only where openssl exists. The
context that wraps the socket is built here and asserted separately.
"""

from __future__ import annotations

import json
import socket
import ssl
from dataclasses import dataclass
from typing import Any, Callable, Iterator

from .checkpoint import CheckpointRefused, Estate, HostSnapshot
from .session import Declarations, Session, SessionRefused


def records(stream) -> Iterator[dict[str, Any]]:
    """One decoded record per line.

    A line that will not parse ends the session rather than being
    skipped: a stream the hub has lost its place in cannot be resumed by
    guessing, and skipping is how half a checkpoint gets promoted.
    """
    for raw in stream:
        line = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as exc:
            raise SessionRefused(
                "unparseable-record",
                f"{exc}; a stream the hub has lost its place in cannot be resumed "
                "by guessing",
            ) from exc


@dataclass
class Served:
    """What one connection did, for the caller's log line."""

    host: str | None
    promoted: HostSnapshot | None
    refusal: SessionRefused | CheckpointRefused | None


def serve(
    stream,
    estate: Estate,
    declarations: Declarations,
    on_promote: Callable[[HostSnapshot], None] | None = None,
) -> Served:
    """Drive one collator session to its end.

    A refusal ends the connection and is RETURNED rather than raised: the
    caller is a loop serving other hosts, and one collator getting the
    protocol wrong must not take the estate view down with it. The host
    is marked disconnected either way — including after a refusal, so a
    collator that dies mid-checkpoint leaves `unswept` rather than a
    session that looks open for ever.
    """
    session = Session(estate=estate, declarations=declarations)
    promoted: HostSnapshot | None = None
    refusal: SessionRefused | CheckpointRefused | None = None
    try:
        for record in records(stream):
            snapshot = session.ingest(record)
            if snapshot is not None:
                promoted = snapshot
                if on_promote is not None:
                    on_promote(snapshot)
    except (SessionRefused, CheckpointRefused) as exc:
        refusal = exc
    finally:
        session.disconnected()
    return Served(host=session.host, promoted=promoted, refusal=refusal)


def server_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    """Mutual TLS, and the `required` is the whole point.

    A hub that accepted a session without a client certificate would have
    reversed the connection and kept none of what the reversal was
    supposed to buy: the network is no longer the containment layer, so
    identity is the only one left.
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=cafile)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def listen(
    bind: tuple[str, int],
    estate: Estate,
    declarations: Declarations,
    context: ssl.SSLContext | None = None,
    on_serve: Callable[[Served], None] | None = None,
    backlog: int = 16,
) -> None:
    """Accept sessions until the process ends.

    Single-threaded on purpose at this size: the estate is about ten
    hosts and a checkpoint is small, so a connection at a time costs
    nothing worth the concurrency bugs. It is stated rather than assumed
    because it is the first thing to revisit if the estate grows.
    """
    with socket.create_server(bind, reuse_port=False, backlog=backlog) as raw:
        while True:
            conn, _peer = raw.accept()
            with conn:
                wrapped = context.wrap_socket(conn, server_side=True) if context else conn
                with wrapped.makefile("rb") as stream:
                    served = serve(stream, estate, declarations)
                if on_serve is not None:
                    on_serve(served)
