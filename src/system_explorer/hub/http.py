"""The hub's HTTP surface: the estate page and the JSON routes.

Stdlib only, and deliberately: the design system was ruled to be the
product's own with no external framework, and the same argument applies
one layer down — a read surface this small does not need a framework's
vocabulary, and importing one is how a product stops owning its own
shape.

**Read-only structurally.** Only GET is routed; every other method is
refused by the handler rather than by a policy somebody could relax. That
is what the hub's bind posture rests on.

**The estate view is computed per request.** The hub holds no observation
of its own — what it holds is metadata — so serving a remembered view
would be last-known-good in the one place the design says it must not be.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from ..surface import render
from .answer import estate_current
from .checkpoint import Estate
from .intent import Intent
from .rollup import EstateView, assemble, opinions
from .routes import Route, table
from .session import Declarations


@dataclass(frozen=True)
class State:
    """One consistent reading of the estate, built for one request."""

    view: EstateView
    intent: Intent
    opinions: tuple
    answers: tuple


def reading(estate: Estate, intent: Intent, declarations: Declarations) -> State:
    view = assemble(estate, intent, declarations)
    return State(
        view=view,
        intent=intent,
        opinions=opinions(estate, declarations),
        # One question today. The list is what makes them discoverable,
        # and adding the second costs a line rather than a route.
        answers=(estate_current(view, estate, intent),),
    )


def _host_allowed(host_header: str, claimed: frozenset[str]) -> bool:
    """The DNS-rebinding defence, same policy as the collator's listener:
    an IP literal, localhost or an absent Host always answers — a rebound
    request always carries the attacker's NAME — and any other name must
    be one this deployment claimed. Deny-by-default over names."""
    if not host_header:
        return True
    host = host_header
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    host = host.lower()
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return host in claimed


def handler_class(view_of: Callable[[], State],
                  allowed_hosts: str | None = None) -> type[BaseHTTPRequestHandler]:
    routes: tuple[Route, ...] = table(view_of)
    # Injected for tests, environmental for the daemon — the same reason
    # the collator's clock is injected: the refusal must be assertable.
    claimed = frozenset(
        name.strip().lower()
        for name in (allowed_hosts if allowed_hosts is not None
                     else os.environ.get("SE_ALLOWED_HOSTS", "")).split(",")
        if name.strip())

    class Handler(BaseHTTPRequestHandler):
        server_version = "se-hub"
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: Any) -> None:  # noqa: D102
            # Silent by default: an access log on an unauthenticated read
            # surface is a second place host names accumulate, and this
            # process has no rotation for it.
            return

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if content_type.startswith("text/html"):
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if not _host_allowed(self.headers.get("Host", ""), claimed):
                self._send(421, json.dumps(
                    {"error": "this listener does not answer to that name; "
                              "a deployment claims its names in "
                              "SE_ALLOWED_HOSTS"}).encode(),
                    "application/json")
                return
            path = self.path.split("?", 1)[0]
            if path == "/":
                state = view_of()
                body = render.estate_page(
                    state.view, state.answers[0], state.opinions).encode()
                self._send(200, body, "text/html; charset=utf-8")
                return
            if path.startswith("/hosts/") and "/collections/" in path:
                parts = [p for p in path.strip("/").split("/") if p]
                if len(parts) == 4:
                    state = view_of()
                    body = render.collection_page(
                        parts[1], parts[3], state.view.rows).encode()
                    self._send(200, body, "text/html; charset=utf-8")
                    return
            if path == "/v1/routes":
                # The tier publishes its own table, which is what lets an
                # MCP surface generate a tool per route without this
                # repository knowing what routes exist at build time.
                body = json.dumps({"routes": [
                    {"path": r.path, "tool": r.tool, "summary": r.summary,
                     "params": list(r.params)} for r in routes]}).encode()
                self._send(200, body, "application/json")
                return
            for route in routes:
                bound = route.matches(path)
                if bound is None or route.handler is None:
                    continue
                try:
                    payload = route.handler(**bound)
                except Exception as exc:  # noqa: BLE001
                    # The type, never the message: an exception's text is
                    # where a URL with a token in it reaches an
                    # unauthenticated channel (acceptance item 11).
                    self._send(500, json.dumps(
                        {"error": type(exc).__name__}).encode(), "application/json")
                    return
                self._send(200, json.dumps(payload).encode(), "application/json")
                return
            self._send(404, json.dumps({"error": "no such route"}).encode(),
                       "application/json")

        def _refuse(self) -> None:
            self._send(405, json.dumps(
                {"error": "this surface is read-only"}).encode(), "application/json")

        # Named rather than defaulted: BaseHTTPRequestHandler answers 501
        # for a method it has no do_ for, and 405 with a stated reason is
        # what an operator can act on.
        do_POST = do_PUT = do_PATCH = do_DELETE = _refuse

    return Handler


def serve(bind: tuple[str, int], view_of: Callable[[], State],
          allowed_hosts: str | None = None) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(bind, handler_class(view_of, allowed_hosts))
