"""Acceptance item 11, across every channel this phase adds.

A planted credential must appear in no output channel: the estate page,
the JSON routes, an MCP tool's result, and the MQTT projection. The
canary is a distinctive string, so a match anywhere is unambiguous — and
the sweep is over EVERY channel rather than the ones this file's author
thought of, which is the whole reason the item is worded that way.

Coverage, stated: this sweeps the hub's channels. The collator's own two
(its host page and its JSON routes) are swept in the Go suite, next to
the store that holds the facts.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from system_explorer.hub.checkpoint import CollectionSnapshot, Estate, HostSnapshot, Reach
from system_explorer.hub.http import reading, serve
from system_explorer.hub.intent import Intent
from system_explorer.hub.lifecycle import Finding, Key
from system_explorer.hub.mcp_surface import call, discover
from system_explorer.hub.mqtt import Projection
from system_explorer.hub.resolution import Verdict
from system_explorer.hub.session import Declarations

CANARY = "se-canary-9d41f2b7c0e5-do-not-publish"
BOOT = "5e000000-0000-4000-8000-000000000001"

DECLARATION = {
    "schema": "se.declaration/1", "collector": "vault", "version": "1.0.0",
    "collections": [{
        "name": "creds", "question": "q", "prefix": "cred", "freshness": "60s",
        "perishability": "perishable", "answer": ["Endpoint"],
        "facts": {
            "Endpoint": {"type": "string", "temperament": "configuration",
                         "kind": "observed", "discloses": "location", "sentence": "."},
            # Declared a credential: withheld at source and never emitted.
            # A collector sending one anyway is the case this guards.
            "ApiToken": {"type": "string", "temperament": "configuration",
                         "kind": "observed", "discloses": "secret", "sentence": "."},
        },
    }],
}


@pytest.fixture(scope="module")
def planted():
    estate = Estate(declared=("storage-1",))
    declarations = Declarations()
    declarations.add("storage-1", DECLARATION, "sha256:v")
    estate.promote(HostSnapshot(
        host="storage-1", checkpoint="cp", boot_id=BOOT,
        collections={"creds": CollectionSnapshot(
            name="creds", generation=2, freshness="current", stale_reason=None,
            objects=({"id": "creds:vault", "name": "vault", "instance": None,
                      "facts": {"Endpoint": "https://vault.example",
                                "ApiToken": CANARY}},),
            opinions=())},
        declarations=("sha256:v",), history_gap=None))
    intent = Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": 1,
        "reviewed": "2026-08-20", "membership": {"hosts": {"storage-1": {}}}})
    server = serve(("127.0.0.1", 0), lambda: reading(estate, intent, declarations))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", estate, declarations, intent
    server.shutdown()


def fetch(url: str) -> str:
    return urllib.request.urlopen(url, timeout=10).read().decode()


def test_the_canary_is_actually_planted(planted) -> None:
    """Anti-vacuity. A sweep over a canary nobody planted passes for ever."""
    _base, estate, _declarations, _intent = planted
    snapshot = estate.visible("storage-1")
    facts = snapshot.collections["creds"].objects[0]["facts"]
    assert facts["ApiToken"] == CANARY, "the canary must be in the state being swept"


def test_neither_rendered_page_carries_the_canary(planted) -> None:
    base, *_ = planted
    estate = fetch(base + "/")
    assert CANARY not in estate
    # The estate page indexes; the collection page lists, and it is where
    # a withheld value must be NAMED rather than left to read as absent.
    collection = fetch(base + "/hosts/storage-1/collections/creds")
    assert CANARY not in collection
    assert "withheld (declared secret)" in collection and "ApiToken" in collection


def test_no_json_route_carries_the_canary(planted) -> None:
    base, *_ = planted
    routes = json.loads(fetch(base + "/v1/routes"))["routes"]
    for route in routes:
        path = route["path"]
        for name in route.get("params") or ():
            path = path.replace("{" + name + "}",
                                {"host": "storage-1", "name": "creds",
                                 "question": "question:estate-current"}[name])
        assert CANARY not in fetch(base + path), path


def test_no_mcp_tool_returns_the_canary(planted) -> None:
    base, *_ = planted
    for tool in discover(base):
        arguments = {"host": "storage-1", "name": "creds",
                     "question": "question:estate-current"}
        got = call(tool, {p: arguments[p] for p in tool.params}, base)
        assert CANARY not in json.dumps(got), tool.name


def test_the_mqtt_projection_carries_no_canary(planted) -> None:
    """It carries findings and never facts, so this should be true twice
    over — and it is asserted rather than assumed for exactly that reason."""
    projection = Projection("homeassistant", "home")
    finding = Finding(key=Key(scope="storage-1", object_id="creds:vault",
                              opinion="token-present"),
                      first_seen="2026-08-20T10:00:00Z",
                      last_seen="2026-08-20T10:00:00Z", verdict=Verdict.CURRENT)
    messages = projection.republish({finding.key.rendered(): finding},
                                    {"storage-1": Reach.CONNECTED})
    blob = json.dumps([m.as_wire() for m in messages])
    assert CANARY not in blob


def test_an_exception_message_never_reaches_a_channel(planted) -> None:
    """The other leak path, and the one that has bitten this product
    before: an exception stringifies with the URL that raised it, and a
    URL can carry a token in its query string."""
    base, estate, declarations, intent = planted

    def exploding():
        raise RuntimeError(f"GET https://vault.example?token={CANARY} failed")

    server = serve(("127.0.0.1", 0), exploding)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        broken = f"http://127.0.0.1:{server.server_port}"
        try:
            fetch(broken + "/v1/hosts")
            raise AssertionError("the handler was supposed to raise")
        except urllib.error.HTTPError as error:
            body = error.read().decode()
        assert CANARY not in body
        assert json.loads(body)["error"] == "RuntimeError", (
            "the type, never the message"
        )
    finally:
        server.shutdown()
