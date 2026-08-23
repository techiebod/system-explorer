"""The hub's read surface: one table, three consumers, no write verb.

The UI, the JSON routes and MCP are the same envelopes rendered
differently. These tests hold that structurally — a route that gained no
tool, or a tool that named a route nobody serves, is a failure here
rather than a discovery later.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
import urllib.error
import urllib.request

import pytest

from system_explorer.hub.checkpoint import CollectionSnapshot, Estate, HostSnapshot
from system_explorer.hub.http import reading, serve
from system_explorer.hub.intent import Intent
from system_explorer.hub.mcp_surface import THIRD_PARTY_WARNING, call, discover
from system_explorer.hub.routes import table
from system_explorer.hub.session import Declarations

BOOT = "5e000000-0000-4000-8000-000000000001"

DECLARATION = {
    "schema": "se.declaration/1", "collector": "c", "version": "1.0.0",
    "collections": [{
        "name": "pools", "question": "q", "prefix": "pool", "freshness": "60s",
        "perishability": "perishable", "answer": ["State"],
        "facts": {"State": {"type": "string", "temperament": "state",
                            "kind": "observed", "discloses": "nothing",
                            "sentence": "."}},
    }],
}


def _hub_base(allowed_hosts=None):
    estate = Estate(declared=("storage-1",))
    declarations = Declarations()
    declarations.add("storage-1", DECLARATION, "sha256:x")
    estate.promote(HostSnapshot(
        host="storage-1", checkpoint="cp", boot_id=BOOT,
        collections={"pools": CollectionSnapshot(
            name="pools", generation=3, freshness="current", stale_reason=None,
            objects=({"id": "pools:tank", "name": "tank", "instance": None,
                      "facts": {"State": "degraded"}},),
            opinions=({"object": "pools:tank", "instance": None, "key": "pool-degraded",
                       "level": "critical", "grounds": "interface",
                       "sentence": "ZFS reports this pool degraded.",
                       "cites": ["State"]},))},
        declarations=("sha256:x",), history_gap=None))
    intent = Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": 41,
        "reviewed": "2026-08-20", "membership": {"hosts": {"storage-1": {}}},
        "plugins": {"widgets": {"targets": []}}})
    server = serve(("127.0.0.1", 0),
                   lambda: reading(estate, intent, declarations),
                   allowed_hosts=allowed_hosts,
                   # The reachability sweep visits every published route, so
                   # the fixture wires a sibling that answers; the refusal
                   # shapes get their own tests.
                   sibling_of=lambda site: {"origin": site, "answer": {
                       "site": site, "hosts": {}, "objects": [],
                       "opinions": [], "ages_s": {}}, "fetched": "stub"})
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    yield base
    server.shutdown()


@pytest.fixture(scope="module")
def hub():
    yield from _hub_base()


@pytest.fixture(scope="module")
def hub_named():
    yield from _hub_base(allowed_hosts="hub.example")


def fetch(url: str) -> bytes:
    return urllib.request.urlopen(url, timeout=10).read()


def test_the_estate_page_renders(hub) -> None:
    body = fetch(hub + "/").decode()
    assert body.startswith("<!doctype html>")
    assert "ZFS reports this pool degraded." in body
    assert 'class="grounds interface"' in body


def test_every_route_is_reachable_and_answers(hub) -> None:
    published = json.loads(fetch(hub + "/v1/routes"))["routes"]
    assert published, "a tier that publishes no routes has no surface"
    for route in published:
        path = route["path"]
        for name in route.get("params") or ():
            path = path.replace("{" + name + "}",
                                {"host": "storage-1", "name": "pools",
                                 "question": "question:estate-current",
                                 "site": "site-b"}[name])
        payload = json.loads(fetch(hub + path))
        assert isinstance(payload, dict) and "error" not in payload, (route, payload)


def test_a_tool_per_route_by_construction(hub) -> None:
    published = json.loads(fetch(hub + "/v1/routes"))["routes"]
    tools = discover(hub)
    assert {t.name for t in tools} == {r["tool"] for r in published}
    assert {t.path for t in tools} == {r["path"] for r in published}
    # Anti-vacuity: the table is the source, so an empty one is a failure
    # rather than a trivially passing parity check.
    assert len(tools) >= 6


def test_every_tool_warns_about_third_party_text(hub) -> None:
    for tool in discover(hub):
        assert THIRD_PARTY_WARNING in tool.description, (
            "a model reading these envelopes is almost never a model holding "
            "only these tools"
        )


def test_a_tool_returns_the_body_untouched(hub) -> None:
    tools = {t.name: t for t in discover(hub)}
    got = call(tools["get_opinions"], {}, hub)
    direct = json.loads(fetch(hub + "/v1/opinions"))
    assert got == direct, "a summarising layer would be a second judgement to drift"
    assert got["opinions"][0]["grounds"] == "interface"


def test_get_collection_reaches_a_collection_by_name(hub) -> None:
    tools = {t.name: t for t in discover(hub)}
    got = call(tools["get_collection"], {"host": "storage-1", "name": "pools"}, hub)
    assert got["objects"][0]["facts"]["State"] == "degraded"


def test_intent_serves_its_hash_and_never_its_document(hub) -> None:
    payload = json.loads(fetch(hub + "/v1/intent"))
    assert payload["hash"].startswith("sha256:")
    assert payload["plugins"] == ["widgets"]
    # The stanza itself is an estate's own arrangement and must not be
    # published to whoever can reach the hub.
    assert "targets" not in json.dumps(payload)
    assert "membership" not in payload


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_the_surface_is_read_only_structurally(hub, method) -> None:
    request = urllib.request.Request(hub + "/v1/hosts", method=method, data=b"{}")
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(request, timeout=10)
    assert caught.value.code == 405
    assert "read-only" in caught.value.read().decode()


def test_an_unknown_route_is_a_stated_404(hub) -> None:
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(hub + "/v1/nothing-here", timeout=10)
    assert caught.value.code == 404


def test_an_unknown_question_says_so_rather_than_inventing_one(hub) -> None:
    payload = json.loads(fetch(hub + "/v1/questions/question:invented"))
    assert payload["error"] == "no such question"


def test_the_route_table_is_the_only_place_routes_are_named() -> None:
    """If a second list appeared, parity would become a check somebody has
    to remember instead of a property of the construction."""
    routes = table(lambda: None)
    paths = [r.path for r in routes]
    assert len(paths) == len(set(paths))
    assert all(r.tool and r.summary for r in routes)


def test_views_serve_the_deployed_directory_fresh(tmp_path) -> None:
    """The ruled-unchanged surface on the rewrite hub: a real document from
    the deployed directory, read fresh per request — the operator edits a
    file and refreshes, no restart. The envelope is the shared loader's,
    so the three consumers cannot drift."""
    from system_explorer.views import load_views
    # The example file is the ENVELOPE; the deployed directory holds one
    # view document per file, so the fixture is the example's view.
    example = json.loads(
        Path("schema/examples/views-storage-simple.json").read_text())
    (tmp_path / "storage.json").write_text(json.dumps(example["views"][0]))
    estate = Estate(declared=("storage-1",))
    declarations = Declarations()
    intent = Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": 41,
        "reviewed": "2026-08-20", "membership": {"hosts": {"storage-1": {}}},
        "plugins": {}})
    server = serve(("127.0.0.1", 0),
                   lambda: reading(estate, intent, declarations),
                   views_of=lambda: load_views(str(tmp_path),
                                               "2026-08-23T12:00:00Z", "site-a"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        body = json.loads(fetch(f"{base}/v1/views"))
        assert body["schema"] == "se.views/1"
        assert [v["name"] for v in body["views"]] == ["storage-simple"]
        assert body.get("errors", []) == []

        # Fresh per request: a second document appears without a restart.
        (tmp_path / "zz-broken.json").write_text("{not json")
        again = json.loads(fetch(f"{base}/v1/views"))
        assert len(again["errors"]) == 1, (
            "a broken view silently dropped is how a curated projection "
            "quietly loses a panel"
        )
    finally:
        server.shutdown()


def test_views_with_no_directory_is_an_empty_list_not_an_error(hub) -> None:
    body = json.loads(fetch(f"{hub}/v1/views"))
    assert body["schema"] == "se.views/1"
    assert body["views"] == []


def test_an_unclaimed_host_name_is_refused_as_misdirected(hub) -> None:
    """Register row 15 at the hub's listener: DNS rebinding carries the
    attacker's NAME in the Host header, so a name this deployment never
    claimed is refused 421 — while the IP-literal spelling every legitimate
    tunnel uses (this fixture's own base URL) keeps answering, which every
    other test in this file is implicitly proving."""
    request = urllib.request.Request(
        hub + "/v1/routes", headers={"Host": "attacker.example"})
    try:
        urllib.request.urlopen(request, timeout=10)
        raise AssertionError("an unclaimed name must be refused")
    except urllib.error.HTTPError as refused:
        assert refused.code == 421
        assert "SE_ALLOWED_HOSTS" in refused.read().decode()


def test_a_claimed_host_name_answers(hub_named) -> None:
    request = urllib.request.Request(
        hub_named + "/v1/routes", headers={"Host": "Hub.Example:8080"})
    assert urllib.request.urlopen(request, timeout=10).status == 200


def test_a_query_parameter_reaches_the_tier_rather_than_being_discarded() -> None:
    """Every declared parameter that is not a path segment was demanded
    of the caller and then dropped.

    `call` looped over every declared parameter and substituted it into
    the path, so a parameter with no `{placeholder}` went nowhere.
    `what_changed` could not carry its `since`; the `lookup` tool could
    not carry its `input` at all, so a model could supply the one value
    the question turns on and receive an answer to a different question.
    And the schema required them, so a caller could neither omit one nor
    make it arrive.
    """
    from system_explorer.hub.mcp_surface import Tool

    asked: list[str] = []

    def opener(url: str) -> bytes:
        asked.append(url)
        return b"{}"

    changes = Tool(name="what_changed", description="d",
                   params=("name", "since", "instance"),
                   path="/v1/collections/{name}/changes")
    assert changes.path_params() == ("name",)
    assert set(changes.query_params()) == {"since", "instance"}
    # Only the path parameter is required: a route decides whether a
    # query parameter was optional, because the route is the party that
    # knows.
    assert changes.schema()["required"] == ["name"]

    call(changes, {"name": "units", "since": "2026-01-01T00:00:00Z",
                   "instance": "radarr"},
         base="http://h", opener=opener)
    assert "since=2026-01-01T00%3A00%3A00Z" in asked[-1], asked[-1]
    assert "instance=radarr" in asked[-1], asked[-1]

    # An omitted query parameter is simply absent, never an invented one.
    call(changes, {"name": "units"}, base="http://h", opener=opener)
    assert "?" not in asked[-1], asked[-1]

    # And a path parameter is still required.
    with pytest.raises(ValueError):
        call(changes, {"since": "x"}, base="http://h", opener=opener)


def test_the_lookup_tool_carries_the_value_the_question_turns_on() -> None:
    from system_explorer.hub.mcp_surface import Tool

    asked: list[str] = []
    lookup = Tool(name="lookup", description="d", params=("name", "input"),
                  path="/v1/lookups/{name}")
    call(lookup, {"name": "snapshots-of", "input": "tank/photos"},
         base="http://h", opener=lambda url: (asked.append(url), b"{}")[1])
    assert "input=tank%2Fphotos" in asked[-1], asked[-1]
