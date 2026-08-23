"""The rewrite hub as a PROCESS.

Nothing served this tier until 2026-08-23: `se-hub` runs the shipping
product's FastAPI app, and the rewrite's routes, federation, views,
acknowledgement and lifecycle existed only under test. R3's record
listed three things as unwired — the write listener, the lifecycle store
path, a sibling session — and an audit found the fact underneath them:
those three gaps presupposed a daemon that did not exist.

A tier proven only by its unit tests is a tier whose WIRING is proven by
nothing, and every hub defect that audit found was in code the tests
exercised and no process ever ran. These tests run the process.
"""

from __future__ import annotations

import json
import pathlib
import threading
import time
import urllib.error
import urllib.request

import pytest

from system_explorer.hub import daemon, writes
from system_explorer.hub.checkpoint import CollectionSnapshot, Estate, HostSnapshot
from system_explorer.hub.lifecycle import Key
from system_explorer.hub.mcp_surface import call, discover
from system_explorer.hub.resolution import Contributor

BOOT = "5e000000-0000-4000-8000-000000000001"
KEY = Key(scope="storage-1", object_id="pool:tank", opinion="zfs-degraded")


@pytest.fixture
def running(tmp_path, monkeypatch):
    credential = tmp_path / "actors"
    credential.write_text("tok-henry henry\n")
    monkeypatch.setenv("SE_TRANSITION_ACTORS_FILE", str(credential))
    hub = daemon.Hub(site="lab", state_dir=tmp_path / "state")
    read, write, _ = daemon.serve(("127.0.0.1", 0), ("127.0.0.1", 0), hub=hub)
    threading.Thread(target=read.serve_forever, daemon=True).start()
    threading.Thread(target=write.serve_forever, daemon=True).start()
    time.sleep(0.15)
    try:
        yield hub, f"http://127.0.0.1:{read.server_address[1]}", \
            f"http://127.0.0.1:{write.server_address[1]}"
    finally:
        read.shutdown()
        write.shutdown()


def promote(hub, generation: int):
    estate = Estate(declared=("storage-1",))
    estate.promote(HostSnapshot(
        host="storage-1", checkpoint="cp", boot_id=BOOT,
        collections={"pools": CollectionSnapshot(
            name="pools", generation=generation, freshness="current",
            stale_reason=None, objects=())},
        declarations=("sha256:x",), history_gap=None))
    hub.estate = estate
    return estate


def derive(hub, at: str, generation: int):
    hub.registry.fold(at, {KEY: [Contributor(host="storage-1", collection="pools",
                                             generation=generation)]},
                      promote(hub, generation))


def post(wbase, body, token=None):
    request = urllib.request.Request(
        wbase + writes.TRANSITIONS_PATH, data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(request) as answer:
            return answer.status, json.loads(answer.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_every_published_route_answers_on_the_running_process(running) -> None:
    _, base, _ = running
    with urllib.request.urlopen(base + "/v1/routes") as answer:
        routes = json.loads(answer.read())["routes"]
    assert routes, "a tier that publishes no routes has no surface"
    for route in routes:
        if any("{" in segment for segment in route["path"].split("/")):
            continue  # exercised with real ids elsewhere
        with urllib.request.urlopen(base + route["path"]) as answer:
            assert answer.status == 200, route["path"]


def test_the_two_listeners_refuse_each_others_methods(running) -> None:
    """The whole reason the write plane has a door of its own: the read
    surface's licence to bind broadly is that it is read-only."""
    _, base, wbase = running
    with pytest.raises(urllib.error.HTTPError) as raised:
        urllib.request.urlopen(urllib.request.Request(
            base + "/v1/hosts", data=b"{}", method="POST"))
    assert raised.value.code == 405
    assert json.loads(raised.value.read())["error"] == "this surface is read-only"

    with pytest.raises(urllib.error.HTTPError) as raised:
        urllib.request.urlopen(wbase + writes.TRANSITIONS_PATH)
    assert raised.value.code == 405
    assert json.loads(raised.value.read())["error"] == "this listener is write-only"


def test_mcp_discovers_and_calls_the_running_tier(running) -> None:
    """The tools are generated from the route table the PROCESS
    publishes, so a route and its tool cannot disagree — and the argument
    path between them is exercised here rather than assumed."""
    hub, base, _ = running
    derive(hub, "2026-08-23T10:00:00Z", 1)
    tools = {tool.name: tool for tool in discover(base)}
    assert "get_acknowledgements" in tools
    assert call(tools["list_hosts"], {}, base=base) == {
        "hosts": {"storage-1": "connected"}}
    acknowledgements = call(tools["get_acknowledgements"], {}, base=base)
    assert KEY.rendered() in acknowledgements["acknowledgements"], (
        "/v1/acknowledgements has a producer: it was an empty mapping for "
        "as long as no daemon passed one")


def test_a_transition_written_on_one_door_is_read_on_the_other(running) -> None:
    hub, base, wbase = running
    derive(hub, "2026-08-23T10:00:00Z", 1)
    rendered = KEY.rendered()
    tools = {tool.name: tool for tool in discover(base)}

    def acknowledgements():
        return call(tools["get_acknowledgements"], {}, base=base)["acknowledgements"]

    assert acknowledgements()[rendered]["acknowledged"] is False
    assert post(wbase, {"finding": rendered, "action": "acknowledge"})[0] == 401
    assert post(wbase, {"finding": rendered, "action": "acknowledge"}, "guess")[0] == 401
    assert post(wbase, {"finding": "nobody/derived/this", "action": "acknowledge"},
                "tok-henry")[1]["error"] == "no-such-finding"
    assert post(wbase, {"finding": rendered, "action": "resolved"},
                "tok-henry")[1]["error"] == "not-declarable"

    assert post(wbase, {"finding": rendered, "action": "acknowledge",
                        "note": "disk on order"}, "tok-henry")[0] == 201
    held = acknowledgements()[rendered]
    assert held["acknowledged"] is True and held["by"] == "henry"
    assert held["note"] == "disk on order"


def test_an_acknowledgement_clears_when_the_finding_resolves(running) -> None:
    """End to end, through both doors and the MCP surface: the recurrence
    must not arrive already acknowledged."""
    hub, base, wbase = running
    rendered = KEY.rendered()
    derive(hub, "2026-08-23T10:00:00Z", 1)
    post(wbase, {"finding": rendered, "action": "acknowledge",
                 "note": "disk on order"}, "tok-henry")
    tools = {tool.name: tool for tool in discover(base)}

    def acknowledgements():
        return call(tools["get_acknowledgements"], {}, base=base)["acknowledgements"]

    assert acknowledgements()[rendered]["acknowledged"] is True

    # A NEWER generation that no longer derives it. The generation must
    # move: a fold at the same generation is not a re-read, so nothing
    # resolves — which is correct, and is what an end-to-end run caught
    # a first draft of this test getting wrong.
    hub.registry.fold("2026-08-24T10:00:00Z", {}, promote(hub, 2))
    assert rendered not in hub.derived()
    assert acknowledgements() == {}

    derive(hub, "2026-09-30T10:00:00Z", 3)
    again = acknowledgements()[rendered]
    assert again["acknowledged"] is False and again["by"] is None
    assert [t.action for t in hub.transitions.history(rendered)] == \
        ["acknowledge", "resolved"]


def test_the_hubs_metadata_survives_a_restart(running, tmp_path) -> None:
    hub, _, wbase = running
    derive(hub, "2026-08-23T10:00:00Z", 1)
    post(wbase, {"finding": KEY.rendered(), "action": "acknowledge"}, "tok-henry")

    reopened = daemon.Hub(site="lab", state_dir=hub.state)
    assert KEY.rendered() in reopened.registry.open(), (
        "a hub that restarts holds findings and no facts; the next fold must "
        "see an unswept estate and FREEZE rather than resolve everything")
    assert reopened.transitions.fold([KEY.rendered()])[KEY.rendered()].by == "henry"


# --- the estate a collator actually populates ------------------------

DECLARATION = json.dumps({
    "schema": "se.declaration/1", "collector": "widgets", "version": "1",
    "interface": {"name": "bearing", "version": "1"},
    "collections": [{
        "name": "widgets", "question": "are the bearings healthy?",
        "prefix": "widget", "answer": ["Spin"],
        "freshness": "60s", "ceiling": {"records": 10},
        "verbs": {"object": {"bytes": 262144, "ms": 5000},
                  "evidence": {"bytes": 1048576, "ms": 10000}},
        "facts": {"Spin": {"type": "integer", "unit": "rpm",
                           "temperament": "gauge", "kind": "observed",
                           "discloses": "nothing",
                           "sentence": "how fast the bearing turns."}},
        "rules": [{"key": "widget-slow", "level": "warn",
                   "grounds": "threshold",
                   "when": {"fact": "Spin", "at_most": 100},
                   "sentence": "Spinning below 100 rpm.", "cites": ["Spin"]}],
    }],
}, separators=(",", ":")).encode()


def test_a_collator_session_populates_the_estate_and_folds_the_registry(
        tmp_path, monkeypatch) -> None:
    """The daemon must ACCEPT a session and fold what it learns.

    It did neither. It bound two listeners over an Estate nothing could
    populate — no session listener, and nothing in `src/` called
    Registry.fold — so /v1/hosts answered {}, /v1/acknowledgements
    answered {}, and a well-formed acknowledgement with a valid
    credential was refused `no-such-finding`, because the derived set is
    the registry's open set and the registry was never written.

    Every daemon test that got past it called `hub.registry.fold(...)`
    from OUTSIDE the process — testing a copy of what the daemon should
    do rather than the daemon. This one drives a real collator over a
    real socket into the daemon's own listener.
    """
    import hashlib
    import os
    import shutil
    import socket
    import subprocess

    go = shutil.which("go")
    if go is None:
        pytest.skip("go toolchain not present")
    repo = pathlib.Path(__file__).resolve().parent.parent
    binary = tmp_path / "se-collate"
    build = subprocess.run([go, "build", "-o", str(binary), "./cmd/se-collate"],
                           cwd=repo / "go", capture_output=True, text=True)
    assert build.returncode == 0, build.stderr

    from collator import driver
    fake = driver.FakeCollector(DECLARATION)
    fake.queue(driver.render([
        {"record": "begin", "request": "r1", "batch": "b1",
         "declaration": "sha256:" + hashlib.sha256(DECLARATION).hexdigest(),
         "boot_id": BOOT, "timens": 0, "instance": None,
         "generations": {"widgets": 1}},
        {"record": "object", "collection": "widgets", "name": "left",
         "facts": {"Spin": 40}, "at": 10.0},
        {"record": "commit", "collection": "widgets", "generation": 1,
         "objects": 1, "assertions": 0, "unobservable": 0, "cpu_ms": 0.5},
        {"record": "end", "request": "r1", "batch": "b1", "cpu_ms": 0.5,
         "wall_ms": 1.0},
    ]))

    credential = tmp_path / "actors"
    credential.write_text("tok-henry henry\n")
    monkeypatch.setenv("SE_TRANSITION_ACTORS_FILE", str(credential))
    hub = daemon.Hub(site="lab", state_dir=tmp_path / "state")
    hub.estate = Estate(declared=("storage-1",))
    read, write, _ = daemon.serve(("127.0.0.1", 0), ("127.0.0.1", 0), hub=hub,
                                  session_bind=("127.0.0.1", 0))
    threading.Thread(target=read.serve_forever, daemon=True).start()
    threading.Thread(target=write.serve_forever, daemon=True).start()
    time.sleep(0.15)
    assert hub.sessions is not None, "the daemon must accept collator sessions"
    session_port = hub.sessions.getsockname()[1]
    base = f"http://127.0.0.1:{read.server_address[1]}"
    wbase = f"http://127.0.0.1:{write.server_address[1]}"

    try:
        run = subprocess.run(
            [str(binary)],
            env={"PATH": os.environ["PATH"],
                 "SE_STATE_DIR": str(tmp_path / "collator"),
                 "SE_COLLECTORS": f"widgets={fake.socket_path}",
                 "SE_ONESHOT": "1",
                 "SE_HUB_ADDR": f"127.0.0.1:{session_port}",
                 "SE_HOST": "storage-1", "SE_HUB_INSECURE": "1"},
            capture_output=True, text=True, timeout=120)
        assert run.returncode == 0, run.stderr
        time.sleep(0.3)

        # The estate the session populated, over the READ surface.
        with urllib.request.urlopen(base + "/v1/hosts") as answer:
            hosts = json.loads(answer.read())["hosts"]
        # `dark` rather than `connected`, and that is the right answer:
        # a one-shot collator promotes its checkpoint and disconnects, so
        # "was connected, is not" is what happened. What must NOT appear
        # is `unswept` — nobody has told us is a different claim from
        # told us and stopped, and `unswept` is what a hub with no
        # session listener said about every host in the estate.
        assert hosts.get("storage-1") == "dark", hosts

        # The registry was folded by the promote, not by a test.
        assert hub.derived(), (
            "a warn opinion the collator sent must become a finding with a "
            "lifecycle; the derived set is what an acknowledgement attaches to")
        finding = hub.derived()[0]
        assert "widget-slow" in finding, finding

        # And it is acknowledgeable end to end, which was refused
        # `no-such-finding` for as long as nothing folded.
        code, body = post(wbase, {"finding": finding, "action": "acknowledge"},
                          "tok-henry")
        assert code == 201, body
        with urllib.request.urlopen(base + "/v1/acknowledgements") as answer:
            held = json.loads(answer.read())["acknowledgements"]
        assert held[finding]["acknowledged"] is True, held
    finally:
        fake.close()
        read.shutdown()
        write.shutdown()
        hub.sessions.close()
