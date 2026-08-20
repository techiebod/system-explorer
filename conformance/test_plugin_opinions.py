"""A collector this repository does not ship reaches a finding.

Gate 5's plugin facet, end to end and with the real binaries: a plugin
declares its own collection, its own facts and its own rule table; the
collator evaluates the table because that is the lowest tier that can
reach the facts; the checkpoint carries the opinions; the hub accepts
them and mints a finding with a lifecycle.

Nothing in this repository knows the plugin's collection, its facts or
its rules — which is the property the plugin surface was built to have,
and the reason this test builds the declaration rather than importing one.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

from system_explorer.hub.checkpoint import CheckpointRefused, Estate
from system_explorer.hub.lifecycle import Key, Registry
from system_explorer.hub.listener import serve
from system_explorer.hub.resolution import Contributor, Verdict
from system_explorer.hub.rollup import opinions
from system_explorer.hub.session import Declarations, Session

REPO = Path(__file__).resolve().parent.parent

# A collection this repository has never heard of, with its own vocabulary.
PLUGIN_DECLARATION = json.dumps({
    "schema": "se.declaration/1", "collector": "widgets", "version": "1.0.0",
    "collections": [{
        "name": "widgets", "question": "are the widgets turning?",
        "prefix": "widget", "freshness": "60s", "perishability": "perishable",
        "answer": ["Spin", "Wobble"],
        "facts": {
            "Spin": {"type": "integer", "temperament": "gauge", "kind": "observed",
                     "discloses": "nothing", "sentence": "Revolutions per minute."},
            "Wobble": {"type": "string", "temperament": "state", "kind": "observed",
                       "discloses": "nothing", "sentence": "What the bearing says."},
        },
        "rules": [
            {"key": "widget-wobbling", "level": "critical", "grounds": "interface",
             "when": {"fact": "Wobble", "equals": "excessive"},
             "sentence": "The bearing reports excessive wobble.",
             "cites": ["Wobble", "Spin"]},
            {"key": "widget-slow", "level": "warn", "grounds": "threshold",
             "when": {"fact": "Spin", "at_most": 100},
             "sentence": "Spinning below 100 rpm.", "cites": ["Spin"]},
        ],
    }],
}, separators=(",", ":")).encode()


@pytest.fixture(scope="module")
def collate_binary() -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("go toolchain not present")
    out = Path(tempfile.mkdtemp(prefix="se-collate-bin")) / "se-collate"
    build = subprocess.run([go, "build", "-o", str(out), "./cmd/se-collate"],
                           cwd=REPO / "go", capture_output=True, text=True)
    assert build.returncode == 0, f"{build.stdout}\n{build.stderr}"
    return out


def plugin_collector(spin: int, wobble: str):
    from collator import driver

    fake = driver.FakeCollector(PLUGIN_DECLARATION)
    fake.queue(driver.render([
        {"record": "begin", "request": "r1", "batch": "b1",
         "declaration": "sha256:" + hashlib.sha256(PLUGIN_DECLARATION).hexdigest(),
         "boot_id": "5e000000-0000-4000-8000-000000000001", "timens": 0,
         "instance": None, "generations": {"widgets": 1}},
        {"record": "object", "collection": "widgets", "name": "left",
         "facts": {"Spin": spin, "Wobble": wobble}, "at": 10.0},
        {"record": "commit", "collection": "widgets", "generation": 1, "objects": 1,
         "assertions": 0, "unobservable": 0, "cpu_ms": 0.5},
        {"record": "end", "request": "r1", "batch": "b1", "cpu_ms": 0.5, "wall_ms": 1.0},
    ]))
    return fake


def run_plugin(collate_binary, tmp_path, spin: int, wobble: str):
    estate = Estate(declared=("storage-1",))
    declarations = Declarations()
    served: list = []
    fake = plugin_collector(spin, wobble)
    try:
        with socket.create_server(("127.0.0.1", 0)) as listener:
            port = listener.getsockname()[1]

            def accept() -> None:
                conn, _ = listener.accept()
                with conn, conn.makefile("rb") as stream:
                    served.append(serve(stream, estate, declarations))

            thread = threading.Thread(target=accept)
            thread.start()
            run = subprocess.run(
                [str(collate_binary)],
                env={"PATH": os.environ["PATH"],
                     "SE_STATE_DIR": str(tmp_path / f"state-{spin}-{wobble}"),
                     "SE_COLLECTORS": f"widgets={fake.socket_path}",
                     "SE_ONESHOT": "1", "SE_HUB_ADDR": f"127.0.0.1:{port}",
                     "SE_HOST": "storage-1", "SE_HUB_INSECURE": "1"},
                capture_output=True, text=True, timeout=120)
            thread.join(timeout=60)
    finally:
        fake.close()
    assert run.returncode == 0, run.stderr
    assert served and served[0].refusal is None, served
    return estate, declarations


def test_a_plugins_own_rule_reaches_a_finding(collate_binary, tmp_path) -> None:
    estate, declarations = run_plugin(collate_binary, tmp_path, spin=40, wobble="excessive")
    held = opinions(estate, declarations)
    by_key = {o.key: o for o in held}
    assert set(by_key) == {"widget-wobbling", "widget-slow"}, held

    wobble = by_key["widget-wobbling"]
    assert wobble.level == "critical"
    assert wobble.grounds == "interface", (
        "the bearing declares this itself; no number of ours is involved"
    )
    assert wobble.sentence == "The bearing reports excessive wobble."
    assert set(wobble.cites) == {"Wobble", "Spin"}
    assert by_key["widget-slow"].grounds == "threshold", (
        "100 rpm is OUR number, and a surface rendering it like the "
        "interface's own verdict would present our opinion as the machine's"
    )

    # And it becomes a finding with a lifecycle, keyed the new way.
    registry = Registry(reset_at="2026-08-20T09:00:00Z")
    derived = {
        Key(scope=o.host, object_id=o.object_id, opinion=o.key, instance=o.instance):
            [Contributor(o.host, o.collection, o.generation)]
        for o in held
    }
    open_now = registry.fold("2026-08-20T10:00:00Z", derived, estate)
    assert len(open_now) == 2
    assert all(f.verdict is Verdict.CURRENT for f in open_now.values())
    assert any("widget-wobbling" in k for k in open_now)


def test_a_healthy_plugin_object_mints_nothing_and_says_so(
    collate_binary, tmp_path
) -> None:
    """An empty opinion list is a reading — judged, and nothing wrong —
    and it must not look like a collection nobody could judge."""
    estate, declarations = run_plugin(collate_binary, tmp_path, spin=500, wobble="none")
    assert opinions(estate, declarations) == ()
    snapshot = estate.visible("storage-1")
    assert snapshot.collections["widgets"].opinions == (), (
        "declared a rule table and nothing fired: an empty tuple, never None"
    )


def test_a_collection_with_no_rule_table_says_nobody_judged_it(
    collate_binary, tmp_path
) -> None:
    """None and empty are different claims and the hub keeps them apart."""
    from system_explorer.hub.checkpoint import CollectionSnapshot

    unjudged = CollectionSnapshot(name="x", generation=1, freshness="current",
                                  stale_reason=None, objects=())
    assert unjudged.opinions is None


def test_an_opinion_whose_subject_was_not_sent_is_refused() -> None:
    """A verdict with nothing to go and look at."""
    from system_explorer.hub.checkpoint import Receiver

    receiver = Receiver()
    receiver.ingest({"record": "manifest", "checkpoint": "cp", "host": "h",
                     "boot_id": "5e000000-0000-4000-8000-000000000001",
                     "declarations": ["sha256:x"],
                     "collections": [{"collection": "widgets", "generation": 1,
                                      "freshness": "current", "objects": 0}]})
    with pytest.raises(CheckpointRefused) as caught:
        receiver.ingest({"record": "collection_state", "checkpoint": "cp",
                         "collection": "widgets", "generation": 1, "objects": [],
                         "opinions": [{"object": "widget:ghost", "key": "k",
                                       "level": "warn", "grounds": "interface",
                                       "sentence": "s", "cites": ["Spin"]}]})
    assert caught.value.reason == "opinion-orphaned"


def test_an_opinion_citing_a_fact_no_declaration_backs_reaches_no_rollup(
    collate_binary, tmp_path
) -> None:
    """Item 7's last half at the hub. The collator refuses a table that
    reaches outside its own collection; this is the other end, where an
    opinion arrives naming a fact the hub holds no axis for."""
    estate, declarations = run_plugin(collate_binary, tmp_path, spin=40, wobble="excessive")
    assert len(opinions(estate, declarations)) == 2
    # A hub that holds no declaration for the pair backs nothing.
    assert opinions(estate, Declarations()) == ()
