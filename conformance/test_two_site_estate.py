"""Two collators into a live hub, and a second hub federating against it.

This is the CI-tier stand-in for gate 4's two-guest clause, and it is
deliberately labelled as a stand-in rather than as that clause: standing
rule 3 puts federation tests on two lab guests as two sites, and what
runs here is two collator processes and two hub objects on one machine.
What it does prove is every property the clause is about — two hosts
promoted independently, one coherent view with reach and coverage, a
sibling that agrees on the intent hash, and one hop that holds.

What it does NOT prove, stated so the gap cannot be read as covered: a
real network between the parts, two kernels, or the NAT-mode dial against
a host that can only originate.
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

from system_explorer.hub.answer import estate_current
from system_explorer.hub.checkpoint import Estate, Reach
from system_explorer.hub.federation import offer, peer_session
from system_explorer.hub.intent import Intent
from system_explorer.hub.listener import Served, serve
from system_explorer.hub.rollup import assemble
from system_explorer.hub.session import Declarations

REPO = Path(__file__).resolve().parent.parent
HOSTS = {"storage-1": "4f9c2e1", "edge-1": "9ab31d0"}


def declaration_bytes() -> bytes:
    return json.dumps({
        "schema": "se.declaration/1", "collector": "nix", "version": "0.7.0",
        "collections": [{
            "name": "generations", "question": "what has this host been?",
            "prefix": "generation", "freshness": "300s",
            "perishability": "reconstructible", "answer": ["ConfigurationRevision"],
            "facts": {name: {"type": "string", "temperament": "configuration",
                             "kind": "observed", "discloses": "nothing", "sentence": "."}
                      for name in ("ConfigurationRevision", "Booted")},
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


def collector_for(host: str, revision: str):
    """A real collector serving one booted generation for this host."""
    from collator import driver

    raw = declaration_bytes()
    fake = driver.FakeCollector(raw)
    fake.queue(driver.render([
        {"record": "begin", "request": f"req-{host}", "batch": f"batch-{host}",
         "declaration": "sha256:" + hashlib.sha256(raw).hexdigest(),
         "boot_id": "5e000000-0000-4000-8000-000000000001", "timens": 0,
         "instance": None, "generations": {"generations": 1}},
        {"record": "object", "collection": "generations", "name": "7",
         "facts": {"Booted": True, "ConfigurationRevision": revision}, "at": 10.0},
        # Counts, all three: a commit carries what it sent so a receiver
        # can tell a finished batch from one whose middle was lost.
        {"record": "commit", "collection": "generations", "generation": 1,
         "objects": 1, "assertions": 0, "unobservable": 0, "cpu_ms": 0.5},
        {"record": "end", "request": f"req-{host}", "batch": f"batch-{host}",
         "cpu_ms": 0.5, "wall_ms": 1.0},
    ]))
    return fake


def run_site(collate_binary, tmp_path) -> tuple[Estate, Declarations, list[Served]]:
    """Stand a hub up and have both collators dial it, one after another."""
    estate = Estate(declared=tuple(HOSTS))
    declarations = Declarations()
    served: list[Served] = []
    fakes = []
    try:
        with socket.create_server(("127.0.0.1", 0)) as listener:
            port = listener.getsockname()[1]

            def accept(n: int) -> None:
                for _ in range(n):
                    conn, _peer = listener.accept()
                    with conn, conn.makefile("rb") as stream:
                        served.append(serve(stream, estate, declarations))

            thread = threading.Thread(target=accept, args=(len(HOSTS),))
            thread.start()
            for host, revision in HOSTS.items():
                fake = collector_for(host, revision)
                fakes.append(fake)
                run = subprocess.run(
                    [str(collate_binary)],
                    env={
                        "PATH": os.environ["PATH"],
                        "SE_STATE_DIR": str(tmp_path / host),
                        "SE_COLLECTORS": f"nix={fake.socket_path}",
                        "SE_ONESHOT": "1",
                        "SE_HUB_ADDR": f"127.0.0.1:{port}",
                        "SE_HOST": host,
                        "SE_HUB_INSECURE": "1",
                    },
                    capture_output=True, text=True, timeout=120,
                )
                assert run.returncode == 0, f"{host}: {run.stderr}"
            thread.join(timeout=60)
            assert not thread.is_alive()
    finally:
        for fake in fakes:
            fake.close()
    return estate, declarations, served


def intent_for() -> Intent:
    return Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": 41,
        "reviewed": "2026-08-20", "estate_hub": "site-a",
        "membership": {"hosts": {h: {"roles": ["host"]} for h in HOSTS}},
    })


def test_two_collators_dial_one_hub_and_the_estate_coheres(collate_binary, tmp_path) -> None:
    estate, declarations, served = run_site(collate_binary, tmp_path)
    assert [s.refusal for s in served] == [None, None], served
    assert {s.host for s in served} == set(HOSTS)

    intent = intent_for()
    view = assemble(estate, intent, declarations)
    answer = estate_current(view, estate, intent)

    # Both promoted, both dark now (each dialled, sent, and closed).
    assert set(view.reach) == set(HOSTS)
    assert all(reach is Reach.DARK for reach in view.reach.values())
    # A dark host keeps its last promoted state, so the view is complete
    # and says how it was gathered.
    assert len(view.rows) == 2
    assert answer["epistemic"] == "complete"
    assert answer["verdict"] == "degraded"
    for revision in HOSTS.values():
        assert revision in answer["answer"]
    assert sorted(answer["reach"]["coverage"]["declared"]) == sorted(HOSTS)


def test_a_sibling_hub_federates_against_the_same_estate(collate_binary, tmp_path) -> None:
    estate, declarations, _ = run_site(collate_binary, tmp_path)
    intent = intent_for()
    view = assemble(estate, intent, declarations)

    a, b = socket.socketpair()
    replies: list[dict] = []
    outcome: list[object] = []

    def site_b():
        with b.makefile("rb") as bi, b.makefile("wb") as bo:
            outcome.append(peer_session(
                bi, bo, offer("site-b", intent), "site-b",
                answer=lambda request: {
                    "hosts": sorted(view.reach),
                    "coverage": {"declared": list(view.coverage.declared)},
                },
            ))

    thread = threading.Thread(target=site_b)
    thread.start()
    try:
        with a.makefile("rb") as ai, a.makefile("wb") as ao:
            theirs = json.loads(ai.readline())
            ao.write((json.dumps({"record": "handshake",
                                  **offer("site-a", intent).as_wire()}) + "\n").encode())
            ao.flush()
            verdict = json.loads(ai.readline())
            assert verdict["record"] == "agreed", verdict
            for target in ("site-b", "site-c"):
                ao.write((json.dumps({"record": "request", "origin_site": "site-a",
                                      "for_site": target}) + "\n").encode())
                ao.flush()
                replies.append(json.loads(ai.readline()))
            ao.flush()
            a.shutdown(socket.SHUT_WR)
            thread.join(timeout=10)
            assert not thread.is_alive()
    finally:
        a.close()
        b.close()

    assert theirs["site"] == "site-b"
    assert theirs["intent_hash"] == intent.hash
    # Its own site: answered. A third site: refused, one hop holding.
    assert replies[0]["record"] == "answer"
    assert sorted(replies[0]["body"]["hosts"]) == sorted(HOSTS)
    assert replies[1]["record"] == "refused"
    assert replies[1]["reason"] == "would-forward"
    assert outcome == [None]
