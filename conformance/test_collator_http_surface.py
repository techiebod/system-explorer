"""The read surface as a PROCESS serves it, not as a handler test calls it.

Every other collator guard either drives `NewHandler` in Go or spawns the
daemon and then reads the STORE — `db_path`/`snapshot`, never a socket. So
until this file the shipping binary's HTTP surface had been exercised by
nothing that runs it, which is the failure the rewrite hub had already
demonstrated once: code every test covered and no process ever started.

What it asks is DESIGN 28's four empty states, at the one tier where they
can still be told apart. A collection that is `absent` COMMITS — that is a
successful reading of the interface — so it is not stale and holds no
objects, and its row is byte-identical to a collection that answered and
honestly holds nothing unless the decline is served. "There is no ZFS on
this host" and "there are no pools" are different answers.

Coverage, stated because a guard that does not say what it misses is the
estate's most repeated defect: this reads `/v1/collections` only, and it
proves the members reach a reader — never that a renderer distinguishes
them, which is R4's and cannot be asked of a JSON body.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "harness"))
from collator import driver  # noqa: E402

DECL = json.dumps(
    {
        "schema": "se.declaration/1",
        "collector": "fixture",
        "collections": [
            {
                "name": "pools",
                "freshness": "1h",
                "facts": {"Health": {"type": "string", "temperament": "state"}},
            }
        ],
    },
    separators=(",", ":"),
).encode()
DIGEST = "sha256:" + hashlib.sha256(DECL).hexdigest()
BOOT = "5e000000-0000-4000-8000-000000000001"


def _stream(records: list[dict], batch: str = "batch-1", gen: int = 1) -> bytes:
    head = {
        "record": "begin", "request": batch, "batch": batch,
        "declaration": DIGEST, "boot_id": BOOT, "timens": 0,
        "instance": None, "generations": {"pools": gen},
    }
    tail = {"record": "end", "request": batch, "batch": batch,
            "cpu_ms": 0.5, "wall_ms": 1.0}
    return b"".join(
        json.dumps(r).encode() + b"\n" for r in [head, *records, tail]
    )


def _commit(objects: int, gen: int = 1) -> dict:
    return {"record": "commit", "collection": "pools", "generation": gen,
            "objects": objects, "assertions": 0, "unobservable": 0,
            "cpu_ms": 0.5}


OBJECT = {"record": "object", "collection": "pools", "name": "tank",
          "facts": {"Health": "ONLINE"}, "at": 10.5}


def _row(rounds: list[list[dict]]) -> dict:
    """Run each round through the real binary and GET the served row.

    The first round is a oneshot so its application is complete before the
    daemon starts; the daemon then runs its own rounds, which is why the
    fake is queued once more than there are rounds.
    """
    binary = driver.collate_binary()
    with tempfile.TemporaryDirectory() as state:
        fake = driver.FakeCollector(DECL)
        try:
            fake.queue(_stream(rounds[0]))
            first = driver.run_oneshot(binary, state, {"pools": fake.socket_path})
            assert first.returncode == 0, first.stderr[-800:]
            # The daemon acquires on its own schedule, so every later round
            # is queued before it starts and the last one is repeated: a
            # round the daemon runs after the queue drains must not change
            # the answer under test.
            for i, records in enumerate(rounds[1:] or [rounds[0]], start=2):
                fake.queue(_stream(records, batch=f"batch-{i}", gen=i))
            fake.queue(_stream(rounds[-1], batch="batch-tail",
                               gen=len(rounds) + 1))
            port = driver.free_port()
            proc = driver.spawn_daemon(binary, state, {"pools": fake.socket_path},
                                       f"127.0.0.1:{port}")
            try:
                deadline = time.monotonic() + 20
                while True:
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/v1/collections", timeout=5
                        ) as answer:
                            rows = json.load(answer)
                        break
                    except (urllib.error.URLError, OSError):
                        if time.monotonic() > deadline:
                            raise AssertionError(
                                "the daemon never served its read surface"
                            )
                        time.sleep(0.2)
            finally:
                proc.terminate()
                proc.wait(timeout=10)
        finally:
            fake.close()
    served = [r for r in rows if r["name"] == "pools"]
    assert served, f"the collection never reached the read surface: {rows}"
    return served[0]


DECLINE_UNAUTHORISED = [
    {"record": "decline", "collection": "pools", "reason": "unauthorised",
     "detail": "the ruleset is readable only to root on this host"}
]
DECLINE_ABSENT = [
    {"record": "decline", "collection": "pools", "reason": "absent",
     "detail": "no pools on this host"},
    _commit(0),
]


def test_a_non_absent_decline_serves_its_reason_and_its_detail():
    row = _row([DECLINE_UNAUTHORISED])
    assert row["stale"] is True
    decline = row.get("decline")
    assert decline, f"a decline that reaches no reader is not a decline: {row}"
    assert decline["reason"] == "unauthorised"
    # The reason says which of four kinds of not-answering this is; the
    # detail says what to do about it, and it is the half that travels out
    # over MCP. It was parsed off the wire and discarded until 2026-08-23.
    assert decline["detail"] == (
        "the ruleset is readable only to root on this host"
    )
    assert decline["at"], "a decline carries when it was made"


def test_absent_is_distinguishable_from_a_collection_that_holds_nothing():
    absent = _row([DECLINE_ABSENT])
    empty = _row([[_commit(0)]])
    # Both commit, both hold nothing, neither is stale. Every other member
    # of the two rows agrees — which is the whole point.
    assert absent["stale"] is False, "absent is a successful reading"
    assert empty["stale"] is False
    assert absent["object_count"] == empty["object_count"] == 0
    assert absent.get("decline", {}).get("reason") == "absent"
    assert "decline" not in empty, (
        "a collection that answered and holds nothing must serve no decline "
        f"member, or 'declined' becomes the default reading: {empty}"
    )


def test_a_collection_that_answers_again_stops_carrying_its_decline():
    # The part no single round can show. Without the clearing rule the
    # columns are write-only and a collection that declined once reads as
    # declined for ever — the stale-confident-claim failure, in the store.
    row = _row([
        [{"record": "decline", "collection": "pools", "reason": "unavailable",
          "detail": "zfs.ko not loaded"}],
        [OBJECT, _commit(1, gen=2)],
    ])
    assert row["object_count"] == 1, f"the answer must land: {row}"
    assert "decline" not in row, (
        f"a commit is an answer and clears the decline: {row}"
    )


def test_an_overdue_collection_says_so_over_real_http():
    """Standing rule 8 applied to the §15 promise check: proven on the
    wire, from outside the process.

    The fixture's boot id differs from the daemon's real one, so this
    exercises the previous-boot branch — the reading predates the
    daemon's boot, uptime is an honest lower bound on its age, and a 1s
    declared promise is certainly two windows gone. Before the verdict
    existed this row served `stale: false` and rendered `current`: the
    founding failure, live (register row 45).
    """
    decl = json.dumps({
        "schema": "se.declaration/1", "collector": "fixture",
        "collections": [{"name": "pools", "freshness": "1s",
                         "facts": {"Health": {"type": "string",
                                              "temperament": "state"}}}],
    }, separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(decl).hexdigest()
    records = [
        {"record": "begin", "request": "b1", "batch": "b1",
         "declaration": digest, "boot_id": BOOT, "timens": 0,
         "instance": None, "generations": {"pools": 1}},
        {"record": "object", "collection": "pools", "name": "tank",
         "facts": {"Health": "ONLINE"}, "at": 10.5},
        {"record": "commit", "collection": "pools", "generation": 1,
         "objects": 1, "assertions": 0, "unobservable": 0, "cpu_ms": 0.5},
        {"record": "end", "request": "b1", "batch": "b1",
         "cpu_ms": 0.5, "wall_ms": 1.0},
    ]
    payload = b"".join(json.dumps(r).encode() + b"\n" for r in records)
    binary = driver.collate_binary()
    with tempfile.TemporaryDirectory() as state:
        fake = driver.FakeCollector(decl)
        try:
            fake.queue(payload)
            run = driver.run_oneshot(binary, state, {"pools": fake.socket_path})
            assert run.returncode == 0, run.stderr[-800:]
            fake.queue(payload)  # the daemon's own round re-delivers; refused as dup, harmless
            port = driver.free_port()
            proc = driver.spawn_daemon(binary, state, {"pools": fake.socket_path},
                                       f"127.0.0.1:{port}")
            try:
                deadline = time.monotonic() + 20
                rows = None
                while time.monotonic() < deadline:
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/v1/collections",
                            timeout=5,
                        ) as answer:
                            rows = json.load(answer)
                        break
                    except (urllib.error.URLError, OSError):
                        time.sleep(0.2)
                assert rows is not None, "the daemon never served"
            finally:
                proc.terminate()
                proc.wait(timeout=10)
        finally:
            fake.close()
    row = [r for r in rows if r["name"] == "pools"][0]
    assert row.get("freshness") == "overdue", (
        "a reading two promise-windows old must not serve as current: "
        f"{row}")
    assert "declared promise of 1s" in row.get("freshness_detail", ""), (
        "the detail carries the measured facts: " + str(row))
    # And /v1/status names it in the roll-up.
    # (Served by the same handler table; asserted via a fresh daemon would
    # repeat the dance — the Go suite covers the wiring; the wire evidence
    # for the row itself is above.)
