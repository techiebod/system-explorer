"""Acceptance item 3 at phase 2: every boundary in harness/crash/boundaries.json
whose kill lands on the collector or the collator, driven against the real
se-collate binary and judged against its durable store.

harness/crash/boundaries.json is the committed contract — enumerated in
phase 1 because the boundaries are properties of the protocol, not of any
implementation. This suite owns every entry: five are driven here, three
belong to the reconnect-checkpoint protocol between collator and hub and are
skipped with the phase that owns them named. A boundary in neither set fails
the ownership test below, so a new entry can never arrive silently undriven.

Two kinds of kill, two vehicles:

- The three collator boundaries are real deaths at the marked point:
  SE_CRASH_AT makes the store's Crashpoint exit 137 — SIGKILL's status,
  indistinguishable from the kernel killing it, because that is what is
  being rehearsed — and the assertions read what a restart finds.

- The two collector boundaries have no crash seam to pull (se-collect-system
  exposes none), so the honest driver kills the STREAM instead: the fake
  serves bytes severed exactly where the collector would have died, which is
  all the collator can ever see of a dead collector. A severed stream before
  commit must apply nothing — the same assertion, made from the side that
  holds the state.

Each driven boundary's `expect` string is pinned verbatim (as the Go crash
tests pin theirs): if the harness file's wording moves, the assertions here
must be re-derived rather than silently kept.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from collator import driver

REPO = Path(__file__).resolve().parent.parent
BOUNDARIES = json.loads((REPO / "harness" / "crash" / "boundaries.json").read_text())["boundaries"]

# The five phase-2 boundaries, with their expectations pinned verbatim.
DRIVEN = {
    "mid-object": "no part of the collection is applied; prior state stands, unmarked",
    "pre-commit": "identical to mid-object — a partial read must never delete anything",
    "post-commit-pre-apply": "on restart the collection is at its previous generation; the batch is re-run",
    "mid-apply": "all of it or none of it; a generation may never advance over unapplied objects",
    "post-apply-pre-ack": "applied and durable; a re-sent identical batch at the same generation is a no-op",
}

# The checkpoint boundaries belong to phase 6 (appendix C: hub evolution +
# protocol suite, "checkpoint, generation and crash tests green"). Two kill
# the hub outright; post-manifest-pre-terminal kills the collator, but what
# it asserts — a hub discarding a partial checkpoint, a host staying unswept
# — is checkpoint-protocol state no phase-2 component holds.
LATER = {
    "mid-checkpoint": (
        "kills the hub during a reconnect checkpoint — the hub is phase 6 "
        "(hub evolution + protocol suite) and does not exist at phase 2"
    ),
    "post-manifest-pre-terminal": (
        "kills the collator inside the reconnect checkpoint it sends the hub — "
        "the checkpoint protocol and the hub that judges it are phase 6 "
        "(hub evolution + protocol suite); neither exists at phase 2"
    ),
    "post-promote-pre-persist": (
        "kills the hub between promoting a checkpoint and persisting finding "
        "lifecycle — the hub is phase 6 (hub evolution + protocol suite) and "
        "does not exist at phase 2"
    ),
}


def test_every_boundary_is_driven_or_named_later() -> None:
    """Deny-by-default over the contract file: every boundary is either
    driven here or skipped with its owning phase named. A new entry lands
    red until somebody claims it — the alternative is a crash enumeration
    that silently stops being an enumeration."""
    ids = {b["id"] for b in BOUNDARIES}
    assert ids == set(DRIVEN) | set(LATER), (
        f"boundaries.json and this suite disagree about who owns what: "
        f"unclaimed {sorted(ids - set(DRIVEN) - set(LATER))}, "
        f"phantom {sorted((set(DRIVEN) | set(LATER)) - ids)}"
    )
    for b in BOUNDARIES:
        if b["id"] in DRIVEN:
            assert b["expect"] == DRIVEN[b["id"]], (
                f"boundary {b['id']}: expect drifted from what these tests assert.\n"
                f" harness: {b['expect']!r}\n  pinned: {DRIVEN[b['id']]!r}"
            )


# ── the shared rig ───────────────────────────────────────────────────────

_DECL = b'{"schema":"se.declaration/1","collector":"system","collections":[{"name":"identity","freshness":"1h"}]}'
_BOOT = "5e000000-0000-4000-8000-000000000001"


def _records(gen: int) -> list[dict]:
    """One clean batch for a generation, deterministic per generation the
    way the contract's transport retry needs: same generation, same bytes."""
    batch = f"batch-{gen}"
    decl = "sha256:" + hashlib.sha256(_DECL).hexdigest()
    return [
        {"record": "begin", "request": batch, "batch": batch, "declaration": decl,
         "boot_id": _BOOT, "timens": 0, "instance": None,
         "generations": {"identity": gen}},
        {"record": "object", "collection": "identity", "name": "host1",
         "facts": {"Gen": gen}, "at": gen + 0.5},
        {"record": "commit", "collection": "identity", "generation": gen,
         "objects": 1, "assertions": 0, "unobservable": 0, "cpu_ms": 0.5},
        {"record": "end", "request": batch, "batch": batch,
         "cpu_ms": 0.5, "wall_ms": 1.0},
    ]


class _Rig:
    def __init__(self, tmp: Path):
        self.state_dir = str(tmp)
        self.fake = driver.FakeCollector(_DECL)
        self.binary = driver.collate_binary()

    def round(self, payload: bytes, crash_at: str = "", want_exit: int = 0) -> None:
        self.fake.queue(payload)
        proc = driver.run_oneshot(
            self.binary, self.state_dir, {"system": self.fake.socket_path}, crash_at
        )
        assert proc.returncode == want_exit, (
            f"round exited {proc.returncode}, want {want_exit} "
            f"(crash_at={crash_at!r}):\n{proc.stderr}"
        )

    def snapshot(self) -> dict:
        return driver.snapshot(driver.db_path(self.state_dir))

    def close(self) -> None:
        self.fake.check()
        self.fake.close()


@pytest.fixture
def rig(tmp_path):
    r = _Rig(tmp_path)
    yield r
    r.close()


def _assert_identity(state: dict, expect: str, gen: int, facts: dict | None) -> None:
    """The store's whole word on the identity collection: generation, the
    object set (exactly one, or exactly none), and never partial."""
    assert set(state["collections"]) == {"identity"}, f"[{expect}] collections {state['collections']}"
    got = state["collections"]["identity"]
    assert got["generation"] == gen, f"[{expect}] generation {got['generation']}, want {gen}"
    if facts is None:
        assert state["objects"] == [], f"[{expect}] expected no objects, found {state['objects']}"
    else:
        assert len(state["objects"]) == 1, f"[{expect}] objects {state['objects']}"
        assert state["objects"][0]["facts"] == facts, (
            f"[{expect}] facts {state['objects'][0]['facts']}, want {facts}"
        )


# ── collector kills: the stream is severed where the process would die ───


def _severed_collector_boundary(rig: _Rig, expect: str, payload: bytes, reason: str) -> None:
    # Generation 1 applies cleanly; the severed generation-2 stream must
    # then change nothing — and the recorded violation proves the stream
    # was seen and refused, not merely never delivered (a judge that could
    # not tell those apart would pass over a fake serving nothing).
    rig.round(driver.render(_records(1)))
    rig.round(payload)
    state = rig.snapshot()
    _assert_identity(state, expect, 1, {"Gen": 1})
    assert not state["collections"]["identity"]["stale"], (
        f"[{expect}] 'unmarked' means unmarked: a severed stream established "
        "nothing, including staleness"
    )
    assert [(r["collection"], r["reason"]) for r in state["rejections"]] == [("", reason)], (
        f"[{expect}] recorded {state['rejections']}, want one batch-level {reason!r}"
    )
    assert state["acked"] == {"batch-1"}, f"[{expect}] acks {state['acked']}"

    # The dead collector stays dead; the next spawn answers. Generation 2
    # was issued durably to the severed batch and is never reused.
    rig.round(driver.render(_records(3)))
    _assert_identity(rig.snapshot(), expect, 3, {"Gen": 3})


def _boundary_mid_object(rig: _Rig, expect: str) -> None:
    records = _records(2)
    intact = driver.render(records[:1])
    # The object line dies partway through its own bytes, newline never
    # written — what the collator reads when the collector was killed
    # mid-record.
    partial = json.dumps(records[1]).encode()[:40]
    _severed_collector_boundary(rig, expect, intact + partial, "unparseable-record")


def _boundary_pre_commit(rig: _Rig, expect: str) -> None:
    # Every record before the commit arrives whole; the commit never does.
    # The batch's last complete line is the last object — the exact bytes of
    # a collector killed after its final read and before its commit.
    _severed_collector_boundary(rig, expect, driver.render(_records(2)[:2]), "missing-end")


# ── collator kills: SE_CRASH_AT, then a restart reads the wreckage ───────


def _crashed_round_2(rig: _Rig, crash_at: str) -> None:
    rig.round(driver.render(_records(1)))
    _assert_identity(rig.snapshot(), "clean run", 1, {"Gen": 1})
    # 137 is SIGKILL's exit status: the death must land AT the boundary.
    rig.round(driver.render(_records(2)), crash_at=crash_at, want_exit=137)


def _boundary_post_commit_pre_apply(rig: _Rig, expect: str) -> None:
    _crashed_round_2(rig, "post-commit-pre-apply")
    state = rig.snapshot()
    _assert_identity(state, expect, 1, {"Gen": 1})
    assert state["rejections"] == [], f"[{expect}] a crash is not a refusal: {state['rejections']}"
    assert state["acked"] == {"batch-1"}, f"[{expect}] acks {state['acked']}"

    # "the batch is re-run": the restart re-acquires. Going back to the
    # interface is a fresh acquisition, so it takes a fresh generation —
    # 3, because the crashed 2 was issued durably and is never reused.
    rig.round(driver.render(_records(3)))
    _assert_identity(rig.snapshot(), expect, 3, {"Gen": 3})


def _boundary_mid_apply(rig: _Rig, expect: str) -> None:
    _crashed_round_2(rig, "mid-apply")
    # Death lands inside the durable transaction, after every write and
    # before COMMIT: the restart must find generation 1 whole — generation
    # 2's already-written rows rolled away with the journal, no partial set.
    state = rig.snapshot()
    _assert_identity(state, expect, 1, {"Gen": 1})
    assert state["acked"] == {"batch-1"}, f"[{expect}] acks {state['acked']}"

    rig.round(driver.render(_records(3)))
    _assert_identity(rig.snapshot(), expect, 3, {"Gen": 3})


def _boundary_post_apply_pre_ack(rig: _Rig, expect: str) -> None:
    _crashed_round_2(rig, "post-apply-pre-ack")
    state = rig.snapshot()
    _assert_identity(state, expect, 2, {"Gen": 2})
    assert state["acked"] == {"batch-1"}, (
        f"[{expect}] the acknowledgement is exactly what the crash lost: {state['acked']}"
    )

    # "a re-sent identical batch at the same generation is a no-op" — the
    # recovery for the lost ack. The collator re-running the request it
    # never acknowledged has no external seam yet (its restart takes a
    # fresh generation), so the driver winds the issued counter back one
    # and re-serves generation 2's byte-identical stream: same bytes, same
    # collector-minted batch id — the one retry the contract promises safe.
    driver.wind_issued(driver.db_path(rig.state_dir), "identity", 1)
    rig.round(driver.render(_records(2)))
    state = rig.snapshot()
    _assert_identity(state, expect, 2, {"Gen": 2})
    assert state["rejections"] == [], (
        f"[{expect}] a safe retry is not an incident: {state['rejections']}"
    )
    assert state["acked"] == {"batch-1", "batch-2"}, (
        f"[{expect}] the retry must land the acknowledgement the crash lost: {state['acked']}"
    )

    rig.round(driver.render(_records(3)))
    _assert_identity(rig.snapshot(), expect, 3, {"Gen": 3})


_SCENARIOS = {
    "mid-object": _boundary_mid_object,
    "pre-commit": _boundary_pre_commit,
    "post-commit-pre-apply": _boundary_post_commit_pre_apply,
    "mid-apply": _boundary_mid_apply,
    "post-apply-pre-ack": _boundary_post_apply_pre_ack,
}


@pytest.mark.parametrize("boundary", BOUNDARIES, ids=lambda b: b["id"])
def test_boundary(boundary: dict, request) -> None:
    if boundary["id"] in LATER:
        pytest.skip(LATER[boundary["id"]])
    rig = request.getfixturevalue("rig")
    _SCENARIOS[boundary["id"]](rig, boundary["expect"])
