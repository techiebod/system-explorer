"""A prefix two collections declare costs the KIND, never the host.

The estate's own declarations contain one: `units` and `workloads` both
declare `unit`. Until 2026-08-23 a contested prefix returned an error
from the batch apply, so a host running both collectors applied NOTHING
— measured on the Debian lab guest that day: 52 collections issued, 0
objects stored, every page reading "never read", and every log line
naming a relation problem rather than the outage it actually was.

DESIGN's rule is unchanged — "two collections declaring one prefix is
refused rather than resolved to whichever was read last", and the
contested kind still resolves to nothing. What changed is the blast
radius, to the one the collator applies everywhere else: one bad thing
must not cost the host its other facts.

This drives the REAL binary through the fixture driver, because the
prefix index is built in AcquireOnce and a test calling the collection
apply directly never reaches it. A Go test that did exactly that passed
with the defect restored.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "harness"))
from collator import driver  # noqa: E402

BOOT = "5e000000-0000-4000-8000-000000000001"


def _decl(collector: str, collection: str, prefix: str) -> bytes:
    return json.dumps({
        "schema": "se.declaration/1", "collector": collector,
        "collections": [{
            "name": collection, "freshness": "1h", "prefix": prefix,
            "facts": {"State": {"type": "string", "temperament": "state"}},
        }],
    }, separators=(",", ":")).encode()


def _stream(decl: bytes, collection: str, batch: str = "b1",
            gen: int = 1) -> bytes:
    digest = "sha256:" + hashlib.sha256(decl).hexdigest()
    records = [
        {"record": "begin", "request": batch, "batch": batch,
         "declaration": digest, "boot_id": BOOT, "timens": 0,
         "instance": None, "generations": {collection: gen}},
        {"record": "object", "collection": collection, "name": "thing",
         "facts": {"State": "up"}, "at": 10.5},
        {"record": "commit", "collection": collection, "generation": gen,
         "objects": 1, "assertions": 0, "unobservable": 0, "cpu_ms": 0.5},
        {"record": "end", "request": batch, "batch": batch,
         "cpu_ms": 0.5, "wall_ms": 1.0},
    ]
    return b"".join(json.dumps(r).encode() + b"\n" for r in records)


def test_a_contested_prefix_does_not_cost_the_host_every_fact():
    # Two collectors on one host, both declaring the prefix `unit` — the
    # estate's own units/workloads clash, reproduced.
    first = _decl("units", "units", "unit")
    second = _decl("resources", "workloads", "unit")
    binary = driver.collate_binary()
    with tempfile.TemporaryDirectory() as state:
        a = driver.FakeCollector(first)
        b = driver.FakeCollector(second)
        try:
            # Distinct batch ids per collector: a batch id is unique to
            # the HOST, not to the collector, and the collator refuses a
            # reused one — which is correct and cost this test a round.
            a.queue(_stream(first, "units", batch="units-1"))
            b.queue(_stream(second, "workloads", batch="workloads-1"))
            run = driver.run_oneshot(binary, state,
                                     {"units": a.socket_path,
                                      "workloads": b.socket_path})
            assert run.returncode == 0, run.stderr[-800:]
            # A SECOND round, and it is the whole test. On the first
            # round the store holds no rival declaration yet, so whichever
            # collector runs first applies before the clash exists — and
            # an assertion that merely finds "some objects" passes with
            # the defect fully restored. The guest's 0-of-52 was a host
            # whose store already held every declaration, which is every
            # round after the first.
            a.queue(_stream(first, "units", batch="units-2", gen=2))
            b.queue(_stream(second, "workloads", batch="workloads-2", gen=2))
            again = driver.run_oneshot(binary, state,
                                       {"units": a.socket_path,
                                        "workloads": b.socket_path})
            assert again.returncode == 0, again.stderr[-800:]
            snapshot = driver.snapshot(driver.db_path(state))
            stderr = (run.stderr or "") + (again.stderr or "")
        finally:
            a.close()
            b.close()

    applied = {name: entry["generation"]
               for name, entry in (snapshot.get("collections") or {}).items()}
    # BOTH, at the second generation. "Some objects landed" is satisfied
    # by whichever collector won the first round and proves nothing.
    assert applied.get("units") == 2 and applied.get("workloads") == 2, (
        "a contested prefix cost the host its facts: this is the guest's "
        "0-of-52 outage, where every declaration was already in the store "
        f"and nothing applied. applied generations: {applied}\n"
        f"the collator said: {stderr[-900:]}")
    objects = snapshot.get("objects") or []
    assert len(objects) == 2, (
        f"both collections keep their objects: {objects}")
