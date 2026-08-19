"""Acceptance items 2, 4 and 5, driven through the collator fixture harness.

The subject is the real se-collate binary: harness/collator/driver.py serves
each fixture's recorded streams from a fake collector unix socket, runs the
binary against it, and judges the fixture's `expect` block exhaustively
against the durable store (and the read API where the fixture says so). The
fixture format is harness/collator/README.md's; the driver is the one that
README promised.

Two guards keep this suite from quietly judging less than it claims:

- The fixture roster is pinned by name and acceptance item. Parametrising
  over a glob alone would let a deleted fixture shrink coverage silently —
  the subset-guard failure, again.
- The judge is self-tested against fixtures that must fail (README.md: "so
  the judge is known to discriminate before it judges anything real"), and
  the loader against fixtures it must refuse. A judge that cannot red
  proves nothing about the runs it greens.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from collator import driver

REAL, SELF_TESTS = driver.discover()

# The pinned roster: every scenario the acceptance items require, by name.
# A new fixture registers here deliberately; a deleted one fails loudly.
REQUIRED = {
    # item 2 — every decline reason produces exactly its declared authority
    # effect: absent commits empty and retires; each other reason, exercised
    # by its own fixture, leaves prior state marked stale. And a decline
    # closes its collection: a record trailing in AFTER one refuses the
    # batch — the second direction of the ordering guard, whose first
    # (records-then-decline) the wire refused from the start.
    "absent-retires": 2,
    "unavailable-leaves-stale": 2,
    "unauthorised-leaves-stale": 2,
    "unsupported-leaves-stale": 2,
    "record-after-decline-refused": 2,
    # item 4 — concurrent, duplicated and replayed batches can never move a
    # collection's state backward. The batch-id pair holds §19's retry
    # ruling from both sides: same-bytes-same-id stays a silent no-op, and
    # a FRESH batch under an acked id is a recorded protocol error rather
    # than a silent skip that disables every future acquisition.
    "below-refused": 4,
    "equal-same-noop": 4,
    "equal-different-protocol-error": 4,
    "concurrent-newest-wins": 4,
    "batch-id-retry-noop": 4,
    "fresh-batch-same-id-is-an-error": 4,
    # item 5 — a six-second acquisition never reports itself fresher than
    # its oldest contributing read; and an age is same-domain arithmetic,
    # so a cross-boot stamp is a stated mismatch, never a subtraction.
    "oldest-read-wins": 5,
    "cross-boot-age-is-stated": 5,
    # item 6 — every relation state reached, and an upgrade that never
    # re-keys. These arrived 2026-08-19, when the loader stopped refusing
    # relation expectations on a reason that had been false since
    # store/relations.go landed: until then item 6 was judged only in
    # process, by tests in the same language as the subject, while the tier
    # built to be independent of it refused every fixture that would have
    # exercised it. The absent state is the retirement case; unresolved and
    # resolved-later are one fixture because the upgrade is the point.
    "relation-resolves-later-without-re-keying": 6,
    "relation-parallel-edges-survive-their-discriminator": 6,
    "relation-confirmed-contradicted-and-unconfirmable": 6,
    "relation-retired-by-a-committed-collection": 6,
}

REQUIRED_SELF_TESTS = {"self-test-unlisted-object", "self-test-wrong-fact",
                       "self-test-unlisted-relation"}


def test_the_required_scenarios_exist() -> None:
    """The roster is exact in both directions: nothing missing, nothing
    unregistered. An unregistered fixture would run un-vouched-for; a
    missing one would be coverage lost without a red."""
    assert {f.name: f.acceptance_item for f in REAL} == REQUIRED
    assert {f.name for f in SELF_TESTS} == REQUIRED_SELF_TESTS


@pytest.mark.parametrize("fixture", REAL, ids=lambda f: f.name)
def test_fixture_holds(fixture: driver.Fixture) -> None:
    driver.run_fixture(fixture)


@pytest.mark.parametrize("fixture", SELF_TESTS, ids=lambda f: f.name)
def test_the_judge_reds_the_must_fail_fixture(fixture: driver.Fixture) -> None:
    """README.md: the judge is known to discriminate before it judges
    anything real. Each self-test fixture states in must_fail why it must
    red; a judge that greens it would green an invented object next."""
    with pytest.raises(AssertionError):
        driver.run_fixture(fixture)
    # And the red must be a judgement, not a defective fixture: a
    # FixtureError escaping run_fixture would have failed the raises above
    # with the wrong exception, so reaching here proves the split held.


# ── the loader discriminates ─────────────────────────────────────────────
#
# Each case below is a fixture the loader must REFUSE — a distinct defect,
# each of which would otherwise let a fixture judge less than it appears
# to. FixtureError, not AssertionError: a broken fixture must never be
# mistakable for a judged red, or the must-fail self-test above becomes
# circular.

_DECL = '{"schema":"se.declaration/1","collector":"fixture","collections":[{"name":"pools","freshness":"1h"}]}'
_HASH = "sha256:" + hashlib.sha256(_DECL.encode()).hexdigest()


def _valid_doc() -> dict:
    batch = "batch-1"
    return {
        "name": "loader-case",
        "acceptance_item": 2,
        "note": "a syntactically complete fixture for the loader cases to corrupt",
        "declaration": _DECL,
        "streams": [
            {
                "records": [
                    {"record": "begin", "request": batch, "batch": batch,
                     "declaration": _HASH,
                     "boot_id": "5e000000-0000-4000-8000-000000000001",
                     "timens": 0, "instance": None, "generations": {"pools": 1}},
                    {"record": "object", "collection": "pools", "name": "tank",
                     "facts": {"Health": "ONLINE"}, "at": 10.5},
                    {"record": "commit", "collection": "pools", "generation": 1,
                     "objects": 1, "assertions": 0, "unobservable": 0},
                    {"record": "end", "request": batch, "batch": batch,
                     "cpu_ms": 0.5, "wall_ms": 1.0},
                ]
            }
        ],
        "expect": {
            "objects": [{"collection": "pools", "id": "pools:tank", "name": "tank",
                         "facts": {"Health": "ONLINE"}}],
            "relations": [],
            "collections": [{"name": "pools", "generation": 1, "stale": False}],
            "rejected": [],
            "acked": ["batch-1"],
        },
    }


def _write(tmp_path: Path, doc: dict) -> Path:
    path = tmp_path / f"{doc['name']}.json"
    path.write_text(json.dumps(doc))
    return path


def test_the_re_key_invariant_fires_when_a_key_moves() -> None:
    """The reversion for _assert_never_re_keyed.

    It runs over the rounds of every sequential fixture, so it reports
    success on all of them — and would report exactly the same success if it
    compared nothing at all, which is the guard shape this repository has
    been caught by more than once. Handed a history where one edge's identity
    is unchanged and its key is not, it must red; handed a stable one it must
    not."""
    identity = ("rules", "", "rule-1", "member-of", "chain", "chain-1", "null")
    synthetic = SimpleNamespace(name="synthetic")

    driver._assert_never_re_keyed(synthetic, [{identity: "rel-a"}, {identity: "rel-a"}])

    with pytest.raises(AssertionError, match="re-keyed"):
        driver._assert_never_re_keyed(
            synthetic, [{identity: "rel-a"}, {identity: "rel-b"}])


def test_the_baseline_loader_case_itself_loads(tmp_path: Path) -> None:
    """The corruption cases below prove nothing if the document they corrupt
    was never loadable — refusing garbage twice over is not discrimination."""
    driver.load_fixture(_write(tmp_path, _valid_doc()))


def test_loader_refuses_a_wrong_declaration_hash(tmp_path: Path) -> None:
    doc = _valid_doc()
    doc["streams"][0]["records"][0]["declaration"] = "sha256:" + "0" * 64
    with pytest.raises(driver.FixtureError, match="hash"):
        driver.load_fixture(_write(tmp_path, doc))


def test_loader_refuses_an_unknown_member(tmp_path: Path) -> None:
    doc = _valid_doc()
    doc["surprise"] = True
    with pytest.raises(driver.FixtureError, match="unknown members"):
        driver.load_fixture(_write(tmp_path, doc))


def test_loader_refuses_an_illegal_stream_record(tmp_path: Path) -> None:
    """A null fact value is the contract's canonical illegal record: a
    fixture carrying one would be judging the collator against a stream no
    collector may emit."""
    doc = _valid_doc()
    doc["streams"][0]["records"][1]["facts"] = {"Health": None}
    with pytest.raises(driver.FixtureError, match="not a legal stream record"):
        driver.load_fixture(_write(tmp_path, doc))


def test_loader_refuses_an_expectation_nothing_judges(tmp_path: Path) -> None:
    """expect.opinions would pass vacuously — the store holds no opinions —
    so a fixture naming one must be refused, not greened.

    `relations` was in this tuple with it until 2026-08-19 and had stopped
    belonging there when store/relations.go landed; the pair of tests below
    is what now proves the loader discriminates on that member instead of
    refusing it wholesale."""
    doc = _valid_doc()
    doc["expect"]["opinions"] = [{"object": "pools:tank", "key": "x", "level": "warn"}]
    with pytest.raises(driver.FixtureError, match="cannot be judged yet"):
        driver.load_fixture(_write(tmp_path, doc))


def test_loader_accepts_a_well_formed_relation_expectation(tmp_path: Path) -> None:
    """The reversion for the two refusal cases below: a loader that refused
    every relation expectation would pass both of them and judge nothing,
    which is exactly the state this member was in until 2026-08-19."""
    doc = _valid_doc()
    doc["expect"]["relations"] = [{
        "collection": "pools", "source_name": "tank", "type": "backed-by",
        "target_kind": "device", "target_name": "sda", "resolved": False,
        "observability": "asserted",
    }]
    driver.load_fixture(_write(tmp_path, doc))


def test_loader_refuses_a_relation_missing_what_it_must_state(tmp_path: Path) -> None:
    """`observability` unstated would leave the one distinction the founding
    incident turned on — asserted versus confirmed — unjudged on that edge."""
    doc = _valid_doc()
    doc["expect"]["relations"] = [{
        "collection": "pools", "source_name": "tank", "type": "backed-by",
        "target_kind": "device", "target_name": "sda", "resolved": False,
    }]
    with pytest.raises(driver.FixtureError, match="missing required members"):
        driver.load_fixture(_write(tmp_path, doc))


def test_loader_refuses_an_unknown_relation_member(tmp_path: Path) -> None:
    """A misspelled member would silently assert nothing."""
    doc = _valid_doc()
    doc["expect"]["relations"] = [{
        "collection": "pools", "source_name": "tank", "type": "backed-by",
        "target_kind": "device", "target_name": "sda", "resolved": False,
        "observability": "asserted", "observabillity": "confirmed",
    }]
    with pytest.raises(driver.FixtureError, match="unknown members"):
        driver.load_fixture(_write(tmp_path, doc))


def test_loader_requires_the_exhaustive_expect_members(tmp_path: Path) -> None:
    """An omitted `acked` (or objects, relations, collections, rejected) would
    be an unjudged surface; the loader demands all five stated, even when
    empty."""
    doc = _valid_doc()
    del doc["expect"]["acked"]
    with pytest.raises(driver.FixtureError, match="missing required members"):
        driver.load_fixture(_write(tmp_path, doc))


def test_loader_refuses_winding_before_any_round(tmp_path: Path) -> None:
    doc = _valid_doc()
    doc["streams"][0]["wind_issued"] = {"pools": 0}
    with pytest.raises(driver.FixtureError, match="before any round"):
        driver.load_fixture(_write(tmp_path, doc))


def test_loader_refuses_a_name_that_argues_with_its_filename(tmp_path: Path) -> None:
    doc = _valid_doc()
    path = tmp_path / "differently-named.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(driver.FixtureError, match="filename"):
        driver.load_fixture(path)


# ── three artifacts, one boundary ────────────────────────────────────────
#
# The stream is judged by three independent artifacts: the contract schema
# (per record), check_stream (the replay judge), and the Go collator (the
# wire, driven as a binary). Phase 2's fresh-eyes review found them
# disagreeing at three boundaries — a negative cost applied by one and
# refused by another, at == 1e9 legal in two courtrooms and refused in the
# third. This section IS the guard against that class recurring: for each
# boundary stream all three verdicts are computed and must agree, and a
# disagreement names the odd one out. Rules that are cross-record by
# nature (decline ordering) exempt the per-record schema EXPLICITLY — an
# exemption stated in the case, not discovered in a debugger.

from se_harness import replay  # noqa: E402  (the alignment cases drive check_stream)

_BOOT = "5e000000-0000-4000-8000-000000000001"
_ALIGN_DECL = _DECL.encode()


def _batch(middle: list[dict], end_overrides: dict | None = None) -> list[dict]:
    """begin..end around `middle`, legal but for the boundary under test."""
    end = {"record": "end", "request": "batch-1", "batch": "batch-1",
           "cpu_ms": 0.5, "wall_ms": 1.0}
    end.update(end_overrides or {})
    return [
        {"record": "begin", "request": "batch-1", "batch": "batch-1",
         "declaration": _HASH, "boot_id": _BOOT, "timens": 0, "instance": None,
         "generations": {"pools": 1}},
        *middle,
        end,
    ]


def _object(at: float) -> dict:
    return {"record": "object", "collection": "pools", "name": "tank",
            "facts": {"Health": "ONLINE"}, "at": at}


def _commit(objects: int = 1, assertions: int = 0) -> dict:
    return {"record": "commit", "collection": "pools", "generation": 1,
            "objects": objects, "assertions": assertions, "unobservable": 0,
            "cpu_ms": 0.5}


# Each case: (records, the agreed verdict, schema_exempt, why).
_BOUNDARY_CASES = {
    "negative-measured-cost": (
        _batch([_object(10.5), _commit()], {"cpu_ms": -1.0}),
        "refuses", False,
        "a cost below zero came off no clock; bounded (never authenticated) "
        "by all three artifacts",
    ),
    "at-exactly-1e9": (
        _batch([_object(1000000000.0), _commit()]),
        "accepts", False,
        "the contract's maximum is inclusive; the boundary point is legal "
        "in every courtroom or legal in none",
    ),
    "nested-null-fact": (
        _batch([_object(10.5), _commit()]),
        "refuses", False,
        "a fact value is never null at any depth; value, absent and "
        "unobservable each have their own channel",
    ),
    "decline-after-records": (
        _batch([
            _object(10.5),
            {"record": "decline", "collection": "pools", "reason": "unavailable"},
        ]),
        "refuses", True,
        "a collection that emitted cannot also decline. The schema is "
        "EXEMPT: it judges one record at a time, and this rule is a "
        "relation between records — check_stream and the wire hold it",
    ),
}
# The null is injected after construction so the helper stays null-free.
_BOUNDARY_CASES["nested-null-fact"][0][1]["facts"] = {
    "Vdevs": [{"Name": "raidz1-0", "State": None}]
}


def _schema_verdict(records: list[dict]) -> str:
    validator = driver._stream_validator()
    bad = [e for record in records for e in validator.iter_errors(record)]
    return "refuses" if bad else "accepts"


def _check_stream_verdict(records: list[dict]) -> str:
    return "refuses" if replay.check_stream(records, {"pools": 1}) else "accepts"


def _collator_verdict(records: list[dict], tmp: Path) -> str:
    """The wire, driven as the binary systemd would spawn: an accepted
    batch applies and acknowledges; a refused one records its violation
    and acknowledges nothing."""
    fake = driver.FakeCollector(_ALIGN_DECL)
    try:
        fake.queue(driver.render(records))
        proc = driver.run_oneshot(
            driver.collate_binary(), str(tmp), {"c0": fake.socket_path})
        assert proc.returncode == 0, proc.stderr
        fake.check()
        state = driver.snapshot(driver.db_path(str(tmp)))
        return "accepts" if state["acked"] else "refuses"
    finally:
        fake.close()


@pytest.mark.parametrize("case", sorted(_BOUNDARY_CASES), ids=str)
def test_the_three_artifacts_agree_at_the_boundary(case: str, tmp_path: Path) -> None:
    records, want, schema_exempt, why = _BOUNDARY_CASES[case]
    verdicts = {
        "check_stream": _check_stream_verdict(records),
        "collator": _collator_verdict(records, tmp_path),
    }
    if not schema_exempt:
        verdicts["schema"] = _schema_verdict(records)
    odd = [name for name, verdict in verdicts.items() if verdict != want]
    assert not odd, (
        f"{case}: {', '.join(odd)} disagree(s) with the ruled verdict "
        f"{want!r} ({verdicts}) — {why}"
    )
