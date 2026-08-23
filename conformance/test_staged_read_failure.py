"""A captured read that FAILED — the third state, and the newest.

A replay directory could say two things about a path: the payload is
absent (NOT CAPTURED — the seam refuses, because falling back would read
the filesystem of the machine replaying the corpus), or the payload is
`null` (the path did not exist, an ordinary reading the adapter degrades
through).

Neither is "the file was there and the read failed", and a whole class of
state turns on exactly that. resources' StallAttributionUnobservable
fires when a member cgroup's pressure could not be READ — so it had no
corpus coverage and never could have had any. The live comparator found
it once in five runs, by luck, which is how it was noticed at all.

`{"read_error": "EACCES"}` is that third state, and
corpus/resources/attribution-unreadable is the first variant to pose it.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
VARIANT = REPO / "corpus" / "resources" / "attribution-unreadable"


def collector():
    loader = importlib.machinery.SourceFileLoader(
        "se_reference_collector", str(REPO / "harness" / "bin" / "se-reference-collector"))
    spec = importlib.util.spec_from_loader("se_reference_collector", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_the_three_states_are_distinct() -> None:
    """Absent, null and failed must not collapse into each other. Each
    means something different about the machine, and the whole point of
    the marker is that the third had nowhere to live."""
    module = collector()
    # A failed read raises the errno it names.
    failure = module.staged_failure({"read_error": "EACCES"})
    assert isinstance(failure, PermissionError), failure
    # A null is a reading, not a failure.
    assert module.staged_failure(None) is None
    # And ordinary content is content, including content that happens to
    # be a mapping.
    assert module.staged_failure("some avg10=0.00") is None
    assert module.staged_failure({"other": "value"}) is None


def test_an_unknown_errno_still_fails_rather_than_passing() -> None:
    """A marker naming an errno this table does not know must not become
    a successful read — that would make a typo in a fixture silently
    stage the opposite of what it says."""
    module = collector()
    failure = module.staged_failure({"read_error": "ENOTAREALERRNO"})
    assert isinstance(failure, OSError), failure


def test_both_seams_honour_the_marker() -> None:
    """The two seam kinds, and only one has a variant using it.

    `dispatched` answers by argument (resources reads that way) and
    `by_path` answers out of one tree document (storage's md walk,
    hardware's sysfs). A plant that stopped `by_path` honouring the
    marker stayed GREEN, because no variant poses a failed read through
    that seam yet — so this asserts the code path directly rather than
    reporting coverage it does not have.
    """
    source = (REPO / "harness" / "bin" / "se-reference-collector").read_text()
    honoured = source.count("staged_failure(")
    assert honoured >= 3, (
        f"the marker is honoured in {honoured} places; both seam kinds "
        f"must raise it, or a fixture staging a failure through the "
        f"unhandled one would be read as ordinary content")
    # And each seam's own branch, named so a removal is visible.
    assert "staged_failure(inside[member])" in source, (
        "the tree seam (by_path) must honour a staged failure")
    assert "staged_failure(payloads[name])" in source, (
        "the argument seam (dispatched) must honour a staged failure")


def test_the_variant_stages_the_condition_and_nothing_else() -> None:
    """Anti-vacuity: the variant must actually pose the question. A
    fixture that stages a failure nothing reads proves nothing."""
    if not VARIANT.exists():
        pytest.skip("the variant is not in this tree")
    markers = [p for p in (VARIANT / "payloads").glob("*.txt")
               if p.read_text().strip().startswith('{"read_error"')]
    assert len(markers) == 1, (
        f"one staged failure, deliberately: {[p.name for p in markers]}")


def test_the_expectation_carries_the_unobservable_state() -> None:
    """And the corpus records what the condition produces — an unread
    member, worded as a gap in the reading rather than as a finding about
    the slice."""
    if not (VARIANT / "expected.jsonl").exists():
        pytest.skip("the variant is not in this tree")
    stated = None
    for line in (VARIANT / "expected.jsonl").read_text().splitlines():
        record = json.loads(line)
        if record.get("record") == "object" and record.get("name") == "system.slice":
            stated = (record.get("facts") or {}).get("StallAttributionUnobservable")
    assert stated, (
        "the variant exists to stage StallAttributionUnobservable; if this "
        "is empty the condition is no longer posed and the fixture is inert")
    assert "could not" in json.dumps(stated) or "no I/O pressure reading" in json.dumps(stated), stated
    # And NOT the unexplained wording: an unread member is not a quiet one.
    for line in (VARIANT / "expected.jsonl").read_text().splitlines():
        record = json.loads(line)
        if record.get("record") == "object" and record.get("name") == "system.slice":
            assert "StallUnexplained" not in (record.get("facts") or {}), (
                "reporting an unread member as 'nothing explains this' would "
                "invent the interesting finding out of a gap in the reading")
