"""Both directions of an accepted divergence, and the asymmetry that
keeps each discriminating.

`se-compare` could express only one: facts the REFERENCE emits and the
port is not asked to (ACCEPTED_DIVERGENCES). The first whole-surface run
produced the other — `system/identity` emits four os-release facts the
reference does not — and there was no way to record a ruling for it.

**The asymmetry is the point in both directions.** An accepted set is
removed from ONE side only, so the other side emitting a listed fact is
itself reported. Strip both and a port that published a fact a ruling put
out of its scope would be invisible.

PORT_ONLY_DIVERGENCES shipped EMPTY until the ruling was taken on
2026-08-23 (port wins). Whether a port's scope may exceed the reference's
is what DESIGN §20 reserves for the owner, so the guard could not stay
"the table is empty" — that assertion expires the moment a ruling exists,
and deleting it would leave the table unguarded exactly when it first has
something in it. It becomes **every entry is a ruling**: carrying its
words, and findable in PLAN, so an entry cannot be a convenience someone
added to make a run go green.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def comparator():
    spec = importlib.util.spec_from_loader(
        "se_compare",
        importlib.machinery.SourceFileLoader(
            "se_compare", str(REPO / "harness" / "bin" / "se-compare")))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_port_only_entry_carries_its_ruling() -> None:
    """An entry is a RULING, not a convenience.

    The move this exists to make visible is someone widening the port's
    scope by editing a dict to turn a red run green. A ruling has words
    and a date; a convenience has neither, so requiring the words is what
    separates them.
    """
    for collector, entry in comparator().PORT_ONLY_DIVERGENCES.items():
        assert set(entry) == {"facts", "ruling"}, (
            f"{collector}: an entry carries exactly its facts and the "
            f"ruling that put them there, got {sorted(entry)}")
        assert entry["facts"], f"{collector}: an empty fact set rules nothing"
        # Long enough to be a reason rather than a label. A one-word
        # "approved" satisfies a shape check and tells the next reader
        # nothing about why the port's scope was allowed to exceed.
        assert len(entry["ruling"]) > 120, (
            f"{collector}: the ruling must say WHY the port's scope may "
            f"exceed the reference's, not merely that it may")
        assert "Ruled 20" in entry["ruling"], (
            f"{collector}: a ruling carries the date it was taken — an "
            f"undated one cannot be checked against the record in PLAN")


def test_every_port_only_ruling_is_findable_in_the_plan() -> None:
    """The record and the table must not be able to drift apart.

    A ruling that lives only in a dict is a decision nobody can find; one
    that lives only in PLAN is a decision the tool does not implement.
    """
    plan = (REPO / "docs" / "PLAN.md").read_text()
    for collector, entry in comparator().PORT_ONLY_DIVERGENCES.items():
        for fact in entry["facts"]:
            assert fact in plan, (
                f"{collector}: `{fact}` is stripped from the port by a "
                f"ruling that PLAN does not record, so the only account of "
                f"why lives in a dict nobody reads")


def test_each_direction_strips_one_side_only() -> None:
    """The asymmetry, asserted on the code rather than described.

    Stripping both sides would hide the case each table exists to
    surface: a port emitting a fact a ruling put out of its scope, or a
    reference emitting one the port owns.
    """
    source = (REPO / "harness" / "bin" / "se-compare").read_text()
    assert "reference = [_without(record, accepted[\"facts\"])" in source, (
        "an accepted divergence is removed from the REFERENCE")
    assert "port = [_without(record, port_only[\"facts\"])" in source, (
        "a port-only divergence is removed from the PORT")
    # And each reports the OTHER side emitting a listed fact.
    assert "port_emitted_accepted" in source
    assert "reference_emitted_accepted" in source


def test_a_divergence_on_an_unlisted_fact_still_fails() -> None:
    """The property the acceptance must not widen into. Both tables are
    per-collector and per-fact, so nothing about them makes an unrelated
    difference pass."""
    module = comparator()
    stripped = module._without(
        {"record": "object", "facts": {"Kept": 1, "Dropped": 2}},
        frozenset({"Dropped"}))
    assert stripped["facts"] == {"Kept": 1}, stripped
    untouched = module._without(
        {"record": "object", "facts": {"Kept": 1}}, frozenset({"Absent"}))
    assert untouched["facts"] == {"Kept": 1}


def test_the_nix_ruling_is_still_the_only_accepted_one() -> None:
    """Anti-vacuity for the direction that IS populated: if this set ever
    empties, every ruled scope decision would start reporting as a defect
    and the report stops being read."""
    accepted = comparator().ACCEPTED_DIVERGENCES
    assert set(accepted) == {"nix"}, sorted(accepted)
    assert len(accepted["nix"]["facts"]) == 5
    assert "2026-08-19" in accepted["nix"]["ruling"], (
        "a ruling names when it was taken")
