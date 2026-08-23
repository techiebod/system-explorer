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

PORT_ONLY_DIVERGENCES ships EMPTY. Whether a port's scope may exceed the
reference's is what DESIGN §20 reserves for the owner; the mechanism
exists so that ruling is one entry rather than a change to the tool.
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


def test_the_port_only_table_ships_empty() -> None:
    """A ruling nobody made must not arrive as a populated table.

    If this ever fails, someone widened the port's scope by editing a
    dict rather than by taking a ruling — which is exactly the move the
    mechanism was built to make visible.
    """
    assert comparator().PORT_ONLY_DIVERGENCES == {}, (
        "PORT_ONLY_DIVERGENCES holds an entry: whether a port's scope may "
        "exceed the reference's is the owner's ruling under §20, and an "
        "entry here is that ruling. Record it in PLAN when it is taken.")


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
