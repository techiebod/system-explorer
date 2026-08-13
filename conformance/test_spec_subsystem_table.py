"""SPEC section 4's table is a contract, so it gets teeth like the rest.

This check exists because the table had drifted badly and silently: ten of
twenty subsystems had no row at all — the entire application tier plus
protection — and `network` had gained three collections without gaining a
mention. Nothing could have caught it. The suite lints adapters against the
spec everywhere else; the one document describing what the product observes
was the one thing nobody validated.

Deliberately ONE-DIRECTIONAL. Every subsystem an adapter serves must have a
row, and every collection it declares must appear in that row — but a name in
the table with no adapter behind it is allowed, because that is how a planned
collection is declared ahead of its acquisition (`conntrack-summary` is the
worked example, and it is published as unavailable-with-a-reason rather than
silently missing). Enforcing the reverse would make the spec unable to
describe anything the code has not caught up with yet, which is backwards for
a document the code is supposed to follow.
"""

from __future__ import annotations

import re

import pytest

from common import PACKAGE_DIR
from system_explorer.agent.adapters import build_adapters

SPEC = PACKAGE_DIR.parent.parent / "docs" / "SPEC.md"
ADAPTERS = build_adapters()


def subsystem_table() -> dict[str, set[str]]:
    """{subsystem: collections named in its row}, parsed from the markdown.

    The parse is deliberately literal — a row is a line whose first cell is a
    backticked name — so a table that stops looking like a table fails loudly
    here rather than quietly matching nothing.
    """
    text = SPEC.read_text()
    start = text.index("## 4. Subsystems v1")
    end = text.index("\nNotes:", start)
    rows: dict[str, set[str]] = {}
    for line in text[start:end].splitlines():
        match = re.match(r"^\|\s*`([a-z0-9-]+)`\s*\|([^|]*)\|", line)
        if not match:
            continue
        rows[match.group(1)] = set(re.findall(r"`([a-z0-9-]+)`", match.group(2)))
    return rows


def test_the_table_still_parses_as_a_table():
    """Anti-vacuity: every check below is driven by this parse, so a parse
    that found nothing would make all of them pass for ever."""
    rows = subsystem_table()
    assert len(rows) >= 15, f"only parsed {len(rows)} rows; the format moved"
    assert "units" in rows and "units" in rows["units"]


@pytest.mark.parametrize("subsystem", sorted(ADAPTERS))
def test_every_subsystem_an_adapter_serves_has_a_row(subsystem):
    rows = subsystem_table()
    assert subsystem in rows, (
        f"adapters/{subsystem}.py serves a subsystem SPEC section 4 does not "
        "list. The table is the product's account of what it observes; a "
        "subsystem shipped without a row is one nobody outside this "
        "repository can discover."
    )


@pytest.mark.parametrize("subsystem", sorted(ADAPTERS))
def test_every_collection_appears_in_its_subsystems_row(subsystem):
    rows = subsystem_table()
    declared = set(ADAPTERS[subsystem].collections())
    missing = sorted(declared - rows.get(subsystem, set()))
    assert not missing, (
        f"{subsystem} serves {missing} and SPEC section 4 does not name them. "
        "A collection absent from the table is one an operator cannot find "
        "and a reviewer cannot check the privilege claim of."
    )


def test_a_planned_collection_may_be_listed_ahead_of_its_adapter():
    """The one-directional rule, made explicit rather than left as an absence
    of a test. `conntrack-summary` is in the table and in no collections()
    list; it is published as unavailable-with-a-reason, which is how this
    product declares work it has named and not built."""
    rows = subsystem_table()
    assert "conntrack-summary" in rows["network"]
    assert "conntrack-summary" not in set(ADAPTERS["network"].collections())


def test_the_table_says_who_holds_it():
    """A check nobody knows about is a check that gets deleted in a hurry.
    The prose beside the table has to name the fact that conformance holds
    it, so the next person to add a subsystem finds out from the document
    rather than from a red build."""
    text = SPEC.read_text()
    assert "held by conformance" in text
