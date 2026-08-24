"""The estate page's marks, and the states it must not collapse.

Every defect here was found by reading the REAL rendered hub page from a
live lab, not by reading the code — and each had shipped because the
assertion that would have caught it did not exist.

The rule underneath all three is DESIGN §27's: a renderer may not decide
what something MEANS. A two-entry severity table in a renderer is the
forbidden fourth copy however few entries it has, and a state whose mark
does not exist renders as neutrality, which SPEC §8 calls re-asserting
the judgement the agent withheld.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from system_explorer.hub.checkpoint import Reach  # noqa: E402
from system_explorer.surface import render  # noqa: E402

TOKENS = (REPO / "src" / "system_explorer" / "surface" / "tokens.css").read_text()


class _Coverage:
    declared = ["lab-a"]
    discovered_not_declared: list = []
    unclassified: list = []
    sources_readable: list = []
    sources_unreadable: list = []


def _marks(html: str) -> dict:
    return {label: cls for cls, label
            in re.findall(r'class="chip ([a-z-]*)">([^<]*)', html)}


def test_every_reach_state_has_its_own_mark():
    # `"ok" if connected else "warn"` collapsed `unswept` and `dark`:
    # one is a gap in our looking, the other a fault on the estate, and
    # the estate page exists to tell them apart.
    html = render.reach_panel(
        {"a": Reach.CONNECTED.value, "b": Reach.DARK.value,
         "c": Reach.UNSWEPT.value}, _Coverage())
    marks = _marks(html)
    seen = {label.split(" · ")[1]: cls for label, cls in marks.items()}
    assert len({seen["connected"], seen["dark"], seen["unswept"]}) == 3, (
        f"two reach states share a mark: {seen}")
    assert seen["connected"] == "ok"
    assert seen["dark"] != seen["unswept"], (
        "never asked and asked-and-got-nothing must not render alike")


def test_the_reach_table_covers_the_whole_closed_enum():
    # Reach is closed, so the table can be complete — and a member added
    # later must not silently fall into whatever the default is.
    for member in Reach:
        assert member.value in render._REACH_MARK, (
            f"{member.value} has no mark, so it renders unstyled and reads "
            f"as neutral")


def test_an_unknown_reach_member_renders_unstyled_rather_than_guessed():
    # A newer hub's vocabulary is SHOWN, never assigned the nearest
    # severity this renderer happens to know.
    html = render.reach_panel({"a": "some-future-state"}, _Coverage())
    assert "some-future-state" in html
    assert 'class="chip "' in html or 'class="chip">' in html, html


def test_every_chip_class_the_page_emits_has_a_rule():
    # `degraded` and `healthy` both rendered as a bare neutral chip
    # because neither class existed in the stylesheet — the one mark
    # saying the estate is not well looked exactly like the one saying it
    # is. A mark with no rule is not a mark.
    emitted = {"degraded", "healthy"} | set(
        v for v in render._REACH_MARK.values() if v)
    for cls in sorted(emitted):
        assert f".chip.{cls}" in TOKENS, (
            f"the page emits class=\"chip {cls}\" and the stylesheet has no "
            f"rule for it, so that state renders as neutrality")


def test_a_structured_value_is_not_rendered_as_a_python_repr():
    # The estate page carried the literal text ['lab-a', 'lab-b'] — a
    # language's internal notation shown to an operator.
    out = render._as_read(["lab-a", "lab-b"])
    assert "[" not in out and "&#x27;" not in out, out
    assert "lab-a" in out and "lab-b" in out
    assert out.count("chip item") == 2


def test_an_empty_structured_value_is_measured_emptiness():
    # Not a missing value, and not a bare blank.
    out = render._as_read([])
    assert out.strip() != ""
    assert "none" in out
