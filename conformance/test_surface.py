"""The server-rendered estate page: escaping, vocabulary, and honesty.

The renderer is the producer, so §27's rule — the renderer knows nothing
the producer knows — is satisfied structurally. These tests hold that:
nothing here may decide a level, a sentence or a state word for itself,
and everything interpolated must be escaped, because once app-tier
collectors publish media titles an envelope carries text written by
strangers on the internet.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from system_explorer.hub.answer import estate_current
from system_explorer.hub.checkpoint import CollectionSnapshot, Estate, HostSnapshot
from system_explorer.hub.intent import Intent
from system_explorer.hub.rollup import HeldOpinion, assemble
from system_explorer.hub.session import Declarations
from system_explorer.surface import render

BOOT = "5e000000-0000-4000-8000-000000000001"
SURFACE = Path(__file__).resolve().parent.parent / "src" / "system_explorer" / "surface"


def declaration(*facts: str) -> dict:
    return {
        "schema": "se.declaration/1", "collector": "c", "version": "1.0.0",
        "collections": [{
            "name": "pools", "question": "q", "prefix": "pool", "freshness": "60s",
            "perishability": "perishable", "answer": list(facts),
            "facts": {f: {"type": "string", "temperament": "state", "kind": "observed",
                          "discloses": "nothing", "sentence": "."} for f in facts},
        }],
    }


def built(objects, facts=("State",)):
    estate = Estate(declared=("storage-1",))
    declarations = Declarations()
    declarations.add("storage-1", declaration(*facts), "sha256:x")
    estate.promote(HostSnapshot(
        host="storage-1", checkpoint="cp", boot_id=BOOT,
        collections={"pools": CollectionSnapshot(
            name="pools", generation=3, freshness="current", stale_reason=None,
            objects=tuple(objects))},
        declarations=("sha256:x",), history_gap=None))
    intent = Intent.load({
        "schema": "se.intent/1", "estate": "home", "revision": 1,
        "reviewed": "2026-08-20", "membership": {"hosts": {"storage-1": {}}}})
    view = assemble(estate, intent, declarations)
    return view, estate_current(view, estate, intent)


def test_third_party_text_cannot_escape_the_page() -> None:
    """A media title is written by a stranger on the internet and reaches
    this renderer verbatim. A page that trusted it would turn a read-only
    observer into a delivery mechanism."""
    hostile = '<script>alert("x")</script>'
    view, answer = built([{ "id": "pools:tank", "name": "tank", "instance": None,
                            "facts": {"State": hostile}}])
    html = render.estate_page(view, answer, [])
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_an_attribute_break_is_escaped_too() -> None:
    hostile = '" onmouseover="alert(1)'
    view, answer = built([{ "id": "pools:tank", "name": hostile, "instance": None,
                            "facts": {"State": hostile}}])
    html = render.estate_page(view, answer, [])
    assert 'onmouseover="alert' not in html
    assert "&quot;" in html


def test_grounds_renders_as_its_own_axis() -> None:
    """Our threshold must never look like the machine declaring its own
    fault. Level and grounds are separate marks, not one."""
    held = [
        HeldOpinion(host="storage-1", collection="pools", generation=3,
                    object_id="pools:tank", instance=None, key="k1", level="critical",
                    grounds="interface", sentence="ZFS says degraded.", cites=("State",)),
        HeldOpinion(host="storage-1", collection="pools", generation=3,
                    object_id="pools:scratch", instance=None, key="k2", level="warn",
                    grounds="threshold", sentence="Above 90% full.", cites=("State",)),
    ]
    view, answer = built([])
    html = render.estate_page(view, answer, held)
    assert 'class="grounds interface"' in html
    assert 'class="grounds threshold"' in html
    assert 'class="chip critical"' in html and 'class="chip warn"' in html


def test_an_unknown_level_still_renders() -> None:
    """A renderer switching on a closed set must treat an unknown member as
    unstyled, never as an error — otherwise one new vocabulary word takes
    the page down."""
    held = [HeldOpinion(host="h", collection="pools", generation=1,
                        object_id="pools:tank", instance=None, key="k",
                        level="apocalyptic", grounds="interface",
                        sentence="s", cites=("State",))]
    view, answer = built([])
    html = render.estate_page(view, answer, held)
    assert "apocalyptic" in html


def test_no_opinion_is_a_claim_about_judging_not_about_health() -> None:
    view, answer = built([])
    html = render.estate_page(view, answer, [])
    assert "statement about what was judged" in html, (
        "an empty page and a page reporting nothing wrong are the same "
        "pixels, and only one of them is a claim"
    )


def test_undeclared_facts_are_named_on_the_row() -> None:
    view, answer = built(
        [{"id": "pools:tank", "name": "tank", "instance": None,
          "facts": {"State": "ok", "Smuggled": "x"}}])
    html = render.estate_page(view, answer, [])
    assert "no declared axis" in html and "Smuggled" in html
    assert ">x<" not in html, "the value itself must not be rendered as a fact"


def test_coverage_is_rendered_as_identities() -> None:
    view, answer = built([])
    html = render.estate_page(view, answer, [])
    reach = html.split("<h2>Reach</h2>")[1].split("</section>")[0]
    assert "declared:" in reach and "storage-1" in reach
    # Scoped to the reach panel deliberately: the ANSWER sentence above it
    # may legitimately summarise ("2 of 2 could not answer"), and it names
    # each host beside the count. What must never be a bare count is the
    # coverage itself, because that is the list a reader checks their own
    # host against.
    assert not re.search(r"\b\d+ of \d+\b", reach), (
        "'six of six' tells a reader nothing they can check"
    )


def test_the_renderer_keeps_no_copy_of_a_published_vocabulary() -> None:
    """The fourth-copy rule, as a lint on this file. LEVEL_ORDER is a
    DISPLAY order and is allowed; a severity-to-colour table, a state
    table or a fact glossary would each be a second copy of something the
    declaration already carries."""
    source = (SURFACE / "render.py").read_text()
    for banned in ("VALUE_CLASS", "SEVERITY", "FACT_HELP", "GROUPS", "DOMAINS"):
        assert banned not in source, f"{banned} is a copy of what the producer knows"
    # LEVEL_ORDER is a sequence, and that is the point: a display order
    # carries no meaning about the levels, where a dict from level to
    # colour or to rank would be this file deciding something the
    # declaration already settled.
    assert isinstance(render.LEVEL_ORDER, tuple)
    assert "LEVEL_ORDER = {" not in source, "an order, never a mapping"
    assert not re.search(r'"(critical|warn|info)"\s*:', source), (
        "a level used as a dict key is a severity table by another name"
    )


def test_the_token_set_is_the_one_that_ships() -> None:
    """The design system was ruled to be the production token set, so a
    drift between the two is the ruling quietly lapsing."""
    tokens = (SURFACE / "tokens.css").read_text()
    shipping = (SURFACE.parent / "ui" / "styles.css").read_text()
    for token in ("--ok:", "--warn:", "--crit:", "--accent:", "--mono:"):
        assert token in tokens, f"{token} missing from the carried-forward set"
        assert token in shipping, f"{token} is not in the shipping set either"
    for value in ("#55b98a", "#e0b640", "#ef6d6d"):
        assert value in tokens and value in shipping, (
            f"{value} differs between the ruled token set and the one shipping"
        )
    assert "cdn" not in tokens.lower() and "@import" not in tokens, (
        "no external library: importing somebody else's vocabulary is the "
        "moment the product stops owning its own"
    )


def test_the_page_is_self_contained() -> None:
    view, answer = built([])
    html = render.estate_page(view, answer, [])
    assert "<style>" in html and "http" not in html.split("<style>")[1][:6000]
    assert html.startswith("<!doctype html>")


def test_both_scales_serve_one_token_set() -> None:
    """Two renderers in two languages, and neither toolchain can read the
    other's tree — so the token set exists as two artifacts of one truth
    and this is what makes drift a failure rather than a surprise.

    Stated as coverage rather than left implied: nothing prevents the two
    files diverging, and only this assertion notices.
    """
    canonical = (SURFACE / "tokens.css").read_bytes()
    embedded = (SURFACE.parent.parent.parent / "go" / "internal" / "collate"
                / "tokens.css").read_bytes()
    assert canonical == embedded, (
        "the collator's embedded token set has drifted from the canonical one; "
        "two design systems is what 'one token set' was ruled against"
    )


def test_a_plugins_own_state_word_renders_with_no_code_change() -> None:
    """The representation facet, structurally. The renderer switches on
    nothing, so a vocabulary this repository has never seen reaches the
    page the day a plugin publishes it."""
    view, answer = built(
        [{"id": "widgets:left", "name": "left", "instance": None,
          "facts": {"State": "wobbling-badly"}}])
    html = render.estate_page(view, answer, [])
    assert "wobbling-badly" in html


def test_a_plugin_cannot_introduce_a_severity() -> None:
    """The other half: bound by the contract rather than by convention.
    A rule's level $refs the closed vocabulary, so this is a schema
    refusal and not a rendering one."""
    import json as _json
    from pathlib import Path as _Path

    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    contract = _Path(__file__).resolve().parent.parent / "contract"
    registry = Registry()
    for path in sorted(contract.glob("*.json")):
        schema = _json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    validator = Draft202012Validator(
        _json.loads((contract / "se.declaration.1.json").read_text()), registry=registry)

    document = {
        "schema": "se.declaration/1", "collector": "widgets", "version": "1.0.0",
        "collections": [{
            "name": "widgets", "question": "q", "prefix": "widget",
            "freshness": "60s", "perishability": "perishable", "answer": ["Spin"],
            "facts": {"Spin": {"type": "integer", "temperament": "gauge",
                               "kind": "observed", "discloses": "nothing",
                               "sentence": "."}},
            "rules": [{"key": "k", "level": "apocalyptic", "grounds": "interface",
                       "when": {"fact": "Spin", "at_most": 1}, "sentence": "s",
                       "cites": ["Spin"]}],
            # Every collection must state its disclosure posture — a
            # plugin's included. Discovered by writing this test without
            # one and being refused, which is the contract working.
            "redaction_exemption": "Widget telemetry holds no credential.",
        }],
    }
    assert any(e.json_path.endswith("level") for e in validator.iter_errors(document)), (
        "a plugin inventing a severity would give the product a level no "
        "surface knows how to rank"
    )
    document["collections"][0]["rules"][0]["level"] = "critical"
    assert not list(validator.iter_errors(document))
