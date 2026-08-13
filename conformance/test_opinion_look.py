"""`look`: the opinion member that turns a condition into a next step.

A host PSI warning states that every non-idle task was waiting on I/O and
offers nowhere to go, even though units/units already carries the same kernel
accounting per unit. `look` is the route that closes that gap — and a route
is only worth shipping if it lands somewhere. Three things are proven here,
in the order a bad link would break them:

  * the shape is refused at the rule that wrote it (envelope.opinion), the
    way an invented severity level is;
  * every route the rulebook emits names a collection an adapter really
    serves, and every ordering fact it names is really emitted there —
    checked HERE rather than raised at runtime, because main.py turns an
    adapter exception into an error envelope and a dead link must not blank
    a page;
  * every schema that carries opinions accepts what the rulebook emits, in
    both the published and the producer profile.

The rulebook is walked through test_rules.CASES, so a link only counts as
proven if a characteristic input actually fires the opinion carrying it.
"""

import ast

import jsonschema
import pytest

from common import AGENT_DIR, SCHEMAS, strict
from test_fact_dictionary import ADAPTERS, names_the_adapter_uses
from test_rules import CASES

from system_explorer.agent import envelope as env
from system_explorer.agent.adapters import units as units_adapter

RULES_DIR = AGENT_DIR / "rules"


def emitted_looks() -> list:
    """(case id, rules module, opinion key, look entry) for every hint the
    characteristic cases actually produce."""
    out = []
    for name, evaluator, facts, _expected in CASES:
        module = evaluator.__module__.rsplit(".", 1)[-1]
        for opinion in evaluator(facts):
            for entry in opinion.get("look") or []:
                out.append(pytest.param(
                    module, opinion["key"], entry,
                    id=f"{name}:{opinion['key']}:"
                       f"{entry['subsystem']}/{entry['collection']}"))
    return out


LOOKS = emitted_looks()


def test_the_rulebook_actually_emits_route_hints():
    """Anti-vacuity: every check below is parametrised over this walk, so a
    walk that found nothing would make all of them pass for ever."""
    assert LOOKS, "no opinion in CASES carries a look"


def test_the_host_stall_warning_offers_the_attribution_it_cannot_state():
    """The reported case, kept from regressing back to a dead end: an
    operator reading "no progress for 54.55% of the last minute" had no way
    to click through to the unit responsible."""
    from system_explorer.agent.rules import system

    [opinion] = system.overview_opinions({"PsiIoFullAvg60": 54.55})
    assert opinion["key"] == "psi-io"
    [entry] = opinion["look"]
    assert entry == {"subsystem": "units", "collection": "units",
                     "fact": "PsiIoFullAvg60",
                     "label": "which units are waiting on I/O"}


# ── the routes land somewhere ────────────────────────────────────────────

@pytest.mark.parametrize("module,key,entry", LOOKS)
def test_a_route_hint_names_a_collection_an_adapter_serves(module, key, entry):
    """A link to a route nobody serves is a 404 with a friendly label on it.
    The envelope cannot check this (it would have to import the adapter
    registry, and raising there would turn one bad link into an error
    envelope for the whole page), so the check lives here."""
    adapter = ADAPTERS.get(entry["subsystem"])
    assert adapter is not None, (
        f"rules/{module}.py opinion {key!r} points at subsystem "
        f"{entry['subsystem']!r}; known: {sorted(ADAPTERS)}")
    assert entry["collection"] in adapter.collections(), (
        f"rules/{module}.py opinion {key!r} points at "
        f"{entry['subsystem']}/{entry['collection']}; that subsystem serves "
        f"{sorted(adapter.collections())}")


@pytest.mark.parametrize("module,key,entry", LOOKS)
def test_the_ordering_fact_is_one_the_destination_adapter_emits(module, key, entry):
    """A hint naming a fact no row carries is worse than no hint: the
    consumer sorts by nothing and the operator learns the link lies. Same
    scan the fact dictionary uses for drift — the adapter's own string
    literals, with its glossary excluded so the check cannot read itself
    back."""
    fact = entry.get("fact")
    if fact is None:
        return
    assert fact in names_the_adapter_uses(entry["subsystem"]), (
        f"rules/{module}.py opinion {key!r} orders "
        f"{entry['subsystem']}/{entry['collection']} by {fact!r}, which "
        f"appears nowhere in adapters/{entry['subsystem']}.py")


def test_the_fact_scan_would_notice_an_invented_name():
    """The guard above is only worth having if a wrong spelling fails it."""
    names = names_the_adapter_uses("units")
    assert "PsiIoFullAvg60" in names
    assert "PsiIoFullAvg60s" not in names


PRESSURE_FILES = {
    # Verbatim /sys/fs/cgroup/<unit>/*.pressure shapes. The kernel defines
    # cpu-full as always zero and never writes the line, which is why the cpu
    # link orders by "some" while io and memory order by "full".
    "io.pressure": ("some avg10=0.00 avg60=2.31 avg300=0.77 total=1234\n"
                    "full avg10=0.00 avg60=54.55 avg300=0.31 total=999\n"),
    "memory.pressure": ("some avg10=0.00 avg60=8.10 avg300=1.02 total=44\n"
                        "full avg10=0.00 avg60=6.44 avg300=0.90 total=40\n"),
    "cpu.pressure": "some avg10=0.00 avg60=71.20 avg300=12.00 total=88\n",
}


def test_the_units_collection_emits_the_exact_facts_the_psi_links_order_by(tmp_path):
    """The spelling proven end to end rather than eyeballed: the parser is
    run over real pressure-file text, and the names it produces must contain
    every fact the host-stall links sort by AND be the ones the collection
    puts on a row. A link is worth exactly as much as this equality."""
    produced: dict = {}
    for name, text in PRESSURE_FILES.items():
        path = tmp_path / name
        path.write_text(text)
        produced.update(units_adapter._read_pressure(str(path)))
    assert produced["PsiIoFullAvg60"] == 54.55
    assert produced["PsiMemoryFullAvg60"] == 6.44
    assert produced["PsiCpuSomeAvg60"] == 71.2
    assert "PsiCpuFullAvg60" not in produced

    ordered_by = {entry["fact"] for _module, _key, entry in
                  (param.values for param in LOOKS)
                  if entry["subsystem"] == "units"
                  and entry["collection"] == "units"
                  and str(entry.get("fact", "")).startswith("Psi")}
    assert ordered_by, "no link orders the units collection by a PSI fact"
    assert ordered_by <= set(produced), (
        f"links order by {sorted(ordered_by - set(produced))}, which the "
        "pressure parser never produces")
    assert ordered_by <= set(units_adapter.ROW_PRESSURE_FACTS), (
        f"links order by {sorted(ordered_by - set(units_adapter.ROW_PRESSURE_FACTS))}, "
        "which the parser produces but the collection row does not carry — a "
        "consumer sorting the list would find the column empty")


# ── every link the rulebook writes is one the cases reach ────────────────

def opinion_keys_with_a_look_in_the_source() -> set[tuple[str, str]]:
    """(module, opinion key) for every env.opinion(...) call in the rulebook
    that passes look=. Source-level, so a link nothing exercises cannot hide
    behind a branch the characteristic cases never take."""
    found: set[tuple[str, str]] = set()
    for source in sorted(RULES_DIR.glob("*.py")):
        tree = ast.parse(source.read_text(), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not any(kw.arg == "look" for kw in node.keywords):
                continue
            key = node.args[0] if node.args else None
            assert isinstance(key, ast.Constant) and isinstance(key.value, str), (
                f"{source.name}:{node.lineno}: an opinion carrying a look must "
                "name its key as a literal, or this coverage check cannot see it")
            found.add((source.stem, key.value))
    return found


def test_every_authored_link_is_reached_by_a_characteristic_case():
    """A route hint that no case fires is a route nothing above ever
    checked: unrouted, unspelled, unvalidated. Adding a link means adding
    (or already having) a case that fires the opinion carrying it."""
    authored = opinion_keys_with_a_look_in_the_source()
    assert authored, f"{RULES_DIR} yielded no look= call sites"
    exercised = {(module, key) for module, key, _entry in
                 (param.values for param in LOOKS)}
    assert authored == exercised, (
        "links the rulebook writes but no case fires: "
        f"{sorted(authored - exercised)}; cases carrying links the source "
        f"scan missed: {sorted(exercised - authored)}")


# ── the shape is refused where it is written ─────────────────────────────

GOOD = {"subsystem": "units", "collection": "units",
        "fact": "PsiIoFullAvg60", "label": "which units are waiting on I/O"}


def test_a_well_formed_hint_survives_unchanged_but_not_shared():
    """Pure data: what the rule wrote is what the consumer gets. Copied,
    because rulebooks declare their hints as module constants and one dict
    shared across every opinion a rule ever emits makes a consumer's
    mutation everyone's."""
    source = [dict(GOOD)]
    first = env.opinion("psi-io", "warn", "stalled", ["PsiIoFullAvg60"], look=source)
    second = env.opinion("psi-io", "warn", "stalled", ["PsiIoFullAvg60"], look=source)
    assert first["look"] == [GOOD]
    assert first["look"][0] is not source[0]
    assert first["look"][0] is not second["look"][0]


def test_a_hint_with_no_ordering_fact_is_a_route_and_nothing_more():
    """Absent, never null: no fact means the collection itself is the
    answer, and an explicit null would make every consumer handle a value
    that carries no information."""
    entry = {"subsystem": "storage", "collection": "block-devices",
             "label": "the devices backing this pool"}
    built = env.opinion("pool-health", "critical", "degraded", ["State"],
                        look=[entry])["look"][0]
    assert "fact" not in built
    assert env.opinion("pool-health", "critical", "degraded", ["State"],
                       look=[{**entry, "fact": None}])["look"][0] == built


def test_no_look_member_is_emitted_when_there_is_nothing_to_point_at():
    assert "look" not in env.opinion("x", "warn", "m", ["F"])
    assert "look" not in env.opinion("x", "warn", "m", ["F"], look=[])


@pytest.mark.parametrize("entry,why", [
    ({**GOOD, "filters": {"PsiIoFullAvg60": "!0"}},
     "a filter member: the fact-filter language cannot express 'greater "
     "than zero', and !0 would not even exclude 0.0"),
    ({**GOOD, "subsytem": "units"}, "a misspelt member, silently ignored"),
    ({"collection": "units", "label": "x"}, "no subsystem"),
    ({"subsystem": "units", "label": "x"}, "no collection"),
    ({"subsystem": "units", "collection": "units"}, "no label"),
    ({**GOOD, "label": "   "}, "a blank label"),
    ({**GOOD, "subsystem": "Units"}, "a route name outside the grammar"),
    ({**GOOD, "collection": "block_devices"}, "an underscore in a route name"),
    ({**GOOD, "fact": ""}, "an empty ordering fact"),
    ({**GOOD, "fact": 60}, "a non-string ordering fact"),
    ("units/units", "a bare string where a route hint belongs"),
])
def test_a_malformed_hint_fails_at_the_rule_that_wrote_it(entry, why):
    """The level-enum treatment, for the same reason: hints are literals in
    the rulebook, so this raise lands in CI rather than on a live page —
    and a member nobody declared would otherwise ship unread for ever."""
    with pytest.raises(ValueError, match="psi-io"):
        env.opinion("psi-io", "warn", "stalled", ["PsiIoFullAvg60"], look=[entry])


# ── the schemas accept what the rulebook emits ───────────────────────────

LOOK_SCHEMAS = sorted(schema_id for schema_id, schema in SCHEMAS.items()
                      if "look" in (schema.get("$defs") or {}))


def test_every_schema_carrying_opinions_declares_look():
    """An opinion's members travel: a row's opinions are lifted verbatim
    into /v1/findings and again into the hub roll-up. A schema in that chain
    that never declared `look` would drop the link in the producer profile
    at whichever hop forgot."""
    assert set(LOOK_SCHEMAS) == {"se.observation/1", "se.collection/1",
                                 "se.findings/1", "se.hub-findings/1"}


@pytest.mark.parametrize("schema_id", LOOK_SCHEMAS)
def test_the_emitted_hints_validate_in_both_profiles(schema_id):
    document = {"$defs": SCHEMAS[schema_id]["$defs"], "$ref": "#/$defs/look"}
    published = jsonschema.Draft202012Validator(document)
    producer = jsonschema.Draft202012Validator(strict(document))
    for _module, _key, entry in (param.values for param in LOOKS):
        assert not list(published.iter_errors([entry])), (
            f"{schema_id} rejects {entry}")
        assert not list(producer.iter_errors([entry])), (
            f"{schema_id} producer profile rejects {entry}")


@pytest.mark.parametrize("schema_id", LOOK_SCHEMAS)
def test_the_producer_profile_still_refuses_an_undeclared_member(schema_id):
    """Anti-vacuity for the check above: the strict profile must have teeth
    on this member too, or an invented one would ship undeclared."""
    document = strict({"$defs": SCHEMAS[schema_id]["$defs"], "$ref": "#/$defs/look"})
    producer = jsonschema.Draft202012Validator(document)
    assert list(producer.iter_errors([{**GOOD, "filters": {"x": "y"}}]))
