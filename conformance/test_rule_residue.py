"""Why a rule table is smaller than the rulebook it was ported from.

DESIGN §17 lists this as one of the three properties that make the
named-evaluator seam "a mechanism rather than an escape hatch": *"the
declaration says which opinions the table does not decide, so a reader
asking why a rule table is smaller than a rulebook gets an answer from
the declaration instead of inferring one from silence — the coverage
rule applied to the rule table itself."*

It was asserted in DESIGN, repeated in `evaluators.go`'s header, and
repeated again in a test comment — and implemented nowhere. The
declaration schema had no member it could be written in, and all twenty
shipped declarations validated. A present-tense claim naming no guard,
false on the day it was written. Found by an audit, 2026-08-23.

**The work list comes from the REFERENCE**, which is the estate's stated
rule for a completeness guard: every opinion key the shipping rulebook
emits must be either declared as a rule of the same name, or named in
that collection's `reference_residue` with the reason. Deny by default,
so a key that quietly stops being ported is a failure rather than a
smaller table nobody notices.

Two dispositions are both legitimate and both must be written down. A
key the table genuinely cannot decide is one. A key decided under a
DIFFERENT name is the other, and it is not cosmetic: a rule key is part
of a finding's identity — the declaration schema says so where `key` is
defined, "renaming one resets a lifecycle" — so a rename nothing records
is a lifecycle reset nobody can find.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RULES = REPO / "src" / "system_explorer" / "agent" / "rules"
DECLARATIONS = REPO / "go" / "cmd"


#: Keys a rulebook BUILDS rather than writes, by module and by the
#: source text of the construction. Deny-by-default: a construction not
#: named here fails, so the extraction's blind spot is what goes red
#: rather than the coverage it stops measuring.
#:
#: Each entry is read off the rulebook once. It is a hand-kept map and
#: that is the honest boundary — the alternative is an extraction that
#: guesses, and a guessed key is worse than a stated one because nothing
#: says which keys were invented.
DYNAMIC_KEYS: dict[str, dict[str, tuple[str, ...]]] = {
    # _component(key, ...) is called with a literal at each site.
    "paperless": {"key": ("paperless-database", "paperless-redis",
                          "paperless-celery", "paperless-index",
                          "paperless-classifier")},
    # _ingress_opinions(kind, ...) over routers and services.
    "traefik": {"f'{kind}-error'": ("router-error", "service-error"),
                "f'{kind}-warning'": ("router-warning", "service-warning"),
                "f'{kind}-disabled'": ("router-disabled", "service-disabled")},
    # a nested judge(key, ...) for the two link comparisons.
    "hardware": {"key": ("link-degraded", "link-width-degraded",
                         "link-slot-capped", "link-width-slot-capped")},
    # _capacity_opinion(prefix, ...) over pools, datasets and mounts.
    # _capacity_opinion(key, ...) over pools, datasets and mounts. The
    # f-string forms first written here were guesses and the staleness
    # guard caught them: storage passes a `key` parameter like the others.
    "storage": {"key": ("pool-capacity", "pool-capacity-critical",
                        "dataset-capacity", "dataset-capacity-critical",
                        "mount-capacity", "mount-capacity-critical")},
}


def reference_opinions() -> dict[str, set[str]]:
    """Every opinion key each shipping rulebook emits, by module.

    Read from the source rather than by importing and running: a rule
    that fires only on a shape no fixture has still exists, and a work
    list built from what happened to execute would be the port shaping
    the reference's own list.

    **Keys built rather than written are the hard half.** Four rulebooks
    construct them — paperless and hardware hand a `key` parameter to a
    helper, traefik and storage build one with an f-string — and taking
    only the literal calls silently shrank this deny-by-default work list
    to the calls the extraction happened to understand. That is the
    subset-guard defect inside the guard written to enforce coverage.

    An unresolvable construction is REPORTED, not skipped: it must be
    named in DYNAMIC_KEYS with the keys it produces, and a construction
    nobody has accounted for fails. So the extraction's own blind spot is
    the thing that goes red, rather than the coverage it silently stops
    measuring.
    """
    found: dict[str, set[str]] = {}
    for path in sorted(RULES.glob("*.py")):
        if path.name.startswith("_"):
            continue
        keys: set[str] = set()
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name != "opinion":
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                keys.add(first.value)
            else:
                keys |= set(DYNAMIC_KEYS.get(path.stem, {}).get(
                    ast.unparse(first), ()))
        if keys:
            found[path.stem] = keys
    return found


def unresolvable() -> dict[str, list[str]]:
    """Every `opinion(...)` whose key this extraction cannot read, by
    module and by source text."""
    out: dict[str, list[str]] = {}
    for path in sorted(RULES.glob("*.py")):
        if path.name.startswith("_"):
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name != "opinion":
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                continue
            out.setdefault(path.stem, []).append(ast.unparse(first))
    return out


def ported() -> dict[str, tuple[set[str], dict[str, str]]]:
    """Per collector: the rule keys it declares, and its stated residue."""
    out: dict[str, tuple[set[str], dict[str, str]]] = {}
    for path in sorted(DECLARATIONS.glob("se-collect-*/declaration.json")):
        document = json.loads(path.read_text())
        keys: set[str] = set()
        residue: dict[str, str] = {}
        for collection in document.get("collections", []):
            for rule in collection.get("rules", []):
                keys.add(rule["key"])
            for entry in collection.get("reference_residue", []):
                residue[entry["opinion"]] = entry["reason"]
        out[path.parent.name.replace("se-collect-", "")] = (keys, residue)
    return out


def test_the_reference_work_list_is_not_empty() -> None:
    """Anti-vacuity. If the AST walk stops finding opinion keys — a
    refactor renames `env.opinion`, say — this guard would pass over
    nothing and report that every rulebook is fully accounted for."""
    reference = reference_opinions()
    assert len(reference) >= 15, f"too few rulebooks read: {sorted(reference)}"
    assert sum(len(keys) for keys in reference.values()) >= 80, (
        "the reference emits far more opinions than this; the extraction "
        "has stopped seeing them")


def test_every_reference_opinion_is_declared_or_its_absence_is() -> None:
    """The coverage rule, applied to the rule table itself."""
    reference = reference_opinions()
    port = ported()
    unaccounted: dict[str, list[str]] = {}
    for collector, keys in sorted(reference.items()):
        declared, residue = port.get(collector, (set(), {}))
        if not declared and not residue:
            # A rulebook whose collector this repository does not ship is
            # not this guard's business; a collector with neither rules
            # nor residue for a rulebook that HAS keys is.
            if collector not in {p.parent.name.replace("se-collect-", "")
                                 for p in DECLARATIONS.glob("se-collect-*/declaration.json")}:
                continue
        missing = sorted(keys - declared - set(residue))
        if missing:
            unaccounted[collector] = missing
    assert not unaccounted, (
        f"reference opinions neither ported nor stated as residue: "
        f"{json.dumps(unaccounted, indent=2)}. Declare the rule, or name "
        f"the key in that collection's reference_residue with the reason — "
        f"a table smaller than its rulebook must say why.")


def test_residue_never_names_a_key_the_table_actually_declares() -> None:
    """Staleness, the other direction. A residue entry for a key that was
    later ported is prose asserting a gap that has closed, which is the
    stale-confident-claim this repository says is worse than silence."""
    stale: dict[str, list[str]] = {}
    for collector, (declared, residue) in sorted(ported().items()):
        overlap = sorted(set(residue) & declared)
        if overlap:
            stale[collector] = overlap
    assert not stale, (
        f"named as residue and declared as a rule: {stale}. One of the two "
        f"is out of date.")


def test_residue_never_names_a_key_the_reference_does_not_emit() -> None:
    """The third direction: a residue entry for a key no rulebook has is
    an answer to a question nobody asked, and it would keep this guard
    quiet about a key that really is missing if the two were ever
    confused."""
    reference = reference_opinions()
    invented: dict[str, list[str]] = {}
    for collector, (_declared, residue) in sorted(ported().items()):
        unknown = sorted(set(residue) - reference.get(collector, set()))
        if unknown:
            invented[collector] = unknown
    assert not invented, (
        f"residue naming keys no reference rulebook emits: {invented}")


def test_every_residue_reason_says_something() -> None:
    """A reason that repeats the key, or says 'not ported', leaves the
    reader exactly where the silence did."""
    thin: dict[str, list[str]] = {}
    for collector, (_declared, residue) in sorted(ported().items()):
        for key, reason in residue.items():
            if len(reason) < 40 or reason.strip().lower() in {
                    "not ported", "not implemented", "todo"}:
                thin.setdefault(collector, []).append(key)
    assert not thin, (
        f"residue reasons that leave the reader where the silence did: {thin}")


def test_every_built_key_is_accounted_for() -> None:
    """The extraction's own blind spot, made to fail rather than to
    quietly shrink the work list.

    Taking only literal `opinion("key", ...)` calls dropped four
    rulebooks' worth of keys — paperless, traefik, hardware and storage
    all build them — so the deny-by-default guard above was measuring
    coverage against a list that silently omitted them.
    """
    unread = unresolvable()
    unaccounted = {}
    for module, constructions in sorted(unread.items()):
        for construction in constructions:
            if construction not in DYNAMIC_KEYS.get(module, {}):
                unaccounted.setdefault(module, []).append(construction)
    assert not unaccounted, (
        f"opinion keys this extraction cannot read and DYNAMIC_KEYS does "
        f"not name: {json.dumps(unaccounted, indent=2)}. Add the keys the "
        f"construction produces — an unread construction silently shrinks "
        f"the work list every other test here is measured against.")


def test_dynamic_keys_names_no_construction_that_has_gone() -> None:
    """Staleness the other way: an entry for a construction no rulebook
    still has is prose about something that is not there, and it would
    keep a real key alive in the work list after its rule was deleted."""
    unread = unresolvable()
    stale = {}
    for module, table in sorted(DYNAMIC_KEYS.items()):
        gone = sorted(set(table) - set(unread.get(module, [])))
        if gone:
            stale[module] = gone
    assert not stale, (
        f"DYNAMIC_KEYS names constructions no rulebook has: {stale}")
