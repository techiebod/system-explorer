"""The named-evaluator seam, from the declarations' side (DESIGN 17,
ruled 2026-08-23).

`evaluators_test.go` asserts the Go half — the set is closed, a name
outside it is refused at load, a rule carries exactly one of `when` and
`evaluator`. This is the half that guard cannot see: whether the shipped
declarations and the shipped evaluator table actually agree, in BOTH
directions.

Both directions, because each is a different defect. A declaration
naming an evaluator that does not exist is a collection whose collator
refuses to load its rules. An evaluator no declaration names is code in
the judging path that nothing exercises — the same shape as a guard
whose pattern never matches, which this estate has shipped twice in one
evening.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TABLE = REPO / "go" / "internal" / "collate" / "evaluators.go"


def declared_evaluators() -> dict[str, list[str]]:
    """Every evaluator a shipped declaration names, to the rules naming it."""
    found: dict[str, list[str]] = {}
    paths = sorted((REPO / "go" / "cmd").glob("se-collect-*/declaration.json"))
    assert paths, "no declarations found; this guard would pass over nothing"
    for path in paths:
        document = json.loads(path.read_text())
        for collection in document.get("collections", []):
            for rule in collection.get("rules", []):
                if "evaluator" in rule:
                    found.setdefault(rule["evaluator"], []).append(
                        f"{path.parent.name}/{collection['name']}/{rule['key']}")
    return found


def table_evaluators() -> set[str]:
    source = TABLE.read_text()
    body = source.split("var evaluators = map[string]evaluator{", 1)[1]
    body = body.split("\n}", 1)[0]
    return set(re.findall(r'"([a-z][a-z0-9-]*)":', body))


def test_every_named_evaluator_exists_in_the_closed_table() -> None:
    named = declared_evaluators()
    assert named, (
        "no declaration names an evaluator; the seam exists for the rules "
        "that use it, and an unused one is a mechanism nothing proves")
    missing = sorted(set(named) - table_evaluators())
    assert not missing, (
        f"declared but not in the closed table: {missing}. A declaration "
        f"NAMES an evaluator and cannot ship one, so this is a collection "
        f"whose rules the collator will refuse to load: "
        f"{[named[name] for name in missing]}")


def test_every_evaluator_in_the_table_is_reached_by_a_declaration() -> None:
    unreached = sorted(table_evaluators() - set(declared_evaluators()))
    assert not unreached, (
        f"in the judging path and named by no shipped declaration: "
        f"{unreached}. Code nothing exercises is indistinguishable from "
        f"code whose condition never matches — delete it, or ship the rule "
        f"it was written for")


def test_a_rule_carries_exactly_one_of_when_and_evaluator() -> None:
    """The contract holds this with a oneOf and the collator holds it at
    load; this checks the shipped documents themselves, because a rule
    with both is two answers to one question and a rule with neither is an
    opinion an operator would wait for."""
    for path in sorted((REPO / "go" / "cmd").glob("se-collect-*/declaration.json")):
        document = json.loads(path.read_text())
        for collection in document.get("collections", []):
            for rule in collection.get("rules", []):
                carried = {"when", "evaluator"} & set(rule)
                assert len(carried) == 1, (
                    f"{path.parent.name}/{collection['name']}/{rule['key']} "
                    f"carries {sorted(carried) or 'neither'}")


def test_an_evaluator_rule_cites_only_facts_its_collection_declares() -> None:
    """Acceptance item 7 holds for an evaluator rule too: the seam moves
    the TEST into code, never the citation discipline. An opinion citing a
    fact nobody declared is one a reader cannot go and look at, whichever
    half of the rule decided it."""
    for path in sorted((REPO / "go" / "cmd").glob("se-collect-*/declaration.json")):
        document = json.loads(path.read_text())
        for collection in document.get("collections", []):
            declared = set(collection.get("facts", {}))
            for rule in collection.get("rules", []):
                if "evaluator" not in rule:
                    continue
                undeclared = sorted(set(rule["cites"]) - declared)
                assert not undeclared, (
                    f"{path.parent.name}/{collection['name']}/{rule['key']} "
                    f"cites {undeclared}, which the collection does not declare")
