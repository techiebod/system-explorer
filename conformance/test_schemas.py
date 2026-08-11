"""SPEC section 11, rules 1 and 6: envelopes validate; the schemas themselves are sound.

Two profiles of the same schemas, because they answer different questions
(SPEC section 5.1). The PUBLISHED schema is the consumer contract and must
tolerate members it does not know, since a hub fans out across agents of
several versions at once and a field added by a newer one must not make an
older consumer reject the envelope. The STRICT profile is the producer
contract: our own fixtures are validated with every declared object closed,
so opening the wire does not license this agent to invent or misspell fields.
"""

import jsonschema
import pytest

from common import EXAMPLES_DIR, SCHEMAS, load_example, strict


@pytest.mark.parametrize("schema_id", sorted(SCHEMAS))
def test_schema_document_is_valid_2020_12(schema_id):
    jsonschema.Draft202012Validator.check_schema(SCHEMAS[schema_id])


def test_example_declares_a_known_schema(example):
    path, doc = example
    assert doc.get("schema") in SCHEMAS, (
        f"{path.name} declares schema {doc.get('schema')!r}; "
        f"known: {sorted(SCHEMAS)}"
    )


def test_example_validates_against_its_schema(example):
    path, doc = example
    validator = jsonschema.Draft202012Validator(SCHEMAS[doc["schema"]])
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    assert not errors, f"{path.name}:\n" + "\n".join(
        f"  at {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
        for e in errors
    )


def test_example_validates_against_the_producer_profile(example):
    """The teeth the published schemas gave up: our fixtures stay closed."""
    path, doc = example
    validator = jsonschema.Draft202012Validator(strict(SCHEMAS[doc["schema"]]))
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    assert not errors, f"{path.name} (producer profile):\n" + "\n".join(
        f"  at {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
        for e in errors
    )


# The one map whose keys are themselves the contract: `counts` keys are the
# severity levels, so an unknown key there is a new level, which SPEC section
# 5.1 rule 6 makes a break rather than an addition. It must stay closed.
CLOSED_BY_DESIGN = {"counts"}


@pytest.mark.parametrize("schema_id", sorted(SCHEMAS))
def test_published_schemas_permit_unknown_members(schema_id):
    """SPEC section 5.1 rule 3, executable: a published schema may not forbid
    members an agent might add, at any depth — opening only the root moves the
    mid-rollout trap one level down rather than removing it."""
    offenders: list[str] = []

    def walk(node, trail: str, property_name: str | None) -> None:
        if isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{trail}[{index}]", None)
            return
        if not isinstance(node, dict):
            return
        if node.get("additionalProperties") is False and property_name not in CLOSED_BY_DESIGN:
            offenders.append(trail or "<root>")
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                for name, sub in value.items():
                    walk(sub, f"{trail}.{name}" if trail else name, name)
            else:
                walk(value, f"{trail}.{key}" if trail else key, None)

    walk(SCHEMAS[schema_id], "", None)
    assert not offenders, (
        f"{schema_id} forbids unknown members at: {offenders}. A consumer "
        "written against this version must keep working when a newer agent "
        "adds a field (SPEC section 5.1); move strictness to the producer "
        "profile instead."
    )


def test_a_newer_agents_added_fields_are_accepted_but_not_invented():
    """The whole policy in one test: consumers tolerate, producers do not invent.

    Simulates an envelope from a newer agent — a root field, a host field and
    an opinion field this version has never heard of. The published schema must
    accept it (or a rolling upgrade breaks every validating consumer mid-way);
    the producer profile must reject it (or we could ship those fields without
    declaring them).
    """
    doc = load_example(EXAMPLES_DIR / "observation-unit.json")
    doc["agent_version"] = "9.9.9"
    doc["host"]["site"] = "site-a"
    doc["opinions"][0]["first_seen"] = "2026-08-01T00:00:00Z"

    published = jsonschema.Draft202012Validator(SCHEMAS[doc["schema"]])
    assert not list(published.iter_errors(doc)), (
        "the published schema rejected fields a newer agent might add:\n"
        + "\n".join(f"  {e.message}" for e in published.iter_errors(doc))
    )

    producer = jsonschema.Draft202012Validator(strict(SCHEMAS[doc["schema"]]))
    rejected = [e.message for e in producer.iter_errors(doc)]
    assert rejected, (
        "the producer profile accepted undeclared fields — it has no teeth, "
        "so a misspelt or undocumented field would ship unnoticed"
    )
