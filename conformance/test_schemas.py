"""SPEC section 11, rules 1 and 6: envelopes validate; the schemas themselves are sound.

Two profiles of the same schemas, because they answer different questions
(SPEC section 5.1). The PUBLISHED schema is the consumer contract and must
tolerate members it does not know, since a hub fans out across agents of
several versions at once and a field added by a newer one must not make an
older consumer reject the envelope. The STRICT profile is the producer
contract: our own fixtures are validated with every declared object closed,
so opening the wire does not license this agent to invent or misspell fields.
"""

import re

import jsonschema
import pytest

from common import EXAMPLES_DIR, PACKAGE_DIR, SCHEMAS, load_example, strict


@pytest.mark.parametrize("schema_id", sorted(SCHEMAS))
def test_schema_document_is_valid_2020_12(schema_id):
    jsonschema.Draft202012Validator.check_schema(SCHEMAS[schema_id])


# ── the census: every discriminator on the wire has a published schema ───
#
# SPEC section 5.1 rule 1 makes the `schema` member the versioning contract —
# "a response without one cannot be versioned at all, and is a defect". It says
# nothing about a response that HAS one naming a schema nobody published, which
# is the state se.capabilities/1 and se.hub-hosts/1 were in: emitted, consumed
# by the UI, and validated by nothing. se.hub-hosts/1 shipped with no schema, no
# fixture and no test whatsoever.
#
# Registering a file fixes an instance. This fixes the class: the next envelope
# cannot reach the wire without one.

SCHEMA_ID_LITERAL = re.compile(r'"(se\.[a-z][a-z0-9-]*/\d+)"')


def emitted_schema_ids() -> dict[str, list[str]]:
    """Schema id -> the file:line literals that emit it, across the package."""
    found: dict[str, list[str]] = {}
    for source in sorted(PACKAGE_DIR.rglob("*.py")):
        for number, line in enumerate(source.read_text().splitlines(), 1):
            for schema_id in SCHEMA_ID_LITERAL.findall(line):
                found.setdefault(schema_id, []).append(
                    f"{source.relative_to(PACKAGE_DIR)}:{number}")
    return found


EMITTED = emitted_schema_ids()


def test_the_schema_id_scan_finds_the_ids_we_know_about():
    """Anti-vacuity: a scan that silently stops matching would make both
    checks below pass for ever."""
    assert {"se.observation/1", "se.collection/1", "se.status/1"} <= set(EMITTED), (
        f"the schema-id scan found only {sorted(EMITTED)}"
    )


def test_every_emitted_schema_id_has_a_published_schema():
    """An envelope naming a schema nobody wrote is unversioned in practice:
    no consumer can validate it and no producer profile can constrain it."""
    undeclared = {name: sites for name, sites in EMITTED.items() if name not in SCHEMAS}
    assert not undeclared, (
        "these envelopes declare a schema that does not exist in schema/: "
        + "; ".join(f"{name} (emitted at {', '.join(sites)})"
                    for name, sites in sorted(undeclared.items()))
    )


def test_every_published_schema_is_emitted_somewhere():
    """The other direction: a schema nothing emits is dead contract, and dead
    contract is what a consumer implements against and then never receives."""
    unemitted = sorted(set(SCHEMAS) - set(EMITTED))
    assert not unemitted, (
        f"schema/ publishes {unemitted}, which no code emits — either the "
        "producer was removed and the schema outlived it, or the id drifted"
    )


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


# The additive-fields policy is the most consequential rule in SPEC section 5.1
# — it is what lets five hosts deploy at different times without breaking a
# validating consumer mid-rollout — and it used to be proven for exactly one
# envelope out of seven. One entry per schema family, each reaching a nested
# $def as well as the root, because opening only the root moves the trap one
# level down rather than removing it (the same argument as the published-schema
# rule above).
FORWARD_COMPAT_EXTENSIONS: dict[str, list[tuple[str, object]]] = {
    # The degraded pool, because this needs an envelope that actually carries
    # an opinion: a healthy object has none.
    "observation-pool-degraded.json": [
        ("agent_version", "9.9.9"),
        ("host.site", "site-a"),
        ("opinions.0.first_seen", "2026-08-01T00:00:00Z"),
    ],
    "collection-units.json": [
        ("page_observed_at", "2026-08-01T00:00:00Z"),
        ("items.0.first_seen", "2026-08-01T00:00:00Z"),
    ],
    "status-docker-down.json": [
        ("poll_interval_seconds", 60),
        ("subsystems.storage.pools.first_seen", "2026-08-01T00:00:00Z"),
    ],
    "changes-deploy-drift.json": [("window_seconds", 86400)],
    "facts-hardware-link.json": [("generated_at", "2026-08-01T00:00:00Z")],
    "capabilities-mixed.json": [
        ("uptime_seconds", 42),
        ("subsystems.docker.socket", "/var/run/docker.sock"),
    ],
    "hub-hosts-two-sites.json": [
        ("poll_interval_seconds", 30),
        ("hosts.host-a.arch", "x86_64"),
    ],
    # The redacted unit, because this needs an envelope that carries the
    # optional members: an error evidence has neither payload nor interface.
    "evidence-unit.json": [
        ("payload_bytes", 512),
        ("host.site", "site-a"),
    ],
    "views-storage-simple.json": [
        ("generated_by", "estate-tooling/1.0"),
        ("views.0.panels.0.icon", "pool"),
    ],
    # The hub's registry will stamp lifecycle onto these records (SPEC
    # section 6.3), so the nested case is exactly the field it will add.
    "findings-unit-failed.json": [
        ("sweep_seconds", 1.4),
        ("findings.0.first_seen", "2026-08-01T00:00:00Z"),
    ],
    "hub-findings-acknowledged.json": [
        ("poll_interval_seconds", 300),
        ("findings.0.transitions.0.via", "ui"),
    ],
    "hub-transitions-ack-then-unack.json": [
        ("writes_enabled", True),
        ("transitions.0.via", "ui"),
    ],
}


def _set_path(doc, dotted: str, value) -> None:
    node = doc
    parts = dotted.split(".")
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    node[parts[-1]] = value


def test_every_schema_family_is_covered_by_a_forward_compat_case():
    """Anti-vacuity: a new schema must not slip past the policy check by
    simply not appearing in the table above."""
    covered = {load_example(EXAMPLES_DIR / name)["schema"]
               for name in FORWARD_COMPAT_EXTENSIONS}
    assert covered == set(SCHEMAS), (
        f"schema families with no forward-compat case: {sorted(set(SCHEMAS) - covered)}"
    )


@pytest.mark.parametrize("fixture", sorted(FORWARD_COMPAT_EXTENSIONS))
def test_a_newer_agents_added_fields_are_accepted_but_not_invented(fixture):
    """The whole policy in one test: consumers tolerate, producers do not invent.

    Simulates an envelope from a newer agent — fields this version has never
    heard of, at the root and inside a nested definition. The published schema
    must accept it (or a rolling upgrade breaks every validating consumer
    mid-way); the producer profile must reject it (or we could ship those
    fields without declaring them).
    """
    doc = load_example(EXAMPLES_DIR / fixture)
    for dotted, value in FORWARD_COMPAT_EXTENSIONS[fixture]:
        _set_path(doc, dotted, value)

    published = jsonschema.Draft202012Validator(SCHEMAS[doc["schema"]])
    assert not list(published.iter_errors(doc)), (
        f"{fixture}: the published schema rejected fields a newer agent might add:\n"
        + "\n".join(f"  {e.message}" for e in published.iter_errors(doc))
    )

    producer = jsonschema.Draft202012Validator(strict(SCHEMAS[doc["schema"]]))
    rejected = [e.message for e in producer.iter_errors(doc)]
    assert rejected, (
        f"{fixture}: the producer profile accepted undeclared fields — it has "
        "no teeth, so a misspelt or undocumented field would ship unnoticed"
    )
