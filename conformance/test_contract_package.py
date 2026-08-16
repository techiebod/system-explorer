"""The contract package is validated by the design document's own examples.

docs/DESIGN.md is the record of intent; contract/ is its wire schemas as
files. This suite holds the two together, in both directions:

- every schema-tagged example in the document validates against its schema
  (the document has shipped self-contradicting examples twice; this is the
  check that would have caught both), and
- every product schema in contract/ is exercised by at least one example —
  a schema nothing exercises is enumeration without proof, the subset-guard
  shape applied to a test suite.

Fixtures are extracted from the document at collection time, so an edit to
either side that breaks the pact fails here, not in an implementer's hands.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

REPO = Path(__file__).resolve().parent.parent
CONTRACT = REPO / "contract"
DESIGN = REPO / "docs" / "DESIGN.md"

# The vocabularies file carries only $defs; every other file is a product
# schema and must be proven by an example in the document.
PRODUCT_SCHEMAS = {
    "se.declaration/1": "se.declaration.1.json",
    "se.stream/1": "se.stream.1.json",
    "se.intent/1": "se.intent.1.json",
    "se.answer/1": "se.answer.1.json",
}

FENCE = re.compile(r"^```(json|jsonl)\s+schema=(\S+)\n(.*?)^```$", re.M | re.S)


def _registry() -> Registry:
    registry = Registry()
    for path in sorted(CONTRACT.glob("*.json")):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def _validator(schema_file: str) -> Draft202012Validator:
    schema = json.loads((CONTRACT / schema_file).read_text())
    return Draft202012Validator(schema, registry=_registry())


def _examples() -> list[tuple[str, str, str]]:
    """(schema id, fence kind, body) per tagged fence in the document."""
    text = DESIGN.read_text()
    return [(m.group(2), m.group(1), m.group(3)) for m in FENCE.finditer(text)]


def _documents(kind: str, body: str) -> list[dict]:
    if kind == "json":
        return [json.loads(body)]
    # jsonl in the document is wrapped for readers: records may span lines
    # and share a block, so stream-decode rather than assume one per line.
    decoder = json.JSONDecoder()
    documents, index = [], 0
    while index < len(body):
        if body[index].isspace():
            index += 1
            continue
        document, index = decoder.raw_decode(body, index)
        documents.append(document)
    return documents


def test_every_contract_schema_is_itself_valid() -> None:
    for path in sorted(CONTRACT.glob("*.json")):
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        assert schema["$id"] == path.name, (
            f"{path.name}: $id must equal the filename, so a $ref is a path"
        )


def test_design_document_has_tagged_examples() -> None:
    assert DESIGN.exists(), "docs/DESIGN.md is the canonical model and must exist"
    assert _examples(), (
        "no schema-tagged examples found: the fence tags are the pact "
        "between the document and contract/, and both have gone missing"
    )


@pytest.mark.parametrize(
    "schema_id,kind,body",
    [pytest.param(*e, id=f"{e[0]}:{i}") for i, e in enumerate(_examples())],
)
def test_design_examples_validate(schema_id: str, kind: str, body: str) -> None:
    assert schema_id in PRODUCT_SCHEMAS, (
        f"example tagged {schema_id!r} but contract/ defines no such schema"
    )
    validator = _validator(PRODUCT_SCHEMAS[schema_id])
    for document in _documents(kind, body):
        errors = sorted(validator.iter_errors(document), key=str)
        assert not errors, f"{schema_id} example does not validate:\n" + "\n".join(
            f"- {e.json_path}: {e.message}" for e in errors
        )


def test_every_product_schema_is_exercised() -> None:
    seen = {schema_id for schema_id, _, _ in _examples()}
    unexercised = set(PRODUCT_SCHEMAS) - seen
    assert not unexercised, (
        f"schemas with no example in docs/DESIGN.md: {sorted(unexercised)} — "
        "a schema nothing exercises is enumeration without proof"
    )


def test_stream_example_is_internally_consistent() -> None:
    """The stream example must satisfy its own batch rules, not only shapes.

    Every collection named in begin.generations either commits or declines;
    a decline of absent is followed by a commit; a commit's generation echoes
    begin's. The wire rules of DESIGN 19, applied to the document's example.
    """
    for schema_id, kind, body in _examples():
        if schema_id != "se.stream/1":
            continue
        records = _documents(kind, body)
        begin = next(r for r in records if r["record"] == "begin")
        commits = {r["collection"]: r for r in records if r["record"] == "commit"}
        declines = {r["collection"]: r for r in records if r["record"] == "decline"}
        for collection, generation in begin["generations"].items():
            assert collection in commits or collection in declines, (
                f"{collection}: named in begin, neither committed nor declined"
            )
            if collection in commits:
                assert commits[collection]["generation"] == generation, (
                    f"{collection}: commit generation does not echo begin's"
                )
        for collection, decline in declines.items():
            if decline["reason"] == "absent":
                assert collection in commits and commits[collection]["objects"] == 0, (
                    f"{collection}: absent is authoritative-empty and must "
                    "commit zero objects"
                )
            else:
                assert collection not in commits, (
                    f"{collection}: a {decline['reason']} decline never commits"
                )
