"""SPEC section 11, rules 1 and 6: envelopes validate; the schemas themselves are sound."""

import jsonschema
import pytest

from common import SCHEMAS


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
