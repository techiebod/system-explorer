"""View documents load honestly in every shape an operator can produce.

The loader is pure over (directory, now, site) — the history.py stance — so
these cases run with a tmp directory and a pinned clock. The malformed
shapes matter most: a broken view silently dropped is how a curated
projection quietly loses a panel (design review, 2026-08-12), so every
refused file must surface as an errors entry naming the file and why.
"""

import json

import jsonschema

from common import SCHEMAS, strict

from system_explorer.views import load_views, view_problem

NOW = "2026-08-12T20:00:00Z"

GOOD = {
    "name": "storage-simple",
    "title": "Storage health",
    "audience": "someone who does not run Linux",
    "panels": [
        {"key": "pools", "title": "Pools",
         "subsystem": "storage", "collection": "pools",
         "columns": ["State", "CapacityPercent"]},
    ],
}


def test_no_directory_is_a_statement_not_an_error():
    envelope = load_views(None, NOW, "site-a")
    assert envelope == {"schema": "se.views/1", "observed_at": NOW,
                        "site": "site-a", "views": []}


def test_a_good_document_is_served_and_the_envelope_validates(tmp_path):
    (tmp_path / "storage.json").write_text(json.dumps(GOOD))
    envelope = load_views(str(tmp_path), NOW, "site-a")
    assert [v["name"] for v in envelope["views"]] == ["storage-simple"]
    assert "errors" not in envelope
    jsonschema.Draft202012Validator(SCHEMAS["se.views/1"]).validate(envelope)
    jsonschema.Draft202012Validator(strict(SCHEMAS["se.views/1"])).validate(envelope)


def test_a_broken_document_is_named_never_dropped(tmp_path):
    (tmp_path / "good.json").write_text(json.dumps(GOOD))
    (tmp_path / "notjson.json").write_text("{nope")
    (tmp_path / "empty-panels.json").write_text(json.dumps(
        {"name": "x", "title": "X", "panels": []}))
    envelope = load_views(str(tmp_path), NOW)
    assert len(envelope["views"]) == 1
    named = {entry["file"]: entry["error"] for entry in envelope["errors"]}
    assert set(named) == {"notjson.json", "empty-panels.json"}
    assert "panels" in named["empty-panels.json"]
    # The mixed envelope still validates: errors are part of the contract.
    jsonschema.Draft202012Validator(SCHEMAS["se.views/1"]).validate(envelope)


def test_problem_messages_name_the_first_missing_member():
    assert view_problem([]) == "not a JSON object"
    assert view_problem({"title": "X", "panels": [{}]}) == "missing name"
    assert view_problem({"name": "x", "title": "X",
                         "panels": [{"key": "a", "title": "A",
                                     "subsystem": "storage"}]}) \
        == "panels.0: missing collection"
    assert view_problem(GOOD) is None


def test_the_repo_fixture_round_trips_through_the_loader(tmp_path):
    # The published example's views must be documents the loader would serve —
    # the fixture and the loader cannot disagree about what a view is.
    from common import EXAMPLES_DIR
    fixture = json.loads((EXAMPLES_DIR / "views-storage-simple.json").read_text())
    for index, view in enumerate(fixture["views"]):
        (tmp_path / f"{index}.json").write_text(json.dumps(view))
    envelope = load_views(str(tmp_path), NOW)
    assert len(envelope["views"]) == len(fixture["views"])
    assert "errors" not in envelope


def test_a_configured_but_missing_directory_is_named_not_empty(tmp_path):
    # The first estate deploy handed the build host's store path to the
    # target: /hub/views answered 200 with views [] — present, empty,
    # quietly wrong. A configured directory that does not exist is a
    # deployment fault and the envelope says so.
    gone = str(tmp_path / "never-created")
    envelope = load_views(gone, NOW, "site-a")
    assert envelope["views"] == []
    assert envelope["errors"] == [
        {"file": gone, "error": "configured views directory does not exist"}]
    import jsonschema
    from common import SCHEMAS
    jsonschema.Draft202012Validator(SCHEMAS["se.views/1"]).validate(envelope)
