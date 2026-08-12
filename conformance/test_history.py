"""SPEC section 10: the pure diff behind /v1/changes, exercised directly.

agent/history.py's diff and since-parsing functions are pure (stdlib only,
like agent/rules/), so characteristic inputs go in and exact diffs come out —
no sqlite, no live acquisition, no HTTP. The envelope shape is proven by
validating a diff_items() product inside a full se.changes/1 document, so the
pure function and the schema cannot drift apart unnoticed.
"""

from datetime import datetime, timezone

import jsonschema
import pytest

from common import SCHEMAS, resolve_fact_path

from system_explorer.agent import history

NOW = datetime(2026, 8, 9, 16, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# parse_since: ISO or relative in, UTC ISO Z out; nonsense raises.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("2026-08-09T15:04:05Z", "2026-08-09T15:04:05Z"),
    ("2026-08-09T17:04:05+02:00", "2026-08-09T15:04:05Z"),
    ("2026-08-09T15:04:05", "2026-08-09T15:04:05Z"),  # naive is UTC
    ("-24h", "2026-08-08T16:00:00Z"),
    ("-30s", "2026-08-09T15:59:30Z"),
    ("-15m", "2026-08-09T15:45:00Z"),
    ("-7d", "2026-08-02T16:00:00Z"),
], ids=["iso-z", "iso-offset", "iso-naive", "rel-hours", "rel-seconds",
        "rel-minutes", "rel-days"])
def test_parse_since(value, expected):
    assert history.parse_since(value, now=NOW) == expected


@pytest.mark.parametrize("value", ["yesterday", "24h", "-24", "-3w", ""])
def test_parse_since_rejects_nonsense(value):
    with pytest.raises(ValueError):
        history.parse_since(value, now=NOW)


# ---------------------------------------------------------------------------
# changed_paths: the path language is the evidence-path language.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("before,after,expected", [
    # identical values, including nested ones, differ nowhere
    ({"facts": {"ActiveState": "active"}}, {"facts": {"ActiveState": "active"}}, []),
    # a changed scalar is reported at its dotted path
    ({"facts": {"ActiveState": "active"}}, {"facts": {"ActiveState": "failed"}},
     ["facts.ActiveState"]),
    # a key present on only one side differs at that key's path
    ({"facts": {}}, {"facts": {"NRestarts": 3}}, ["facts.NRestarts"]),
    ({"worst_opinion_level": "ok", "facts": {}}, {"facts": {}},
     ["worst_opinion_level"]),
    # lists of scalars are one value: order matters, one path
    ({"facts": {"Names": ["a", "b"]}}, {"facts": {"Names": ["b", "a"]}},
     ["facts.Names"]),
    # lists of dicts compare positionally, indices as digits
    ({"facts": {"vdevs": [{"state": "ONLINE"}, {"state": "ONLINE"}]}},
     {"facts": {"vdevs": [{"state": "ONLINE"}, {"state": "DEGRADED"}]}},
     ["facts.vdevs.1.state"]),
    # a length change in a dict list differs at the extra index
    ({"facts": {"Members": [{"Device": "sda1"}]}},
     {"facts": {"Members": [{"Device": "sda1"}, {"Device": "sdb1"}]}},
     ["facts.Members.1"]),
    # a type change is a difference at the node's path
    ({"facts": {"MainPID": 812}}, {"facts": {"MainPID": None}},
     ["facts.MainPID"]),
    ({"facts": {"State": {"Running": True}}}, {"facts": {"State": "running"}},
     ["facts.State"]),
], ids=["no-change", "scalar", "key-added", "key-removed", "scalar-list-order",
        "dict-list-positional", "dict-list-grew", "value-to-none", "type-change"])
def test_changed_paths(before, after, expected):
    assert history.changed_paths(before, after) == expected


def test_changed_paths_resolve_like_evidence():
    """Every reported path resolves via the conformance evidence-path walker
    on at least one side — a change entry cites facts the way an opinion does
    (SPEC section 10)."""
    before = {"facts": {"vdevs": [{"state": "ONLINE"}], "errors": 0}}
    after = {"facts": {"vdevs": [{"state": "FAULTED"}], "read_errors": 3}}
    for path in history.changed_paths(before, after):
        resolved = []
        for side in (before, after):
            try:
                resolved.append(resolve_fact_path(side, path))
            except KeyError:
                pass
        assert resolved, f"path {path!r} resolves on neither side"


# ---------------------------------------------------------------------------
# diff_items: identity carries the diff; empty sections are omitted.
# ---------------------------------------------------------------------------

def _unit(unit_id, state, pid):
    return {"id": unit_id, "type": "service", "native_id": unit_id.split(":", 1)[1],
            "facts": {"ActiveState": state, "MainPID": pid}}


def test_diff_items_no_change_is_empty():
    items = [_unit("unit:sshd.service", "active", 812)]
    assert history.diff_items(items, list(items)) == {}


def test_diff_items_added_removed_changed():
    before = [_unit("unit:sshd.service", "active", 812),
              _unit("unit:legacy-app.service", "active", 990)]
    after = [_unit("unit:sshd.service", "failed", 0),
             _unit("unit:podman-auto-update.timer", "active", 0)]
    diff = history.diff_items(before, after)
    assert diff == {
        "added": ["unit:podman-auto-update.timer"],
        "removed": ["unit:legacy-app.service"],
        "changed": [{"id": "unit:sshd.service",
                     "paths": ["facts.ActiveState", "facts.MainPID"]}],
    }


def test_diff_items_omits_empty_sections():
    before = [_unit("unit:sshd.service", "active", 812)]
    after = before + [_unit("unit:nginx.service", "active", 1200)]
    diff = history.diff_items(before, after)
    assert diff == {"added": ["unit:nginx.service"]}
    assert "removed" not in diff and "changed" not in diff


def test_diff_items_product_validates_in_envelope():
    """A diff_items() product dropped into a full se.changes/1 document
    validates — the pure function and changes.schema.json agree on shape."""
    before = [_unit("unit:sshd.service", "active", 812),
              _unit("unit:legacy-app.service", "active", 990)]
    after = [_unit("unit:sshd.service", "failed", 0)]
    envelope = {
        "schema": "se.changes/1",
        "host": {"machine_id": "0123456789abcdef0123456789abcdef", "hostname": "host-a"},
        "observed_at": "2026-08-09T16:20:31Z",
        "since_requested": "2026-08-08T16:20:31Z",
        "baseline": {"snapshot_at": "2026-08-08T16:12:04Z",
                     "boot_id": "fedcba9876543210fedcba9876543210"},
        "current_boot_id": "fedcba9876543210fedcba9876543210",
        "rebooted": False,
        "status": "ok",
        "subsystems": {"units": {"units": history.diff_items(before, after)}},
    }
    jsonschema.Draft202012Validator(SCHEMAS["se.changes/1"]).validate(envelope)


# ---------------------------------------------------------------------------
# The store round-trips both eras of the items column. Rows written since
# compression landed are zlib BLOBs (the store had reached 94 MB in three
# days on one host); rows before it are plain JSON text, and both stay
# readable forever — sniffed, never migrated. This is the store's first
# test with a real file: the pure-function stance above stands, but a
# format change earns a round trip.
# ---------------------------------------------------------------------------

def test_store_round_trips_and_reads_legacy_rows(tmp_path):
    import json
    import sqlite3
    from datetime import datetime, timedelta, timezone

    store = history.HistoryStore(tmp_path / "history.db")
    stamp = datetime.now(timezone.utc)
    early = (stamp - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    late = (stamp - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    items = [{"id": "unit:a.service", "type": "service", "native_id": "a.service",
              "facts": {"ActiveState": "active"}}]
    store.write_snapshot(early, "boot-1", {"units": {"units": items}},
                         retention_days=30)
    # A pre-compression row, exactly as the old writer stored it: text.
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "INSERT INTO snapshots VALUES (2, 'units', 'units', ?, 'boot-1', ?)",
            (late, json.dumps([{"id": "unit:b.service", "facts": {}}])))

    compressed_era = store.baseline(early)
    assert compressed_era["data"]["units"]["units"] == items
    legacy_era = store.baseline(late)
    assert legacy_era["data"]["units"]["units"][0]["id"] == "unit:b.service"

    # And the new row really is compressed at rest, not text wearing a BLOB.
    with sqlite3.connect(store.db_path) as conn:
        blob = conn.execute(
            "SELECT items FROM snapshots WHERE snapshot_id = 1").fetchone()[0]
    assert isinstance(blob, bytes) and blob[:1] == b"\x78"


def test_diff_ignores_the_derived_opinions_member():
    # Row opinions are derived from the row's own facts by the one
    # evaluator (rule 14): any genuine change already reports at a facts
    # path or worst_opinion_level. Diffing the derived subset would report
    # a phantom "opinions" change on every warn/critical row the first
    # sweep after the 0.6 upgrade, and double-report forever after.
    before = [{"id": "unit:a.service", "type": "service",
               "native_id": "a.service",
               "facts": {"ActiveState": "failed"},
               "worst_opinion_level": "critical"}]
    after = [{**before[0],
              "opinions": [{"key": "unit-health", "level": "critical",
                            "message": "Unit has failed (failed).",
                            "evidence": ["ActiveState"]}]}]
    assert history.diff_items(before, after) == {}
