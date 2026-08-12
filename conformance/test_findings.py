"""The findings surface lifts what rows already carry — never re-evaluates.

finding_records() and findings_envelope() are pure (agent/findings.py), so
these run with built rows and a pinned clock, the views.py arrangement. The
cases that matter most are the honesty ones: every carried opinion becomes
exactly one record with the rule-15 identity, and a collection that could
not be evaluated is NAMED in `unobserved` — the member that stops an
adapter failure reading at the hub as all of its findings resolving at
once.
"""

import jsonschema

from common import SCHEMAS, strict

from system_explorer.agent import envelope as env
from system_explorer.agent.findings import finding_records, findings_envelope

NOW = "2026-08-12T21:00:00Z"

FAILED_UNIT = env.item_summary(
    "unit:observer.service", "service", "observer.service",
    {"ActiveState": "failed", "NRestarts": 4},
    opinions=[
        env.opinion("unit-health", "critical", "Unit has failed (failed).",
                    ["ActiveState"]),
        env.opinion("restart-churn", "warn", "Service has restarted 4 times.",
                    ["NRestarts"]),
    ])
HEALTHY_UNIT = env.item_summary(
    "unit:sshd.service", "service", "sshd.service",
    {"ActiveState": "active"}, opinions=[], healthy="ok")


def test_only_rows_with_carried_opinions_become_findings():
    records = finding_records("units", "units", [HEALTHY_UNIT, FAILED_UNIT])
    assert [r["opinion"]["key"] for r in records] == ["unit-health", "restart-churn"]
    # One record per opinion, each carrying the identity the hub keys on
    # (object id + opinion key; host arrives on the envelope) and the
    # pointer back to the object that can prove or refute it now.
    for record in records:
        assert record["subsystem"] == "units"
        assert record["object"]["id"] == "unit:observer.service"
        assert record["evidence_ref"] == "/v1/evidence/units/units/unit:observer.service"


def test_the_object_name_rides_along_when_the_row_has_one():
    named = env.item_summary(
        "pool:example", "pool", "example",
        {"State": "DEGRADED"}, name="example",
        opinions=[env.opinion("pool-health", "critical", "Pool is DEGRADED.",
                              ["State"])])
    [record] = finding_records("storage", "pools", [named])
    assert record["object"]["name"] == "example"


def test_ids_with_slashes_keep_the_one_owner_encoding():
    dataset = env.item_summary(
        "dataset:tank/photos", "filesystem", "tank/photos",
        {"UsePercent": 91},
        opinions=[env.opinion("dataset-capacity", "warn", "91% of quota.",
                              ["UsePercent"])])
    [record] = finding_records("storage", "datasets", [dataset])
    assert record["evidence_ref"] == env.evidence_ref(
        "storage", "datasets", "dataset:tank/photos")


def test_the_envelope_validates_in_both_profiles():
    envelope = findings_envelope(
        NOW,
        finding_records("units", "units", [FAILED_UNIT]),
        [{"subsystem": "vms", "collection": "domains",
          "reason": "no libvirt read-only socket"}])
    assert envelope["status"] == "ok"
    jsonschema.Draft202012Validator(SCHEMAS["se.findings/1"]).validate(envelope)
    jsonschema.Draft202012Validator(strict(SCHEMAS["se.findings/1"])).validate(envelope)


def test_unobserved_is_present_even_when_empty():
    # The empty list is a statement — "everything evaluable was evaluated" —
    # and it is what licenses a consumer to read absence as resolution.
    envelope = findings_envelope(NOW, [], [])
    assert envelope["unobserved"] == []
    jsonschema.Draft202012Validator(strict(SCHEMAS["se.findings/1"])).validate(envelope)


def test_errors_make_the_sweep_partial_and_are_scrubbed():
    envelope = findings_envelope(
        NOW, [], [{"subsystem": "storage", "collection": "pools",
                   "reason": "TimeoutExpired: zpool status"}],
        errors=["storage/pools: HTTPStatusError: "
                "http://upstream/api?apikey=0123456789abcdef"])
    assert envelope["status"] == "partial"
    # Failure text is a credential channel (SPEC section 11, rule 10):
    # the query string never survives the envelope boundary.
    assert "apikey" not in envelope["errors"][0]
    assert "?[query-stripped]" in envelope["errors"][0]
    jsonschema.Draft202012Validator(SCHEMAS["se.findings/1"]).validate(envelope)


def test_a_narrowed_process_names_what_it_is_not_running():
    # SE_ADAPTERS selection removes whole subsystems from the sweep; the
    # envelope must say so or it claims full coverage falsely and the hub
    # resolves findings nobody looked at (adversarial review, 2026-08-12).
    from system_explorer.agent.findings import (DESELECTED_REASON,
                                                deselected_unobserved)
    entries = deselected_unobserved(
        {"docker": ["containers", "volumes", "networks"],
         "storage": ["pools", "lookups"],
         "logs": ["journal"],
         "packages": ["packages"]},
        declines={("logs", "journal"), ("packages", "packages")})
    named = {(entry["subsystem"], entry["collection"]) for entry in entries}
    # lookups and declined pairs can never bear findings from ANY process,
    # so they are skipped exactly as the live sweep skips them.
    assert named == {("docker", "containers"), ("docker", "volumes"),
                     ("docker", "networks"), ("storage", "pools")}
    assert all(entry["reason"] == DESELECTED_REASON for entry in entries)


def test_app_records_carry_their_locator_and_the_envelope_its_coverage():
    # One process, host and app subsystems at once: the app's findings and
    # unobserved entries must key under the app locator the collection
    # surfaces declare, and the envelope must state every locator it
    # fronts — or the hub reads "the app was never mentioned" as
    # "the app was observed clean" (adversarial review, 2026-08-12).
    from system_explorer.agent.findings import locator_scoped
    app_block = env.host_block(app="paperless")
    records = locator_scoped(
        finding_records("paperless", "instance", [
            env.item_summary("instance:paperless", "paperless-instance",
                             "paperless", {"DocumentCount": 0},
                             opinions=[env.opinion("paperless-empty",
                                                   "critical", "Zero documents.",
                                                   ["DocumentCount"])])]),
        app_block)
    assert records[0]["host"]["app"] == "paperless"
    unscoped = locator_scoped([{"subsystem": "units", "collection": "units",
                                "reason": "x"}], None)
    assert "host" not in unscoped[0]
    envelope = findings_envelope(NOW, records, [],
                                 locators=[env.HOST, app_block])
    assert envelope["locators"][1]["app"] == "paperless"
    jsonschema.Draft202012Validator(SCHEMAS["se.findings/1"]).validate(envelope)
    jsonschema.Draft202012Validator(
        strict(SCHEMAS["se.findings/1"])).validate(envelope)
