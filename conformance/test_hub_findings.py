"""The findings registry holds lifecycle without ever holding truth.

Every case runs against a real SQLite store in a tmp directory (the
test_history.py arrangement) with pinned clocks, and builds its host
envelopes through the AGENT's own builders — so these tests also pin the
two halves of the product to one contract: what agent/findings.py emits is
exactly what hub/findings.py folds.

The cases that matter most are section 6.3's four decisions, each with the
failure it forbids:

- lifecycle: first_seen survives recurrence (reappearance is the same
  finding recurring, not a new one);
- resolution is observed: only an agent that COULD look resolves a finding
  by no longer deriving it;
- absence never resolves: an unswept agent or an unobserved collection
  freezes lifecycle and withholds `current` — the absence-as-health shape,
  refused where it would corrupt history;
- acknowledgement styles, never removes: an acked finding stays in the
  list, and un-acking is an appended record, not an edit.
"""

import jsonschema

from common import SCHEMAS, strict

from system_explorer.agent import envelope as env
from system_explorer.agent.findings import finding_records, findings_envelope
from system_explorer.hub.findings import (FindingsRegistry, assemble,
                                          identity_key)

T0, T1, T2 = ("2026-08-12T20:00:00Z", "2026-08-12T21:00:00Z",
              "2026-08-12T22:00:00Z")
HOST_A = {"machine_id": "a" * 32, "hostname": "host-a"}
HOST_B = {"machine_id": "b" * 32, "hostname": "host-b"}

FAILED_UNIT = env.item_summary(
    "unit:observer.service", "service", "observer.service",
    {"ActiveState": "failed"},
    opinions=[env.opinion("unit-health", "critical",
                          "Unit has failed (failed).", ["ActiveState"])])
KEY_A = identity_key("a" * 32, "unit:observer.service", "unit-health")


def _sweep(agent: str, host: dict, items: list, now: str,
           unobserved: list | None = None) -> dict:
    return {"agent": agent, "envelope": findings_envelope(
        now, finding_records("units", "units", items),
        unobserved or [], host=host)}


def test_first_seen_survives_recurrence_and_last_seen_advances(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("host-a", HOST_A, [FAILED_UNIT], T0)], 90)
    registry.record_sweep(T1, [_sweep("host-a", HOST_A, [FAILED_UNIT], T1)], 90)
    [row] = registry.rows()
    assert row["first_seen"] == T0
    assert row["last_seen"] == T1
    assert row["key"] == KEY_A


def test_resolution_is_observed_never_declared(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("host-a", HOST_A, [FAILED_UNIT], T0)], 90)
    # The agent looked (units observed, nothing unobserved) and no longer
    # derives the finding: that IS resolution, and only that.
    clean = _sweep("host-a", HOST_A, [], T1)
    registry.record_sweep(T1, [clean], 90)
    view = assemble(T1, "site-a", False, [clean],
                    registry.rows(), registry.transitions())
    [finding] = view["findings"]
    assert finding["observable"] is True
    assert finding["current"] is False
    assert finding["first_seen"] == T0 and finding["last_seen"] == T0


def test_an_unobserved_collection_freezes_instead_of_resolving(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("host-a", HOST_A, [FAILED_UNIT], T0)], 90)
    broken = _sweep("host-a", HOST_A, [], T1, unobserved=[
        {"subsystem": "units", "collection": "units",
         "reason": "capability discovery failed: DBusError: no bus"}])
    registry.record_sweep(T1, [broken], 90)
    view = assemble(T1, "site-a", False, [broken],
                    registry.rows(), registry.transitions())
    [finding] = view["findings"]
    assert finding["observable"] is False
    # "Could not look" is not "looked and it was gone": no current claim.
    assert "current" not in finding
    assert finding["last_seen"] == T0


def test_an_unswept_agent_freezes_all_of_its_findings(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("host-a", HOST_A, [FAILED_UNIT], T0)], 90)
    dark = {"agent": "host-a", "error": "ConnectError: connection refused"}
    view = assemble(T1, "site-a", False, [dark],
                    registry.rows(), registry.transitions())
    assert view["hosts"]["host-a"] == {"swept": False,
                                       "error": "ConnectError: connection refused"}
    [finding] = view["findings"]
    assert finding["observable"] is False and "current" not in finding


def test_acknowledgement_marks_and_never_removes(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    sweep = _sweep("host-a", HOST_A, [FAILED_UNIT], T0)
    registry.record_sweep(T0, [sweep], 90)
    history = registry.append_transition(
        T1, KEY_A, "acknowledged", "the operator", "known-bad, replacement planned")
    assert [t["transition"] for t in history] == ["acknowledged"]
    view = assemble(T1, "site-a", True, [sweep],
                    registry.rows(), registry.transitions())
    [finding] = view["findings"]
    # Still present, still current, marked — styled, never suppressed.
    assert finding["current"] is True
    assert finding["acknowledged"] is True
    assert finding["transitions"][0]["by"] == "the operator"


def test_unacknowledging_is_an_appended_record_not_an_edit(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("host-a", HOST_A, [FAILED_UNIT], T0)], 90)
    registry.append_transition(T1, KEY_A, "acknowledged", "the operator", None)
    history = registry.append_transition(T2, KEY_A, "unacknowledged",
                                         "the operator", "it got worse")
    assert [t["transition"] for t in history] == ["acknowledged", "unacknowledged"]
    view = assemble(T2, "site-a", True,
                    [_sweep("host-a", HOST_A, [FAILED_UNIT], T2)],
                    registry.rows(), registry.transitions())
    assert view["findings"][0]["acknowledged"] is False
    assert len(view["findings"][0]["transitions"]) == 2


def test_a_transition_needs_a_finding_the_estate_has_derived(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    unknown = identity_key("c" * 32, "pool:ghost", "pool-health")
    assert registry.append_transition(T0, unknown, "acknowledged",
                                      "someone", None) is None


def test_retention_prunes_a_finding_with_its_transitions(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("host-a", HOST_A, [FAILED_UNIT], T0)], 90)
    registry.append_transition(T0, KEY_A, "acknowledged", "the operator", None)
    # A later sweep with retention 0: everything older than `now` ages out,
    # and the acknowledgement cannot outlive the finding it attached to.
    registry.record_sweep(T1, [_sweep("host-a", HOST_A, [], T1)], 0)
    assert registry.rows() == []
    assert registry.transitions() == {}


def test_the_rule15_locator_separates_two_instances_on_one_machine(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    first = {"agent": "apps-1", "envelope": findings_envelope(
        T0, finding_records("servarr", "indexers", [FAILED_UNIT]), [],
        host=env.host_block(app="readarr"))}
    second = {"agent": "apps-2", "envelope": findings_envelope(
        T0, finding_records("servarr", "indexers", [FAILED_UNIT]), [],
        host=env.host_block(app="readarr-audio"))}
    registry.record_sweep(T0, [first, second], 90)
    keys = {row["key"] for row in registry.rows()}
    assert len(keys) == 2  # same object id, same opinion, distinct identity


def test_without_a_registry_live_findings_are_lifecycle_less_not_absent():
    sweep = _sweep("host-a", HOST_A, [FAILED_UNIT], T0)
    view = assemble(T0, "site-a", False, [sweep],
                    registry_note="findings registry disabled: no state dir")
    [finding] = view["findings"]
    assert finding["current"] is True and finding["observable"] is True
    assert "first_seen" not in finding and "acknowledged" not in finding
    assert view["errors"] == ["findings registry disabled: no state dir"]


def test_the_assembled_envelope_validates_in_both_profiles(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    sweep = _sweep("host-a", HOST_A, [FAILED_UNIT], T0,
                   unobserved=[{"subsystem": "vms", "collection": "domains",
                                "reason": "no libvirt socket"}])
    registry.record_sweep(T0, [sweep], 90)
    registry.append_transition(T1, KEY_A, "acknowledged", "the operator", "noted")
    dark = {"agent": "host-b", "error": "ConnectError: refused"}
    view = assemble(T1, "site-a", True, [sweep, dark],
                    registry.rows(), registry.transitions())
    jsonschema.Draft202012Validator(SCHEMAS["se.hub-findings/1"]).validate(view)
    jsonschema.Draft202012Validator(
        strict(SCHEMAS["se.hub-findings/1"])).validate(view)


def test_ordering_puts_attention_before_history(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    warn_row = env.item_summary(
        "dataset:tank/photos", "filesystem", "tank/photos", {"UsePercent": 91},
        opinions=[env.opinion("dataset-capacity", "warn", "91% of quota.",
                              ["UsePercent"])])
    both = {"agent": "host-a", "envelope": findings_envelope(
        T0,
        finding_records("units", "units", [FAILED_UNIT])
        + finding_records("storage", "datasets", [warn_row]),
        [], host=HOST_A)}
    registry.record_sweep(T0, [both], 90)
    # Second sweep: the dataset resolves, a dark host-b freezes its pool.
    registry.record_sweep(T1, [_sweep("host-b", HOST_B, [
        env.item_summary("pool:tank", "pool", "tank", {"State": "DEGRADED"},
                         opinions=[env.opinion("pool-health", "critical",
                                               "Pool is DEGRADED.", ["State"])])
    ], T1)], 90)
    latest = _sweep("host-a", HOST_A, [FAILED_UNIT], T2)
    dark = {"agent": "host-b", "error": "ConnectError: refused"}
    view = assemble(T2, "site-a", False, [latest, dark],
                    registry.rows(), registry.transitions())
    shapes = [(f.get("current"), f["observable"], f["opinion"]["level"])
              for f in view["findings"]]
    assert shapes == [(True, True, "critical"),      # current attention first
                      (None, False, "critical"),     # frozen next
                      (False, True, "warn")]         # resolved history last


def test_retention_never_prunes_what_it_could_not_see(tmp_path):
    # The freeze must reach pruning too: an adapter broken for longer than
    # retention used to erase the finding AND its acknowledgement history
    # without any observation of absence (adversarial review, 2026-08-12).
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("host-a", HOST_A, [FAILED_UNIT], T0)], 90)
    registry.append_transition(T0, KEY_A, "acknowledged", "the operator", None)
    frozen = _sweep("host-a", HOST_A, [], T1, unobserved=[
        {"subsystem": "units", "collection": "units",
         "reason": "capability discovery failed: DBusError: no bus"}])
    registry.record_sweep(T1, [frozen], 0)  # horizon at now: everything stale
    [row] = registry.rows()
    assert row["first_seen"] == T0  # survived, history intact
    assert registry.transitions()[KEY_A][0]["transition"] == "acknowledged"
    # A hub polled while the whole estate is dark prunes nothing at all.
    registry.record_sweep(T2, [], 0)
    assert len(registry.rows()) == 1


def test_retention_prunes_only_where_absence_was_observed(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("host-a", HOST_A, [FAILED_UNIT], T0)], 90)
    # This sweep COULD see units (nothing unobserved) and the finding is
    # gone: with the horizon at now, ageing out is legitimate.
    registry.record_sweep(T1, [_sweep("host-a", HOST_A, [], T1)], 0)
    assert registry.rows() == []


def test_visibility_is_keyed_on_the_locator_not_the_config_name(tmp_path):
    # Renaming the hub's config entry for a host must not change which
    # findings count as lookable-at: the sweep carries the same machine_id,
    # so the registry row recorded under the OLD name still resolves.
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("old-name", HOST_A, [FAILED_UNIT], T0)], 90)
    renamed = _sweep("new-name", HOST_A, [], T1)
    registry.record_sweep(T1, [renamed], 90)
    view = assemble(T1, "site-a", False, [renamed],
                    registry.rows(), registry.transitions())
    [finding] = view["findings"]
    assert finding["observable"] is True and finding["current"] is False


def test_a_hostless_envelope_yields_a_swept_entry_without_null_members():
    view = assemble(T0, "site-a", False,
                    [{"agent": "host-a", "envelope": {
                        "schema": "se.findings/1", "observed_at": T0,
                        "status": "ok", "findings": [], "unobserved": []}}])
    entry = view["hosts"]["host-a"]
    assert entry["swept"] is True
    assert "host" not in entry  # omission, never null (the hub's own schema)
    import jsonschema
    from common import SCHEMAS, strict
    jsonschema.Draft202012Validator(
        strict(SCHEMAS["se.hub-findings/1"])).validate(view)


def test_envelope_problem_names_the_first_reason_or_none():
    from system_explorer.hub.findings import envelope_problem
    good = findings_envelope(T0, [], [], host=HOST_A)
    assert envelope_problem(good) is None
    assert envelope_problem([]) == "not a JSON object"
    assert "schema" in envelope_problem({"schema": "se.status/1"})
    assert envelope_problem({"schema": "se.findings/1", "status": "ok",
                             "findings": [{}], "unobserved": []}) \
        == "findings.0: object.id missing"
    assert envelope_problem({"schema": "se.findings/1", "status": "ok",
                             "findings": [], "unobserved": {}}) \
        == "unobserved is not a list"


def test_the_transitions_receipt_matches_its_published_schema(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("host-a", HOST_A, [FAILED_UNIT], T0)], 90)
    history = registry.append_transition(T1, KEY_A, "acknowledged",
                                         "the operator", None)
    from system_explorer.hub.findings import SCHEMA_TRANSITIONS
    receipt = {"schema": SCHEMA_TRANSITIONS,
               "finding": {"machine_id": "a" * 32,
                           "object_id": "unit:observer.service",
                           "opinion_key": "unit-health"},
               "transitions": history}
    import jsonschema
    from common import SCHEMAS, strict
    jsonschema.Draft202012Validator(SCHEMAS["se.hub-transitions/1"]).validate(receipt)
    jsonschema.Draft202012Validator(
        strict(SCHEMAS["se.hub-transitions/1"])).validate(receipt)


def test_a_mixed_process_keys_app_findings_under_the_app_locator(tmp_path):
    registry = FindingsRegistry(tmp_path / "findings.db")
    app_block = {"machine_id": "a" * 32, "hostname": "host-a",
                 "app": "paperless"}
    record = finding_records("paperless", "instance", [
        env.item_summary("instance:paperless", "paperless-instance",
                         "paperless", {"DocumentCount": 0},
                         opinions=[env.opinion("paperless-empty", "critical",
                                               "Zero documents.",
                                               ["DocumentCount"])])])[0]
    envelope = findings_envelope(T0, [{**record, "host": app_block}], [],
                                 host=HOST_A, locators=[HOST_A, app_block])
    registry.record_sweep(T0, [{"agent": "host-a", "envelope": envelope}], 90)
    [row] = registry.rows()
    assert row["key"][0:3] == ("a" * 32, "", "paperless")
    view = assemble(T0, "site-a", False,
                    [{"agent": "host-a", "envelope": envelope}],
                    registry.rows(), registry.transitions())
    [finding] = view["findings"]
    assert finding["host"]["app"] == "paperless"
    assert finding["current"] is True


def test_one_narrowed_sibling_cannot_freeze_what_the_other_observed(tmp_path):
    # Two processes, one machine: the apps process honestly declines the
    # host subsystems (deselected -> unobserved under the host locator),
    # while the host process observes them. The host process's clean sweep
    # must still RESOLVE a stale host finding — a sibling's decline is not
    # an estate-wide blindfold. And with only the apps process swept, the
    # same finding freezes.
    registry = FindingsRegistry(tmp_path / "findings.db")
    registry.record_sweep(T0, [_sweep("host-a", HOST_A, [FAILED_UNIT], T0)], 90)
    apps = {"agent": "host-a-apps", "envelope": findings_envelope(
        T1, [], [{"subsystem": "units", "collection": "units",
                  "reason": "subsystem not selected in this process"}],
        host=HOST_A, locators=[HOST_A])}
    host_clean = _sweep("host-a", HOST_A, [], T1)
    both = [apps, host_clean]
    registry.record_sweep(T1, both, 90)
    view = assemble(T1, "site-a", False, both,
                    registry.rows(), registry.transitions())
    [finding] = view["findings"]
    assert finding["observable"] is True and finding["current"] is False
    apps_only = [apps]
    view = assemble(T1, "site-a", False, apps_only,
                    registry.rows(), registry.transitions())
    [finding] = view["findings"]
    assert finding["observable"] is False and "current" not in finding


# ── the registry says what it covers ─────────────────────────────────────

def test_the_host_listing_states_that_it_is_a_registry_not_a_discovery():
    """Asked "are all hosts up to date", this listing answered yes while the
    estate's only internet-facing host sat five revisions behind, registered
    with no hub and absent from every listing. The scope WAS the whole
    defect: every host it knew about was up to date.

    A registry is configuration, and the honest place to say so is beside the
    answer rather than in a tool description a consumer may never have read —
    an LLM reading `hosts` as the set of hosts that exist is the case this
    sentence is for.
    """
    import asyncio
    from system_explorer.hub import server

    async def no_agents_reachable():
        return {name: {"reachable": False, "error": "not probed in this test"}
                for name in server.AGENTS}

    original = (server.AGENTS, server.SIBLINGS, server._local_hosts)
    server.AGENTS = {"one": "http://one", "two": "http://two"}
    server.SIBLINGS = {}
    server._local_hosts = no_agents_reachable
    try:
        body = asyncio.run(server.hub_hosts())
    finally:
        server.AGENTS, server.SIBLINGS, server._local_hosts = original

    assert "2 agent(s) this hub is configured with" in body["scope"]
    assert "registry, not a discovery" in body["scope"]
    assert "indistinguishable from it not existing" in body["scope"], (
        "the sentence must name the ambiguity, not merely hedge: absent and "
        "non-existent are the two answers a consumer has to tell apart"
    )
