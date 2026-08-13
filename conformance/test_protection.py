"""The protection surfaces, folded — and the distinctions that make them
worth reading.

Five states, not two: declared, implemented, running-green, proven by
restore, and tried-and-failed. The tests below pin the places that
collapse if nobody is watching — a hop declared and never built, a job
that has never once succeeded (which is not the same as a job that
failed), a target running green with nothing ever restored from it, a
restore somebody performed and could not read back, and a verdict nobody
has recomputed still rendering as current. The estate's own invariants
call these 5 and 6; this file is where they stop being prose.

Two joins are pinned here because both are silent when they break: a job
keyed for its HOP rather than its target still has to find its class, and
a job the declaration names nowhere has to SAY that rather than take the
gentler grade in silence.

No estate hostnames or real target names: the fixture is a miniature
estate of its own, and the shapes are what matter.
"""

import asyncio
import json
import time

import pytest

from system_explorer.agent.adapters import protection as mod
from system_explorer.agent.rules import protection as rules

MANIFEST = {
    "schema": 1,
    "counts": {"backup": 3, "replicate": 1, "recreate": 0},
    "destinations": {
        "near-zfs": {"kind": "zfs-recv", "independent": False,
                     "immutability": None,
                     "pruneAuthority": "the receiving host's own retention"},
        "offsite": {"kind": "restic-s3", "independent": True,
                    "immutability": "Object Lock is enabled; default "
                                    "retention is deliberately off",
                    "pruneAuthority": "a maintenance identity absent from "
                                      "every source host"},
    },
    "targets": {
        # Both hops built, and proven from ONE of them — the shape a single
        # cross-rung date would render as simply "proven".
        "documents": {
            "class": "backup", "kind": "app-export", "ownerHost": "host-a",
            "source": "app:documents", "retention": "long", "cadence": "daily",
            "destinations": ["near-zfs", "offsite"],
            "implementedBy": {"near-zfs": "host-a:documents",
                              "offsite": "host-b:documents-offsite"},
            "proofs": [{"at": "2026-08-13", "rung": "offsite",
                        "scope": "3 files sampled", "result": "pass",
                        "comparedAgainst": "the live tree",
                        "record": "docs/recovery-proofs.md"}],
            "lastProvenAt": {"offsite": "2026-08-13"},
        },
        # Irreplaceable, replicated next door, and NOTHING off-site: the
        # shape that hid behind green replication until the estate began
        # asking per hop instead of per target.
        "photos": {
            "class": "backup", "kind": "zfs-dataset", "ownerHost": "host-a",
            "source": "pool/photos", "cadence": "hourly",
            "destinations": ["near-zfs", "offsite"],
            "implementedBy": {"near-zfs": "host-a:photos"},
            "proofs": [], "lastProvenAt": {},
        },
        # The off-site push registered under its OWN key on this host,
        # because the job is named for the hop and the target's name is
        # already taken by the capture. Nothing but implementedBy ties
        # `ledgers-offsite` to what it protects. Its one restore attempt
        # came back wrong.
        "ledgers": {
            "class": "backup", "kind": "app-export", "ownerHost": "host-a",
            "source": "app:ledgers", "retention": "long", "cadence": "daily",
            "destinations": ["near-zfs", "offsite"],
            "implementedBy": {"near-zfs": "host-a:ledgers",
                              "offsite": "host-a:ledgers-offsite"},
            "proofs": [{"at": "2026-08-12", "rung": "offsite",
                        "scope": "the whole export", "result": "fail",
                        "comparedAgainst": "the live tree — bytes differed",
                        "record": "docs/recovery-proofs.md"}],
            "lastProvenAt": {},
        },
        # Someone else's target: facts here, verdicts on its owner.
        "scratch": {
            "class": "replicate", "kind": "fs-mirror", "ownerHost": "host-b",
            "source": "/srv/scratch", "cadence": "daily",
            "destinations": ["near-zfs"],
            "implementedBy": {}, "proofs": [], "lastProvenAt": {},
        },
    },
}

# Relative, never a literal: the verdict's own age is now a fact, so a
# hardcoded stamp would rot into a spurious staleness warn as the fixture
# ages and the suite would start failing on the calendar.
CHECKED_AT = int(time.time()) - 1800

STATUS = {
    "schema": 1, "host": "host-a", "checkedAt": CHECKED_AT,
    "jobs": [
        {"job": "documents", "state": "ok", "basis": "last-success",
         "ageSeconds": 3600, "maxAgeSeconds": 172800, "lastResult": "success"},
        {"job": "photos", "state": "stale",
         "basis": "registered-never-succeeded", "ageSeconds": 400000,
         "maxAgeSeconds": 172800, "lastResult": "none"},
        # Keyed for the hop, not the target.
        {"job": "ledgers-offsite", "state": "stale",
         "basis": "registered-never-succeeded", "ageSeconds": 400000,
         "maxAgeSeconds": 172800, "lastResult": "none"},
        # A registered job the declaration names nowhere — a maintenance
        # timer, or a protection job that has lost its join. Which of the
        # two is exactly what the row may not silently decide.
        {"job": "housekeeping-scrub", "state": "stale",
         "basis": "registered-never-succeeded", "ageSeconds": 900000,
         "maxAgeSeconds": 691200, "lastResult": "none"},
    ],
    "unimplemented": [],
    "unimplementedHops": ["photos -> offsite"],
}


@pytest.fixture
def estate(tmp_path, monkeypatch):
    """A miniature protection layer on disk, at the paths the adapter
    reads, on the host that owns most of it."""
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    (tmp_path / "manifest.json").write_text(json.dumps(MANIFEST))
    (tmp_path / "status.json").write_text(json.dumps(STATUS))
    for suffix, result in (("last", "success"), ("last-success", "success")):
        (receipts / f"documents.{suffix}.json").write_text(json.dumps({
            "schema": 1, "job": "documents", "host": "host-a",
            "unit": "homelab-backup-documents.service",
            "finishedAt": "2026-08-13T02:00:00+00:00",
            "finishedAtEpoch": 1786596000, "result": result,
            "exitStatus": "0"}))
    monkeypatch.setattr(mod, "MANIFEST", str(tmp_path / "manifest.json"))
    monkeypatch.setattr(mod, "STATUS", str(tmp_path / "status.json"))
    monkeypatch.setattr(mod, "RECEIPTS", str(receipts))
    # The join from a hop-named job back to its target is host-qualified,
    # so the fixture states which host it is standing on rather than
    # inheriting the machine running the suite.
    monkeypatch.setattr(mod.env, "HOST", {"machine_id": "x",
                                          "hostname": "host-a"})
    return tmp_path


def rows(collection, adapter=None):
    return asyncio.run((adapter or mod.Adapter()).acquire(collection))


def test_a_declared_hop_with_no_job_is_named_not_averaged():
    facts = mod.target_facts("photos", MANIFEST["targets"]["photos"],
                             MANIFEST["destinations"])
    assert facts["ImplementedHops"] == ["near-zfs"]
    assert facts["UnimplementedHops"] == ["offsite"]
    # The distinction the whole collection exists for: independence is a
    # property of the destination, and it is the one that decides whether
    # the data survives losing the site.
    assert facts["IndependentDestinations"] == ["offsite"]


def test_an_implemented_hop_names_the_job_that_builds_it():
    """"Built" with nothing to go and look at is half a fact: the
    declaration says which job on which host, and the estate splits
    execution by verb, so the answer is routinely another machine."""
    facts = mod.target_facts("documents", MANIFEST["targets"]["documents"],
                             MANIFEST["destinations"])
    assert facts["HopImplementedBy"] == ["near-zfs -> host-a:documents",
                                         "offsite -> host-b:documents-offsite"]


def test_proofs_are_per_rung_because_proving_one_proves_nothing_else():
    facts = mod.target_facts("documents", MANIFEST["targets"]["documents"],
                             MANIFEST["destinations"])
    assert facts["ProvenRungs"] == ["offsite"]
    # Per rung, and never one date for the target: a cross-rung maximum is
    # a date about ONE copy wearing the whole target's name.
    assert facts["LastProvenAt"] == ["offsite: 2026-08-13"]
    # Proven off-site says nothing about the rung an operator reaches for
    # first, so the near copy stays listed as unproven.
    assert facts["UnprovenRungs"] == ["near-zfs"]
    assert facts["ProofRecord"] == "docs/recovery-proofs.md"
    # And the caveat travels with the date: "3 files sampled" is not a
    # restore of the artifact, and a row that drops the scope oversells
    # every sampled proof it carries.
    assert facts["ProofScope"] == ["offsite 2026-08-13: 3 files sampled"]
    assert facts["ProofComparedAgainst"] == \
        ["offsite 2026-08-13: the live tree"]


def test_a_target_never_restored_from_says_so_by_absence_of_a_date():
    facts = mod.target_facts("photos", MANIFEST["targets"]["photos"],
                             MANIFEST["destinations"])
    assert "LastProvenAt" not in facts  # never proven, and never a tick
    assert facts["UnprovenRungs"] == ["near-zfs", "offsite"]


def test_a_proof_from_the_rung_reached_for_first_certifies_no_destination():
    """The source host's own snapshot history is a rung a proof may cite
    and not a destination at all: it survives neither the disk nor the
    site. Judged by a single cross-rung date, one such proof renders a
    target nothing has ever been read back from as proven."""
    raw = {"class": "backup", "ownerHost": "host-a",
           "destinations": ["near-zfs", "offsite"],
           "implementedBy": {"near-zfs": "host-a:ledgers",
                             "offsite": "host-a:ledgers-offsite"},
           "proofs": [{"at": "2026-08-13", "rung": "local-snapshots",
                       "scope": "one file", "result": "pass",
                       "comparedAgainst": "the live tree",
                       "record": "docs/recovery-proofs.md"}],
           "lastProvenAt": {"local-snapshots": "2026-08-13"}}
    facts = mod.target_facts("ledgers", raw, MANIFEST["destinations"])
    assert facts["ProvenRungs"] == ["local-snapshots"]
    assert facts["UnprovenRungs"] == ["near-zfs", "offsite"]
    fired = {opinion["key"] for opinion in rules.target_opinions(facts)}
    assert "protection-unproven" in fired, \
        "one rung's proof vouched for the rungs nothing came back from"
    message = [opinion["message"] for opinion in rules.target_opinions(facts)
               if opinion["key"] == "protection-unproven"][0]
    assert "near-zfs, offsite" in message and "local-snapshots" in message


def test_a_restore_tried_and_failed_is_not_a_restore_never_tried():
    """The declaration records failed attempts deliberately and only
    passes reach lastProvenAt, so a row that reads proofs for their record
    alone publishes the most alarming fact it can hold as the ordinary
    absence of one."""
    tried = mod.target_facts("ledgers", MANIFEST["targets"]["ledgers"],
                             MANIFEST["destinations"])
    never = mod.target_facts("photos", MANIFEST["targets"]["photos"],
                             MANIFEST["destinations"])
    assert tried["FailedProofRungs"] == ["offsite"]
    assert tried["LastFailedProofAt"] == "2026-08-12"
    assert "FailedProofRungs" not in never
    assert {(opinion["key"], opinion["level"])
            for opinion in rules.target_opinions(tried)} == {
        ("protection-proof-failed", "warn"), ("protection-unproven", "info")}
    assert {opinion["key"] for opinion in rules.target_opinions(never)} == {
        "protection-no-durable-copy", "protection-unproven"}


def test_a_later_pass_answers_a_failure_and_an_earlier_one_does_not():
    """Invariant 5 the right way up: a rung that passed once and has
    failed since is not proven, and a rung that failed once and has passed
    since is not still failing."""
    def facts_for(proof_at, proven_at):
        raw = {"class": "backup", "ownerHost": "host-a",
               "destinations": ["offsite"],
               "implementedBy": {"offsite": "host-a:ledgers-offsite"},
               "proofs": [{"at": proof_at, "rung": "offsite",
                           "scope": "the whole export", "result": "fail",
                           "comparedAgainst": "the live tree",
                           "record": "docs/recovery-proofs.md"}],
               "lastProvenAt": {"offsite": proven_at}}
        return mod.target_facts("ledgers", raw, MANIFEST["destinations"])

    failed_since = facts_for("2026-08-13", "2026-08-01")
    assert failed_since["FailedProofRungs"] == ["offsite"]
    answered = facts_for("2026-08-01", "2026-08-13")
    assert "FailedProofRungs" not in answered


def test_the_immutability_sentence_is_carried_verbatim():
    # It is a security claim a person wrote and corrected; a paraphrase
    # here would be SE making a security claim of its own.
    facts = mod.destination_facts(MANIFEST["destinations"]["offsite"])
    assert facts["Immutability"] == \
        MANIFEST["destinations"]["offsite"]["immutability"]
    assert facts["Independent"] is True
    assert "Immutability" not in mod.destination_facts(
        MANIFEST["destinations"]["near-zfs"])  # states none, invents none


def test_never_ran_and_ran_and_failed_are_different_rows():
    ran_and_failed = mod.job_facts(
        {"job": "x", "state": "ok", "basis": "last-success",
         "ageSeconds": 60, "maxAgeSeconds": 172800, "lastResult": "exit-code"},
        {"last": {"finishedAt": "2026-08-13T04:00:00+00:00",
                  "exitStatus": "1", "unit": "x.service"},
         "last-success": {"finishedAt": "2026-08-12T04:00:00+00:00"}}, "backup")
    assert ran_and_failed["LastResult"] == "exit-code"
    assert ran_and_failed["LastSuccessAt"] == "2026-08-12T04:00:00+00:00"

    never_ran = mod.job_facts(
        {"job": "y", "state": "stale", "basis": "registered-never-succeeded",
         "ageSeconds": 400000, "maxAgeSeconds": 172800, "lastResult": "none"},
        {}, "backup")
    assert never_ran["Basis"] == "registered-never-succeeded"
    # "none" is the checker's filler for a job with no receipt at all; a
    # fact saying the last result was "none" would read as a real outcome.
    assert "LastResult" not in never_ran
    assert "LastSuccessAt" not in never_ran


def test_a_first_run_that_failed_does_not_claim_an_earlier_success():
    """A failed run over a standing success still leaves a copy; a failed
    run over no success at all leaves none, and is unstale only because
    its first window has not passed yet. Every newly registered job spends
    its first window in the second state."""
    first = mod.job_facts(
        {"job": "x", "state": "ok", "basis": "registered-never-succeeded",
         "ageSeconds": 7200, "maxAgeSeconds": 129600},
        {"last": {"finishedAt": "2026-08-13T01:00:00+00:00",
                  "result": "exit-code", "exitStatus": "1",
                  "unit": "x.service"}}, "backup")
    fired = rules.job_opinions(first)
    assert [(op["key"], op["level"]) for op in fired] == \
        [("protection-first-run-failed", "warn")]
    assert "never succeeded" in fired[0]["message"]
    assert "LastSuccessAt" not in first


def test_the_last_runs_result_comes_from_the_receipt_not_the_hourly_check():
    """The checker reads the same receipt, but up to 65 minutes earlier
    (hourly, plus five minutes of jitter). One row must not mix two
    vintages of one run: "succeeded" beside exit status 1 is the warn the
    two-receipt design exists to produce, suppressed for an hour."""
    facts = mod.job_facts(
        {"job": "x", "state": "ok", "basis": "last-success",
         "ageSeconds": 1800, "maxAgeSeconds": 172800,
         "lastResult": "success"},
        {"last": {"finishedAt": "2026-08-13T10:30:00+00:00",
                  "result": "exit-code", "exitStatus": "1",
                  "unit": "x.service"},
         "last-success": {"finishedAt": "2026-08-13T09:30:00+00:00"}},
        "backup")
    assert facts["LastResult"] == "exit-code"
    assert [op["key"] for op in rules.job_opinions(facts)] == \
        ["protection-last-run-failed"]
    # The receipt is the preferred source, never the required one: a job
    # whose receipt this host cannot open still states what the last check
    # saw, and says which it is.
    fallback = mod.job_facts(
        {"job": "x", "state": "ok", "basis": "last-success",
         "ageSeconds": 1800, "maxAgeSeconds": 172800,
         "lastResult": "exit-code"}, {}, "backup")
    assert fallback["LastResult"] == "exit-code"


def test_an_unreadable_document_is_a_stated_fault_not_an_empty_estate(
        tmp_path, monkeypatch):
    broken = tmp_path / "manifest.json"
    broken.write_text("{ half a manif")
    monkeypatch.setattr(mod, "MANIFEST", str(broken))
    document, problem = mod._load(str(broken))
    assert document is None and "JSONDecodeError" in problem
    capability = asyncio.run(mod.Adapter().capability())
    assert capability["available"] is False
    assert "could not be read" in capability["reason"]
    # And absence is the OTHER answer, distinguishable from this one.
    monkeypatch.setattr(mod, "MANIFEST", str(tmp_path / "absent.json"))
    assert mod._load(str(tmp_path / "absent.json")) == (None, None)
    assert "declares no protection inventory" in \
        asyncio.run(mod.Adapter().capability())["reason"]


def test_a_receipt_that_will_not_open_is_not_a_job_that_never_succeeded(
        estate):
    """Three answers, not two: written and readable, written and
    unreadable, never written. The middle one is where a corrupt file
    would otherwise render as the innocent absence of one."""
    receipt = estate / "receipts" / "documents.last-success.json"
    receipt.write_text('{"schema":1,"job":"docum')
    truncated = {row["id"]: row for row in rows("jobs")}["job:documents"]
    assert "LastSuccessAt" not in truncated["facts"]
    assert "JSONDecodeError" in truncated["facts"]["ReceiptsUnobservable"]
    assert truncated["worst_opinion_level"] == "warn"
    # The evidence can show its object: the broken file appears as itself
    # rather than as a gap in the pair the row rests on.
    evidence = asyncio.run(
        mod.Adapter().get_evidence("jobs", "job:documents"))
    assert set(evidence["payload"][mod.RECEIPTS]) == {"last"}
    assert f"{mod.RECEIPTS} (unreadable)" in evidence["payload"]

    receipt.unlink()
    absent = {row["id"]: row for row in rows("jobs")}["job:documents"]
    assert "ReceiptsUnobservable" not in absent["facts"]
    assert truncated["facts"] != absent["facts"], \
        "an unreadable receipt rendered byte-identically to an absent one"


def test_a_frozen_verdict_is_not_a_current_green_board(estate):
    """status.json only changes when the checker COMPLETES, and the file
    persists — so a stopped timer leaves every row reporting the state it
    last saw, for ever. This is invariant 6 (a scrub timer reporting
    success while never firing) inside the adapter written to catch it."""
    fresh = {row["id"]: row for row in rows("jobs")}["job:documents"]
    assert fresh["facts"]["CheckedAt"] == mod._epoch_iso(CHECKED_AT)
    assert fresh["facts"]["CheckedAgeSeconds"] >= 1800
    assert fresh["worst_opinion_level"] == "ok"  # green, and honestly so

    frozen = dict(STATUS, checkedAt=CHECKED_AT - 40 * 86400)
    (estate / "status.json").write_text(json.dumps(frozen))
    stopped = {row["id"]: row for row in rows("jobs")}["job:documents"]
    assert stopped["facts"]["State"] == "ok"  # the checker's word, kept
    assert stopped["worst_opinion_level"] == "warn"
    assert [op["key"] for op in stopped["opinions"]] == \
        ["protection-verdict-stale"]


def test_verdicts_are_scoped_to_the_owner_so_one_gap_alerts_once(
        estate, monkeypatch):
    adapter = mod.Adapter()
    by_id = {row["id"]: row for row in rows("targets", adapter)}
    # The estate-wide declaration is readable everywhere...
    assert by_id["target:scratch"]["facts"]["UnimplementedHops"] == ["near-zfs"]
    # ...but the verdict on another host's target belongs to that host: no
    # severity claim at all, which is not the same as claiming health.
    assert "worst_opinion_level" not in by_id["target:scratch"]
    assert by_id["target:photos"]["worst_opinion_level"] == "warn"
    # Built, green, and proven from one rung only: info, never ok. The row
    # that is green everywhere else is exactly where this gets lost.
    assert by_id["target:documents"]["worst_opinion_level"] == "info"
    # The full set lives on the opened object (rows carry the attention
    # subset only — rule 14).
    opened = asyncio.run(adapter.get_object("targets", "target:photos"))
    assert {opinion["key"] for opinion in opened["opinions"]} == \
        {"protection-no-durable-copy", "protection-unproven"}
    documents = asyncio.run(adapter.get_object("targets", "target:documents"))
    assert [opinion["key"] for opinion in documents["opinions"]] == \
        ["protection-unproven"]
    # An object nobody judged says so, instead of reading like one judged
    # and found clean — the two are the same envelope otherwise.
    unjudged = asyncio.run(adapter.get_object("targets", "target:scratch"))
    assert "opinions" not in unjudged
    assert any("NOT JUDGED HERE" in note
               for note in unjudged["source"]["notes"])
    assert not any("NOT JUDGED HERE" in note
                   for note in documents["source"]["notes"])

    monkeypatch.setattr(mod.env, "HOST", {"machine_id": "y",
                                          "hostname": "host-b"})
    moved = mod.Adapter()
    by_id = {row["id"]: row for row in rows("targets", moved)}
    assert "worst_opinion_level" not in by_id["target:photos"]
    assert by_id["target:scratch"]["worst_opinion_level"] == "info"
    owned = asyncio.run(moved.get_object("targets", "target:scratch"))
    assert [opinion["key"] for opinion in owned["opinions"]] == \
        ["protection-hop-unimplemented"]


def test_a_job_row_joins_its_targets_class_and_its_own_receipts(estate):
    by_id = {row["id"]: row for row in rows("jobs")}
    documents = by_id["job:documents"]["facts"]
    assert documents["TargetClass"] == "backup"
    assert documents["Unit"] == "homelab-backup-documents.service"
    assert documents["LastSuccessAt"] == "2026-08-13T02:00:00+00:00"
    # Irreplaceable data whose job has never once succeeded is the only
    # critical this subsystem states.
    photos = by_id["job:photos"]
    assert photos["worst_opinion_level"] == "critical"


def test_a_job_keyed_for_its_hop_still_finds_the_class_it_protects(estate):
    """The job that carries the only independent copy is routinely named
    for the hop rather than the target — the target's own name is already
    taken by the capture. Joined by name equality alone it grades quieter
    than the LAN hop beside it, on a naming coincidence."""
    offsite = {row["id"]: row for row in rows("jobs")}["job:ledgers-offsite"]
    assert offsite["facts"]["TargetClass"] == "backup"
    assert offsite["facts"]["ImplementsHops"] == ["ledgers -> offsite"]
    assert offsite["worst_opinion_level"] == "critical"


def test_a_job_the_declaration_names_nowhere_says_so_rather_than_softening(
        estate):
    """An unjoined class is unknown, not known to be small. The softer
    grade is honest only while the row states what it could not join."""
    unjoined = {row["id"]: row for row in rows("jobs")}["job:housekeeping-scrub"]
    assert "TargetClass" not in unjoined["facts"]
    assert "unknown" in unjoined["facts"]["TargetClassUnjoined"]
    assert unjoined["worst_opinion_level"] == "warn"
    message = unjoined["opinions"][0]["message"]
    assert "could not be joined" in message


def test_without_a_staleness_verdict_only_the_jobs_collection_declines(
        estate, monkeypatch):
    monkeypatch.setattr(mod, "STATUS", str(estate / "absent.json"))
    capability = asyncio.run(mod.Adapter().capability())
    assert capability["available"] is True
    assert capability["collections"] == ["targets", "destinations"]
    reason = capability["unavailable_collections"]["jobs"]
    # The manifest in hand says this host owes cadences, and the same
    # declaration that rendered it installs the checker — so a missing
    # verdict is a file nobody has written, never a host that owes
    # nothing. Claiming the latter is rule 7's absence dressed as
    # configuration, and it is the claim an operator would act on.
    assert "unobservable, not absent" in reason
    for owed in ("documents", "photos", "ledgers"):
        assert owed in reason
    # And what HAS written a receipt here is stated too, because it is the
    # other half of the discrimination and it is already on disk.
    assert "documents" in reason.rpartition("written a receipt here:")[2]


def test_evidence_shows_the_documents_the_row_was_folded_from(estate):
    adapter = mod.Adapter()
    evidence = asyncio.run(adapter.get_evidence("jobs", "job:documents"))
    payload = evidence["payload"]
    assert set(payload) == {mod.STATUS, mod.RECEIPTS}
    # Both receipts, because the pair IS the distinction the rows rest on.
    assert set(payload[mod.RECEIPTS]) == {"last", "last-success"}
    # Evidence must be able to show its object, so an id no document
    # carries is a refusal, never a page of somebody else's receipts.
    with pytest.raises(mod.env.UnknownObject):
        asyncio.run(adapter.get_evidence("jobs", "job:absent"))


def test_evidence_refuses_the_ids_the_collection_itself_refuses(
        estate, monkeypatch):
    """The membership test and the collection must be one predicate: an
    entry that is not an object is no object at all, and evidence
    vouching for an id get_object denies cannot show its object."""
    manifest = json.loads(json.dumps(MANIFEST))
    manifest["targets"]["malformed"] = "a string where an object belongs"
    (estate / "manifest.json").write_text(json.dumps(manifest))
    adapter = mod.Adapter()
    assert "target:malformed" not in {row["id"] for row in rows("targets", adapter)}
    with pytest.raises(mod.env.UnknownObject):
        asyncio.run(adapter.get_object("targets", "target:malformed"))
    with pytest.raises(mod.env.UnknownObject):
        asyncio.run(adapter.get_evidence("targets", "target:malformed"))
