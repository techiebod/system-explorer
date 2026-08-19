"""Adversaries stay red: every passing-wrong collector is a permanent fixture.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. fixtures/adversaries/ holds the adversarial
rounds' artefacts — collectors that at some point satisfied this repository's
judge while being wrong about the machine — and every one of them is driven
through the REAL judge here: replay.run_collector over the real corpus, then
the same four verdicts test_corpus_replay reaches (stream schema, check_stream
against the issued generations, the byte diff, the staged anchors).

The expectation table is declared, and deny-by-default in both directions: a
fixture file the table does not name fails the suite — an undocumented
adversary is an unaudited one — and a table row without its file is a fixture
that silently stopped running.

**A row is bound to a REASON, not to redness.** Non-zero problems is not a
verdict: an adversary that begins failing for an unrelated reason — a schema
tightening, a change to the request line, a fact renamed — would satisfy a
table that only counted problems, and the fixture would quietly stop testing
what it was committed to test. So every RED row names the CHANNEL its defect
must surface in and the literal EVIDENCE that must appear there: the rule it
breaks, or the anchored fact it falsifies. The verdict test asserts the
evidence, not the count.

The converse trap is vacuity, and it has a name in this repository:
fixtures/adversaries/a5_hardcoded_healthy.py fails every anchor of
corpus/storage/degraded with "no object named host-2f5789 in 'pools'", because
it predates the tokenised request line and publishes under the wrong
collection — a red that would survive deleting the staged variant entirely.
So a row whose evidence is an ANCHOR must also name CONTROL variants the same
subject passes: a subject that fails everything proves nothing about the one
fact it was staged against.

Some rows are GREEN, and each names the adjudication — one of DESIGN 19's
replay bounds, or DESIGN 20's third trap — that makes the pass honest rather
than an oversight; ADJUDICATED_GREEN below is the closed set, so an
unadjudicated green row fails the suite. The non-vacuity tests at the bottom
prove each DESIGN 19 green subject really put the wrong bytes on the wire and
passed by rule, not by accident of agreement; the DESIGN 20 green — the
eight-defect port — has its non-vacuity in test_differential.py instead,
where every one of its defect classes must visibly disagree with the
reference under mutation, or be refused.
"""

from __future__ import annotations

import functools
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from se_harness import corpus, replay

REPO = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "adversaries"

VARIANTS = {v.name: v for v in corpus.all_variants()}

A2 = "a2_defective_port.py"

# The judge's four verdicts, kept apart rather than concatenated, because
# WHICH of them caught a subject is the whole of what a row is bound to.
CHANNELS = ("schema", "rules", "diff", "anchors")


@dataclass(frozen=True)
class Expectation:
    """One audited adversary: which subject, which capture, which verdict —
    and, for a RED, exactly what the failure must say."""

    fixture: str
    defect: str | None  # SE_DEFECT axis for the multi-axis fixture, else None
    variant: str
    verdict: str  # "RED" or "GREEN"
    why: str
    # The judge channel the defect must surface in, and literal substrings
    # that must appear in it. Required for RED, forbidden for GREEN.
    channel: str | None = None
    evidence: tuple[str, ...] = ()
    # Variants this same subject passes, proving the red is the named defect
    # and not a subject that is wrong about everything.
    control: tuple[str, ...] = field(default_factory=tuple)


EXPECTED = (
    # ── RED, forever: round a2's envelope defects, one member at a time ──
    Expectation(A2, "generation_invented", "network/healthy", "RED",
                "mints generations instead of echoing the issued map",
                channel="rules",
                evidence=("must equal the issued generations",)),
    Expectation(A2, "generation_zero_always", "network/healthy", "RED",
                "claims generation 0 forever, disabling newest-wins",
                channel="rules",
                evidence=("must equal the issued generations",)),
    Expectation(A2, "generation_constant_100", "network/healthy", "RED",
                "zero_always's constant changed to 100 — the base the old "
                "fixed issuance handed every single-collection variant, so "
                "this one character passed every channel until the issuance "
                "was seeded per variant and 100 excluded from its range",
                channel="rules",
                evidence=("must equal the issued generations",)),
    Expectation(A2, "generation_borrowed_base", "network/healthy", "RED",
                "echoes storage/healthy's real seeded base (458) — a "
                "constant matching one variant must fail every other, so "
                "only parsing the request line passes everywhere",
                channel="rules",
                evidence=("must equal the issued generations",)),
    Expectation(A2, "batch_drift", "network/healthy", "RED",
                "end closes a batch begin never opened",
                channel="rules",
                evidence=("end must echo begin",)),
    Expectation(A2, "at_wallclock", "network/healthy", "RED",
                "`at` from the wall clock is epoch-scale, not boot-scale",
                channel="rules",
                evidence=("`at` must be a finite boot-scale reading",)),
    Expectation(A2, "at_far_future", "network/healthy", "RED",
                "`at` in milliseconds against a seconds-scale rule",
                channel="rules",
                evidence=("`at` must be a finite boot-scale reading",)),
    Expectation(A2, "boot_id_blank", "network/healthy", "RED",
                "a swallowed boot_id read leaves nothing to attribute `at` to",
                channel="rules",
                evidence=("boot_id must be UUID-shaped",)),
    Expectation(A2, "boot_id_constant", "network/healthy", "RED",
                "the nil UUID is the stub every runtime hands out for free",
                channel="rules",
                evidence=("boot_id must be UUID-shaped", "never the nil UUID")),
    Expectation(A2, "go_port", "network/healthy", "RED",
                "four ordinary porting mistakes at once — a first port's shape",
                channel="rules",
                evidence=("boot_id must be UUID-shaped",
                          "end must echo begin",
                          "must equal the issued generations",
                          "`at` must be a finite boot-scale reading")),
    # ── GREEN, adjudicated: the two honest bounds DESIGN 19 names ──
    Expectation(A2, "boot_id_constant_valid", "network/healthy", "GREEN",
                "a constant VALID boot id is indistinguishable from a real one "
                "by single-capture physics — the cross-boot deferral, held "
                "deliberately: nil is red above, this stays green"),
    # ── RED, forever: the whole-subject rounds ──
    #
    # a5's own artefact is bound to what ACTUALLY kills it. Its health claims
    # are struct defaults, but a healthy pool makes every one of them true, so
    # what fails here is the stubbed envelope: boot_id "replay", `at` 0.0,
    # generations minted as 1, and a pre-tokenised request line that publishes
    # under `pools:100`. The health defect itself is a5_health_never_read.py's
    # row below, against the variant staged to catch it.
    Expectation("a5_hardcoded_healthy.py", None, "storage/healthy", "RED",
                "the round's artefact, on the wire it was captured against: "
                "boot_id 'replay', `at` at the struct zero, minted "
                "generations, no self-cost — the envelope is stubbed, and "
                "against a healthy pool that is all there is to catch",
                channel="rules",
                evidence=("boot_id must be UUID-shaped",
                          "`at` must be a finite boot-scale reading",
                          "must equal the issued generations",
                          "a batch that emitted objects must report a "
                          "positive wall_ms")),
    Expectation("a6_zero_value_envelope.py", None, "network/healthy", "RED",
                "right about the ruleset, wrong about time: at 0, blank "
                "boot_id, end ids minted fresh, no self-cost",
                channel="rules",
                evidence=("boot_id must be UUID-shaped",
                          "`at` must be a finite boot-scale reading",
                          "end must echo begin")),
    # ── RED, forever: the three deferrals the 2026-08-16 lab variants closed ──
    #
    # Each of these was expected-GREEN while the corpus held only healthy
    # captures and jump-only rulesets: the subject was wrong about the machine
    # and no committed pair could say so. Each row now names the variant that
    # closes it and the anchored fact that does the killing, and each subject
    # passes the variants that cannot see its defect — which is what makes the
    # red attributable to the staging rather than to a botched port.
    Expectation("a5_health_never_read.py", None, "storage/degraded", "RED",
                "a5 S1–S5, on the current wire: State is the struct default "
                "ONLINE, StatusMessage is never read, and the two unhealthy "
                "lists are stubs — killed by storage/degraded's anchors, "
                "which were written from what the lab DID to the pool",
                channel="anchors",
                evidence=("State", "DEGRADED", "StatusMessage",
                          "UnhealthyVdevs", "VdevsWithErrors"),
                control=("storage/healthy",)),
    Expectation("a5_goto_blind.py", None, "network/goto", "RED",
                "a5 N1: JumpedFrom built from `jump` alone, so the chain "
                "reached only by `goto` is published Unreferenced — killed by "
                "network/goto's anchors on `inet gotolab dispatch`, a chain "
                "an operator deletes on the strength of that fact",
                channel="anchors",
                evidence=("inet gotolab dispatch", "JumpedFrom",
                          "Unreferenced"),
                control=("network/healthy", "network/canary",
                         "network/fedora-empty", "network/debian-absent",
                         "network/asymmetric", "network/named-map")),
    Expectation("a5_map_blind.py", None, "network/named-map", "RED",
                "a5 N2, the defect the round's own artefact carries and never "
                "enumerated: rule expressions are walked in full and top-level "
                "`map` objects are not read at all, so the chain reached only "
                "through `vmap @dispatch` is published Unreferenced — killed "
                "by network/named-map's anchors on `inet maplab landing`",
                channel="anchors",
                evidence=("inet maplab landing", "JumpedFrom",
                          "Unreferenced"),
                control=("network/healthy", "network/canary",
                         "network/fedora-empty", "network/debian-absent",
                         "network/goto", "network/asymmetric")),
    Expectation("a5_name_keyed_reachability.py", None, "network/asymmetric",
                "RED",
                "reachability keyed on the chain name alone, so one answer "
                "serves two chains that share a name across families — killed "
                "by network/asymmetric's anchors on `ip6 asym shared`, the "
                "dead v6 chain wearing the live v4 chain's JumpedFrom",
                channel="anchors",
                evidence=("ip6 asym shared", "Unreferenced", "JumpedFrom"),
                control=("network/healthy", "network/canary",
                         "network/fedora-empty", "network/debian-absent",
                         "network/goto", "network/named-map")),
    # ── GREEN, adjudicated ──
    Expectation("fabricated_cost.py", None, "storage/healthy", "GREEN",
                "cost is advisory by construction (DESIGN 19): the rules bound "
                "cpu_ms/wall_ms without authenticating them, and the collator's "
                "slice accounting is the authoritative cost of observation"),
    # ── GREEN, adjudicated: DESIGN 20's third trap, kept executable ──
    #
    # The eight-defect port: wrong about the machine in eight ways, and green
    # on EVERY committed pair — replay equivalence proves a collector right
    # about the machines the corpus holds and nothing else, so a port whose
    # blind spots fall outside the captured shapes passes by construction and
    # every added variant only moves the frontier. These two rows, one per
    # collector it serves, are the replay judge saying so honestly rather
    # than a regression: the fixture's RED lives in test_differential.py,
    # where each of its defect classes must visibly disagree with the
    # reference under mutation, or be refused. If either row goes red here,
    # the replay judge has grown a rule that can see one of the eight classes
    # — DESIGN 20's trap statement and test_differential.py's case table must
    # move in the same change, not this table alone.
    Expectation("a7_replay_green_port.py", None, "network/healthy", "GREEN",
                "family-enum and single-caller walks that no committed "
                "ruleset can expose: every capture stays inside {ip, ip6, "
                "inet} and no committed chain has two callers"),
    Expectation("a7_replay_green_port.py", None, "storage/healthy", "GREEN",
                "first-vdev redundancy, epoch-zero scan time, "
                "spare-as-unhealthy and nested nulls that no committed pool "
                "exhibits: the captures are single-layout, scan-finished, "
                "spare-less and fully reported"),
    # ── GREEN, adjudicated: DESIGN 20's third trap, the group-enum spelling ──
    #
    # The l2cache-blind port: it drops the whole l2cache vdev group, and every
    # committed pool is cache-less, so under replay there is nothing to drop and
    # the judge honestly passes it. Its RED lives in test_differential.py, where
    # the zpool-cache-vdev operator mints an l2cache group into the seed and the
    # closure guard proves that group is minted by an operator rather than left
    # an orphan of the declared ZFS_GROUP_VDEVS set. If this goes red here, the
    # replay judge has grown a rule that sees a group no committed pool holds —
    # DESIGN 20's trap statement and test_differential.py's case table move
    # together, not this row alone.
    Expectation("a8_l2cache_blind.py", None, "storage/healthy", "GREEN",
                "an l2cache group dropped whole, which no committed pool can "
                "expose: every capture is cache-less, so the blindness is "
                "invisible under replay and the differential guard owns its red"),
    # ── GREEN, adjudicated: the third trap, the vms spelling ──
    #
    # The address-blind port: it never implemented the address fact, and the
    # only captured domain is SHUT OFF — a stopped guest has no address because
    # it is off, so the reference omits the fact too and the two rows are
    # identical. The judge honestly passes it. Its RED lives in
    # test_differential.py, where the libvirt-running-guest operator brings the
    # guest up with a lease and the reference reads the address this port
    # drops. If this goes red here, the replay judge has grown a rule that sees
    # an address no committed capture holds — DESIGN 20's trap statement and
    # test_differential.py's case table move together, not this row alone.
    Expectation("a9_address_blind.py", None, "vms/healthy", "GREEN",
                "a domain row with no address fact, which no committed guest "
                "can expose: the captured domain is shut off, so both "
                "implementations omit the fact and the differential guard owns "
                "the red"),
    # ── GREEN, adjudicated: the third trap, the unread-column spelling ──
    #
    # The status-blind port publishes every row dpkg has a record of, including
    # the ones removed with their configuration left behind. Every row of the
    # only committed packages capture is `installed`, so there is nothing to
    # over-report and the judge honestly passes it. Its RED lives in
    # test_differential.py, where the dpkg-removed-config-row operator inserts
    # an `rc ifupdown` row the reference drops. If this goes red here, the
    # replay judge has grown a rule that sees a status no committed capture
    # holds — DESIGN 20's trap statement and the case table move together, not
    # this row alone.
    Expectation("a9_dpkg_status_blind.py", None, "packages/healthy", "GREEN",
                "the dpkg status column never read, which no committed capture "
                "can expose: all 963 rows are `installed`, so the filter is "
                "exercised by nothing under replay and the differential guard "
                "owns its red"),
    # ── GREEN, adjudicated: the third trap, the counted-twice spelling ──
    #
    # The thread-share-blind port reads `thread0.` where the resolver's `total.`
    # belongs, and the only captured resolver runs ONE thread — so the two are
    # the same number on every line of the payload and both implementations
    # emit the same row. The judge honestly passes it. Its RED lives in
    # test_differential.py, where the unbound-second-thread operator gives the
    # resolver a second thread and the totals stop being one thread's share. If
    # this goes red here, the replay judge has grown a rule that sees a thread
    # split no committed capture holds — DESIGN 20's trap statement and the
    # case table move together, not this row alone.
    Expectation("a9_thread_share_blind.py", None, "unbound/healthy", "GREEN",
                "one thread's counters published as the resolver's, which no "
                "committed capture can expose: the captured resolver runs a "
                "single thread, so thread0 and total are the same number and "
                "the differential guard owns the red"),
    # ── GREEN, adjudicated: the third trap, the narrowed-enum spelling ──
    #
    # The scope-state-blind port names a scope unit only for a RUNNING
    # container, where adapters/docker.py's _SCOPED_STATES has three members.
    # Every container in the only committed docker capture is running or
    # exited, and the two rules agree on both — running keeps its scope either
    # way, exited keeps none either way — so the judge honestly passes it. Its
    # RED lives in test_differential.py, where docker-restarting-container and
    # docker-paused-container mint the two remaining members and the reference
    # names the scope this port drops. If this goes red here, the replay judge
    # has grown a rule that sees a container state no committed capture holds —
    # DESIGN 20's trap statement and the case table move together, not this row
    # alone.
    # ── GREEN, adjudicated: the third trap, the counted-not-listed spelling ──
    #
    # The unlistable-remainder port applies the reservation filter before the
    # count instead of after it, so its ReservationCount is its row count by
    # construction and it never states a remainder. Every reservation in the only
    # committed kea capture pins an address, so the filter removes nothing, the
    # remainder is nil, and the correct answer omits UnlistedReservations too —
    # the judge honestly passes it. Its RED lives in test_differential.py, where
    # the kea-addressless-reservation operator puts a hostname-only reservation
    # into the seed's subnet and the two counts stop agreeing. If this goes red
    # here, the replay judge has grown a rule that sees a remainder no committed
    # capture holds — DESIGN 20's trap statement and the case table move
    # together, not this row alone.
    Expectation("a9_unlistable_remainder_blind.py", None, "kea/no-lease-hook",
                "GREEN",
                "the reservation filter applied before the count, which no "
                "committed capture can expose: every captured reservation pins "
                "an address, so nothing is filtered out and the remainder is "
                "absent from both answers, and the differential guard owns the red"),
    # ── GREEN, adjudicated: the third trap, the one-name-apart spelling ──
    #
    # The oom-blind port lifts `oom` where `oom_kill` belongs — how many times
    # a workload hit its memory limit, published as how many of its processes
    # the kernel killed. Every memory.events document in the only committed
    # resources capture reads 0 for both, because the guest was at rest, so
    # there is nothing to conflate and the judge honestly passes it. Its RED
    # lives in test_differential.py, where the cgroup-oom-kill operator gives
    # one workload three events and one kill. If this goes red here, the replay
    # judge has grown a rule that sees an OOM record no committed capture holds
    # — DESIGN 20's trap statement and the case table move together, not this
    # row alone.
    Expectation("a9_oom_kill_blind.py", None, "resources/healthy", "GREEN",
                "an OOM event published as an OOM kill, which no committed "
                "capture can expose: every memory.events reads 0 for both, so "
                "the two counters are the same number under replay and the "
                "differential guard owns the red"),
    Expectation("a9_scope_state_blind.py", None, "docker/healthy", "GREEN",
                "a scope unit named only for a running container, which no "
                "committed capture can expose: every captured container is "
                "running or exited and the narrow rule agrees with the "
                "reference on both, so the differential guard owns the red"),
    # ── GREEN, adjudicated: the third trap, the empty-member spelling ──
    #
    # The manager-version-blind port never lifts the sonarr and radarr releases
    # bazarr reports. The only committed instance is wired to NEITHER manager,
    # and the interface spells that as an empty string rather than as a missing
    # member — so the reference's truthiness gate drops both facts and the two
    # implementations emit the same row. The judge honestly passes it. Its RED
    # lives in test_differential.py, where the bazarr-wired-managers operator
    # wires the instance to both. If this goes red here, the replay judge has
    # grown a rule that sees a wiring no committed capture holds — DESIGN 20's
    # trap statement and the case table move together, not this row alone.
    Expectation("a9_manager_version_blind.py", None, "bazarr/healthy", "GREEN",
                "the manager releases never lifted, which no committed capture "
                "can expose: the captured instance is wired to neither sonarr "
                "nor radarr and the interface spells that as an empty string, "
                "so both implementations drop both facts and the differential "
                "guard owns the red"),
    # ── GREEN, adjudicated: the third trap, the fronts-nothing spelling ──
    #
    # The dynamic-provider-blind port never reads the members a bare Traefik
    # does not carry: a service's type, load balancer and serverStatus map, a
    # router's tls block and its error list, the overview's provider list. The
    # only committed capture is of a proxy with no dynamic providers — the
    # universal shape, present on every install — so not one of those members
    # exists in it and both implementations emit identical rows. The judge
    # honestly passes it. Its RED lives in test_differential.py, where the
    # traefik-dynamic-provider operator deploys one TLS'd application on two
    # backends, one of them down, plus one route Traefik refused. If this goes
    # red here, the replay judge has grown a rule that sees a dynamic provider
    # no committed capture holds — DESIGN 20's trap statement and the case table
    # move together, not this row alone.
    Expectation("a9_traefik_dynamic_blind.py", None, "traefik/healthy", "GREEN",
                "the members only a dynamic provider brings, never read, which "
                "no committed capture can expose: the captured proxy fronts "
                "nothing but its own internal routes, so there is no backend "
                "health, no TLS block and no rejected route to miss and the "
                "differential guard owns the red"),
    # ── GREEN, adjudicated: the third trap, the idle-fleet spelling ──
    #
    # The reason-blind port publishes a download's verdict without the app's own
    # explanation of it. The captured fleet has never downloaded anything — its
    # queue holds no records and its trail no events — so the two collections
    # that carry the explanation are empty and the judge honestly passes it. Its
    # RED lives in test_differential.py, where the servarr-grab-in-flight
    # operator puts one acquisition through the fleet and the messages appear.
    # If this goes red here, the replay judge has grown a rule that sees a queue
    # record no committed capture holds — DESIGN 20's trap statement and the
    # case table move together, not this row alone.
    Expectation("a9_queue_reason_blind.py", None, "servarr/healthy", "GREEN",
                "the app's own reason for a stuck download never read, which no "
                "committed capture can expose: the captured fleet is idle, so "
                "its queue holds no records at all and there is nothing to "
                "explain — the differential guard owns the red"),
    # ── GREEN, adjudicated: the third trap, the unfired-arm spelling ──
    #
    # The error-text-blind port publishes a transfer's error CODE and never the
    # client's own words. Every torrent in the only committed downloaders
    # capture reports error 0 beside an empty errorString — a staged lab torrent
    # announces to a host that does not resolve, so nothing ever refuses it —
    # and the reference's own guard fires on neither, so both implementations
    # omit the fact and the judge honestly passes it. Its RED lives in
    # test_differential.py, where the transmission-errored-transfer operator
    # gives the first torrent a tracker that answers 404. If this goes red here,
    # the replay judge has grown a rule that sees an error no committed capture
    # holds — DESIGN 20's trap statement and the case table move together, not
    # this row alone.
    Expectation("a9_transfer_error_blind.py", None, "downloaders/healthy",
                "GREEN",
                "the client's own error line never published, which no "
                "committed capture can expose: every captured transfer reports "
                "error 0 with an empty errorString, so the arm that publishes "
                "the line is taken by neither implementation and the "
                "differential guard owns the red"),
)

# The closed set of adjudicated greens, and the DESIGN clause each rests
# on. A green row absent from here is an undocumented survivor, which is the
# thing this table exists to prevent — so this is asserted, not commented.
ADJUDICATED_GREEN = {
    ("fabricated_cost.py", None): "advisory self-cost",
    (A2, "boot_id_constant_valid"): "single-capture physics, cross-boot deferral",
    ("a7_replay_green_port.py", None): "the third trap: replay cannot decide "
    "the uncovered space (DESIGN 20); the differential guard owns this red",
    ("a8_l2cache_blind.py", None): "the third trap: replay cannot see the "
    "l2cache group no committed pool holds (DESIGN 20); the differential "
    "guard owns this red, under zpool-cache-vdev",
    ("a9_address_blind.py", None): "the third trap: replay cannot see an "
    "address no committed guest holds, because the only captured domain is "
    "shut off (DESIGN 20); the differential guard owns this red, under "
    "libvirt-running-guest",
    ("a9_dpkg_status_blind.py", None): "the third trap: replay cannot see a "
    "removed-but-configured row no committed capture holds, because every "
    "captured row is installed (DESIGN 20); the differential guard owns this "
    "red, under dpkg-removed-config-row",
    ("a9_thread_share_blind.py", None): "the third trap: replay cannot tell a "
    "thread's counters from the resolver's, because the only captured resolver "
    "runs one thread and the two are the same number (DESIGN 20); the "
    "differential guard owns this red, under unbound-second-thread",
    ("a9_queue_reason_blind.py", None): "the third trap: replay cannot see a "
    "stuck download's explanation, because the captured fleet is idle and its "
    "queue holds no records at all (DESIGN 20); the differential guard owns "
    "this red, under servarr-grab-in-flight",
    ("a9_unlistable_remainder_blind.py", None): "the third trap: replay cannot "
    "see a reservation that pins a name and no address, because every captured "
    "one pins an address and a port that filters before it counts reproduces "
    "the pair exactly (DESIGN 20); the differential guard owns this red, under "
    "kea-addressless-reservation",
    ("a9_oom_kill_blind.py", None): "the third trap: replay cannot tell an OOM "
    "event from an OOM kill, because the only captured machine was at rest and "
    "both counters read zero on every cgroup (DESIGN 20); the differential "
    "guard owns this red, under cgroup-oom-kill",
    ("a9_scope_state_blind.py", None): "the third trap: replay cannot see a "
    "restarting or paused container, because every captured one is running or "
    "exited and a running-only scope rule agrees on both (DESIGN 20); the "
    "differential guard owns this red, under docker-restarting-container and "
    "docker-paused-container",
    ("a9_manager_version_blind.py", None): "the third trap: replay cannot see "
    "a bazarr wired to a manager, because the only captured instance is wired "
    "to neither and the interface spells that as an empty string both "
    "implementations drop (DESIGN 20); the differential guard owns this red, "
    "under bazarr-wired-managers",
    ("a9_traefik_dynamic_blind.py", None): "the third trap: replay cannot see "
    "a backend health map, a TLS block, a provider list or a rejected route, "
    "because the only captured proxy fronts nothing but its own internal "
    "routes and carries none of those members (DESIGN 20); the differential "
    "guard owns this red, under traefik-dynamic-provider",
    ("a9_transfer_error_blind.py", None): "the third trap: replay cannot see a "
    "transfer's error line, because every captured torrent reports error 0 "
    "beside an empty errorString and the reference's own guard fires on "
    "neither (DESIGN 20); the differential guard owns this red, under "
    "transmission-errored-transfer",
}


def _ids(entry: Expectation) -> str:
    return f"{entry.fixture}:{entry.defect}" if entry.defect else entry.fixture


@functools.lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    registry = Registry()
    for path in sorted((REPO / "contract").glob("*.json")):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return Draft202012Validator(
        json.loads((REPO / "contract" / "se.stream.1.json").read_text()),
        registry=registry,
    )


@dataclass(frozen=True)
class Judgement:
    """What the judge said, kept per channel."""

    emitted: list[dict]
    by_channel: dict[str, list[str]]

    @property
    def problems(self) -> list[str]:
        return [p for channel in CHANNELS for p in self.by_channel[channel]]


def _judge(binary: list[str], variant: corpus.Variant) -> Judgement:
    """The real judge, whole: everything test_corpus_replay asserts, kept in
    its four channels. RED means the problem list is non-empty; the fixture
    itself must still RUN and emit — an adversary that crashes is a rotted
    fixture, not a caught one, so exit status and emptiness are hard failures
    here."""
    issued = replay.issue_generations(variant.collections(), seed=variant.name)
    proc = replay.run_collector(binary, variant, issued=issued)
    assert proc.returncode == 0, (
        f"{binary[-1]}: exited {proc.returncode} — the adversaries all wear "
        f"the collector's face and exit zero; a crash is fixture rot, not a "
        f"verdict\n{proc.stderr[:2000]}"
    )
    emitted = replay.parse_stream(proc.stdout)
    assert emitted, f"{binary[-1]}: emitted nothing — fixture rot, not a verdict"
    return Judgement(
        emitted=emitted,
        by_channel={
            "schema": [
                f"schema: {record.get('record')}: {error.json_path}: {error.message}"
                for record in emitted
                for error in sorted(_validator().iter_errors(record), key=str)
            ],
            "rules": replay.check_stream(emitted, issued),
            "diff": replay.diff(variant.expected, emitted),
            "anchors": corpus.validate_anchors(variant, emitted),
        },
    )


def _fixture_binary(name: str) -> list[str]:
    return [sys.executable, str(FIXTURES / name)]


def _set_defect(monkeypatch, entry: Expectation) -> None:
    if entry.defect is None:
        monkeypatch.delenv("SE_DEFECT", raising=False)
    else:
        monkeypatch.setenv("SE_DEFECT", entry.defect)
    # The eight-defect port's request-parse gate is differential-guard
    # apparatus, never part of a replay verdict: leaked in from the shell it
    # would refuse every green row's run and misattribute the red ones.
    monkeypatch.delenv("SE_PORT_NO_REQUEST_PARSE", raising=False)


# ── deny-by-default: the table and the directory are one set ─────────────


def test_every_fixture_file_is_declared() -> None:
    """A file in fixtures/adversaries/ absent from the expectation table fails
    the suite — an undocumented adversary is an unaudited one. Both
    directions: a declared row whose file is gone is a fixture that silently
    stopped running, which is the same defect seen from the other end."""
    present = {p.name for p in FIXTURES.iterdir() if p.name != "__pycache__"}
    declared = {e.fixture for e in EXPECTED}
    assert present == declared, (
        f"fixtures/adversaries/ and the expectation table disagree — "
        f"undeclared: {sorted(present - declared)}, "
        f"missing: {sorted(declared - present)}. Every adversary is audited "
        "or it does not ship."
    )


def test_the_multi_axis_fixture_declares_exactly_the_audited_axes() -> None:
    """Same rule one level down: the a2 fixture's own defect switch and this
    table must agree axis-for-axis, or an axis one side knows alone is an
    unaudited adversary wearing a shared filename."""
    listing = subprocess.run(
        [*_fixture_binary(A2), "--defects"], capture_output=True, text=True
    )
    assert listing.returncode == 0, listing.stderr
    in_fixture = set(listing.stdout.split())
    in_table = {e.defect for e in EXPECTED if e.fixture == A2}
    assert in_fixture == in_table, (
        f"a2 axes out of audit — fixture-only: {sorted(in_fixture - in_table)}, "
        f"table-only: {sorted(in_table - in_fixture)}"
    )


# ── the table's own shape: a row must say why, and a green must be adjudicated ──


@pytest.mark.parametrize("entry", EXPECTED, ids=_ids)
def test_every_row_is_bound_to_a_reason(entry: Expectation) -> None:
    """A row that only expects redness pins nothing.

    RED carries a channel and literal evidence, so a fixture that starts
    failing for an unrelated reason fails this suite instead of quietly
    passing it. GREEN carries neither: evidence on a green row would be a
    claim nothing checks.
    """
    assert entry.variant in VARIANTS, (
        f"{_ids(entry)} names unknown variant {entry.variant!r}"
    )
    for name in entry.control:
        assert name in VARIANTS, (
            f"{_ids(entry)} names unknown control variant {name!r}"
        )
    assert entry.variant not in entry.control, (
        f"{_ids(entry)} lists its own subject variant as a control — the row "
        "would demand the same run be both red and green"
    )
    if entry.verdict == "RED":
        assert entry.channel in CHANNELS, (
            f"{_ids(entry)} must name the judge channel its defect surfaces "
            f"in, one of {list(CHANNELS)}"
        )
        assert entry.evidence, (
            f"{_ids(entry)} is RED with no evidence — 'it failed' is not a "
            "reason, and a row that does not say what the failure must state "
            "is satisfied by any unrelated regression"
        )
        # The a5_hardcoded_healthy lesson, executed: that subject fails every
        # anchor of every variant with "no object named … in 'pools'", because
        # it publishes under the wrong collection. An anchor-bound red from a
        # subject that is wrong about everything says nothing about the fact
        # the variant was staged for, so it must be shown right elsewhere.
        if entry.channel == "anchors":
            assert entry.control, (
                f"{_ids(entry)} is bound to an anchor, so it must name control "
                "variants this subject PASSES — an anchor failure from a "
                "subject that fails everything would survive deleting the "
                "staged variant, which is vacuity rather than a catch"
            )
    else:
        assert entry.channel is None and not entry.evidence, (
            f"{_ids(entry)} is GREEN and carries evidence — a green row states "
            "an adjudication, and evidence there would be a claim no assertion "
            "reaches"
        )


def test_the_green_residue_is_exactly_the_adjudicated_set() -> None:
    """The complete list of adversaries this repository lets pass.

    Two are DESIGN 19 bounds on what one replayed capture can authenticate:
    self-reported cost is advisory by construction, and a constant VALID boot
    id is indistinguishable from a real one without a second boot. The third
    is DESIGN 20's bound on what replay itself can decide: the eight-defect
    port is green on every committed pair by construction, and the
    differential guard (test_differential.py) is where its wrongness is
    caught, class by class. Everything else in fixtures/adversaries/ is red
    forever. A new green row — a new deferral, or an old one quietly
    re-opened — fails here, because an undocumented survivor is precisely
    what this table exists to prevent.
    """
    green = {(e.fixture, e.defect) for e in EXPECTED if e.verdict == "GREEN"}
    assert green == set(ADJUDICATED_GREEN), (
        f"the adjudicated-green set moved — unadjudicated: "
        f"{sorted(green - set(ADJUDICATED_GREEN))}, adjudicated but no longer "
        f"in the table: {sorted(set(ADJUDICATED_GREEN) - green)}. A green "
        "adversary is a statement in DESIGN 19; add it there in the same "
        "change or make it red."
    )


# ── the judge's teeth, positive control ──────────────────────────────────


@pytest.mark.parametrize(
    "name",
    sorted({e.variant for e in EXPECTED} | {c for e in EXPECTED for c in e.control}),
)
def test_the_judge_passes_the_reference(name: str) -> None:
    """Positive control: the same judge, the same variant, the reference
    collector — zero problems. Without this, every RED below could be a
    broken judge or a stale corpus rather than a caught adversary, and every
    control green could be a variant nothing can fail."""
    problems = _judge(replay.reference_binary(), VARIANTS[name]).problems
    assert not problems, f"{name}: the reference fails its own corpus:\n" + "\n".join(
        f"  - {p}" for p in problems[:10]
    )


# ── the verdicts ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("entry", EXPECTED, ids=_ids)
def test_the_adversary_meets_its_declared_verdict(entry, monkeypatch) -> None:
    _set_defect(monkeypatch, entry)
    judgement = _judge(_fixture_binary(entry.fixture), VARIANTS[entry.variant])
    if entry.verdict != "RED":
        assert not judgement.problems, (
            f"{_ids(entry)} is expected GREEN — {entry.why}. It failed instead:\n"
            + "\n".join(f"  - {p}" for p in judgement.problems[:10])
            + "\nIf the fabricated-cost row is the one failing, cost has become "
            "authenticated and DESIGN 19's advisory-cost bound must be updated "
            "in the same change; if the valid-constant boot id row is failing, "
            "the cross-boot deferral has been revoked and DESIGN 19's "
            "two-regimes law must say so; if an eight-defect-port row is "
            "failing, the replay judge has grown a rule that sees one of "
            "DESIGN 20's mutation-owned classes, and the trap statement plus "
            "test_differential.py's case table must move in the same change."
        )
        return

    assert judgement.problems, (
        f"{_ids(entry)} PASSED the judge. This subject is wrong about the "
        f"machine ({entry.why}); a green run means a guard has regressed "
        "and the round's defect is live again."
    )
    # Red is not the assertion. The declared channel must be the one that
    # caught it, and it must say the declared thing — otherwise a schema
    # tightening or a renamed member would keep this row green while the
    # defect it was committed to pin went unwatched.
    caught = "\n".join(judgement.by_channel[entry.channel])
    missing = [text for text in entry.evidence if text not in caught]
    assert not missing, (
        f"{_ids(entry)} is red, but not for its declared reason. The "
        f"{entry.channel} channel does not mention {missing!r}.\n"
        f"Declared reason: {entry.why}\n"
        f"What the {entry.channel} channel actually said:\n"
        + ("\n".join(f"  - {p}" for p in judgement.by_channel[entry.channel][:10])
           or "  (nothing)")
        + "\nA row bound only to redness would have passed this run. Either "
        "the subject stopped exercising its defect, or the guard that used to "
        "catch it moved — find out which before editing this table."
    )


@pytest.mark.parametrize(
    "entry", [e for e in EXPECTED if e.control], ids=_ids
)
def test_the_adversary_is_green_where_its_defect_cannot_be_seen(
    entry, monkeypatch
) -> None:
    """The other half of an attributable red.

    These subjects are correct ports carrying one defect each, so every
    variant that does not stage that defect must pass — and each of them
    DID pass, for as long as the corpus held only those variants, which is
    exactly why the defect was a deferral. A subject that goes red here is
    wrong about more than its declared defect, and its red on the staged
    variant stops being evidence about the staging.
    """
    _set_defect(monkeypatch, entry)
    for name in entry.control:
        problems = _judge(_fixture_binary(entry.fixture), VARIANTS[name]).problems
        assert not problems, (
            f"{_ids(entry)} failed its control variant {name}. It is meant to "
            f"be wrong in exactly one way ({entry.why}) and right about "
            f"everything else; a red here means its red on {entry.variant} is "
            "no longer attributable to the staged defect:\n"
            + "\n".join(f"  - {p}" for p in problems[:10])
        )


# ── the green rows are not vacuous ───────────────────────────────────────


def test_fabricated_cost_really_fabricates(monkeypatch) -> None:
    """The GREEN must be the judge tolerating a wrong ruled member, not the
    fixture accidentally agreeing with the pair. The constants must appear on
    the wire and differ from the committed pair's cost readings."""
    monkeypatch.delenv("SE_DEFECT", raising=False)
    variant = VARIANTS["storage/healthy"]
    judgement = _judge(_fixture_binary("fabricated_cost.py"), variant)
    assert not judgement.problems
    end = next(r for r in judgement.emitted if r["record"] == "end")
    committed_end = next(r for r in variant.expected if r["record"] == "end")
    assert (end["cpu_ms"], end["wall_ms"]) == (0.7, 1.3), (
        f"the fixture no longer emits its placeholder cost: {end}"
    )
    assert (end["cpu_ms"], end["wall_ms"]) != (
        committed_end.get("cpu_ms"),
        committed_end.get("wall_ms"),
    ), (
        "the fabricated cost equals the committed pair's — the green would "
        "prove agreement, not adjudication"
    )


def test_the_valid_constant_boot_id_really_differs(monkeypatch) -> None:
    """Both directions of the deferral, on the wire: the green subject carries
    a boot id the committed pair does not, and the nil spelling of the very
    same defect is red. One capture, one axis, two verdicts — the rule
    discriminates on shape, not on agreement."""
    variant = VARIANTS["network/healthy"]
    monkeypatch.setenv("SE_DEFECT", "boot_id_constant_valid")
    judgement = _judge(_fixture_binary(A2), variant)
    assert not judgement.problems
    begin = next(r for r in judgement.emitted if r["record"] == "begin")
    committed_begin = next(r for r in variant.expected if r["record"] == "begin")
    assert begin["boot_id"] != committed_begin["boot_id"], (
        "the valid-constant axis emitted the committed boot id — the green "
        "would prove agreement, not adjudication"
    )
    monkeypatch.setenv("SE_DEFECT", "boot_id_constant")
    judgement = _judge(_fixture_binary(A2), variant)
    assert any("boot_id" in p for p in judgement.problems), (
        "the nil spelling of the same constant-boot-id defect went green — "
        "the shape rule has stopped discriminating"
    )
