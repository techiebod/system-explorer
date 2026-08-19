"""The differential guard: disagreement under mutation is the verdict.

DESIGN 20's third trap, executable. Replay equivalence proves a collector
right about the machines the corpus holds and nothing else — the committed
proof is fixtures/adversaries/a7_replay_green_port.py, a port wrong about the
machine in eight ways that passes every committed pair (its adjudicated-GREEN
rows in test_adversaries_stay_red.py are the replay judge saying so honestly).
So the corpus is also a seed set: se_harness.differential applies structural
transformations a real machine could exhibit, runs the reference and a
challenger over the same mutated payloads, and the verdict is AGREE, DISAGREE
or REFUSED — with disagreement, not redness, as the finding.

Three disciplines, each the executable form of a failure this repository has
already shipped once:

- **A case is bound to a REASON, never to redness.** Every row names the
  defect class, the operator that exposes it, the channel the disagreement
  must surface in, and literal evidence that must appear there — the same
  binding test_adversaries_stay_red.py puts on its rows, because a red that
  any unrelated regression satisfies pins nothing.
- **The control is asserted per operator.** The reference must agree with
  ITSELF on every (seed, operator) pair: a mutated payload the reference
  rejects, or answers nondeterministically, is a mutator bug and must fail
  as one — a payload the reference cannot handle meaningfully tests nothing,
  which is the whole difference between a mutator and a fuzzer.
- **Coverage is deny-by-default, in both directions.** Every operator must
  produce at least one disagreement against a committed wrong fixture, or it
  is dead weight — and every fixture in fixtures/adversaries/ must be
  exercised by a case OR carry a named exemption, or it is an uncovered
  judge-fooler. The table tests say so by name each way. The fixture
  direction is the one DESIGN 20 turns on — "every collector that has ever
  fooled a judge is kept as a fixture that must visibly disagree under
  mutation" — so a new adversary cannot land named by nothing and redden
  nothing; the set is derived from the directory, never enumerated by hand.

Two of the port's eight defects are NOT payload-exposable, and each deferral
is executed rather than assumed: the unparsed request line is refused by the
driver's per-run issuance (any operator's run alike — the exposing instrument
is the varied generation map, not the payload), and the constant `at` stays
AGREE with the wrong bytes proven on the wire, because replay pins the clock
and time's truth belongs to the live comparator (DESIGN 19's ownership law —
a rule placed at the wrong tier is a guard that cannot fail wearing a
stricter one's clothes).

The whole module is budgeted well under 90 seconds — the runs measured ~6s
total — and marked `differential` so CI can schedule it apart from the fast
suite (`-m "not differential"` / `-m differential`).
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from se_harness import corpus, differential, replay

pytestmark = pytest.mark.differential

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "adversaries"
VARIANTS = {v.name: v for v in corpus.all_variants()}
OPERATORS = {op.name: op for op in differential.OPERATORS}

PORT = "a7_replay_green_port.py"

# The one defect class whose exposing instrument is the driver rather than
# any payload: the issuance is seeded per (variant, operator), so a
# challenger that bakes in a generation instead of parsing the request line
# is refused on every operator alike. Named here so the class-consistency
# test can exempt exactly this row and nothing else.
DRIVER_EXPOSED = "unparsed-request"


@dataclass(frozen=True)
class Case:
    """One defect class: the operator that exposes it, the fixture that
    carries it, and what the disagreement must SAY."""

    defect: str
    operator: str
    challenger: str
    verdict: str  # DISAGREE or REFUSED — never AGREE; a green case is no case
    channel: str  # "differences" or "challenger_problems"
    evidence: tuple[str, ...]
    env: tuple[tuple[str, str], ...] = ()


CASES = (
    # ── the eight-defect port, class by class ────────────────────────────
    Case("family-enum", "nft-netdev-ingress", PORT, differential.DISAGREE,
         "differences",
         # The whole chain goes missing, by name: the port dropped the
         # family, so the machine's outermost filter is simply not reported.
         ("missing:", differential.NETDEV_CHAIN)),
    Case("family-enum", "nft-bridge-family", PORT, differential.DISAGREE,
         "differences",
         # Both shapes at once: the hooked chain and the Unreferenced one.
         ("missing:", differential.BRIDGE_BASE_CHAIN,
          differential.BRIDGE_ISLAND_CHAIN)),
    Case("family-enum", "nft-arp-family", PORT, differential.DISAGREE,
         "differences",
         # The arp family the same enum drops last: the hooked arp chain goes
         # missing by name. arp had no operator until the closure guard proved
         # it an orphan of the declared family set — the family this row now
         # binds is the one that let the family-enum label lie.
         ("missing:", differential.ARP_CHAIN)),
    Case("single-caller", "nft-second-caller", PORT, differential.DISAGREE,
         "differences",
         # The reference lists both callers; the single-caller map kept one.
         # Bound to the full pair so a port that dropped the OTHER caller
         # would not satisfy this row by accident.
         ("input-allow", "JumpedFrom", "['input', 'rpfilter']")),
    Case("first-vdev-redundancy", "zpool-mixed-stripe", PORT,
         differential.DISAGREE, "differences",
         # The mixed layout named in full, tolerance graded by the weakest
         # vdev — versus the first-vdev port's confident "raidz1".
         ("Redundancy", "raidz1 + stripe", "DeviceFailuresTolerated")),
    Case("epoch-zero-scan", "zpool-scan-running", PORT, differential.DISAGREE,
         "differences",
         # The discriminating bytes: the epoch rendered as a date, and the
         # derived age that only exists if 0 was read as an end time.
         ("1970-01-01", "ScanAgeDays")),
    Case("scan-function-blind", "zpool-resilver-overwrote-scrub", PORT,
         differential.DISAGREE, "differences",
         # The third channel, missing: the reference says the scrub time
         # exists and cannot be read, and the port says nothing at all — so
         # the fact is bound here beside the commit count that betrays the
         # dropped record, since a port that emitted the record and miscounted
         # would not satisfy this row.
         ("LastScrubEndTime", "unobservable")),
    Case("spare-as-unhealthy", "zpool-spares-and-logs", PORT,
         differential.DISAGREE, "differences",
         # The AVAIL spare, by WWN, inside the unhealthy list it does not
         # belong in.
         ("UnhealthyVdevs", differential.SPARE_DISK)),
    Case("group-enum", "zpool-cache-vdev", "a8_l2cache_blind.py",
         differential.DISAGREE, "differences",
         # The dropped Group, by name and by device: the reference labels the
         # cache disk's row Group=l2cache, and the groups-by-enum port emits no
         # row for it. l2cache was the storage twin of arp — minted by nothing,
         # named nowhere — and this binds the group whose absence let the guard
         # claim the whole ZFS_GROUP_VDEVS set was closed. a7 handles all three
         # groups, so this needs its own l2cache-blind challenger.
         ("l2cache", differential.CACHE_DISK)),
    Case("nested-null", "zpool-nulled-member", PORT, differential.REFUSED,
         "challenger_problems",
         # Not a diff: the stream itself is unlawful. The recursive null
         # rule names the path one level down, where the top-level sweep
         # this port wrote cannot see.
         ("/State is null", "at any depth")),
    Case(DRIVER_EXPOSED, "nft-jump-to-goto", PORT, differential.REFUSED,
         "challenger_problems",
         # Deliberately an operator the port otherwise AGREEs on, so the
         # refusal is attributable to the request line alone. The evidence
         # is the issuance echo rule — the varied generation map is the
         # exposing instrument, and it rides every operator's run.
         ("must equal the issued generations",),
         env=(("SE_PORT_NO_REQUEST_PARSE", "1"),)),
    # ── the earlier rounds' single-defect subjects, under mutation ───────
    # These two operators cannot fail the eight-defect port — it walks goto
    # and reads map objects — so their non-vacuity rests on the round-a5
    # fixtures, which is DESIGN 20's closing move: every collector that ever
    # fooled a judge stays as a fixture that must visibly disagree under
    # mutation, so each catch closes a CLASS instead of an instance.
    Case("goto-blind", "nft-jump-to-goto", "a5_goto_blind.py",
         differential.DISAGREE, "differences",
         # The converted target, published Unreferenced by the jump-only
         # walk while the reference names its caller.
         ("rpfilter-allow", "JumpedFrom", "Unreferenced")),
    Case("map-blind", "nft-named-map", "a5_map_blind.py",
         differential.DISAGREE, "differences",
         # The minted landing chain: reached only through the map object,
         # so the expression-only walk publishes it Unreferenced.
         (differential.LANDING_CHAIN, "JumpedFrom", "Unreferenced")),
    Case("health-stub", "zpool-faulted-leaf", "a5_health_never_read.py",
         differential.DISAGREE, "differences",
         # The degraded pool a5's struct defaults report healthy: DEGRADED
         # read as ONLINE, the catalogue prose never read, the faulted members
         # dropped from the unhealthy list. On the committed corpus this red
         # lives on storage/degraded's anchors; here the fault is a MUTATION,
         # so the whole S1–S5 class is regression on every healthy seed.
         ("DEGRADED", "StatusMessage", "UnhealthyVdevs")),
    Case("address-blind", "libvirt-running-guest", "a9_address_blind.py",
         differential.DISAGREE, "differences",
         # The fact and the address it carries, by name. Every committed
         # capture is of a stopped guest, whose address is inapplicable and
         # omitted by both implementations — so the blindness is invisible
         # until the operator brings the guest up, and this is the row that
         # binds it.
         ("IPAddresses", differential.GUEST_ADDRESS)),
    Case("status-blind", "dpkg-removed-config-row", "a9_dpkg_status_blind.py",
         differential.DISAGREE, "differences",
         # The removed package published as installed, by name, and the port's
         # own count betraying it. Both, because the object alone would also be
         # satisfied by a port that emitted the row AND miscounted, and the
         # count alone by a port that lost some other row entirely. Every
         # committed dpkg row is `installed`, so the filter is exercised by no
         # capture and this is the operator that mints the one shape it exists
         # for.
         ("unexpected:", differential.REMOVED_PACKAGE, "objects: expected")),
    Case("thread-share-blind", "unbound-second-thread",
         "a9_thread_share_blind.py", differential.DISAGREE, "differences",
         # Both halves of the one row, by value: the resolver's query total,
         # which only an implementation reading `total.` can produce, and the
         # first thread's share, which is what a thread-blind one publishes in
         # its place. Bound to the pair because the facts dict is compared
         # whole — a single spelling would also be satisfied by a port that had
         # lost some other counter entirely. Every committed capture is of a
         # ONE-thread resolver, where the two numbers are the same on every
         # line, so this distinction is exercised by no replay and this
         # operator is what mints the only shape that draws it.
         (differential.UNBOUND_QUERY_TOTAL, differential.UNBOUND_THREAD_SHARE)),
    Case("oom-counter-blind", "cgroup-oom-kill", "a9_oom_kill_blind.py",
         differential.DISAGREE, "differences",
         # Both spellings of the one row, by value: the processes the kernel
         # actually killed, and the times the limit was merely hit, which is
         # what a port that read `oom` publishes in their place. Bound to the
         # pair because the facts dict is compared whole — a single spelling
         # would also be satisfied by a port that had lost some other counter
         # entirely — and to the workload's name, because a port that minted
         # the record on a different row would otherwise satisfy the values.
         # Every committed capture is of a machine at rest, where oom and
         # oom_kill are 0 on all 73 documents, so this distinction is exercised
         # by no replay and this operator is what mints the only shape that
         # draws it.
         (differential.OOM_KILLED_UNIT, differential.OOM_KILLS_TRUE,
          differential.OOM_KILLS_BLIND)),
    Case("scoped-state-enum", "docker-restarting-container",
         "a9_scope_state_blind.py", differential.DISAGREE, "differences",
         # The fact and the unit it names, by value. Every committed container
         # is running or exited, and a running-only scope rule agrees with the
         # reference on both — so the blindness is invisible until a container
         # is crash-looping, which is the moment somebody is actually following
         # the edge from a units/units row back to a name. Bound to the scope
         # NAME as well as the fact, because the name is derived from the full
         # id and a port that published the twelve-character form would satisfy
         # a bare "ScopeUnit" and still resolve to no unit at all.
         ("ScopeUnit", differential.RESTARTING_SCOPE)),
    Case("stuck-reason-blind", "servarr-grab-in-flight",
         "a9_queue_reason_blind.py", differential.DISAGREE, "differences",
         # Both sentences the app wrote and the fact that carries them. The
         # captured fleet has never downloaded anything — its queue holds no
         # records and its trail no events — so a port that publishes a
         # download's verdict without the app's own explanation of it is
         # invisible to every committed pair, and this operator is what puts
         # one acquisition through the fleet. Bound to the pair because the
         # facts dict is compared whole: a single spelling would also be
         # satisfied by a port that had lost some other member entirely.
         ("StatusMessages", differential.SERVARR_STUCK_MESSAGE,
          differential.SERVARR_ERROR_MESSAGE)),
    Case("unlistable-remainder", "kea-addressless-reservation",
         "a9_unlistable_remainder_blind.py", differential.DISAGREE, "differences",
         # Both halves of the reconciliation, by value: the count over every
         # entry the configuration holds, and the remainder that says how many
         # of them no row can carry. Bound to the pair because the facts dict is
         # compared whole — ReservationCount alone would also be satisfied by a
         # port that had lost some other subnet fact, and the remainder alone by
         # one that published it and miscounted. Every reservation in the only
         # committed kea capture states an address, so the remainder is nil there
         # and a port that filters before it counts reproduces the pair exactly;
         # this operator mints the one shape that draws the distinction.
         (differential.KEA_RESERVATION_COUNT, differential.KEA_UNLISTED_REMAINDER)),
    Case("scoped-state-enum", "docker-paused-container",
         "a9_scope_state_blind.py", differential.DISAGREE, "differences",
         # The third member of the declared set, staged separately for the same
         # reason the nftables families are: an enum that learned `restarting`
         # the hard way still drops `paused`, and a closed set is closed member
         # by member or not at all.
         ("ScopeUnit", differential.PAUSED_SCOPE)),
    Case("manager-version-blind", "bazarr-wired-managers",
         "a9_manager_version_blind.py", differential.DISAGREE, "differences",
         # Both facts, by name AND value. bazarr spells "wired to nothing" as
         # an empty string, so the captured instance carries both members
         # present and empty, the reference's truthiness gate drops both, and a
         # port blind to either emits exactly the committed row. Bound to the
         # pair because the facts dict is compared whole — one spelling alone
         # would also be satisfied by a port that had lost some other fact
         # entirely — and to the values because these facts are pass-through:
         # a port that published the member's presence rather than its content
         # would satisfy a name-only row.
         (differential.BAZARR_SONARR_VERSION, differential.BAZARR_RADARR_VERSION)),
    Case("dynamic-provider-blind", "traefik-dynamic-provider",
         "a9_traefik_dynamic_blind.py", differential.DISAGREE, "differences",
         # Both readings this tier exists to give, by value. The health fold —
         # a service whose backends are not all up, which is the front-door-onto-
         # nothing shape — bound to the count AND to the backend it names, so a
         # port that folded the map and lost the URL would not satisfy this row.
         # And the rejected route's own words, which are the difference between
         # an overview saying one router is broken and a row saying which. Every
         # committed capture is of a Traefik with no dynamic providers, where
         # none of these members exists at all, so this operator mints the only
         # shape that draws the distinction.
         (differential.TRAEFIK_SERVERS_DOWN, differential.TRAEFIK_DOWN_BACKEND,
          differential.TRAEFIK_ROUTER_ERROR)),
    Case("error-text-blind", "transmission-errored-transfer",
         "a9_transfer_error_blind.py", differential.DISAGREE, "differences",
         # The fact and the client's own words, by value. Every torrent in the
         # only committed downloaders capture reports error 0 beside an empty
         # errorString — a lab torrent announces to a host that does not
         # resolve and never gets a reply to be refused by — so the arm that
         # publishes the line is exercised by no replay, and this operator
         # mints the one shape that takes it. Bound to the TEXT as well as the
         # fact name, because a port that published some other error line would
         # satisfy a bare "ErrorString" while still being wrong about what the
         # tracker said.
         ("ErrorString", differential.TRANSFER_ERROR_TEXT)),
    Case("hwdb-fallback-blind", "usb-hwdb-miss", "a9_usb_hwdb_blind.py",
         differential.DISAGREE, "differences",
         # Both facts, by the only values the SECOND source can produce: the
         # hub's own manufacturer string and its own product string, which the
         # hardware database never spells that way. Bound to the pair because
         # the facts dict is compared whole — a single fact would also be
         # satisfied by a port that had lost some other USB attribute — and to
         # the values rather than to the fact names, because a port publishing
         # the fact from the database would satisfy a bare "Vendor". Every USB
         # device in the committed capture is a root hub the database knows, so
         # the fallback is exercised by no replay and this operator is what
         # mints the only shape that draws it.
         (differential.USB_SYSFS_MANUFACTURER, differential.USB_SYSFS_PRODUCT)),
)


# ── coverage is deny-by-default over the fixtures directory (DESIGN 20) ───
#
# "Every collector that has ever fooled a judge is kept as a fixture that must
# visibly disagree under mutation." A CASES table that enumerates a subset is
# the subset guard one level up: three round-a5 subjects once sat in no case
# and no exemption, and a FUTURE judge-fooling fixture could land in
# fixtures/adversaries/ named by nothing here and redden nothing. So the set of
# fixtures this guard must account for is DERIVED from the directory, and every
# file is EITHER exercised by a case above OR named here with the reason
# mutation is not its venue — a file in neither fails test_every_fixture_is_
# covered_or_exempt. This mirrors test_adversaries_stay_red.py's own
# directory-vs-table check, one guard down.
#
# Two kinds of reason, and each must be TRUE, not a shrug:
#   · declared-green (DESIGN 19): no wrong-about-the-machine claim exists for a
#     mutation to expose.
#   · caught by the committed corpus under the replay judge: the fixture's
#     defect is visible without mutation, so replay owns its red and a
#     differential run would only re-fire the same rules — the differential
#     guard exists for what replay CANNOT see.
EXEMPT_FROM_MUTATION = {
    "fabricated_cost.py":
        "DESIGN 19 declared-green: self-reported cost is advisory by "
        "construction — the byte diff never sees cpu_ms/wall_ms and the rules "
        "only bound them — so no mutation has a wrong-about-the-machine claim "
        "to expose.",
    "a2_defective_port.py":
        "envelope defects — minted/zeroed/borrowed generations, wall-clock and "
        "far-future `at`, blank and nil boot_id, a drifting batch id — each "
        "caught by the committed corpus under the replay judge, and every axis "
        "held RED in test_adversaries_stay_red.py. The fixture selects its "
        "defect from SE_DEFECT, which the differential harness strips, so it "
        "cannot even stage one here; its one green axis, boot_id_constant_valid, "
        "is DESIGN 19's cross-boot deferral. Replay owns this fixture.",
    "a5_hardcoded_healthy.py":
        "a stubbed envelope — boot_id 'replay', `at` 0.0, minted generations, "
        "no positive wall_ms — unlawful on every pair, mutated or not, so the "
        "committed corpus catches it (RED on storage/healthy via the rules "
        "channel in test_adversaries_stay_red.py). A differential run only "
        "re-fires those same envelope rules; the health facet it also carries "
        "is caught as a MUTATION by a5_health_never_read.py's case above.",
    "a6_zero_value_envelope.py":
        "a zero-value envelope — blank boot_id, `at` 0, end ids minted fresh — "
        "caught by the committed corpus under the replay judge (RED on "
        "network/healthy via the rules channel); like a5_hardcoded_healthy, a "
        "differential run merely re-fires the envelope rules replay already "
        "applies.",
    "a5_name_keyed_reachability.py":
        "reachability keyed on the chain name alone, wrong ONLY when two chains "
        "share a name across families with different reachability — a shape no "
        "mutation operator mints. corpus/network/asymmetric stages it and owns "
        "the red under judge soundness; test_the_name_keyed_exemption_is_true "
        "executes both halves (RED there, AGREE under every operator here).",
}


def _ids(case: Case) -> str:
    return f"{case.defect}:{case.operator}"


def _seed(operator: differential.Operator) -> corpus.Variant:
    return VARIANTS[differential.SEEDS[operator.collector]]


def _binary(name: str) -> list[str]:
    return [sys.executable, str(FIXTURES / name)]


@pytest.fixture(autouse=True)
def _clean_fixture_switches(monkeypatch):
    """The port's request-parse gate and the a2 fixture's axis switch are
    ambient environment; a value leaking in from the caller's shell would
    turn attributable verdicts into unattributable ones."""
    monkeypatch.delenv("SE_PORT_NO_REQUEST_PARSE", raising=False)
    monkeypatch.delenv("SE_DEFECT", raising=False)


# ── the table's own shape: bound, consistent, and covering ───────────────


def test_every_case_is_bound_to_a_reason() -> None:
    """A case that only expects a verdict pins nothing — the same lesson
    test_adversaries_stay_red.py already paid for. Every row names a real
    operator, a committed fixture, a non-AGREE verdict, a channel, and
    literal evidence; and its class matches the operator's own declared
    `exposes`, so the table cannot drift from the mutator (the one
    driver-exposed class is exempted by name, because no payload operator
    declares it)."""
    for case in CASES:
        assert case.operator in OPERATORS, (
            f"{_ids(case)} names unknown operator {case.operator!r}"
        )
        assert (FIXTURES / case.challenger).is_file(), (
            f"{_ids(case)} names missing fixture {case.challenger!r}"
        )
        assert case.verdict in (differential.DISAGREE, differential.REFUSED), (
            f"{_ids(case)} expects {case.verdict!r} — a case that expects "
            "AGREE is not a catch, and belongs in the deferral tests below "
            "with its bound stated, not here"
        )
        assert case.channel in ("differences", "challenger_problems"), (
            f"{_ids(case)} names unknown channel {case.channel!r}"
        )
        assert case.evidence, (
            f"{_ids(case)} carries no evidence — 'it disagreed' is not a "
            "reason, and a row that does not say what the disagreement must "
            "state is satisfied by any unrelated mismatch"
        )
        if case.defect != DRIVER_EXPOSED:
            assert case.defect == OPERATORS[case.operator].exposes, (
                f"{_ids(case)}: the case claims class {case.defect!r} but "
                f"{case.operator} declares it exposes "
                f"{OPERATORS[case.operator].exposes!r} — one of them is "
                "wrong about what this mutation means"
            )


def test_no_operator_is_dead_weight() -> None:
    """Non-vacuity, per operator: every operator produces at least one
    disagreement (or refusal) against at least one committed wrong fixture.
    An operator no fixture can fail exercises nothing — it would sit in the
    control loop proving only that the reference agrees with itself — so its
    absence from this table fails the suite until either a fixture that dies
    to it is committed or the operator is removed as dead weight."""
    covered = {case.operator for case in CASES}
    dead = sorted(set(OPERATORS) - covered)
    assert not dead, (
        f"operators {dead} appear in no case: no committed wrong fixture "
        "disagrees under them, so they are dead weight — every operator "
        "must be able to kill something, or mutation coverage is being "
        "claimed for shapes nothing checks"
    )


def test_the_seeds_are_the_declared_smallest_set() -> None:
    """One healthy seed per collector, and both must exist in the corpus:
    the smallest set that exercises every operator, kept literal so a corpus
    reorganisation cannot silently starve the guard."""
    assert set(differential.SEEDS) == {op.collector
                                       for op in differential.OPERATORS}
    for collector, name in differential.SEEDS.items():
        assert name in VARIANTS, (
            f"seed {name!r} for {collector} is gone from the corpus"
        )


def test_every_fixture_is_covered_or_exempt() -> None:
    """Deny-by-default over the directory, not the table (DESIGN 20). Every
    file in fixtures/adversaries/ must EITHER be the challenger of a case above
    OR carry an EXEMPT_FROM_MUTATION reason — a fixture in neither fails here,
    which is the only thing that stops a future judge-fooling port from landing
    with no mutation coverage and reddening nothing. Both directions, because a
    named-but-absent exemption is a fixture that silently stopped shipping."""
    present = {p.name for p in FIXTURES.iterdir()
               if p.suffix == ".py" and p.name != "__pycache__"}
    covered = {case.challenger for case in CASES}
    exempt = set(EXEMPT_FROM_MUTATION)
    both = sorted(covered & exempt)
    assert not both, (
        f"{both} are both exercised by a case AND listed exempt — a fixture the "
        "mutator exposes needs no exemption, and one it cannot must not also "
        "claim a case; pick the one that is true"
    )
    assert present == covered | exempt, (
        "fixtures/adversaries/ and the differential guard's coverage disagree — "
        f"uncovered: {sorted(present - covered - exempt)}, named but absent: "
        f"{sorted((covered | exempt) - present)}. DESIGN 20: every collector "
        "that ever fooled a judge must visibly disagree under mutation, or "
        "carry a named reason the committed corpus (not a mutation operator) "
        "owns its red. Add a case that reddens it, or an EXEMPT_FROM_MUTATION "
        "entry that is true."
    )


# ── the declared closed classes are exhaustively owned (DESIGN 20) ────────
#
# The deepest form of the subset guard this module fights: an `exposes=` label
# that names a FINITE, DECLARED set — the nftables families, the ZFS vdev groups
# — claims the guard closes that set member by member, and two operators wearing
# `family-enum` said so while `arp` was minted by no operator and named in no
# residual. A CASES table listing the operators that DO exist cannot catch that:
# it enumerates what the author minted, which is the very shape the label was
# supposed to have closed. Only reading the AUTHORITY does — so for each closed
# class the guard declares, the full membership is derived from the product's
# own source of truth (below), partitioned into judge-owned ∪ guard-owned ∪
# declared-residual, and that partition is held EXHAUSTIVE. A member owned by
# none fails by name. This is the same discipline DESIGN 19 puts on the
# run-varying set — "a member in neither regime fails the harness's own tests"
# — turned on the mutation operators' own claimed coverage.
#
# The authority is READ, never retyped: a constant copied here would drift into
# quiet agreement with a broken walk, which is the defect one level up. Editing
# network.py's family enumeration, or storage.py's ZFS_GROUP_VDEVS, moves what
# this test demands — which is exactly the reversion the closure guard ships
# with (a family added to the authority with no operator reddens this by name).


def _families_from_prose(description: str) -> frozenset[str]:
    """The address families a Family glossary sentence enumerates.

    The sentence is "…belongs to — ip, ip6, inet, arp, bridge or netdev.": take
    the clause after the em dash up to the sentence's end, and tokenise on the
    commas and the trailing "or". Parsed from the prose the product actually
    publishes to a reader, not a set retyped beside it — so the authority this
    guard reads is the one a person reading the fact dictionary would."""
    _, _, tail = description.partition("—")
    clause = tail.split(".", 1)[0]
    return frozenset(
        token.strip() for token in re.split(r",|\bor\b", clause) if token.strip()
    )


def _declared_nft_families() -> frozenset[str]:
    """The nftables family set, from network.py's own fact dictionary. Both the
    rule and chain glossaries enumerate it; their union is read, so an edit to
    either is picked up and a divergence errs toward demanding MORE coverage —
    the safe direction for a deny-by-default guard."""
    from system_explorer.agent.adapters import network

    families = _families_from_prose(
        network._NFT_RULE_GLOSSARY["Family"]
    ) | _families_from_prose(network._NFT_CHAIN_GLOSSARY["Family"])
    assert families, (
        "network.py's Family glossary enumerated no families — the authority "
        "the family-enum closure reads is gone or unparseable, so the guard "
        "cannot know what set it must close"
    )
    return families


def _declared_zfs_groups() -> frozenset[str]:
    """The ZFS vdev-group set, from storage.py's own declared constant."""
    from system_explorer.agent.adapters import storage

    return frozenset(storage.ZFS_GROUP_VDEVS)


def _declared_scoped_states() -> frozenset[str]:
    """The container states that keep a scope cgroup, from docker.py's own
    declared constant. Docker's vocabulary rather than this product's, which is
    the point: the set is closed by the daemon and a port that shipped a shorter
    one is wrong about a machine, not about a convention."""
    from system_explorer.agent.adapters import docker

    return frozenset(docker._SCOPED_STATES)


_AUTHORITIES = {
    "family-enum": _declared_nft_families,
    "group-enum": _declared_zfs_groups,
    "scoped-state-enum": _declared_scoped_states,
}


@pytest.mark.parametrize("closed", differential.CLOSED_CLASSES,
                         ids=lambda c: c.label)
def test_the_closed_class_is_exhaustively_owned(closed) -> None:
    """Every declared member of a closed class is owned by capture, operator or
    named residual — and a member owned by none fails by name.

    This is the guard's own claim, made checkable: `exposes="family-enum"` and
    `exposes="group-enum"` each assert the whole declared set is covered, and
    this partitions that set against three owners and proves the cover total.
    The full membership comes from the PRODUCT (network.py's Family glossary,
    storage.py's ZFS_GROUP_VDEVS) so the test cannot drift into agreement with a
    guard that only minted the members its author remembered."""
    # Deny-by-default one level up: a closed class the guard declares with no
    # authority reader here is a promise nothing verifies.
    assert closed.label in _AUTHORITIES, (
        f"{closed.label}: differential.CLOSED_CLASSES declares this class but no "
        "authority reader derives its full membership — add one that reads "
        f"{closed.authority}, or the closure is asserted over an empty set"
    )
    full = _AUTHORITIES[closed.label]()

    # judge-owned: present in a committed capture, so the replay judge sees the
    # member without any mutation at all.
    captures = [v for v in corpus.all_variants()
                if v.meta["collector"] == closed.collector]
    judge = frozenset().union(
        *(closed.members_in(v.payloads) for v in captures)
    ) & full

    # guard-owned: minted into the seed by some operator, beyond what the seed
    # (itself a committed capture) already carried. Read from the operators'
    # actual output, not their declared labels — an operator owns a member by
    # minting it, whatever class it says it exposes.
    seed = VARIANTS[differential.SEEDS[closed.collector]]
    seed_members = closed.members_in(seed.payloads)
    guard = frozenset(
        member
        for op in differential.OPERATORS if op.collector == closed.collector
        for member in (closed.members_in(differential.mutated_payloads(op, seed))
                       - seed_members) & full
    )

    # residual: declared, and each entry must be a TRUE "no operator can mint
    # this" with a stated reason — never a member an operator does mint (that is
    # a contradiction, the covered-and-exempt shape), and never one outside the
    # declared set.
    residual = frozenset(closed.residual)
    assert residual <= full, (
        f"{closed.label}: residual names {sorted(residual - full)} outside the "
        f"declared set {sorted(full)} — a residual is for a declared member "
        "that cannot be minted, not for one the authority never named"
    )
    assert not (residual & guard), (
        f"{closed.label}: {sorted(residual & guard)} is both minted by an "
        "operator and declared a residual — a member the guard mints needs no "
        "residual; pick the one that is true"
    )
    assert all(closed.residual[member].strip() for member in residual), (
        f"{closed.label}: a residual carries an empty reason — 'it cannot be "
        "minted' is not a reason, and the live comparator must be named as the "
        "venue that catches it instead"
    )

    orphans = sorted(full - (judge | guard | residual))
    assert not orphans, (
        f"{closed.label}: {orphans} in the declared set {sorted(full)} "
        f"({closed.authority}) is owned by nobody — not seen in a committed "
        f"capture (judge: {sorted(judge)}), not minted by an operator (guard: "
        f"{sorted(guard)}), not a declared residual (residual: {sorted(residual)}"
        "). DESIGN 20: the product names its net and never implies absence of "
        "holes, so a declared member no operator mints is the subset guard one "
        "level up. Add an operator that mints it (arp and l2cache both can be), "
        "or a residual whose reason is true and whose venue is the live "
        "comparator."
    )


def test_the_name_keyed_exemption_is_true() -> None:
    """The one exemption whose claim is substantive rather than definitional:
    a5_name_keyed_reachability is exempt as corpus-caught-not-mutation-caught,
    and a false exemption is worse than none, so both halves are executed. It
    must go RED on the committed network/asymmetric pair — the anchors the
    exemption rests on — AND AGREE under every network operator, because the
    only shape that exposes it (two chains sharing a name across families with
    different reachability) is one no operator mints. Either half breaking
    means the exemption has become a lie: add a case, or move the coverage."""
    fixture = "a5_name_keyed_reachability.py"
    assert fixture in EXEMPT_FROM_MUTATION, (
        "this test guards a specific exemption; it has left the ledger"
    )
    binary = _binary(fixture)

    # corpus-caught: RED on network/asymmetric's anchors, through the real judge
    variant = VARIANTS["network/asymmetric"]
    issued = replay.issue_generations(variant.collections(), seed=variant.name)
    proc = replay.run_collector(binary, variant, issued=issued)
    assert proc.returncode == 0, (
        f"{fixture} crashed on network/asymmetric — fixture rot, not a "
        f"catch:\n{proc.stderr[:500]}"
    )
    anchor_problems = corpus.validate_anchors(
        variant, replay.parse_stream(proc.stdout)
    )
    assert anchor_problems, (
        f"{fixture} no longer fails network/asymmetric's anchors — the "
        "committed catch this exemption rests on is gone, so the fixture is "
        "now covered by nothing"
    )

    # not mutation-caught: AGREE under every operator that could touch it
    for operator in differential.OPERATORS:
        if operator.collector != "network":
            continue
        run = differential.run_differential(binary, _seed(operator), operator)
        assert run.verdict == differential.AGREE, (
            f"{fixture} is exempt as corpus-only, but {operator.name} exposes "
            f"it ({run.verdict}) — an operator now mints the cross-family name "
            "collision, so add a case for it and drop the exemption:\n"
            f"{run.report()}"
        )


# ── the ported collectors, judged by the guard that judges the fixtures ──
#
# Everything above this line points the mutation guard at a committed wrong
# fixture. Nothing pointed it at a PORTED COLLECTOR — every call site passed a
# fixture path or the reference itself — so the tier's demands on the artefacts
# the port actually ships were aspirational, stated in prose and enforced by
# nothing. That is the subset guard one level up: an apparatus that closes a
# class against the subjects it was written with, and never against the subject
# it exists for.
#
# The partition below is therefore deny-by-default over conftest.GO_COLLECTORS,
# in every direction: a ported collector is judged under every operator its
# collector has, or it is named here with the venue that owns its truth; a name
# here that IS judged is a stale excuse and fails; a name here that is not a
# ported collector at all fails.

PORTED_WITHOUT_A_REFERENCE = {
    "system": (
        "the differential guard's reference half is replay.reference_binary() "
        "— the Python shim — and no Python adapter serves the system "
        "collector, so there is no reference to disagree with and a seed would "
        "only produce REFUSED through no fault of the challenger. Its payloads "
        "are text (os-release, hostname, boot_id) and differential.write_payloads "
        "writes every stem as JSON, so the guard could not hand it a readable "
        "directory even with a reference. Venue: the live comparator, and a "
        "second independent implementation of the collector if one is ever "
        "written — an agreement guard needs two parties and this collector has "
        "one."
    ),
}


def _ported_cases() -> list[tuple[str, differential.Operator]]:
    from conftest import GO_COLLECTORS

    return [
        (collector, operator)
        for collector in sorted(GO_COLLECTORS)
        for operator in differential.OPERATORS
        if operator.collector == collector
    ]


@pytest.mark.parametrize(
    "collector,operator", _ported_cases(), ids=lambda v: getattr(v, "name", v)
)
def test_a_ported_collector_agrees_with_the_reference_under_mutation(
    collector: str, operator: differential.Operator
) -> None:
    """The port, the reference, the same mutated payload: AGREE.

    This is the check replay equivalence cannot make. A port that hardcodes
    its way through the committed captures is green by construction on every
    pair — a7_replay_green_port.py is the committed proof — and stops being
    green the moment the payload grows a shape its author never met. Each
    operator names the defect class it exposes; a DISAGREE here says which.

    Agreement proves consistency with the reference, never truth: truth rests
    on the corpus anchors, and a mismatch is an adjudication (PLAN standing
    rule 6), so read the diff before assuming the port is the wrong half.
    """
    from conftest import go_collector_binary

    binary = [go_collector_binary(collector)]
    run = differential.run_differential(binary, _seed(operator), operator)
    assert not run.reference_problems, (
        f"{collector} × {operator.name}: the reference half is unlawful, so "
        f"this run proves nothing about the port:\n{run.report()}"
    )
    assert run.verdict == differential.AGREE, (
        f"{collector} × {operator.name}: {run.verdict}. This operator exposes "
        f"the {operator.exposes!r} class — a shape no committed capture holds, "
        f"which is why replay equivalence passed it:\n{run.report()}"
    )


def test_every_ported_collector_is_mutation_judged_or_named() -> None:
    """The partition over the ported set, asserted rather than assumed.

    A collector can leave this guard three ways, and only one of them is
    honest: by being judged. So the other two are closed here — an unjudged
    collector with no entry fails, and an entry that has become untrue fails
    whether it went stale (the collector is judged now) or was never true (it
    names something that is not a ported collector).
    """
    from conftest import GO_COLLECTORS

    ported = set(GO_COLLECTORS)
    assert ported, "GO_COLLECTORS is empty; this whole arm is vacuous"
    judged = {op.collector for op in differential.OPERATORS} & ported

    orphans = sorted(ported - judged - set(PORTED_WITHOUT_A_REFERENCE))
    assert not orphans, (
        f"ported and unjudged by the mutation guard, named by nothing: "
        f"{orphans}. Replay equivalence alone cannot see a hardcoded port, so "
        "a collector with neither operators nor a named residual is graded "
        "only on the machines that happen to be in the corpus. Add a seed and "
        "operators, or name the venue that owns its truth instead."
    )
    stale = sorted(set(PORTED_WITHOUT_A_REFERENCE) & judged)
    assert not stale, (
        f"{stale} carry an excuse from the guard AND are judged by it — a "
        "residual that has come true is an excuse nobody withdrew, and the "
        "next reader will believe it"
    )
    unknown = sorted(set(PORTED_WITHOUT_A_REFERENCE) - ported)
    assert not unknown, (
        f"{unknown} are excused from the mutation guard but are not ported "
        "collectors at all — an entry about nothing reads as coverage"
    )
    for name, reason in PORTED_WITHOUT_A_REFERENCE.items():
        assert "Venue:" in reason, (
            f"{name}: a residual names the venue that owns its truth, or it "
            "is a hole dressed as a disclosure"
        )


# ── the control: the reference against itself, every operator ────────────


@pytest.mark.parametrize("operator", differential.OPERATORS,
                         ids=lambda op: op.name)
def test_the_reference_agrees_with_itself(operator) -> None:
    """The mutator's own soundness, one operator at a time. The reference
    run twice over the same mutated payloads must AGREE — a refusal here
    means the operator emitted a payload the reference rejects (a fuzzer
    move, not a mutator move), and a disagreement means nondeterminism.
    Either way the bug is the mutator's, and every DISAGREE elsewhere in
    this module rests on this test saying so first."""
    run = differential.run_differential(
        replay.reference_binary(), _seed(operator), operator
    )
    assert run.verdict == differential.AGREE, (
        f"{operator.name}: the reference does not survive its own mutation "
        f"— this operator is broken, and no verdict under it means "
        f"anything:\n{run.report()}"
    )
    assert not run.reference_problems and not run.challenger_problems


# ── the verdicts: each defect class, for its declared reason ─────────────


@pytest.mark.parametrize("case", CASES, ids=_ids)
def test_the_class_disagrees_for_its_declared_reason(case, monkeypatch) -> None:
    """The fixture meets its operator, and the disagreement says the
    declared thing. Redness is not the assertion: a case is satisfied only
    when the named channel carries the named evidence, so a fixture that
    starts failing for an unrelated reason — a schema tightening, a corpus
    edit — fails THIS test instead of quietly satisfying it."""
    for key, value in case.env:
        monkeypatch.setenv(key, value)
    operator = OPERATORS[case.operator]
    run = differential.run_differential(
        _binary(case.challenger), _seed(operator), operator
    )
    # The reference half must be clean, or the verdict is about a poisoned
    # control rather than about the challenger.
    assert not run.reference_problems, (
        f"{_ids(case)}: the reference side is unlawful, so this run proves "
        f"nothing about {case.challenger}:\n{run.report()}"
    )
    assert run.verdict == case.verdict, (
        f"{_ids(case)}: expected {case.verdict}, got {run.verdict}. "
        f"{case.challenger} is wrong about the machine in exactly this "
        f"class; a different verdict means either the fixture stopped "
        f"exercising its defect or the guard that exposes it has "
        f"regressed:\n{run.report()}"
    )
    caught = "\n".join(getattr(run, case.channel))
    missing = [text for text in case.evidence if text not in caught]
    assert not missing, (
        f"{_ids(case)} reached {case.verdict}, but not for its declared "
        f"reason: the {case.channel} channel does not mention {missing!r}.\n"
        f"What it said:\n"
        + ("\n".join(f"  - {line}"
                     for line in getattr(run, case.channel)[:10]) or "  (nothing)")
        + "\nA case bound only to its verdict would have passed this run — "
        "find out what actually moved before editing the table."
    )


# ── the two deferrals, executed rather than assumed ──────────────────────


def test_constant_at_is_the_live_comparators_to_catch() -> None:
    """The port's constant `at` is on the wire, differs from the reference's
    advancing readings, and the verdict is still AGREE — that is DESIGN 19's
    ownership law holding, not a gap: replay pins the clock, so no
    replay-side judge can tell a constant from a reading, and a rule here
    that pretended otherwise would be a guard that cannot fail. The live
    comparator, which sees real readings beside the reference's, owns
    time's truth. Both halves are asserted so the deferral cannot rot into
    vacuity: if the wrong bytes ever stop appearing, or agreement breaks
    for an unrelated reason, this test names which half moved."""
    operator = OPERATORS["nft-jump-to-goto"]
    run = differential.run_differential(_binary(PORT), _seed(operator), operator)
    assert run.verdict == differential.AGREE, (
        "the port no longer agrees under its AGREE operator — its verdict "
        f"moved, so this deferral test is aimed at the wrong run:\n{run.report()}"
    )
    port_ats = [r["at"] for r in run.challenger_emitted
                if r["record"] == "object"]
    reference_ats = [r["at"] for r in run.reference_emitted
                     if r["record"] == "object"]
    assert len(set(port_ats)) == 1, (
        f"the port's `at` is no longer constant ({sorted(set(port_ats))[:5]}) "
        "— its defect 5 has been edited away, and the deferral this test "
        "documents no longer has a subject"
    )
    assert port_ats != reference_ats, (
        "the port's constant happens to equal the reference's readings — "
        "the green would prove agreement, not adjudication"
    )
