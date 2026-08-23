"""The gap register: one authority for what is ported, owed, and ruled.

PLAN's re-baseline found three lists agreeing with each other and none of
them with the reference: the comparator's ``SERVES``, the replay seam's
``SEAM`` and the live driver's ``LIVE`` each named the collections the port
already implemented, so every venue asked both sides only for what the port
had, and eighteen collections the shipping product serves were never asked
for at all. This module is the R2 inversion. The work list DERIVES from the
reference adapters' own ``collections()``; every exclusion is an entry here
with its reason; and a collection in neither the port nor this register is
an error every consumer refuses to run past.

Three consumers, deliberately: ``harness/bin/se-compare`` builds its work
list from :func:`comparator_work` and refuses to start on an inconsistent
register; ``harness/bin/se-live-reference`` serves exactly what the work
list says a collector answers for; and ``conformance/test_port_completeness``
holds every list below to reality in both directions, so an entry cannot go
stale in either the "owed but built" or the "built but owed" direction.

Coverage, stated where it is defined: everything here is read from the
tree — adapter source, committed declarations, ``app.js`` — so this module
can say what is *encoded*, never what a live run would show. Whether the
compared collections actually agree is the comparator's answer, on a real
machine, at gate R3.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parent.parent.parent
ADAPTERS = REPO / "src" / "system_explorer" / "agent" / "adapters"
GO_CMD = REPO / "go" / "cmd"


class RegisterViolation(AssertionError):
    """The register and the tree disagree, or a parse went blind.

    An AssertionError so pytest renders it as a failure, and raised rather
    than returned so no consumer can take a half-derived work list and run
    with it — a comparator that starts on a lying register reports parity
    about a subset while looking exhaustive, which is the defect this whole
    module exists to end.
    """


#: Collections the rewrite deliberately does not carry, each with the ruling
#: that settled it. A reason here is a decision somebody made, not a note
#: that work is outstanding — for that, see NOT_YET_PORTED.
DELIBERATELY_DROPPED: dict[str, str] = {
    "network/lookups": "lookup is a VERB in the new contract, not a collection "
                       "(DESIGN 18): the collector serves `lookup` and there is "
                       "nothing to enumerate.",
    "storage/lookups": "same ruling as network/lookups.",
    "system/self": "the collator reports its own cost per collection (DESIGN 19), "
                   "so a self collection would be a second account of it.",
}

#: Collections that ARE owed and are not built. Every entry is a hole in the
#: product a person would notice, and the list is what stops gate 6 being
#: reachable while they are open.
NOT_YET_PORTED: dict[str, str] = {
}

#: Collectors the CORPUS venues cannot drive through the Python reference,
#: each with why. The live comparator is not gated by this — it drives every
#: collector below — but the replay seam stages captured payloads per
#: adapter, and one adapter has no such seam yet. An entry here is owed
#: work, never a decision.
NO_REPLAY_SEAM: dict[str, str] = {
    "system": "OWNER:R5 — no payload-staging seam was ever written for the system "
              "adapter, so the corpus venues replay its captures through the "
              "PORT only — time landed at R3b on captured-then-scrubbed "
              "guest payloads without one. **Re-owned to R5 on 2026-08-23**, "
              "after an audit found this excuse had outlived its own "
              "condition: it read 'the Python seam stays owed while its "
              "collections port', and all four ported — identity at R2, "
              "time, boot and overview at R3b, which PLAN declares done. So "
              "four landed collections have never been diffed against the "
              "reference anywhere a merge can see, and the guard could not "
              "notice because it asserted the excuse EXISTS rather than that "
              "it still holds. `se-compare` is their only venue and needs a "
              "live Linux host, which is why this is R5's deployment work "
              "rather than something a corpus run can close. Row 28 owns it, "
              "so it is counted rather than sitting in a second list the "
              "27-row census never reached.",
}


def reference_collections() -> dict[str, list[str]]:
    """What each shipping adapter serves, read from its own ``collections()``.

    Ordered as the adapter returns them, because the applied order is part of
    what a collection is (DESIGN §19, the 2026-08-21 ruling). Parsed from
    source rather than imported so every consumer — including scripts that
    must not import the agent's dependencies — reads one derivation.

    The parse refuses to go quietly blind: a regex that stopped matching
    would shrink the work list of every consumer at once while each kept
    reporting success, so anything under the known adapter count raises.
    """
    out: dict[str, list[str]] = {}
    for path in sorted(ADAPTERS.glob("*.py")):
        if path.stem == "__init__":
            continue
        match = re.search(
            r"def collections\(self\)[^\n]*\n(?:\s*#[^\n]*\n)*\s*return \[(.*?)\]",
            path.read_text(), re.S)
        if match:
            out[path.stem] = re.findall(r'"([a-z][a-z0-9-]*)"', match.group(1))
    if len(out) < 20 or len(out.get("network", [])) < 10:
        raise RegisterViolation(
            f"the collections() parse found only {sorted(out)} — the regex "
            "has gone blind, and a blind parse must not become a short work "
            "list that every consumer reports success over")
    return out


def ported_collections() -> dict[str, dict[str, dict]]:
    """Each port's committed declaration, keyed collector → collection name.

    The whole collection object is returned, because more than one guard
    reads it: the work list needs the names, the answer rulings need
    ``answer``, and the register rows probe ``names``/``relations``/``rules``.
    """
    out: dict[str, dict[str, dict]] = {}
    for path in sorted(GO_CMD.glob("se-collect-*/declaration.json")):
        document = json.loads(path.read_text())
        out[document["collector"]] = {
            c["name"]: c for c in document["collections"]}
    if len(out) < 20:
        raise RegisterViolation(
            f"only {len(out)} committed declarations found under go/cmd — "
            "either collectors were removed or the glob has gone blind")
    return out


def comparator_work(
    reference: dict[str, list[str]] | None = None,
    ported: dict[str, dict[str, dict]] | None = None,
) -> dict[str, dict]:
    """The live comparator's work list, derived and cross-checked.

    For every collector the REFERENCE serves: which collections are compared
    (the port declares them), and which are excluded with the register entry
    that says why. Deny-by-default in all four directions at once —

    * a reference collection that is neither ported nor registered raises:
      that is the hole the eighteen sat in;
    * a port collection the reference never served raises: new capability is
      frozen until parity (PLAN, the re-baseline);
    * a register entry claiming a collection is owed when the port declares
      it raises: a stale register is how a hole gets forgotten twice;
    * a register entry naming a collection no adapter serves raises: an
      exclusion with no subject excludes nothing and rots silently.

    ``reference`` and ``ported`` are injectable so the conformance drills can
    feed this function a world that is wrong in exactly one way and watch it
    refuse; both default to the tree's own truth.
    """
    reference = reference_collections() if reference is None else reference
    ported = ported_collections() if ported is None else ported

    problems: list[str] = []
    known = {f"{collector}/{name}"
             for collector, names in reference.items() for name in names}
    for key in list(DELIBERATELY_DROPPED) + list(NOT_YET_PORTED):
        if key not in known:
            problems.append(
                f"{key}: registered, but no adapter serves it — the entry "
                "excludes nothing and should be removed")

    work: dict[str, dict] = {}
    for collector, names in sorted(reference.items()):
        declared = ported.get(collector, {})
        compare: list[str] = []
        excluded: dict[str, str] = {}
        for name in names:
            key = f"{collector}/{name}"
            registered = (key in DELIBERATELY_DROPPED) or (key in NOT_YET_PORTED)
            if registered and name in declared:
                problems.append(
                    f"{key}: listed in the register as not carried, but the "
                    "port declares it — update the register")
            elif key in DELIBERATELY_DROPPED:
                excluded[name] = "dropped: " + DELIBERATELY_DROPPED[key]
            elif key in NOT_YET_PORTED:
                excluded[name] = "owed: " + NOT_YET_PORTED[key]
            elif name in declared:
                compare.append(name)
            else:
                problems.append(
                    f"{key}: served by the reference, not ported, and no "
                    "register entry says why — this is the hole the eighteen "
                    "sat in, and silence does not pass")
        for name in sorted(set(declared) - set(names)):
            problems.append(
                f"{collector}/{name}: the port declares a collection the "
                "reference never served — new capability is frozen until "
                "parity (PLAN, the re-baseline)")
        work[collector] = {"compare": compare, "excluded": excluded}

    if problems:
        raise RegisterViolation(
            "the register and the tree disagree:\n  " + "\n  ".join(problems))
    return work


# ── the answer rulings (register row 26) ──────────────────────────────────
#
# The old UI's COLUMNS table is the argued column preset per collection —
# several entries carry paragraph-length arguments — and the ports' `answer`
# lists diverged from it silently, which gate 5 then rendered as an empty-
# looking product. Every divergence between the two is an entry here: either
# RULED, with the ground, or OWED, with the phase that re-judges it. The
# conformance test computes the real divergence set from app.js and the
# declarations and holds this table to it in both directions, so neither a
# new divergence nor a healed one can pass silently.

# **Seven rulings were re-owned from R3d to R4 on 2026-08-23.** They were
# owed to R3d, R3d closed with them unanswered, and a follow-up promise
# that outlives its phase is owned by nobody — while row 26 rendered them
# as ruled and read "built" over the lot. Gate R3's own clause is "the
# register shows no unowned row", so this was that clause failing
# silently.
#
# R4 is the honest home rather than a convenient one: an `answer` list IS
# the row density §27 defines — which facts ride a row — and that is
# judged by looking at the row. It is the same reasoning that moved the
# three acceptance items, taken by the owner the same day: an item that
# names a page is judged where pages exist. storage/pools is the sharpest
# of the seven, because a collection whose row cannot answer its own
# declared question ("when was one last scrubbed?", with ScanFunction no
# longer on the row) is a defect the page makes obvious and a table does
# not.
#
# `test_no_ruling_is_owed_to_a_phase_that_has_closed` now catches this
# class. The guard that let it through asserted a phase was NAMED and
# never that the phase was still open.
ANSWER_RULINGS: dict[str, str] = {
    "units/units": "ruled: additive — the reference's three columns survive "
                   "verbatim and in order, and the port appends "
                   "MissingRequirements, dependency health the old UI only "
                   "surfaced on the object page.",
    "network/nft-chains": "ruled: at the R3d nft retrofit — the preset's own "
                          "argument (one chain name in ip and ip6 is two "
                          "chains) is answered by the row's NAME, which since "
                          "R3b is the three-part 'family table name', so "
                          "Family/Table/Name as answer columns would respell "
                          "the name three times; all three stay declared for "
                          "filtering. Policy returns — a base chain's policy "
                          "is the fate of an unmatched packet, the single "
                          "most consequential fact on the row. Priority stays "
                          "declared and off the answer: it orders chains on a "
                          "shared hook, which is drill-down, not headline.",
    "network/nft-rules": "ruled: at the R3d nft retrofit — Position's argument "
                         "(first-match-wins, so order IS meaning) is carried "
                         "by applied order since R1, and Family/Table/Chain "
                         "by the row's name, which leads with them. "
                         "JumpTarget returns: where a rule dispatches is how "
                         "a reader follows the ruleset's flow, and it was "
                         "carried by nothing.",
    "resources/workloads": "ruled: additive — the reference's eight columns "
                           "survive as an ordered subsequence; the port adds "
                           "the depth, throttle and stall-attribution facts "
                           "the old UI never had.",
    "docker/containers": "owed: R4 — Status (docker's own 'Up 3 hours' "
                         "reading) was dropped and Ports added; keep-or-"
                         "replace is re-judged at the docker retrofit.",
    "docker/volumes": "owed: R4 — ComposeProject, the join the estate "
                      "actually reads, was dropped from the preset.",
    "docker/networks": "owed: R4 — Internal was dropped from the preset.",
    "storage/pools": "owed: R4 — the port answers UnhealthyVdevs where the "
                     "reference answered DeviceFailuresTolerated/ScanFunction/"
                     "Errors; no design section grounds the swap, and the "
                     "declared question still asks 'when was one last "
                     "scrubbed?' while the answer no longer carries "
                     "ScanFunction.",
    "nix/generations": "owed: R4 — Kernel/ConfigurationRevision/Changed/"
                       "Deployed/Created left the preset (the facts are still "
                       "emitted and compared; only the answer narrowed).",
    "packages/packages": "owed: R4 — Architecture and StorePath left the "
                         "preset; the facts are still emitted and compared.",
    "hardware/platform": "ruled: at R3c — SysVendor stays added — vendor and "
                         "product are the machine's identity pair, and a bare "
                         "product string names half a machine. BiosVersion "
                         "stays declared and leaves the answer: a one-object "
                         "collection's answer is its headline, and a firmware "
                         "release is a drill-down fact, not what the machine "
                         "IS.",
    "hardware/scsi": "ruled: at R3c — the preset returns verbatim and in order "
                     "except its two synthetics. Kind is carried by the type "
                     "member since R1, and Link — app.js composed it from "
                     "LinkSpeed and a width SATA does not have — returns as "
                     "LinkSpeed, the fact the column actually read; the SAS "
                     "width pair stays declared for the object page.",
    "hardware/nvme": "ruled: at R3c — FirmwareRev, Serial and Namespaces return "
                     "with the champion (Serial is also a name family now). "
                     "Link returns as LinkBandwidthBytesPerSec — the preset's "
                     "own comment argues speed and width MULTIPLY into the "
                     "one number a reader wants, and the port minted that "
                     "number as a fact. SmartPercentUsed stays added: rated "
                     "write life is the NVMe health headline the old UI "
                     "never had.",
    "vms/domains": "owed: R4 — Autostart left the preset.",
}


def old_answer_presets() -> dict[str, list[str]]:
    """The old UI's COLUMNS table, parsed from ``app.js``.

    Parsed live rather than copied, because a copy is a fourth thing to
    disagree with the file the estate still runs. Order is kept: several
    presets argue their order in comments beside them, so 'same columns,
    different order' is a divergence and must read as one.
    """
    source = (REPO / "src" / "system_explorer" / "ui" / "app.js").read_text()
    match = re.search(r"const COLUMNS = \{(.*?)\n\};", source, re.S)
    if not match:
        raise RegisterViolation("app.js no longer has a COLUMNS table to hold "
                                "the answer rulings to")
    body = re.sub(r"/\*.*?\*/", "", match.group(1), flags=re.S)
    out: dict[str, list[str]] = {}
    for route, columns in re.findall(r'"([a-z-]+/[a-z-]+)":\s*\[(.*?)\]',
                                     body, re.S):
        out[route] = re.findall(r'"([A-Za-z0-9]+)"', columns)
    if len(out) < 30:
        raise RegisterViolation(
            f"the COLUMNS parse found only {len(out)} presets — the regex "
            "has gone blind, and a blind parse would let every answer "
            "divergence pass as 'no preset to differ from'")
    return out


def answer_divergences(
    presets: dict[str, list[str]] | None = None,
    ported: dict[str, dict[str, dict]] | None = None,
) -> dict[str, dict[str, list[str]]]:
    """Every ported collection whose ``answer`` differs from the old preset.

    Compared as ordered lists, not sets: the presets argue their order.
    Coverage: only collections the old UI carried a preset for — a port
    collection with no preset has nothing argued to diverge from, and an
    unported preset's divergence is owned by its NOT_YET_PORTED entry until
    the collection exists to judge.
    """
    presets = old_answer_presets() if presets is None else presets
    ported = ported_collections() if ported is None else ported
    out: dict[str, dict[str, list[str]]] = {}
    for route, columns in sorted(presets.items()):
        collector, name = route.split("/", 1)
        declared = ported.get(collector, {}).get(name)
        if declared is None:
            continue
        answer = declared.get("answer") or []
        if answer != columns:
            out[route] = {"reference": columns, "port": answer}
    return out


# ── the gap register (PLAN, the re-baseline) ──────────────────────────────


@dataclass(frozen=True)
class Row:
    """One register row: what is missing or was missing, who owns it, and —
    where the tree can attest it — a probe that says whether it is built.

    ``probe`` returns True when the tree shows the item built. The
    conformance test holds ``state`` to the probe in BOTH directions: a row
    claiming built whose probe fails is an over-claim, and a row claiming
    owed whose probe passes is a stale register — the direction that let a
    hole be forgotten twice. ``coverage`` states what the probe can and
    cannot see, or why no probe exists; a guard that cannot see something
    must say so where it is defined.
    """

    number: int
    item: str
    state: str  # "built" | "owed"
    owner: str
    probe: Callable[[], bool] | None
    coverage: str


def _in_file(relative: str, needle: str) -> bool:
    path = REPO / relative
    return path.is_file() and needle in path.read_text()


def _verb_landed(verb: str) -> bool:
    """Whether the verb is ANSWERABLE and REACHABLE, which is two tiers.

    **The answering half** matches the verb inside any `case` clause of a
    collector main, not `case "<verb>":` literally — units dispatches
    `case "object", "evidence":` as one clause, and the literal spelling sat
    blind to it for exactly as long as it took the first verb to land
    (found 2026-08-21).

    **The reaching half was missing entirely until 2026-08-23**, and its
    absence is why this probe reported three rows built over a feature
    nothing in the shipping product could invoke. The collector leaf
    answered; the wire client offered `Declare` and `Collect` and no third
    method; the collator published no route. So the verbs were reachable
    only by a person piping a request into a collector binary by hand, and
    a probe that greps only the leaf could not tell that from a working
    feature. That is register row 17's defect — a probe reading one tier
    for a responsibility DESIGN §06 places at another — found in three more
    rows by an audit of R3's own landings.

    So the probe now asks both tiers, and a verb answered by every collector
    and reachable by nothing is not built.
    """
    clause = re.compile(r'case [^:\n]*"' + re.escape(verb) + '"')
    answers = any(clause.search(path.read_text())
                  for path in GO_CMD.glob("se-collect-*/main.go"))
    reaches = _in_file("go/internal/wire/verbs.go", f'Verb{verb.capitalize()}')
    # The REGISTRATION, not the identifier. Each of wire.VerbObject,
    # wire.VerbEvidence and wire.VerbLookup occurs twice in rest.go —
    # once in the dispatch switch and once in the mux registration — so
    # removing every route registration left the identifier behind and
    # the probe still read "built". Found by review the same day the
    # probe was widened, which is the third time this row's probe has
    # been satisfied by something adjacent to the thing it claims.
    serves = _in_file("go/internal/collate/rest.go",
                      f'serveVerb(wire.Verb{verb.capitalize()})')
    # **And WIRED.** The three tiers above were each a grep, so a channel
    # that existed and was never handed to the running daemon satisfied
    # all of them: NewHandlerWithReverse had one caller, NewHandler,
    # passing nil — every deployment answered `no-collectors` and the
    # serving body had never executed. The probe said built. Found by a
    # review of the commit that widened it, the same day it was widened.
    wired = (_in_file("go/internal/collate/run.go", "NewHandlerWithReverse(")
             and _in_file("go/internal/collate/run.go", "reverseFor(collectors)"))
    return answers and reaches and serves and wired


def _declares(collector: str, member: str) -> bool:
    """Every collection of the named port declares the member, non-empty."""
    collections = ported_collections().get(collector, {})
    return bool(collections) and all(c.get(member) for c in collections.values())


def _declares_somewhere(collector: str, member: str) -> bool:
    """Some collection of the named port declares the member, non-empty.

    The weaker test, and the right one for the three members a collection may
    legitimately have NOTHING to put in. A PCI inventory row relates to
    nothing and is judged by no rule; a platform row is the machine itself.
    Under the all-collections test those three would have to grow an invented
    relation or an unfirable rule to satisfy a probe, which is the probe
    driving the port rather than reading it.

    What it cannot see, stated where it is defined: a collection that SHOULD
    declare the member and does not is indistinguishable here from one that
    has none to declare. That distinction is the fleet audit, which is these
    rows' own R3d half.
    """
    collections = ported_collections().get(collector, {})
    return any(c.get(member) for c in collections.values())


REGISTER: tuple[Row, ...] = (
    Row(1, "`object` verb — object density behind the row facts",
        "built", "R3c/R3d", lambda: _verb_landed("object"),
        "the probe reads the request dispatch of every collector main and "
        "flips on the FIRST landing (units, R3c); it sees the verb exist "
        "somewhere, not everywhere, and not that its answer is dense. The "
        "per-collector rollout landed fleet-wide at R3d — all twenty mains "
        "dispatch both verbs — but this probe still cannot tell twenty from "
        "one, and each collector's own verbs tests are what pin its answers. "
        "**Corrected 2026-08-23:** this row read built from R3c until an audit found the verbs were answerable by every collector and reachable by NOTHING — the wire client offered Declare and Collect and no third method, and the collator published no route, so the only way to invoke one was a person piping a request into a collector binary by hand. The probe greped the collector leaf for a responsibility DESIGN 06 places at the collator, which is row 17's defect in three more rows. The reverse channel now exists — a CLOSED list of three verbs, refused before a socket is dialled and recorded when refused, admitted only for collections the collator's own store lists — and the probe asks all three tiers, so a verb answered everywhere and reachable nowhere is no longer built."),
    Row(2, "`evidence` verb — capture-fresh raw document and digest",
        "built", "R3c/R3d", lambda: _verb_landed("evidence"),
        "same probe shape and same limits as row 1. "
        "**Corrected 2026-08-23:** this row read built from R3c until an audit found the verbs were answerable by every collector and reachable by NOTHING — the wire client offered Declare and Collect and no third method, and the collator published no route, so the only way to invoke one was a person piping a request into a collector binary by hand. The probe greped the collector leaf for a responsibility DESIGN 06 places at the collator, which is row 17's defect in three more rows. The reverse channel now exists — a CLOSED list of three verbs, refused before a socket is dialled and recorded when refused, admitted only for collections the collator's own store lists — and the probe asks all three tiers, so a verb answered everywhere and reachable nowhere is no longer built."),
    Row(3, "`lookup` verb — parametrised queries, the lookup palette",
        "built", "R3d", lambda: _verb_landed("lookup"),
        "same probe shape and same limits as row 1: it flipped when storage "
        "and network landed their palettes (snapshots-of; route-get and "
        "resolve, R3d) and sees the dispatch exist, not that a palette "
        "answers well — and no probe reads the declaration-root `lookups` "
        "member, so a collector serving the verb with no palette declared "
        "is invisible to this row. "
        "**Corrected 2026-08-23:** this row read built from R3c until an audit found the verbs were answerable by every collector and reachable by NOTHING — the wire client offered Declare and Collect and no third method, and the collator published no route, so the only way to invoke one was a person piping a request into a collector binary by hand. The probe greped the collector leaf for a responsibility DESIGN 06 places at the collator, which is row 17's defect in three more rows. The reverse channel now exists — a CLOSED list of three verbs, refused before a socket is dialled and recorded when refused, admitted only for collections the collator's own store lists — and the probe asks all three tiers, so a verb answered everywhere and reachable nowhere is no longer built."),
    Row(4, "object `type` on the wire",
        "built", "R1", lambda: _in_file("contract/se.stream.1.json", '"type"'),
        "the probe sees the contract member; that every heterogeneous "
        "collection emits it is the live comparator's to show."),
    Row(5, "applied order preserved; trees derived from relations",
        "built", "R1",
        lambda: _in_file("go/internal/store/store.go", "ORDER BY scope, seq"),
        "the probe sees the store's ordering clause; end-to-end preservation "
        "is asserted by the store and REST tests, order parity by the live "
        "comparator's order check."),
    Row(6, "name families on `units`/`hardware` (fleet-wide audit follows)",
        "built", "R3c/R3d",
        lambda: _declares_somewhere("hardware", "names"),
        "carried by hardware alone, and that is the answer rather than half "
        "an answer: a systemd unit HAS one native name, so units publishes no "
        "family and never will, where a disk is reachable by wwid, by-id "
        "spelling, serial and kernel path and publishes all four. The probe "
        "reads the champion's declaration only. The R3d fleet audit "
        "(2026-08-23) found five collections carrying a family and three "
        "whose native names churn while the stable identity sat on the row "
        "as a fact only; all three landed the same day, on both "
        "implementations, judged equal by the corpus replay: block-devices "
        "carry their by-id and partuuid spellings (kname is enumeration "
        "order and moves across boots), arrays their md uuid (the numbering "
        "moves), and tailscale nodes their public key (the DNS label is "
        "renameable in the admin console). Presence-driven everywhere — a "
        "capture without the devlink trees or without PublicKey attaches "
        "nothing — and this probe sees none of it: the champion's "
        "declaration is still all it reads."),
    Row(7, "relations on `units`/`hardware` (fleet-wide audit follows)",
        "built", "R3c/R3d",
        lambda: (_declares_somewhere("units", "relations")
                 and _declares_somewhere("hardware", "relations")),
        "same scope and same limit as row 6, and the same reason for the "
        "weaker test: a PCI inventory row relates to nothing, so requiring "
        "every collection would make the probe drive the port. The R3d fleet "
        "audit (2026-08-23) found the undeclared-palette defect TWICE — the "
        "journal verb's member-of, then units asserting requires, wants and "
        "after with only member-of declared, on the champion itself — both "
        "fixed with their pins the day they were found; the collator rejects "
        "an undeclared type, so each was a latent rejection. The reference's "
        "opened-object edges landed the same day: docker's container edges "
        "(member-of, mounts, attached-to — its runs/in travels as member-of "
        "because the assertion model asserts outward and carries no "
        "direction), docker networks' plumbed-onto, vms' owns per host tap, "
        "and units' runs from a machine scope to its domain, unescaped. "
        "Still owed, each awaiting the facts it would cite: vms' bridge and "
        "PCI edges. kea's lease-to-reservation edge stays deliberately "
        "unported (the collect.go ruling: it belongs to a collection nothing "
        "there serves)."),
    Row(8, "rule tables fleet-wide (restart-churn, SMART verdicts, link-rate…)",
        "built", "R3c/R3d",
        lambda: (_declares_somewhere("units", "rules")
                 and _declares_somewhere("hardware", "rules")),
        "the first table landed with system/time at R3b, so 'any table "
        "exists' stopped discriminating; the probe reads the champions, whose "
        "named rules — restart-churn, the SMART verdicts, the link-rate "
        "opinion — are this row's own examples and are all three declared. "
        "The fleet rollout landed at R3d — every reference evaluator whose "
        "conditions the closed vocabulary can express is a declared table, "
        "fired in its collector's rules_test.go — with the inexpressible "
        "residue stated where each table is tested. docker's went the "
        "champions' derived-fact route on 2026-08-23: Health and ExitCode "
        "are minted on both implementations from the list endpoint (the "
        "substring parses the evaluator used are now facts a rule can "
        "name), leaving only OOMKilled, which has no list-endpoint carrier "
        "at all. downloader-disk, paperless-storage and nix's "
        "deployment-not-verified followed the same day — DiskUsedPercent, "
        "StorageUsedPercent and DeploymentOutcome minted on both "
        "implementations, their bands and rule fired. The last two landed "
        "2026-08-23 and are NOT mints: resources' slice rules (a per-fact "
        "explained-by map) and protection's target rules (set algebra over "
        "hop lists) are the fifth §17 predicted would need real code, so "
        "their derivation stays in code and their declaration carries the "
        "opinion with a named evaluator in place of a condition — the row "
        "is declared, only the test is not data. Six evaluators, not the "
        "two the estimate said: the estimate counted rule FAMILIES, and "
        "the slice states three things while protection's three are the "
        "branches of one if/elif/else, each carrying its own exclusion "
        "because rules evaluate independently. The price is stated where "
        "it bites: a plugin can express the four fifths and not these. "
        "Nine plants proven to bite, in both directions — a declaration "
        "naming an evaluator that does not exist, and an evaluator no "
        "declaration names. What no "
        "probe here shows is PARITY: "
        "that the declared tables reach the same judgement as the reference's "
        "evaluators on the same facts. The firing cases are written from "
        "agent/rules/*.py, which is a correspondence no machine checks — the "
        "owner's to judge at acceptance."),
    Row(9, "the unported collections (network, storage, system, plex)",
        "built", "R3b/R3d", lambda: not NOT_YET_PORTED,
        "the probe is the register's own owed list emptying, which it did on "
        "2026-08-23 when plex/requests — the last of the six R3d owed — "
        "landed; that each entry matched reality on the way was the "
        "completeness tests' both-directions check, and the drills that used "
        "owed names as their seats moved to permanent ones as the list "
        "drained."),
    Row(10, "`/v1/status` roll-up (worst per collection, attention counts)",
        "built", "R3a",
        lambda: _in_file("go/internal/collate/rest.go", "/v1/status"),
        "the probe sees the route string in the collator's REST surface; "
        "the judged/unjudged split and the roll-up arithmetic are asserted "
        "by go/internal/collate/status_test.go."),
    Row(11, "fact filters with the 422 near-miss refusal",
        "built", "R3a",
        lambda: _in_file("go/internal/collate/query.go", "checkNearMiss"),
        "the probe sees the refusal exist; its behaviour — the fold rule, "
        "the open-vocabulary empty page, the secret-fact non-oracle — is "
        "asserted by go/internal/collate/query_test.go."),
    Row(12, "pagination — limit/cursor, declared ceilings honoured on reads",
        "built", "R3a",
        lambda: _in_file("go/internal/collate/rest.go", "cursor"),
        "the probe sees the parameter reach the route; the ceiling clamp "
        "and the explicit cursor are asserted by "
        "go/internal/collate/query_test.go."),
    Row(13, "`/v1/capabilities` serving `object_prefixes` (id→route)",
        "built", "R3a",
        lambda: _in_file("go/internal/collate/dictionary.go", "object_prefixes"),
        "the probe sees the member served; the narrowing and the contended-"
        "prefix refusal are asserted by "
        "go/internal/collate/dictionary_test.go."),
    Row(14, "fact dictionary route + MCP tool",
        "built", "R3a",
        lambda: _in_file("go/internal/collate/rest.go", "/v1/facts"),
        "the probe sees the collator route; the MCP tool derives from the "
        "published route table (tools are per route), and verbatim serving "
        "is asserted by go/internal/collate/dictionary_test.go."),
    Row(15, "host-header allowlist on the read listeners",
        "built", "R3a",
        lambda: (_in_file("go/internal/collate/hostguard.go", "HostGuard")
                 and _in_file("src/system_explorer/hub/http.py", "_host_allowed")),
        "the probe sees the guard exist at BOTH listeners; the refusal and "
        "the always-safe forms are asserted by hostguard_test.go and "
        "test_hub_surface.py. It cannot see whether a deployment sets "
        "SE_ALLOWED_HOSTS — that is the R5 module's to wire."),
    Row(16, "cost served on the read surface (the cost chip's data)",
        "built", "R3a",
        lambda: _in_file("go/internal/collate/rest.go", "advisory_cost_cpu_ms"),
        "the probe sees the labelled member served; that the commit's "
        "account survives to it end-to-end is asserted by the collate and "
        "REST tests. The collator's own slice accounting — the authoritative "
        "figure DESIGN 19 names — is R5's resource measurement, not this."),
    Row(17, "change tracking — history, `/v1/changes`, `what_changed`",
        "built", "R3e",
        lambda: (_in_file("go/internal/store/record.go", "snapshots")
                 and _in_file("go/internal/collate/changes.go", "MeasureFacts")
                 and _in_file("go/internal/collate/rest.go", "what_changed")),
        "the probe reads the COLLATOR, and that is the correction this row "
        "needed: it probed the hub until 2026-08-23, encoding an assumption "
        "the design contradicts — §06 gives the record to the collator, "
        "because that is the tier that already holds both samples. Flipped "
        "the same day. Three pieces, because any one alone is a store "
        "nothing reads, a differ with no record, or a route with neither. "
        "The measures are excluded by DECLARATION, not by a list: a fact "
        "whose declared temperament is counter or gauge never reaches the "
        "diff OR the snapshot, so a plugin's counter is excluded the day it "
        "arrives and there is no table here to fall out of step with one — "
        "which the reference could not do, having no declared temperament "
        "to read. A snapshot is written only when the diffable content "
        "moved, so a host whose counters advance every sweep stores one row "
        "rather than one per sweep. A question reaching before the record "
        "begins is a stated gap: an unreachable baseline is not an empty "
        "one, and diffing against nothing would report every object as "
        "added. Seven plants proven to bite. What the probe cannot see: the "
        "absent list is NOT diffed — store.ObjectRow serves no reader for "
        "that column — so a fact moving between value and absent is "
        "invisible, which is stated in changes.go where the type is "
        "defined; and no scheduler calls PruneSnapshots yet, so retention "
        "is a function nothing invokes."),
    Row(18, "findings persistence (a registry that survives restart)",
        "built", "R3e",
        lambda: any(_in_file(f"src/system_explorer/hub/{m}.py", "sqlite3")
                    for m in ("checkpoint", "session", "rollup", "resolution",
                              "lifecycle", "intent", "answer")),
        "the probe greps the rewrite hub's own modules for a store; the OLD "
        "hub's findings.db is a different product and deliberately out of "
        "scope. Flipped 2026-08-23: lifecycle.Registry persists its open "
        "set — first_seen, contributors, blind — and the restart case is "
        "proven end to end: the reopened registry's first fold sees an "
        "unswept estate and freezes rather than resolves, which is the "
        "founding failure the persistence exists to prevent. What the probe "
        "cannot see: transitions and acknowledgement are NOT here — they "
        "arrive with row 19's posture ruling — and no daemon wires the "
        "store path yet, which is deployment's."),
    Row(19, "acknowledgement — appended/attributed/reversible, write posture",
        "built", "R3e",
        lambda: (_in_file("src/system_explorer/hub/writes.py", "TRANSITIONS_PATH")
                 and _in_file("src/system_explorer/hub/transitions.py", "UNACKNOWLEDGE")
                 and _in_file("src/system_explorer/hub/routes.py",
                              "/v1/acknowledgements")),
        "the probe sees all three pieces the ruling needs — the write "
        "listener's one path, the reversing transition, and the READ route "
        "that serves the state — because any one alone would be a write "
        "plane with no reader, a log with no door, or a door with no log. "
        "Flipped 2026-08-23 on the posture ruled the same day. The store is "
        "append-only: INSERT and nothing else, so a finding's whole "
        "acknowledgement history survives and the current state is FOLDED "
        "rather than stored — the log and the state cannot disagree because "
        "only one of them exists. The actor is established at the listener "
        "from a credential file and a body that supplies one is refused "
        "rather than overridden, since a self-declared actor is a claim and "
        "the two would be indistinguishable once stored. The write listener "
        "binds separately and refuses reads, symmetric to the read "
        "surface\'s refusal of writes, so the read bind\'s read-only "
        "licence survives literally. Seven plants proven to bite on "
        "2026-08-23, one of which changed a TEST rather than the code: the "
        "same-second ordering case stayed green under `ORDER BY at`, so it "
        "was asserting a property it never tested and was rewritten to the "
        "case that discriminates — a later append carrying an earlier "
        "stamp. What the probe cannot see: no daemon binds the second "
        "listener yet, and resolution stays observed — `resolve` is not a "
        "transition this log accepts, so nothing here can declare a system "
        "state."),
    Row(20, "views route (`se.views/1` was ruled 'survives unchanged')",
        "built", "R3e",
        lambda: (_in_file("src/system_explorer/hub/routes.py", "/v1/views")
                 and _in_file("go/internal/collate/views.go", "/v1/views")
                 # WIRED, not merely defined: the first version of this
                 # probe read views.go alone, so a route defined and never
                 # registered would have passed it. Found by planting the
                 # removal of registerViews and watching the probe stay
                 # green, 2026-08-23.
                 and _in_file("go/internal/collate/rest.go", "registerViews(mux)")),
        "the probe sees the hub route by name. Flipped 2026-08-23: the "
        "rewrite hub serves /v1/views through the SAME shared loader the "
        "old hub and the MCP surface read (one loader, three servers), "
        "fresh from the deployed directory per request, with the tool "
        "generated from the route table like every other. The probe cannot "
        "see is that the documents validate. **Corrected 2026-08-23:** this row "
        "read built while the collator served no views at all, because the "
        "probe read only the hub's routes file — the same one-tier probe "
        "defect as rows 1, 2, 3 and 17, and DESIGN's §1892 ruling says "
        "se.views/1 is \'served by both tiers like every other "
        "projection\'. A view surface only the hub serves is one that "
        "disappears exactly when the hub does, against the founding "
        "invariant that a host with no hub keeps its own surface in full. "
        "The collator now serves it, and because the two toolchains cannot "
        "read each other\'s tree that is a SECOND implementation of one "
        "truth — handled as tokens.css is, with a conformance test driving "
        "both over one corpus and requiring identical verdicts, and "
        "views.py right where they differ."),
    Row(21, "sibling reads wired to the hub surface (one hop, serving)",
        "built", "R3e",
        lambda: _in_file("src/system_explorer/hub/routes.py", "/v1/sites/"),
        "the probe sees the route R3e designed, which it could not guess "
        "before the design existed — an unprobed owed row, so no drill "
        "forced this flip; the tests are the forcing instead. Flipped "
        "2026-08-23: /v1/sites/{site} asks the sibling LIVE per request "
        "through the peer session — never from a store, because "
        "replicating observations between hubs stays forbidden — with "
        "both ages visible: age_at_origin_s per host, the sibling's own "
        "measurement built on the new told_at stamp and None where "
        "nothing stamped an arrival, and the asked/answered moments only "
        "this hub can stamp. The answer is rendered by the same functions "
        "the local surface uses, so the two spellings cannot drift, and a "
        "mismatched sibling surfaces its refusal naming both values "
        "rather than a 500. What the probe cannot see: no daemon holds a "
        "long-lived dialled session yet — surface_reader takes a connect "
        "callable, and wiring it to a real socket pair per deployment is "
        "R5's."),
    Row(22, "NixOS module consumes declared `authority` into sandboxing",
        "owed", "R5",
        lambda: _in_file("nix/skeleton-module.nix", "declaration.json"),
        "the probe sees whether the skeleton module reads the declarations "
        "at all — today its sandbox is a common hardening block, not "
        "authority-derived; whether the generated sandbox holds is the "
        "deployment gate's."),
    Row(23, "root SMART snapshot arrangement (grantDiskAccess)",
        "owed", "R5", None,
        "no probe: the arrangement is deployment posture on estate hosts, "
        "and nothing in this tree can attest it without over-claiming."),
    Row(24, "resource measurement — the stated objective of the rewrite",
        "owed", "R5, in the gate",
        lambda: bool(list((REPO / "docs" / "history").glob("*resource*"))),
        "the probe accepts any dated resource record under docs/history; "
        "whether the numbers answer the objective is the gate's judgement."),
    Row(25, "§27/§28 surface + hide-group invariants carried from app.js",
        "owed", "R4", None,
        "no probe: whether a page implements its specification is the "
        "owner's judgement at gate R4, and a grep for it would be the "
        "subset-guard shape wearing a test's clothes."),
    Row(26, "`answer`-list divergences each an explicit ruling",
        "built", "R2",
        lambda: (set(answer_divergences()) <= set(ANSWER_RULINGS)
                 and bool(ANSWER_RULINGS)),
        "the probe recomputes the divergence set from app.js and the "
        "declarations and requires every entry ruled; the staleness "
        "direction is the conformance test's."),
    Row(27, "`system/identity` compared (gate 3's claim was false)",
        "owed", "the owner — an adjudication, §20",
        # NO PROBE, and its absence is the finding.
        #
        # This probed `"identity" in comparator_work()["system"]["compare"]`
        # — the WORK LIST — and read "built" through two waves while the
        # comparison it names had never been executed once. When it was
        # finally run, on 2026-08-23, it failed. Whether a live comparison
        # is CLEAN is not a fact any file in this tree holds, and a probe
        # over the list of things to compare is exactly the shape that
        # made "compared" mean "listed for comparison".
        None,
        "the probe sees the work list drive it. **The first live run "
        "happened on 2026-08-23 and it was NOT clean**, which is what this "
        "row had never established: `system/identity` and the reference's "
        "identity share ZERO fact names. The reference reads hostname1 over "
        "D-Bus and emits Architecture, Chassis, HardwareModel, "
        "HardwareVendor, KernelName, KernelRelease, MachineID, "
        "OperatingSystemPrettyName, StaticHostname and Virtualization; the "
        "port folds os-release and the kernel hostname into Hostname, OsId, "
        "OsPrettyName and OsVersionId. Not one name is on both sides, so "
        "MachineID, Virtualization, HardwareVendor and Chassis — the facts "
        "that answer what this machine IS — are absent from the port. The "
        "collector's own source stated the deviation, but stated it as an "
        "EVIDENCE decision about which document to show, where it was a "
        "scope decision about which facts exist. **Ruled an omission and "
        "restored the same day**, on the evidence: the collector already "
        "declared busctl authority and already called systemd1, so one of "
        "the two GetAlls was being made; and no ADR, queue entry or "
        "declaration member recorded a narrowing, where a real scope cut "
        "here looks like system/self — ruled out in writing and named in "
        "the comparator's own exclusions. identity now carries fourteen "
        "facts, captured from both lab guests rather than crafted, each "
        "variant taking the reply from the OS its own os-release names. "
        "**What remains, and is the owner's:** the port emits Hostname, "
        "OsId, OsPrettyName and OsVersionId, which the reference does not "
        "— the port emitting MORE, which §20 reserves for the owner and "
        "which the comparator can only express in the other direction. "
        "The whole-surface run now reads 19 of 20 at parity with nothing "
        "unreachable, against six unreachable and three differing on the "
        "first run. The replay-seam half stays named in NO_REPLAY_SEAM and "
        "is row 28's."),
    Row(28, "the system adapter's replay seam — four collections with no "
        "reference-vs-port venue in CI",
        "owed", "R5",
        lambda: _in_file("harness/bin/se-reference-collector", '"system": {'),
        "OWNS-SEAM:system — the probe asks whether se-reference-collector "
        "stages the system adapter at all. Added 2026-08-23 by an audit, because this work "
        "had no row: NO_REPLAY_SEAM is a second list the 27-row census "
        "never reached, so 'the register shows no unowned row' was true of "
        "the register and false of the estate. The system adapter reads "
        "through nx.read and a handful of direct Path reads, so the seam is "
        "the path-acquisition shape storage already uses — but the captures "
        "have to come from a live Linux host, which is why it is R5's "
        "rather than a corpus run's. What the probe cannot see: whether the "
        "staged set matches what the register compares, which "
        "test_the_replay_seam_stages_what_the_register_compares asserts "
        "once a seam exists."),
    Row(29, "the findings surface — `get_findings` has no port tool at "
        "either tier",
        "owed", "R4",
        lambda: (_in_file("src/system_explorer/hub/routes.py", "/v1/findings")
                 or _in_file("go/internal/collate/rest.go", '"get_findings"')),
        "the probe asks whether either tier publishes it. Added 2026-08-23 "
        "by an audit that derived the reference's MCP tool set and held the "
        "port to it — the dimension the register's own hand-transcribed row "
        "set never covered, which is PLAN rule 7 obeyed for collections and "
        "not for the surface. The port serves `get_opinions` and "
        "`get_acknowledgements` and neither is findings: a finding is an "
        "opinion at warn or above WITH A LIFECYCLE, which is the registry's, "
        "and no route serves the registry's open set. So the lifecycle "
        "landed at R3e and its surface did not, and the one question the "
        "reference's attention surface answers — what needs attention, and "
        "how long it has been true — has no tool. Held to R4 because it is "
        "a page as much as a route. What the probe cannot see: whether the "
        "surface carries the reset marker post-cut findings must display, "
        "which is acceptance item 12's."),
)
