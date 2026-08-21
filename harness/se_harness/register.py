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
    "network/links": "interfaces on every Linux host; the largest single hole.",
    "network/routes": "routing table; present on every host.",
    "network/listening": "listening sockets — half of 'what is exposed'.",
    "network/resolver": "resolver configuration.",
    "network/nft-tables": "the table-grained view above nft-chains.",
    "network/port-exposure": "the joined answer nft + listening produce together.",
    "network/tailscale": "a discovery source membership depends on (DESIGN 23).",
    "storage/block-devices": "block devices on every host.",
    "storage/mounts": "mount points on every host.",
    "storage/arrays": "md arrays.",
    "storage/datasets": "ZFS datasets — the level protection joins against.",
    "system/time": "clock and sync state, which §09's skew work needs.",
    "system/boot": "boot time and kernel command line.",
    "system/overview": "the per-host summary the old UI opened on.",
    "plex/requests": "seerr requests.",
}

#: Collectors the CORPUS venues cannot drive through the Python reference,
#: each with why. The live comparator is not gated by this — it drives every
#: collector below — but the replay seam stages captured payloads per
#: adapter, and one adapter has no such seam yet. An entry here is owed
#: work, never a decision.
NO_REPLAY_SEAM: dict[str, str] = {
    "system": "the system adapter reads the host's own identity files and no "
              "payload-staging seam was ever written for it; its corpus is "
              "port self-capture only. Live comparison runs since R2 "
              "(register row 27); the replay seam is owed with R3b's system "
              "collections.",
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

ANSWER_RULINGS: dict[str, str] = {
    "units/units": "ruled: additive — the reference's three columns survive "
                   "verbatim and in order, and the port appends "
                   "MissingRequirements, dependency health the old UI only "
                   "surfaced on the object page.",
    "network/nft-chains": "owed: R3d — the port dropped Family/Table/Name/"
                          "Priority/Policy; the preset's own argument (one "
                          "chain name in ip and ip6 is two chains) is "
                          "unanswered and is re-judged at the nft retrofit.",
    "network/nft-rules": "owed: R3d — Position's argument (first-match-wins, "
                         "so order is meaning) is carried by applied order "
                         "since R1; Family/Table/Chain/JumpTarget are carried "
                         "by nothing and are re-judged at the nft retrofit.",
    "resources/workloads": "ruled: additive — the reference's eight columns "
                           "survive as an ordered subsequence; the port adds "
                           "the depth, throttle and stall-attribution facts "
                           "the old UI never had.",
    "docker/containers": "owed: R3d — Status (docker's own 'Up 3 hours' "
                         "reading) was dropped and Ports added; keep-or-"
                         "replace is re-judged at the docker retrofit.",
    "docker/volumes": "owed: R3d — ComposeProject, the join the estate "
                      "actually reads, was dropped from the preset.",
    "docker/networks": "owed: R3d — Internal was dropped from the preset.",
    "storage/pools": "owed: R3d — the port answers UnhealthyVdevs where the "
                     "reference answered DeviceFailuresTolerated/ScanFunction/"
                     "Errors; no design section grounds the swap, and the "
                     "declared question still asks 'when was one last "
                     "scrubbed?' while the answer no longer carries "
                     "ScanFunction.",
    "nix/generations": "owed: R3d — Kernel/ConfigurationRevision/Changed/"
                       "Deployed/Created left the preset (the facts are still "
                       "emitted and compared; only the answer narrowed).",
    "packages/packages": "owed: R3d — Architecture and StorePath left the "
                         "preset; the facts are still emitted and compared.",
    "hardware/platform": "owed: R3c — SysVendor added, BiosVersion dropped; "
                         "re-judged with the hardware champion retrofit.",
    "hardware/scsi": "owed: R3c — the owner's named exemplar. Kind is carried "
                     "by the type member since R1; Transport/Link/Devices/"
                     "EnclosureSlot are carried by nothing and return with "
                     "the champion retrofit.",
    "hardware/nvme": "owed: R3c — Link/FirmwareRev/Serial/Namespaces dropped, "
                     "LinkBandwidthBytesPerSec/SmartPercentUsed added; Serial "
                     "is also a names-layer question and lands with the "
                     "champion retrofit.",
    "vms/domains": "owed: R3d — Autostart left the preset.",
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


# ── the 27-row gap register (PLAN, the re-baseline) ───────────────────────


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
    """Whether any collector's request dispatch answers the verb. Today the
    grammar is declare/probe/collect; the verbs land per collector at R3c/d,
    and the first landing flips this."""
    return any(f'case "{verb}":' in path.read_text()
               for path in GO_CMD.glob("se-collect-*/main.go"))


def _declares(collector: str, member: str) -> bool:
    """Every collection of the named port declares the member, non-empty."""
    collections = ported_collections().get(collector, {})
    return bool(collections) and all(c.get(member) for c in collections.values())


def _any_rules() -> bool:
    return any(c.get("rules")
               for collections in ported_collections().values()
               for c in collections.values())


REGISTER: tuple[Row, ...] = (
    Row(1, "`object` verb — object density behind the row facts",
        "owed", "R3c/R3d", lambda: _verb_landed("object"),
        "the probe reads the request dispatch of every collector main; it "
        "sees the verb exist, not that its answer is dense."),
    Row(2, "`evidence` verb — capture-fresh raw document and digest",
        "owed", "R3c/R3d", lambda: _verb_landed("evidence"),
        "same probe shape and same limit as row 1."),
    Row(3, "`lookup` verb — parametrised queries, the lookup palette",
        "owed", "R3d", lambda: _verb_landed("lookup"),
        "same probe shape and same limit as row 1."),
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
        "owed", "R3c/R3d",
        lambda: _declares("units", "names") and _declares("hardware", "names"),
        "the probe reads the two champions' declarations only; the fleet "
        "audit is the same row's R3d half and is not probed until then."),
    Row(7, "relations on `units`/`hardware` (fleet-wide audit follows)",
        "owed", "R3c/R3d",
        lambda: (_declares("units", "relations")
                 and _declares("hardware", "relations")),
        "same scope and same limit as row 6."),
    Row(8, "rule tables fleet-wide (restart-churn, SMART verdicts, link-rate…)",
        "owed", "R3c/R3d", _any_rules,
        "the probe sees whether ANY first-party declaration carries a rule "
        "table; parity of judgement against the reference's opinions is not "
        "mechanically checkable — the old rules are code — and is judged at "
        "the retrofit."),
    Row(9, "the unported collections (network, storage, system, plex)",
        "owed", "R3b/R3d", lambda: not NOT_YET_PORTED,
        "the probe is the register's own owed list emptying; that each entry "
        "matches reality is the completeness tests' both-directions check."),
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
        "owed", "R3e — owner ruling owed on §36",
        lambda: _in_file("src/system_explorer/hub/routes.py", "/v1/changes"),
        "the probe sees the hub route; the §36 migration question is the "
        "owner's and no probe can close it."),
    Row(18, "findings persistence (a registry that survives restart)",
        "owed", "R3e",
        lambda: any(_in_file(f"src/system_explorer/hub/{m}.py", "sqlite3")
                    for m in ("checkpoint", "session", "rollup", "resolution",
                              "lifecycle", "intent", "answer")),
        "the probe greps the rewrite hub's own modules for a store; the OLD "
        "hub's findings.db is a different product and deliberately out of "
        "scope."),
    Row(19, "acknowledgement — appended/attributed/reversible, write posture",
        "owed", "R3e — owner ruling owed on posture",
        lambda: _in_file("src/system_explorer/hub/routes.py", "acknowledge"),
        "the probe sees a route by name; posture — who may, over what bind — "
        "is the owner's ruling and no probe can close it."),
    Row(20, "views route (`se.views/1` was ruled 'survives unchanged')",
        "owed", "R3e",
        lambda: _in_file("src/system_explorer/hub/routes.py", "/v1/views"),
        "the probe sees the hub route by name."),
    Row(21, "sibling reads wired to the hub surface (one hop, serving)",
        "owed", "R3e", None,
        "no probe: the handshake exists and serving does not, and no grep "
        "can tell those apart without guessing the name of a route R3e has "
        "not designed — a guess that matched the wrong thing would report "
        "built about a hub that still cannot serve a sibling's rows."),
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
        "built", "R2 (live); replay seam owed R3b",
        lambda: "identity" in comparator_work()["system"]["compare"],
        "the probe sees the work list drive it; the first clean live run is "
        "gate R3's to show, and the replay-seam half stays named in "
        "NO_REPLAY_SEAM until R3b."),
)
