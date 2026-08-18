"""Loading and validating corpus variants.

A variant is a pair — the native payloads a collector read, and the stream it
emitted from them (corpus/README.md). This module is the only thing that knows
the on-disk layout, so the replay driver, the capture tool and the tests all
agree about what a variant is without three copies of the shape.

Validation here is deliberately strict about the things that make a corpus
worth having: a variant that declares no payloads, or whose expected stream is
empty, is rejected rather than replayed, because a pair proving nothing is the
subset-guard shape wearing a test's clothes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
CORPUS = REPO / "corpus"
CONTRACT = REPO / "contract"

# os_version is required because coverage() reads it unconditionally — the
# version dimension is the one interface drift actually lives on, and a meta
# that omits it used to load fine and then KeyError in the coverage report.
# anchors are required because a variant with no hand-asserted truth proves
# determinism only, never correctness — DESIGN 20's second trap.
REQUIRED_META = (
    "collector",
    "variant",
    "os",
    "os_version",
    "source_version",
    "regenerable",
    "anchors",
)

# The closed set of variant kinds. A set that is consulted, unlike the tuple
# it replaces, which sat here asserting nothing while any spelling loaded: a
# new kind of variant is a decision about what the corpus covers, so it is
# added here, not minted ad hoc in a meta.json.
#
# The three ruleset kinds were added together, in one decision, when the lab
# staged the shapes a chain-reachability walk gets wrong. Each names the
# structure that makes it a distinct kind of coverage rather than another
# healthy ruleset, and each was a live defect in some collector:
#   goto        — a chain reached only by `goto`. A walk that counts `jump`
#                 alone reports it unreachable, and unreachable is the one
#                 answer here somebody acts on.
#   asymmetric  — one chain name in two families, jumped to in one of them.
#                 A walk keyed on the name alone answers for both at once.
#   named-map   — a chain reached only through `vmap @name`, whose verdicts
#                 live in the map OBJECT, in no rule's expression at all.
VALID_VARIANTS = frozenset(
    {
        "healthy",
        "degraded",
        "absent",
        "empty-ruleset",
        "canary",
        "goto",
        "asymmetric",
        "named-map",
    }
)

# The anchor forms of DESIGN 20, as exact key sets — exact, because an anchor
# with a misspelt or extra key would otherwise be silently reshaped into
# whichever form its surviving keys resemble. The count form has two
# spellings: a committed size, or a decline with a stated reason.
#
# The relation form asserts one directed edge and what discriminates it. A
# variant staging a spare, a jump or a mount is staging an EDGE, and until
# this form existed the only anchorable half of that truth was a fact on a
# row — so "the pool is backed by this device twice, once inside spare-3 and
# once under spares" was a thing the corpus could regenerate and nobody could
# assert. `assertion_facts` is the whole fact dict, not a subset, so an
# anchor cannot pass by naming the discriminator and ignoring a wrong value
# beside it; {} asserts a type that carries none.
_ANCHOR_FORMS = (
    frozenset({"collection", "object", "fact", "value"}),
    frozenset({"collection", "object", "absent_fact"}),
    frozenset({"collection", "commit_objects"}),
    frozenset({"collection", "decline_reason"}),
    frozenset({"collection", "object", "relation", "target", "assertion_facts"}),
)


# Wrongness the corpus and the differential guard together cannot see, named
# rather than left to imply absence (DESIGN 20: "the product names its net… it
# never implies absence of holes"). Each entry is a collector defect that no
# committed capture makes false and no mutation operator mints — so its truth
# is owned by the venue named, not by the replay tier. These are the *unclaimed*
# gaps: a gap inside a class an operator declares it closes (an nftables family,
# a ZFS vdev group) is a guard defect and is closed by construction in
# differential.py, not parked here.
#
# A venue that does not exist yet is stated as owed, not as owned. Naming the
# net is worth nothing if the net is a promise, and for a while this list had
# one unbuilt tool holding up five separate deferrals — "Venue: the live
# comparator" reads to any reader as "there is a place this gets caught".
#
# The comparator was built on 2026-08-18 (harness/bin/se-compare) and run
# beside a real degraded pool, so the entries below now say what is true of a
# tool that exists. An entry whose venue is still unbuilt keeps saying so.
NAMED_RESIDUALS = {
    # Kept, and narrowed, rather than deleted. The comparator now exercises
    # this join on every run — a five-wide raidz1 on virtio disks resolved
    # every by-id member to its kernel name, and the REMOVED member resolved
    # to nothing, which is the honest answer and the other half of the shape.
    # What replay still cannot do is judge it: no committed pool carries real
    # disks with an alias tree and no operator mints one, so the corpus would
    # pass a port that had lost the join entirely. The truth is now OWNED, by
    # a venue that runs; it is simply owned somewhere other than here.
    "storage/device-resolution": (
        "the by-id-path → kernel-name join (Device fact, names.ephemeral.kernel) "
        "fires only for a disk leaf whose path is in a readable devlinks tree; no "
        "committed pool carries real disks with an alias tree, and no operator "
        "mints one. Venue: the live comparator (harness/bin/se-compare), which "
        "exists and is run beside a real pool — so this truth is owned, and "
        "owned OUTSIDE the replay tier rather than owed."
    ),
    # Closed 2026-08-18 by corpus/network/rules, the first committed pair to
    # open two collections: "network/nft-rules — served by the reference but
    # captured by no committed variant". What replaces it is narrower and
    # true, and it is a shape rather than a collection.
    "network/nft-rules-opaque": (
        "every rule in every committed ruleset renders full or partial; no "
        "capture stages an `xt` statement or a bare-string statement, so the "
        "opaque comprehension path and both OpaqueReason spellings are "
        "exercised by no replayed stream, and no mutation operator mints one. "
        "Venue: a capture from a host running iptables-nft compatibility "
        "(Docker, libvirt); the live comparator now exists and would surface a "
        "disagreement on such a host, but no lab guest runs that compatibility "
        "layer yet — so the tool is real and the SHAPE is still unvisited, and "
        "this truth stays owed."
    ),
}


class CorpusError(Exception):
    """A corpus entry that cannot be trusted to prove anything."""


def typed_equal(a: object, b: object) -> bool:
    """Recursive equality under a typed reader's eyes.

    Python's == thinks True == 1 and 20 == 20.0. A consumer in a typed
    language does not, so a corpus judged with == would pass a port that
    turned a bool into an int or an int into a float — a wrong value on the
    wire that no diff would ever show. bool is tested before anything else
    because bool IS int to isinstance, and applied recursively because the
    values that drift live inside facts dicts and name lists, not at the top.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(typed_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(
            typed_equal(x, y) for x, y in zip(a, b, strict=True)
        )
    if type(a) is not type(b):
        return False
    return a == b


@dataclass(frozen=True)
class Variant:
    """One collect invocation, captured."""

    path: Path
    meta: dict
    payloads: dict[str, object]
    expected: list[dict]

    @property
    def name(self) -> str:
        # the directory, not the declared variant: two variants may share a
        # variant name across OSes, and an id has to locate the one that failed
        return f"{self.meta['collector']}/{self.path.name}"

    @property
    def canaries(self) -> list[str]:
        return list(self.meta.get("canaries", []))

    @property
    def regenerable(self) -> bool:
        return bool(self.meta["regenerable"])

    def collections(self) -> set[str]:
        return {
            record["collection"] for record in self.expected if "collection" in record
        }


def _read_stream(path: Path) -> list[dict]:
    """Decode a stream file.

    Records may be pretty-printed across lines — the wire is one object per
    line, but a corpus file is read by people, so decode by object rather than
    by line and let both shapes work.
    """
    text = path.read_text()
    decoder = json.JSONDecoder()
    records, index = [], 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        record, index = decoder.raw_decode(text, index)
        records.append(record)
    return records


def _anchor_shape_problem(anchor: object) -> str | None:
    """Why this anchor matches none of the declared forms, or None."""
    if not isinstance(anchor, dict):
        return "an anchor is an object, not a bare value"
    keys = frozenset(anchor)
    if keys not in _ANCHOR_FORMS:
        return (
            f"keys {sorted(keys)} match no anchor form — the forms are exact "
            "key sets, so an extra or misspelt key is rejected rather than "
            "reshaped into whichever form the rest resembles"
        )
    for key in ("collection", "object", "fact", "absent_fact", "decline_reason",
                "relation"):
        if key in anchor and (not isinstance(anchor[key], str) or not anchor[key]):
            return f"{key} must be a non-empty string, not {anchor[key]!r}"
    if "target" in anchor:
        target = anchor["target"]
        if not isinstance(target, dict) or frozenset(target) != frozenset(
            {"kind", "name"}
        ):
            return (
                f"target must be exactly {{kind, name}}, not {target!r} — a "
                "target carries a name and never an id, because resolution is "
                "a property that changes (DESIGN 13)"
            )
        for key in ("kind", "name"):
            if not isinstance(target[key], str) or not target[key]:
                return f"target.{key} must be a non-empty string, not {target[key]!r}"
    if "assertion_facts" in anchor and not isinstance(anchor["assertion_facts"], dict):
        return (
            f"assertion_facts must be an object, not {anchor['assertion_facts']!r} "
            "— {} asserts a relation type that carries no facts"
        )
    if "commit_objects" in anchor and (
        isinstance(anchor["commit_objects"], bool)
        or not isinstance(anchor["commit_objects"], int)
        or anchor["commit_objects"] < 0
    ):
        return f"commit_objects must be a non-negative int, not {anchor['commit_objects']!r}"
    if "value" in anchor and anchor["value"] is None:
        return (
            "a fact value is never null (DESIGN 19), so an anchor asserting "
            "null asserts the unassertable"
        )
    return None


def load_variant(path: Path) -> Variant:
    """Load one variant directory, or say precisely why it cannot be used."""
    meta_path = path / "meta.json"
    if not meta_path.exists():
        raise CorpusError(f"{path}: no meta.json — a variant must say what it is")
    meta = json.loads(meta_path.read_text())

    missing = [key for key in REQUIRED_META if key not in meta]
    if missing:
        raise CorpusError(f"{path}: meta.json lacks {missing}")

    if meta["variant"] not in VALID_VARIANTS:
        raise CorpusError(
            f"{path}: variant {meta['variant']!r} is not one of "
            f"{sorted(VALID_VARIANTS)} — a new kind of variant is a decision "
            "about what the corpus covers, made in VALID_VARIANTS, not minted "
            "in a meta.json"
        )

    anchors = meta["anchors"]
    if not isinstance(anchors, list) or not anchors:
        raise CorpusError(
            f"{path}: anchors is {anchors!r} — every variant carries at least "
            "one truth hand-asserted at staging time, because a pair whose "
            "expected half came from the reference proves determinism, never "
            "correctness (DESIGN 20)"
        )
    for anchor in anchors:
        problem = _anchor_shape_problem(anchor)
        if problem:
            raise CorpusError(f"{path}: anchor {anchor!r}: {problem}")

    # Missing, not merely empty: git does not track empty directories, so an
    # absent-interface variant still commits a keep file under payloads/ and
    # a directory that is not there at all is a broken checkout — replaying a
    # populated variant against it would judge the collector over nothing.
    payload_dir = path / "payloads"
    if not payload_dir.is_dir():
        raise CorpusError(
            f"{path}: payloads/ directory is missing — a broken checkout is "
            "not an absent interface; even a variant with nothing to replay "
            "commits the empty directory"
        )
    # Every file under payloads/ IS a payload: the native format is the
    # payload (DESIGN 20), and for some interfaces that format is text —
    # os-release, the kernel hostname — so a loader that only spoke JSON
    # would silently drop a text capture and then reject the variant as
    # payload-less. .json parses; anything else is the raw text, keyed by
    # stem exactly as the replay seam names it. Dotfiles are git plumbing
    # (the .gitkeep that makes an absent-interface payloads/ committable),
    # never captures.
    payloads: dict[str, object] = {}
    for p in sorted(payload_dir.iterdir()):
        if not p.is_file() or p.name.startswith("."):
            continue
        if p.stem in payloads:
            raise CorpusError(
                f"{path}: two payload files share the stem {p.stem!r} — the "
                "replay seam addresses payloads by stem, so one of them "
                "would silently shadow the other"
            )
        payloads[p.stem] = (
            json.loads(p.read_text()) if p.suffix == ".json" else p.read_text()
        )
    expected_path = path / "expected.jsonl"
    if not expected_path.exists():
        raise CorpusError(f"{path}: no expected.jsonl — half a pair is not a pair")
    expected = _read_stream(expected_path)
    if not expected:
        raise CorpusError(f"{path}: expected.jsonl is empty")

    # A variant with no payloads is legitimate in exactly one case: the
    # interface was absent on the machine captured, and the expected stream
    # says so. Anything else is a variant that would replay against nothing
    # and agree with itself.
    if not payloads:
        declines = [r for r in expected if r.get("record") == "decline"]
        if not declines:
            raise CorpusError(
                f"{path}: no payloads and no decline — a variant with nothing "
                "to replay against proves nothing, and would pass vacuously"
            )
        if any(r["reason"] != "absent" for r in declines):
            raise CorpusError(
                f"{path}: a payload-less variant may only expect an absent "
                "decline; unauthorised, unavailable and unsupported all mean "
                "something was there and could not be read"
            )

    return Variant(path=path, meta=meta, payloads=payloads, expected=expected)


def validate_anchors(variant: Variant, records: list[dict]) -> list[str]:
    """Hold a stream to the variant's planted truths (DESIGN 20).

    The expected half of a pair is generated by running the reference over
    the payloads, so the two halves agreeing proves determinism and nothing
    more — wherever the reference is wrong, the corpus enshrines the wrong
    answer and fails the collector that gets it right. Anchors are written at
    staging time, the one moment ground truth is known independently of any
    implementation, which is what makes them an authority the generated half
    is not. Both halves are validated against them, so a reference that
    drifts from what was staged fails its own corpus.
    """
    problems: list[str] = []
    for anchor in variant.meta.get("anchors", []):
        collection = anchor.get("collection")
        if "relation" in anchor:
            # Every copy, and the facts compared WHOLE. A relation is keyed on
            # source, type, target name and the declared discriminator, so two
            # assertions differing only in a fact value are two edges — which
            # is exactly the engaged-spare shape — and an anchor that matched
            # on the first three would certify either of them.
            matches = [
                r
                for r in records
                if r.get("record") == "relation_assertion"
                and r.get("collection") == collection
                and r.get("name") == anchor["object"]
                and r.get("type") == anchor["relation"]
                and r.get("target") == anchor["target"]
                and typed_equal(r.get("facts", {}), anchor["assertion_facts"])
            ]
            if not matches:
                problems.append(
                    f"anchor {anchor!r}: no {anchor['relation']!r} assertion "
                    f"from {anchor['object']!r} to {anchor['target']!r} with "
                    f"those facts in {collection!r}"
                )
            continue
        if "object" in anchor:
            # every copy, not the first: a corrupted duplicate hiding behind
            # a good one is the exact shape diff() was once blind to
            matches = [
                r
                for r in records
                if r.get("record") == "object"
                and r.get("collection") == collection
                and r.get("name") == anchor["object"]
            ]
            if not matches:
                problems.append(
                    f"anchor {anchor!r}: no object named {anchor['object']!r} "
                    f"in {collection!r}"
                )
            for record in matches:
                facts = record.get("facts") or {}
                if "fact" in anchor:
                    if anchor["fact"] not in facts:
                        problems.append(
                            f"anchor {anchor!r}: {anchor['fact']!r} is not "
                            "among the object's facts"
                        )
                    elif not typed_equal(facts[anchor["fact"]], anchor["value"]):
                        problems.append(
                            f"anchor {anchor!r}: stream carries "
                            f"{facts[anchor['fact']]!r}, staging asserted "
                            f"{anchor['value']!r}"
                        )
                elif anchor["absent_fact"] in facts:
                    problems.append(
                        f"anchor {anchor!r}: {anchor['absent_fact']!r} was "
                        "asserted absent at staging, and the stream carries it"
                    )
        elif "commit_objects" in anchor:
            commits = [
                r
                for r in records
                if r.get("record") == "commit" and r.get("collection") == collection
            ]
            if not commits:
                problems.append(f"anchor {anchor!r}: no commit for {collection!r}")
            for commit in commits:
                if not typed_equal(commit.get("objects"), anchor["commit_objects"]):
                    problems.append(
                        f"anchor {anchor!r}: commit carries "
                        f"objects={commit.get('objects')!r}, staging asserted "
                        f"{anchor['commit_objects']!r}"
                    )
        else:
            declines = [
                r
                for r in records
                if r.get("record") == "decline" and r.get("collection") == collection
            ]
            if not any(d.get("reason") == anchor["decline_reason"] for d in declines):
                problems.append(
                    f"anchor {anchor!r}: no decline with reason "
                    f"{anchor['decline_reason']!r} for {collection!r}"
                )
    return problems


def all_variants(root: Path | None = None) -> list[Variant]:
    """Every variant in the corpus, in a stable order."""
    root = root or CORPUS
    if not root.exists():
        return []
    found = []
    for meta_path in sorted(root.rglob("meta.json")):
        found.append(load_variant(meta_path.parent))
    return found


def coverage(variants: list[Variant]) -> dict:
    """What the corpus covers, as a statement rather than an implication.

    The corpus must state its own coverage (DESIGN 20), so this is the shape a
    reader gets: which collectors, which variants, which interface versions,
    which entries the lab cannot re-stage — the set a drift diff misses — and
    what the re-stageable ones need in order to be re-staged at all.

    That last dimension is not a nicety. `regenerable` is a boolean and the
    truth is not: storage/degraded IS re-stageable, but only on a guest
    carrying OpenZFS >= 2.3, because `zpool status -j` does not exist before
    it — the lab's own Ubuntu 24.04 image ships 2.2.2 and can produce no
    storage payload at all. A drift run on that guest regenerates the network
    variants, silently skips the storage one and presents a clean diff over a
    partial set, which is DESIGN 20's stated failure. So a variant may
    declare `regenerable_on`, and the report carries it beside the
    unregenerable list rather than leaving it to a note nothing reads.
    """
    collectors: dict[str, set[str]] = {}
    versions: dict[str, set[str]] = {}
    opened: dict[str, set[str]] = {}
    systems: set[str] = set()
    unregenerable: list[str] = []
    requires: dict[str, str] = {}
    for variant in variants:
        collector = variant.meta["collector"]
        collectors.setdefault(collector, set()).add(variant.meta["variant"])
        versions.setdefault(collector, set()).add(variant.meta["source_version"])
        opened.setdefault(collector, set()).update(variant.collections())
        systems.add(f"{variant.meta['os']} {variant.meta['os_version']}")
        if not variant.regenerable:
            unregenerable.append(variant.name)
        elif variant.meta.get("regenerable_on"):
            requires[variant.name] = variant.meta["regenerable_on"]
    return {
        "collectors": {k: sorted(v) for k, v in sorted(collectors.items())},
        "source_versions": {k: sorted(v) for k, v in sorted(versions.items())},
        # The dimension whose absence hid a whole collection. Until this line
        # existed the report named collectors, variant kinds, operating
        # systems and interface versions — every dimension except the one a
        # collection can go missing on — so nft-rules was served by the
        # reference, captured by nothing, and visible only to a person who
        # already knew to look. A collection is what a collector is FOR, and
        # a coverage report that cannot say which ones were exercised is
        # reporting success about what it never reached.
        "collections": {k: sorted(v) for k, v in sorted(opened.items())},
        # The dimension interface drift actually lives on: a corpus on one OS
        # cannot show a field that a different distribution's build removed.
        "operating_systems": sorted(systems),
        "unregenerable": sorted(unregenerable),
        # Regenerable, but not everywhere: the guest a re-stage needs.
        "regeneration_requires": dict(sorted(requires.items())),
        # The net named, so absence of a hole is never implied (DESIGN 20). A
        # shape here is wrong-detectable by neither a committed capture nor a
        # mutation operator — it is owned by the venue named, not by this tier.
        "named_residuals": dict(sorted(NAMED_RESIDUALS.items())),
        "variants": len(variants),
    }
