"""Replay: same payloads in, same records out.

The executable seam a collector in any language implements — set
``SE_REPLAY_DIR`` and the collector reads its native documents from that
directory instead of from the live interface, and does everything else
unchanged. The production parse, the declared redactions and the stream
generation all run; only the acquisition call is redirected.

That is what makes this checkable from the outside. The harness never imports
a collector, never calls a helper inside one, and never knows what language it
was written in — it runs a binary and diffs the bytes.

**What this module has to survive.** An adversarial review built a collector
wrong in five simultaneous ways — five required members missing, a fabricated
generation, every object emitted twice with the first copy corrupted — and an
earlier version of this file reported no differences. Each defect it exploited
now has a named guard below, because a judge that cannot fail is a judge that
proves nothing.

A second adversarial round then proved the first fix's own promise false: this
file claimed every member dropped from the diff was recovered structurally,
and for five of the seven it was not. The promise is now a table — RULED maps
every run-varying member to the rule that recovers it, and
test_member_regimes.py proves the table exhaustive and every named rule
reachable, so the claim fails a test rather than holding by assertion (DESIGN
19, the two-regimes law).
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import zlib
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .corpus import Variant, typed_equal

# Members that legitimately differ between two runs of the same collector over
# the same payloads: monotonic clock readings, collator-issued identifiers,
# and measured cost. Everything named here loses byte comparison, so every
# entry MUST have a rule in RULED below — a member in neither regime is a
# free-fire zone for every wrong value a port can put there, and
# test_member_regimes.py fails if one appears.
RUN_VARYING = {
    "begin": ("request", "batch", "boot_id", "generations", "declaration"),
    "object": ("at",),
    "commit": ("cpu_ms", "generation"),
    "end": ("request", "batch", "cpu_ms", "wall_ms"),
}

# The other regime, named. Each entry is the rule in check_stream() that
# recovers the member the diff cannot see, and the value is a literal
# substring of every problem message that rule emits — which is what lets
# test_member_regimes.py prove each rule reachable by feeding check_stream a
# violation and finding the string, instead of trusting this comment.
RULED = {
    ("begin", "request"): "end must echo begin",
    ("begin", "batch"): "end must echo begin",
    ("begin", "boot_id"): "boot_id must be UUID-shaped",
    ("begin", "declaration"): "the declaration digest identifies the collector's "
    "own declaration",
    ("begin", "generations"): "must equal the issued generations",
    ("object", "at"): "`at` must be a finite boot-scale reading, "
    "non-decreasing within its collection",
    ("commit", "generation"): "a commit echoes the generation begin named",
    ("commit", "cpu_ms"): "measured cost must be a finite non-negative number",
    ("end", "request"): "end must echo begin",
    ("end", "batch"): "end must echo begin",
    ("end", "cpu_ms"): "measured cost must be a finite non-negative number",
    ("end", "wall_ms"): "a batch that emitted objects must report a positive wall_ms",
}

# What /proc/sys/kernel/random/boot_id serves: 8-4-4-4-12 hex. Case-blind
# because "UUID-shaped" is the ruling (DESIGN 19), not any one platform's
# spelling of it. The blank-only rule this replaces was a subset guard — it
# enumerated missing, "" and non-string, and the nil UUID sailed past as a
# plausible constant stub.
_BOOT_ID_SHAPE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_NIL_UUID = "00000000-0000-0000-0000-000000000000"

# Distinguishes "member absent" from "member present and null". Without it,
# dict.get() returns None for both, and every required member whose expected
# value is null can simply be omitted — including `complete` on a commit,
# which the contract forbids outright.
_MISSING = object()


@dataclass
class ReplayResult:
    variant: Variant
    ok: bool
    emitted: list[dict] = field(default_factory=list)
    differences: list[str] = field(default_factory=list)
    stderr: str = ""

    def report(self) -> str:
        head = f"{self.variant.name}: {'ok' if self.ok else 'MISMATCH'}"
        if self.ok:
            return head
        shown = "\n".join(f"  - {d}" for d in self.differences[:20])
        more = (
            f"\n  … and {len(self.differences) - 20} more"
            if len(self.differences) > 20
            else ""
        )
        return f"{head}\n{shown}{more}"


def issue_generations(collections: Iterable[str], seed: str) -> dict[str, int]:
    """The generations the harness-as-collator issues for one request.

    The collator issues, the collector echoes (DESIGN 19) — so the harness
    plays the issuing side, deterministically to keep corpus pairs
    reproducible: sorted collections, collection i gets base + 17*i, with the
    base derived from `seed` (the variant's identity, in practice).

    The base VARIES BY SEED because the fixed rule this replaces was the
    subset-guard shape on the issuing side: 100 + 17*i issued the constant
    100 to every single-collection variant, so the echo guard caught every
    invented constant except the one it issued — the declared-RED
    generation_zero_always adversary, its 0 changed to 100, passed every
    channel. crc32 is not secrecy and does not need to be: the property is
    that no constant passes EVERYWHERE, so a collector must parse the
    request line rather than bake in a number that happens to match one
    variant. The range excludes 0 and 100 by construction — the two
    constants adversaries have actually shipped.

    THE RANGE IS WIDE BECAUSE DISTINCTNESS IS THE PROPERTY, and the first
    spelling of it was 103..997. 895 slots is a birthday problem: at the
    25 variants this corpus already held, the chance that some pair
    collided was better than one in three, and on 2026-08-19 a pair did —
    paperless/healthy and storage/healthy both issued 458, which is a
    constant that would have passed both. Nothing was wrong with the new
    variant; the issuance was sized for a corpus a third this size and
    would have failed again on the one after. A scheme whose guard fails
    a third of the time it is extended is the subset-guard shape wearing
    arithmetic, so the modulus is now large enough that distinctness is
    the ordinary outcome rather than the lucky one. The guard still
    ASSERTS it — a collision is caught, never assumed away — and these
    stay small enough to read as issued rather than measured.
    """
    base = 103 + zlib.crc32(seed.encode()) % 99895
    return {name: base + 17 * i for i, name in enumerate(sorted(collections))}


def normalise(records: list[dict]) -> list[dict]:
    """Drop the members that vary per run, keeping everything that is a claim."""
    out = []
    for record in records:
        copy = dict(record)
        for key in RUN_VARYING.get(copy.get("record", ""), ()):
            copy.pop(key, None)
        # The generation map's VALUES are collator-issued, but WHICH
        # collections were requested is a claim — so the keys go back in,
        # and the values are held by check_stream's issued-map rule instead.
        if copy.get("record") == "begin":
            copy["generations"] = sorted(record.get("generations") or {})
        out.append(copy)
    return out


def _key(record: dict) -> tuple:
    """A record's full identity.

    Every member that distinguishes one record from another must appear here.
    A key that omitted the relation target let three assertions to three
    different chains collapse onto one entry, so a collector emitting one of
    them — or all three pointing at the wrong place — was judged identical.

    And the fix for that was itself a subset guard: it added VdevPath, the
    one discriminator its author had met, so two same-type same-target
    assertions told apart by any OTHER fact still collapsed — and, zip-paired
    in stream order, a CORRECT collector emitting them in the other order
    failed with a false facts mismatch, against this module's own reordering
    rule. DESIGN 19 declares discriminators per relation type, so the key now
    carries the ENTIRE facts dict, canonically serialised: content-based
    identity generalises to every discriminator, declared or yet to be.
    """
    target = record.get("target") or {}
    return (
        record.get("record", ""),
        record.get("collection", ""),
        record.get("name", ""),
        record.get("fact", ""),
        record.get("type", ""),
        target.get("kind", ""),
        target.get("name", ""),
        # Assertions only: an object's identity is (collection, name) and its
        # facts are compared member-wise, so keying them here would turn
        # every wrong fact value into a missing/unexpected pair and lose the
        # named which-member report.
        json.dumps(record.get("facts", {}), sort_keys=True)
        if record.get("record") == "relation_assertion"
        else "",
    )


def diff(expected: list[dict], emitted: list[dict],
         moving: frozenset[str] = frozenset()) -> list[str]:
    """Differences between two streams, named so a reader can act on them.

    Ordering inside a stream is not significant (DESIGN 19 — the collator
    buffers a collection until it ends), so records are compared by identity
    rather than by position; a reordering is not a defect and must not read
    as one. Multiplicity IS significant: emitting one object twice is a real
    collector bug, so counts are compared, not just key sets.

    `moving` names facts whose VALUE may legitimately differ between the two
    streams, and it defaults to empty so the corpus judge is unchanged: there,
    both sides read the same frozen payload and any difference is a defect.

    It exists for the live comparator, which cannot freeze anything. That tool
    runs the reference and then the port against the same machine, and between
    the two the machine keeps running — so every advancing counter differs by
    however long that took. Before this, `resources` reported four differing
    rows on every single run and not one was a defect, which is worse than
    reporting none: a real disagreement would have arrived buried in noise
    everybody had learned to scroll past.

    A moving fact is still compared for PRESENCE and for TYPE. Only its value
    is exempt — a port that dropped the fact, or that started emitting a string
    where the reference emits an integer, still fails. And the set is built
    from the collector's own committed declaration rather than from anything
    observed at run time, so widening it is a reviewed diff.
    """
    want_records, got_records = normalise(expected), normalise(emitted)
    want_counts = Counter(_key(r) for r in want_records)
    got_counts = Counter(_key(r) for r in got_records)

    # Last-writer-wins would hide a corrupted duplicate, so keep them all.
    want: dict[tuple, list[dict]] = {}
    got: dict[tuple, list[dict]] = {}
    for record in want_records:
        want.setdefault(_key(record), []).append(record)
    for record in got_records:
        got.setdefault(_key(record), []).append(record)

    differences: list[str] = []
    for key in sorted(want.keys() - got.keys()):
        differences.append(f"missing: {key}")
    for key in sorted(got.keys() - want.keys()):
        differences.append(f"unexpected: {key}")

    for key in sorted(want.keys() & got.keys()):
        if want_counts[key] != got_counts[key]:
            differences.append(
                f"{key}: emitted {got_counts[key]}x, expected {want_counts[key]}x"
            )
        # strict=False deliberately: a count mismatch is already reported
        # above, and pairing what overlaps still shows WHICH copy is wrong.
        for want_record, got_record in zip(want[key], got[key], strict=False):
            for member in sorted(set(want_record) | set(got_record)):
                a = want_record.get(member, _MISSING)
                b = got_record.get(member, _MISSING)
                if a is _MISSING and b is not _MISSING:
                    differences.append(f"{key}: {member}: emitted but not expected")
                elif b is _MISSING and a is not _MISSING:
                    differences.append(f"{key}: {member}: expected but not emitted")
                # typed_equal, not ==: Python thinks True == 1 and 20 == 20.0,
                # and a port that made either swap would emit a wrong value on
                # the wire that a typed consumer sees and == never would.
                elif member == "facts" and moving:
                    differences.extend(
                        _fact_differences(key, a, b, moving))
                elif not typed_equal(a, b):
                    differences.append(f"{key}: {member}: expected {a!r}, got {b!r}")
    return differences


def _fact_differences(key: tuple, want: object, got: object,
                      moving: frozenset[str]) -> list[str]:
    """One row's facts, with declared counters and gauges exempt by VALUE only.

    Compared fact by fact rather than dict against dict, because the whole
    point is that one member may move while its neighbours may not — a
    wholesale comparison can only pass or fail the entire row, which is how a
    live counter took four correct rows down with it.
    """
    if not (isinstance(want, dict) and isinstance(got, dict)):
        return ([] if typed_equal(want, got)
                else [f"{key}: facts: expected {want!r}, got {got!r}"])
    out: list[str] = []
    for name in sorted(set(want) | set(got)):
        a = want.get(name, _MISSING)
        b = got.get(name, _MISSING)
        if a is _MISSING:
            out.append(f"{key}: facts.{name}: emitted but not expected")
        elif b is _MISSING:
            out.append(f"{key}: facts.{name}: expected but not emitted")
        elif name in moving:
            # Presence and type still hold. A counter that became a string, or
            # a gauge the port stopped emitting, is a defect whatever its value
            # was going to be.
            if type(a) is not type(b):
                out.append(
                    f"{key}: facts.{name}: declared a moving reading, so its "
                    f"value is not compared — but its TYPE changed, "
                    f"{type(a).__name__} to {type(b).__name__}"
                )
        elif not typed_equal(a, b):
            out.append(f"{key}: facts.{name}: expected {a!r}, got {b!r}")
    return out


def _measured(value: object) -> bool:
    """A cost reading that could have come off a clock: finite, non-negative."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def _null_paths(value: object, path: str) -> list[str]:
    """Every path at which a null sits inside a fact value, to any depth.

    Depth one was the subset guard again, on the judge's side: the rule
    refused `"State": null` at the top of the facts dict and passed the same
    null one level down, inside a vdev row — which is exactly where
    marshalling a struct with nil members puts it, so the wire the rule
    exists for was the wire it could not see. The schema's facts definition
    recurses identically; two independent refusals, one law (DESIGN 19).
    """
    if value is None:
        return [path]
    if isinstance(value, dict):
        return [
            p
            for key, inner in value.items()
            for p in _null_paths(inner, f"{path}/{key}")
        ]
    if isinstance(value, list):
        return [
            p
            for i, inner in enumerate(value)
            for p in _null_paths(inner, f"{path}[{i}]")
        ]
    return []


def check_stream(records: list[dict], issued: dict[str, int] | None = None) -> list[str]:
    """Structural rules of a batch, over the stream that actually arrived.

    These are the rules of RULED — the properties the byte diff cannot see
    because normalise() drops their members — plus the ones that are about
    the stream as a whole rather than about any record in it. DESIGN 19
    makes each of them load-bearing at the collator, so a collector must be
    held to them here. When `issued` is given it is the generation map the
    harness put on the request line, and begin must echo it exactly.
    """
    problems: list[str] = []
    begins = [r for r in records if r.get("record") == "begin"]
    ends = [r for r in records if r.get("record") == "end"]
    if len(begins) != 1:
        problems.append(f"expected exactly one begin record, found {len(begins)}")
    if len(ends) != 1:
        problems.append(f"expected exactly one end record, found {len(ends)}")
    if not begins:
        return problems

    begin = begins[0]

    # Shape and not-nil are the honest bound of what one capture can
    # authenticate (DESIGN 19): a boot id is SUPPOSED to vary only across
    # boots, so a constant VALID id is indistinguishable here by physics and
    # is a cross-boot variant's to catch — a named deferral, not a gap.
    boot_id = begin.get("boot_id")
    if (
        not isinstance(boot_id, str)
        or not _BOOT_ID_SHAPE.fullmatch(boot_id)
        or boot_id == _NIL_UUID
    ):
        problems.append(
            f"begin: boot_id is {boot_id!r}; boot_id must be UUID-shaped "
            "(8-4-4-4-12 hex) and never the nil UUID — `at` readings are "
            "meaningless without knowing which boot's clock they came from "
            "(DESIGN 09), and nil is the plausible stub every runtime hands "
            "out for free (DESIGN 19)"
        )

    # The declaration digest identifies the collector's OWN declaration, which
    # is why it cannot be byte-compared here. The judge's whole job is running
    # a port against an expectation another implementation generated, and two
    # correct implementations necessarily hold different declarations — so the
    # committed halves carry whatever the party that generated them published,
    # and comparing that byte-for-byte does not test a reading of the machine,
    # it tests whether the port copied somebody else's identity. It forced
    # exactly that: both ports shipped a constant matching the corpus answer,
    # each flagged it as the one value it could not derive, and each was right
    # to. Shape here, truth at the tier that can see it — the ownership law
    # again (DESIGN 19). test_contract_verification holds a ported collector's
    # digest to the bytes its own `declare` emits, which is the claim that
    # actually matters and the only tier that can make it.
    declaration = begin.get("declaration")
    if not isinstance(declaration, str) or not declaration.startswith("sha256:") \
            or len(declaration) <= len("sha256:"):
        problems.append(
            f"begin: declaration is {declaration!r}; the declaration digest "
            "identifies the collector's own declaration and travels as "
            "'sha256:<digest>' — a collator that cannot tell which contract a "
            "batch was produced under has to refetch on every collect or "
            "trust one it never saw (DESIGN 19)"
        )

    # end closes exactly the batch and request begin opened. Both values are
    # run-varying so the diff never sees them, and both must be non-empty on
    # both sides: an empty string echoing an empty string proves nothing.
    if ends:
        for member in ("request", "batch"):
            opened, closed = begin.get(member), ends[0].get(member)
            if not isinstance(opened, str) or not opened:
                problems.append(
                    f"begin: {member} is {opened!r}; end must echo begin's "
                    f"{member}, and a missing or empty one leaves nothing to echo"
                )
            if not isinstance(closed, str) or not closed:
                problems.append(
                    f"end: {member} is {closed!r}; end must echo begin — a "
                    "stream that cannot say which batch it closes is not a batch"
                )
            elif isinstance(opened, str) and opened and closed != opened:
                problems.append(
                    f"end: {member} {closed!r} does not match begin's "
                    f"{opened!r}; end must echo begin, or two interleaved "
                    "streams could close each other's batches"
                )

    generations = begin.get("generations") or {}
    if not isinstance(generations, dict) or not generations:
        problems.append("begin carries no generation map")
        return problems

    if issued is not None and not typed_equal(generations, dict(issued)):
        problems.append(
            f"begin: generations {generations!r} must equal the issued "
            f"generations {issued!r} — the collator issues and the collector "
            "echoes; one that mints its own has defeated the ordering the "
            "generation exists for (DESIGN 19)"
        )

    # Full lists, never a dict comprehension: last-writer-wins let a
    # duplicate commit hide behind the final copy — the exact shape diff()
    # was cured of once already — and a duplicate is itself a protocol
    # error, since one commit is one claim of authority over a collection.
    commits: dict[str, list[dict]] = {}
    declines: dict[str, list[dict]] = {}
    for record in records:
        if record.get("record") == "commit":
            commits.setdefault(str(record.get("collection")), []).append(record)
        elif record.get("record") == "decline":
            declines.setdefault(str(record.get("collection")), []).append(record)

    for collection, group in sorted(commits.items()):
        if len(group) > 1:
            problems.append(
                f"{collection}: {len(group)} commit records — a commit claims "
                "authority over the whole collection, and a second claim means "
                "either a retry that must be idempotent or a bug that is not"
            )
    for collection, group in sorted(declines.items()):
        if len(group) > 1:
            problems.append(
                f"{collection}: {len(group)} decline records for one "
                "collection — one reading, one verdict"
            )

    # A commit or decline for a collection the request never opened is not
    # extra coverage, it is a record the collator has no generation for.
    for collection in sorted((set(commits) | set(declines)) - set(generations)):
        problems.append(
            f"{collection}: committed or declined but never named in begin — "
            "the request line opens a collection; a record cannot"
        )

    for collection, generation in generations.items():
        if not isinstance(generation, int) or generation < 0:
            problems.append(f"{collection}: generation {generation!r} is not an index")
        if collection not in commits and collection not in declines:
            # The whole-stream radius is deliberate and differs from the
            # collator's: under a pinned corpus an incomplete emission is
            # a broken collector, where the live collator holds only the
            # offending collection and applies the rest (DESIGN 19).
            problems.append(
                f"{collection}: named in begin, neither committed nor declined "
                "— replay refuses the whole stream, where the live collator "
                "would hold only this collection and apply the rest"
            )
        for commit in commits.get(collection, []):
            echoed = commit.get("generation")
            if echoed != generation:
                problems.append(
                    f"{collection}: commit generation {echoed!r} does not "
                    f"match begin's {generation!r} — a commit echoes the "
                    "generation begin named, or the collator cannot order it"
                )

    # A decline is a statement about the whole collection, so it closes
    # the collection to every emitting record — in BOTH orders. The wire
    # judges the orders separately (decline-after-records, record-after-
    # decline); over a complete stream the bag form is the same law, and
    # the one-direction rule this replaces let records after a non-absent
    # decline vanish without a problem.
    emitted: Counter[str] = Counter(
        str(r.get("collection"))
        for r in records
        if r.get("record") in ("object", "relation_assertion", "unobservable")
    )
    for collection, group in sorted(declines.items()):
        if emitted[collection]:
            problems.append(
                f"{collection}: {emitted[collection]} record(s) emitted for a "
                "declined collection — a decline closes its collection to "
                "everything except absent's zero commit (DESIGN 19)"
            )
        for decline in group:
            if decline.get("reason") == "absent":
                closing = commits.get(collection, [])
                if not closing or any(
                    c.get(member) != 0
                    for c in closing
                    for member in ("objects", "assertions", "unobservable")
                ):
                    problems.append(
                        f"{collection}: an absent decline is authoritative-empty "
                        "and must commit zero objects (and zero assertions and "
                        "unobservables — there is nothing to count)"
                    )
            elif collection in commits:
                problems.append(
                    f"{collection}: a {decline.get('reason')!r} decline must not "
                    "commit — nothing was established, so prior state stands"
                )

    # A commit's self-declared counts describe the stream it closes, so they
    # are checkable against it. All three are required, always — a subject
    # that can disable the check by omitting the count has defeated it
    # (DESIGN 19), which is why absence is a problem and never a skip.
    for collection, group in sorted(commits.items()):
        for commit in group:
            for member, kind in (
                ("objects", "object"),
                ("assertions", "relation_assertion"),
                ("unobservable", "unobservable"),
            ):
                if member not in commit:
                    problems.append(
                        f"{collection}: commit lacks {member} — all three "
                        "counts are required members, zero when zero, because "
                        "an omitted count is a truncation check switched off"
                    )
                    continue
                actual = sum(
                    1
                    for r in records
                    if r.get("record") == kind and r.get("collection") == collection
                )
                if not typed_equal(commit[member], actual):
                    problems.append(
                        f"{collection}: commit says {member}={commit[member]!r}, "
                        f"stream carries {actual}"
                    )
            cpu = commit.get("cpu_ms", _MISSING)
            if cpu is not _MISSING and not _measured(cpu):
                problems.append(
                    f"{collection}: commit cpu_ms is {cpu!r}; measured cost "
                    "must be a finite non-negative number"
                )

    last_at: dict[str, float] = {}
    for record in records:
        kind = record.get("record")
        if kind not in ("object", "relation_assertion"):
            continue
        where = f"{record.get('collection')}/{record.get('name')}"
        if kind == "object":
            at = record.get("at", _MISSING)
            # Bounded above as well as below: a boot-scale monotonic reading
            # is small, and epoch seconds (~1.7e9), epoch millis, NaN, Inf
            # and the 0.0 placeholder are all real stamps a wrong port has
            # produced.
            if (
                at is _MISSING
                or isinstance(at, bool)
                or not isinstance(at, (int, float))
                or not math.isfinite(at)
                or not 0 < at <= 1e9
            ):
                problems.append(
                    f"{where}: `at` is {at!r}; `at` must be a finite "
                    "boot-scale reading, non-decreasing within its collection "
                    "— 0 < at <= 1e9 (inclusive, as the contract's maximum "
                    "is), monotonic seconds, stamped before the earliest "
                    "contributing read (DESIGN 09)"
                )
            else:
                # The structural part of the third replay bound (DESIGN 19):
                # within one collection, emission order is acquisition order
                # and a clock cannot run backwards inside one acquisition
                # pass. Only this much is judged here — a pinned clock cannot
                # authenticate a reading's truth, which the live comparator
                # owns. Non-decreasing, not strictly increasing: two reads
                # inside one clock tick are legitimate. Per collection, not
                # per stream: a collector reading two interfaces has two ages
                # and may interleave them.
                collection = str(record.get("collection"))
                previous = last_at.get(collection)
                if previous is not None and at < previous:
                    problems.append(
                        f"{where}: `at` {at!r} precedes the {previous!r} "
                        "emitted before it; `at` must be a finite boot-scale "
                        "reading, non-decreasing within its collection — a "
                        "clock cannot run backwards inside one acquisition "
                        "pass (DESIGN 19)"
                    )
                last_at[collection] = at
        # Both fact-bearing record types, recursively: a relation's facts
        # carry its discriminators, and a null there un-names an assertion
        # as surely as a null on an object row un-states a fact.
        facts = record.get("facts") or {}
        for fact in sorted(facts):
            for path in _null_paths(facts[fact], fact):
                problems.append(
                    f"{where}: fact {path} is null — a fact value is never "
                    "null at any depth; value, absent and unobservable each "
                    "have their own channel and null names none of them "
                    "(DESIGN 19)"
                )

    if ends:
        end = ends[0]
        cpu = end.get("cpu_ms", _MISSING)
        if cpu is not _MISSING and not _measured(cpu):
            problems.append(
                f"end: cpu_ms is {cpu!r}; measured cost must be a finite "
                "non-negative number"
            )
        wall = end.get("wall_ms", _MISSING)
        if wall is not _MISSING and not _measured(wall):
            problems.append(
                f"end: wall_ms is {wall!r}; measured cost must be a finite "
                "non-negative number"
            )
        # Presence, not only sanity: work takes time, so a batch that
        # emitted objects reports how much (DESIGN 19), and an omitted
        # wall_ms would otherwise be the one cost nothing ever checked.
        if any(r.get("record") == "object" for r in records) and (
            wall is _MISSING or not _measured(wall) or not wall > 0
        ):
            problems.append(
                f"end: wall_ms is {'absent' if wall is _MISSING else repr(wall)}; "
                "a batch that emitted objects must report a positive wall_ms"
            )
    return problems


def collector_env(variant: Variant, payload_dir: Path | None = None) -> dict[str, str]:
    """The environment a collector is replayed under.

    One place, so the tests and the module API cannot drift — an earlier split
    had the tests setting the clock pin and this module not, which meant the
    published entry point silently dropped the determinism the suite depends
    on.
    """
    env = dict(os.environ)
    env["SE_REPLAY_DIR"] = str(payload_dir or (variant.path / "payloads"))
    env["SE_REFERENCE_COLLECTOR"] = variant.meta["collector"]
    if variant.meta.get("captured"):
        env["SE_REPLAY_NOW"] = variant.meta["captured"]
    return env


def run_collector(
    binary: list[str],
    variant: Variant,
    payload_dir: Path | None = None,
    timeout: int = 120,
    issued: dict[str, int] | None = None,
) -> subprocess.CompletedProcess:
    """Run a collector against a variant's payloads.

    The request line goes on stdin and the stream comes back on stdout, which
    is the same contract socket activation gives the collector in production —
    so a collector that works here works there, and vice versa. Each token is
    `<collection>:<generation>` (DESIGN 18): the harness plays the issuing
    collator, and the collector parses and echoes — a token without its
    generation is a malformed request.

    The request line is the collector's ONLY channel to the issued generation,
    and the seal below is what makes that true. The seed issue_generations() is
    keyed on is variant.name, which the variant's own payloads/ directory spells
    in its last two path components — and the crc32 formula is public in this
    file — while expected.jsonl, carrying begin.generations verbatim, sits one
    level up at ../expected.jsonl. So a collector that ignored stdin could
    reconstruct the issuance from SE_REPLAY_DIR's path or read it from the
    adjacent file and echo the right value while proving nothing. Both channels
    are closed by replaying every variant's payloads (only — never
    expected.jsonl, never meta.json) from a fresh mkdtemp whose name names no
    variant, the same sealed path the differential guard already replays
    through. The seed stays variant.name, so issuance is unchanged and the
    corpus pair on disk still reproduces byte for byte across two runs.
    """
    # Seeded by the variant's identity, so every variant gets its own base
    # and the pair on disk was captured under the same issuance this replays.
    if issued is None:
        issued = issue_generations(variant.collections(), seed=variant.name)
    tokens = " ".join(f"{name}:{gen}" for name, gen in sorted(issued.items()))

    def _spawn(directory: Path | None) -> subprocess.CompletedProcess:
        return subprocess.run(
            binary,
            input=f"collect {tokens}\n",
            capture_output=True,
            text=True,
            env=collector_env(variant, directory),
            timeout=timeout,
        )

    # A caller that supplies its own payload_dir already controls a sealed,
    # non-variant-naming path — the differential guard's mutated tempdir, the
    # empty-environment test's tmp_path — so it is honoured as given.
    if payload_dir is not None:
        return _spawn(payload_dir)

    # payload_dir is None: seal the variant's own payloads out of reach of the
    # seed and the answer before the collector ever sees SE_REPLAY_DIR. Every
    # payload file, not *.json: text payloads (os-release, hostname) ARE the
    # native documents, and a glob that only carried JSON replayed the system
    # variant against an empty directory — an honest absent decline judged
    # against a capture that was anything but. Dotfiles stay behind: the
    # .gitkeep marking an absent-interface variant is git plumbing, and the
    # loader refuses to read it as a capture for the same reason.
    with tempfile.TemporaryDirectory(prefix="se-replay-") as sealed:
        directory = Path(sealed)
        for payload in sorted((variant.path / "payloads").iterdir()):
            if payload.is_file() and not payload.name.startswith("."):
                shutil.copy(payload, directory / payload.name)
        return _spawn(directory)


def parse_stream(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def replay(binary: list[str], variant: Variant) -> ReplayResult:
    """Replay one variant and report whether the collector reproduced it."""
    issued = issue_generations(variant.collections(), seed=variant.name)
    proc = run_collector(binary, variant, issued=issued)
    if proc.returncode != 0:
        return ReplayResult(
            variant=variant,
            ok=False,
            stderr=proc.stderr,
            differences=[
                f"collector exited {proc.returncode}; non-zero means "
                '"I could not run", never a decline'
            ],
        )
    emitted = parse_stream(proc.stdout)
    if not emitted:
        return ReplayResult(
            variant=variant,
            ok=False,
            stderr=proc.stderr,
            differences=["collector emitted nothing"],
        )
    differences = check_stream(emitted, issued) + diff(variant.expected, emitted)
    return ReplayResult(
        variant=variant,
        ok=not differences,
        emitted=emitted,
        differences=differences,
        stderr=proc.stderr,
    )


def reference_binary() -> list[str]:
    """The reference implementation, wearing a collector's face.

    Until Go collectors exist, the shipping adapters are what a corpus pair is
    captured from and replayed against — rule 4 of the plan, made executable.
    """
    import sys

    return [
        sys.executable,
        str(Path(__file__).resolve().parent.parent / "bin" / "se-reference-collector"),
    ]
