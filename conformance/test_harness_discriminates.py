"""The judge is itself judged.

An adversarial review built a collector wrong in five simultaneous ways and
the replay suite reported `16 passed`. Every defect it exploited is pinned
here, because a harness with no tests of its own is a harness nobody can
trust — and the failure mode is silent by construction: a judge that cannot
fail looks exactly like a subject that never fails.

Each test below corrupts something a collector could plausibly get wrong and
requires the harness to say so. They are cheap, they run without a corpus
where possible, and they are the reason a green replay run means anything.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from se_harness import corpus, replay

REPO = Path(__file__).resolve().parent.parent
ANONYMISE = REPO / "harness" / "bin" / "se-anonymise"

# Tolerant on purpose, narrowly: while the corpus is mid-regeneration its
# meta may not yet satisfy the loader (anchors landed before the re-scrub),
# and that must skip the variant-backed tests below — their declared absence
# path — rather than error this whole module out of collection, taking the
# corpus-free scrubber tests with it.
try:
    VARIANTS = corpus.all_variants()
except corpus.CorpusError:
    VARIANTS = []


def _network_healthy() -> corpus.Variant:
    for variant in VARIANTS:
        if (
            variant.meta["collector"] == "network"
            and variant.meta["variant"] == "healthy"
        ):
            return variant
    pytest.skip("network/healthy variant absent")


# ── diff() must see what it was blind to ─────────────────────────────────


def test_duplicate_records_are_a_difference() -> None:
    """A collector emitting every object twice is a real bug — a retry, a
    double walk of a vdev tree — and last-writer-wins hid it entirely."""
    variant = _network_healthy()
    assert replay.diff(variant.expected, variant.expected + variant.expected)


def test_a_corrupted_duplicate_cannot_hide_behind_a_good_one() -> None:
    """The sharper form: emit the object twice, first copy wrong. Building the
    comparison map with a dict comprehension kept only the last copy, so the
    corrupted one was never compared against anything."""
    variant = _network_healthy()
    emitted: list[dict] = []
    for record in variant.expected:
        if record["record"] == "object":
            corrupted = copy.deepcopy(record)
            corrupted["facts"] = {**corrupted["facts"], "Policy": "accept"}
            emitted.append(corrupted)
        emitted.append(record)
    assert replay.diff(variant.expected, emitted)


def test_an_absent_member_differs_from_a_null_one() -> None:
    """dict.get() returns None for both, so any member whose expected value is
    null could simply be omitted — including `complete` on a commit, which the
    contract forbids outright."""
    expected = [{"record": "begin", "instance": None, "generations": {"x": 1}}]
    emitted = [{"record": "begin", "generations": {"x": 1}}]
    differences = replay.diff(expected, emitted)
    assert any("instance" in d for d in differences), differences


def test_relation_targets_are_part_of_a_record_s_identity() -> None:
    """Three assertions of one type to three different chains collapsed onto a
    single key, so a collector emitting one of them — or all three pointing at
    the wrong place — was judged identical."""

    def assertion(target: str) -> dict:
        return {
            "record": "relation_assertion",
            "collection": "nft-chains",
            "name": "inet filter input",
            "type": "jumps-to",
            "vantage": "nft-chains",
            "target": {"kind": "nft-chain", "name": target},
        }

    expected = [assertion(t) for t in ("a", "b", "c")]
    assert replay.diff(expected, [assertion("a")]), "a dropped assertion passed"
    assert replay.diff(expected, [assertion("a"), assertion("x"), assertion("y")]), (
        "assertions pointing at the wrong targets passed"
    )


def test_a_relation_s_own_facts_are_part_of_its_identity() -> None:
    """The VdevPath fix was itself a subset guard: identity keyed on the ONE
    discriminator its author had met, so two same-type same-target assertions
    told apart by any OTHER fact collapsed onto one key — and because same-key
    copies are zip-paired in stream order, a CORRECT collector emitting them
    in the other order failed with a false facts mismatch, contradicting the
    module's own reordering rule. Both directions are held: the collapse must
    not hide a drop, and the reorder must cost nothing."""

    def jump(handle: int) -> dict:
        # Two rules in one chain both jumping to one target: same type, same
        # target, distinguished only by the rule handle — a discriminator the
        # VdevPath-only key had never heard of.
        return {
            "record": "relation_assertion",
            "collection": "nft-chains",
            "name": "inet filter input",
            "type": "jumps-to",
            "vantage": "nft-chains",
            "target": {"kind": "nft-chain", "name": "input-allow"},
            "facts": {"RuleHandle": handle},
        }

    expected = [jump(4), jump(9)]
    assert replay.diff(expected, [jump(4)]), "a dropped assertion passed"
    assert not replay.diff(expected, [jump(9), jump(4)]), (
        "a reordering of same-type same-target assertions read as a mismatch"
    )


def test_reordering_is_still_not_a_difference() -> None:
    """The tolerance the rules do require, kept while tightening the rest:
    stream order is not significant (DESIGN 19)."""
    variant = _network_healthy()
    assert not replay.diff(variant.expected, list(reversed(variant.expected)))


# ── check_stream() covers what the diff deliberately drops ───────────────


def test_a_fabricated_generation_is_caught() -> None:
    """normalise() drops the collator-issued value, so byte comparison cannot
    see it; the echo between begin and commit is what holds it."""
    records = [
        {"record": "begin", "generations": {"pools": 7}},
        {"record": "commit", "collection": "pools", "generation": 424242, "objects": 0},
        {"record": "end"},
    ]
    assert any("echo" in p for p in replay.check_stream(records))


def test_a_commit_that_lies_about_its_counts_is_caught() -> None:
    """A commit's counts describe the stream it closes, so they are checkable
    against it — independently of the diff."""
    records = [
        {"record": "begin", "generations": {"pools": 1}},
        {
            "record": "object",
            "collection": "pools",
            "name": "a",
            "facts": {},
            "at": 1.0,
        },
        {"record": "commit", "collection": "pools", "generation": 1, "objects": 9},
        {"record": "end"},
    ]
    assert any("stream carries" in p for p in replay.check_stream(records))


def test_a_collection_named_in_begin_must_be_resolved() -> None:
    records = [
        {"record": "begin", "generations": {"pools": 1, "datasets": 1}},
        {"record": "commit", "collection": "pools", "generation": 1, "objects": 0},
        {"record": "end"},
    ]
    assert any("datasets" in p for p in replay.check_stream(records))


def test_only_an_absent_decline_may_commit() -> None:
    """The distinction the whole record type exists for: absent is a successful
    reading and retires objects; the other three leave prior state alone."""

    def stream(reason: str, commit: bool) -> list[dict]:
        # Well-formed everywhere BUT the property under test: the absent
        # stream with a commit must pass with zero problems, so it has to
        # satisfy every other rule check_stream now holds — a UUID-shaped
        # boot_id, the begin/end echo, and all three commit counts.
        records = [
            {"record": "begin", "request": "rq", "batch": "b1",
             "declaration": "sha256:replay",
             "boot_id": "5e000000-0000-4000-8000-000000000001",
             "generations": {"pools": 1}},
            {"record": "decline", "collection": "pools", "reason": reason},
        ]
        if commit:
            records.append(
                {
                    "record": "commit",
                    "collection": "pools",
                    "generation": 1,
                    "objects": 0,
                    "assertions": 0,
                    "unobservable": 0,
                }
            )
        records.append({"record": "end", "request": "rq", "batch": "b1"})
        return records

    assert not replay.check_stream(stream("absent", commit=True))
    assert replay.check_stream(stream("absent", commit=False))
    assert replay.check_stream(stream("unavailable", commit=True))


def test_a_decline_closes_its_collection_in_both_directions() -> None:
    """A decline is a statement about the whole collection, so it closes the
    collection to every emitting record — before it (a collection that
    emitted cannot also decline) and after it (the direction that was
    guarded nowhere: the wire refused records-then-decline while
    decline-then-records sailed through with the records silently dropped,
    and an assertion could even ride under an absent decline's commit).
    check_stream judges the completed stream, so one bag rule holds both
    orders; the wire refuses each order by name."""

    def stream(middle: list[dict]) -> list[dict]:
        return [
            {"record": "begin", "request": "rq", "batch": "b1",
             "declaration": "sha256:replay",
             "boot_id": "5e000000-0000-4000-8000-000000000001",
             "generations": {"pools": 1}},
            *middle,
            {"record": "end", "request": "rq", "batch": "b1"},
        ]

    obj = {"record": "object", "collection": "pools", "name": "tank",
           "facts": {"Health": "ONLINE"}, "at": 1.0}
    decline = {"record": "decline", "collection": "pools", "reason": "unavailable"}
    rule = "declined collection"

    after = replay.check_stream(stream([decline, obj]))
    assert any(rule in p for p in after), (
        f"a record AFTER a decline raised nothing — the record would vanish "
        f"silently at the collator: {after}"
    )
    before = replay.check_stream(stream([obj, decline]))
    assert any(rule in p for p in before), (
        f"records BEFORE a decline raised nothing: {before}"
    )

    # The F4 demonstration: an assertion committed under an absent decline,
    # counts reconciling — accepted by all three artifacts before the rule.
    assertion = {"record": "relation_assertion", "collection": "pools",
                 "name": "tank", "type": "backed-by", "vantage": "pools",
                 "target": {"kind": "block-device", "name": "sda"}}
    absent = {"record": "decline", "collection": "pools", "reason": "absent"}
    zero_commit_but_assertion = {"record": "commit", "collection": "pools",
                                 "generation": 1, "objects": 0,
                                 "assertions": 1, "unobservable": 0}
    smuggled = replay.check_stream(
        stream([absent, assertion, zero_commit_but_assertion]))
    assert any(rule in p for p in smuggled), (
        f"an assertion under an absent decline raised nothing: {smuggled}"
    )

    # And the closure costs nothing it should not: absent plus its zero
    # commit, with no emitting records, stays clean.
    clean_commit = {"record": "commit", "collection": "pools", "generation": 1,
                    "objects": 0, "assertions": 0, "unobservable": 0}
    assert not replay.check_stream(stream([absent, clean_commit]))


def test_an_object_without_a_monotonic_reading_is_caught() -> None:
    """`at` is dropped from the diff because it genuinely varies, so its
    presence and sanity are held here instead."""
    records = [
        {"record": "begin", "generations": {"pools": 1}},
        {"record": "object", "collection": "pools", "name": "a", "facts": {}},
        {"record": "commit", "collection": "pools", "generation": 1, "objects": 1},
        {"record": "end"},
    ]
    assert any("`at`" in p for p in replay.check_stream(records))


def test_an_at_that_runs_backwards_within_its_collection_is_caught() -> None:
    """The structural part of DESIGN 19's third replay bound: within one
    collection, emission order is acquisition order and a clock cannot run
    backwards inside one acquisition pass. Only shape is judged under a
    pinned clock — the reading's truth is the live comparator's — so the
    rule must hold exactly this much and no more: backwards is red, a tie
    is not (two reads in one clock tick), and a second collection's clock
    restarting lower is not (a collector reading two interfaces has two
    ages and may interleave them)."""

    def obj(collection: str, name: str, at: float) -> dict:
        return {"record": "object", "collection": collection, "name": name,
                "facts": {"Health": "ONLINE"}, "at": at}

    def stream(objects: list[dict]) -> list[dict]:
        collections = sorted({o["collection"] for o in objects})
        records = [{"record": "begin",
                    "generations": {c: 1 for c in collections}}, *objects]
        for c in collections:
            count = sum(1 for o in objects if o["collection"] == c)
            records.append({"record": "commit", "collection": c,
                            "generation": 1, "objects": count})
        records.append({"record": "end"})
        return records

    backwards = stream([obj("pools", "a", 2.0), obj("pools", "b", 1.5)])
    problems = replay.check_stream(backwards)
    assert any("non-decreasing within its collection" in p for p in problems), (
        f"a backwards `at` inside one collection raised nothing: {problems}"
    )
    tie = stream([obj("pools", "a", 2.0), obj("pools", "b", 2.0)])
    assert not any("non-decreasing" in p for p in replay.check_stream(tie)), (
        "two readings in one clock tick were refused — the rule is "
        "non-decreasing, not strictly increasing"
    )
    interleaved = stream([obj("pools", "a", 5.0), obj("arrays", "m", 1.0),
                          obj("pools", "b", 5.5)])
    assert not any("non-decreasing" in p for p in replay.check_stream(interleaved)), (
        "a second collection's lower reading was refused — the rule is "
        "per collection, and a collector reading two interfaces has two ages"
    )


def test_a_nested_null_fact_value_is_caught() -> None:
    """The null-fact rule checked depth one, so it was the subset guard
    wearing the judge's clothes: a vdev row carrying "State": null — what
    marshalling a struct with nil fields produces — passed check_stream
    while the same null one level up was refused. The recursion used to
    live only in test_reference_honesty, hardwired to the reference; now
    the rule the PORTS are judged by descends every dict and list."""
    records = [
        {"record": "begin", "generations": {"pools": 1}},
        {"record": "object", "collection": "pools", "name": "tank",
         "facts": {"Vdevs": [{"Name": "raidz1-0", "Type": "raidz",
                              "State": None}]},
         "at": 1.0},
        {"record": "commit", "collection": "pools", "generation": 1,
         "objects": 1},
        {"record": "end"},
    ]
    problems = replay.check_stream(records)
    assert any("Vdevs[0]/State is null" in p for p in problems), (
        f"a null nested in a vdev row raised nothing: {problems}"
    )
    # The same law from the schema's side: the wire refuses the record too,
    # and the healthy twin passes — so what discriminates is the null, not
    # some unrelated shape defect in the fixture.
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    registry = Registry()
    for path in sorted((REPO / "contract").glob("*.json")):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(
            schema["$id"], Resource.from_contents(schema))
    validator = Draft202012Validator(
        json.loads((REPO / "contract" / "se.stream.1.json").read_text()),
        registry=registry,
    )
    nested_null = dict(records[1], record="object")
    assert list(validator.iter_errors(nested_null)), (
        "the schema accepted a nested null fact value — its facts rule "
        "still stops at depth one"
    )
    healthy = dict(nested_null,
                   facts={"Vdevs": [{"Name": "raidz1-0", "Type": "raidz",
                                     "State": "ONLINE"}]})
    assert not list(validator.iter_errors(healthy)), (
        "the non-null twin fails the schema, so the red above indicts the "
        "fixture rather than the null"
    )


# ── the anonymiser must not corrupt the shapes it protects ───────────────
#
# The scrubber is manifest-driven and keyed (DESIGN 21): each case below runs
# the real tool over a one-field payload with a one-entry manifest, under a
# pinned secret so every run of this suite derives the same replacements.

TEST_SECRET = "conformance-fixed-secret"


def _anonymise(payload: dict, manifest: dict, *, hostnames: str = "",
               secret: str = TEST_SECRET, map_path: Path | None = None):
    """Run the installed tool; return (proc, scrubbed document or None)."""
    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = Path(tmp) / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        payload_path = Path(tmp) / "payload.json"
        payload_path.write_text(json.dumps(payload))
        argv = [sys.executable, str(ANONYMISE), "--manifest", str(manifest_path),
                str(payload_path)]
        if hostnames:
            argv += ["--hostnames", hostnames]
        if map_path:
            argv += ["--map", str(map_path)]
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            env={**os.environ, "SE_SCRUB_SECRET": secret},
        )
        scrubbed = None
        if proc.returncode == 0:
            scrubbed = json.loads(payload_path.read_text())
        return proc, scrubbed


def _anonymise_many(payloads: dict[str, object], manifest: dict, *,
                    hostnames: str = "", secret: str = TEST_SECRET):
    """Scrub SEVERAL named payloads in one run, as a real capture is scrubbed.

    The payload's stem is the name a scoped manifest entry refers to, so a
    helper that writes every payload to `payload.json` cannot exercise
    scoping at all.
    """
    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = Path(tmp) / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        paths = []
        for stem, document in payloads.items():
            path = Path(tmp) / f"{stem}.json"
            path.write_text(json.dumps(document))
            paths.append(path)
        argv = [sys.executable, str(ANONYMISE), "--manifest", str(manifest_path),
                *(str(p) for p in paths)]
        if hostnames:
            argv += ["--hostnames", hostnames]
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            env={**os.environ, "SE_SCRUB_SECRET": secret},
        )
        scrubbed = None
        if proc.returncode == 0:
            scrubbed = {p.stem: json.loads(p.read_text()) for p in paths}
        return proc, scrubbed


# The two shapes one collector's manifest has to cover at once: zpool's
# documents, keyed by fixed schema members, and the device alias map, whose
# root keys ARE data — an alias path per symlink, each ending in the partition
# UUID that correlates the disk across captures.
_DEVLINKS = {"/dev/disk/by-partuuid/7f3c1d92-4b6e-4a01-9f2b-0c8d5e7a1b34": "vda13"}
_STATUS = {"pools": {"examplepool": {"state": "DEGRADED"}}}
_SCOPED_MANIFEST = {
    "~key": {"discloses": "identity", "format": "path", "payload": "devlinks"},
    "*": {"discloses": "nothing", "payload": "devlinks"},
    "pools.~key": {"discloses": "content", "format": "name"},
    "pools.*.state": {"discloses": "nothing"},
}


def test_a_payload_scoped_entry_governs_only_the_payload_it_names() -> None:
    """One manifest per collector, and its payloads do not share a root.

    The devlinks map needs a '~key' entry AT THE ROOT, because its root keys
    are the data. That same entry unscoped is a claim that `pools` and
    `output_version` — zpool's schema members — are data too, and the run
    refuses a document it understands perfectly (the next test). Scoping is
    what lets both be classified truthfully in one file.
    """
    proc, docs = _anonymise_many(
        {"devlinks": _DEVLINKS, "status": _STATUS}, _SCOPED_MANIFEST,
        hostnames="examplepool",
    )
    assert proc.returncode == 0, proc.stderr
    (alias,) = docs["devlinks"]
    assert alias.startswith("/dev/disk/by-partuuid/"), alias
    assert "7f3c1d92" not in alias, "the partition UUID survived the scrub"
    assert docs["devlinks"][alias] == "vda13", "the kernel name is positional"
    assert set(docs["status"]) == {"pools"}, "a schema root was rewritten"
    (pool,) = docs["status"]["pools"]
    assert pool != "examplepool", "the operator-chosen pool name survived"


def test_an_unscoped_root_key_entry_refuses_the_document_it_misclassifies() -> None:
    """The reversion of the test above, run as a test.

    Without the scope the two entries reach every payload, so zpool's schema
    roots take a substituting class, survive unchanged, and the deny-by-
    default gate refuses — which is the scrubber being right. A silencing fix
    (KEEP-listing `pools`) would classify to quiet a refusal and would pass a
    pool actually named `pools` on the same day.
    """
    unscoped = {
        key: {k: v for k, v in spec.items() if k != "payload"}
        for key, spec in _SCOPED_MANIFEST.items()
    }
    proc, _ = _anonymise_many(
        {"devlinks": _DEVLINKS, "status": _STATUS}, unscoped, hostnames="examplepool"
    )
    assert proc.returncode != 0, "an unscoped root ~key entry scrubbed a schema root"
    assert "pools: classified identity" in proc.stderr, proc.stderr


def test_scoping_creates_no_precedence_between_two_matching_entries() -> None:
    """A scoped entry does not quietly outrank an unscoped one.

    Exactly one entry must classify a leaf, and 'the more specific wins' is
    the rule that would let a manifest's meaning depend on this file's
    iteration order. Two matching entries stay the two-entries refusal.
    """
    proc, _ = _anonymise_many(
        {"list": {"v": {"x": "12297829382473034410"}}},
        {
            "v.*": {"discloses": "nothing", "payload": "list"},
            "v.x": {"discloses": "identity", "format": "guid_u64"},
        },
    )
    assert proc.returncode != 0
    assert "exactly one must" in proc.stderr, proc.stderr


def _scrub(value, fmt: str | None = None, *, discloses: str = "identity",
           hostnames: str = "", secret: str = TEST_SECRET):
    entry: dict = {"discloses": discloses}
    if fmt:
        entry["format"] = fmt
    proc, doc = _anonymise({"v": value}, {"v": entry},
                           hostnames=hostnames, secret=secret)
    assert proc.returncode == 0, proc.stderr
    return doc["v"]


@pytest.mark.parametrize(
    "original",
    [
        # A PCI address and an IPv6 address are the same characters in the same
        # order. A loose IPv6 pattern rewrote every disk's phys_path into the
        # documentation range, in committed corpus. The address patterns now
        # anchor on the whole whitespace-delimited token; only the manifest
        # decides whether such a field is touched at all.
        "pci-0000:03:00.0-sas-phy2-lun-0",
        "pci-0000:01:00.0-sas-phy7-lun-0",
        # the SCSI topology spelling the old pattern ate as an IPv6 address
        "scsi-0:0:0:0",
    ],
)
def test_bus_topology_survives_scrubbing(original: str) -> None:
    assert _scrub(original, "path") == original


@pytest.mark.parametrize(
    "original,fmt,shape",
    [
        ("52:54:00:0c:b9:bc", "mac",
         lambda s: s.count(":") == 5 and len(s) == 17),
        ("wwn-0x5000c500a1b2c3d4", "wwn",
         lambda s: s.startswith("wwn-0x") and len(s) == 22),
        ("192.168.122.43", "ipv4", lambda s: s.count(".") == 3),
        ("11550964982834382071", "guid_u64",
         lambda s: s.isdigit() and len(s) == 20 and s[0] != "0"),
        # the prefix is a constant and survives; the host part can embed the
        # MAC under modified EUI-64, so it must not
        ("fe80::1c9a:22ff:fe33:4455", "ipv6",
         lambda s: s.startswith("fe80::") and "1c9a" not in s),
    ],
)
def test_scrubbing_preserves_shape(original: str, fmt: str, shape) -> None:
    """A replacement of the wrong shape breaks the parser the specimen exists
    to exercise. A MAC that came back as an IPv6 is the case that happened."""
    scrubbed = _scrub(original, fmt)
    assert scrubbed != original, f"{original} was not scrubbed"
    assert shape(scrubbed), f"{original} -> {scrubbed} has the wrong shape"


def test_a_replacement_is_not_scrubbed_again() -> None:
    """Patterns run in sequence, so a MAC rewritten to 02:xx:xx:xx:xx:xx is
    still colon-separated hex and the IPv6 pattern will eat it unless each
    replacement is parked out of reach until the end."""
    scrubbed = _scrub("link 52:54:00:0c:b9:bc is up")  # free text: every pattern runs
    assert "02:" in scrubbed, scrubbed
    assert "2001:db8" not in scrubbed


# ── an address's space is part of its shape ──────────────────────────────


@pytest.mark.parametrize(
    "constant",
    [
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255",
        "224.0.0.251",  # mDNS
        "169.254.169.254",  # cloud metadata
        "10.0.0.0",  # RFC 1918 range base
        "100.64.0.0",  # RFC 6598 — the range every tailnet shares
        "fe80::",  # link-local prefix
        "ff02::fb",  # mDNS over v6
        "fd7a:115c:a1e0::",  # a published ULA prefix
    ],
)
def test_protocol_constants_are_never_substituted(constant: str) -> None:
    """These are the same on every machine on earth, so they disclose nothing
    and are load-bearing to a reader.

    A firewall rule matching 100.64.0.0/10 is a rule about tailnet traffic.
    Rewritten to 192.0.2.135/10 it is a rule about nothing — and that is not a
    weaker specimen but a wrong one, since 192.0.2.135 is not even a valid base
    for a /10. That happened, in committed corpus.
    """
    fmt = "ipv6" if ":" in constant else "ipv4"
    assert _scrub(constant, fmt) == constant


@pytest.mark.parametrize(
    "original,fmt,space",
    [
        ("100.71.9.42", "ipv4",
         lambda s: s.startswith("100.") and 64 <= int(s.split(".")[1]) <= 127),
        ("192.168.122.43", "ipv4", lambda s: s.startswith("192.168.")),
        ("10.20.30.40", "ipv4", lambda s: s.startswith("10.")),
        ("172.20.5.9", "ipv4",
         lambda s: s.startswith("172.") and 16 <= int(s.split(".")[1]) <= 31),
        ("8.8.8.8", "ipv4", lambda s: s.startswith("192.0.2.")),  # global -> doc
        ("fd7a:115c:a1e0::1a2b:3c4d", "ipv6",
         lambda s: s.startswith("fd7a:115c:a1e0::")),
        ("2606:4700::1111", "ipv6",
         lambda s: s.startswith("2001:db8")),  # global -> documentation
    ],
)
def test_substitution_stays_in_the_original_space(original: str, fmt: str, space) -> None:
    """Only a globally routable address becomes a documentation address.

    A private address rewritten into 192.0.2.0/24 has been moved to a
    different kind of network, which is a change of meaning rather than of
    value — and the space is what tells a reader what a rule is about.
    """
    scrubbed = _scrub(original, fmt)
    assert scrubbed != original, f"{original} was not scrubbed"
    assert space(scrubbed), f"{original} -> {scrubbed} left its own space"


def test_a_tailnet_host_address_is_still_scrubbed() -> None:
    """The range holds both classes at once: 100.64.0.0/10 is a constant, and
    a specific address inside it correlates one node across captures. The
    well-known table may relax location to nothing; it may never soften
    identity, or a peer address would slip through on being non-routable."""
    assert _scrub("100.71.9.42", "ipv4") != "100.71.9.42"


# ── the manifest decides, and the key decides deterministically ──────────


def test_the_same_secret_derives_the_same_replacement() -> None:
    """One original maps to one replacement across files AND across runs of
    one corpus: the joins between payloads are the property the specimens
    exist to teach, and determinism within a corpus is what preserves them."""
    first = _scrub("wwn-0x5000c500a1b2c3d4", "wwn")
    second = _scrub("wwn-0x5000c500a1b2c3d4", "wwn")
    assert first == second


def test_a_different_secret_derives_a_different_replacement() -> None:
    """An unkeyed digest is a lookup table for anyone who can enumerate the
    input space — a /10 of addresses falls in seconds. Two corpora with two
    secrets must not share a mapping."""
    ours = _scrub("100.71.9.42", "ipv4")
    theirs = _scrub("100.71.9.42", "ipv4", secret="another-corpus-entirely")
    assert ours != theirs


def test_an_unclassified_leaf_refuses_the_run() -> None:
    """Deny-by-default: an unclassified field is a capture the tool does not
    understand, and the failure mode of passing it is publication."""
    proc, _ = _anonymise(
        {"v": "fine", "surprise": "12297829382473034410"},
        {"v": {"discloses": "nothing"}},
    )
    assert proc.returncode != 0
    assert "surprise" in proc.stderr


# ── a transcription's payloads: one scalar per path, addressed by glob ───
#
# A TREE-shaped interface's native document is the filesystem transcribed
# (DESIGN's tree-shape ruling, 2026-08-19), which is one payload per path the
# machine had — hundreds of stems the manifest's author never chose, and `null`
# wherever a path was not there. Two properties have to hold for that to be
# publishable at all, and both are deny-by-default; each is asserted here
# against the real tool, because a manifest language that silently passed
# either would publish a capture nobody classified.


def _scrub_files(files: dict[str, str], manifest: dict):
    """Scrub payload files written VERBATIM, so a `.json` document that is a
    bare scalar and a `.txt` document both reach the tool as themselves."""
    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = Path(tmp) / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        paths = []
        for name, body in files.items():
            path = Path(tmp) / name
            path.write_text(body)
            paths.append(path)
        proc = subprocess.run(
            [sys.executable, str(ANONYMISE), "--manifest", str(manifest_path),
             *(str(p) for p in paths)],
            capture_output=True, text=True,
            env={**os.environ, "SE_SCRUB_SECRET": TEST_SECRET},
        )
        return proc, {p.name: p.read_text() for p in paths}


def test_a_scalar_json_payload_is_classified_whole_or_refused() -> None:
    """`null` is how a transcription records a path that was not there, and a
    document that is one scalar has no leaves for a dotted path to name — the
    same property a text payload has. Classified whole it survives verbatim;
    unclassified it refuses, which is what stops a capture of this shape
    reaching a public corpus unclassified."""
    manifest = {"absent path": {"payload": "*-io.stat", "whole": {"discloses": "nothing"}}}
    proc, files = _scrub_files({"cg-io.stat.json": "null\n"}, manifest)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(files["cg-io.stat.json"]) is None

    proc, _ = _scrub_files({"cg-memory.peak.json": "null\n"}, manifest)
    assert proc.returncode != 0
    assert "cg-memory.peak" in proc.stderr


def test_a_whole_entry_may_scope_by_glob_and_two_matches_refuse() -> None:
    """A transcription's stems are the machine's paths, not a vocabulary
    anybody wrote down, so the classification is stated per FILE KIND and the
    entry names the kind. Overlap is refused rather than resolved, because
    which entry governs must never depend on the manifest's iteration order."""
    manifest = {"cpu": {"payload": "*-cpu.stat", "whole": {"discloses": "nothing"}}}
    proc, files = _scrub_files({"a-cpu.stat.txt": "usage_usec 5\n"}, manifest)
    assert proc.returncode == 0, proc.stderr
    assert files["a-cpu.stat.txt"] == "usage_usec 5\n"

    manifest["cpu again"] = {"payload": "a-*", "whole": {"discloses": "nothing"}}
    proc, _ = _scrub_files({"a-cpu.stat.txt": "usage_usec 5\n"}, manifest)
    assert proc.returncode != 0
    assert "exactly one must" in proc.stderr


def test_a_declared_secret_refuses_the_run_without_echoing_it() -> None:
    """A secret must never have been captured; scrubbing cannot repair the
    payload, and the refusal itself must not become the leak."""
    proc, _ = _anonymise(
        {"token": "hunter2-not-for-echoing"},
        {"token": {"discloses": "secret"}},
    )
    assert proc.returncode != 0
    assert "token" in proc.stderr
    assert "hunter2-not-for-echoing" not in proc.stderr + proc.stdout


def test_the_map_is_refused_inside_any_git_tree(tmp_path: Path) -> None:
    """The old guard anchored on this repo's source layout, so the tool
    silently disarmed wherever else it was installed — reproduced: a map
    written straight into a foreign working tree. The guard now walks up
    looking for a .git, wherever the tree is."""
    foreign = tmp_path / "somebody-elses-checkout"
    (foreign / ".git").mkdir(parents=True)
    proc, _ = _anonymise(
        {"v": "52:54:00:0c:b9:bc"},
        {"v": {"discloses": "identity", "format": "mac"}},
        map_path=foreign / "map.json",
    )
    assert proc.returncode != 0
    assert "git working tree" in proc.stderr
    assert not (foreign / "map.json").exists()


def test_an_integer_guid_stays_an_integer_and_fits_u64() -> None:
    """The old scrubber only rewrote strings, so zpool's integer GUIDs went
    out verbatim — and its string replacements exceeded 2^64-1, a value no
    64-bit interface can emit. Type and range are both part of the shape."""
    scrubbed = _scrub(12297829382473034410, "guid_u64")
    assert isinstance(scrubbed, int)
    assert scrubbed != 12297829382473034410
    assert scrubbed <= 2**64 - 1
    assert len(str(scrubbed)) == 20  # digit-width preserved


def test_a_mixed_comparand_keeps_its_numbers_but_not_identifier_scale_ones() -> None:
    """nft's match.right holds ports and fwmarks beside addresses in ONE
    member, so a formatless substituting entry must pass a bare number — a
    number embeds no token the free-text pass could find. The pass-through
    stops at 2^48, where real WWNs and GUIDs live: an identifier-scale
    integer still refuses until its entry says guid_u64, because that
    silence is the exact hole that shipped zpool's integer GUIDs verbatim."""
    proc, doc = _anonymise({"v": 262144}, {"v": {"discloses": "location"}})
    assert proc.returncode == 0, proc.stderr
    assert doc["v"] == 262144
    proc, _ = _anonymise({"v": 2**48}, {"v": {"discloses": "location"}})
    assert proc.returncode != 0
    assert "guid_u64" in proc.stderr


def test_an_addr_len_pair_is_scrubbed_to_a_valid_base() -> None:
    """Substituting the address without the mask produced 100.89.226.124/23
    in committed corpus — an address where a network base belongs. The pair
    is one value wearing two members, so it is scrubbed as a unit."""
    import ipaddress

    proc, doc = _anonymise(
        {"prefix": {"addr": "100.106.160.207", "len": 23}},
        {
            "prefix.addr": {"discloses": "location", "format": "ipv4"},
            "prefix.len": {"discloses": "nothing"},
        },
    )
    assert proc.returncode == 0, proc.stderr
    addr, length = doc["prefix"]["addr"], doc["prefix"]["len"]
    assert addr != "100.106.160.207"
    assert length == 23
    network = ipaddress.ip_network(f"{addr}/{length}", strict=True)  # must not raise
    assert network.network_address in ipaddress.ip_network("100.64.0.0/10")


def test_a_hostname_is_caught_at_an_underscore_boundary() -> None:
    """`_` is a word character, so a \\b-anchored pattern walked straight past
    tank/<host>_backups. Hostname matching is a case-insensitive substring
    with no boundary requirement, deliberately."""
    scrubbed = _scrub("tank/ExampleHost_backups", hostnames="examplehost")
    assert "examplehost" not in scrubbed.lower()
    assert scrubbed.startswith("tank/")
    assert scrubbed.endswith("_backups")


def test_distinct_hostnames_never_share_a_replacement() -> None:
    """The old scheme hashed into 100 buckets, so node1 and node2 shared one
    — merging two machines teaches a reader a join that does not exist.
    Distinct originals must map to distinct replacements, retried on
    collision."""
    names = [f"node{i}" for i in range(300)]
    manifest = {
        "hosts.~key": {"discloses": "nothing"},
        "hosts.*": {"discloses": "location", "format": "hostname"},
    }
    proc, doc = _anonymise(
        {"hosts": {str(i): name for i, name in enumerate(names)}}, manifest
    )
    assert proc.returncode == 0, proc.stderr
    replacements = list(doc["hosts"].values())
    assert len(set(replacements)) == len(names), "hostname buckets collided"


def test_group_macs_stay_groups_and_group_constants_survive() -> None:
    """Broadcast and the multicast mappings are the same on every LAN on
    earth; and a group address that came back unicast would change what a
    frame means, so the group bit survives substitution."""
    assert _scrub("ff:ff:ff:ff:ff:ff", "mac") == "ff:ff:ff:ff:ff:ff"
    assert _scrub("01:00:5e:00:00:fb", "mac") == "01:00:5e:00:00:fb"
    assert _scrub("33:33:00:00:00:01", "mac") == "33:33:00:00:00:01"
    scrubbed = _scrub("05:aa:bb:cc:dd:ee", "mac")
    assert scrubbed != "05:aa:bb:cc:dd:ee"
    assert int(scrubbed[:2], 16) & 1, "a group address came back unicast"


def test_the_devid_spelling_is_scrubbed_and_keeps_the_join() -> None:
    """devid spells a WWN as scsi-3<16hex> — no 0x — and the old pattern
    missed every one of them. The same drive named in both spellings must
    come back as the same replacement body, or the join is deleted."""
    devid = _scrub("scsi-35000c500aabbccdd-part1", "wwn")
    by_id = _scrub("wwn-0x5000c500aabbccdd", "wwn")
    assert devid != "scsi-35000c500aabbccdd-part1"
    assert devid.startswith("scsi-3") and devid.endswith("-part1")
    assert devid.removeprefix("scsi-3").removesuffix("-part1") == \
        by_id.removeprefix("wwn-0x")
