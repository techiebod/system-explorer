"""Every leak detector is proved to fire, and proved to hold its tongue.

The detectors (se_harness/detectors.py) are the publish gate's second
opinion: they share no pattern, table or code path with the scrubber, so a
scrubber bug is a red run instead of a silent agreement. That independence is
only worth having if each detector actually discriminates — fires on a seeded
real-shaped specimen AND stays quiet on the shapes the scrubber is meant to
produce — so every detector here is tested in both directions.

The named regression cases at the bottom are the seven verified misses of the
shape-guessing scrubber, each reproduced against the committed tool before it
was replaced: real WWNs left untouched because devid spells them without 0x,
JSON integers walked past entirely, GUIDs emitted above 2^64-1, CIDR bases
invalid for their length, scsi-0:0:0:0 topology eaten as an IPv6 address,
hostnames missed at underscore boundaries, and a --check that grepped with
the scrubber's own pattern and therefore could not fail.

Below those sit the second review's misses — proved against the REBUILT
stack, every probe run silent before its detector existed: a vendor-OUI MAC,
a public IPv4 and a global IPv6 (only private spaces had been examined), an
nvme by-id tail (the checker knew fewer bus spellings than the scrubber), a
bare 0x WWN, an 18-digit guid string ducking the 19-digit floor, a dashed
UUID under an id-ish key — and a scrub run that printed `scrubbed` while an
operator-chosen pool name walked through verbatim because no names source
was given and nothing refused.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from se_harness import detectors
from se_harness.detectors import scan

REPO = Path(__file__).resolve().parent.parent
ANONYMISE = REPO / "harness" / "bin" / "se-anonymise"


def classes(findings) -> set[str]:
    return {f.value_class for f in findings}


# ── NAA/EUI identifiers, in every spelling ───────────────────────────────
#
# Every identifier below is SYNTHETIC. The shape is what the detector reads —
# a vendor-assigned NAA body, which is the half a replacement never produces —
# so a fabricated unit address exercises it exactly as a real one would. The
# first draft of this file used a real disk's WWN and a real pool GUID, which
# is the leak these detectors exist to catch, committed into the test that
# proves they catch it. A fixture is published bytes like any other.


@pytest.mark.parametrize(
    "spelling",
    [
        "wwn-0x5000c500aabbccdd",
        "scsi-35000c500aabbccdd",
        "naa.5000c500aabbccdd",
        "eui.5000c500aabbccdd",
        "nvme-eui.5000c500aabbccdd",
    ],
)
def test_a_real_identifier_fires_in_every_spelling(spelling: str) -> None:
    assert "identifier" in classes(scan({"disk": spelling}))


def test_a_locally_assigned_body_is_the_scrubbed_shape() -> None:
    """NAA nibble 3 names no vendor — it is where replacements live."""
    assert not scan({"disk": "wwn-0x35d73dfb65d47d90"})
    assert not scan({"disk": "scsi-335d73dfb65d47d90-part1"})


def test_bare_sixteen_hex_fires_only_beside_an_id_ish_key() -> None:
    """The key is the tiebreak: 16 hex under `devid` claims to identify; the
    same characters under a prose key are indistinguishable from a hash."""
    assert scan({"devid": "5000c500aabbccdd"})
    assert not scan({"note": "5000c500aabbccdd"})
    assert not scan({"devid": "35d73dfb65d47d90"})


# ── integer ranges no real interface exceeds ─────────────────────────────


def test_a_guid_sized_integer_under_an_id_key_fires() -> None:
    assert scan({"pool_guid": 12297829382473034410})


def test_the_scrub_band_is_quiet_and_a_capacity_is_not_an_id() -> None:
    assert not scan({"pool_guid": 18443322837869408100})  # 1844… band
    assert not scan({"total_space": 39994735460352})  # big, but not id-keyed
    assert not scan({"pool_guid": 5000})  # spa_version-sized


def test_an_integer_above_u64_fires_under_any_key() -> None:
    """No real interface emits one; only a broken scrub ever did."""
    assert scan({"harmless_looking": 2**64})


@pytest.mark.parametrize(
    "value,leaks",
    [
        ("5000116122791584830", True),  # 19 digits, real-shaped
        ("30000050057949013544", True),  # 20 digits AND above u64
        ("18443322837869408100", False),  # the band, within u64
        ("18449999999999999999", True),  # wears the prefix, exceeds u64
    ],
)
def test_long_decimal_strings(value: str, leaks: bool) -> None:
    assert bool(scan({"pool_guid": value})) is leaks


# ── prefix bases must be valid for their length ──────────────────────────


def test_an_invalid_cidr_base_fires_as_string_and_as_pair() -> None:
    assert "cidr" in classes(scan({"rule": "matched 192.0.2.135/10 here"}))
    assert "cidr" in classes(scan({"prefix": {"addr": "100.89.226.124", "len": 23}}))


def test_a_valid_base_is_quiet_in_both_shapes() -> None:
    assert "cidr" not in classes(scan({"prefix": {"addr": "100.112.228.0", "len": 23}}))
    assert "cidr" not in classes(
        scan({"rule": "100.64.0.0/10 fe80::/64"}, declares_address_fields=True)
    )


# ── machine-id shapes, either case ───────────────────────────────────────


@pytest.mark.parametrize(
    "value", ["4c6f6e646f6e2069732061206369747901", "4C6F6E646F6E2069732061206369747901"]
)
def test_thirty_two_hex_fires_in_either_case(value: str) -> None:
    assert "machine-id" in classes(scan({"id": value[:32]}))


def test_the_marked_thirty_two_hex_is_quiet() -> None:
    assert not scan({"id": "5cb0637ac05cf23aabf4b32eed9c7b08"})


# ── by-id serial tails ───────────────────────────────────────────────────


def test_a_by_id_serial_tail_fires() -> None:
    assert "serial" in classes(
        scan({"path": "/dev/disk/by-id/ata-EXAMPLEDISK_8CJ4VC2T-part1"})
    )


def test_the_anon_marked_tail_is_quiet() -> None:
    assert not scan({"path": "/dev/disk/by-id/ata-EXAMPLEDISK_ANON7F2A-part1"})


# ── private addresses where the manifest promises none ───────────────────


@pytest.mark.parametrize(
    "address", ["10.9.8.7", "100.71.9.42", "192.168.4.20", "fd12:3456::1"]
)
def test_a_private_address_fires_without_declared_address_fields(address: str) -> None:
    assert "address" in classes(scan({"v": address}))
    # …and is legitimate exactly where the manifest declares addresses live:
    # in-space substitution keeps a private replacement private.
    assert "address" not in classes(scan({"v": address}, declares_address_fields=True))


@pytest.mark.parametrize(
    "constant", ["10.0.0.0", "100.64.0.0", "fd7a:115c:a1e0::", "192.0.2.7"]
)
def test_constants_and_documentation_addresses_are_quiet(constant: str) -> None:
    """Range bases and the published tailnet prefix are facts about the
    internet; 192.0.2.x is where scrubbed globals are supposed to land."""
    assert "address" not in classes(scan({"v": constant}))


# ── the seven verified misses, pinned by name ────────────────────────────
#
# Each RED half was reproduced against the committed shape-guessing scrubber
# before replacement; the detector firing here is the independent catch that
# did not exist then.


def test_regression_devid_spells_the_wwn_without_0x() -> None:
    """The old scrubber's wwn pattern wanted 0x, devid never writes it, and a
    real drive's WWN went to the public corpus verbatim."""
    assert "identifier" in classes(
        scan({"devid": "scsi-35000c500aabbccdd-part1"})
    )


def test_regression_an_integer_guid_is_not_invisible() -> None:
    """The old scrubber only rewrote strings, so a pool GUID emitted as a
    JSON integer — which is how zpool status emits it — passed untouched."""
    assert scan({"pool_guid": 12297829382473034410})


def test_regression_a_guid_above_u64_is_flagged_in_both_types() -> None:
    """The old replacement prepended a digit and kept the width, producing
    values no 64-bit interface can emit — 30000050057949013544 is committed
    corpus. As a string it is a long-decimal finding; as an integer it is an
    impossible value under any key."""
    assert scan({"pool_guid": "30000050057949013544"})
    assert scan({"pool_guid": 30000050057949013544})


def test_regression_the_slash23_that_was_not_a_base() -> None:
    """Substituting the address without masking produced 100.89.226.124/23 —
    an address where a network base belongs (reproduced verbatim from the
    old tool). The pair form is what nftables JSON actually carries."""
    assert "cidr" in classes(scan({"prefix": {"addr": "100.89.226.124", "len": 23}}))


def test_regression_topology_is_not_an_address() -> None:
    """scsi-0:0:0:0 and a PCI path are the shapes the old scrubber ate as
    IPv6. The detectors must not repeat the shape-guess in reverse: bus
    topology is not a finding."""
    assert not scan(
        {"phys_path": "pci-0000:03:00.0-sas-phy2-lun-0", "target": "scsi-0:0:0:0"}
    )


def test_regression_a_hostname_survives_no_boundary() -> None:
    """`_` is a word character, so the old \\b-anchored pattern walked past
    tank/<host>_backups. The detector matches by substring, boundaries be
    damned — the caller who names the hosts wants them found."""
    text = {"dataset": "tank/examplehost_backups"}
    assert "hostname" in classes(scan(text, hostnames=["examplehost"]))
    assert not scan(text)  # without the names there is nothing to know


def test_regression_check_is_no_longer_the_scrubbers_echo(tmp_path: Path) -> None:
    """The old --check grepped with the scrubber's own patterns, so a file
    the scrubber had missed was reported `clean` (exit 0, reproduced). The
    check is rewired to the detectors and MUST fail on that very file."""
    leaky = tmp_path / "leaky.json"
    leaky.write_text(json.dumps({
        "devid": "scsi-35000c500aabbccdd-part1",
        "dataset": "tank/examplehost_backups",
    }))
    proc = subprocess.run(
        [sys.executable, str(ANONYMISE), "--check",
         "--hostnames", "examplehost", str(leaky)],
        capture_output=True, text=True,
    )
    assert proc.returncode != 0, "a leaky file passed --check again"
    assert "finding" in proc.stdout


# ── the second review's misses, pinned by name ───────────────────────────
#
# Each probe below was run against the rebuilt detectors before its fix and
# reported nothing — deny-by-default in name only. The quiet halves prove
# the new detectors discriminate rather than merely fire.


def test_regression_a_vendor_oui_mac_is_a_finding() -> None:
    """No MAC detector existed at all: a real vendor-OUI address passed bare
    and inside an ether-saddr rule alike."""
    assert "mac" in classes(scan({"mac": "3c:22:fb:11:22:33"}))
    assert "mac" in classes(
        scan({"rule": "ether saddr 3c:22:fb:11:22:33 accept"})
    )


def test_scrubbed_and_group_macs_are_quiet() -> None:
    """02:/03: is the locally-administered scrub convention; broadcast, the
    multicast mappings and the 802.1D group are the same on every LAN."""
    for quiet in ("02:1f:00:9c:44:5a", "03:33:44:55:66:77",
                  "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb",
                  "33:33:00:00:00:01", "01:80:c2:00:00:00"):
        assert not scan({"mac": quiet}), quiet


def test_regression_a_public_ipv4_is_a_finding_in_any_regime() -> None:
    """Only private/CGNAT spaces were examined, so the most identifying
    address there is — a real global — passed in both manifest regimes.
    Scrubbed globals land in documentation space; a live one is always real."""
    assert "address" in classes(scan({"v": "89.58.41.7"}))
    assert "address" in classes(
        scan({"v": "89.58.41.7"}, declares_address_fields=True)
    )


def test_regression_a_global_ipv6_is_a_finding_in_any_regime() -> None:
    """v6 was never examined for global scope: only a ULA pattern existed."""
    assert "address" in classes(scan({"v": "2a02:8010:abcd::1"}))
    assert "address" in classes(
        scan({"v": "2a02:8010:abcd::1"}, declares_address_fields=True)
    )


def test_documentation_and_non_global_spaces_stay_quiet() -> None:
    """The deny side is global scope, not v6-ness: documentation, link-local
    and ULA spaces are exactly where legitimate material lives."""
    for quiet in ("192.0.2.7", "2001:db8::17", "fe80::1c9a:22ff:fe33:4455",
                  "fd7a:115c:a1e0::f9fc"):
        assert "address" not in classes(
            scan({"v": quiet}, declares_address_fields=True)
        ), quiet


def test_regression_an_nvme_by_id_tail_is_a_finding() -> None:
    """The tail detector enumerated ata|scsi|sas|usb — fewer bus spellings
    than the scrubber it checks, inverting the intended asymmetry. An nvme
    serial tail passed whole."""
    assert "serial" in classes(scan(
        {"path": "/dev/disk/by-id/nvme-EXAMPLE_SSD_1TB_S649NX0T702123B"}
    ))
    assert not scan(
        {"path": "/dev/disk/by-id/nvme-EXAMPLE_SSD_1TB_ANON7F2A9C-part1"}
    )


def test_regression_a_bare_0x_wwn_is_a_finding_in_free_text() -> None:
    """smartctl and zdb print WWNs as plain 0x hex literals — a spelling the
    scrubber knew and the checker did not."""
    assert "identifier" in classes(
        scan({"note": "disk 0x5000c500aabbccdd reported errors"})
    )
    assert not scan({"note": "disk 0x35d73dfb65d47d90 reported errors"})


def test_regression_a_short_guid_string_fires_under_an_id_key() -> None:
    """LONG_DECIMAL floored at 19 digits, but ~5% of real u64 guids are 18
    digits or fewer. Under an id-ish key the floor is 16; elsewhere the old
    floor stands, because a shortish number in prose is too common a shape."""
    assert scan({"pool_guid": "584837779264247573"})   # 18 digits, real-shaped
    assert scan({"vdev_guid": "58483777926424757"})    # 17 digits
    assert not scan({"pool_guid": "184411112222333344"})  # 18 digits, in band
    assert not scan({"note": "584837779264247573"})    # not claiming identity


def test_regression_a_dashed_uuid_fires_under_an_id_key() -> None:
    """A dashed UUID under an id-ish key is a boot/fs/partition identity, and
    no detector looked: the dashes break the 32-hex shape. Quiet: the 5cb0
    scrub marker, the nil UUID (a non-value — DESIGN 19's regime rules own
    it, it identifies nobody), the reference collector's published replay
    stand-in, and prose keys that claim nothing."""
    assert "uuid" in classes(
        scan({"boot_id": "8f14e45f-ceea-467f-a34e-9dcbd54a2c13"})
    )
    for key, value in [
        ("boot_id", "5cb0e45f-ceea-467f-a34e-9dcbd54a2c13"),
        ("boot_id", "00000000-0000-0000-0000-000000000000"),
        ("boot_id", "5e000000-0000-4000-8000-000000000001"),
        ("note", "8f14e45f-ceea-467f-a34e-9dcbd54a2c13"),
    ]:
        assert "uuid" not in classes(scan({key: value})), (key, value)


def test_regression_a_package_version_is_not_an_address() -> None:
    """The packages capture's four false positives, and the line the fix holds.

    alsa-topology-conf 1.2.5.1-3build1 and libasound2-data 1.2.15.3-1ubuntu1.1
    are dotted quads whose every component is 0..255, so the address detector
    read four Ubuntu package versions as live global addresses and the whole
    committed corpus went red on a payload carrying nothing identifying at
    all. The discriminator is the release field — a hyphen, a digit, a run
    with a letter — which is how Debian and RPM spell one and no address is
    written. Both directions, because a detector narrowed by a shape has to
    prove it kept the shapes it was narrowed around: an address followed by a
    letter-led word is still a finding (that is a hostname beside an address,
    not a release), an address range is still a finding, and a version with no
    release field at all is still a finding — which is the side to be wrong on.
    """
    for quiet in ("1.2.5.1-3build1", "1.2.15.3-1ubuntu1.1",
                  "1.2.15.3-1ubuntu1.5", "1.07.1-4build1"):
        assert "address" not in classes(scan({"v": quiet})), quiet
    for loud in ("89.58.41.7-router", "89.58.41.7-89.58.41.9", "89.58.41.7",
                 "1.2.5.1"):
        assert "address" in classes(scan({"v": loud})), loud


def test_regression_a_name_field_must_not_noop_silently(tmp_path: Path) -> None:
    """The demonstrated F2 leak: a manifest classifying an operator-chosen
    pool name as content/name, a run given no names source, the tool printing
    `scrubbed` — and the name walking through verbatim as dict key AND value.
    Layer 1 refuses the run up front; layer 2 refuses any leaf a substituting
    class hands back unchanged, naming the path; and the guard discriminates:
    the same run with the name supplied succeeds and substitutes it."""
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "pools.~key": {"discloses": "content", "format": "name"},
        "pools.*.name": {"discloses": "content", "format": "name"},
        "pools.*.pool_guid": {"discloses": "identity", "format": "guid_u64"},
    }))
    original = {"pools": {"operatorpool": {
        "name": "operatorpool", "pool_guid": 12297829382473034410}}}
    payload = tmp_path / "payload.json"
    env = {**os.environ, "SE_SCRUB_SECRET": "conformance-fixed-secret"}

    def run(*extra: str) -> subprocess.CompletedProcess:
        payload.write_text(json.dumps(original))
        return subprocess.run(
            [sys.executable, str(ANONYMISE), "--manifest", str(manifest),
             *extra, str(payload)],
            capture_output=True, text=True, env=env,
        )

    proc = run()  # layer 1: no names source at all
    assert proc.returncode != 0, "a nameless run scrubbed name fields again"
    assert "--hostnames" in proc.stderr and "pools.*.name" in proc.stderr
    assert json.loads(payload.read_text()) == original, "refusal must write nothing"

    proc = run("--check")  # the check is refused the same blindness
    assert proc.returncode != 0
    assert "--hostnames" in proc.stderr

    proc = run("--hostnames", "someothername")  # layer 2: the list misses the pool
    assert proc.returncode != 0, "an unengaged substitution shrugged again"
    assert "pools.operatorpool.name" in proc.stderr
    assert "unchanged" in proc.stderr
    assert json.loads(payload.read_text()) == original, "refusal must write nothing"

    proc = run("--hostnames", "operatorpool")  # the guard discriminates
    assert proc.returncode == 0, proc.stderr
    assert "operatorpool" not in json.dumps(json.loads(payload.read_text()))


def run_anonymise(payload, manifest, state, hostnames: str = "") -> int:
    """Drive the real tool the way a capture does, and return its exit code."""
    env = {**os.environ, "SE_SCRUB_SECRET": "conformance-fixed-secret"}
    argv = [sys.executable, str(ANONYMISE), "--manifest", str(manifest),
            "--map", str(state)]
    if hostnames:
        argv += ["--hostnames", hostnames]
    return subprocess.run(argv + [str(payload)], capture_output=True,
                          text=True, env=env).returncode


def test_prose_may_honestly_carry_no_identifier(tmp_path: Path) -> None:
    """A journal MESSAGE that contains nothing identifying is not a hole.

    The survived-unchanged gate exists for a real leak: a pool name classified
    as substituting, left verbatim by a run that then printed `scrubbed`. That
    reasoning holds for every format whose whole VALUE is the identifier, and
    breaks for unbounded text — a log line, a syslog record, a command line —
    where carrying no identifier is the ordinary case and refusing it would
    mean a corpus can never contain prose at all.

    So `format: prose` exempts that one refusal and nothing else. Both
    directions are asserted here, because an exemption nobody bounded is an
    escape hatch: prose that DOES embed a hostname must still come back
    substituted, and every other class must still refuse when nothing engaged.
    """
    payload = tmp_path / "journal.json"
    manifest = tmp_path / "m.json"
    state = tmp_path / "map.json"

    payload.write_text(json.dumps({
        "MESSAGE": "Started Daily apt download activities.",   # nothing in it
        "SPEAKING": "connection from labhost-9 accepted",      # a name in it
    }))
    manifest.write_text(json.dumps({
        "MESSAGE": {"discloses": "content", "format": "prose"},
        "SPEAKING": {"discloses": "content", "format": "prose"},
    }))
    code = run_anonymise(payload, manifest, state, hostnames="labhost-9")
    assert code == 0, "prose carrying no identifier is not a refusal"

    after = json.loads(payload.read_text())
    assert after["MESSAGE"] == "Started Daily apt download activities.", (
        "prose with nothing in it comes back verbatim — substituting it would "
        "corrupt the capture to satisfy a gate"
    )
    assert "labhost-9" not in after["SPEAKING"], (
        "prose is NOT an exemption from scrubbing: the free-text pass still "
        "runs, and a name written inside a log line is still substituted"
    )


def test_the_survived_unchanged_gate_still_refuses_every_other_class(tmp_path: Path) -> None:
    """The reversion for the test above, as its own test.

    If `prose` had been implemented by relaxing the gate for any entry without
    a format — the smaller change, and the tempting one — this would pass
    while thirty formatless entries in the shipped manifests silently stopped
    being checked. It fails instead, which is the evidence that the exemption
    is scoped to the one format that claims it.
    """
    payload = tmp_path / "p.json"
    manifest = tmp_path / "m.json"
    state = tmp_path / "map.json"
    # ONE leaf, formatless, and that is the whole point of the fixture. An
    # earlier version of this test also carried a `format: name` leaf, which
    # refused under BOTH implementations and made the test pass whether or not
    # the exemption was scoped — it pinned nothing, and only running the
    # reversion showed it.
    payload.write_text(json.dumps({"note": "tank"}))
    manifest.write_text(json.dumps({"note": {"discloses": "content"}}))
    code = run_anonymise(payload, manifest, state, hostnames="")
    assert code != 0, (
        "a formatless substituting class that changed nothing must still "
        "refuse — that is the pool name which outlived a run printing "
        "`scrubbed`, and exempting it along with prose would retire the gate "
        "for thirty entries in the shipped manifests"
    )


def test_a_prose_manifest_declares_that_addresses_may_appear() -> None:
    """The one bit the detectors take from a manifest must include prose.

    `_declares_addresses` tells the detectors whether a private address in this
    payload is expected or is a finding. It enumerated ipv4 and ipv6, and was
    not extended when `prose` was ruled in — so a manifest whose address-bearing
    fields are all prose read as "this file declares none", which is precisely
    the misreading the predicate exists to prevent, aimed at the scrubber's own
    output. The first journal payload produced twenty-seven findings, every one
    of them an address the free-text pass had correctly substituted RFC1918 to
    RFC1918.

    The vocabulary now lives once, beside the detectors that consume it, because
    two copies drifted apart the moment prose landed and which one governed
    depended on whether you were scrubbing or checking.
    """
    assert "prose" in detectors.ADDRESS_BEARING_FORMATS, (
        "a prose leaf may hold an address inside it, so a manifest carrying one "
        "has declared that addresses may appear"
    )
    for shaped in ("ipv4", "ipv6"):
        assert shaped in detectors.ADDRESS_BEARING_FORMATS

    # And the other direction: a format that cannot hold an address must not
    # widen the predicate, or every manifest would declare addresses and the
    # detectors' address rule would be switched off everywhere.
    for narrow in ("mac", "wwn", "serial", "guid_u64", "hostname", "name", "path"):
        assert narrow not in detectors.ADDRESS_BEARING_FORMATS, narrow


def test_the_scrubber_and_the_conformance_guard_read_one_vocabulary() -> None:
    """Two copies of a predicate is the fourth-copy failure, in the guard that
    decides what may be published. Both sides now import the same set, so a
    format added for one is added for the other."""
    import importlib.util

    spec = importlib.util.spec_from_loader("se_anonymise_script", loader=None)
    module = importlib.util.module_from_spec(spec)
    source = ANONYMISE.read_text()
    assert "detectors.ADDRESS_BEARING_FORMATS" in source, (
        "se-anonymise must read the vocabulary from se_harness.detectors rather "
        "than spelling its own copy"
    )
    guard = (REPO / "conformance" / "test_corpus_is_scrubbed.py").read_text()
    assert "detectors.ADDRESS_BEARING_FORMATS" in guard, (
        "the conformance guard must read the same one"
    )
    assert module is not None  # the loader is unused; the source read is the test
