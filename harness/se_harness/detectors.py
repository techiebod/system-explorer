"""The publish gate's second opinion: deny-by-default leak detectors.

The old --check grepped a scrubbed file with the scrubber's own patterns, so
it could only confirm the removal it had just performed — 0 detections in 300
fuzzed runs, by construction. A verifier that shares the remover's knowledge
agrees with every mistake the remover will ever make (DESIGN 21).

So this module shares NOTHING with harness/bin/se-anonymise: no pattern, no
table, no code path. Knowledge is duplicated deliberately — a bug in one side
is a red run, not a silent agreement.

What the two sides do share is a published CONVENTION, because a scrub that
preserves shape is otherwise indistinguishable from the original by any test
that has no key: an anonymised identifier lands in a locally-assigned or
documentation space, exactly as a scrubbed MAC becomes 02:… and a scrubbed
global address becomes 192.0.2.x. The convention, restated independently here:

  16-hex identifier bodies   first nibble 3 (NAA locally-assigned)
  32-hex identifiers         first four nibbles 5cb0 (dashed UUIDs included)
  guid_u64 decimal strings   prefix 1844 (the 2^64 band), <= 2^64-1
  by-id serial tails         start ANON
  MAC sextets                first octet 02 (unicast) or 03 (group)
  addresses                  documentation ranges, or their original space —
                             never a globally-routable address, in ANY file

A real identifier wears a vendor's marks — an NAA 5/6 nibble, a registered
OUI, a manufacturer serial — so anything outside the convention is treated as
real and flagged. The residual risk is a real value that happens to sit inside
a convention space (a genuinely locally-assigned WWN, a real GUID starting
1844…); that channel is why the scrubber's manifest walk refuses unclassified
fields rather than leaning on this gate alone.

Each detector returns (path, value-class, why). Callers pass context this
module must not infer for itself: whether the file's manifest declares any
address fields (private in-space replacements are legitimate only there), and
the estate's hostnames if they are willing to name them.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, NamedTuple

U64_MAX = 2**64 - 1


class Finding(NamedTuple):
    """One suspected leak: where it sits, what kind of value, and why."""

    path: str
    value_class: str
    why: str


# ── the convention, as this side states it ───────────────────────────────

GUID_BAND_PREFIX = "1844"  # scrubbed u64s live under the 2^64 = 18446… ceiling
HEX32_MARKER = "5cb0"  # scrubbed 32-hex identifiers announce themselves
SERIAL_MARKER = "ANON"  # scrubbed by-id serial tails


def _hex16_is_scrubbed(body: str) -> bool:
    # NAA nibble 3 is "locally assigned" — the one spelling that names no
    # vendor, which is what makes it honest for a stand-in. All-decimal
    # bodies are u64 GUIDs rendered in hex-compatible characters, so they
    # answer to the decimal band instead.
    if body.isdigit():
        return body.startswith(GUID_BAND_PREFIX)
    return body[0] in "3"


def _decimal_is_scrubbed(digits: str) -> bool:
    return digits.startswith(GUID_BAND_PREFIX) and int(digits) <= U64_MAX


# ── detector patterns: written fresh, not imported ───────────────────────

# NAA/EUI identifiers in every spelling the estate's tooling has produced —
# including the bare 0x one: smartctl and zdb both print a WWN as a plain
# 0x-prefixed hex literal, and a list without it passed a real WWN in free
# text while catching the identical body in by-id dress.
SPELLED_ID = re.compile(
    r"(?i)\b(wwn-0x|scsi-3|naa\.|nvme-eui\.|eui\.|0x)([0-9a-f]{32}|[0-9a-f]{16})"
)
BARE_HEX16 = re.compile(r"\b[0-9a-fA-F]{16}\b")
HEX32 = re.compile(r"\b[0-9a-fA-F]{32}\b")  # machine-id shape, either case
# The u64 GUID neighbourhood. 19-20 digits is unmistakable anywhere; under an
# id-ish key the floor drops to 16, because a uniformly random u64 is below
# 10^19 about one time in twenty — a real guid short enough to dodge the
# 19-digit floor is a ~5% event, not a curiosity.
LONG_DECIMAL = re.compile(r"\b\d{19,20}\b")
ID_LONG_DECIMAL = re.compile(r"\b\d{16,20}\b")
# Every bus the by-id namer writes a <model>_<serial> tail for — authored
# from udev's spellings, deliberately not from the scrubber's own list: the
# scrubber knowing fewer spellings than its checker is the asymmetry that
# catches the miss (nvme was exactly such a gap).
BYID_TAIL = re.compile(
    r"\b((?:ata|scsi|sas|usb|nvme|mmc|memstick|virtio|ieee1394)-[\w.\-]+)"
    r"_([A-Za-z0-9]{4,})\b"
)
# A dashed UUID: boot ids, filesystem ids, partition ids. Scrubbed ones carry
# the 5cb0 marker in their first four nibbles like any other 32-hex identity.
UUID_SHAPE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
NIL_UUID = "00000000-0000-0000-0000-000000000000"  # a non-value, not a leak
# The reference collector's published replay stand-in (DESIGN 19: a constant
# boot_id is the honest bound of what replay can authenticate). Restated here,
# not imported: it identifies the harness, never a machine.
REPLAY_BOOT_ID = "5e000000-0000-4000-8000-000000000001"
# A MAC sextet, fenced so the first six groups of an all-2-hex-group IPv6
# cannot volunteer. Scrubbed MACs are locally administered and vendorless:
# first octet 02, or 03 for a group address.
MAC_SEXTET = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])"
)
CIDR = re.compile(
    r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+)/(\d{1,3})\b"
)
V4_ADDR = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# The manifest formats under which a payload may legitimately hold an address.
#
# This is the ONE bit these detectors take from a scrub manifest — DESIGN 21
# forbids them any more of the collector's vocabulary, because a detector that
# knew what the collector knew would agree with it about the same blind spots.
# It lives HERE, with its consumer, and the scrubber imports it: two copies
# drifted apart the moment `prose` was ruled in, and which copy governed
# depended on whether you were scrubbing or checking.
#
# `prose` was missing from that vocabulary at first, which made the gate refuse
# a manifest for the scrubber's OWN work — the free-text pass substitutes an
# address inside a log line RFC1918 to RFC1918, and a manifest whose
# address-bearing fields are all prose then read as "declares none", the exact
# misreading the predicate exists to prevent. A set, not a literal tuple,
# because enumerating the formats its author had met is the whole defect.
ADDRESS_BEARING_FORMATS = frozenset({"ipv4", "ipv6", "prose"})
# The release field of a package version, which is what follows a dotted quad
# that is not an address: alsa-topology-conf is 1.2.5.1-3build1 and
# libasound2-data is 1.2.15.3-1ubuntu1.1 — four components, every one of them
# 0..255, and an IPv4 address by shape alone. Debian and RPM spell a release
# as a hyphen, a digit, and a run that carries a letter, and nothing that is
# an address is written that way. The leading digit is load-bearing: it keeps
# 10.0.0.1-router a finding, so this narrows the address detector by one
# notation rather than by every hyphen. The bound: a version with no release
# field at all (a bare "1.2.3.4") stays indistinguishable from an address and
# still fires, which is the side to be wrong on.
VERSION_RELEASE = re.compile(r"-\d[0-9A-Za-z.+~]*[A-Za-z]")
# Any colon-grouped hex run is a v6 CANDIDATE; ipaddress is the arbiter, so
# timestamps, SCSI targets and PCI functions fall out as parse failures
# instead of being pattern-guessed away (the DESIGN 21 lesson, in reverse).
V6_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:])"
)

# Keys under which a bare number, hex run or UUID is claiming to identify
# something.
ID_KEY = re.compile(r"(?i)(wwn|guid|serial|devid|uuid|(^|[_-])id([_-]|$))")

# This side's own copy of the well-known constants that may appear anywhere:
# protocol-assigned, identical on every machine on earth. Duplicated from the
# shipped table on purpose — importing it would let one wrong edit blind both
# the scrubber and its checker in the same stroke.
KNOWN_PRIVATE_V4 = {"10.0.0.0", "172.16.0.0", "192.168.0.0", "100.64.0.0"}
KNOWN_PRIVATE_V6 = {"fc00::", "fd00::", "fd7a:115c:a1e0::"}  # incl. Tailscale's

# Group MACs every LAN on earth shares, written down from the protocols that
# assign them — broadcast, the IPv4 and IPv6 multicast mappings, 802.1D —
# not read out of the scrubber's keep table.
KNOWN_GROUP_MACS = {"ff:ff:ff:ff:ff:ff"}
KNOWN_GROUP_MAC_PREFIXES = ("01:00:5e", "33:33", "01:80:c2")

PRIVATE_V4_SPACES = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
]
ULA = ipaddress.ip_network("fc00::/7")


# ── the walk ─────────────────────────────────────────────────────────────


def scan(
    document: object,
    *,
    declares_address_fields: bool = False,
    hostnames: Iterable[str] = (),
) -> list[Finding]:
    """Every finding in one parsed document (payload, stream record, meta).

    `declares_address_fields` is the one manifest-derived bit this checker
    accepts, and only as a boolean computed by the caller: a file whose
    manifest declares address fields legitimately contains in-space private
    replacements, and one that declares none must contain no private address
    at all. `hostnames` arms the substring detector for callers willing to
    name the machines.
    """
    findings: list[Finding] = []
    lowered = [h.lower() for h in hostnames if h]
    _scan_node(document, "", "", findings, declares_address_fields, lowered)
    return findings


def _scan_node(
    node: object,
    path: str,
    key: str,
    findings: list[Finding],
    declares_addresses: bool,
    hostnames: list[str],
) -> None:
    if isinstance(node, dict):
        _check_prefix_pair(node, path, findings)
        for k, v in node.items():
            child = f"{path}.{k}" if path else str(k)
            if isinstance(k, str):
                # keys are a leak channel of their own: a dict of disks is
                # keyed by the very WWNs its values also carry
                _scan_text(k, child, str(k), findings, declares_addresses, hostnames)
            _scan_node(v, child, str(k), findings, declares_addresses, hostnames)
        return
    if isinstance(node, list):
        for i, v in enumerate(node):
            _scan_node(v, f"{path}.{i}" if path else str(i), key, findings,
                       declares_addresses, hostnames)
        return
    if isinstance(node, bool) or node is None:
        return
    if isinstance(node, int):
        _scan_int(node, path, key, findings)
        return
    if isinstance(node, str):
        _scan_text(node, path, key, findings, declares_addresses, hostnames)


def _scan_int(value: int, path: str, key: str, findings: list[Finding]) -> None:
    if value > U64_MAX:
        findings.append(Finding(
            path, "integer",
            f"{value} exceeds 2^64-1 — no real interface emits it; "
            "a scrub artefact or a corrupted capture",
        ))
        return
    if value >= 2**48 and ID_KEY.search(key) and not _decimal_is_scrubbed(str(value)):
        findings.append(Finding(
            path, "identifier-integer",
            f"{value} under id-ish key {key!r} is in the range real GUIDs and "
            f"WWNs occupy, and is not in the {GUID_BAND_PREFIX}… scrub band",
        ))


def _check_prefix_pair(node: dict, path: str, findings: list[Finding]) -> None:
    """An {addr, len} pair must be a valid base for its own length."""
    addr, length = node.get("addr"), node.get("len")
    if not isinstance(addr, str) or not isinstance(length, int):
        return
    try:
        ipaddress.ip_network((addr, length), strict=True)
    except ValueError:
        findings.append(Finding(
            path, "cidr",
            f"{addr}/{length} is not a valid base for its length — "
            "the mark of a substitution that ignored the mask",
        ))


def _scan_text(
    text: str,
    path: str,
    key: str,
    findings: list[Finding],
    declares_addresses: bool,
    hostnames: list[str],
) -> None:
    spelled_spans: list[tuple[int, int]] = []
    for m in SPELLED_ID.finditer(text):
        spelled_spans.append(m.span())
        if not _hex16_is_scrubbed(m.group(2).lower()):
            findings.append(Finding(
                path, "identifier",
                f"{m.group(0)} spells an NAA/EUI identifier outside the "
                "locally-assigned convention — a real drive's name",
            ))

    def in_spelled(span: tuple[int, int]) -> bool:
        return any(a <= span[0] and span[1] <= b for a, b in spelled_spans)

    id_keyed = bool(ID_KEY.search(key))
    if id_keyed:
        for m in BARE_HEX16.finditer(text):
            if m.group(0).isdigit():
                continue  # all-decimal runs answer to the decimal band below
            if in_spelled(m.span()) or _hex16_is_scrubbed(m.group(0).lower()):
                continue
            findings.append(Finding(
                path, "identifier",
                f"bare 16-hex {m.group(0)} beside id-ish key {key!r}",
            ))
        for m in UUID_SHAPE.finditer(text):
            low = m.group(0).lower()
            if low in (NIL_UUID, REPLAY_BOOT_ID):
                continue
            if low.replace("-", "").startswith(HEX32_MARKER):
                continue
            findings.append(Finding(
                path, "uuid",
                f"dashed UUID {m.group(0)} beside id-ish key {key!r} carries "
                f"no {HEX32_MARKER}… scrub marker — a real boot/fs/partition id",
            ))

    for m in HEX32.finditer(text):
        if in_spelled(m.span()) or m.group(0).lower().startswith(HEX32_MARKER):
            continue
        findings.append(Finding(
            path, "machine-id",
            f"32-hex {m.group(0)} is the machine-id shape and carries no "
            f"{HEX32_MARKER}… scrub marker",
        ))

    # Under an id-ish key the decimal floor drops to 16 digits: ~5% of real
    # u64 guids are short enough to slip a 19-digit floor, and the key has
    # already said the number claims to identify something.
    decimal = ID_LONG_DECIMAL if id_keyed else LONG_DECIMAL
    for m in decimal.finditer(text):
        if not _decimal_is_scrubbed(m.group(0)):
            findings.append(Finding(
                path, "identifier-integer",
                f"{m.group(0)} is a {len(m.group(0))}-digit decimal — the u64 "
                f"GUID neighbourhood — outside the {GUID_BAND_PREFIX}… scrub band",
            ))

    for m in MAC_SEXTET.finditer(text):
        low = m.group(0).lower()
        if low in KNOWN_GROUP_MACS or low.startswith(KNOWN_GROUP_MAC_PREFIXES):
            continue  # protocol-assigned, identical on every LAN on earth
        if low.startswith(("02:", "03:")):
            continue  # locally administered and vendorless: the scrubbed shape
        findings.append(Finding(
            path, "mac",
            f"MAC {m.group(0)} wears a registered OUI, not the locally-"
            "administered 02:/03: scrub convention — a real interface's address",
        ))

    for m in BYID_TAIL.finditer(text):
        if m.group(1).lower().startswith("scsi-3") or in_spelled(m.span()):
            continue  # the NAA spelling already answered for it
        if not m.group(2).startswith(SERIAL_MARKER):
            findings.append(Finding(
                path, "serial",
                f"by-id tail {m.group(0)} ends in a serial without the "
                f"{SERIAL_MARKER} marker",
            ))

    for m in CIDR.finditer(text):
        base, length = m.group(1), int(m.group(2))
        try:
            ipaddress.ip_address(base)
        except ValueError:
            continue  # not an address at all — a version string, a ratio
        try:
            ipaddress.ip_network((base, length), strict=True)
        except ValueError:
            findings.append(Finding(
                path, "cidr",
                f"{base}/{length} is not a valid base for its length",
            ))

    # A private address is legitimate exactly where the manifest declares
    # address fields (in-space substitution keeps a replacement private). A
    # GLOBALLY ROUTABLE address is legitimate nowhere: the convention lands
    # every scrubbed global in documentation space, so a live global — the
    # most identifying address there is — is a leak whatever the manifest
    # says. ipaddress classifies; the deny side is everything it cannot put
    # in private/CGNAT/loopback/link-local/multicast/documentation/ULA.
    for m in V4_ADDR.finditer(text):
        if VERSION_RELEASE.match(text, m.end()):
            continue  # a package version's upstream half, not an address
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if ip.is_global and not ip.is_multicast:
            findings.append(Finding(
                path, "address",
                f"{m.group(0)} is a globally routable IPv4 address — scrubbed "
                "globals land in documentation space, so this one is real",
            ))
        elif not declares_addresses \
                and any(ip in net for net in PRIVATE_V4_SPACES) \
                and m.group(0) not in KNOWN_PRIVATE_V4:
            findings.append(Finding(
                path, "address",
                f"{m.group(0)} is a private/CGNAT address in a file whose "
                "manifest declares no address fields",
            ))
    for m in V6_CANDIDATE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue  # a timestamp, a bus address — not this detector's business
        if ip.is_global and not ip.is_multicast:
            findings.append(Finding(
                path, "address",
                f"{m.group(0)} is a globally routable IPv6 address — scrubbed "
                "globals land in documentation space, so this one is real",
            ))
        elif not declares_addresses and ip in ULA \
                and m.group(0).lower() not in KNOWN_PRIVATE_V6:
            findings.append(Finding(
                path, "address",
                f"{m.group(0)} is a ULA address in a file whose manifest "
                "declares no address fields",
            ))

    lowered = text.lower()
    for host in hostnames:
        if host in lowered:
            # substring on purpose, no word boundary: tank/<host>_backups is
            # exactly the miss the boundary-anchored grep committed
            findings.append(Finding(
                path, "hostname",
                f"hostname {host!r} appears in {text!r}",
            ))
