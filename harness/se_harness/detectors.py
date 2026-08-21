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
# systemd's published message catalogue, as systemd itself lists it.
#
# THE PROBLEM THIS SOLVES, because it is the one shape §21's independence rule
# makes structurally unfixable anywhere else. A journal entry carries BOTH a
# `_MACHINE_ID` — a real identity that must be substituted — and a `MESSAGE_ID`,
# systemd's catalogue id for the message TYPE, compiled into the software and
# byte-identical on every machine on earth. Both are 32 hex. After a scrub the
# first carries the 5cb0 marker and this checker passes it; the second is
# untouched, correctly, and this checker flagged all of them. Every systemd host
# emits catalogue ids, so no capture of the journal could ever pass, and `logs`
# had no corpus at all.
#
# The repair could NOT be on the manifest side: §21 gives these detectors one
# manifest-derived bit and forbids them the collector's vocabulary, because a
# checker that knew what the collector knew would share its blind spots. So this
# is not the collector's opinion — it is a published, external, closed set,
# restated here exactly as REPLAY_BOOT_ID and NIL_UUID are restated rather than
# imported. A reviewer can check any line of it against systemd.
#
# Deny-by-default survives intact, which is the whole reason this is a VALUE
# allowlist and not a field one: a 32-hex value in any field that is not one of
# these and carries no scrub marker is still a finding. A real machine-id that
# landed in MESSAGE_ID would still be caught.
#
# Regenerate on a systemd host with:  journalctl --list-catalog | awk '{print $1}'
# A newer systemd publishes more ids, and a capture carrying one this table does
# not hold FAILS CLOSED — the fix is a reviewed line here, which is the point.
SYSTEMD_CATALOGUE_IDS = {
    "0027229ca0644181a76c4e92458afa2e":
        "systemd: One or more messages could not be forwarded to syslog",
    "010190138f494e29a0ef6669749531aa":
        "systemd: No valid unit name can be generated for device @DE...",
    "0e4284a0caca4bfc81c0bb6786972673": "systemd: Unit skipped",
    "0e54470984ac419689743d957a119e2e": "systemd: Failed to allocate manager object",
    "1675d7f172174098b1108bf8c7dc8f5d": "systemd: DNSSEC validation failed",
    "187c62eb1e7f463bb530394f52cb090f": "systemd: A Portable Service has been attached",
    "1b3bb94037f04bbf81028e135a12d293":
        "systemd: Failed to generate valid unit name from path '@MOU...",
    "1c0454c1bd2241e0ac6fefb4bc631433":
        "systemd: systemd-udev-settle.service is deprecated.",
    "1dee0369c7fc4736b7099b38ecb46ee7": "systemd: Mount point is not empty",
    "1edabb4eda2a49c19bc0206f24b43889": "systemd: Mount point path contains symlinks",
    "1f4e0a44a88649939aaea34fc6da8c95":
        "systemd: Process @COREDUMP_PID@ (@COREDUMP_COMM@) terminate...",
    "24d8d4452573402496068381a6312df2":
        "systemd: A virtual machine or container has been started",
    "267437d33fdd41099ad76221cc24a335":
        "systemd: Battery level critically low, powering off",
    "2ed18d4f78ca47f0a9bc25271c26adb4":
        "systemd: Init received fatal signal but waitpid() failed",
    "3354939424b4456d9802ca8333ed424a":
        "systemd: Session @SESSION_ID@ has been terminated",
    "3405205d368e49feb5ab3925fee13874":
        "systemd: Non-system user or group used for device ownership",
    "36db2dfa5a9045e1bd4af5f93e1cf057":
        "systemd: DNSSEC mode has been turned off, as server doesn't...",
    "375ac151ef9d4de39068b3efbfed0cee":
        "systemd: Opening of the configure watchdog device failed",
    "38e8b1e039ad469291b18b44c553a5b7": "systemd: Init failed to fork crash shell",
    "39f53479d3a045ac8e11786248231fbf":
        "systemd: A start job for unit @UNIT@ has finished successfully",
    "3a73a98baf5b4b199929e3226c0be783":
        "systemd: Init received fatal signal from other process",
    "3ed0163e868a4417ab8b9e210407a96c": "systemd: System reboot failed after crash",
    "3f7d5ef3e54f4302b4f0b143bb270cab": "systemd: TPM PCR Extended",
    "42695b500df048298bee37159caa9f2e":
        "systemd: Init failed to drop capability bounding set",
    "438188861e0b427a9d638a90487a0ca6": "systemd: TPM clear requested",
    "45f82f4aef7a4bbf942ce861d1f20990": "systemd: Time zone change to @TIMEZONE@",
    "4ac7566d4d7548f4981f629a28f0f829":
        "systemd: Init received fatal signal and dumped core",
    "4c2e46d266a747c6ac1460aa54484fa7": "systemd: TPM NvPCR Extended",
    "4d4408cfd0d144859184d1e65d7c8a65":
        "systemd: A DNSSEC trust anchor has been revoked",
    "5084367542f7472dbc6a94125d5debce":
        "systemd: Unit job deleted due to an ordering cycle",
    "50876a9db00f4c40bde1a2ad381c3a1b":
        "systemd: The system is configured in a way that might cause...",
    "56b1cd96f24246c5b607666fda952356":
        "systemd: Init received fatal signal but coredump failed",
    "58432bd3bace477cb514b56381b8a758":
        "systemd: A virtual machine or container has been terminated",
    "59288af523be43a28d494e41e26e4510":
        "systemd: Manager failed to start default target",
    "5aadd8e954dc4b1a8c954d63fd9e1137":
        "systemd: Core file was truncated to @SIZE_LIMIT@ bytes.",
    "5addb3a06a734d3396b794bf98fb2d01":
        "systemd: Init received fatal signal while coredump is disabled",
    "5c9e98de4ab94c6a9d04d0ad793bd903":
        "systemd: Init received fatal signal but fork failed",
    "5e6f1f5e4db64a0eaee3368249d20b94":
        "systemd: Init received fatal signal from unknown sender pro...",
    "5eb03494b6584870a536b337290809b3":
        "systemd: Automatic restarting of a unit has been scheduled",
    "5ed836f1766f4a8a9fc5da45aae23b29":
        "systemd: Manager failed to collect passed file descriptors",
    "641257651c1b4ec9a8624d7a40a9e1e7":
        "systemd: Process @EXECUTABLE@ could not be executed",
    "645c735537634ae0a32b15a7c6cba7d4": "systemd: Init execution froze",
    "658a67adc1c940b3b3316e7e8628834a": "systemd: Manager failed to load SELinux policy",
    "689b4fcc97b4486ea5da92db69c9e314":
        "systemd: Manager failed to isolate default target",
    "6a40fbfbd2ba4b8db02fb40c9cd090d7":
        "systemd: Init failed to fix up environment variables",
    "6bbd95ee977941e497c48be27c254128": "systemd: System sleep state @SLEEP@ entered",
    "76c5c754d628490d8ecba4c9d042112b": "systemd: A Portable Service has been detached",
    "79e05b67bc4545d1922fe47107ee60c5": "systemd: Manager failed to run main loop",
    "7ad2d189f7e94e70a38c781354912448": "systemd: Unit succeeded",
    "7b05ebc668384222baa8881179cfda54":
        "systemd: A reload job for unit @UNIT@ has finished",
    "7c8a41f37b764941a0e1780b1be2f037": "systemd: Initial clock synchronization",
    "7d4958e842da4a758f6c1cdc7b36dcc5":
        "systemd: A start job for unit @UNIT@ has begun execution",
    "7db73c8af0d94eeb822ae04323fe6ab6": "systemd: The system clock has been changed",
    "83f84b35ee264f74a3896a9717af34cb":
        "systemd: Init received fatal signal from our own process",
    "872729b47dbe473eb768ccecd477beda": "systemd: Crash shell failed to execute",
    "8739789eca064325af15a8ed0ecfc556":
        "systemd: Sending a keep-alive to the hardware watchdog devi...",
    "8811e6df2a8e40f58a94cea26f8ebf14": "systemd: System sleep state @SLEEP@ left",
    "8d45620c1a4348dbb17410da57c60c66":
        "systemd: A new session @SESSION_ID@ has been created for us...",
    "8f07a5b814ca4762b89fcc3082e48aed":
        "systemd: TPM NV index backed PCRs not supported on the loca...",
    "98268866d1d54a499c4e98921d93bc40": "systemd: System shutdown initiated",
    "98e322203f7a4ed290d09fe03c09fe15": "systemd: Unit process exited",
    "9cf56b8baf9546cf9478783a8de42113":
        "systemd: A foreign process changed a sysctl systemd-network...",
    "9d1aaa27d60140bd96365438aad20286":
        "systemd: A stop job for unit @UNIT@ has finished",
    "a596d6fe7bfa4994828e72309e95d61e":
        "systemd: Messages from a service have been suppressed",
    "a8fa8dacdb1d443e9503b8be367a6adb": "systemd: SysV Service Found",
    "ab984ea008964fb88d6e389fb513fb94":
        "systemd: TPM NV index space exhausted, unable to initialize...",
    "ad7089f928ac4f7ea00c07457d47ba8a":
        "systemd: Authorization failure while attempting to enroll S...",
    "ae8f7b866b0347b9af31fe1c80b127c0": "systemd: Resources consumed by unit runtime",
    "af55a6f75b544431b72649f36ff6d62c":
        "systemd: Critical error while doing system shutdown",
    "b07a249cd024414a82dd00cd181378ff": "systemd: System start-up is now complete",
    "b2bcbaf5edf948e093ce50bbea0e81ec":
        "systemd: The Secure Attention Key (SAK) was pressed on @SEA...",
    "b3112ddad19045538c76685ba5918a80":
        "systemd: Unable to break ordering cycle between units",
    "b480325f9c394a7b802c231e51a2752c":
        "systemd: Special user @OFFENDING_USER@ configured, this is ...",
    "b61fdac612e94b9182285b998843061f":
        "systemd: Accepting user/group name @USER_GROUP_NAME@, which...",
    "be02cf6855d2428ba40df7e9d022f03d":
        "systemd: A start job for unit @UNIT@ has failed",
    "bfc2430724ab44499735b4f94cca9295":
        "systemd: User manager failed to disable new privileges",
    "c14aaf76ec284a5fa1f105f88dfb061c": "systemd: System factory reset initiated",
    "c7a787079b354eaaa9e77b371893cd27": "systemd: Time change",
    "d18e0339efb24a068d9c1060221048c2":
        "systemd: Init failed to fork off valgrind helper",
    "d34d037fff1847e6ae669a370e694725":
        "systemd: A reload job for unit @UNIT@ has begun execution",
    "d67fa9f847aa4b048a2ae33535331adb":
        "systemd: Manager failed to write Smack onlycap list",
    "d93fb3c9c24d451a97cea615ce59c00b": "systemd: The journal has been stopped",
    "d989611b15e44c9dbf31e3c81256e4ed":
        "systemd: systemd-oomd killed one or more processes in unit ...",
    "d9b373ed55a64feb8242e02dbe79a49c": "systemd: Unit failed",
    "d9ec5e95e4b646aaaea2fd05214edbda": "systemd: Container init crashed",
    "dbb136b10ef4457ba47a795d62f108c9":
        "systemd: User manager failed to determine $XDG_RUNTIME_DIR ...",
    "de5b426a63be47a7b6ac3eaac82e2f6f":
        "systemd: A stop job for unit @UNIT@ has begun execution",
    "e6f456bd92004d9580160b2207555186":
        "systemd: Battery level critically low, waiting for charger",
    "e7852bfe46784ed0accde04bc864c2d5": "systemd: Seat @SEAT_ID@ has now been removed",
    "e9bf28e6e834481bb6f48f548ad13606": "systemd: Journal messages have been missed",
    "ec387f577b844b8fa948f33cad9a75e6": "systemd: Disk space used by the journal",
    "ed158c2df8884fa584eead2d902c1032":
        "systemd: Init failed to drop capability bounding set of use...",
    "eed00a68ffd84e31882105fd973abdd1": "systemd: User manager start-up is now complete",
    "f27a3f94406a4783b946a9bc849e9452": "systemd: Unit ordering cycle found",
    "f77379a8490b408bbe5f6940505a777b": "systemd: The journal has been started",
    "f9b0be465ad540d0850ad32172d57c21": "systemd: Memory Trimmed",
    "fc2e22bc6ee647b6b90729ab34a250b1":
        "systemd: Process @COREDUMP_PID@ (@COREDUMP_COMM@) dumped core",
    "fcbefc5da23d428093f97c82a9290f7b": "systemd: A new seat @SEAT_ID@ is now available",
    "fe6faa94e7774663a0da52717891d8ef":
        "systemd: A process of @UNIT@ unit has been killed by the OO...",
}

# OpenSSH's fingerprint rendering, which is an identifier with no other shape.
#
# `Accepted publickey for ... ED25519 SHA256:<43 base64 chars>` survived both
# the scrubber and these detectors verbatim: `prose` substitutes shapes and
# `--hostnames` removes words somebody chose, and a base64 hash is neither — so
# the only thing that reached it was naming it to the run, which means a capture
# carrying a fingerprint nobody named passed SILENTLY. A green --check on that
# payload was a false clean, which is the exact failure this gate exists to
# prevent.
#
# It is not a secret — it is a hash of a public key — but it correlates: anyone
# holding that key can recognise the estate it authenticates to. The `SHA256:`
# and `MD5:` prefixes are what make it findable, and they are OpenSSH's own
# spelling rather than anything this repository invented.
SSH_FINGERPRINT_MARKER = "ANON"  # what a substituted one starts with
SSH_FINGERPRINT = re.compile(
    r"\b(?:SHA256:[A-Za-z0-9+/]{43}=?|MD5:(?:[0-9a-f]{2}:){15}[0-9a-f]{2})\b"
)


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

# ── one channel this module deliberately does not read ───────────────────
#
# Every pattern above reads a string AS WRITTEN, and a producer that writes an
# identifier in its own escaping is therefore invisible here: systemd spells
# one partition UUID three ways in a single ListUnits row — plain in the
# device's description, `\x2d`-escaped in the unit name derived from it, and
# escaped again as `_5cx2d` in the object path derived from the name — and
# this module reports nothing on two of the three.
#
# Scanning the folded reading as well was tried and REMOVED, measured rather
# than argued. It caught none of those UUIDs, because a dashed UUID is only a
# finding under an id-ish key and a unit name is not one; and it invented two
# it could not resolve, because `dev-virtio\x2dports-org.qemu.guest_agent`
# folds into the by-id serial shape while `org.qemu.guest_agent` is a port
# name identical on every QEMU guest. A gate a correct capture cannot pass is
# not a gate, and the only ways past it were to weaken this module's serial
# rule or to let the scrubber mangle a meaningful name.
#
# So this channel has ONE opinion rather than two: the scrubber's `unit_name`
# and `object_path` formats, declared per leaf in the manifest, fold before
# they substitute. Named here because a bound nobody wrote down reads as
# coverage — and because the asymmetry is the shape this module exists to
# refuse, admitted deliberately in one place instead of arriving by accident.

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
        # systemd's catalogue ids wear this exact shape and identify a MESSAGE
        # TYPE rather than a machine — see SYSTEMD_CATALOGUE_IDS for why the
        # allowlist is on the VALUE and could not be on the field.
        if m.group(0).lower() in SYSTEMD_CATALOGUE_IDS:
            continue
        # All zeros identifies nobody — the nil-UUID reasoning, met again in
        # /proc/net's hex encoding, where the IPv6 any-address `::` is
        # spelled as exactly this. Only the one value: 31 zeros and a 1 is
        # back to being a finding.
        if m.group(0) == "0" * 32:
            continue
        findings.append(Finding(
            path, "machine-id",
            f"32-hex {m.group(0)} is the machine-id shape and carries no "
            f"{HEX32_MARKER}… scrub marker",
        ))

    # An identifier with no shape but its own prefix. Unconditional, and
    # deliberately not gated on an id-ish key: the one this was written for sat
    # in a journal MESSAGE, which is prose under a key that says nothing.
    for m in SSH_FINGERPRINT.finditer(text):
        # A scrubbed fingerprint announces itself, the same way a scrubbed
        # 32-hex identifier carries 5cb0. Restated here rather than imported
        # from the scrubber: this checker must be able to disagree with it.
        body = m.group(0).partition(":")[2]
        if body.startswith(SSH_FINGERPRINT_MARKER) or body.startswith("a0:a0:"):
            continue
        findings.append(Finding(
            path, "key-fingerprint",
            f"{m.group(0)} is an OpenSSH public-key fingerprint — not a secret, "
            "but anyone holding the key recognises the estate it authenticates to",
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
