"""hardware subsystem: platform, pci, usb, scsi, nvme.

What lshw/lspci/lsusb print, acquired the SPEC way: none of those tools
speak JSON, but everything they show comes from sysfs (the native kernel
interface) plus the udev hwdb, which `udevadm info --json=short` serves
structured. The scsi collection is the physical path a block device takes —
host adapter → (expanders) → end device → disk — with enclosure slots
mapped when an SES device is present, so "which bay is sdX in" is a fact,
not a guess.

Firmware is a first-class fact everywhere it exists natively: BIOS (DMI),
drive revision (scsi `rev` *is* drive firmware), NVMe firmware_rev, USB
bcdDevice, enclosure IOM revision, HBA version_fw/version_bios where the
driver publishes them. SMART health arrives in depth order: hwmon sysfs
temperatures (nvme + drivetemp, zero privilege) always; udisks2 over D-Bus
where the daemon runs; and smartctl --json where the operator granted raw
device access (module grantDiskAccess) — udisks2's NVMe interface has no
endurance property, so percentage-used is only observable this way.
Reference commands name the familiar tools; smartctl is the only one ever
run, and only under that explicit grant.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import anyio

from .. import envelope as env
from ..rules import worst_level
from ..rules.hardware import (has_smart_reading, nvme_opinions,
                              scsi_disk_opinions, smart_opinions)
from ..sysbus import BUS

UDISKS = "org.freedesktop.UDisks2"
UDISKS_PATH = "/org/freedesktop/UDisks2"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"

PCI_DEVICES = "/sys/bus/pci/devices"
USB_DEVICES = "/sys/bus/usb/devices"
NVME_DEVICES = "/sys/class/nvme"
SCSI_HOSTS = "/sys/class/scsi_host"
SCSI_DEVICES = "/sys/bus/scsi/devices"
SAS_EXPANDERS = "/sys/class/sas_expander"
SAS_DEVICES = "/sys/class/sas_device"
SAS_PHYS = "/sys/class/sas_phy"
ATA_LINKS = "/sys/class/ata_link"
ENCLOSURES = "/sys/class/enclosure"
BY_PATH = "/dev/disk/by-path"
DMI = "/sys/devices/virtual/dmi/id"
HWMON = "/sys/class/hwmon"

# HBA drivers publish firmware under driver-specific attribute names;
# read whichever exists (mpt3sas: version_fw/version_bios/board_name,
# qla/lpfc-style: fw_version/fwrev/model_name).
SCSI_HOST_FIRMWARE_ATTRS = (
    ("version_fw", "FirmwareVersion"),
    ("fw_version", "FirmwareVersion"),
    ("fwrev", "FirmwareVersion"),
    ("version_bios", "BiosVersion"),
    ("board_name", "BoardName"),
    ("model_name", "BoardName"),
)

SMART_SNAPSHOT_DIR = "/run/system-explorer-smart"


def _smartctl_json(path: str) -> dict:
    """smartctl exit codes are bitmasks that flag drive problems while the
    JSON stays valid — parse whatever came back, never require rc 0. NVMe
    nodes need the type stated; auto-detection fails on ng/controller
    devices."""
    cmd = ["smartctl", "--json=c", "-H", "-A", path]
    if re.match(r"^/dev/(ng|nvme)\d", path):
        cmd[1:1] = ["-d", "nvme"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    return json.loads(proc.stdout or "{}")


def _smart_snapshot(name: str) -> tuple[dict, float] | None:
    """The root collector's snapshot for a device (and its write time), if
    the module's grantDiskAccess timer is running (see nix/module.nix)."""
    path = Path(f"{SMART_SNAPSHOT_DIR}/{name}.json")
    try:
        return json.loads(path.read_text()), path.stat().st_mtime
    except (OSError, ValueError):
        return None


def _smart_no_reading(name: str) -> str | None:
    """smartctl's own words for why the last run produced no reading.

    The collector writes this beside the snapshot (nix/module.nix) precisely so
    the agent does not have to guess. "Device is in STANDBY mode" is the common
    one and it is not a fault: the collector passes -n standby so a spun-down
    bulk disk is deliberately left asleep, and its facts are honestly
    last-known rather than current.
    """
    try:
        text = Path(f"{SMART_SNAPSHOT_DIR}/{name}.reason").read_text().strip()
    except OSError:
        return None
    return env.reason(text) if text else None


def _epoch_iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


PLATFORM_REFERENCE = ["lshw -class system", "dmidecode -t system", "lscpu",
                      "cat /proc/meminfo"]
PCI_REFERENCE = ["lspci -nnk", "ls /sys/bus/pci/devices",
                 "udevadm info /sys/bus/pci/devices/<addr>"]
USB_REFERENCE = ["lsusb", "lsusb -t",
                 "cat /sys/bus/usb/devices/<dev>/{idVendor,idProduct,manufacturer,"
                 "product,speed,version,bcdDevice,bDeviceClass}"]
# Reference commands are a promise: an administrator can reproduce the
# observation by running them (SPEC rule 5). That makes them a truthfulness
# surface, and they had drifted — link rates, host identity and serials were all
# being read from places nothing here named, because facts were added without
# updating this. Anything the adapter reads belongs in one of these lists.
SCSI_REFERENCE = ["lsscsi -v",
                  "ls -l /dev/disk/by-path",
                  "ls /sys/class/enclosure",
                  # host identity: driver, transport, and the PCI function it
                  # hangs from, whose hwdb names come from udev not sysfs.
                  "cat /sys/class/scsi_host/host*/{proc_name,state}",
                  "udevadm info /sys/bus/pci/devices/<addr>",
                  # the devices themselves: type, identity and state
                  "cat /sys/bus/scsi/devices/<id>/{type,vendor,model,rev,state,"
                  "wwid,vpd_pg80}",
                  "ls /sys/bus/scsi/devices/<id>/block",
                  # expanders in the attachment tree
                  "cat /sys/class/sas_expander/expander-*/{vendor_id,product_id,level}",
                  "cat /sys/class/sas_device/expander-*/sas_address",
                  # negotiated link rate, per transport
                  "cat /sys/class/ata_link/link*/{sata_spd,hw_sata_spd_limit}",
                  "cat /sys/class/sas_phy/phy-*/negotiated_linkrate",
                  "cat /sys/class/sas_phy/phy-*/maximum_linkrate",
                  "cat /sys/class/sas_device/end_device-*/{sas_address,phy_identifier}",
                  # capacity and serial without a daemon
                  "cat /sys/block/<disk>/size",
                  "sg_vpd --page=sn /dev/<disk>",
                  "smartctl -H -A /dev/<disk>",
                  # the zero-privilege temperature floor, which is all a host
                  # with no udisks2 and no disk grant can see
                  "cat /sys/class/hwmon/hwmon*/{name,temp1_input}",
                  "ls /sys/class/hwmon/hwmon*/device/block"]
NVME_REFERENCE = ["nvme list",
                  "smartctl -H -A /dev/<ctrl>",
                  "cat /sys/class/nvme/<ctrl>/{firmware_rev,model,serial,state,transport}",
                  # The wwid is the NAMESPACE's, not the controller's — the
                  # same read scsi does, one directory along.
                  "cat /sys/block/<ctrl>n1/wwid",
                  # PCIe link, and the bridge above it whose capability is what
                  # distinguishes a narrow slot from a degraded link
                  "cat /sys/class/nvme/<ctrl>/device/{current,max}_link_{speed,width}",
                  "lspci -vv -s <addr> | grep LnkSta",
                  "cat /sys/class/hwmon/hwmon*/{name,temp1_input}"]

# ── the fact dictionary ──────────────────────────────────────
# One sentence per fact, saying what it MEANS. Facts carry native property
# names (SPEC section 5) and native names are not self-explanatory: a reader
# looking at LinkSpeed beside LinkWidth reasonably asked whether lanes and
# speed were the same thing, and nothing on the screen could tell them.
#
# It lives beside the code that emits the fact, so the sentence cannot drift
# from the thing it describes, and it is served from one endpoint rather than
# riding on every envelope — an agent paging a collection should not pay for
# the same prose on every row. Presentation belongs to clients, so these are
# descriptions, never labels: the fact name itself is unchanged.
_PCIE_LINK_GLOSSARY = {
    "LinkSpeed": "The signalling rate of ONE PCIe lane, in the kernel's own "
                 "label. Not the link's total — multiply by LinkWidth for that.",
    "LinkSpeedMax": "The fastest per-lane rate the device itself supports, "
                    "whatever the slot it is fitted in can do.",
    "LinkWidth": "How many PCIe lanes are actually carrying traffic. The "
                 "link's bandwidth is LinkSpeed multiplied by this.",
    "LinkWidthMax": "How many lanes the device can use when a slot provides them.",
    "SlotLinkWidthMax": "How many lanes the slot is physically wired for, read "
                        "from the bridge above the device. A property of the "
                        "board, which no configuration can change.",
    "SlotLinkSpeedMax": "The fastest per-lane rate the slot supports, read from "
                        "the bridge above the device.",
    "LinkBandwidthBytesPerSec": "Derived, not read: LinkSpeed's per-lane "
                                "throughput after PCIe line encoding, times "
                                "LinkWidth. Each direction — PCIe is full duplex.",
    "LinkBandwidthMaxBytesPerSec": "The same arithmetic at LinkSpeedMax and "
                                   "LinkWidthMax — what this device would carry "
                                   "in a slot that did not narrow it.",
}
_SERIAL_LINK_GLOSSARY = {
    "LinkSpeed": "The rate this SATA or SAS link negotiated. One serial "
                 "connection, so unlike PCIe there is no lane count to multiply.",
    "LinkSpeedMax": "The fastest rate this link could run at. On SATA the kernel "
                    "fills this in only when something has limited the link, so "
                    "it is usually absent rather than equal to the negotiated rate.",
}
_SMART_GLOSSARY = {
    "SmartOverallPassed": "The drive's own pass/fail self-assessment. A pass is "
                          "the drive saying it has not crossed its own failure "
                          "thresholds, not a promise about tomorrow.",
    "SmartFailing": "The ATA equivalent of SmartOverallPassed, inverted: true "
                    "means the drive is reporting imminent failure.",
    "SmartTemperatureC": "Drive temperature in degrees Celsius, from SMART where "
                         "it is readable and from hwmon otherwise.",
    "SmartPowerOnHours": "Hours the drive has been powered on across its life — "
                         "its age in service, not its uptime since boot.",
    "SmartPercentUsed": "The NVMe drive's own estimate of the write endurance it "
                        "has consumed. Above 100 is defined and expected; it "
                        "means the rated endurance is spent, not that it failed.",
    "SmartAvailableSparePct": "How much of the drive's spare block pool is left "
                              "to remap failing blocks with.",
    "SmartSpareThresholdPct": "The spare level below which the drive itself "
                              "declares a problem — the number "
                              "SmartAvailableSparePct is judged against.",
    "SmartMediaErrors": "Unrecovered data-integrity errors the NVMe controller "
                        "has counted. Non-zero is worth investigating.",
    "SmartBadSectors": "Sectors the drive has reallocated or cannot read. A "
                       "count that is growing matters more than its value.",
    "SmartCriticalWarning": "The NVMe controller's own critical-warning flags, "
                            "verbatim — the drive naming what it is unhappy about.",
    "SmartSelftestStatus": "How the drive's last self-test ended, in its own words.",
    "SmartSnapshotAt": "When the root SMART collector last wrote these readings. "
                       "They are last-known, not live: reading SMART needs "
                       "privilege the agent does not hold.",
    "SmartSnapshotAgeSeconds": "How old that snapshot is. Large means the "
                               "collector is not running, not that the drive is quiet.",
    "SmartSnapshotReason": "Why the snapshot is stale or absent, recorded by the "
                           "collector itself rather than guessed here.",
    "SmartUnobservable": "Why this device yielded no health reading at all, so a "
                         "rule can decline to vouch for it instead of calling it healthy.",
}
_DEVICE_GLOSSARY = {
    "Model": "The device's model string, as it reports it.",
    "Vendor": "The maker, as reported — for ATA devices behind SCSI this is "
              "derived from the model prefix, which is where the real name survives.",
    "Serial": "The device's serial number, as it reports it.",
    "FirmwareRev": "The firmware revision the device is running.",
    "Firmware": "The firmware revision as the health daemon reports it; the same "
                "value as FirmwareRev, from the other source.",
    "Transport": "How the device is actually attached — SAS, SATA, USB, PCIe — "
                 "established from the kernel's own topology rather than a "
                 "driver-name lookup.",
    "PCIAddress": "The PCI function this device hangs from, in domain:bus:device.function form.",
    "SizeBytes": "The device's capacity as the kernel reports it.",
    "Block": "The block device this hardware backs, if the kernel created one.",
    "Namespaces": "The NVMe namespaces this controller exposes — the block "
                  "devices a filesystem can actually sit on.",
    "WWN": "The device's world-wide name — the kernel's wwid, read from the "
           "SCSI device or, on NVMe, from its namespace. A kernel name "
           "renumbers when enumeration order shifts and this does not, so it "
           "is what a join survives a reboot on.",
    "WWNUnobservable": "Why this controller states no world-wide name: a wwid "
                       "belongs to a namespace, and a controller exposing "
                       "several has no single one of its own.",
    "State": "The kernel's own device state. It records that the device was "
             "enumerated and is reachable, which is not a measurement of health.",
    "Devices": "How many devices are attached below this host.",
    "Enclosure": "The enclosure this device is a member of.",
    "EnclosureSlot": "Which physical bay in the enclosure holds this device — "
                     "the number to walk to when a drive needs replacing.",
    "Driver": "The kernel driver bound to this device.",
}
_HARDWARE_GLOSSARY: dict[str, dict[str, str]] = {
    "nvme": {**_DEVICE_GLOSSARY, **_PCIE_LINK_GLOSSARY, **_SMART_GLOSSARY},
    "scsi": {**_DEVICE_GLOSSARY, **_SERIAL_LINK_GLOSSARY, **_SMART_GLOSSARY},
}


# ATA devices reach SCSI with the transport in the vendor field; the real
# maker is recoverable from the model string's conventional prefix. This is
# the same derivation udisks applies — deterministic, not a guess.
ATA_VENDOR_PREFIXES = (
    ("ST", "Seagate"), ("WDC", "Western Digital"), ("HGST", "HGST"),
    ("SAMSUNG", "Samsung"), ("Samsung", "Samsung"), ("MZ", "Samsung"),
    ("KINGSTON", "Kingston"), ("OCZ", "OCZ"), ("SanDisk", "SanDisk"),
    ("TOSHIBA", "Toshiba"), ("HITACHI", "Hitachi"), ("Hitachi", "Hitachi"),
    ("INTEL", "Intel"), ("Micron", "Micron"), ("Crucial", "Crucial"),
)


def _ata_vendor(model: str | None) -> str | None:
    for prefix, vendor in ATA_VENDOR_PREFIXES:
        if model and model.startswith(prefix):
            return vendor
    return None


def _natural_key(name: str) -> list:
    """2:0:10:0 sorts after 2:0:9:0, host10 after host9 — digits compare as
    numbers, everything else as text."""
    return [int(part) if part.isdigit() else part
            for part in re.split(r"(\d+)", name)]


# USB device names are bus-port(.port…); interfaces carry a ':config.iface'
# suffix and are the same physical device again.
USB_DEV_RE = re.compile(r"^(usb\d+|\d+-\d+(\.\d+)*)$")
# Segments of a sysfs device path that are nodes in the scsi topology.
SCSI_SEG_RE = re.compile(r"^(host\d+|expander-\d+:\d+(?::\d+)?)$")
SCSI_DEV_RE = re.compile(r"^\d+:\d+:\d+:\d+$")
END_DEVICE_RE = re.compile(r"^end_device-[\d:]+$")
PCI_ADDR_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")

# Kernel scsi device type codes (include/scsi/scsi_proto.h).
SCSI_TYPES = {0: "disk", 1: "tape", 4: "worm", 5: "cd-dvd", 6: "scanner",
              7: "optical", 8: "changer", 12: "raid", 13: "enclosure", 14: "rbc"}


def _udev_json(syspath: str) -> dict:
    proc = subprocess.run(["udevadm", "info", "--json=short", syspath],
                          capture_output=True, text=True, timeout=10)
    if proc.returncode != 0:
        return {}
    try:
        return json.loads(proc.stdout or "{}")
    except ValueError:
        return {}


def _lscpu_json() -> dict:
    proc = subprocess.run(["lscpu", "-J"], capture_output=True, text=True,
                          timeout=10, check=True)
    return json.loads(proc.stdout or "{}")


def _read(path: str) -> str | None:
    """One sysfs attribute as text, or None where there is no text to read.

    UnicodeDecodeError is caught beside OSError because sysfs holds BINARY
    attributes — SCSI VPD pages, EDID blobs — and a device directory read
    whole will meet one. It was uncaught until 2026-08-21, when the evidence
    verb first read a real SCSI disk's directory and died on vpd_pg80's 0x80
    byte: every evidence request for a SCSI disk raised, and main.py turned it
    into an error envelope, so the surface had never worked and nothing said
    so. A binary attribute is not unreadable, it is not TEXT — it travels
    through _read_bytes, which is asked for it by name.
    """
    try:
        return Path(path).read_text().strip() or None
    except (OSError, UnicodeDecodeError):
        return None


def _read_bytes(path: str) -> str | None:
    """A sysfs attribute whose content is BINARY, transcribed as base64.

    SCSI VPD page 0x80 is the only one this collector reads: four header bytes
    then the drive's serial, which a text read mangles before the slice can
    drop it. It is a named primitive rather than an inline Path.read_bytes so
    the replay seam has a stub point — an unstubbed binary read answered out
    of the tree of whichever machine was replaying, which is how a lab guest
    with one disk would have published the serial of the developer's laptop.

    Base64 because a payload is JSON and these bytes are not text; the DECODE
    stays with the caller, so the seam transcribes and the parse is still the
    port's to reproduce.
    """
    try:
        return base64.b64encode(Path(path).read_bytes()).decode("ascii")
    except OSError:
        return None


def _listdir(path: str) -> list[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def _realpath(path: str) -> str:
    """Where a sysfs link actually lands, as a named primitive.

    A third of what this adapter knows is read off the resolved path rather
    than out of a file: which ata port a disk hangs from, which PCI function a
    host adapter is, which kernel name a by-path alias denotes. That makes the
    link graph part of the native document — DESIGN's ruling of 2026-08-19 on
    tree-shaped interfaces, which is that the payload is the filesystem
    transcribed, listings and contents alike — and a bare os.path.realpath has
    no stub point, so a replay would resolve against the tree of whichever
    machine is REPLAYING. It does not fail there: realpath returns a missing
    path unchanged, so the walk quietly finds no ata port and no PCI function
    and publishes a host with neither, which is a wrong answer wearing a
    complete one's clothes.

    Named here for the same reason _read and _listdir are, and it changes
    nothing live — this is os.path.realpath, called through one door.
    """
    return os.path.realpath(path)


def _exists(path: str) -> bool:
    """Whether a sysfs attribute is there at all, as a named primitive.

    One transport verdict turns on presence rather than content —
    host_sas_address exists on a SAS host and nowhere else, and it is read for
    nothing but that — so the probe IS the reading and there is no file
    contents for _read to carry.

    Named for the same reason _realpath is, and it is the last unseamed native
    touch on the acquisition path: called bare, it answers about the machine
    REPLAYING a capture rather than the one captured, which makes a corpus pair
    stop being a function of its payload — a SAS host replaying a SATA capture
    would read SAS out of its own tree.
    """
    return os.path.exists(path)


# sysfs says "<unknown>" or "Unknown" where a value is not established. Both
# read as data if passed through, so they become absence.
_SYSFS_UNKNOWN = {"", "<unknown>", "unknown", "Unknown", "none"}


def _sysfs_value(raw: str | None) -> str | None:
    value = (raw or "").strip()
    return None if value in _SYSFS_UNKNOWN else value


BY_ID = "/dev/disk/by-id"


def _hardware_assertions(parent: str | None, facts: dict) -> list[dict]:
    """The R3c relation layer, in the order the Go collector pins: the chain
    edge, the silicon, what it backs, where it is racked. One spelling on both
    implementations, because the comparator holds them to one truth."""
    edges = []
    if parent:
        edges.append({"type": "attached-to",
                      "target": {"kind": "scsi", "name": parent}})
    if facts.get("PCIAddress"):
        edges.append({"type": "attached-to",
                      "target": {"kind": "pci", "name": facts["PCIAddress"]}})
    if facts.get("Block"):
        edges.append({"type": "backs",
                      "target": {"kind": "block-device", "name": facts["Block"]}})
    for namespace in facts.get("Namespaces") or []:
        edges.append({"type": "backs",
                      "target": {"kind": "block-device", "name": namespace}})
    if facts.get("Enclosure"):
        edges.append({"type": "member-of",
                      "target": {"kind": "scsi", "name": facts["Enclosure"]}})
    return edges


def _disk_names(wwn: str | None, serial: str | None,
                links: list[str], block: str) -> dict | None:
    """Law 1 on a hardware disk: every native name observed, split by
    stability class. The wwid file and udev's wwn-… link are two spellings of
    one identity and both are published in the wwn family — the join runs on
    published values, and a spelling nobody publishes is a join that silently
    fails."""
    wwn_family: list[str] = [wwn] if wwn else []
    devid_family: list[str] = []
    for link in links:
        family = wwn_family if link.startswith("wwn-") else devid_family
        if link not in family:
            family.append(link)
    stable: dict[str, list[str]] = {}
    if wwn_family:
        stable["wwn"] = wwn_family
    if devid_family:
        stable["devid"] = devid_family
    if serial:
        stable["serial"] = [serial]
    if not stable:
        return None
    return {"stable": stable, "ephemeral": {"kernel": [f"/dev/{block}"]}}


# The DMI attributes an evidence document does not serve, as the platform
# collection's declared `redactions` state. The row facts are a vendor, a
# model, a firmware release and four topology counts, all identical on every
# machine of that model; DMI also carries the machine's OWN identity, and the
# evidence verb reads the directory whole.
WITHHELD_DMI = frozenset({"product_serial", "chassis_serial", "board_serial",
                          "product_uuid"})


def _device_directory(base: str) -> bool:
    """Whether a device's own sysfs directory is there, through the seam.

    A sysfs device directory always holds a uevent file, so the probe is a
    presence test on that — and it goes through _exists rather than
    os.path.isdir because an unseamed probe answers out of the tree of
    whichever machine is REPLAYING. Under replay that made every evidence
    request fail with UnknownObject regardless of what the capture held, and
    live it silently searched three classes with no record of having done so.
    """
    return _exists(f"{base}/uevent")


def _attributes(base: str, withheld: frozenset[str] = frozenset()) -> dict[str, str]:
    """Every readable attribute in one sysfs directory, by name.

    A name with nothing to read is left OUT rather than carried as a null: a
    directory entry may be a subdirectory, a write-only trigger or a binary
    page, and none of those is an attribute whose value is nothing. The Go
    collector's own attributes() skips on the same rule, so an evidence
    document means the same thing whichever implementation served it.
    """
    out: dict[str, str] = {}
    for name in _listdir(base):
        if name in withheld:
            continue
        value = _read(f"{base}/{name}")
        if value is not None:
            out[name] = value
    return out


def _link_status(current, device_max, slot_max) -> str | None:
    """One axis of a link: at the device's own maximum, held below it by the
    slot, or below what BOTH ends could do.

    The distinction is the whole rule. A drive at x2 of its own x4 in a socket
    wired for two lanes is an immutable property of the board — worth knowing,
    because it halves bandwidth, but nothing an operator can act on. The same
    numbers where the slot ALSO offers four mean the link trained down, which
    is a fault, and reporting both as a warning was a false positive on a real
    host. Comparison is equality on the kernel's own labels ("8.0 GT/s PCIe",
    "6.0 Gbit") and on lane counts; ranking the labels would invent precision.

    None where the device reports no maximum, as a healthy SATA port does: a
    link with nothing to be below is not judged at all rather than judged well.
    """
    if not current or not device_max:
        return None
    if current == device_max:
        return "at-maximum"
    if slot_max is not None and slot_max == current:
        return "capped-by-slot"
    return "degraded"


def _facts(values: dict) -> dict:
    """A row's facts, with the readings that were not there left off.

    A fact's value is never null (DESIGN 19): *we could not read this*, *this
    object genuinely has no such property* and *here is the value* are three
    statements on three channels, and null names none of them — the contract's
    recursive fact_value and the replay judge both refuse it. Nearly every
    reading here is a sysfs file or a hwdb property that may simply not exist,
    so absence arrives as None at a dozen sites: a QEMU guest has no
    board_name, an ata_piix host publishes no firmware attribute under any of
    the six names, a PCI function with no driver bound has no DRIVER.

    Dropped once, where a row is built, rather than by thirteen conditional
    dict literals — which is the same shape traefik took when the same defect
    was found on a stock install (DESIGN, adjudication queue, 2026-08-19).
    """
    return {key: value for key, value in values.items() if value is not None}


def _lane_count(raw: str | None) -> int | None:
    """A lane count is a number and was being carried as the sysfs string.
    That silently disabled the "x2 lanes" rendering which exists precisely so
    that a bare 2 beside a bare 4 is not read as a speed."""
    value = _sysfs_value(raw)
    return int(value) if value and value.isdigit() else None


# PCIe throughput of ONE lane, in bytes per second each way, keyed on the
# kernel's own current_link_speed / max_link_speed label. These are the rates
# after line encoding — 8b/10b through Gen2, 128b/130b from Gen3, the 242B/256B
# FLIT at Gen6 — so they are what the link actually carries, not the raw
# transfer rate the label names.
#
# Exact labels only. A generation this table has not met yet must produce
# silence rather than a plausible wrong number, so there is no parsing of the
# leading float and no interpolation.
#
# This is the one place the product turns a kernel label into a quantity.
# link_opinions still compares those labels as strings, on the grounds that
# ranking them would invent precision — converting an exact match does not, and
# it stays here in the adapter rather than spreading into the rule.
_PCIE_LANE_BYTES = {
    "2.5 GT/s PCIe": 250_000_000,
    "5.0 GT/s PCIe": 500_000_000,
    "8.0 GT/s PCIe": 984_615_384,
    "16.0 GT/s PCIe": 1_969_230_769,
    "32.0 GT/s PCIe": 3_938_461_538,
    "64.0 GT/s PCIe": 7_562_500_000,
}


def _pcie_bandwidth(speed: str | None, lanes: int | None) -> int | None:
    per_lane = _PCIE_LANE_BYTES.get(speed or "")
    return per_lane * lanes if per_lane and lanes else None


def _scsi_link_facts(scsi_id: str) -> dict:
    """Negotiated link rate for a SCSI-attached disk, and the maximum where the
    kernel establishes one.

    Worth having because a link that trained low is a real performance fault
    that nothing else here would show: a 6 Gbps drive at 1.5 Gbps, or a SAS phy
    that came up at half rate, looks perfectly healthy in every other fact.

    Two native sources, chosen by how the device is actually attached rather
    than by a driver-name table. SATA: the ata port in the device's own sysfs
    path names its link, and ata_link carries the negotiated speed. SAS: the
    end_device names its phy, and sas_phy carries both negotiated and maximum,
    which is what makes the comparison possible there and not on SATA.
    """
    segments = _realpath(f"{SCSI_DEVICES}/{scsi_id}").split("/")

    ata = next((seg for seg in segments if re.fullmatch(r"ata\d+", seg)), None)
    if ata:
        link = f"{ATA_LINKS}/link{ata[3:]}"
        return {key: value for key, value in {
            "LinkSpeed": _sysfs_value(_read(f"{link}/sata_spd")),
            # Usually "<unknown>" on a healthy port, so usually absent: the
            # kernel only fills it when something has limited the link.
            "LinkSpeedMax": _sysfs_value(_read(f"{link}/hw_sata_spd_limit")),
        }.items() if value}

    end_device = next((seg for seg in segments if seg.startswith("end_device-")), None)
    if end_device:
        host = end_device.removeprefix("end_device-").split(":")[0]
        phy_id = _sysfs_value(_read(f"{SAS_DEVICES}/{end_device}/phy_identifier"))
        if phy_id:
            phy = f"{SAS_PHYS}/phy-{host}:{phy_id}"
            return {key: value for key, value in {
                "LinkSpeed": _sysfs_value(_read(f"{phy}/negotiated_linkrate")),
                "LinkSpeedMax": _sysfs_value(_read(f"{phy}/maximum_linkrate")),
            }.items() if value}
    return {}


def _nvme_wwn(namespaces: list[str]) -> dict:
    """The device's world-wide name, which on NVMe belongs to the NAMESPACE.

    hardware/scsi has carried WWN since it shipped and hardware/nvme never
    did — the same identity fact treated two ways inside one subsystem, which
    matters more than an ordinary omission because identity is what every
    join is made of. A kernel name renumbers: `nvme0n1` can come back as
    `nvme1n1` when enumeration order shifts, which on a four-drive host is
    not hypothetical. The wwid does not.

    NOT taken from udisks2, which is where it looks like it should come from.
    Measured on the estate: `org.freedesktop.UDisks2.Drive.WWN` is the empty
    string on every NVMe drive here, so reading it would publish "" — a fact
    that asserts an identity and carries none, which is worse than the gap it
    would appear to close. The kernel's own per-namespace wwid is the same
    read SCSI already does, one directory along.

    A controller with SEVERAL namespaces has several wwids and no single one
    of its own, so it says that rather than picking the first — the shape
    this adapter already uses for a SMART reading it cannot take.
    """
    if not namespaces:
        return {}
    values = {ns: _read(f"/sys/block/{ns}/wwid") for ns in namespaces}
    present = {ns: v for ns, v in values.items() if v}
    if len(namespaces) == 1:
        return {"WWN": present.get(namespaces[0])}
    distinct = set(present.values())
    if len(distinct) == 1:
        return {"WWN": next(iter(distinct))}
    return {"WWNUnobservable":
            f"This controller exposes {len(namespaces)} namespaces and a wwid"
            f" belongs to a namespace, not a controller, so no single"
            f" world-wide name identifies it. The per-namespace names are on"
            f" the block devices themselves."}


def _nvme_link_facts(controller: str) -> dict:
    """PCIe link speed and width for an NVMe controller — what it negotiated,
    what the DEVICE can do, and what the SLOT can do.

    The third one is the point. A drive running x2 of its own x4 is either wired
    that way or trained down, and those are completely different statements: the
    first is an immutable property of the board, the second is a fault. Without
    the upstream bridge's capability there is no way to tell, and warning about
    the first is warning about something no operator can act on — which is
    exactly what the first version of this did on a real host.
    """
    base = f"{NVME_DEVICES}/{controller}/device"
    facts: dict = {
        "LinkSpeed": _sysfs_value(_read(f"{base}/current_link_speed")),
        "LinkSpeedMax": _sysfs_value(_read(f"{base}/max_link_speed")),
        "LinkWidth": _lane_count(_read(f"{base}/current_link_width")),
        "LinkWidthMax": _lane_count(_read(f"{base}/max_link_width")),
    }
    # The bridge immediately above shares this link, so its max_link_* is the
    # slot's capability while the device's is the card's.
    bridge = os.path.dirname(_realpath(base))
    facts["SlotLinkWidthMax"] = _lane_count(_read(f"{bridge}/max_link_width"))
    facts["SlotLinkSpeedMax"] = _sysfs_value(_read(f"{bridge}/max_link_speed"))
    # Derived, not read — and the reason the four facts above stop reading as
    # four unrelated numbers. Speed is the rate of ONE lane and width is how
    # many are active, so the figure a reader is actually after is the product;
    # asked what "x2 of x4" cost them, nobody could answer from this screen.
    # It is a fact rather than prose so the rule can CITE it instead of
    # asserting it (SPEC rule 3), the UI can draw it without carrying a PCIe
    # table of its own, and an agent consumer gets the same arithmetic.
    facts["LinkBandwidthBytesPerSec"] = _pcie_bandwidth(
        facts["LinkSpeed"], facts["LinkWidth"])
    facts["LinkBandwidthMaxBytesPerSec"] = _pcie_bandwidth(
        facts["LinkSpeedMax"], facts["LinkWidthMax"])
    return {key: value for key, value in facts.items() if value}


def _host_transport(base: str, driver: str | None) -> str | None:
    """How a SCSI host actually attaches its devices, from native evidence
    rather than a list of driver names.

    The kernel presents SATA and USB storage through the SCSI subsystem, so
    every one of these is a `scsi_host` — which left an AHCI port indistinguish-
    able from a SAS HBA in the UI, both labelled scsi-host with nothing else to
    go on. An ata port in the path means SATA; a host_sas_address means SAS.
    """
    if _exists(f"{base}/host_sas_address"):
        return "SAS"
    if any(re.fullmatch(r"ata\d+", seg)
           for seg in _realpath(base).split("/")):
        return "SATA"
    if driver in ("usb-storage", "uas"):
        return "USB"
    if driver == "virtio_scsi":
        return "virtio"
    return None


def _pci_addr_of(syspath: str) -> str | None:
    """Deepest PCI function on the device's real path — the adapter a
    controller hangs from."""
    addr = None
    for seg in _realpath(syspath).split("/"):
        if PCI_ADDR_RE.match(seg):
            addr = seg
    return addr


def _lscpu_fields(raw: dict) -> dict[str, str]:
    fields: dict[str, str] = {}

    def walk(entries: list) -> None:
        for entry in entries:
            if isinstance(entry, dict):
                data = entry.get("data")
                if entry.get("field") and data is not None:
                    fields[entry["field"].rstrip(":")] = data
                walk(entry.get("children") or [])

    walk(raw.get("lscpu") or [])
    return fields


def _meminfo_total_bytes() -> int | None:
    # /proc/meminfo is a kernel interface: 'MemTotal:  16265256 kB'.
    for line in (_read("/proc/meminfo") or "").splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024
    return None


def _int_or_none(value: str | None) -> int | None:
    return int(value) if value is not None and value.isdigit() else None


def _kelvin_to_c(value) -> float | int | None:
    """udisks reports temperatures in kelvin (0 = unknown).

    Whole kelvin in, whole degrees out. Subtracting 273.15 from an integer
    always lands on .85, so rounding to one decimal made every udisks reading
    end in .9 — a digit the sensor never measured. A drive reporting 300 K
    knows it is 27 °C, not 26.9 °C, and inventing precision is the same class
    of error as inventing a value.

    The hwmon floor is left fractional on purpose: it reports millidegrees, so
    its one decimal is real.
    """
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    celsius = value - 273.15
    return round(celsius) if float(value).is_integer() else round(celsius, 1)


def _bytes_to_str(value) -> str | None:
    """udisks 'ay' strings arrive NUL-terminated via the base64 marker."""
    if isinstance(value, dict) and "__bytes_base64__" in value:
        return base64.b64decode(value["__bytes_base64__"]).rstrip(b"\x00").decode(
            "utf-8", "replace")
    if isinstance(value, str):
        return value
    return None


def _no_reading_reason(facts: dict) -> str:
    """Why this drive carries no health reading, as specifically as we can say.

    Order matters: smartctl's own words beat any inference. A drive whose
    snapshot was garbage-collected for carrying no reading has no
    SmartSnapshotAt at all, so without checking the recorded reason first this
    would blame grantDiskAccess on a host where the collector is installed,
    running, and correctly declining to wake a sleeping disk.
    """
    recorded = facts.get("SmartSnapshotReason")
    if recorded:
        return f"the root smartctl collector got no reading — {recorded}"
    if facts.get("SmartSnapshotAt"):
        return ("the root smartctl snapshot for this device carried no reading "
                "(smartctl declined the drive, or it was asleep and left alone).")
    return ("no root smartctl snapshot exists for this device (grantDiskAccess "
            "off?) and udisks2 exposed no SMART for this transport — udisks "
            "speaks ATA SMART only, so SAS drives have none.")


class Adapter:
    subsystem = "hardware"

    def collections(self) -> list[str]:
        return ["platform", "pci", "usb", "scsi", "nvme"]

    def fact_glossary(self, collection: str) -> dict[str, str]:
        return _HARDWARE_GLOSSARY.get(collection, {})

    async def capability(self) -> dict:
        unavailable: dict[str, str] = {}
        if not os.path.isdir(PCI_DEVICES):
            unavailable["pci"] = f"{PCI_DEVICES} does not exist"
        if not os.path.isdir(USB_DEVICES):
            unavailable["usb"] = f"{USB_DEVICES} does not exist (no USB buses?)"
        if not os.path.isdir(SCSI_HOSTS):
            unavailable["scsi"] = f"{SCSI_HOSTS} does not exist (no scsi hosts?)"
        if not os.path.isdir(NVME_DEVICES):
            unavailable["nvme"] = f"{NVME_DEVICES} does not exist (no NVMe controllers)"
        return {"available": True,
                "collections": [c for c in self.collections() if c not in unavailable],
                "unavailable_collections": unavailable}

    # ── drive health: hwmon (always) → udisks2 → smartctl (granted) ──

    @staticmethod
    def _hwmon_temps() -> dict[str, float]:
        """Device name (nvme controller or sdX) -> °C from hwmon sysfs.
        The nvme driver and drivetemp (SATA) register sensors readable by
        anyone — the floor that exists even with no daemon and no grant."""
        out: dict[str, float] = {}
        for hw in _listdir(HWMON):
            name = _read(f"{HWMON}/{hw}/name")
            raw = _read(f"{HWMON}/{hw}/temp1_input")
            if raw is None or name not in ("nvme", "drivetemp"):
                continue
            try:
                celsius = round(int(raw) / 1000, 1)
            except ValueError:
                continue
            device = _realpath(f"{HWMON}/{hw}/device")
            if name == "nvme":
                out[os.path.basename(device)] = celsius
            else:
                block = next(iter(_listdir(f"{device}/block")), None)
                if block:
                    out[block] = celsius
        return out

    async def _smart_deep(self, candidates: dict[str, list[str]]) -> dict[str, dict]:
        """smartctl --json depth per device, only where the binary is on
        PATH and a device node is readable (the module's grantDiskAccess
        opt-in). udisks2 cannot report NVMe endurance — its NVMe.Controller
        interface has no percentage-used property (introspected 2026-08-09)
        — so a drive past its rated life is invisible without this. The
        primary source is the root collector's snapshots (smartctl's admin
        ioctls need CAP_SYS_ADMIN regardless of device-node permissions);
        direct execution stays as the fallback for ad-hoc runs that happen
        to have the access."""
        out: dict[str, dict] = {}
        have_tool = shutil.which("smartctl") is not None
        for dev, paths in candidates.items():
            info: dict = {}
            # Read unconditionally, because the interesting case is when there
            # is a reason and NO snapshot: the collector garbage-collects a
            # snapshot that carries no reading, so a drive left asleep long
            # enough ends up with the reason alone. Attaching it only alongside
            # a snapshot would blame grantDiskAccess on a host whose collector
            # is working correctly (observed 2026-08-11).
            recorded_reason = await anyio.to_thread.run_sync(_smart_no_reading, dev)
            if recorded_reason:
                info["SmartSnapshotReason"] = recorded_reason
            data: dict | None = None
            snapshot = await anyio.to_thread.run_sync(_smart_snapshot, dev)
            if snapshot is not None:
                data, mtime = snapshot
                # Snapshot facts are only as fresh as the file: stamp when
                # the collector wrote it and how old that is right now —
                # the age is computed here so the staleness rule stays pure
                # (rules never read clocks). A direct smartctl run below is
                # observed_at-fresh and carries neither fact.
                info["SmartSnapshotAt"] = _epoch_iso(mtime)
                info["SmartSnapshotAgeSeconds"] = max(0, int(time.time() - mtime))
            else:
                # No snapshot, so try a direct run — one bail-out point rather
                # than three, because each of them has to preserve a recorded
                # reason. Dropping the device silently would discard the only
                # explanation the operator can get for why a drive shows no
                # health at all.
                if have_tool:
                    path = next((p for p in paths if os.access(p, os.R_OK)), None)
                    if path is not None:
                        try:
                            data = await anyio.to_thread.run_sync(_smartctl_json, path)
                        except Exception:  # noqa: BLE001 - per-device isolation
                            data = None
                if data is None:
                    if recorded_reason:
                        out[dev] = info
                    continue
            nvme_log = data.get("nvme_smart_health_information_log") or {}
            if nvme_log:
                info["SmartPercentUsed"] = nvme_log.get("percentage_used")
                info["SmartAvailableSparePct"] = nvme_log.get("available_spare")
                info["SmartSpareThresholdPct"] = nvme_log.get("available_spare_threshold")
                info["SmartMediaErrors"] = nvme_log.get("media_errors")
            passed = (data.get("smart_status") or {}).get("passed")
            if passed is not None:
                info["SmartOverallPassed"] = passed
            temp = (data.get("temperature") or {}).get("current")
            if temp is not None:
                info["SmartTemperatureC"] = temp
            hours = (data.get("power_on_time") or {}).get("hours")
            if hours is not None:
                info["SmartPowerOnHours"] = hours
            out[dev] = {k: v for k, v in info.items() if v is not None}
        return out

    # ── drive health via udisks2 ─────────────────────────────
    async def _drive_health(self) -> tuple[dict[str, dict], dict[str, dict]]:
        """(block name → SMART/identity facts, block name → raw udisks
        interfaces). udisks2 reads SMART unprivileged over D-Bus; where it is
        not running these are simply absent — noted, never faked."""
        try:
            objects = (await BUS.call(UDISKS, UDISKS_PATH, OBJECT_MANAGER,
                                      "GetManagedObjects"))[0]
            self._udisks_ok = True
        except Exception:  # noqa: BLE001 - no udisks2 => no SMART facts
            self._udisks_ok = False
            return {}, {}
        drives: dict[str, dict] = {}
        raw: dict[str, dict] = {}
        for path, ifaces in objects.items():
            drive = ifaces.get(f"{UDISKS}.Drive")
            if not drive:
                continue
            info: dict = {"Serial": drive.get("Serial") or None,
                          "Vendor": drive.get("Vendor") or None,
                          "Firmware": drive.get("Revision") or None}
            ata = ifaces.get(f"{UDISKS}.Drive.Ata")
            if ata and ata.get("SmartSupported"):
                info["SmartFailing"] = ata.get("SmartFailing")
                info["SmartBadSectors"] = env.norm_u64(ata.get("SmartNumBadSectors"))
                info["SmartSelftestStatus"] = ata.get("SmartSelftestStatus") or None
                info["SmartTemperatureC"] = _kelvin_to_c(ata.get("SmartTemperature"))
                seconds = ata.get("SmartPowerOnSeconds")
                if isinstance(seconds, int) and seconds > 0:
                    info["SmartPowerOnHours"] = round(seconds / 3600)
            nvme = ifaces.get(f"{UDISKS}.NVMe.Controller")
            if nvme:
                warnings = nvme.get("SmartCriticalWarning") or []
                info["SmartCriticalWarning"] = list(warnings) or None
                # udisks2's NVMe.Controller carries the device self-test
                # verdict under the same property name Drive.Ata uses, but
                # only the ATA branch lifted it — a real drive's known_seg_fail sat
                # in raw evidence, invisible in facts (2026-08-10 audit,
                # coverage asymmetry). One fact name, both transports.
                info["SmartSelftestStatus"] = nvme.get("SmartSelftestStatus") or None
                info["SmartTemperatureC"] = _kelvin_to_c(nvme.get("SmartTemperature"))
                hours = nvme.get("SmartPowerOnHours")
                if isinstance(hours, int) and hours > 0:
                    info["SmartPowerOnHours"] = hours
            drives[path] = info
            raw[path] = {name: props for name, props in ifaces.items()
                         if name.startswith(f"{UDISKS}.Drive") or ".NVMe." in name}
        health: dict[str, dict] = {}
        raw_by_block: dict[str, dict] = {}
        for _path, ifaces in objects.items():
            block = ifaces.get(f"{UDISKS}.Block")
            if not block or not drives.get(block.get("Drive")):
                continue
            name = os.path.basename(_bytes_to_str(block.get("Device")) or "")
            if name:
                health.setdefault(name, drives[block["Drive"]])
                raw_by_block.setdefault(name, raw.get(block["Drive"], {}))
        return health, raw_by_block

    @staticmethod
    def _merge_health(item: dict, health: dict[str, dict], block: str | None) -> None:
        info = health.get(block or "")
        if info:
            item["facts"].update({k: v for k, v in info.items() if v is not None})

    # ── platform ─────────────────────────────────────────────
    async def _platform_observation(self) -> dict:
        try:
            cpu = _lscpu_fields(await anyio.to_thread.run_sync(_lscpu_json))
        except Exception:  # noqa: BLE001 - lscpu absent is a note, not a failure
            cpu = {}
        facts = {
            "SysVendor": _read(f"{DMI}/sys_vendor"),
            "ProductName": _read(f"{DMI}/product_name"),
            "BoardName": _read(f"{DMI}/board_name"),
            "BiosVersion": _read(f"{DMI}/bios_version"),
            "BiosDate": _read(f"{DMI}/bios_date"),
            "CPUModel": cpu.get("Model name"),
            "Architecture": cpu.get("Architecture"),
            "CPUs": _int_or_none(cpu.get("CPU(s)")),
            "Sockets": _int_or_none(cpu.get("Socket(s)")),
            "CoresPerSocket": _int_or_none(cpu.get("Core(s) per socket")),
            "ThreadsPerCore": _int_or_none(cpu.get("Thread(s) per core")),
            "MemoryTotalBytes": _meminfo_total_bytes(),
        }
        obj = env.obj_ref(f"platform:{env.HOST['hostname']}", "platform",
                          env.HOST["hostname"])
        return env.observation(
            self.subsystem, obj,
            env.source("hardware-fs", "sysfs DMI + lscpu -J + /proc/meminfo",
                       PLATFORM_REFERENCE),
            _facts(facts),
            evidence_ref=env.evidence_ref("hardware", "platform", obj['id']))

    # ── pci ──────────────────────────────────────────────────
    async def _pci_items(self) -> list[dict]:
        addresses = _listdir(PCI_DEVICES)
        udev = await asyncio.gather(*(
            anyio.to_thread.run_sync(_udev_json, f"{PCI_DEVICES}/{a}")
            for a in addresses))
        items = []
        for address, props in zip(addresses, udev, strict=True):
            facts = {
                "Class": props.get("ID_PCI_SUBCLASS_FROM_DATABASE")
                         or props.get("ID_PCI_CLASS_FROM_DATABASE"),
                "Vendor": props.get("ID_VENDOR_FROM_DATABASE"),
                "Model": props.get("ID_MODEL_FROM_DATABASE"),
                "Driver": props.get("DRIVER"),
                "PCIID": props.get("PCI_ID"),
            }
            items.append(env.item_summary(f"pci:{address}", "pci-device",
                                          address, _facts(facts)))
        return items

    # ── usb ──────────────────────────────────────────────────
    async def _usb_items(self) -> list[dict]:
        names = [n for n in _listdir(USB_DEVICES) if USB_DEV_RE.match(n)]
        udev = await asyncio.gather(*(
            anyio.to_thread.run_sync(_udev_json, f"{USB_DEVICES}/{n}")
            for n in names))
        items = []
        for name, props in zip(names, udev, strict=True):
            base = f"{USB_DEVICES}/{name}"
            device_class = _read(f"{base}/bDeviceClass")
            facts = {
                "Vendor": props.get("ID_VENDOR_FROM_DATABASE") or _read(f"{base}/manufacturer"),
                "Product": props.get("ID_MODEL_FROM_DATABASE") or _read(f"{base}/product"),
                "VendorID": _read(f"{base}/idVendor"),
                "ProductID": _read(f"{base}/idProduct"),
                "SpeedMbps": _read(f"{base}/speed"),
                "USBVersion": _read(f"{base}/version"),
                # bcdDevice: the device's own firmware/release version.
                "DeviceVersion": _read(f"{base}/bcdDevice"),
            }
            items.append(env.item_summary(
                f"usb:{name}", "usb-hub" if device_class == "09" else "usb-device",
                name, _facts(facts)))
        return items

    # ── scsi topology ────────────────────────────────────────
    @staticmethod
    def _chain_of(syspath: str) -> list[str]:
        """Topology nodes along a device's real sysfs path, outermost first."""
        return [seg for seg in _realpath(syspath).split("/")
                if SCSI_SEG_RE.match(seg)]

    @staticmethod
    def _block_by_path() -> dict[str, str]:
        """sdX → its /dev/disk/by-path name (the human phy/slot route)."""
        out: dict[str, str] = {}
        for name in _listdir(BY_PATH):
            target = _realpath_base(f"{BY_PATH}/{name}")
            if target and "part" not in name:
                out.setdefault(target, name)
        return out

    @staticmethod
    def _by_id_names(block: str) -> list[str]:
        """Every /dev/disk/by-id name udev minted for this block device.

        Out of the device's own DEVLINKS rather than by listing the by-id
        directory and resolving each link back: udev already holds the answer
        per device, so this is one query instead of a listing plus a realpath
        per entry — and the listing would have carried every OTHER disk's
        identity into a payload this row has no business publishing.
        """
        try:
            links = _udev_json(f"/sys/block/{block}").get("DEVLINKS") or ""
        except Exception:  # noqa: BLE001 - names are enrichment, never the row
            return []
        return [link.rpartition("/")[2] for link in links.split()
                if link.startswith(f"{BY_ID}/")]

    @staticmethod
    def _enclosure_slots() -> tuple[dict[str, dict], dict[str, dict]]:
        """(enclosure id → slot table, scsi device id → its slot facts)."""
        by_enclosure: dict[str, dict] = {}
        by_device: dict[str, dict] = {}
        for enc in _listdir(ENCLOSURES):
            slots: dict[str, dict] = {}
            base = f"{ENCLOSURES}/{enc}"
            for comp in _listdir(base):
                comp_dir = f"{base}/{comp}"
                if not os.path.isdir(comp_dir) or _read(f"{comp_dir}/type") is None:
                    continue
                slot = {"Status": _read(f"{comp_dir}/status"),
                        "Slot": _read(f"{comp_dir}/slot") or comp}
                device = _realpath(f"{comp_dir}/device")
                occupant = os.path.basename(device)
                if SCSI_DEV_RE.match(occupant):
                    slot["Device"] = occupant
                    by_device[occupant] = {"Enclosure": enc, **slot}
                slots[comp] = slot
            by_enclosure[enc] = slots
        return by_enclosure, by_device

    def _scsi_items(self) -> list[dict]:
        by_path = self._block_by_path()
        enclosure_slots, device_slots = self._enclosure_slots()

        items_by_name: dict[str, dict] = {}
        parents: dict[str, str | None] = {}

        for host in _listdir(SCSI_HOSTS):
            base = f"{SCSI_HOSTS}/{host}"
            pci_addr = _pci_addr_of(base)
            driver = _read(f"{base}/proc_name")
            facts: dict = {"Driver": driver,
                     "State": _read(f"{base}/state"),
                     # SATA and USB storage are presented through the SCSI
                     # subsystem, so an AHCI port and a SAS HBA were both just
                     # "scsi-host" with nothing to tell them apart.
                     "Transport": _host_transport(base, driver),
                     "PCIAddress": pci_addr}
            # The controller's own identity, so a host row names its silicon
            # in the shared Vendor/Model columns instead of a wall of dashes.
            if pci_addr:
                try:
                    # udevadm --json=short emits a FLAT property object, not
                    # one nested under "properties" — so reading a "properties"
                    # key silently found nothing and every SATA host in the UI
                    # showed a blank vendor and model, for as long as this
                    # collection has existed. The identity was always there:
                    # "Intel Corporation / 500 Series Chipset Family SATA
                    # Controller (AHCI)".
                    props = _udev_json(f"{PCI_DEVICES}/{pci_addr}")
                    facts["Vendor"] = props.get("ID_VENDOR_FROM_DATABASE")
                    facts["Model"] = props.get("ID_MODEL_FROM_DATABASE")
                except Exception:  # noqa: BLE001 - identity is enrichment
                    pass
            for attr, key in SCSI_HOST_FIRMWARE_ATTRS:
                if facts.get(key) is None:
                    facts[key] = _read(f"{base}/{attr}")
            # hwdb has gaps; the driver's board name is the next best label.
            if facts.get("Model") is None:
                facts["Model"] = facts.get("BoardName")
            items_by_name[host] = env.item_summary(
                f"scsi:{host}", "scsi-host", host, _facts(facts))
            if edges := _hardware_assertions(None, facts):
                items_by_name[host]["assertions"] = edges
            parents[host] = None

        for expander in _listdir(SAS_EXPANDERS):
            base = f"{SAS_EXPANDERS}/{expander}"
            # vendor_id/product_id ARE the vendor and model — use the shared
            # column names so expander rows read like everything else.
            facts = {"Vendor": _read(f"{base}/vendor_id"),
                     "Model": _read(f"{base}/product_id"),
                     "Transport": "SAS",
                     "Level": _read(f"{base}/level"),
                     # expanders publish their address via the sas_device
                     # class, same as end devices (verified on a NetApp shelf)
                     "SASAddress": _read(f"/sys/class/sas_device/{expander}/sas_address")}
            chain = self._chain_of(f"{base}/device")
            parents[expander] = next((s for s in reversed(chain) if s != expander), None)
            items_by_name[expander] = env.item_summary(
                f"scsi:{expander}", "expander", expander, _facts(facts))
            if edges := _hardware_assertions(parents[expander], facts):
                items_by_name[expander]["assertions"] = edges

        for dev in _listdir(SCSI_DEVICES):
            if not SCSI_DEV_RE.match(dev):
                continue
            base = f"{SCSI_DEVICES}/{dev}"
            type_code = _int_or_none(_read(f"{base}/type"))
            dev_type = SCSI_TYPES.get(type_code if type_code is not None else -1, "device")
            block = next(iter(_listdir(f"{base}/block")), None)
            chain = self._chain_of(base)
            end_device = next((seg for seg in _realpath(base).split("/")
                               if END_DEVICE_RE.match(seg)), None)
            # libata and usb-storage fill the SCSI vendor field with the
            # transport name — that is a protocol fact, not a manufacturer.
            # The maker comes back via the model-prefix convention (ATA) or
            # stays the genuine SCSI vendor; SAS-attached devices with a
            # real vendor get their transport from the sas_device class.
            raw_vendor = _read(f"{base}/vendor")
            model = _read(f"{base}/model")
            transport = raw_vendor if raw_vendor in ("ATA", "USB", "SATA", "NVMe") else None
            vendor = _ata_vendor(model) if transport else raw_vendor
            sas_address = (_read(f"/sys/class/sas_device/{end_device}/sas_address")
                           if end_device else None)
            if transport is None and sas_address:
                transport = "SAS"
            # Serial and WWN need no daemon: SCSI VPD page 0x80 and the
            # kernel's wwid file are sysfs reads.
            serial = None
            encoded = _read_bytes(f"{base}/vpd_pg80")
            if encoded:
                raw_vpd = base64.b64decode(encoded)
                serial = raw_vpd[4:].decode("ascii", errors="ignore").strip() or None
            # Capacity from the kernel's sector count — the same read the
            # storage subsystem trusts for md arrays; 512-byte units by
            # sysfs contract regardless of the device's logical block size.
            # Through _read, like every other attribute: an inline
            # Path.read_text has no stub point, so a replay answered it out of
            # the tree of whichever machine was replaying — and the first
            # capture with a disk in it refused rather than reading a laptop's
            # /sys/block (2026-08-21, the same shape as vpd_pg80's).
            sectors = _int_or_none(_read(f"/sys/block/{block}/size")) if block else None
            facts = {
                # The wire type again, as a FACT, because a rule condition
                # names facts and nothing else — the closed vocabulary has no
                # way to say "disks only", and the device-state rule must not
                # judge a host or an expander this adapter deliberately leaves
                # unjudged. The links collection's Kind is the precedent.
                "DeviceType": dev_type,
                "Vendor": vendor,
                "Transport": transport,
                "Model": model,
                "Revision": _read(f"{base}/rev"),
                "State": _read(f"{base}/state"),
                "Block": block,
                "SizeBytes": sectors * 512 if sectors else None,
                "Serial": serial,
                "WWN": _read(f"{base}/wwid"),
                "ByPath": by_path.get(block or ""),
                "SASAddress": sas_address,
            }
            # Negotiated link rate, so a drive that trained low is visible. A
            # link at half speed reports nothing else wrong.
            facts.update(_scsi_link_facts(dev))
            slot = device_slots.get(dev)
            if slot:
                facts["Enclosure"] = slot["Enclosure"]
                slot_no = slot["Slot"]
                facts["EnclosureSlot"] = (int(slot_no) if str(slot_no).isdigit()
                                          else slot_no)
                facts["SlotStatus"] = slot["Status"]
            if dev_type == "enclosure":
                facts["Slots"] = enclosure_slots.get(dev, {})
            # Severity waits for _scsi_items_with_health: SMART facts merge
            # after this walk, and rows must reflect the merged whole.
            items_by_name[dev] = env.item_summary(f"scsi:{dev}", dev_type, dev,
                                                  _facts(facts))
            parents[dev] = chain[-1] if chain else None
            if block:
                names = _disk_names(facts.get("WWN"), serial,
                                    self._by_id_names(block), block)
                if names:
                    items_by_name[dev]["names"] = names
            if edges := _hardware_assertions(parents[dev], _facts(facts)):
                items_by_name[dev]["assertions"] = edges

        # Devices behind each host, so the UI can hide childless controllers
        # by default (an empty SATA port is noise, not information).
        child_counts: dict[str, int] = {}
        for parent in parents.values():
            if parent:
                child_counts[parent] = child_counts.get(parent, 0) + 1
        for name, item in items_by_name.items():
            if item["type"] == "scsi-host":
                item["facts"]["Devices"] = child_counts.get(name, 0)

        # Depth-first walk, hosts first — the physical attachment tree.
        children: dict[str | None, list[str]] = {}
        for name, parent in parents.items():
            children.setdefault(parent if parent in items_by_name else None,
                                []).append(name)
        ordered: list[dict] = []
        seen: set[str] = set()

        def walk(name: str, depth: int) -> None:
            if name in seen:
                return
            seen.add(name)
            item = items_by_name[name]
            item["depth"] = depth
            ordered.append(item)
            for child in sorted(children.get(name, []), key=_natural_key):
                walk(child, depth + 1)

        for root in sorted(children.get(None, []), key=_natural_key):
            walk(root, 0)
        return ordered

    # ── nvme ─────────────────────────────────────────────────
    def _nvme_sysfs_items(self) -> list[dict]:
        items = []
        for ctrl in _listdir(NVME_DEVICES):
            base = f"{NVME_DEVICES}/{ctrl}"
            namespaces = [n for n in _listdir(base)
                          if re.match(rf"^{re.escape(ctrl)}n\d+$", n)]
            facts = {
                "Model": _read(f"{base}/model"),
                "FirmwareRev": _read(f"{base}/firmware_rev"),
                **_nvme_link_facts(ctrl),
                "Serial": _read(f"{base}/serial"),
                "State": _read(f"{base}/state"),
                "Transport": _read(f"{base}/transport"),
                "PCIAddress": _pci_addr_of(f"{base}/device"),
                "Namespaces": namespaces,
                **_nvme_wwn(namespaces),
            }
            item = env.item_summary(f"nvme:{ctrl}", "nvme-controller",
                                    ctrl, _facts(facts))
            # Law 1 on a controller: serial and wwid where they exist. The
            # by-id links belong to the NAMESPACE block devices — the same
            # reasoning as _nvme_wwn — so they are published by the storage
            # subsystem's rows, not manufactured here.
            stable = {}
            if facts.get("Serial"):
                stable["serial"] = [facts["Serial"]]
            if facts.get("WWN"):
                stable["wwn"] = [facts["WWN"]]
            if stable:
                item["names"] = {"stable": stable}
            if edges := _hardware_assertions(None, _facts(facts)):
                item["assertions"] = edges
            items.append(item)
        return items

    async def _nvme_items(self) -> list[dict]:
        items = self._nvme_sysfs_items()
        health, _raw = await self._drive_health()
        hwmon = await anyio.to_thread.run_sync(self._hwmon_temps)
        wanted: dict[str, list[str]] = {}
        for item in items:
            namespaces = item["facts"].get("Namespaces") or []
            paths = [f"/dev/{ns.replace('nvme', 'ng', 1)}" for ns in namespaces[:1]]
            paths += [f"/dev/{ns}" for ns in namespaces[:1]]
            paths.append(f"/dev/{item['native_id']}")
            wanted[item["native_id"]] = paths
        deep = await self._smart_deep(wanted)
        for item in items:
            namespaces = item["facts"].get("Namespaces") or []
            self._merge_health(item, health, namespaces[0] if namespaces else None)
            # setdefault(key, None) WRITES the key, and this runs after
            # item_summary has already stripped nulls — so a device with no
            # hwmon reading published `SmartTemperatureC: null`, which names
            # none of DESIGN 19's three channels. Found live on 2026-08-19 by
            # the NixOS guest: no smartctl, no udisks2, a SCSI disk, and the
            # port omitting the fact where this emitted a null. The 38th site
            # of the family the null sweep closed 37 of, and it survived
            # precisely because it is written after the sweep.
            temperature = hwmon.get(item["native_id"])
            if temperature is not None:
                item["facts"].setdefault("SmartTemperatureC", temperature)
            self._merge_deep(item, deep.get(item["native_id"]))
            self._apply_severity("nvme", item)
        return items

    async def _scsi_items_with_health(self) -> list[dict]:
        items = await anyio.to_thread.run_sync(self._scsi_items)
        health, _raw = await self._drive_health()
        hwmon = await anyio.to_thread.run_sync(self._hwmon_temps)
        deep = await self._smart_deep(
            {i["facts"]["Block"]: [f"/dev/{i['facts']['Block']}"]
             for i in items if i["facts"].get("Block")})
        for item in items:
            block = item["facts"].get("Block")
            self._merge_health(item, health, block)
            if block:
                temperature = hwmon.get(block)
                if temperature is not None:
                    item["facts"].setdefault("SmartTemperatureC", temperature)
                self._merge_deep(item, deep.get(block))
            self._apply_severity("scsi", item)
        return items

    @staticmethod
    def _merge_deep(item: dict, info: dict | None) -> None:
        if info:
            item["facts"].update(info)

    # One evaluator per device (agent/rules/hardware.py), shared verbatim
    # with the detail path — rows and opened objects cannot disagree. The
    # scsi tree is heterogeneous, so dispatch keys on object type the way
    # _scsi_items builds it: hosts and expanders are topology, not health
    # subjects; only disks carry the running-state expectation; every other
    # device with a block node can still carry SMART facts (udisks manages
    # optical drives too).
    @staticmethod
    def _opinions(collection: str, obj_type: str, facts: dict) -> list[dict]:
        if collection == "nvme":
            return nvme_opinions(facts)
        if collection == "scsi" and obj_type not in ("scsi-host", "expander"):
            return scsi_disk_opinions(facts) if obj_type == "disk" else smart_opinions(facts)
        return []

    @staticmethod
    def _judgement_facts(facts: dict) -> None:
        """What the declared rule table cannot express itself (DESIGN 17).

        A rule condition names ONE fact and a literal, by design: the
        vocabulary is closed so a rule table stays reviewable data rather than
        an expression language that grows into a plugin-supplied evaluator.
        Two of this collection's judgements compare one fact to ANOTHER and
        one is a substring test, so each is minted here as the reading it is
        and cited by the rule that acts on it. rules/hardware.py still forms
        the same opinions from the same inputs — these are the inputs said
        out loud, not a second evaluator.
        """
        spare = facts.get("SmartAvailableSparePct")
        threshold = facts.get("SmartSpareThresholdPct")
        if spare is not None and threshold is not None:
            facts["SmartSpareBelowThreshold"] = spare <= threshold
        # A drive the collector deliberately left asleep is normal operation
        # and must not wear a warning, where an unexplained stale snapshot
        # really may be a wedged collector. smartctl says which, in its own
        # words, and "STANDBY" is the word.
        reason = facts.get("SmartSnapshotReason")
        if isinstance(reason, str) and reason:
            facts["SmartSnapshotAsleep"] = "STANDBY" in reason.upper()
        for axis in ("Speed", "Width"):
            status = _link_status(facts.get(f"Link{axis}"),
                                  facts.get(f"Link{axis}Max"),
                                  facts.get(f"SlotLink{axis}Max"))
            if status is not None:
                facts[f"Link{axis}Status"] = status

    def _apply_severity(self, collection: str, item: dict) -> None:
        """Row severity, evaluated once every SMART source has merged.
        Hosts and expanders keep their historical shape (no worst field);
        disks and controllers are positively healthy only in their running
        state and neutral when it is unreadable; other scsi device types
        are neutral."""
        if collection == "scsi" and item["type"] in ("scsi-host", "expander"):
            return
        facts = item["facts"]
        # A disk or controller that yielded no health reading says so, so the
        # rule can decline to vouch for it. State == running is the kernel
        # having enumerated the device, not a measurement of its health.
        self._judgement_facts(facts)
        if (collection == "nvme" or item["type"] == "disk") and not has_smart_reading(facts):
            facts.setdefault("SmartUnobservable", _no_reading_reason(facts))
        if collection == "scsi" and item["type"] != "disk":
            healthy = "info"
        else:
            expected = "live" if collection == "nvme" else "running"
            healthy = "ok" if facts.get("State") == expected else "info"
        # Post-hoc because rows here are assembled before SMART merges in;
        # both keys still come from one evaluated list, item_summary's rule.
        opinions = self._opinions(collection, item["type"], facts)
        item["worst_opinion_level"] = worst_level(opinions, healthy=healthy)
        if subset := env.attention(opinions):
            item["opinions"] = subset

    # ── protocol ─────────────────────────────────────────────
    _udisks_ok: bool | None = None

    def _source_for(self, collection: str) -> dict:
        table = {
            "platform": ("hardware-fs", "sysfs DMI + lscpu -J + /proc/meminfo", PLATFORM_REFERENCE),
            "pci": ("hardware-fs", "sysfs + udev hwdb (udevadm --json=short)", PCI_REFERENCE),
            "usb": ("hardware-fs", "sysfs + udev hwdb (udevadm --json=short)", USB_REFERENCE),
            "scsi": ("hardware-fs", "sysfs scsi/sas/enclosure classes + udisks2 SMART", SCSI_REFERENCE),
            "nvme": ("hardware-fs", "sysfs nvme class + udisks2 SMART", NVME_REFERENCE),
        }
        adapter, iface, refs = table[collection]
        notes = None
        if collection in ("scsi", "nvme"):
            missing = []
            if self._udisks_ok is False:
                missing.append("udisks2 is not on the bus — its SMART facts are absent")
            if not os.path.isdir(SMART_SNAPSHOT_DIR):
                missing.append("no root SMART collector snapshots "
                               "(grantDiskAccess) — endurance and verdict absent")
            if missing:
                notes = [*missing,
                         "hwmon (nvme/drivetemp) temperatures are the remaining floor"]
        return env.source(adapter, iface, refs, notes=notes)

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        """The full materialisation, shared: collect() pages it, get_object
        searches it, and main.py's status/snapshot/changes sweeps consume it
        directly instead of re-acquiring per page. Single-flighted so a sweep
        and a concurrent UI poll ride one acquisition (envelope.single_flight
        — coalescing, not caching). The scsi/nvme walks set _udisks_ok on
        self, which is what keeps the source note truthful for whoever
        builds an envelope after this lands."""
        if collection == "pci":
            return await self._pci_items()
        if collection == "usb":
            return await self._usb_items()
        if collection == "scsi":
            return await self._scsi_items_with_health()
        if collection == "nvme":
            return await self._nvme_items()
        if collection == "platform":
            obs = await self._platform_observation()
            return [env.item_summary(obs["object"]["id"], "platform",
                                     obs["object"]["native_id"], obs["facts"])]
        raise env.UnknownCollection(collection)

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, self._source_for(collection),
                                   page, applied, next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    async def get_object(self, collection: str, object_id: str) -> dict:
        if collection == "platform":
            # Not routed through acquire(): the item summary acquire() serves
            # is derived FROM this observation, so going through it would mean
            # rebuilding the original out of its own derivative.
            obs = await self._platform_observation()
            if obs["object"]["id"] != object_id:
                raise env.UnknownObject(object_id)
            return obs
        match = next((i for i in await self.acquire(collection) if i["id"] == object_id), None)
        if match is None:
            raise env.UnknownObject(object_id)
        facts = match["facts"]
        relationships = []
        if collection in ("scsi", "nvme"):
            if facts.get("PCIAddress"):
                relationships.append(env.rel(
                    "attached-to", "out", f"pci:{facts['PCIAddress']}",
                    subsystem="hardware"))
            for block in filter(None, [facts.get("Block"), *(facts.get("Namespaces") or [])]):
                relationships.append(env.rel(
                    "backs", "out", f"block-device:{block}", subsystem="storage"))
            if facts.get("Enclosure"):
                relationships.append(env.rel(
                    "member-of", "out", f"scsi:{facts['Enclosure']}",
                    subsystem="hardware"))
        opinions = self._opinions(collection, match["type"], facts)
        return env.observation(
            self.subsystem,
            env.obj_ref(object_id, match["type"], match["native_id"]),
            self._source_for(collection), facts,
            opinions=opinions, relationships=relationships,
            evidence_ref=env.evidence_ref("hardware", collection, object_id))

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        payload: dict
        if collection == "platform":
            payload = {
                "dmi": _attributes(DMI, withheld=WITHHELD_DMI),
                "lscpu": await anyio.to_thread.run_sync(_lscpu_json),
                "meminfo_MemTotal_bytes": _meminfo_total_bytes(),
            }
        elif collection in ("pci", "usb"):
            name = object_id.split(":", 1)[1]
            base = f"{PCI_DEVICES if collection == 'pci' else USB_DEVICES}/{name}"
            if not _device_directory(base):
                raise env.UnknownObject(object_id)
            payload = {
                "syspath": _realpath(base),
                "udev": await anyio.to_thread.run_sync(_udev_json, base),
            }
        elif collection == "scsi":
            name = object_id.split(":", 1)[1]
            for base in (f"{SCSI_HOSTS}/{name}", f"{SAS_EXPANDERS}/{name}",
                         f"{SCSI_DEVICES}/{name}"):
                if _device_directory(base):
                    payload = {
                        "syspath": _realpath(base),
                        "attributes": _attributes(base),
                    }
                    block = next(iter(_listdir(f"{base}/block")), None)
                    if block:
                        _health, raw = await self._drive_health()
                        payload["udisks2"] = raw.get(block) or None
                    break
            else:
                raise env.UnknownObject(object_id)
        elif collection == "nvme":
            name = object_id.split(":", 1)[1]
            base = f"{NVME_DEVICES}/{name}"
            if not _device_directory(base):
                raise env.UnknownObject(object_id)
            payload = {
                "syspath": _realpath(base),
                "attributes": _attributes(base),
            }
            namespaces = [n for n in _listdir(base)
                          if re.match(rf"^{re.escape(name)}n\d+$", n)]
            if namespaces:
                _health, raw = await self._drive_health()
                payload["udisks2"] = raw.get(namespaces[0]) or None
        else:
            raise env.UnknownCollection(collection)
        return {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": self._source_for(collection)["interface"],
            "payload": payload,
        }


def _realpath_base(path: str) -> str | None:
    try:
        return os.path.basename(_realpath(path))
    except OSError:
        return None
