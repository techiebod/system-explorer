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


PLATFORM_REFERENCE = ["lshw -class system", "dmidecode -t system", "lscpu"]
PCI_REFERENCE = ["lspci -nnk"]
USB_REFERENCE = ["lsusb", "lsusb -t"]
SCSI_REFERENCE = ["lsscsi -v", "ls -l /dev/disk/by-path", "ls /sys/class/enclosure",
                  "smartctl -H /dev/<disk>"]
NVME_REFERENCE = ["nvme list", "smartctl -H /dev/<ctrl>", "cat /sys/class/nvme/*/firmware_rev"]

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
    try:
        return Path(path).read_text().strip() or None
    except OSError:
        return None


def _listdir(path: str) -> list[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def _pci_addr_of(syspath: str) -> str | None:
    """Deepest PCI function on the device's real path — the adapter a
    controller hangs from."""
    addr = None
    for seg in os.path.realpath(syspath).split("/"):
        if PCI_ADDR_RE.match(seg):
            addr = seg
    return addr


def _lscpu_fields(raw: dict) -> dict[str, str]:
    fields: dict[str, str] = {}

    def walk(entries: list) -> None:
        for entry in entries:
            if isinstance(entry, dict):
                if entry.get("field"):
                    fields[entry["field"].rstrip(":")] = entry.get("data")
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
            device = os.path.realpath(f"{HWMON}/{hw}/device")
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
            # is working correctly (seen on vat, 2026-08-11).
            recorded_reason = await anyio.to_thread.run_sync(_smart_no_reading, dev)
            if recorded_reason:
                info["SmartSnapshotReason"] = recorded_reason
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
                data = None
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
        for path, ifaces in objects.items():
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
            facts, evidence_ref=f"/v1/hardware/platform/{obj['id']}/evidence")

    # ── pci ──────────────────────────────────────────────────
    async def _pci_items(self) -> list[dict]:
        addresses = _listdir(PCI_DEVICES)
        udev = await asyncio.gather(*(
            anyio.to_thread.run_sync(_udev_json, f"{PCI_DEVICES}/{a}")
            for a in addresses))
        items = []
        for address, props in zip(addresses, udev):
            facts = {
                "Class": props.get("ID_PCI_SUBCLASS_FROM_DATABASE")
                         or props.get("ID_PCI_CLASS_FROM_DATABASE"),
                "Vendor": props.get("ID_VENDOR_FROM_DATABASE"),
                "Model": props.get("ID_MODEL_FROM_DATABASE"),
                "Driver": props.get("DRIVER"),
                "PCIID": props.get("PCI_ID"),
            }
            items.append(env.item_summary(f"pci:{address}", "pci-device",
                                          address, facts))
        return items

    # ── usb ──────────────────────────────────────────────────
    async def _usb_items(self) -> list[dict]:
        names = [n for n in _listdir(USB_DEVICES) if USB_DEV_RE.match(n)]
        udev = await asyncio.gather(*(
            anyio.to_thread.run_sync(_udev_json, f"{USB_DEVICES}/{n}")
            for n in names))
        items = []
        for name, props in zip(names, udev):
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
                name, facts))
        return items

    # ── scsi topology ────────────────────────────────────────
    @staticmethod
    def _chain_of(syspath: str) -> list[str]:
        """Topology nodes along a device's real sysfs path, outermost first."""
        return [seg for seg in os.path.realpath(syspath).split("/")
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
                device = os.path.realpath(f"{comp_dir}/device")
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
            facts = {"Driver": _read(f"{base}/proc_name"),
                     "State": _read(f"{base}/state"),
                     "PCIAddress": pci_addr}
            # The controller's own identity, so a host row names its silicon
            # in the shared Vendor/Model columns instead of a wall of dashes.
            if pci_addr:
                try:
                    props = _udev_json(f"{PCI_DEVICES}/{pci_addr}").get("properties", {})
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
                f"scsi:{host}", "scsi-host", host, facts)
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
            items_by_name[expander] = env.item_summary(
                f"scsi:{expander}", "expander", expander, facts)
            chain = self._chain_of(f"{base}/device")
            parents[expander] = next((s for s in reversed(chain) if s != expander), None)

        for dev in _listdir(SCSI_DEVICES):
            if not SCSI_DEV_RE.match(dev):
                continue
            base = f"{SCSI_DEVICES}/{dev}"
            type_code = _int_or_none(_read(f"{base}/type"))
            dev_type = SCSI_TYPES.get(type_code if type_code is not None else -1, "device")
            block = next(iter(_listdir(f"{base}/block")), None)
            chain = self._chain_of(base)
            end_device = next((seg for seg in os.path.realpath(base).split("/")
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
            try:
                raw_vpd = Path(f"{base}/vpd_pg80").read_bytes()
                serial = raw_vpd[4:].decode("ascii", errors="ignore").strip() or None
            except OSError:
                pass
            # Capacity from the kernel's sector count — the same read the
            # storage subsystem trusts for md arrays; 512-byte units by
            # sysfs contract regardless of the device's logical block size.
            sectors = None
            if block:
                try:
                    sectors = int(Path(f"/sys/block/{block}/size").read_text())
                except (OSError, ValueError):
                    pass
            facts = {
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
            items_by_name[dev] = env.item_summary(f"scsi:{dev}", dev_type, dev, facts)
            parents[dev] = chain[-1] if chain else None

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
                "Serial": _read(f"{base}/serial"),
                "State": _read(f"{base}/state"),
                "Transport": _read(f"{base}/transport"),
                "PCIAddress": _pci_addr_of(f"{base}/device"),
                "Namespaces": namespaces,
            }
            items.append(env.item_summary(f"nvme:{ctrl}", "nvme-controller",
                                          ctrl, facts))
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
            item["facts"].setdefault("SmartTemperatureC", hwmon.get(item["native_id"]))
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
                item["facts"].setdefault("SmartTemperatureC", hwmon.get(block))
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
        if (collection == "nvme" or item["type"] == "disk") and not has_smart_reading(facts):
            facts.setdefault("SmartUnobservable", _no_reading_reason(facts))
        if collection == "scsi" and item["type"] != "disk":
            healthy = "info"
        else:
            expected = "live" if collection == "nvme" else "running"
            healthy = "ok" if facts.get("State") == expected else "info"
        item["worst_opinion_level"] = worst_level(
            self._opinions(collection, item["type"], facts), healthy=healthy)

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

    async def _items(self, collection: str) -> list[dict]:
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
        items = env.apply_fact_filters(await self._items(collection), query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, self._source_for(collection),
                                   page, applied, next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    async def get_object(self, collection: str, object_id: str) -> dict:
        if collection == "platform":
            obs = await self._platform_observation()
            if obs["object"]["id"] != object_id:
                raise env.UnknownObject(object_id)
            return obs
        match = next((i for i in await self._items(collection) if i["id"] == object_id), None)
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
            evidence_ref=f"/v1/hardware/{collection}/{object_id}/evidence")

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        payload: dict
        if collection == "platform":
            payload = {
                "dmi": {name: _read(f"{DMI}/{name}") for name in _listdir(DMI)
                        if os.path.isfile(f"{DMI}/{name}")},
                "lscpu": await anyio.to_thread.run_sync(_lscpu_json),
                "meminfo_MemTotal_bytes": _meminfo_total_bytes(),
            }
        elif collection in ("pci", "usb"):
            name = object_id.split(":", 1)[1]
            base = f"{PCI_DEVICES if collection == 'pci' else USB_DEVICES}/{name}"
            if not os.path.isdir(base):
                raise env.UnknownObject(object_id)
            payload = {
                "syspath": os.path.realpath(base),
                "udev": await anyio.to_thread.run_sync(_udev_json, base),
            }
        elif collection == "scsi":
            name = object_id.split(":", 1)[1]
            for base in (f"{SCSI_HOSTS}/{name}", f"{SAS_EXPANDERS}/{name}",
                         f"{SCSI_DEVICES}/{name}"):
                if os.path.isdir(base):
                    payload = {
                        "syspath": os.path.realpath(base),
                        "attributes": {attr: _read(f"{base}/{attr}")
                                       for attr in _listdir(base)
                                       if os.path.isfile(f"{base}/{attr}")},
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
            if not os.path.isdir(base):
                raise env.UnknownObject(object_id)
            payload = {
                "syspath": os.path.realpath(base),
                "attributes": {attr: _read(f"{base}/{attr}")
                               for attr in _listdir(base)
                               if os.path.isfile(f"{base}/{attr}")},
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
        return os.path.basename(os.path.realpath(path))
    except OSError:
        return None
