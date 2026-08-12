"""system subsystem: identity, time, boot, overview — what every host has.

identity/time/boot come from hostname1/timedate1/systemd1 over D-Bus.
overview is the point-in-time host snapshot (ROADMAP slice 1): loadavg,
meminfo, PSI and ARC read straight from procfs — kernel-precomputed
aggregates only, never rates derived from counters (metric time-series stay
with Beszel, SPEC section 12).

Every collection here exists on every host this agent targets, which is now
the defining property of the subsystem: generations and packages moved to
`nix` precisely because they did not. What remains NixOS-specific here is a
handful of facts on otherwise universal objects — the OS version on identity,
the profile pointers on boot — read through agent/nixos.py and omitted rather
than nulled off NixOS (SPEC section 2, rule 7).
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import anyio

from .. import envelope as env
from .. import nixos as nx
from ..rules import worst_level
from ..rules.system import (boot_opinions,
                            overview_opinions, time_opinions)
from ..sysbus import BUS, HOSTNAME1, SYSTEMD, SYSTEMD_MANAGER, SYSTEMD_PATH, TIMEDATE1

# Manager.Environment is the manager-wide environment block; the same property
# name the units adapter redacts per-unit. Declared here rather than imported
# from units so each adapter states its own secret surface, and shared only
# through env.redact_list_properties, which is the mechanism.
SECRET_LIST_PROPERTIES = ("Environment",)

HOSTNAME1_PATH = "/org/freedesktop/hostname1"
TIMEDATE1_PATH = "/org/freedesktop/timedate1"
TIMESYNC1 = "org.freedesktop.timesync1"
TIMESYNC1_PATH = "/org/freedesktop/timesync1"
TIMESYNC1_MANAGER = "org.freedesktop.timesync1.Manager"

# The Nix closure paths and readers live in agent/nixos.py, shared with the
# `nix` adapter that owns generations and packages. This subsystem keeps only
# the NixOS-derived FACTS that belong to a universal object: the OS version on
# identity, and the profile pointers on boot. Both are omitted off NixOS rather
# than nulled (SPEC section 2, rule 7).
PROFILES = nx.PROFILES
CURRENT_SYSTEM = nx.CURRENT_SYSTEM
BOOTED_SYSTEM = nx.BOOTED_SYSTEM
_is_nixos = nx.is_nixos


_read = nx.read
_realpath = nx.realpath
_epoch_to_iso = nx.epoch_to_iso


# ── host overview (procfs, world-readable — SPEC rule 8 tier 3) ───────

ARCSTATS = "/proc/spl/kstat/zfs/arcstats"
OVERVIEW_FILES = ["/proc/uptime", "/proc/loadavg", "/proc/stat", "/proc/meminfo",
                  "/proc/pressure/cpu", "/proc/pressure/memory",
                  "/proc/pressure/io", "/proc/net/dev", "/proc/diskstats",
                  ARCSTATS]
OVERVIEW_REFERENCE = ["uptime", "cat /proc/pressure/*", "free -b",
                      "cat /proc/stat /proc/net/dev /proc/diskstats",
                      # Named because they are READ, not because a tool
                      # summarises them: `uptime` and `free -b` present the
                      # same numbers, but rule 5 asks for a command that
                      # reproduces the observation, and these are it.
                      "cat /proc/uptime /proc/loadavg /proc/meminfo",
                      "cat /proc/spl/kstat/zfs/arcstats",
                      "ls /sys/block"]

# Synthetic block devices whose I/O is noise at host scale.
DISKSTATS_SKIP = re.compile(r"^(loop|ram|zram|sr|fd)\d")


def _net_counters() -> dict:
    """Per-interface cumulative byte counters since boot (/proc/net/dev).
    Counters, not rates, on purpose: the agent holds no previous sample
    (SPEC rules 4/10); a client derives rates across its own polls, with
    the window it actually observed."""
    out: dict[str, dict] = {}
    for line in _read("/proc/net/dev").splitlines()[2:]:
        name, sep, rest = line.partition(":")
        fields = rest.split()
        if sep and len(fields) >= 9:
            out[name.strip()] = {"RxBytes": int(fields[0]), "TxBytes": int(fields[8])}
    return out


def _disk_counters() -> dict:
    """Per-device cumulative read/write bytes since boot (/proc/diskstats,
    sector fields × 512 by kernel contract). Whole devices only — partition
    rows double-count their parent."""
    out: dict[str, dict] = {}
    for line in _read("/proc/diskstats").splitlines():
        fields = line.split()
        if len(fields) < 14:
            continue
        name = fields[2]
        if DISKSTATS_SKIP.match(name) or not os.path.isdir(f"/sys/block/{name}"):
            continue
        out[name] = {"ReadBytes": int(fields[5]) * 512,
                     "WriteBytes": int(fields[9]) * 512,
                     # Field 10 (ms spent doing I/O) is what separates a
                     # saturated device from a merely busy one: bytes/s cannot
                     # tell them apart, because a small-random workload
                     # saturates a disk at a throughput a sequential one would
                     # call idle. A counter, not a rate — the client derives
                     # utilisation across its own poll window, exactly as it
                     # already does for bytes (SPEC rules 4/12).
                     "IoTicksMs": int(fields[12]),
                     # Weighted time in queue: rises faster than IoTicksMs
                     # when requests are queueing, so the pair distinguishes
                     # "busy" from "backed up".
                     "WeightedIoMs": int(fields[13])}
    return out


# /proc/stat's aggregate line, in the kernel's documented field order. steal
# and the guest fields matter on a VM and are meaningless on metal, so they are
# carried when present rather than assumed.
CPU_TIME_FIELDS = ("User", "Nice", "System", "Idle", "Iowait", "Irq",
                   "Softirq", "Steal", "Guest", "GuestNice")


def _cpu_times() -> dict:
    """Cumulative CPU time per state since boot, in the kernel's USER_HZ ticks.

    Counters, not a percentage, for the same reason NetCounters and DiskCounters
    are: the agent holds no previous sample (SPEC rules 4/10), so a client
    derives utilisation across the window it actually observed and can state
    that window. There was no CPU-utilisation fact in this product at all until
    now — only load average, which is a proxy for a different question.

    Iowait is the one worth having separately: a host can be 90% "busy" doing
    nothing but waiting for a disk, which reads as saturated CPU on any meter
    that lumps the states together, and is the exact confusion the per-unit PSI
    work exists to resolve.
    """
    for line in _read("/proc/stat").splitlines():
        fields = line.split()
        if fields and fields[0] == "cpu":
            return {name: int(value) for name, value in
                    zip(CPU_TIME_FIELDS, fields[1:], strict=True) if value.isdigit()}
    return {}


def _meminfo_bytes() -> dict[str, int]:
    """The kB-suffixed /proc/meminfo fields, converted to bytes. The bare
    counters (HugePages_Total and friends) are deliberately not collected."""
    out: dict[str, int] = {}
    for line in _read("/proc/meminfo").splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] == "kB":
            out[fields[0].rstrip(":")] = int(fields[1]) * 1024
    return out


def _psi_facts() -> dict:
    """PSI stall shares — the kernel's own decaying averages, the only
    honest 'how contended is this host right now' numbers that need no
    delta between samples. A kernel without CONFIG_PSI has no
    /proc/pressure: the facts are absent, never zero."""
    facts: dict = {}
    for resource in ("cpu", "memory", "io"):
        for line in _read(f"/proc/pressure/{resource}").splitlines():
            fields = line.split()
            # cpu "full" is defined as zero by the kernel; carrying it
            # would look like a measurement.
            if not fields or (resource == "cpu" and fields[0] == "full"):
                continue
            share = fields[0].capitalize()
            for token in fields[1:]:
                key, _, value = token.partition("=")
                if key.startswith("avg"):
                    facts[f"Psi{resource.capitalize()}{share}Avg{key[3:]}"] = float(value)
    return facts


def _arc_facts() -> dict:
    """ZFS ARC size and target. Absent without the zfs module — absence is
    the fact; zero would read as an empty cache."""
    names = {"size": "ArcSizeBytes", "c": "ArcTargetBytes"}
    facts: dict = {}
    for line in _read(ARCSTATS).splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] in names:
            facts[names[fields[0]]] = int(fields[2])
    return facts


def _overview_facts() -> dict:
    facts: dict = {}
    uptime = _read("/proc/uptime").split()
    if uptime:
        seconds = float(uptime[0])
        facts["UptimeSeconds"] = int(seconds)
        facts["BootedAt"] = _epoch_to_iso(
            datetime.now(timezone.utc).timestamp() - seconds)
    loadavg = _read("/proc/loadavg").split()
    cpus = os.cpu_count()
    if len(loadavg) >= 3:
        facts.update({"LoadAvg1": float(loadavg[0]),
                      "LoadAvg5": float(loadavg[1]),
                      "LoadAvg15": float(loadavg[2]),
                      "CpuCount": cpus})
        if cpus:
            facts["LoadPerCpu1"] = round(facts["LoadAvg1"] / cpus, 2)
    mem = _meminfo_bytes()
    if "MemTotal" in mem and "MemAvailable" in mem and mem["MemTotal"]:
        used = mem["MemTotal"] - mem["MemAvailable"]
        facts.update({"MemTotalBytes": mem["MemTotal"],
                      "MemAvailableBytes": mem["MemAvailable"],
                      "MemUsedBytes": used,
                      "MemUsedPercent": round(used * 100 / mem["MemTotal"])})
    if "SwapTotal" in mem and "SwapFree" in mem:
        swap_used = mem["SwapTotal"] - mem["SwapFree"]
        facts.update({"SwapTotalBytes": mem["SwapTotal"],
                      "SwapUsedBytes": swap_used,
                      # null, not 0%: a swapless host has no swap pressure
                      # to be innocent of.
                      "SwapUsedPercent": round(swap_used * 100 / mem["SwapTotal"])
                                         if mem["SwapTotal"] else None})
    cpu_times = _cpu_times()
    if cpu_times:
        facts["CpuTimes"] = cpu_times
    facts.update(_psi_facts())
    facts.update(_arc_facts())
    net = _net_counters()
    if net:
        facts["NetCounters"] = net
    disk = _disk_counters()
    if disk:
        facts["DiskCounters"] = disk
    return facts


# ── UEFI NVRAM (efivarfs, world-readable — no tool, no capability) ────

EFIVARS = "/sys/firmware/efi/efivars"
EFI_GLOBAL_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


def _efivar(name: str) -> bytes | None:
    """Variable payload with the 4-byte attribute header stripped."""
    try:
        return Path(f"{EFIVARS}/{name}-{EFI_GLOBAL_GUID}").read_bytes()[4:]
    except OSError:
        return None


def _efi_u16(name: str) -> int | None:
    data = _efivar(name)
    return int.from_bytes(data[:2], "little") if data and len(data) >= 2 else None


def _efi_bool(name: str) -> bool | None:
    data = _efivar(name)
    return bool(data[0]) if data else None


def _parse_load_option(data: bytes) -> dict:
    """EFI_LOAD_OPTION: Attributes u32, FilePathListLength u16, Description
    (UTF-16LE, NUL-terminated), then the device path list. Only the nodes an
    operator asks about are decoded: the GPT partition a boot entry points at
    and the loader path on it; everything else is passed over."""
    attributes = int.from_bytes(data[:4], "little")
    fpl_len = int.from_bytes(data[4:6], "little")
    i = 6
    while i + 1 < len(data) and data[i:i + 2] != b"\x00\x00":
        i += 2
    description = data[6:i].decode("utf-16-le", errors="replace")
    device_path = data[i + 2:i + 2 + fpl_len]

    partition_uuid = None
    file_path = None
    j = 0
    while j + 4 <= len(device_path):
        node_type, node_sub = device_path[j], device_path[j + 1]
        node_len = int.from_bytes(device_path[j + 2:j + 4], "little")
        if node_len < 4:
            break
        node = device_path[j + 4:j + node_len]
        if node_type == 0x04 and node_sub == 0x01 and len(node) >= 38 and node[37] == 2:
            # Media/HardDrive node with a GPT signature: the partition GUID.
            partition_uuid = str(uuid.UUID(bytes_le=bytes(node[20:36])))
        elif node_type == 0x04 and node_sub == 0x04:
            file_path = node.decode("utf-16-le", errors="replace").rstrip("\x00")
        elif node_type == 0x7F:
            break
        j += node_len
    return {"attributes": attributes, "description": description,
            "partition_uuid": partition_uuid, "file_path": file_path}


def _efi_facts() -> dict:
    """UEFI boot facts. Empty facts on BIOS hosts — absence of efivarfs is
    the fact (and what keeps the EFI rules from firing there)."""
    if not os.path.isdir(EFIVARS):
        return {"Firmware": "bios"}

    order_raw = _efivar("BootOrder") or b""
    order_ids = [int.from_bytes(order_raw[k:k + 2], "little")
                 for k in range(0, len(order_raw) - 1, 2)]
    current = _efi_u16("BootCurrent")
    boot_next = _efi_u16("BootNext")

    entries = []
    try:
        var_names = sorted(os.listdir(EFIVARS))
    except OSError:
        var_names = []
    for var in var_names:
        if not (var.startswith("Boot") and var.endswith(EFI_GLOBAL_GUID)
                and len(var) == len("BootXXXX-") + len(EFI_GLOBAL_GUID)):
            continue
        try:
            num = int(var[4:8], 16)
        except ValueError:
            continue
        data = _efivar(var[:8])
        if not data:
            continue
        option = _parse_load_option(data)
        device = None
        stale = None
        if option["partition_uuid"]:
            resolved = _realpath(f"/dev/disk/by-partuuid/{option['partition_uuid']}")
            if resolved:
                device = f"block-device:{os.path.basename(resolved)}"
                stale = False
            else:
                stale = True
        in_order = num in order_ids
        entries.append({
            "ID": f"Boot{num:04X}",
            "Description": option["description"],
            "Active": bool(option["attributes"] & 1),
            "OrderPosition": order_ids.index(num) + 1 if in_order else None,
            "Current": num == current,
            "Device": device,
            "FilePath": option["file_path"],
            "Stale": stale,
        })

    facts = {
        "Firmware": "uefi",
        "SecureBoot": _efi_bool("SecureBoot"),
        "SetupMode": _efi_bool("SetupMode"),
        "BootCurrent": f"Boot{current:04X}" if current is not None else None,
        "BootNext": f"Boot{boot_next:04X}" if boot_next is not None else None,
        "BootOrder": [f"Boot{num:04X}" for num in order_ids],
        "BootTimeoutSeconds": _efi_u16("Timeout"),
        "BootEntries": entries,
    }
    return facts


class Adapter:
    subsystem = "system"

    def __init__(self) -> None:
        # acquire() returns rows, but every collection here is one object
        # deep: the page's source and get_object's whole observation come out
        # of the same acquisition the row does, and the source cannot be
        # rebuilt outside it without duplicating decisions made during it
        # (the timesync1-unavailable note on time, the NixOS pointer note on
        # boot). So each flight parks its observation here and callers read
        # it only after awaiting a fresh acquire() — nothing is ever served
        # that was not just observed, which keeps this coalescing, not
        # caching (SPEC section 2, rule 4).
        self._observed: dict[str, dict] = {}

    def collections(self) -> list[str]:
        return ["identity", "time", "boot", "overview"]

    async def capability(self) -> dict:
        # Everything here is universal now that generations and packages have
        # moved to the `nix` subsystem: hostname1/timedate1/systemd1 D-Bus plus
        # procfs, all unconditional on the hosts this agent targets. Nothing to
        # decline — which is the point of having made the split.
        return {"available": True, "collections": self.collections()}

    async def _identity(self) -> dict:
        props = await BUS.get_all(HOSTNAME1, HOSTNAME1_PATH, HOSTNAME1)
        manager = await BUS.get_all(SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER)
        facts = {
            "StaticHostname": props.get("StaticHostname"),
            "Chassis": props.get("Chassis"),
            "OperatingSystemPrettyName": props.get("OperatingSystemPrettyName"),
            "KernelName": props.get("KernelName"),
            "KernelRelease": props.get("KernelRelease"),
            "HardwareVendor": props.get("HardwareVendor"),
            "HardwareModel": props.get("HardwareModel"),
            "Architecture": manager.get("Architecture"),
            "Virtualization": manager.get("Virtualization"),
            "MachineID": env.HOST["machine_id"],
        }
        # NixOS identity, read from the running system closure — present only
        # where there is one to read.
        if _is_nixos():
            facts["NixosVersion"] = _read(f"{CURRENT_SYSTEM}/nixos-version") or None
            facts["ConfigurationRevision"] = (
                _read(f"{CURRENT_SYSTEM}/configuration-revision") or None)
        obj = env.obj_ref(f"identity:{facts['StaticHostname'] or env.HOST['hostname']}",
                          "identity", facts["StaticHostname"] or env.HOST["hostname"])
        return env.observation(
            self.subsystem, obj,
            env.source("system-dbus", HOSTNAME1, ["hostnamectl status", "hostnamectl --json=pretty"],
                       method="org.freedesktop.DBus.Properties.GetAll"),
            facts,
            evidence_ref=env.evidence_ref("system", "identity", obj['id']),
        )

    async def _time(self) -> dict:
        props = await BUS.get_all(TIMEDATE1, TIMEDATE1_PATH, TIMEDATE1)
        facts = {
            "Timezone": props.get("Timezone"),
            "LocalRTC": props.get("LocalRTC"),
            "NTP": props.get("NTP"),
            "NTPSynchronized": props.get("NTPSynchronized"),
            "CurrentTime": env.usec_to_iso(props.get("TimeUSec")),
        }
        notes = []
        # NTP source detail comes from timesyncd where it runs; a chrony host
        # simply lacks these facts rather than faking them.
        try:
            sync = await BUS.get_all(TIMESYNC1, TIMESYNC1_PATH, TIMESYNC1_MANAGER)
            poll_min = sync.get("PollIntervalMinUSec")
            poll_max = sync.get("PollIntervalMaxUSec")
            facts.update({
                "CurrentNTPServer": sync.get("ServerName") or None,
                "SystemNTPServers": sync.get("SystemNTPServers") or [],
                "FallbackNTPServers": sync.get("FallbackNTPServers") or [],
                "PollIntervalSeconds": [
                    round(poll_min / 1e6) if isinstance(poll_min, int) else None,
                    round(poll_max / 1e6) if isinstance(poll_max, int) else None,
                ],
            })
        except Exception:  # noqa: BLE001 - timesyncd absent is a fact, not a failure
            notes.append("timesync1 unavailable; NTP source facts need systemd-timesyncd.")

        obj = env.obj_ref(f"time:{env.HOST['hostname']}", "time", env.HOST["hostname"])
        return env.observation(
            self.subsystem, obj,
            env.source("system-dbus", f"{TIMEDATE1} + {TIMESYNC1}",
                       ["timedatectl status", "timedatectl timesync-status"],
                       method="org.freedesktop.DBus.Properties.GetAll",
                       notes=notes or None),
            facts, opinions=time_opinions(facts),
            evidence_ref=env.evidence_ref("system", "time", obj['id']),
        )

    async def _boot(self) -> dict:
        manager = await BUS.get_all(SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER)
        boot_id = _read("/proc/sys/kernel/random/boot_id").replace("-", "")
        facts = {
            "BootID": boot_id,
            "SystemState": manager.get("SystemState"),
            "NFailedUnits": manager.get("NFailedUnits"),
            "NJobs": manager.get("NJobs"),
            "SystemdVersion": manager.get("Version"),
            "KernelTimestamp": env.usec_to_iso(manager.get("KernelTimestamp")),
            "UserspaceTimestamp": env.usec_to_iso(manager.get("UserspaceTimestamp")),
            "FinishTimestamp": env.usec_to_iso(manager.get("FinishTimestamp")),
        }
        # The three system pointers and how they can disagree — the same
        # semantics an ad-hoc preview script reported, made permanently
        # observable.
        # Nix-only, so absent rather than null elsewhere (see _is_nixos).
        if _is_nixos():
            # nx.pointers(), not self._pointers(): the method moved to
            # agent/nixos.py with the rest of the closure primitives when the
            # nix subsystem split off, and this call site was left behind —
            # which broke system/boot on every NixOS host with an AttributeError
            # until the new empty-collection message made it legible.
            pointers = nx.pointers()
            default_gen = None
            try:
                link = os.readlink(PROFILES / "system")
                if link.startswith("system-") and link.endswith("-link"):
                    default_gen = int(link[len("system-"):-len("-link")])
            except (OSError, ValueError):
                pass
            # Named for what it is: the system profile pointer. It normally
            # becomes the boot default, but a failed bootloader install can
            # leave the two disagreeing — actual bootloader entries
            # (bootctl --json) are a separate, still-open observation.
            facts.update({
                "CurrentSystem": pointers["current"],
                "BootedSystem": pointers["booted"],
                "SystemProfile": pointers["default"],
                "SystemProfileGeneration": default_gen,
            })

        # The firmware's view: what will actually boot, in what order, and
        # whether Secure Boot would block it. Pure efivarfs reads — threaded,
        # because efivarfs is notoriously slow and would stall the loop.
        facts.update(await anyio.to_thread.run_sync(_efi_facts))

        obj = env.obj_ref(f"boot:{boot_id or env.HOST['hostname']}", "boot", boot_id or "unknown")
        return env.observation(
            self.subsystem, obj,
            env.source("system-dbus", SYSTEMD_MANAGER,
                       ["systemctl status", "systemd-analyze", "systemctl is-system-running",
                        "cat /proc/sys/kernel/random/boot_id",
                        # efibootmgr decodes these; the agent reads the
                        # variables directly, so both are named.
                        "efibootmgr -v", "ls /sys/firmware/efi/efivars"]
                       + (["readlink -f /run/current-system /run/booted-system "
                           "/nix/var/nix/profiles/system"] if _is_nixos() else []),
                       method="org.freedesktop.DBus.Properties.GetAll",
                       notes=(["System pointer facts (CurrentSystem, BootedSystem, "
                               "SystemProfile) are filesystem reads, not D-Bus."]
                              if _is_nixos() else None)),
            facts, opinions=boot_opinions(facts),
            evidence_ref=env.evidence_ref("system", "boot", obj['id']),
        )

    async def _overview(self) -> dict:
        facts = _overview_facts()
        obj = env.obj_ref("overview:host", "overview", "host")
        return env.observation(
            self.subsystem, obj,
            env.source("procfs", "/proc", OVERVIEW_REFERENCE),
            facts, opinions=overview_opinions(facts),
            evidence_ref=env.evidence_ref("system", "overview", obj['id']),
        )

    async def _single(self, collection: str) -> dict:
        builder = {"identity": self._identity, "time": self._time, "boot": self._boot,
                   "overview": self._overview}.get(collection)
        if builder is None:
            raise env.UnknownCollection(collection)
        return await builder()

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        """The full materialisation, shared: collect() pages it, get_object()
        serves the observation behind it, and main.py's status/snapshot/changes
        sweeps consume it directly instead of re-acquiring per page.
        Single-flighted so concurrent callers ride one acquisition
        (envelope.single_flight — coalescing, not caching)."""
        obs = await self._single(collection)
        self._observed[collection] = obs
        # healthy=None keeps the single-object rows' historical shape: no
        # opinions omits the severity field rather than asserting "ok".
        return [env.item_summary(
            obs["object"]["id"], obs["object"]["type"], obs["object"]["native_id"],
            obs["facts"],
            worst_opinion_level=worst_level(obs.get("opinions", []), healthy=None),
        )]

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        # No await between acquire() returning and this read, so the source
        # is the one the acquisition just built, notes and all.
        source = self._observed[collection]["source"]
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, source, page,
                                   applied, next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    # Every collection here is a single object whose evaluator is attached
    # inside _single() (agent/rules/system.py), shared verbatim with the
    # summary path so rows and opened objects cannot disagree — routed through
    # acquire() so an open object and a concurrent sweep ride one flight.
    async def get_object(self, collection: str, object_id: str) -> dict:
        await self.acquire(collection)
        obs = self._observed[collection]
        if obs["object"]["id"] != object_id:
            raise env.UnknownObject(object_id)
        return obs

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        if collection == "overview":
            if object_id != "overview:host":
                raise env.UnknownObject(object_id)
            # The raw file contents, captured fresh (SPEC section 2, rule 4);
            # absent files (no PSI, no ZFS) are absent from the payload too.
            payload = {}
            for path in OVERVIEW_FILES:
                content = _read(path)
                if content:
                    payload[path] = content
            return {
                "object_id": object_id,
                "captured_at": env.utc_now(),
                "interface": "/proc",
                "payload": payload,
            }
        current = await self._single(collection)
        if current["object"]["id"] != object_id:
            raise env.UnknownObject(object_id)
        payloads = {
            "identity": (HOSTNAME1, HOSTNAME1_PATH, HOSTNAME1),
            "time": (TIMEDATE1, TIMEDATE1_PATH, TIMEDATE1),
            "boot": (SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER),
        }
        dest, path, iface = payloads[collection]
        payload = {iface: await BUS.get_all(dest, path, iface)}
        if collection == "time":
            try:
                payload[TIMESYNC1_MANAGER] = await BUS.get_all(
                    TIMESYNC1, TIMESYNC1_PATH, TIMESYNC1_MANAGER)
            except Exception:  # noqa: BLE001
                pass
        # org.freedesktop.systemd1.Manager.Environment is the manager-wide
        # block passed to every executed process — systemd.managerEnvironment
        # and `systemctl set-environment` write it — and it was being served
        # verbatim on an unauthenticated API. The units adapter has redacted
        # the per-unit Environment= since the same exposure was found there;
        # this is that property one interface up. Nothing on this estate had
        # anything but LANG and PATH in it, which is why it stayed unnoticed.
        payload, redacted = env.redact_list_properties(payload, SECRET_LIST_PROPERTIES)
        out = {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": iface,
            "method": "org.freedesktop.DBus.Properties.GetAll",
            "payload": payload,
        }
        if redacted:
            out["redacted"] = redacted
        return out
