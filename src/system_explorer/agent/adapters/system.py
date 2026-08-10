"""system subsystem: identity, time, boot, generations, packages, overview.

identity/time/boot come from hostname1/timedate1/systemd1 over D-Bus. The
NixOS view — generations and packages — is pure filesystem reading: profile
symlinks under /nix/var/nix/profiles, the metadata files every system
closure carries (nixos-version, configuration-revision), and the
/run/current-system/sw link farm. Nothing is executed; the store *is* the
structured interface. overview is the point-in-time host snapshot (ROADMAP
slice 1): loadavg, meminfo, PSI and ARC read straight from procfs —
kernel-precomputed aggregates only, never rates derived from counters
(metric time-series stay with Beszel, SPEC section 12).
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import anyio

from .. import envelope as env
from ..rules import worst_level
from ..rules.system import (boot_opinions, generation_opinions,
                            overview_opinions, time_opinions)
from ..sysbus import BUS, HOSTNAME1, SYSTEMD, SYSTEMD_MANAGER, SYSTEMD_PATH, TIMEDATE1

HOSTNAME1_PATH = "/org/freedesktop/hostname1"
TIMEDATE1_PATH = "/org/freedesktop/timedate1"
TIMESYNC1 = "org.freedesktop.timesync1"
TIMESYNC1_PATH = "/org/freedesktop/timesync1"
TIMESYNC1_MANAGER = "org.freedesktop.timesync1.Manager"

PROFILES = Path("/nix/var/nix/profiles")
CURRENT_SYSTEM = "/run/current-system"
BOOTED_SYSTEM = "/run/booted-system"
SW = f"{CURRENT_SYSTEM}/sw"


def _is_nixos() -> bool:
    """Whether this host has a nix system closure to read facts out of.

    /run/current-system is the activated-closure pointer, and it exists only
    where something activated one. Nix-derived facts are omitted entirely off
    such a host rather than emitted as nulls: a null "NixosVersion" on Debian
    reads as *unknown*, when the truth is *not applicable*, and four null rows
    on the boot card is what a non-Nix user saw first (ROADMAP section 5,
    phase 2). Absence with a reason is the rule (SPEC section 2, rule 7);
    for individual facts, the honest form of that is not to claim the fact.
    """
    return os.path.exists(CURRENT_SYSTEM)

GENERATIONS_REFERENCE = ["nixos-rebuild list-generations",
                         "ls -l /nix/var/nix/profiles",
                         "readlink -f /run/current-system /run/booted-system"]
PACKAGES_REFERENCE = ["ls /run/current-system/sw/bin",
                      "readlink /run/current-system/sw/bin/<command>"]

STORE_RE = re.compile(r"(/nix/store/[a-z0-9]{32}-([^/]+))")
# name-version split: the version starts at the first dash followed by a digit.
NAME_VERSION_RE = re.compile(r"(.+?)-([0-9].*)")


def _read(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return ""


def _realpath(path: str) -> str | None:
    try:
        return os.path.realpath(path) if os.path.exists(path) else None
    except OSError:
        return None


def _epoch_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── host overview (procfs, world-readable — SPEC rule 8 tier 3) ───────

ARCSTATS = "/proc/spl/kstat/zfs/arcstats"
OVERVIEW_FILES = ["/proc/uptime", "/proc/loadavg", "/proc/meminfo",
                  "/proc/pressure/cpu", "/proc/pressure/memory",
                  "/proc/pressure/io", "/proc/net/dev", "/proc/diskstats",
                  ARCSTATS]
OVERVIEW_REFERENCE = ["uptime", "cat /proc/pressure/*", "free -b",
                      "cat /proc/net/dev /proc/diskstats"]

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
                     "WriteBytes": int(fields[9]) * 512}
    return out


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

    def collections(self) -> list[str]:
        return ["identity", "time", "boot", "generations", "packages", "overview"]

    async def capability(self) -> dict:
        # overview needs no gate: procfs is unconditional on the kernels
        # this agent targets.
        unavailable: dict[str, str] = {}
        if not PROFILES.is_dir():
            unavailable["generations"] = f"{PROFILES} does not exist (not a NixOS host?)"
        if not os.path.isdir(SW):
            unavailable["packages"] = f"{SW} does not exist (not a NixOS host?)"
        return {"available": True,
                "collections": [c for c in self.collections() if c not in unavailable],
                "unavailable_collections": unavailable}

    # ── generations ──────────────────────────────────────────
    @staticmethod
    def _pointers() -> dict[str, str | None]:
        return {"current": _realpath(CURRENT_SYSTEM),
                "booted": _realpath(BOOTED_SYSTEM),
                "default": _realpath(str(PROFILES / "system"))}

    @staticmethod
    def _generation_links() -> list[tuple[int, Path, str]]:
        """(generation number, profile link, store path), newest first."""
        out = []
        for link in PROFILES.glob("system-*-link"):
            try:
                number = int(link.name[len("system-"):-len("-link")])
            except ValueError:
                continue
            try:
                out.append((number, link, os.readlink(link)))
            except OSError:
                continue
        return sorted(out, reverse=True)

    def _generation_items(self) -> list[dict]:
        pointers = self._pointers()
        items = []
        for number, link, target in self._generation_links():
            kernel = _realpath(f"{target}/kernel")
            kernel_match = STORE_RE.match(kernel or "")
            revision = _read(f"{target}/configuration-revision")
            try:
                specialisations = sorted(os.listdir(f"{target}/specialisation"))
            except OSError:
                specialisations = []
            facts = {
                "NixosVersion": _read(f"{target}/nixos-version") or None,
                "Kernel": kernel_match.group(2) if kernel_match else None,
                "ConfigurationRevision": revision or None,
                "Created": _epoch_to_iso(link.lstat().st_mtime),
                "Current": target == pointers["current"],
                "Booted": target == pointers["booted"],
                "Profile": target == pointers["default"],
                "Specialisations": specialisations,
                "StorePath": target,
            }
            # Only the running generation is positively vouched for; the rest
            # are neutral history unless a rule (generation-pending) fires.
            items.append(env.item_summary(
                f"generation:{number}", "generation", str(number), facts,
                worst_opinion_level=worst_level(
                    generation_opinions(facts),
                    healthy="ok" if facts["Current"] else "info")))
        return items

    # ── packages ─────────────────────────────────────────────
    @staticmethod
    def _package_paths() -> dict[str, str]:
        """name-version → store path for everything linked into the system
        environment. Two scandir levels: buildEnv links packages directly or,
        on collision, merges one directory level and links inside it."""
        seen: dict[str, str] = {}

        def record(link_target: str) -> None:
            match = STORE_RE.match(link_target)
            if match:
                seen.setdefault(match.group(2), match.group(1))

        for sub in ("bin", "sbin", "lib", "libexec", "share", "etc"):
            root = os.path.join(SW, sub)
            try:
                level_one = list(os.scandir(root))
            except OSError:
                continue
            for entry in level_one:
                if entry.is_symlink():
                    record(os.readlink(entry.path))
                elif entry.is_dir(follow_symlinks=False):
                    try:
                        for nested in os.scandir(entry.path):
                            if nested.is_symlink():
                                record(os.readlink(nested.path))
                    except OSError:
                        continue
        return seen

    def _package_items(self) -> list[dict]:
        items = []
        for name_version, store_path in sorted(self._package_paths().items()):
            match = NAME_VERSION_RE.match(name_version)
            facts = {
                "Name": match.group(1) if match else name_version,
                "Version": match.group(2) if match else None,
                "StorePath": store_path,
            }
            items.append(env.item_summary(
                f"package:{name_version}", "package", name_version, facts))
        items.sort(key=lambda i: (i["facts"]["Name"], i["native_id"]))
        return items

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
            evidence_ref=f"/v1/system/identity/{obj['id']}/evidence",
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
            evidence_ref=f"/v1/system/time/{obj['id']}/evidence",
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
            pointers = self._pointers()
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
                       ["systemctl status", "systemd-analyze", "systemctl is-system-running"]
                       + (["readlink -f /run/current-system /run/booted-system "
                           "/nix/var/nix/profiles/system"] if _is_nixos() else []),
                       method="org.freedesktop.DBus.Properties.GetAll",
                       notes=(["System pointer facts (CurrentSystem, BootedSystem, "
                               "SystemProfile) are filesystem reads, not D-Bus."]
                              if _is_nixos() else None)),
            facts, opinions=boot_opinions(facts),
            evidence_ref=f"/v1/system/boot/{obj['id']}/evidence",
        )

    async def _overview(self) -> dict:
        facts = _overview_facts()
        obj = env.obj_ref("overview:host", "overview", "host")
        return env.observation(
            self.subsystem, obj,
            env.source("procfs", "/proc", OVERVIEW_REFERENCE),
            facts, opinions=overview_opinions(facts),
            evidence_ref=f"/v1/system/overview/{obj['id']}/evidence",
        )

    async def _single(self, collection: str) -> dict:
        builder = {"identity": self._identity, "time": self._time, "boot": self._boot,
                   "overview": self._overview}.get(collection)
        if builder is None:
            raise env.UnknownCollection(collection)
        return await builder()

    def _multi_source(self, collection: str) -> dict:
        if collection == "generations":
            return env.source("nixos-fs", "/nix/var/nix/profiles (filesystem)",
                              GENERATIONS_REFERENCE)
        return env.source("nixos-fs", "/run/current-system/sw (filesystem)",
                          PACKAGES_REFERENCE)

    def _multi_items(self, collection: str) -> list[dict]:
        if collection == "generations":
            return self._generation_items()
        if collection == "packages":
            return self._package_items()
        raise env.UnknownCollection(collection)

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        if collection in ("generations", "packages"):
            # The link-farm and profile scandir walks are synchronous
            # filesystem work — off the event loop like every other adapter's
            # acquisition (backlog note, 2026-08-09: async hygiene).
            fetched = await anyio.to_thread.run_sync(self._multi_items, collection)
            items = env.apply_fact_filters(fetched, query)
            page, applied, next_cursor, total = env.paginate(items, limit, cursor)
            return env.collection_page(self.subsystem, collection,
                                       self._multi_source(collection), page,
                                       applied, next_cursor, requested_limit=limit,
                                       total=total, filters=query or None)
        obs = await self._single(collection)
        # healthy=None keeps the single-object rows' historical shape: no
        # opinions omits the severity field rather than asserting "ok".
        item = env.item_summary(
            obs["object"]["id"], obs["object"]["type"], obs["object"]["native_id"],
            obs["facts"],
            worst_opinion_level=worst_level(obs.get("opinions", []), healthy=None),
        )
        items = env.apply_fact_filters([item], query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, obs["source"], page,
                                   applied, next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    # Evaluators per collection (agent/rules/system.py), shared verbatim with
    # the summary path — rows and opened objects cannot disagree. time, boot
    # and overview attach theirs inside _single(), so only generations
    # dispatches here.
    _RULES = {"generations": generation_opinions}

    async def get_object(self, collection: str, object_id: str) -> dict:
        if collection in ("generations", "packages"):
            fetched = await anyio.to_thread.run_sync(self._multi_items, collection)
            match = next((i for i in fetched if i["id"] == object_id), None)
            if match is None:
                raise env.UnknownObject(object_id)
            rule = self._RULES.get(collection)
            opinions = rule(match["facts"]) if rule else []
            return env.observation(
                self.subsystem,
                env.obj_ref(object_id, match["type"], match["native_id"]),
                self._multi_source(collection), match["facts"], opinions=opinions,
                evidence_ref=f"/v1/system/{collection}/{object_id}/evidence")
        obs = await self._single(collection)
        if obs["object"]["id"] != object_id:
            raise env.UnknownObject(object_id)
        return obs

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        if collection == "generations":
            number = object_id.removeprefix("generation:")
            link = PROFILES / f"system-{number}-link"
            if not link.is_symlink():
                raise env.UnknownObject(object_id)
            target = os.readlink(link)
            return {
                "object_id": object_id,
                "captured_at": env.utc_now(),
                "interface": "/nix/var/nix/profiles (filesystem)",
                "payload": {
                    "link": str(link), "target": target,
                    "pointers": self._pointers(),
                    "nixos-version": _read(f"{target}/nixos-version"),
                    "configuration-revision": _read(f"{target}/configuration-revision"),
                    "kernel": _realpath(f"{target}/kernel"),
                },
            }
        if collection == "packages":
            name_version = object_id.removeprefix("package:")
            store_path = self._package_paths().get(name_version)
            if store_path is None:
                raise env.UnknownObject(object_id)
            links = {}
            for sub in ("bin", "sbin", "lib", "libexec", "share", "etc"):
                root = os.path.join(SW, sub)
                try:
                    for entry in os.scandir(root):
                        if entry.is_symlink():
                            target = os.readlink(entry.path)
                            if target.startswith(store_path + "/"):
                                links[f"{sub}/{entry.name}"] = target
                except OSError:
                    continue
            return {
                "object_id": object_id,
                "captured_at": env.utc_now(),
                "interface": "/run/current-system/sw (filesystem)",
                "payload": {"store_path": store_path, "links": links},
            }
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
        return {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": iface,
            "method": "org.freedesktop.DBus.Properties.GetAll",
            "payload": payload,
        }
