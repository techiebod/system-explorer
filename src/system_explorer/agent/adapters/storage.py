"""storage subsystem: block devices, mounts, md arrays, and (capability-gated) ZFS.

Sources are structured CLI output (lsblk -J, findmnt -J, zpool/zfs -j) plus
sysfs for md arrays, which have no structured CLI — /sys/block/*/md is the
kernel's own view, no /proc/mdstat parsing. ZFS collections report
unsupported with a reason on hosts without OpenZFS — absence is a capability
statement, not a fake domain.

Cross-links (SPEC section 2, typed relationships): partitions and disks are
member-of the arrays and pools built on them; arrays back their exposed
block device; datasets are member-of their pool and parent dataset and
mount their mountpoint; zfs mounts point back at their dataset.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time

import anyio

from .. import envelope as env
from ..rules import worst_level
from ..rules.storage import (MD_ACTIVE_SYNC, array_opinions, dataset_opinions,
                             mount_opinions, pool_opinions)

LSBLK_COLUMNS = "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL,ROTA,RM"

# zpool/zfs normalise short column names in -j output (alloc -> allocated,
# avail -> available); the value() helpers below use the long keys.
ZPOOL_LIST_COLUMNS = "name,size,alloc,free,cap,frag,health"
# usedbysnapshots is precomputed pool metadata — snapshot weight per dataset
# at zero marginal cost, no enumeration.
ZFS_LIST_COLUMNS = "name,used,avail,usedbysnapshots,mountpoint,canmount,readonly,mounted"

# libata and usb-storage report the transport where SCSI reports a vendor;
# the same strings appear in zpool vdev names never, so scoped to md/scsi.
ZFS_GROUP_VDEVS = {"logs", "l2cache", "spares"}

# Snapshots are asked for, never enumerated wholesale: a sanoid host carries
# thousands, so they are a parameterised lookup scoped to one dataset (SPEC
# section 6), not a collection the UI would re-poll. The newest rows render;
# the rest is a stated count, never a silent cap.
STORAGE_LOOKUPS = {
    "snapshots-of": {
        "Question": "Which snapshots and bookmarks exist for this dataset?",
        "Input": "a dataset name; append /* to include descendants",
        "Example": "tank/home",
    },
}

# Safety gate for the argv token, not full zfs-name validation: alnum start
# (no leading dash), the zfs name charset, optional trailing /* marker.
DATASET_ARG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:%/-]{0,254}$")

SNAPSHOT_DISPLAY_CAP = 100


def _zfs_snapshots(dataset: str, recursive: bool) -> dict:
    depth = ["-r"] if recursive else ["-d", "1"]
    return _run_json(["zfs", "list", "-j", "-p", "-t", "snapshot,bookmark",
                      *depth, "-o", "name,used,creation,referenced", dataset])


def _epoch_iso(raw: object) -> str | None:
    seconds = _int_or_none(raw)
    if seconds is None:
        return None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_json(cmd: list[str]) -> dict:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=True)
    return json.loads(proc.stdout)


def _lsblk() -> dict:
    return _run_json(["lsblk", "-J", "-o", LSBLK_COLUMNS])


# Whether the last findmnt read fell back to the agent's own mount namespace
# (see _findmnt); _source_for("mounts") turns it into a source note.
_findmnt_fallback = False


def _findmnt() -> dict:
    # --task 1 reads PID 1's mount namespace — the host's truth. The agent's
    # own view is a sandbox artifact: ProtectSystem=strict re-mounts "/" ro
    # and PrivateTmp substitutes a private /tmp, so every host reported / as
    # ro (2026-08-10 audit, systemic). /proc/1/mountinfo is world-readable
    # and the module sets no ProtectProc, so the read needs no privilege.
    # If the invocation fails (older util-linux, hardened /proc), fall back
    # to the agent's namespace and say so in the source notes rather than
    # passing the sandbox view off as the host's. Both argvs stay literal so
    # the lint sees their tokens (SPEC section 11, rule 5).
    global _findmnt_fallback
    try:
        data = _run_json(["findmnt", "-J", "--real", "-b", "--task", "1",
                          "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,SIZE,USED,AVAIL,USE%"])
        _findmnt_fallback = False
        return data
    except (subprocess.CalledProcessError, OSError):
        _findmnt_fallback = True
        return _run_json(["findmnt", "-J", "--real", "-b",
                          "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,SIZE,USED,AVAIL,USE%"])


def _zpool_status() -> dict:
    # --json-int renders scan_stats times as epoch ints (verified against
    # OpenZFS 2026-08-09); without it end_time is a locale string ("Sun 1
    # Feb 16:14:52 GMT 2026") no machine consumer can compare. Older
    # OpenZFS rejects the flag — fall back to plain -j and degrade
    # honestly (ScanEndTime stays verbatim, ScanAgeDays is omitted). Both
    # argvs stay literal so the lint sees their tokens (SPEC section 11,
    # rule 5).
    try:
        return _run_json(["zpool", "status", "-j", "--json-int"])
    except subprocess.CalledProcessError:
        return _run_json(["zpool", "status", "-j"])


def _zpool_list() -> dict:
    # -v adds per-vdev rows: top-level vdevs carry their own size/alloc/
    # capacity (leaves report '-'), which feeds the pool capacity meters.
    return _run_json(["zpool", "list", "-j", "-p", "-v", "-o", ZPOOL_LIST_COLUMNS])


def _zfs_list() -> dict:
    return _run_json(["zfs", "list", "-j", "-p", "-o", ZFS_LIST_COLUMNS])


def _zpool_evidence() -> dict:
    return {"status": _zpool_status(), "list": _zpool_list()}


def _int_or_none(raw: object) -> int | None:
    try:
        return int(str(raw))
    except (TypeError, ValueError):
        return None


def _sys_read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            value = fh.read().strip()
        return value or None
    except OSError:
        return None


def _sys_list(path: str) -> list[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


# ── md arrays (sysfs) ────────────────────────────────────────


def _md_scrape() -> dict:
    """Every md array on the host, from /sys/block/*/md."""
    arrays: dict[str, dict] = {}
    for name in _sys_list("/sys/block"):
        md = f"/sys/block/{name}/md"
        if not os.path.isdir(md):
            continue
        members: dict[str, dict] = {}
        for entry in _sys_list(md):
            if not entry.startswith("dev-"):
                continue
            dev = f"{md}/{entry}"
            kname = os.path.basename(os.path.realpath(f"{dev}/block"))
            members[kname] = {
                "state": _sys_read(f"{dev}/state"),
                "slot": _sys_read(f"{dev}/slot"),
                "errors": _int_or_none(_sys_read(f"{dev}/errors")),
            }
        percent = None
        sync_completed = _sys_read(f"{md}/sync_completed")
        if sync_completed and "/" in sync_completed:
            try:
                done, total = (int(part.strip()) for part in sync_completed.split("/"))
                percent = round(done * 100 / total, 1) if total else None
            except ValueError:
                percent = None
        sectors = _int_or_none(_sys_read(f"/sys/block/{name}/size"))
        arrays[name] = {
            "level": _sys_read(f"{md}/level"),
            "array_state": _sys_read(f"{md}/array_state"),
            "degraded": _int_or_none(_sys_read(f"{md}/degraded")),
            "raid_disks": _int_or_none(_sys_read(f"{md}/raid_disks")),
            "metadata_version": _sys_read(f"{md}/metadata_version"),
            "uuid": _sys_read(f"{md}/uuid"),
            "sync_action": _sys_read(f"{md}/sync_action"),
            "sync_completed": sync_completed,
            "sync_percent": percent,
            "size_bytes": sectors * 512 if sectors is not None else None,
            "members": members,
        }
    return {"arrays": arrays}


def _md_holders(kname: str) -> list[str]:
    """md arrays this block device is a member of (kernel holders links)."""
    return [holder for holder in _sys_list(f"/sys/class/block/{kname}/holders")
            if os.path.isdir(f"/sys/block/{holder}/md")]


# ── zfs helpers ──────────────────────────────────────────────


def _resolve_leaf_kname(name: str) -> str | None:
    """Leaf vdev name -> kernel block name. zpool reports whatever path the
    pool was imported with (wwn-*, by-id, plain sdX, absolute paths, or —
    for stripe-pool leaves — a bare partition GUID); the kname is what
    lsblk and the block-devices collection agree on."""
    path = name if name.startswith("/") else None
    if path is None:
        # by-partuuid: stripe leaves are named by partition GUID alone.
        for base in ("/dev", "/dev/disk/by-id", "/dev/disk/by-partuuid"):
            candidate = f"{base}/{name}"
            if os.path.exists(candidate):
                path = candidate
                break
    if path and os.path.exists(path):
        return os.path.basename(os.path.realpath(path))
    return None


def _flatten_vdevs(nodes: dict | None, out: list[dict], group: str = "data",
                   depth: int = 1) -> None:
    """Depth-first vdev walk. Group vdevs (logs, l2cache, spares) label their
    subtree; the root vdev is namespace, not a device. Depth drives the UI's
    tree indentation; Device is the resolved, linkable kernel block name."""
    for name, vdev in (nodes or {}).items():
        is_container = vdev.get("vdev_type") == "root" or name in ZFS_GROUP_VDEVS
        next_group = name if name in ZFS_GROUP_VDEVS else group
        child_depth = depth
        if not is_container:
            # Stripe pools omit the "vdev_type" (and "state") keys on their
            # leaf entries entirely; a childless vdev under a non-group
            # parent is a plain disk in zpool's own semantics — the JSON
            # just leaves the key out. Infer "disk" so stripe leaves get
            # the same Device resolution and member-of edges as typed raidz
            # leaves; State stays as reported (absent -> None, which the
            # UnhealthyVdevs filter already tolerates). Native semantic,
            # absent key — verified against a stripe layout, 2026-08-09.
            vdev_type = vdev.get("vdev_type")
            if vdev_type is None and not vdev.get("vdevs"):
                vdev_type = "disk"
            # Key order is column order in the UI's mini-table: the resolved
            # Device sits beside State (the wwn-* vdev name alone answers
            # nothing), and Group only appears for special classes — "data"
            # is the default, not information.
            entry = {
                "Name": name,
                "Depth": depth,
                "Type": vdev_type,
                "State": vdev.get("state"),
                # Explicit None on container rows keeps the Device column
                # beside State — the UI derives column order from the first
                # row that mentions a key, and raidz rows come first.
                "Device": None,
            }
            if vdev_type == "disk":
                # zpool's own path field is authoritative; the vdev NAME is
                # only a fallback (some hosts lack the matching by-id link).
                kname = None
                path = vdev.get("path")
                if path and os.path.exists(path):
                    kname = os.path.basename(os.path.realpath(path))
                if kname is None:
                    kname = _resolve_leaf_kname(str(name))
                entry["Device"] = f"block-device:{kname}" if kname else None
            if next_group != "data":
                entry["Group"] = next_group
            entry.update({
                "ReadErrors": _int_or_none(vdev.get("read_errors")),
                "WriteErrors": _int_or_none(vdev.get("write_errors")),
                "ChecksumErrors": _int_or_none(vdev.get("checksum_errors")),
            })
            out.append(entry)
            child_depth = depth + 1
        _flatten_vdevs(vdev.get("vdevs"), out, next_group, child_depth)


def _leaf_device_knames(vdevs: list[dict]) -> dict[str, str]:
    """Leaf vdev name -> kname for relationship edges, from the Device
    already resolved during the vdev walk — one resolution point."""
    out: dict[str, str] = {}
    for vdev in vdevs:
        device = vdev.get("Device")
        if vdev.get("Type") == "disk" and device:
            out[str(vdev["Name"])] = str(device).removeprefix("block-device:")
    return out


def _prop_value(props: dict, key: str) -> str | None:
    return ((props.get(key) or {}).get("value")) or None


def _prop_source(props: dict, key: str) -> str | None:
    source = (props.get(key) or {}).get("source") or {}
    stype = source.get("type")
    if stype == "INHERITED":
        return f"inherited from {source.get('data')}"
    if not stype or stype == "NONE":
        return None
    return str(stype).lower()


def _use_percent(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(str(raw).rstrip("%"))
    except ValueError:
        return None


def _flatten_devices(nodes: list[dict], parent: str | None = None,
                     depth: int = 0) -> list[tuple[dict, str | None, int]]:
    out = []
    for node in nodes:
        out.append((node, parent, depth))
        out.extend(_flatten_devices(node.get("children", []), node.get("name"), depth + 1))
    return out


def _flatten_mounts(nodes: list[dict], depth: int = 0) -> list[tuple[dict, int]]:
    out = []
    for node in nodes:
        out.append((node, depth))
        out.extend(_flatten_mounts(node.get("children", []), depth + 1))
    return out


class Adapter:
    subsystem = "storage"

    # A failed probe is retried after this long; success is cached forever.
    # Without the retry a probe racing boot-time pool import pinned
    # "unavailable" into capabilities until agent restart (backlog note,
    # 2026-08-09) — the same fix as network's _nft_available.
    PROBE_RETRY_SECONDS = 60

    def __init__(self) -> None:
        self._zfs = shutil.which("zpool") is not None
        self._zfs_probe: tuple[bool, str] | None = None
        self._zfs_probed_at: float = 0.0

    def collections(self) -> list[str]:
        base = ["block-devices", "mounts", "arrays"]
        return base + (["pools", "datasets", "lookups"] if self._zfs else [])

    async def _zfs_readable(self) -> tuple[bool, str]:
        """zpool being on PATH says nothing about /dev/zfs permissions or a
        pool-less host; probe on first use, report the actual failure, and
        re-probe failures on a TTL."""
        stale = (self._zfs_probe is not None and not self._zfs_probe[0]
                 and time.monotonic() - self._zfs_probed_at > self.PROBE_RETRY_SECONDS)
        if self._zfs_probe is None or stale:
            self._zfs_probed_at = time.monotonic()
            try:
                await anyio.to_thread.run_sync(_zpool_status)
                self._zfs_probe = (True, "")
            except Exception as exc:  # noqa: BLE001 - the reason is the fact
                self._zfs_probe = (False,
                                   f"zpool is installed but unusable: {str(exc)[:140]}")
        return self._zfs_probe

    async def capability(self) -> dict:
        cap: dict = {"available": True, "collections": self.collections()}
        if not self._zfs:
            reason = "zpool not on PATH (OpenZFS not installed on this host)"
            cap["unavailable_collections"] = {
                "pools": reason, "datasets": reason, "lookups": reason,
            }
        else:
            ok, reason = await self._zfs_readable()
            if not ok:
                cap["collections"] = ["block-devices", "mounts", "arrays"]
                cap["unavailable_collections"] = {
                    "pools": reason, "datasets": reason, "lookups": reason,
                }
        return cap

    async def _zpool_member_map(self) -> dict[str, str]:
        """kname -> pool name; empty when zfs is absent or unreadable."""
        if not self._zfs or not (await self._zfs_readable())[0]:
            return {}
        try:
            status = await anyio.to_thread.run_sync(_zpool_status)
        except Exception:  # noqa: BLE001 - enrichment only, never break block-devices
            return {}
        out: dict[str, str] = {}
        for pool_name, pool in (status.get("pools") or {}).items():
            vdevs: list[dict] = []
            _flatten_vdevs(pool.get("vdevs"), vdevs)
            for kname in _leaf_device_knames(vdevs).values():
                out[kname] = pool_name
        return out

    async def _block_items(self) -> list[dict]:
        data = await anyio.to_thread.run_sync(_lsblk)
        items = []
        for node, parent, depth in _flatten_devices(data.get("blockdevices", [])):
            name = node["name"]
            facts = {
                "Type": node.get("type"), "Size": node.get("size"),
                "FsType": node.get("fstype"),
                "Mountpoints": [m for m in node.get("mountpoints", []) if m],
                "Model": node.get("model"), "Serial": node.get("serial"),
                "Rotational": node.get("rota"), "Removable": node.get("rm"),
            }
            item = env.item_summary(f"block-device:{name}", node.get("type") or "disk", name, facts)
            item["depth"] = depth
            if parent:
                item["_parent"] = parent
            items.append(item)
        return items

    async def _mount_items(self) -> list[dict]:
        data = await anyio.to_thread.run_sync(_findmnt)
        items = []
        for node, depth in _flatten_mounts(data.get("filesystems", [])):
            target = node["target"]
            use = _use_percent(node.get("use%"))
            facts = {
                "Source": node.get("source"), "FsType": node.get("fstype"),
                "Options": node.get("options"), "SizeBytes": node.get("size"),
                "UsedBytes": node.get("used"), "AvailBytes": node.get("avail"),
                "UsePercent": use,
            }
            worst = worst_level(mount_opinions(facts),
                                healthy="ok" if use is not None else "info")
            item = env.item_summary(f"mount:{target}", "mount", target, facts,
                                    worst_opinion_level=worst)
            item["depth"] = depth
            items.append(item)
        return items

    async def _array_items(self) -> list[dict]:
        data = await anyio.to_thread.run_sync(_md_scrape)
        items = []
        for name, arr in data["arrays"].items():
            action = arr["sync_action"]
            # array_state stays "clean"/"active" during a resync — the kernel
            # only tracks superblock dirtiness there. Status is the state an
            # operator means: the sync action while one runs, else the state.
            status = action if action in MD_ACTIVE_SYNC else arr["array_state"]
            facts = {
                "Status": status,
                "Level": arr["level"], "ArrayState": arr["array_state"],
                "Degraded": arr["degraded"], "RaidDisks": arr["raid_disks"],
                "MetadataVersion": arr["metadata_version"], "UUID": arr["uuid"],
                "SyncAction": action, "SyncPercent": arr["sync_percent"],
                "SizeBytes": arr["size_bytes"],
                "Members": [{"Device": f"block-device:{kname}",
                             "State": member["state"],
                             "Slot": member["slot"],
                             "Errors": member["errors"]}
                            for kname, member in arr["members"].items()],
            }
            items.append(env.item_summary(f"array:{name}", arr["level"] or "md-array",
                                          name, facts,
                                          worst_opinion_level=worst_level(array_opinions(facts))))
        return items

    async def _pool_items(self) -> list[dict]:
        status = await anyio.to_thread.run_sync(_zpool_status)
        try:
            listing = (await anyio.to_thread.run_sync(_zpool_list)).get("pools") or {}
        except Exception:  # noqa: BLE001 - capacity is enrichment; status is the fact
            listing = {}
        items = []
        for name, pool in (status.get("pools") or {}).items():
            vdevs: list[dict] = []
            _flatten_vdevs(pool.get("vdevs"), vdevs)
            scan = pool.get("scan_stats") or {}
            props = (listing.get(name) or {}).get("properties") or {}

            # Per-vdev fullness from zpool list -v, matched onto the status
            # walk's entries by vdev name.
            vdev_caps: dict[str, dict] = {}

            def collect_caps(nodes: dict | None) -> None:
                for vname, vd in (nodes or {}).items():
                    vprops = vd.get("properties") or {}
                    alloc = _int_or_none(_prop_value(vprops, "allocated"))
                    if alloc is not None:
                        vdev_caps[str(vname)] = {
                            "SizeBytes": _int_or_none(_prop_value(vprops, "size")),
                            "AllocatedBytes": alloc,
                            "CapacityPercent": _int_or_none(_prop_value(vprops, "capacity")),
                        }
                    collect_caps(vd.get("vdevs"))

            collect_caps((listing.get(name) or {}).get("vdevs"))
            for entry in vdevs:
                cap = vdev_caps.get(str(entry["Name"]))
                if cap:
                    entry.update(cap)
            unhealthy = [vdev["Name"] for vdev in vdevs
                         if vdev.get("State") not in (None, "ONLINE", "AVAIL")]
            vdev_errors = [vdev["Name"] for vdev in vdevs
                           if any((vdev.get(key) or 0) for key in
                                  ("ReadErrors", "WriteErrors", "ChecksumErrors"))]
            cap = _int_or_none(_prop_value(props, "capacity"))
            # --json-int gives end_time as an epoch int; the plain -j
            # fallback gives a locale string, kept verbatim with
            # ScanAgeDays omitted so pool-scrub-stale simply does not
            # evaluate (SPEC rule 14: a rule fires only when the facts it
            # needs are present). The age is computed here, not in the
            # rule — rules are pure, with no clock access (SPEC section
            # 11, rule 8).
            end_time = scan.get("end_time")
            scan_age_days = (int((time.time() - end_time) // 86400)
                             if isinstance(end_time, int) else None)
            facts = {
                "State": pool.get("state"),
                "StatusMessage": (pool.get("status") or "").strip() or None,
                "Errors": pool.get("error_count"),
                "ScanFunction": scan.get("function"),
                "ScanState": scan.get("state"),
                "ScanEndTime": (_epoch_iso(end_time)
                                if isinstance(end_time, int) else end_time),
                **({"ScanAgeDays": scan_age_days}
                   if scan_age_days is not None else {}),
                "SizeBytes": _int_or_none(_prop_value(props, "size")),
                "AllocatedBytes": _int_or_none(_prop_value(props, "allocated")),
                "FreeBytes": _int_or_none(_prop_value(props, "free")),
                "CapacityPercent": cap,
                "FragmentationPercent": _int_or_none(_prop_value(props, "fragmentation")),
                "Vdevs": vdevs,
                "UnhealthyVdevs": unhealthy,
                "VdevsWithErrors": vdev_errors,
            }
            items.append(env.item_summary(f"pool:{name}", "pool", name, facts,
                                          worst_opinion_level=worst_level(pool_opinions(facts))))
        return items

    async def _dataset_items(self) -> list[dict]:
        data = await anyio.to_thread.run_sync(_zfs_list)
        items = []
        for name, ds in (data.get("datasets") or {}).items():
            props = ds.get("properties") or {}
            used = _int_or_none(_prop_value(props, "used"))
            avail = _int_or_none(_prop_value(props, "available"))
            # Share of what this dataset could grow into (quota- or
            # pool-bounded) — the same gauge semantics the mounts carry.
            use_pct = (round(used * 100 / (used + avail))
                       if used is not None and avail and (used + avail) else None)
            facts = {
                "UsedBytes": used,
                "AvailBytes": avail,
                "UsePercent": use_pct,
                "SnapshotUsedBytes": _int_or_none(_prop_value(props, "usedbysnapshots")),
                # A door, not a datum: the UI routes lookup: ids to this
                # subsystem's lookups collection.
                "SnapshotsLookup": f"lookup:snapshots-of/{name}",
                "Mountpoint": _prop_value(props, "mountpoint"),
                "MountpointSource": _prop_source(props, "mountpoint"),
                "CanMount": _prop_value(props, "canmount"),
                "CanMountSource": _prop_source(props, "canmount"),
                "ReadOnly": _prop_value(props, "readonly"),
                "ReadOnlySource": _prop_source(props, "readonly"),
                "Mounted": _prop_value(props, "mounted"),
            }
            items.append(env.item_summary(
                f"dataset:{name}", ds.get("type", "filesystem"), name, facts,
                worst_opinion_level=worst_level(
                    dataset_opinions(facts),
                    healthy="ok" if use_pct is not None else "info")))
        return items

    def _source_for(self, collection: str) -> dict:
        table = {
            "block-devices": ("lsblk-json", "lsblk -J", ["lsblk", "lsblk -o +MODEL,SERIAL"]),
            "mounts": ("findmnt-json", "findmnt -J",
                       ["findmnt --real --task 1", "df -h"]),
            "arrays": ("md-sysfs", "/sys/block/*/md",
                       ["cat /proc/mdstat", "mdadm --detail /dev/md*"]),
            "pools": ("zfs-json", "zpool -j", ["zpool status -j", "zpool list -j -p"]),
            "datasets": ("zfs-json", "zfs -j", ["zfs list -j -p -o " + ZFS_LIST_COLUMNS]),
            "lookups": ("zfs-json", "zfs list -j -t snapshot,bookmark",
                        ["zfs list -t snapshot -d 1 <dataset>",
                         "zfs list -t snapshot -r <dataset>"]),
        }
        adapter, iface, refs = table[collection]
        notes = None
        if collection == "mounts" and _findmnt_fallback:
            notes = ["findmnt --task 1 failed — observing the agent's own "
                     "mount namespace, not PID 1's; the service sandbox "
                     "skews it (ProtectSystem=strict shows / as ro)"]
        return env.source(adapter, iface, refs, notes=notes)

    async def _items(self, collection: str) -> list[dict]:
        if collection in ("pools", "datasets") and not self._zfs:
            raise env.UnknownCollection(collection)
        fetch = {"block-devices": self._block_items, "mounts": self._mount_items,
                 "arrays": self._array_items,
                 "pools": self._pool_items, "datasets": self._dataset_items,
                 "lookups": self._lookup_items}
        if collection not in fetch:
            raise env.UnknownCollection(collection)
        return await fetch[collection]()

    async def _lookup_items(self) -> list[dict]:
        return [env.item_summary(f"lookup:{name}", "lookup", name, dict(spec))
                for name, spec in STORAGE_LOOKUPS.items()]

    @staticmethod
    def _parse_lookup_id(object_id: str) -> tuple[str, str]:
        if not object_id.startswith("lookup:"):
            raise env.UnknownObject(object_id)
        name, _, arg = object_id[len("lookup:"):].partition("/")
        if name not in STORAGE_LOOKUPS:
            raise env.UnknownObject(object_id)
        return name, arg

    @staticmethod
    def _parse_snapshot_arg(arg: str) -> tuple[str, bool]:
        recursive = arg.endswith("/*")
        dataset = arg[:-2] if recursive else arg
        if not DATASET_ARG_RE.match(dataset):
            raise ValueError("not a plausible dataset name")
        return dataset, recursive

    async def _lookup_observation(self, object_id: str) -> dict:
        name, arg = self._parse_lookup_id(object_id)
        obj = env.obj_ref(object_id, "lookup", object_id[len("lookup:"):])
        src = self._source_for("lookups")
        if not arg:
            facts = dict(STORAGE_LOOKUPS[name])
            facts["Usage"] = f"GET /v1/storage/lookups/lookup:{name}/<dataset>"
            return env.observation(self.subsystem, obj, src, facts)
        try:
            dataset, recursive = self._parse_snapshot_arg(arg)
            data = await anyio.to_thread.run_sync(_zfs_snapshots, dataset, recursive)
        except ValueError as exc:
            return env.observation(self.subsystem, obj, src, {"Input": arg},
                                   status="error", errors=[str(exc)])
        except Exception as exc:  # noqa: BLE001 - the failure is the answer
            return env.observation(self.subsystem, obj, src, {"Input": arg},
                                   status="error", errors=[str(exc)[:200]])

        entries = []
        for full_name, snap in (data.get("datasets") or {}).items():
            props = snap.get("properties") or {}
            sep = "@" if "@" in full_name else "#"
            entries.append({
                "Name": sep + full_name.split(sep, 1)[1] if sep in full_name else full_name,
                "Of": full_name.split(sep, 1)[0] if recursive else None,
                "Type": (snap.get("type") or "").lower() or None,
                "UsedBytes": _int_or_none(_prop_value(props, "used")),
                "ReferencedBytes": _int_or_none(_prop_value(props, "referenced")),
                "Created": _epoch_iso(_prop_value(props, "creation")),
            })
        entries.sort(key=lambda e: e["Created"] or "", reverse=True)
        if not recursive:
            for entry in entries:
                entry.pop("Of", None)
        total_used = sum(e["UsedBytes"] or 0 for e in entries)
        facts = {
            "Dataset": dataset,
            "Recursive": recursive,
            "Count": len(entries),
            "TotalUsedBytes": total_used,
            "Newest": entries[:SNAPSHOT_DISPLAY_CAP],
        }
        if len(entries) > SNAPSHOT_DISPLAY_CAP:
            facts["Omitted"] = (f"{len(entries) - SNAPSHOT_DISPLAY_CAP} older "
                                "entries not shown; evidence has all of them")
        return env.observation(
            self.subsystem, obj, src, facts,
            relationships=[env.rel("member-of", "out", f"dataset:{dataset}")],
            evidence_ref=f"/v1/storage/lookups/{object_id}/evidence",
        )

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        items = env.apply_fact_filters(await self._items(collection), query)
        for item in items:
            item.pop("_parent", None)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, self._source_for(collection),
                                   page, applied, next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    async def _relationships(self, collection: str, match: dict) -> list[dict]:
        rels: list[dict] = []
        facts = match["facts"]
        native = match["native_id"]

        if collection == "block-devices":
            if match.get("_parent"):
                rels.append(env.rel("member-of", "out", f"block-device:{match['_parent']}"))
            for holder in _md_holders(native):
                rels.append(env.rel("member-of", "out", f"array:{holder}"))
            if os.path.isdir(f"/sys/block/{native}/md"):
                rels.append(env.rel("backs", "in", f"array:{native}"))
            # The physical device behind this block device: sd* resolves to
            # its SCSI address, nvme namespaces to their controller — the
            # hardware subsystem's view of the same hardware.
            device_dir = os.path.realpath(f"/sys/class/block/{native}/device")
            physical = os.path.basename(device_dir)
            if re.match(r"^\d+:\d+:\d+:\d+$", physical):
                rels.append(env.rel("backs", "in", f"scsi:{physical}",
                                    subsystem="hardware"))
            elif re.match(r"^nvme\d+$", physical):
                rels.append(env.rel("backs", "in", f"nvme:{physical}",
                                    subsystem="hardware"))
            pool = (await self._zpool_member_map()).get(native)
            if pool:
                rels.append(env.rel("member-of", "out", f"pool:{pool}"))

        elif collection == "arrays":
            for member in (facts.get("Members") or []):
                rels.append(env.rel("member-of", "in", member["Device"]))
            rels.append(env.rel("backs", "out", f"block-device:{native}"))

        elif collection == "pools":
            for kname in _leaf_device_knames(facts.get("Vdevs") or []).values():
                rels.append(env.rel("member-of", "in", f"block-device:{kname}"))
            try:
                data = await anyio.to_thread.run_sync(_zfs_list)
                for ds_name in (data.get("datasets") or {}):
                    if ds_name == native or ds_name.startswith(native + "/"):
                        rels.append(env.rel("member-of", "in", f"dataset:{ds_name}"))
            except Exception:  # noqa: BLE001 - dataset edges are enrichment
                pass

        elif collection == "datasets":
            pool = native.split("/")[0]
            rels.append(env.rel("member-of", "out", f"pool:{pool}"))
            if "/" in native:
                parent = native.rsplit("/", 1)[0]
                rels.append(env.rel("member-of", "out", f"dataset:{parent}"))
            mountpoint = facts.get("Mountpoint")
            if facts.get("Mounted") == "yes" and str(mountpoint or "").startswith("/"):
                rels.append(env.rel("mounts", "out", f"mount:{mountpoint}"))

        elif collection == "mounts":
            source_val = str(facts.get("Source", ""))
            if source_val.startswith("/dev/"):
                device = source_val.removeprefix("/dev/")
                rels.append(env.rel("mounts", "out", f"block-device:{device}"))
            elif facts.get("FsType") == "zfs" and source_val and not source_val.startswith("/"):
                rels.append(env.rel("mounts", "out", f"dataset:{source_val}"))

        return rels

    # One evaluator per collection (agent/rules/storage.py), shared verbatim
    # with the summary path — rows and opened objects cannot disagree.
    _RULES = {"mounts": mount_opinions, "arrays": array_opinions,
              "pools": pool_opinions, "datasets": dataset_opinions}

    def _opinions(self, collection: str, match: dict) -> list[dict]:
        rule = self._RULES.get(collection)
        return rule(match["facts"]) if rule else []

    async def get_object(self, collection: str, object_id: str) -> dict:
        if collection == "lookups":
            return await self._lookup_observation(object_id)
        items = await self._items(collection)
        match = next((i for i in items if i["id"] == object_id), None)
        if match is None:
            raise env.UnknownObject(object_id)

        return env.observation(
            self.subsystem,
            env.obj_ref(object_id, match["type"], match["native_id"]),
            self._source_for(collection),
            match["facts"],
            opinions=self._opinions(collection, match),
            relationships=await self._relationships(collection, match),
            evidence_ref=f"/v1/storage/{collection}/{object_id}/evidence",
        )

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        if collection == "lookups":
            # Evidence re-runs the lookup — captured fresh, uncapped, through
            # the same validated helpers as the observation.
            _, arg = self._parse_lookup_id(object_id)
            dataset, recursive = self._parse_snapshot_arg(arg)
            payload = await anyio.to_thread.run_sync(_zfs_snapshots, dataset, recursive)
            return {
                "object_id": object_id,
                "captured_at": env.utc_now(),
                "interface": self._source_for(collection)["interface"],
                "payload": payload,
            }
        raw = {
            "block-devices": _lsblk, "mounts": _findmnt, "arrays": _md_scrape,
            "pools": _zpool_evidence, "datasets": _zfs_list,
        }.get(collection)
        if raw is None:
            raise env.UnknownCollection(collection)
        payload = await anyio.to_thread.run_sync(raw)
        return {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": self._source_for(collection)["interface"],
            "payload": payload,
        }
