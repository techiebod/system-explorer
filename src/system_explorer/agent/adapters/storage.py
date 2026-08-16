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
from ..rules.storage import (MD_ACTIVE_SYNC, array_opinions, dataset_opinions,
                             mount_opinions, pool_opinions)

# TRAN is the transport — virtio, sata, sas, nvme, usb — and it was missing,
# which mattered more than it looks. The hardware subsystem is organised BY
# transport (scsi, nvme), so a virtio disk appears in no hardware collection at
# all: on a VM the only place the guest's own disk is visible is here, and here
# it did not even say what kind of disk it was. Asked directly by an operator
# looking at a guest that showed block devices and no physical disks.
LSBLK_COLUMNS = "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL,ROTA,RM,TRAN"

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


def scan_facts(scan: dict) -> dict:
    """The pool's scan facts, honest in all three shapes zfs produces.

    scan_stats is ONE record — the most recent scan, whatever kind it was —
    and both dishonest readings of it reached deployed pools:

    - A scan in progress renders end_time as 0 under --json-int, and 0 is an
      int, so a pool mid-scrub derived ScanEndTime 1970-01-01 and a
      twenty-thousand-day ScanAgeDays (found live on a scrubbing pool,
      2026-08-12). Zero means "has not ended", not the epoch.
    - A resilver REPLACES the scrub's record, so after one the time since
      the last completed scrub cannot be read from this pool at all. The
      stale-scrub rule guards on ScanFunction and simply went silent — and
      silence beside a months-stale scrub is absence-as-health, observed on
      a foreign host whose shelf showed ScanAgeDays 9 from a resilver. Per
      rule 7 the value exists and cannot be seen, so LastScrubEndTime is
      null with the reason in its Unobservable sibling, and a rule turns
      the pair into a stated unknown instead of nothing.

    --json-int's absence (older OpenZFS) leaves end_time a locale string:
    kept verbatim, age omitted, exactly as before. Module-level and pure so
    conformance feeds it every shape without a pool.
    """
    end_time = scan.get("end_time")
    if end_time == 0:
        end_time = None
    scan_age_days = (int((time.time() - end_time) // 86400)
                     if isinstance(end_time, int) else None)
    function = scan.get("function")
    out = {
        "ScanFunction": function,
        "ScanState": scan.get("state"),
        "ScanEndTime": (_epoch_iso(end_time)
                        if isinstance(end_time, int) else end_time),
        **({"ScanAgeDays": scan_age_days} if scan_age_days is not None else {}),
    }
    if function is not None and function != "SCRUB":
        out["LastScrubEndTime"] = None
        out["LastScrubEndTimeUnobservable"] = (
            f"the last recorded scan is a {function.lower()}, and ZFS keeps "
            "only the most recent scan's record — the time since the last "
            "completed scrub cannot be read from this pool")
    return out


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

# The alias trees a vdev reference resolves through. by-id is where zpool's
# own path field points; by-partuuid is how stripe leaves are named (a bare
# partition GUID, verified against a stripe layout 2026-08-09); mapper is a
# pool imported over dm/LUKS nodes, whose /dev/mapper name is not its kernel
# name.
_DEVLINK_TREES = ("/dev/disk/by-id", "/dev/disk/by-partuuid", "/dev/mapper")


def _devlinks() -> dict[str, str] | None:
    """{alias path: kernel block name} for every device symlink on the host.

    This is an ACQUISITION, module-level on purpose: it is the one place vdev
    resolution touches the filesystem, so the replay seam can redirect it the
    same way it redirects the zpool documents (a payload named "devlinks").
    While resolution called os.path.realpath inline, the emitted Device was a
    property of the machine RUNNING the code, not the machine that produced
    the payload — every committed corpus Device was null because the corpus
    was generated on a workstation with no /dev/disk.

    None when no tree is readable. That is could-not-read, a different
    statement from an empty tree, and the caller routes it to the
    unobservable channel rather than letting it impersonate absence.
    """
    links: dict[str, str] | None = None
    for tree in _DEVLINK_TREES:
        try:
            entries = sorted(os.listdir(tree))
        except OSError:
            continue
        if links is None:
            links = {}
        for entry in entries:
            path = f"{tree}/{entry}"
            try:
                links[path] = os.path.basename(os.readlink(path))
            except OSError:
                continue  # /dev/mapper/control and friends: nodes, not aliases
    return links


def _resolve_kname(ref: str, links: dict[str, str]) -> str | None:
    """vdev path or name -> kernel block name, through the devlinks map ONLY.

    zpool reports whatever the pool was imported with (wwn-*, by-id, plain
    sdX, absolute paths, or — for stripe leaves — a bare partition GUID); the
    kname is what lsblk and the block-devices collection agree on. No
    filesystem read happens here: under replay the map is the capture's, so
    the answer stays a fact about the captured machine, and a ref the map
    cannot account for is an honest absence rather than a guess.
    """
    if ref.startswith("/"):
        kname = links.get(ref)
        if kname:
            return kname
        # A node named directly — /dev/sdc1, /dev/vdb — dereferences nothing:
        # the basename IS the kernel name, which is what lets a virtio disk
        # (which grows no by-id link) still resolve.
        tail = ref.removeprefix("/dev/")
        if ref.startswith("/dev/") and "/" not in tail:
            return tail
        return None
    for tree in ("/dev/disk/by-id", "/dev/disk/by-partuuid"):
        kname = links.get(f"{tree}/{ref}")
        if kname:
            return kname
    # A bare kernel name (a pool imported as plain sdc) appears in the map as
    # an alias TARGET, never as an alias.
    return ref if ref in links.values() else None


def _flatten_vdevs(nodes: dict | None, out: list[dict],
                   links: dict[str, str] | None, group: str = "data",
                   depth: int = 1) -> None:
    """Depth-first vdev walk. Group vdevs (logs, l2cache, spares) label their
    subtree; the root vdev is namespace, not a device. Depth drives the UI's
    tree indentation; Device is the resolved, linkable kernel block name,
    read through the devlinks acquisition (`links`) and nothing else.

    Each disk leaf also publishes its own name set (law 1): its guid, the wwn
    its by-id name encodes, the devid zpool recorded — the stable names a
    collator joins pool members to block devices on — plus the resolved
    kernel path, carried because a person searches for /dev/sdc and joined on
    never. It rides the row: a stream object's names channel holds flat
    scalar families (the contract's name_scalar), so a PER-LEAF set can only
    live where the leaf itself does.
    """
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
            # leaves. State stays as reported; where zpool omits it, the row
            # omits it too — DESIGN 19 forbids a null standing in for an
            # absent key, and the UnhealthyVdevs filter tolerates the gap.
            vdev_type = vdev.get("vdev_type")
            if vdev_type is None and not vdev.get("vdevs"):
                vdev_type = "disk"
            entry = {
                "Name": name,
                "Depth": depth,
                "Type": vdev_type,
                "State": vdev.get("state"),
            }
            if vdev_type == "disk":
                # zpool's own path field is authoritative; the vdev NAME is
                # only a fallback (some hosts lack the matching by-id link).
                # links None means the acquisition itself was unreadable —
                # the CALLER emits the unobservable record for that, because
                # a missing Device here must not impersonate absence.
                kname = None
                if links is not None:
                    path = vdev.get("path")
                    kname = _resolve_kname(str(path), links) if path else None
                    if kname is None:
                        kname = _resolve_kname(str(name), links)
                if kname:
                    entry["Device"] = f"block-device:{kname}"
                stable: dict[str, object] = {}
                if vdev.get("guid") is not None:
                    stable["guid"] = str(vdev["guid"])
                if str(name).startswith("wwn-"):
                    stable["wwn"] = str(name)
                if vdev.get("devid"):
                    stable["devid"] = vdev["devid"]
                leaf_names: dict[str, dict] = {}
                if stable:
                    leaf_names["stable"] = stable
                if kname:
                    leaf_names["ephemeral"] = {"kernel": f"/dev/{kname}"}
                if leaf_names:
                    entry["Names"] = leaf_names
            if next_group != "data":
                entry["Group"] = next_group
            entry.update({
                "ReadErrors": _int_or_none(vdev.get("read_errors")),
                "WriteErrors": _int_or_none(vdev.get("write_errors")),
                "ChecksumErrors": _int_or_none(vdev.get("checksum_errors")),
            })
            # Null is never a fact value (DESIGN 19): a member zpool did not
            # report is simply not on the row. This costs the old trick of an
            # explicit None pinning the Device column beside State — a column
            # position is not worth a value that names none of the three
            # statements a reader could take from it.
            out.append({k: v for k, v in entry.items() if v is not None})
            child_depth = depth + 1
        _flatten_vdevs(vdev.get("vdevs"), out, links, next_group, child_depth)


def _split_absent(facts: dict) -> tuple[dict, list[str]]:
    """DESIGN 19: a fact's value is never null — value, absent list and
    unobservable record are three statements with three channels, and a null
    names none of them. A None here is the source reporting the property
    genuinely missing (lsblk and findmnt emit JSON null for exactly that), so
    it moves to the object's absent list; a None that means could-not-read is
    routed to the unobservable channel by the caller that knows the reason,
    BEFORE this sweep runs."""
    return ({k: v for k, v in facts.items() if v is not None},
            sorted(k for k, v in facts.items() if v is None))


def _attach_channels(item: dict, absent: list[str] | None = None,
                     unobservable: list[dict] | None = None) -> dict:
    """The stream channels, riding the item beside its facts. Additive on the
    live API's row shape (the way `depth` already is) and lifted verbatim by
    the reference collector — one representation, so the API and the stream
    cannot tell two different stories about the same reading."""
    if absent:
        item["absent"] = absent
    if unobservable:
        item["unobservable"] = sorted(unobservable, key=lambda u: u["fact"])
    return item


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
                     depth: int = 0) -> list[tuple[dict, list[str], int]]:
    """The lsblk tree as one row per DEVICE, not per appearance.

    lsblk -J is a tree of containment, and containment is not a tree: an md
    array is listed under every member it is assembled from, so a two-disk
    mirror publishes md126 twice. Emitting a row per appearance put the same
    object id in one collection page twice — which breaks rule 15 identity,
    overstates `total` by however many mirror members exist, and makes
    get_object's matches[0] an arbitrary choice between two rows that differ
    (measured live, 2026-08-13: GET /v1/storage/block-devices returned
    block-device:md126 twice on a host with an md array).

    First appearance wins for `depth`, and every parent is kept. Those are
    different decisions for a reason. Depth is the tree coordinate a list
    renders indentation from and a multi-parent device HAS no single one, so
    the first is a real path to it rather than a truth about it — a claim
    small enough to state and honour. The PARENTS are the thing that would
    have been a lie: silently keeping the first would say md126 is assembled
    from sda1, which is false, and the falsehood would travel as a member-of
    relationship. So the row carries all of them and get_object emits one edge
    each. Insertion order preserved, so the first appearance stays first
    wherever a consumer treats the list as ranked.
    """
    seen: dict[str, tuple[dict, list[str], int]] = {}
    order: list[str] = []

    def walk(children: list[dict], parent_name: str | None, node_depth: int) -> None:
        for node in children:
            name = node["name"]
            entry = seen.get(name)
            if entry is None:
                seen[name] = (node, [parent_name] if parent_name else [], node_depth)
                order.append(name)
            elif parent_name and parent_name not in entry[1]:
                entry[1].append(parent_name)
            walk(node.get("children", []), name, node_depth + 1)

    walk(nodes, parent, depth)
    return [seen[name] for name in order]


def _flatten_mounts(nodes: list[dict], depth: int = 0) -> list[tuple[dict, int]]:
    out = []
    for node in nodes:
        out.append((node, depth))
        out.extend(_flatten_mounts(node.get("children", []), depth + 1))
    return out


# The scan facts, documented because their scopes bit twice in one day: a
# mid-scrub pool wore a 1970 scan end, and a resilver record left a stale
# scrub reading as nothing-to-say. One record, three shapes — the sentences
# carry what the names cannot (the LinkSpeed/LinkWidth lesson).
_STORAGE_KINDS = {
    "pools": {"Redundancy": "derived", "DeviceFailuresTolerated": "derived",
              "ScanAgeDays": "derived"},
    "block-devices": {},
}

_POOL_GLOSSARY = {
    "Redundancy": "How this pool's data vdevs are laid out, in zpool's own words — a stripe, a mirror, raidz1. A pool is only as redundant as its weakest data vdev, because losing any one of them loses the pool, so a mixed layout is named in full rather than summarised to its best part.",
    "DeviceFailuresTolerated": "How many whole devices this pool survives losing, read from the layout above; 0 means the next disk to fail takes the pool with it. Stated and graded by nothing here: whether that is a problem depends on what lives on the pool, which the protection inventory knows and this adapter cannot.",
    "ScanFunction": (
        "What kind of scan the pool's single scan record describes — SCRUB "
        "or RESILVER. ZFS keeps only the most recent scan, so a resilver "
        "replaces the scrub's record entirely; see LastScrubEndTime for "
        "what that does to scrub age."
    ),
    "ScanState": (
        "Where that scan stands: SCANNING while in progress, FINISHED when "
        "complete. A scan in progress has no end time yet, which is why "
        "ScanEndTime and ScanAgeDays are empty mid-scrub."
    ),
    "ScanEndTime": (
        "When the recorded scan finished, whatever kind it was. On the "
        "absent list while a scan is running — no end exists yet; a plain "
        "prose date on OpenZFS too old to render the machine-readable form, "
        "and then no age is derived from it."
    ),
    "ScanAgeDays": (
        "Whole days since the recorded scan finished — the SCAN, not "
        "necessarily the scrub: after a resilver this counts from the "
        "resilver. The stale-scrub warning only reads it when the record "
        "is a finished scrub."
    ),
    "LastScrubEndTime": (
        "When the last completed scrub finished. An unobservable record, "
        "with the reason in LastScrubEndTimeUnobservable, when a later "
        "resilver replaced the scrub's record — the value exists, this pool "
        "just cannot report it."
    ),
    "LastScrubEndTimeUnobservable": (
        "Why the last scrub's end time cannot be read from this pool: ZFS "
        "keeps one scan record, and a resilver overwrote the scrub's. "
        "Present only in that state, and it carries an info opinion so the "
        "unknown is stated rather than silent."
    ),
}


_BLOCK_DEVICE_GLOSSARY = {
    "Parents": (
        "The devices this one is assembled from or carved out of — a "
        "partition names its disk, an md array names every member it was "
        "assembled from. More than one entry means containment here is not a "
        "tree, and the row's depth can only describe the first path to it."
    ),
}


# ── what a pool survives losing ──────────────────────────────────────
#
# A FACT, and deliberately no opinion. Whether a pool with no parity is a
# problem depends entirely on what sits on it: a stripe holding replicas of
# data that lives elsewhere is a capacity decision, and the same stripe under
# an irreplaceable dataset with no other copy is a real exposure. This adapter
# knows the vdev layout and cannot know the second thing — the protection
# inventory does — so it states the layout and grades nothing. Emitting the
# fact is what lets something that DOES know decide; a verdict here would be
# this adapter ranking a pool whose purpose it cannot see.
#
# Parity comes from the vdev's NAME, which looks like an oversight and is not.
# Measured against zpool status -j on two live layouts (2026-08-14): a raidz1
# vdev reports vdev_type "raidz" with NO nparity key anywhere in the document,
# and the only place the number 1 appears is the name zpool gave it,
# "raidz1-0". Reading the type alone yields "raidz" for every parity level,
# which is precisely the confident half-answer this fact would be worthless
# for.
_PARITY_NAME = re.compile(r"^(raidz|draid)(\d)")


def _redundancy(vdevs: list[dict]) -> tuple[str | None, int | None]:
    """(how this pool is laid out, how many whole devices it survives losing).

    Data vdevs only. A cache or log device leaving is not a pool leaving, and
    counting a spare would report protection that is not attached to anything
    yet — those carry a Group in the flattened walk and are skipped.

    A pool is only as redundant as its WEAKEST data vdev, because losing any
    one of them loses the pool. Striping a mirror across a bare disk is a bare
    disk with extra steps, and reporting "mirror" for that layout is exactly
    the kind of half-truth that gets acted on.
    """
    kinds: list[str] = []
    tolerance: list[int] = []
    current: str | None = None
    members = 0

    def close() -> bool:
        """Finish the vdev just walked past. False where it cannot be read."""
        nonlocal current, members
        if current is None:
            return True
        if current == "mirror":
            # A mirror survives losing all but one member, and the members are
            # the entries nested under THIS vdev — counted as the walk passes
            # them rather than globally, or a pool of two mirrors would credit
            # each with the other's disks.
            if members < 2:
                return False
            kinds.append("mirror")
            tolerance.append(members - 1)
        current, members = None, 0
        return True

    for vdev in vdevs:
        depth, kind = vdev.get("Depth"), str(vdev.get("Type") or "").lower()
        if vdev.get("Group"):
            continue                       # logs, l2cache, spares
        if depth == 1:
            if not close():
                return None, None
            if kind == "disk":
                kinds.append("stripe")
                tolerance.append(0)
            elif kind == "mirror":
                current = "mirror"
            else:
                parity = _PARITY_NAME.match(str(vdev.get("Name") or ""))
                if not parity or kind not in ("raidz", "draid"):
                    # An unrecognised top-level vdev is not a redundant one by
                    # default: claiming tolerance this walk cannot justify is
                    # the direction that gets somebody hurt.
                    return None, None
                kinds.append(parity.group(0))
                tolerance.append(int(parity.group(2)))
        elif depth == 2 and current == "mirror" and kind == "disk":
            members += 1
    if not close() or not kinds:
        return None, None
    layout = kinds[0] if len(set(kinds)) == 1 else " + ".join(kinds)
    return layout, min(tolerance)


class Adapter:
    subsystem = "storage"

    def fact_glossary(self, collection: str) -> dict[str, str]:
        if collection == "pools":
            return _POOL_GLOSSARY
        return _BLOCK_DEVICE_GLOSSARY if collection == "block-devices" else {}

    def fact_kinds(self, collection: str) -> dict[str, str] | None:
        """Redundancy is the one that had to be classified. zpool reports
        vdev_type "raidz" for every parity level and never states the number
        anywhere in its document — the parity is read out of the NAME zpool
        assigned the vdev — so both facts are this adapter's reading of a
        string, not a figure the pool published. A reader treating
        DeviceFailuresTolerated as measured would be trusting a regex."""
        return _STORAGE_KINDS.get(collection)

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
        # Static, like every other adapter: this is what the subsystem HAS,
        # not what it can answer on this host. Availability belongs to
        # capability() alone. While this list was conditional, a host without
        # OpenZFS got two silent absences instead of one honest reason —
        # /v1/storage/pools answered 404 "unknown collection" although the
        # reason existed, and /v1/status omitted the row altogether rather
        # than declining it. Both are exactly what SPEC section 2 rule 7
        # forbids, in the roll-up whose whole job is honest absence.
        return ["block-devices", "mounts", "arrays", "pools", "datasets", "lookups"]

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
                                   env.reason(f"zpool is installed but unusable: {exc}"))
        return self._zfs_probe

    async def capability(self) -> dict:
        unavailable: dict[str, str] = {}
        if not self._zfs:
            reason = "zpool not on PATH (OpenZFS not installed on this host)"
            unavailable = {"pools": reason, "datasets": reason, "lookups": reason}
        else:
            ok, reason = await self._zfs_readable()
            if not ok:
                unavailable = {"pools": reason, "datasets": reason, "lookups": reason}
        return {
            "available": True,
            "collections": [c for c in self.collections() if c not in unavailable],
            "unavailable_collections": unavailable,
        }

    async def _zpool_member_map(self) -> dict[str, str]:
        """kname -> pool name; empty when zfs is absent or unreadable."""
        if not self._zfs or not (await self._zfs_readable())[0]:
            return {}
        try:
            status = await anyio.to_thread.run_sync(_zpool_status)
        except Exception:  # noqa: BLE001 - enrichment only, never break block-devices
            return {}
        links = await anyio.to_thread.run_sync(_devlinks)
        out: dict[str, str] = {}
        for pool_name, pool in (status.get("pools") or {}).items():
            vdevs: list[dict] = []
            _flatten_vdevs(pool.get("vdevs"), vdevs, links)
            for kname in _leaf_device_knames(vdevs).values():
                out[kname] = pool_name
        return out

    async def _block_items(self) -> list[dict]:
        data = await anyio.to_thread.run_sync(_lsblk)
        items = []
        for node, parents, depth in _flatten_devices(data.get("blockdevices", [])):
            name = node["name"]
            facts = {
                "Type": node.get("type"), "Size": node.get("size"),
                "FsType": node.get("fstype"),
                "Mountpoints": [m for m in node.get("mountpoints", []) if m],
                # Every device this one is assembled from or carved out of.
                # A list because containment is not a tree (see
                # _flatten_devices): `depth` can only state the first path to
                # a multi-parent device, so this is where the row says how
                # many there really are. Empty for a whole disk.
                "Parents": parents,
                "Model": node.get("model"), "Serial": node.get("serial"),
                "Rotational": node.get("rota"), "Removable": node.get("rm"),
                # Only lsblk reports this for every transport, which makes this
                # collection the one honest answer to "what disks does this host
                # have" — hardware/scsi and hardware/nvme are transport-specific
                # by construction and a virtio disk belongs to neither.
                "Transport": node.get("tran"),
            }
            # lsblk emits JSON null for a property a device does not have
            # (a partition's MODEL, a virtual device's TRAN): that is the
            # absent list's statement, never a null fact (DESIGN 19).
            facts, absent = _split_absent(facts)
            item = env.item_summary(f"block-device:{name}", node.get("type") or "disk", name, facts)
            item["depth"] = depth
            items.append(_attach_channels(item, absent))
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
            # A pseudo-filesystem genuinely has no size or usage: findmnt
            # reports null, and the absent list is what that means here.
            facts, absent = _split_absent(facts)
            item = env.item_summary(f"mount:{target}", "mount", target, facts,
                                    opinions=mount_opinions(facts),
                                    healthy="ok" if use is not None else "info")
            item["depth"] = depth
            items.append(_attach_channels(item, absent))
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
                # A member attribute sysfs did not yield is left off the row
                # rather than carried as null; the rulebook reads members
                # with .get() and treats the gap as no statement.
                "Members": [{k: v for k, v in
                             {"Device": f"block-device:{kname}",
                              "State": member["state"],
                              "Slot": member["slot"],
                              "Errors": member["errors"]}.items()
                             if v is not None}
                            for kname, member in arr["members"].items()],
            }
            facts, absent = _split_absent(facts)
            item = env.item_summary(f"array:{name}", arr["level"] or "md-array",
                                    name, facts,
                                    opinions=array_opinions(facts))
            items.append(_attach_channels(item, absent))
        return items

    async def _pool_items(self) -> list[dict]:
        status = await anyio.to_thread.run_sync(_zpool_status)
        try:
            listing = (await anyio.to_thread.run_sync(_zpool_list)).get("pools") or {}
        except Exception:  # noqa: BLE001 - capacity is enrichment; status is the fact
            # None, not {}: a listing that could not be read makes the
            # capacity facts unobservable, which is a different statement
            # from a listing that reported no such properties.
            listing = None
        links = await anyio.to_thread.run_sync(_devlinks)
        items = []
        for name, pool in (status.get("pools") or {}).items():
            absent: list[str] = []
            unobservable: list[dict] = []
            vdevs: list[dict] = []
            _flatten_vdevs(pool.get("vdevs"), vdevs, links)
            if links is None:
                # The alias trees could not be read (live) or no devlinks
                # payload was captured (replay). Every leaf's Device is a
                # could-not-read, one record each — never a silent null and
                # never a claim about the machine doing the replaying.
                for entry in vdevs:
                    if entry.get("Type") == "disk":
                        unobservable.append({
                            "fact": f"Vdevs/{entry['Name']}/Device",
                            "reason": "unavailable",
                            "detail": "no device alias tree could be read, "
                                      "so the member's kernel name cannot "
                                      "be resolved"})
            scan = pool.get("scan_stats") or {}
            props = ((listing.get(name) or {}).get("properties") or {}
                     if listing is not None else {})

            # Per-vdev fullness from zpool list -v, matched onto the status
            # walk's entries by vdev name.
            # The accumulator rides as a parameter, not a closure over the
            # loop variable: the call is same-iteration today, but a closure
            # capturing a loop variable is one refactor away from reading a
            # LATER iteration's dict, and the shape is identical either way.
            vdev_caps: dict[str, dict] = {}

            def collect_caps(nodes: dict | None, caps: dict[str, dict]) -> None:
                for vname, vd in (nodes or {}).items():
                    vprops = vd.get("properties") or {}
                    alloc = _int_or_none(_prop_value(vprops, "allocated"))
                    if alloc is not None:
                        caps[str(vname)] = {
                            "SizeBytes": _int_or_none(_prop_value(vprops, "size")),
                            "AllocatedBytes": alloc,
                            "CapacityPercent": _int_or_none(_prop_value(vprops, "capacity")),
                        }
                    collect_caps(vd.get("vdevs"), caps)

            collect_caps(((listing or {}).get(name) or {}).get("vdevs"), vdev_caps)
            for entry in vdevs:
                cap = vdev_caps.get(str(entry["Name"]))
                if cap:
                    # cap members can be None (leaves report '-'): the same
                    # null-is-no-statement rule as the walk's own members.
                    entry.update({k: v for k, v in cap.items() if v is not None})
            unhealthy = [vdev["Name"] for vdev in vdevs
                         if vdev.get("State") not in (None, "ONLINE", "AVAIL")]
            vdev_errors = [vdev["Name"] for vdev in vdevs
                           if any((vdev.get(key) or 0) for key in
                                  ("ReadErrors", "WriteErrors", "ChecksumErrors"))]
            cap_pct = _int_or_none(_prop_value(props, "capacity"))
            sfacts = scan_facts(scan)
            if "LastScrubEndTimeUnobservable" in sfacts:
                # scan_facts speaks the old in-band pair (rule 7); DESIGN 19
                # gives could-not-read its own record instead. The null half
                # moves to that channel; the reason stays a string fact
                # because the rulebook cites it as evidence.
                del sfacts["LastScrubEndTime"]
                unobservable.append({
                    "fact": "LastScrubEndTime", "reason": "unavailable",
                    "detail": sfacts["LastScrubEndTimeUnobservable"]})
            if "ScanAgeDays" not in sfacts:
                if isinstance(sfacts.get("ScanEndTime"), str):
                    # an end time was reported but as prose (no --json-int):
                    # the age exists and this OpenZFS cannot let us derive it
                    unobservable.append({
                        "fact": "ScanAgeDays", "reason": "unsupported",
                        "detail": "this OpenZFS renders scan end_time as "
                                  "prose, not an epoch, so no age can be "
                                  "derived from it"})
                else:
                    # no scan record, or a scan still running: there is
                    # genuinely no end to measure an age from
                    absent.append("ScanAgeDays")
            facts = {
                "State": pool.get("state"),
                "StatusMessage": (pool.get("status") or "").strip() or None,
                "Errors": pool.get("error_count"),
                **sfacts,
                "SizeBytes": _int_or_none(_prop_value(props, "size")),
                "AllocatedBytes": _int_or_none(_prop_value(props, "allocated")),
                "FreeBytes": _int_or_none(_prop_value(props, "free")),
                "CapacityPercent": cap_pct,
                "FragmentationPercent": _int_or_none(_prop_value(props, "fragmentation")),
                "Vdevs": vdevs,
                "UnhealthyVdevs": unhealthy,
                "VdevsWithErrors": vdev_errors,
            }
            if listing is None:
                # the properties are on the pool; zpool list is what could
                # not be read — five unobservables, not five absences
                for key in ("SizeBytes", "AllocatedBytes", "FreeBytes",
                            "CapacityPercent", "FragmentationPercent"):
                    facts.pop(key)
                    unobservable.append({
                        "fact": key, "reason": "unavailable",
                        "detail": "zpool list could not be read; zpool "
                                  "status alone carries no capacity "
                                  "properties"})
            layout, tolerated = _redundancy(vdevs)
            if layout:
                facts["Redundancy"] = layout
                facts["DeviceFailuresTolerated"] = tolerated
            else:
                # the pool HAS a layout; this walk cannot justify a claim
                # about it (an unrecognised top-level vdev shape) — which is
                # could-not-read, not has-no-such-property
                for key in ("Redundancy", "DeviceFailuresTolerated"):
                    unobservable.append({
                        "fact": key, "reason": "unsupported",
                        "detail": "a top-level vdev of a shape this reading "
                                  "does not recognise; claiming a tolerance "
                                  "the walk cannot justify is the direction "
                                  "that gets somebody hurt"})
            facts, missing = _split_absent(facts)
            absent = sorted(absent + missing)
            item = env.item_summary(f"pool:{name}", "pool", name, facts,
                                    opinions=pool_opinions(facts))
            # Law 1: every native name observed, split by stability class.
            # A names family holds scalars (the contract's name_scalar), so
            # the pool's channel carries the guid that survives rename and
            # import, the member names as ZFS records them, and the kernel
            # paths a person searches for — while each leaf's fuller name
            # set (guid/wwn/devid) rides its own Vdevs row.
            leaves = [entry for entry in vdevs if entry.get("Type") == "disk"]
            stable: dict[str, object] = {}
            if pool.get("pool_guid") is not None:
                stable["guid"] = str(pool["pool_guid"])
            devices = [str(entry["Name"]) for entry in leaves]
            if devices:
                stable["devices"] = devices
            kernels = [entry["Names"]["ephemeral"]["kernel"] for entry in leaves
                       if "ephemeral" in entry.get("Names", {})]
            if stable:
                item["names"] = {"stable": stable}
                if kernels:
                    item["names"]["ephemeral"] = {"kernel": kernels}
            items.append(_attach_channels(item, absent, unobservable))
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
                "Mounted": _prop_value(props, "mounted"),
            }
            # libzfs derives readonly (and atime/exec/setuid/…) from the
            # QUERYING process's mount table: where a mount option contradicts
            # the stored property it returns the mount's value with source
            # "temporary". ProtectSystem=strict hands this agent every
            # filesystem read-only, so every MOUNTED dataset reported
            # ReadOnly=on/temporary while PID 1's table said rw — 21 rows
            # across two hosts, every one of them wrong (2026-08-10 audit).
            #
            # That is the sandbox's value, not the dataset's, and the stored
            # property is masked behind it. Could-not-read has its own
            # channel (DESIGN 19): ReadOnly becomes an unobservable record —
            # never a null standing where a fact should be — while the reason
            # stays a string fact because consumers cite it in place.
            # Unmounted datasets are unaffected: no mount, no override, so
            # their local/inherited value is the truth.
            readonly_source = _prop_source(props, "readonly")
            masked = readonly_source == "temporary"
            unobservable: list[dict] = []
            if masked:
                facts["ReadOnlyUnobservable"] = (
                    "masked by a temporary mount-option override in the agent's "
                    "own mount namespace (ProtectSystem=strict): zfs reads "
                    "/proc/self/mounts, not PID 1's. This dataset's mount row "
                    "carries the host's live read-only state.")
                unobservable.append({
                    "fact": "ReadOnly", "reason": "unavailable",
                    "detail": facts["ReadOnlyUnobservable"]})
            else:
                facts["ReadOnly"] = _prop_value(props, "readonly")
            facts["ReadOnlySource"] = readonly_source
            facts, absent = _split_absent(facts)
            item = env.item_summary(
                f"dataset:{name}", ds.get("type", "filesystem"), name, facts,
                opinions=dataset_opinions(facts),
                healthy="ok" if use_pct is not None else "info")
            items.append(_attach_channels(item, absent, unobservable))
        return items

    def _source_for(self, collection: str) -> dict:
        table = {
            # The sysfs reads are named alongside the tools: lsblk and mdadm
            # present the same state, but the adapter reads these files and
            # rule 5 asks for what reproduces the observation, not what
            # resembles it. md in particular reported the mdstat/mdadm pair
            # while every fact came from /sys/block/*/md.
            "block-devices": ("lsblk-json", "lsblk -J",
                              ["lsblk", "lsblk -o +MODEL,SERIAL",
                               "ls /sys/class/block/<device>/holders",
                               "readlink -f /sys/class/block/<device>/device"]),
            "mounts": ("findmnt-json", "findmnt -J",
                       ["findmnt --real --task 1", "df -h"]),
            "arrays": ("md-sysfs", "/sys/block/*/md",
                       ["cat /proc/mdstat", "mdadm --detail /dev/md*",
                        "ls /sys/block",
                        "cat /sys/block/<md>/md/{level,array_state,degraded,"
                        "raid_disks,metadata_version,uuid,sync_action,sync_completed}",
                        "cat /sys/block/<md>/md/dev-*/{state,slot,errors}",
                        "cat /sys/block/<device>/size"]),
            # The alias listing is how a reader reproduces Device resolution:
            # the links' targets ARE the kernel names the rows carry.
            "pools": ("zfs-json", "zpool -j",
                      ["zpool status -j", "zpool list -j -p",
                       "ls -l /dev/disk/by-id /dev/disk/by-partuuid /dev/mapper"]),
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

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        """The full materialisation, shared: collect() pages it, get_object
        searches it, and main.py's status/snapshot/changes sweeps consume it
        directly (envelope.single_flight — coalescing, not caching). The
        lookups catalog dispatches here like any other collection: its items
        ARE the documentation. Acquiring mounts sets _findmnt_fallback as a
        side effect, which is why collect() builds its source only after the
        acquisition lands — the note must describe the read that produced
        this page, not the previous one's."""
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
            facts: dict = dict(STORAGE_LOOKUPS[name])
            facts["Usage"] = f"GET /v1/storage/lookups/lookup:{name}/<dataset>"
            return env.observation(self.subsystem, obj, src, facts)
        try:
            dataset, recursive = self._parse_snapshot_arg(arg)
            data = await anyio.to_thread.run_sync(_zfs_snapshots, dataset, recursive)
        except ValueError as exc:
            return env.observation(self.subsystem, obj, src, {"Input": arg},
                                   status="error", errors=[env.reason(exc)])
        except Exception as exc:  # noqa: BLE001 - the failure is the answer
            return env.observation(self.subsystem, obj, src, {"Input": arg},
                                   status="error", errors=[env.reason(exc)])

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
            evidence_ref=env.evidence_ref("storage", "lookups", object_id),
        )

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        items = env.apply_fact_filters(await self.acquire(collection), query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, self._source_for(collection),
                                   page, applied, next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    async def _relationships(self, collection: str, match: dict) -> list[dict]:
        rels: list[dict] = []
        facts = match["facts"]
        native = match["native_id"]

        if collection == "block-devices":
            # One edge per parent, from the row's own fact. An md array is
            # assembled from every mirror member, so naming only the first
            # would publish a false containment as a typed relationship.
            for parent in (facts.get("Parents") or []):
                rels.append(env.rel("member-of", "out", f"block-device:{parent}"))
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
        items = await self.acquire(collection)
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
            evidence_ref=env.evidence_ref("storage", collection, object_id),
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
