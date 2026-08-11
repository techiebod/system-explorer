"""Hardware opinions: drive SMART verdicts plus scsi/nvme device state.

SMART facts arrive by depth (hwmon sysfs, udisks2, the root collector's
smartctl snapshots — see adapters/hardware.py) but the verdicts on them live
here and nowhere else, shared by scsi and nvme because the fact names already
are. Presence-driven throughout: a host without grantDiskAccess never carries
SmartPercentUsed, so endurance is simply not evaluated there — a capability
statement, not drifted thresholds.
"""

from __future__ import annotations

from .. import envelope as env

# NVMe percentage_used at which a drive is worth watching / past its rated life.
SMART_ENDURANCE_WARN = 90
SMART_ENDURANCE_CRITICAL = 100

# Snapshot age beyond 3 collector periods (nix/module.nix runs smartctl on a
# 5-minute timer). Older means the collector is wedged, or the drive is in
# standby and deliberately left unwoken (-n standby) — either way the SMART
# facts are that old, not observed_at-fresh.
SMART_SNAPSHOT_STALE_SECONDS = 900

# udisks2's self-test verdict vocabularies, one fact name for both
# transports (adapters/hardware.py lifts Drive.Ata and NVMe.Controller
# SmartSelftestStatus alike). Failed verdicts only: everything else —
# success, inprogress, the aborted*/interrupted family, ctrl_reset,
# ns_removed — is not a failure and stays silent.
SMART_SELFTEST_FAILURES = frozenset({
    # Drive.Ata
    "fatal", "error_unknown", "error_electrical", "error_servo",
    "error_read", "error_handling",
    # NVMe.Controller (known_seg_fail, seen on a real drive)
    "fatal_error", "known_seg_fail", "unknown_seg_fail",
})


# Every fact that constitutes an actual health reading. If a drive carries
# none of them, nothing about its health has been measured — and the row must
# not say "ok", which is a positive claim.
SMART_HEALTH_FACTS = (
    "SmartFailing", "SmartOverallPassed", "SmartCriticalWarning",
    "SmartSelftestStatus", "SmartPercentUsed", "SmartAvailableSparePct",
    "SmartMediaErrors", "SmartBadSectors", "SmartTemperatureC",
    "SmartPowerOnHours",
)


def has_smart_reading(facts: dict) -> bool:
    """Whether anything about this drive's health was actually measured.

    Deliberately excludes SmartSnapshotAt/SmartSnapshotAgeSeconds: those say
    the collector RAN, not that it read anything. Conflating the two is how
    five raidz1 members displayed a vouched-for "ok" while their snapshots
    held nothing but an smartctl error.
    """
    return any(facts.get(name) is not None for name in SMART_HEALTH_FACTS)


def smart_opinions(facts: dict) -> list[dict]:
    """Drive health from whatever SMART depth the facts carry."""
    opinions: list[dict] = []
    # Absence with a reason (SPEC section 2, rule 7): the adapter supplies the
    # prose, the rule turns it into a neutral row so "ok" keeps meaning
    # measured-and-healthy rather than merely enumerated.
    unobservable = facts.get("SmartUnobservable")
    if unobservable and not has_smart_reading(facts):
        opinions.append(env.opinion(
            "smart-unmeasured", "info",
            f"No drive-health reading is available: {unobservable} "
            "This row reports the device exists and is running, which is not "
            "the same as healthy.", ["SmartUnobservable"]))
    if facts.get("SmartFailing"):
        opinions.append(env.opinion(
            "smart-health", "critical",
            "SMART reports this drive as failing.", ["SmartFailing"]))
    elif facts.get("SmartCriticalWarning"):
        opinions.append(env.opinion(
            "smart-health", "warn",
            f"NVMe critical warning: {', '.join(facts['SmartCriticalWarning'])}.",
            ["SmartCriticalWarning"]))
    if facts.get("SmartOverallPassed") is False:
        opinions.append(env.opinion(
            "smart-health", "critical",
            "smartctl overall health assessment: FAILED.",
            ["SmartOverallPassed"]))
    selftest = facts.get("SmartSelftestStatus")
    if selftest in SMART_SELFTEST_FAILURES:
        opinions.append(env.opinion(
            "smart-selftest", "warn",
            f"The last SMART self-test failed: {selftest}.",
            ["SmartSelftestStatus"]))
    pct = facts.get("SmartPercentUsed")
    if pct is not None and pct >= SMART_ENDURANCE_WARN:
        opinions.append(env.opinion(
            "smart-endurance",
            "critical" if pct >= SMART_ENDURANCE_CRITICAL else "warn",
            f"Drive has used {pct}% of its rated write endurance"
            + ("; it is past its specified life."
               if pct >= SMART_ENDURANCE_CRITICAL else "."),
            ["SmartPercentUsed"]))
    spare = facts.get("SmartAvailableSparePct")
    threshold = facts.get("SmartSpareThresholdPct")
    if spare is not None and threshold is not None and spare <= threshold:
        opinions.append(env.opinion(
            "smart-spare", "critical",
            f"Available spare ({spare}%) is at or below its threshold "
            f"({threshold}%).", ["SmartAvailableSparePct", "SmartSpareThresholdPct"]))
    if facts.get("SmartMediaErrors"):
        opinions.append(env.opinion(
            "smart-media-errors", "warn",
            f"{facts['SmartMediaErrors']} media error(s) recorded in the "
            "NVMe health log.", ["SmartMediaErrors"]))
    age = facts.get("SmartSnapshotAgeSeconds")
    if isinstance(age, int) and age > SMART_SNAPSHOT_STALE_SECONDS:
        # The rule sees a stale file, not the reason: a wedged collector, a
        # spun-down drive (-n standby preserves the last snapshot), or
        # leftover snapshots on a host with no collector installed at all
        # (an ad-hoc run reading /run residue, seen 2026-08-10). Claim
        # only what the evidence carries.
        opinions.append(env.opinion(
            "smart-snapshot-stale", "warn",
            f"SMART facts are last-known, not current: the newest snapshot "
            f"is {_human_age(age)} old. The collector may be wedged or not "
            "installed on this host, or the drive may be asleep.",
            ["SmartSnapshotAt", "SmartSnapshotAgeSeconds"]))
    return opinions


def _human_age(seconds: int) -> str:
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d{(seconds % 86400) // 3600}h"


def scsi_disk_opinions(facts: dict) -> list[dict]:
    """scsi disks: the kernel device state (offline, blocked, …) plus SMART.
    Only disks carry the running expectation — hosts and expanders are
    topology, not health subjects, and other device types (enclosures,
    changers) are neutral, so the adapter dispatches them elsewhere."""
    opinions: list[dict] = []
    state = facts.get("State")
    if state is not None and state != "running":
        opinions.append(env.opinion(
            "device-state", "warn",
            f"Device state is {state}, not running.", ["State"]))
    return opinions + smart_opinions(facts)


def nvme_opinions(facts: dict) -> list[dict]:
    """nvme controllers: sysfs controller state plus SMART."""
    opinions: list[dict] = []
    state = facts.get("State")
    if state is not None and state != "live":
        opinions.append(env.opinion(
            "controller-state", "warn",
            f"Controller state is {state}, not live.", ["State"]))
    return opinions + smart_opinions(facts)
