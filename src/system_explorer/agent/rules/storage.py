"""Storage opinions: mounts, md arrays, ZFS pools and datasets.

Thresholds live here and nowhere else. The UI's capacity bars colour at the
same numbers; if these change, ui/app.js renderCell and capacityPanel change
in the same commit (the conformance suite cannot see JS).
"""

from __future__ import annotations

from .. import envelope as env

# md sync_action values that mean redundancy is being rebuilt or verified.
MD_ACTIVE_SYNC = {"resync", "recover", "check", "repair", "reshape"}

# Shared by mounts and datasets: UsePercent is "share of what this could
# grow into" in both (quota- or pool-bounded for datasets).
CAPACITY_WARN = 90
CAPACITY_CRITICAL = 95

POOL_CAPACITY_WARN = 80
POOL_CAPACITY_CRITICAL = 90

# Scrubs are how latent disk errors get found before a resilver needs the
# redundancy they silently ate. 35 days means a monthly cadence has missed a
# cycle — the threshold that first caught a raidz1 pool sitting six months
# unscrubbed with nothing on the row to say so.
SCRUB_STALE_DAYS = 35

# A full pool's next question is which datasets ate it. Ordered by UsedBytes,
# not UsePercent: a dataset's UsePercent is its share of what IT could grow
# into, which is pool-bounded, so on a full pool every dataset reads high and
# the ranking says nothing. Bytes name the consumer. Both facts are on the
# dataset row (adapters/storage.py _dataset_items).
LOOK_DATASETS_BY_USED = [{"subsystem": "storage", "collection": "datasets",
                          "fact": "UsedBytes",
                          "label": "which datasets are using the space"}]


def _capacity_opinion(key: str, use: object, message: str) -> list[dict]:
    if not isinstance(use, int) or use < CAPACITY_WARN:
        return []
    level = "critical" if use >= CAPACITY_CRITICAL else "warn"
    return [env.opinion(key, level, message, ["UsePercent"])]


def mount_opinions(facts: dict) -> list[dict]:
    use = facts.get("UsePercent")
    return _capacity_opinion("mount-capacity", use, f"Filesystem is {use}% full.")


def dataset_opinions(facts: dict) -> list[dict]:
    use = facts.get("UsePercent")
    return _capacity_opinion(
        "dataset-capacity", use,
        f"Dataset has consumed {use}% of its available headroom "
        "(quota- or pool-bounded).")


def array_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    degraded = facts.get("Degraded") or 0
    if degraded:
        opinions.append(env.opinion(
            "array-degraded", "critical",
            f"{degraded} of {facts.get('RaidDisks')} member devices "
            "missing or failed.", ["Degraded", "Members"]))
    erroring = [member["Device"] for member in (facts.get("Members") or [])
                if member.get("Errors")]
    if erroring:
        opinions.append(env.opinion(
            "array-member-errors", "warn",
            "Member device errors recorded on: " + ", ".join(erroring) + ".",
            ["Members"]))
    action = facts.get("SyncAction")
    if action in MD_ACTIVE_SYNC:
        percent = facts.get("SyncPercent")
        progress = f" ({percent}% complete)" if percent is not None else ""
        opinions.append(env.opinion(
            "array-sync", "warn" if action == "recover" else "info",
            f"Array {action} in progress{progress}; redundancy is not "
            "fully established until it finishes.",
            ["SyncAction", "SyncPercent"]))
    return opinions


def pool_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    state = facts.get("State")
    # Presence-driven: an absent/unreadable state is neutral-unknown, not an
    # indictment — only a reported non-ONLINE state is a verdict.
    if state is not None and state != "ONLINE":
        opinions.append(env.opinion(
            "pool-health", "critical",
            f"Pool state is {state}.", ["State"]))
    if facts.get("UnhealthyVdevs"):
        opinions.append(env.opinion(
            "vdev-health", "critical",
            "Vdev(s) not healthy: "
            + ", ".join(facts["UnhealthyVdevs"]) + ".", ["Vdevs"]))
    if facts.get("VdevsWithErrors"):
        opinions.append(env.opinion(
            "vdev-errors", "warn",
            "Read/write/checksum errors recorded on: "
            + ", ".join(facts["VdevsWithErrors"]) + ".", ["Vdevs"]))
    cap = facts.get("CapacityPercent")
    if isinstance(cap, int) and cap >= POOL_CAPACITY_WARN:
        opinions.append(env.opinion(
            "pool-capacity",
            "critical" if cap >= POOL_CAPACITY_CRITICAL else "warn",
            f"Pool is {cap}% full; ZFS performance degrades as pools "
            "fill.", ["CapacityPercent"], look=LOOK_DATASETS_BY_USED))
    if facts.get("ScanState") == "SCANNING":
        opinions.append(env.opinion(
            "pool-scan", "info",
            f"{(facts.get('ScanFunction') or 'scan').lower()} in "
            "progress.", ["ScanFunction", "ScanState"]))
    # ScanAgeDays exists only when the adapter got an epoch end_time
    # (zpool --json-int); the locale-string fallback and never-scrubbed
    # pools (no scan_stats — absence of history is not a finding yet)
    # carry no age, so the rule stays silent (SPEC rule 14).
    # A resilver replaced the scrub's record: the stale-scrub rule below
    # cannot evaluate, and its silence beside a possibly months-stale scrub
    # is absence-as-health — the exact shape this product exists to kill,
    # observed on a foreign host whose shelf read ScanAgeDays 9 from a
    # resilver while the true scrub age was unknowable. A stated unknown at
    # info: nothing is wrong, the agent simply cannot answer, and should
    # say so rather than say nothing (rule 7).
    if facts.get("LastScrubEndTimeUnobservable"):
        opinions.append(env.opinion(
            "pool-scrub-age-unknown", "info",
            "Time since the last completed scrub is unknown: "
            + str(facts["LastScrubEndTimeUnobservable"]) + ".",
            ["ScanFunction", "LastScrubEndTimeUnobservable"]))
    age = facts.get("ScanAgeDays")
    if (facts.get("ScanFunction") == "SCRUB"
            and facts.get("ScanState") == "FINISHED"
            and isinstance(age, int) and age >= SCRUB_STALE_DAYS):
        opinions.append(env.opinion(
            "pool-scrub-stale", "warn",
            f"Last completed scrub finished {age} days ago; latent disk "
            "errors surface only when a scrub reads them.",
            ["ScanEndTime", "ScanAgeDays"]))
    return opinions
