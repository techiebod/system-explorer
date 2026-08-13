"""downloaders rules: the transfer tier's own statements, mirrored.

Both clients state their troubles directly — transmission per-torrent
(error codes, its own stalled verdict), sabnzbd per-queue (paused state,
disk headroom it measures itself) — and the estate adds only what the
clients cannot say: a configured client that stopped answering, and
receipts that never arrived. Disk capacity reuses the storage rulebook's
ladder where the client states BOTH total and free (sabnzbd does);
transmission states free bytes with no denominator, so no percentage is
invented and the fact stands alone (rule 7: no thresholds without a
denominator the source stated).
"""

from __future__ import annotations

from .. import envelope as env

# The same 90/95 ladder the storage rulebook declares, restated (rulebooks
# import only the envelope) and pinned to storage's values by conformance.
CAPACITY_WARN = 90
CAPACITY_CRITICAL = 95

# transmission's own error vocabulary: 0 none, 1 tracker warning,
# 2 tracker error, 3 local error.
_TRANSMISSION_LOCAL_ERROR = 3


def client_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    if facts.get("ConfigMissing"):
        opinions.append(env.opinion(
            "downloader-unconfigured", "warn",
            "The client is configured by URL but its receipts are"
            " incomplete: " + ", ".join(facts["ConfigMissing"]) + ".",
            ["ConfigMissing"]))
        return opinions
    if facts.get("StatusUnobservable"):
        opinions.append(env.opinion(
            "downloader-unreachable", "critical",
            "The configured client did not answer its API — every manager"
            " dispatching to it is blocked.",
            ["Client", "StatusUnobservable"]))
        return opinions
    total = facts.get("DiskTotalBytes")
    free = facts.get("DiskFreeBytes")
    if isinstance(total, int) and isinstance(free, int) and total > 0:
        used_percent = round((total - free) * 100 / total)
        if used_percent >= CAPACITY_WARN:
            opinions.append(env.opinion(
                "downloader-disk",
                "critical" if used_percent >= CAPACITY_CRITICAL else "warn",
                f"The download volume the client sees is {used_percent}%"
                " full.", ["DiskTotalBytes", "DiskFreeBytes"]))
    if facts.get("Paused") is True:
        opinions.append(env.opinion(
            "downloader-paused", "warn",
            "The whole queue is paused; nothing the managers dispatch"
            " will move until it is resumed.", ["Paused"]))
    return opinions


def transfer_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    error = facts.get("Error")
    if isinstance(error, int) and error != 0 and facts.get("ErrorString"):
        opinions.append(env.opinion(
            "transfer-error",
            "critical" if error == _TRANSMISSION_LOCAL_ERROR else "warn",
            "The client reports: " + str(facts["ErrorString"]) + ".",
            ["Error", "ErrorString"]))
    if facts.get("IsStalled") is True:
        opinions.append(env.opinion(
            "transfer-stalled", "warn",
            "The client's own verdict: no peers are moving this transfer.",
            ["IsStalled"]))
    return opinions
