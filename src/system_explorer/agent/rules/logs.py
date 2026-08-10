"""Log opinions: journal entry severity from the syslog priority.

A log entry is neutral by default — it records that something happened, it
does not vouch for health — so both consumers pass healthy="info" to
worst_level(). Severity from priority alone is only trusted at p<=2:
applications use p3 (err) so promiscuously (dbus-broker's cosmetic
"duplicate name" spam, container stderr logged at a fixed priority) that
err by itself is not attention-worthy, so p3 carries a neutral info row
rather than a warn (audit 2026-08-10). Recency and lifecycle are
deliberately not judged here: whether an error is stale or recurring is
the findings layer's job.
"""

from __future__ import annotations

from .. import envelope as env

# RFC 5424 severity names, indexed by priority. Only 0-3 ever reach a
# message (higher priorities carry no opinion); the full scale documents
# the mapping.
SYSLOG_LEVELS = ("emerg", "alert", "crit", "err",
                 "warning", "notice", "info", "debug")

PRIORITY_CRITICAL = 2  # emerg/alert/crit — severity trusted from priority alone
PRIORITY_INFO = 3      # err — noted, not judged (see module docstring)


def journal_opinions(facts: dict) -> list[dict]:
    priority = facts.get("Priority")
    if not isinstance(priority, int) or priority > PRIORITY_INFO:
        return []
    level = "critical" if priority <= PRIORITY_CRITICAL else "info"
    name = SYSLOG_LEVELS[priority] if 0 <= priority < len(SYSLOG_LEVELS) else "unknown"
    return [env.opinion(
        "journal-priority", level,
        f"Entry logged at priority {priority} ({name}).", ["Priority"])]
