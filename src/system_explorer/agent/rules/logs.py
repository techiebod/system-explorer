"""Log opinions: journal entry severity from the syslog priority.

A log entry is neutral by default — it records that something happened, it
does not vouch for health — so both consumers pass healthy="info" to
worst_level(). Severity from priority alone is only trusted at p<=2:
applications use p3 (err) so promiscuously (dbus-broker's cosmetic
"duplicate name" spam, container stderr logged at a fixed priority) that
err by itself is not attention-worthy, so p3 carries a neutral info row
rather than a warn (audit 2026-08-10: on two hosts a single cosmetic
dbus-broker message was 72 of 72 p<=3 entries for a day).

Flattening p3 solved the false positives and created a second problem: a
genuine p3 became indistinguishable from spam. Two native signals restore
the discrimination without moving any level.

  Transport/Container — a container's stderr is mapped to err by the
  journald log driver, so a p3 from a container may say only "the
  application wrote to stderr", not "the application called this an error".

  RepeatCount/RepeatWindow — repetition is the signal priority cannot give.
  Gated at p<=3 deliberately: the point is to discriminate among the
  entries whose priority we refuse to judge, and a thousand-row kernel page
  should not grow a thousand opinions.

No level ever moves on repetition. Distinguishing "spam" from "crash loop"
needs lifecycle, which is the findings layer's job — as is whether an error
is stale.
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

# One message identity this often within a single page is a pattern rather
# than an event.
REPEAT_NOISE_THRESHOLD = 3


def journal_opinions(facts: dict) -> list[dict]:
    priority = facts.get("Priority")
    if not isinstance(priority, int) or priority > PRIORITY_INFO:
        return []
    name = SYSLOG_LEVELS[priority] if 0 <= priority < len(SYSLOG_LEVELS) else "unknown"
    opinions: list[dict] = []
    if priority <= PRIORITY_CRITICAL:
        opinions.append(env.opinion(
            "journal-priority", "critical",
            f"Entry logged at priority {priority} ({name}); emerg/alert/crit are "
            "trusted as severity from the priority alone.", ["Priority"]))
    elif facts.get("Container"):
        opinions.append(env.opinion(
            "journal-priority", "info",
            f"Entry logged at priority {priority} ({name}) by container "
            f"{facts['Container']}: the journald log driver maps a container's "
            "stderr to err, so the priority is the stream it was written on, not "
            "a severity the application chose.", ["Priority", "Container"]))
    else:
        opinions.append(env.opinion(
            "journal-priority", "info",
            f"Entry logged at priority {priority} ({name}). err alone is not "
            "attention-worthy — applications log routine output at err — so this "
            "entry is recorded, not judged.", ["Priority"]))
    # Evidence must cite only facts guaranteed present in the firing branch:
    # never MessageId, which plenty of emitters do not set.
    repeats, window = facts.get("RepeatCount"), facts.get("RepeatWindow")
    if (isinstance(repeats, int) and isinstance(window, int)
            and repeats >= REPEAT_NOISE_THRESHOLD):
        opinions.append(env.opinion(
            "journal-repeated", "info",
            f"This message appears {repeats} times in the {window} entries this "
            "page read: repetition is the signal priority cannot give — judge it "
            "by content, not by level.", ["RepeatCount", "RepeatWindow"]))
    return opinions
