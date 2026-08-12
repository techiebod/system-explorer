"""Pool scan facts are honest in every shape zfs produces.

Two dishonest readings of scan_stats reached deployed pools (2026-08-12):
a scan in progress renders end_time as 0 under --json-int, and 0 is an int,
so a pool mid-scrub derived ScanEndTime 1970-01-01 and a twenty-thousand-day
ScanAgeDays; and a resilver replaces the scrub's record entirely, so the
stale-scrub rule went silent beside a possibly months-stale scrub — the
absence-as-health shape, backlogged from a foreign host's shelf that read
ScanAgeDays 9 off a resilver.

scan_facts() is module-level and pure (the summary_facts precedent); the
rule cases live in test_rules.py's table like every other evaluator's.
"""

import time

from system_explorer.agent.adapters.storage import scan_facts


def test_a_finished_scrub_carries_its_age():
    week_ago = int(time.time()) - 7 * 86400
    facts = scan_facts({"function": "SCRUB", "state": "FINISHED",
                        "end_time": week_ago})
    assert facts["ScanAgeDays"] == 7
    assert facts["ScanEndTime"].endswith("Z")
    assert "LastScrubEndTime" not in facts
    assert "LastScrubEndTimeUnobservable" not in facts


def test_a_scan_in_progress_is_not_the_epoch():
    # end_time 0 means "has not ended", not 1970: mid-scrub, the row used to
    # claim a ~20,000-day-old scan end.
    facts = scan_facts({"function": "SCRUB", "state": "SCANNING",
                        "end_time": 0, "start_time": int(time.time()) - 3600})
    assert facts["ScanEndTime"] is None
    assert "ScanAgeDays" not in facts


def test_a_resilver_record_states_the_unknown_instead_of_nothing():
    day_ago = int(time.time()) - 86400
    facts = scan_facts({"function": "RESILVER", "state": "FINISHED",
                        "end_time": day_ago})
    # The scan facts stay truthful about the scan that IS recorded…
    assert facts["ScanFunction"] == "RESILVER"
    assert facts["ScanAgeDays"] == 1
    # …and the scrub's are null-with-reason, never silently absent (rule 7).
    assert facts["LastScrubEndTime"] is None
    assert "resilver" in facts["LastScrubEndTimeUnobservable"]


def test_the_locale_string_fallback_survives_unchanged():
    # Older OpenZFS without --json-int: end_time is prose, kept verbatim,
    # age omitted so the stale rule simply does not evaluate.
    facts = scan_facts({"function": "SCRUB", "state": "FINISHED",
                        "end_time": "Sun  1 Feb 16:14:52 GMT 2026"})
    assert facts["ScanEndTime"] == "Sun  1 Feb 16:14:52 GMT 2026"
    assert "ScanAgeDays" not in facts


def test_no_scan_history_stays_bare():
    facts = scan_facts({})
    assert facts["ScanFunction"] is None
    assert "ScanAgeDays" not in facts
    assert "LastScrubEndTimeUnobservable" not in facts
