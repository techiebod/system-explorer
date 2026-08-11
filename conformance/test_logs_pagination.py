"""The journal's time bound must survive pagination.

journalctl refuses --since together with --cursor, so the adapter resolves
since= to an absolute floor itself and carries that floor inside its own
cursor. These are pure-function tests: they import the adapter but call
nothing that spawns a process, so they run anywhere the rest of the suite does.

Regression under test (measured 2026-08-10): with the bound handed to
journalctl on page 1 only, page 2 of a `-30m` query returned entries 83
minutes old while `filters` still advertised the 30-minute window.
"""

from datetime import datetime, timezone

import pytest

from system_explorer.agent.adapters import logs

NOW = datetime(2026, 8, 10, 22, 34, 58, tzinfo=timezone.utc)
NOW_USEC = int(NOW.timestamp() * 1_000_000)


@pytest.mark.parametrize("expr, expected_offset_seconds", [
    ("-30m", 30 * 60),
    ("-30min", 30 * 60),
    ("-30minutes", 30 * 60),
    ("-24h", 24 * 3600),
    ("-1d", 86400),
    ("-2w", 2 * 604800),
    ("-45s", 45),
    ("now", 0),
])
def test_relative_since_resolves_to_an_absolute_floor(expr, expected_offset_seconds):
    floor = logs._since_floor_usec(expr, NOW)
    assert floor == NOW_USEC - expected_offset_seconds * 1_000_000


def test_utc_timestamp_resolves():
    assert logs._since_floor_usec("2026-08-10T12:00:00Z", NOW) == int(
        datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1_000_000)


def test_epoch_form_resolves():
    assert logs._since_floor_usec("@1786104000", NOW) == 1786104000 * 1_000_000


@pytest.mark.parametrize("expr", ["last monday", "2 days ago", "", "-", "-10furlongs"])
def test_unenforceable_spellings_are_refused_not_guessed(expr):
    """journalctl accepts some of these; this adapter cannot enforce them on
    page 2, and a bound that silently stops applying is worse than a refusal."""
    assert logs._since_floor_usec(expr, NOW) is None


def test_cursor_round_trip_carries_the_floor():
    journal_cursor = "s=abc;i=1;b=def;m=123;t=456;x=789"
    encoded = logs._encode_cursor(NOW_USEC, journal_cursor)
    assert logs._decode_cursor(encoded) == (NOW_USEC, journal_cursor)


def test_a_bare_journal_cursor_still_decodes():
    """Cursors issued before the floor was carried must keep working."""
    journal_cursor = "s=abc;i=1;b=def;m=123;t=456;x=789"
    assert logs._decode_cursor(journal_cursor) == (None, journal_cursor)


def test_the_separator_cannot_occur_in_a_journal_cursor():
    """Journal cursors are s=..;i=..;b=..;m=..;t=..;x=.. — only [a-z0-9=;]."""
    assert logs.CURSOR_SEP not in "abcdefghijklmnopqrstuvwxyz0123456789=;"


def test_no_cursor_decodes_to_nothing():
    assert logs._decode_cursor(None) == (None, None)


@pytest.mark.parametrize("record, expected", [
    ({"MESSAGE_ID": "abc", "MESSAGE": "pid 1 died"}, "id:abc"),
    ({"MESSAGE_ID": "abc", "MESSAGE": "pid 2 died"}, "id:abc"),
    ({"MESSAGE": "no catalog id here"}, "msg:no catalog id here"),
    ({"MESSAGE_ID": "", "MESSAGE": "empty id falls back"}, "msg:empty id falls back"),
])
def test_repeat_identity_groups_a_message_type(record, expected):
    """MESSAGE_ID groups entries differing only in interpolated values; an
    emitter that sets none falls back to the verbatim text."""
    assert logs._repeat_identity(record) == expected
