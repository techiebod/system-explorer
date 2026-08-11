"""Pure envelope helpers, tested directly.

envelope.py imports only stdlib plus system_explorer.text, so this runs
anywhere the rules tests do — no live host, no D-Bus.
"""

import pytest

from system_explorer import text
from system_explorer.agent import envelope as env

# The live regression this exists to prevent: two hosts reported the reason
# below clipped at 120 characters, cutting it mid-word at "remote pe" and
# discarding "activation request failed: unknown unit" — which was the entire
# diagnosis.
LIVE_RESOLVE1_FAILURE = (
    "resolve1 not available on the system bus: "
    "org.freedesktop.DBus.Properties.GetAll failed: "
    "org.freedesktop.DBus.Error.NameHasNoOwner: "
    "[\"Could not activate remote peer 'org.freedesktop.resolve1': "
    "activation request failed: unknown unit\"]"
)


def test_a_short_reason_passes_through_unchanged():
    assert env.reason("no docker socket at /var/run/docker.sock") == (
        "no docker socket at /var/run/docker.sock")


def test_multiline_native_output_collapses_to_one_line():
    """nft and journalctl stderr are multi-line; a reason is one line."""
    assert env.reason("nft cannot read\n  the\truleset") == "nft cannot read the ruleset"


def test_the_live_failure_survives_whole():
    reason = env.reason(LIVE_RESOLVE1_FAILURE)
    assert len(LIVE_RESOLVE1_FAILURE) < text.MAX_LENGTH
    assert reason == LIVE_RESOLVE1_FAILURE
    assert reason.endswith('unknown unit"]'), "the diagnosis must survive"


def test_over_the_limit_cuts_on_a_word_boundary_and_says_so():
    out = env.reason("alpha beta gamma delta", limit=12)
    assert out == "alpha beta … (truncated)"
    assert " …" in out, "a dropped tail must be marked, never silent"


def test_a_single_pathological_token_is_still_bounded():
    """No spaces to cut on — bound it anyway rather than emitting a blob."""
    out = env.reason("A" * 50, limit=10)
    assert out.startswith("A" * 10)
    assert out.endswith("… (truncated)")


def test_dangling_punctuation_is_not_left_at_the_cut():
    assert env.reason("failed to open device, because", limit=20) == (
        "failed to open … (truncated)")


def test_bounding_is_idempotent():
    """A reason may pass through more than one layer (adapter, then the status
    roll-up) without accumulating markers."""
    once = env.reason("word " * 200)
    assert env.reason(once) == once


@pytest.mark.parametrize("value", [None, 42, ValueError("boom"), b"bytes"])
def test_any_object_becomes_a_string(value):
    """Call sites pass exceptions directly; nothing may raise here."""
    assert isinstance(env.reason(value), str)


# ---------------------------------------------------------------------------
# The opinion builder's two invariants. Both are enforced here rather than left
# to discipline, and neither had a test: the evidence rule (SPEC section 2,
# rule 3) reached production untested, and the level enum was not checked at
# all — a typo travelled to the schema on the detail path and to a ValueError
# deep in worst_level's max() on the row path.
# ---------------------------------------------------------------------------

def test_an_opinion_must_cite_evidence():
    with pytest.raises(ValueError, match="must cite evidence"):
        env.opinion("pool-health", "critical", "Pool is DEGRADED.", [])


@pytest.mark.parametrize("level", env.OPINION_LEVELS)
def test_every_level_the_enum_names_is_accepted(level):
    assert env.opinion("k", level, "m", ["Fact"])["level"] == level


@pytest.mark.parametrize("level", ["warning", "INFO", "err", "ok", "none", ""])
def test_a_level_outside_the_closed_enum_is_refused(level):
    """`ok` and `none` are row vocabulary, not opinion levels — a rule reaching
    for either is a category error the builder should catch, not pass on."""
    with pytest.raises(ValueError, match="enum is closed"):
        env.opinion("k", level, "m", ["Fact"])
