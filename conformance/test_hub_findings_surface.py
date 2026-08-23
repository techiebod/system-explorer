"""The findings surface: what needs attention, and how long it has been true.

Register row 29. The lifecycle landed at R3e and its surface did not, so
the one question the shipping product's attention page answers had no
route at either tier. `get_opinions` is not it: an opinion has no
lifecycle, and a finding is an opinion at warn or above WITH one.

The distinction this file mostly exists to hold: an unwired registry must
not answer like a quiet estate. "Nothing is open" and "nobody is keeping
the lifecycle" are the two readings this product exists to keep apart,
and collapsing them on the attention surface is the founding failure at
its loudest.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from system_explorer.hub.routes import table  # noqa: E402


def _route(**kwargs):
    for route in table(lambda: None, **kwargs):
        if route.tool == "get_findings":
            return route
    raise AssertionError("no get_findings route is served")


def test_the_findings_route_exists_and_is_named_for_its_question():
    route = _route()
    assert route.path == "/v1/findings"
    # The description is what an agent reads to choose between this and
    # get_opinions, so it must say what separates them.
    assert "lifecycle" in route.summary
    assert "get_opinions" in route.summary


def test_an_unwired_registry_does_not_answer_like_a_quiet_estate():
    body = _route().handler()
    assert body["findings"] is None, (
        "an empty list here reads as 'nothing is open', which is absence "
        "rendered as health on the one surface whose whole subject is "
        "attention")
    assert "not a report that nothing is open" in body["unanswered"]


def test_a_wired_registry_serves_its_open_set_with_the_ages():
    held = [{"finding": "host:a|unit:x|unit-health", "scope": "host:a",
             "object": "unit:x", "opinion": "unit-health", "instance": None,
             "first_seen": "2026-08-20T00:00:00Z",
             "last_seen": "2026-08-23T00:00:00Z",
             "verdict": "current", "age_is_the_conditions": True, "blind": []}]
    body = _route(findings_of=lambda: held).handler()
    assert body["count"] == 1
    served = body["findings"][0]
    # How long it has been true is the half that makes it a finding
    # rather than an opinion.
    assert served["first_seen"] == "2026-08-20T00:00:00Z"
    assert served["age_is_the_conditions"] is True


def test_a_reset_finding_says_its_age_is_not_the_conditions():
    # Post-cut findings display the reset, and the flag rides on the
    # finding so every surface says the same thing rather than each one
    # deciding. Without it a page shows the reset as the condition's own
    # age and claims an age the estate does not have.
    held = [{"finding": "k", "scope": "host:a", "object": "o", "opinion": "p",
             "instance": None, "first_seen": "2026-08-23T00:00:00Z",
             "last_seen": "2026-08-23T00:00:00Z", "verdict": "current",
             "age_is_the_conditions": False, "blind": []}]
    body = _route(findings_of=lambda: held).handler()
    assert body["findings"][0]["age_is_the_conditions"] is False


def test_an_empty_open_set_is_a_reading_and_not_an_absence():
    # The other direction, and it must NOT look like the unwired case: a
    # wired registry holding nothing is a genuine "nothing is open".
    body = _route(findings_of=lambda: []).handler()
    assert body["findings"] == []
    assert body["count"] == 0
    assert "unanswered" not in body, (
        "a wired registry that holds nothing has ANSWERED; saying it could "
        "not would be the mirror of the defect this file guards")


def test_the_surface_is_json_serialisable():
    # It travels over MCP, which will not carry a dataclass.
    body = _route(findings_of=lambda: [
        {"finding": "k", "scope": "s", "object": "o", "opinion": "p",
         "instance": None, "first_seen": "t", "last_seen": "t",
         "verdict": "current", "age_is_the_conditions": True, "blind": []}
    ]).handler()
    json.dumps(body)
