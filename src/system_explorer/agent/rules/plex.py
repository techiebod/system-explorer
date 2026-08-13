"""plex-family rules: the media server tier states little, so little is
judged — reachability of what is configured, and nothing invented.

Sessions and pending requests are activity, not health: they carry no
warn/critical shapes at all (a stream is not a fault and a request is a
person waiting, surfaced as facts and info). The one estate-added
judgment is the usual pair no app can make about itself: configured but
unanswering, and configured without receipts.
"""

from __future__ import annotations

from .. import envelope as env


def server_opinions(facts: dict) -> list[dict]:
    if facts.get("ConfigMissing"):
        return [env.opinion(
            "plex-unconfigured", "warn",
            "The server is configured by URL but its receipts are"
            " incomplete: " + ", ".join(facts["ConfigMissing"]) + ".",
            ["ConfigMissing"])]
    if facts.get("StatusUnobservable"):
        return [env.opinion(
            "plex-unreachable", "critical",
            "The configured media server did not answer its API.",
            ["StatusUnobservable"])]
    return []


def request_opinions(facts: dict) -> list[dict]:
    if facts.get("Status") == "pending":
        # info, deliberately: a pending request is a person waiting, which
        # belongs on the object and off the estate attention surface — it
        # is not a fault, and paging an operator for it would teach them
        # to ignore the page.
        return [env.opinion(
            "request-pending", "info",
            "This request awaits approval.", ["Status"])]
    return []
