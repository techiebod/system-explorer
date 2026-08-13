"""bazarr rules: the subtitle manager's own health list, mirrored whole.

bazarr does not grade its issues — its health endpoint is a flat list of
problem sentences — so the mirror is one warn carrying its count, with
the issues themselves as facts. The estate adds only the configured-but-
dark pair, as everywhere.
"""

from __future__ import annotations

from .. import envelope as env


def instance_opinions(facts: dict) -> list[dict]:
    if facts.get("ConfigMissing"):
        return [env.opinion(
            "bazarr-unconfigured", "warn",
            "The instance is configured by URL but its receipts are"
            " incomplete: " + ", ".join(facts["ConfigMissing"]) + ".",
            ["ConfigMissing"])]
    if facts.get("StatusUnobservable"):
        return [env.opinion(
            "bazarr-unreachable", "critical",
            "The configured instance did not answer its API.",
            ["StatusUnobservable"])]
    issues = facts.get("HealthIssues")
    if issues:
        return [env.opinion(
            "bazarr-health", "warn",
            f"The app reports {len(issues)} health issue(s) of its own —"
            " each is listed in HealthIssues.", ["HealthIssues"])]
    return []
