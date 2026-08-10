"""Docker opinions: container state, exit codes, healthcheck verdicts.

The list endpoint (/containers/json) carries no Health or ExitCode fact —
both surface there only inside the human Status string ("Up 3 hours
(unhealthy)", "Exited (137) 2 hours ago"). Each rule therefore reads
whichever representation the facts dict carries and cites the fact it
actually used, so rows and opened objects reach the same verdict from their
own facts. OOMKilled is inspect-only with no summary carrier at all: an
OOM-killed container is a warn row (via its non-zero exit code) but a
critical observation — a documented acquisition gap, not drifted logic.
"""

from __future__ import annotations

import re

from .. import envelope as env

# The list endpoint's Status prefix for a stopped container; group 1 is the
# code that inspect reports as the ExitCode fact.
EXITED_STATUS_RE = re.compile(r"^Exited \((-?\d+)\)")


def _exit_code(facts: dict) -> int | None:
    code = facts.get("ExitCode")
    if isinstance(code, int):
        return code
    match = EXITED_STATUS_RE.match(str(facts.get("Status") or ""))
    return int(match.group(1)) if match else None


def container_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    state = facts.get("State")
    if facts.get("Health") == "unhealthy":
        opinions.append(env.opinion(
            "container-health", "critical",
            "Container healthcheck reports unhealthy.", ["Health"]))
    elif "(unhealthy)" in str(facts.get("Status") or ""):
        opinions.append(env.opinion(
            "container-health", "critical",
            "Container healthcheck reports unhealthy.", ["Status"]))
    if state == "restarting":
        evidence = ["State"] + (["RestartCount"] if "RestartCount" in facts else [])
        opinions.append(env.opinion(
            "container-health", "critical",
            "Container is stuck restarting.", evidence))
    if state in ("paused", "dead"):
        opinions.append(env.opinion(
            "container-health", "warn", f"Container is {state}.", ["State"]))
    code = _exit_code(facts)
    if state == "exited" and code not in (0, None):
        evidence = ["State", "ExitCode"] if "ExitCode" in facts else ["State", "Status"]
        opinions.append(env.opinion(
            "container-exit", "warn",
            f"Container exited with code {code}.", evidence))
    if facts.get("OOMKilled"):
        opinions.append(env.opinion(
            "container-oom", "critical",
            "Container was killed by the OOM killer.", ["OOMKilled", "State"]))
    return opinions
