"""traefik rules: the ingress speaks for itself — status, errors, backends.

Traefik is the estate's front door: every stack's HTTP path crosses it, so
one adapter's rows describe every route in the estate. The rules fire on
what the API itself states — a router or service carrying its own error
list, a load balancer's per-server health map — never on inference from
traffic. The judgment worth having early is the backend one: a router can
be enabled and green while every server behind its service is DOWN, which
renders as a healthy front door onto nothing (the wrapper-is-not-the-app
shape, at the ingress tier).
"""

from __future__ import annotations

from .. import envelope as env

# Traefik's status vocabulary is THREE-valued (pkg/config/runtime):
# enabled routes clean, disabled does not route, and warning ROUTES —
# non-critical errors append to the error list while the router keeps
# serving. The first cut read it as two values and claimed a serving
# router was rejected with nothing routing through it — a false outage
# on the ingress tier's own rows (adversarial review, 2026-08-12,
# grounded in Traefik's AddError semantics).
ENABLED = "enabled"
DISABLED = "disabled"


def _ingress_opinions(facts: dict, kind: str) -> list[dict]:
    opinions: list[dict] = []
    errors = facts.get("Error")
    status = facts.get("Status")
    error_evidence = ["Error"] + (["Status"] if status is not None else [])
    if errors and status == DISABLED:
        opinions.append(env.opinion(
            f"{kind}-error", "critical",
            f"Traefik rejects this {kind}: " + "; ".join(errors) + ".",
            error_evidence))
    elif errors:
        opinions.append(env.opinion(
            f"{kind}-warning", "warn",
            f"Traefik loaded this {kind} with warnings — still routing: "
            + "; ".join(errors) + ".", error_evidence))
    if status == DISABLED:
        opinions.append(env.opinion(
            f"{kind}-disabled", "warn",
            f"{kind.capitalize()} status is disabled; nothing routes"
            " through it.", ["Status"]))
    elif status is not None and status != ENABLED and not errors:
        # A non-enabled status with no error text: state the status
        # without asserting an outage the API did not claim.
        opinions.append(env.opinion(
            f"{kind}-warning", "warn",
            f"{kind.capitalize()} status is {status}.", ["Status"]))
    return opinions


def router_opinions(facts: dict) -> list[dict]:
    return _ingress_opinions(facts, "router")


def service_opinions(facts: dict) -> list[dict]:
    opinions = _ingress_opinions(facts, "service")
    down = facts.get("ServersDown")
    up = facts.get("ServersUp")
    if isinstance(down, int) and down > 0 and isinstance(up, int):
        # All backends down is a dead route wearing a green router; some
        # down is degraded capacity. Both cite the same health map.
        if up == 0:
            opinions.append(env.opinion(
                "service-servers-down", "critical",
                "Every backend server of this service reports down — the "
                "route is a front door onto nothing.",
                ["ServersDown", "DownServers"]))
        else:
            opinions.append(env.opinion(
                "service-servers-down", "warn",
                f"{down} of {up + down} backend servers report down.",
                ["ServersDown", "DownServers"]))
    return opinions


def overview_opinions(facts: dict) -> list[dict]:
    # Routers and services judge themselves row by row; middlewares have no
    # rows here (deliberately — their documents are where basic-auth
    # hashes live), so their error COUNT is the one overview-level verdict.
    errors = facts.get("MiddlewaresErrors")
    if isinstance(errors, int) and errors > 0:
        return [env.opinion(
            "middlewares-errors", "warn",
            f"Traefik reports {errors} middleware(s) in error.",
            ["MiddlewaresErrors"])]
    return []
