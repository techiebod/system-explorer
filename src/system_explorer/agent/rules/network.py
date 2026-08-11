"""Network opinions: link operational state, resolver server presence, and
tailscale node health.

Operstate is the deciding fact for links, and the quiet set below is why
loopback needs no exemption by name: interfaces without carrier detection
(lo, wireguard, tun) report "unknown", which is neutral here, never an
indictment. Everything outside the quiet set is a link that exists but is
not passing traffic — previously a warn row that only earned an opinion
when the state was exactly "down"; both consumers now share this evaluator.
"""

from __future__ import annotations

from .. import envelope as env

# Operstates that carry no opinion: "up" is positively healthy; "unknown"
# and "" are carrier-detection absence, not trouble. The remainder of the
# kernel's set (down, dormant, lowerlayerdown, notpresent, testing) warns.
LINK_QUIET_STATES = ("up", "unknown", "")


def link_opinions(facts: dict) -> list[dict]:
    state = facts.get("OperState")
    if state is None or state in LINK_QUIET_STATES:
        return []
    # veth ends flap with the peer namespace's lifecycle; their health is
    # the containers collection's verdict, not the host link table's.
    if facts.get("Kind") == "veth":
        return []
    # A bridge with no member ports is down by design — the kernel only
    # raises a bridge when a member is up, and dockerd assigns docker0's
    # address unconditionally, so the configured-addresses heuristic below
    # misfires on exactly this shape (idle docker0 on several hosts, audit
    # 2026-08-10). A down bridge WITH members lost its ports — a real
    # failure — and falls through to the heuristic.
    if facts.get("Kind") == "bridge" and facts.get("BridgeMembers") == 0:
        return [env.opinion(
            "link-state", "info",
            f"Bridge is {state} with no member ports — an empty bridge is "
            "down by design (its address is daemon-assigned, not intent).",
            ["OperState", "BridgeMembers"])]
    # Intent heuristic until expected-state policy exists (ROADMAP slice 3):
    # a down link carrying configured addresses is something that should be
    # working and is not — warn. A down link with nothing configured on it
    # (an unwired spare NIC, an unused wifi radio) is inventory, not
    # trouble — info, so the row stays neutral instead of crying wolf
    # across every host with spare ports (operator call, 2026-08-10).
    configured = bool(facts.get("Addresses"))
    return [env.opinion(
        "link-state", "warn" if configured else "info",
        f"Link is administratively present but {state}." +
        ("" if configured else " Nothing is configured on it."),
        ["OperState", "Addresses"])]


def resolver_opinions(facts: dict) -> list[dict]:
    if "DNSServersInUse" not in facts:
        return []
    if facts.get("DNSServersInUse") or facts.get("CurrentDNSServer"):
        return []
    return [env.opinion(
        "resolver-servers", "warn",
        "No DNS servers are configured globally or on any link.",
        ["DNSServersInUse", "GlobalDNSServers", "PerLinkDNS"])]


# Node-key expiry ladder: a month out is a calendar reminder; inside a week
# the node is about to fall off the tailnet ("goes dark" territory).
KEY_EXPIRY_WARN_DAYS = 30
KEY_EXPIRY_CRITICAL_DAYS = 7

# Snapshot age beyond 3 collector periods (nix/module.nix runs
# `tailscale status --json` on a one-minute timer under grantTailscaleAccess).
TAILSCALE_SNAPSHOT_STALE_SECONDS = 180


def tailscale_opinions(facts: dict) -> list[dict]:
    """Self and peer items share this evaluator; presence keeps it honest —
    only the self item carries BackendState, KeyExpiryDays and the snapshot
    age, so peers are never judged offline here (that is expected-state
    territory, ROADMAP slice 3)."""
    opinions: list[dict] = []
    days = facts.get("KeyExpiryDays")
    if isinstance(days, int) and days <= KEY_EXPIRY_WARN_DAYS:
        if days < 0:
            message = "The node key has expired."
        elif days == 0:
            message = "The node key expires today."
        else:
            message = f"The node key expires in {days} day{'s' if days != 1 else ''}."
        opinions.append(env.opinion(
            "key-expiry",
            "critical" if days <= KEY_EXPIRY_CRITICAL_DAYS else "warn",
            message, ["KeyExpiry", "KeyExpiryDays"]))
    state = facts.get("BackendState")
    if state is not None and (state != "Running" or facts.get("Online") is False):
        opinions.append(env.opinion(
            "node-offline", "warn",
            "Node is not connected to the tailnet.",
            ["BackendState", "Online"]))
    # Daemon health messages ride the status payload verbatim; the adapter
    # only carries Health when non-empty, so presence is the trigger. Info,
    # not warn: tailscaled uses these for advisories too, and the messages
    # themselves are the substance.
    health = facts.get("Health")
    if isinstance(health, list) and health:
        message = f'The daemon reports: "{health[0]}"'
        if len(health) > 1:
            message += f" (and {len(health) - 1} more)"
        opinions.append(env.opinion(
            "tailscale-health", "info", message + ".", ["Health"]))
    age = facts.get("TailscaleSnapshotAgeSeconds")
    if isinstance(age, int) and age > TAILSCALE_SNAPSHOT_STALE_SECONDS:
        # The rule sees a stale file, not the reason: a wedged collector, or
        # leftover snapshots on a host whose collector was since disabled.
        # Claim only what the evidence carries.
        opinions.append(env.opinion(
            "tailscale-snapshot-stale", "warn",
            f"Tailscale facts are last-known, not current: the snapshot is "
            f"{_human_age(age)} old. The collector may be wedged or not "
            "running on this host.",
            ["TailscaleSnapshotAt", "TailscaleSnapshotAgeSeconds"]))
    return opinions


def _human_age(seconds: int) -> str:
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d{(seconds % 86400) // 3600}h"


def route_opinions(facts: dict) -> list[dict]:
    """A route in a policy table that outranks this host's own connected route.

    The failure this exists for: a node inside a subnet that some tailnet peer
    advertises accepts a route for the segment under its own feet. tailscaled's
    table 52 is consulted at rule preference 5270 and main not until 32766, so
    the tunnelled route wins and every reply to a LAN neighbour goes into the
    tunnel. ARP is not routed, so ARP keeps answering and the host looks
    half-alive: reachable on its overlay address, dark on its LAN address, from
    every machine on the estate including one on the same switch.

    It happened three times before anything could see it, because the routes
    collection read only the main table and the shadowing route was not in the
    envelope at all. The fix is a policy rule below the overlay's preference,
    which is host configuration rather than anything this can assert — so this
    reports the condition and names the remedy rather than pretending to know
    the intent.

    warn, not critical: the host is still reachable by its overlay address, and
    on a deliberate policy-routing setup (a VPN split tunnel) this shape can be
    exactly what was intended. It is always worth a look and never a certainty.
    """
    if not facts.get("ShadowsLocalPrefix"):
        return []
    return [env.opinion(
        "route-shadows-local",
        "warn",
        f"Table {facts.get('Table')} is consulted at rule preference "
        f"{facts.get('RulePreference')}, ahead of main, and carries a route for "
        f"{facts.get('Destination')} — a prefix this host is directly attached "
        "to. Traffic to those neighbours leaves by "
        f"{facts.get('Device')} instead of the local link, which reads as the "
        "host going dark on its own LAN while ARP still answers. A policy rule "
        "for this prefix below that preference restores it.",
        ["Table", "RulePreference", "Destination", "Device", "ShadowsLocalPrefix"])]
