"""network subsystem: links, routes, resolver, nftables, tailscale, lookups.

Acquisition: `ip -j` (structured CLI over netlink), resolve1 over D-Bus for
the stub resolver, `nft -j` for the ruleset. nftables needs CAP_NET_ADMIN,
which the NixOS module grants per host; without it the collection reports
its absence honestly. conntrack-summary is deferred until the netlink
acquisition lands and is declared unavailable rather than faked.

tailscale follows the SMART collector precedent (SPEC rule 12): the module's
grantTailscaleAccess timer has root write `tailscale status --json` to
/run/system-explorer-tailscale/status.json, and this adapter only ever reads
the snapshot and reports its age — no subprocess, no socket reach.

Lookups (SPEC section 6) are the parameterised half of debugging: "which
route would the kernel pick for this address", "what does the resolver
answer for this name". The input is a single validated value passed as one
argv token or one D-Bus argument — it never reaches a shell and never
chooses which command runs.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import anyio

from .. import envelope as env
from ..rules.network import (LINK_QUIET_STATES, link_opinions,
                             resolver_opinions, route_opinions,
                             tailscale_opinions)
from ..sysbus import BUS, CallError

RESOLVE1 = "org.freedesktop.resolve1"
RESOLVE1_PATH = "/org/freedesktop/resolve1"
RESOLVE1_MANAGER = "org.freedesktop.resolve1.Manager"
RESOLVE1_LINK = "org.freedesktop.resolve1.Link"

LINK_REFERENCE = ["ip -d addr show", "networkctl status <link>"]
ROUTE_REFERENCE = ["ip -4 route show table all", "ip -6 route show table all",
                   "ip rule show"]
RESOLVER_REFERENCE = ["resolvectl status", "resolvectl dns"]
# The file shape: what glibc itself reads when no resolved stub is present.
# A specified format (resolv.conf(5)), not human-readable command output —
# reading it is rule-8 legitimate the way /etc/machine-id is.
RESOLV_CONF = "/etc/resolv.conf"
FILE_RESOLVER_REFERENCE = ["cat /etc/resolv.conf", "ls -l /etc/resolv.conf"]
# What this collection ACTUALLY reports, which is not what it used to name.
# `nft list ruleset` was cited while the rows carry table and chain inventory
# with a rule COUNT — so an operator reproducing the cited command saw
# strictly more than the observation contained, which is rule 5 broken in the
# direction the lint cannot see: it checks that a command is named, never
# that its output is used. The ruleset command stays, last, because it is
# what answers the question these rows raise and cannot settle.
NFT_REFERENCE = ["nft list tables", "nft list chains", "nft list ruleset"]

# Stated on every nft-tables response, because the shape of these rows
# invites a conclusion they cannot support. A firewall's rows here say a
# table exists and how many rules it holds; they do not say what any rule
# permits, so deleting the single rule that admits sshd on one interface
# would move RuleCount from 25 to 24 and change nothing else on this page.
# On a host whose entire posture is its ruleset that is absence rendered as
# health, and until the rules themselves are objects the honest move is to
# say so where the rows are read rather than leave the gap to be inferred.
NFT_NOTES = [
    "Rules are COUNTED here, never read: these rows carry each table's"
    " chains and how many rules they hold, and no fact on this page says"
    " what any rule matches or permits. A ruleset that admits one port from"
    " one interface and one that admits everything from anywhere are"
    " indistinguishable in this collection.",
    "The full ruleset — every match, port, interface and verdict — is in"
    " this collection's evidence, which is where to look until the rules"
    " have rows of their own.",
]
TAILSCALE_REFERENCE = ["tailscale status --json"]

TAILSCALE_SNAPSHOT = "/run/system-explorer-tailscale/status.json"
TAILSCALE_UNAVAILABLE = (f"no tailscale snapshot at {TAILSCALE_SNAPSHOT} "
                         "(grantTailscaleAccess off, or tailscaled absent)")

# What the link facts MEAN, served over /v1/facts. Written because the Kind
# column reads as an em-dash on every physical interface and nothing in the
# product explained why: a reader who asked why five of seven rows were blank
# had nowhere to look. Native names are the contract (SPEC §5), so the sentence
# carries the concept the name cannot.
_LINK_GLOSSARY = {
    "OperState": (
        "The kernel's operational state for this interface: up, down, or "
        "unknown. Loopback and point-to-point devices report unknown because "
        "they have no carrier to detect, which is not the same as being down."
    ),
    "Kind": (
        "The software device type the kernel reports — bridge, veth, vlan, "
        "bond, and tun or tap. A physical interface has none, because a kind "
        "comes from the driver that implements a virtual device; blank here "
        "means this is not a software device, and loopback is blank for the "
        "same reason. tun and tap share one driver, so the kernel names that "
        "driver \"tun\" for both and the mode one level down; this reports the "
        "mode, because the mode is what makes them different devices. See "
        "LinkType for the link layer, which every interface has."
    ),
    "LinkType": (
        "The link layer this interface speaks, from the kernel's hardware type: "
        "ether for Ethernet — which includes bridges and TAP devices, both of "
        "which carry Ethernet frames — loopback, or none for an interface with "
        "no link-layer header at all. A layer-3 tunnel is none, which is why it "
        "has no MAC address. This is the only one of the two that every "
        "interface has, so it is what names a physical NIC or loopback, neither "
        "of which has a Kind."
    ),
    "MTU": "The largest payload this interface will carry, in bytes.",
    "MACAddress": (
        "The hardware address currently in use. This can be set by "
        "configuration; PermanentMACAddress appears when it differs from the "
        "one burned into the device."
    ),
    "PermanentMACAddress": (
        "The address burned into the hardware, present only when it differs "
        "from the address in use — that is, when the MAC has been overridden."
    ),
    "Master": (
        "The bridge or bond this interface is enslaved to, if any. A port's own "
        "addresses are usually empty because the master carries them."
    ),
    "Addresses": (
        "The IP addresses configured on this interface, in CIDR form. An empty "
        "list on an enslaved port is normal."
    ),
    "BridgeMembers": (
        "How many interfaces are enslaved to this bridge. Present only on a "
        "bridge; zero means the bridge has no ports, which is why the kernel "
        "keeps it down."
    ),
    "ParentBus": (
        "The bus the device sits on, when it is backed by hardware — pci, usb. "
        "Absent on software devices, which have no parent."
    ),
    "ParentDev": (
        "The bus address of the hardware behind this interface, spelled as the "
        "kernel spells it, so it joins to the matching device in hardware/pci."
    ),
    "PeerMACAddresses": (
        "The hardware addresses this bridge has learned behind this port — the "
        "join key that names what is on the other end of a veth. Absent means "
        "the port has been quiet, not that nothing is attached."
    ),
    "LLDPNeighbors": (
        "What the switch or host on the other end of this link says it is, "
        "when it announces itself over LLDP."
    ),
}

_ROUTE_GLOSSARY = {
    "Destination": "The prefix this route matches, or `default` for the route of last resort.",
    "Gateway": "The next hop, when the destination is not directly attached.",
    "Device": "The interface the kernel sends matching traffic out of.",
    "Protocol": "What installed the route — kernel for a directly-attached prefix, dhcp, ra, static, or a daemon's own name.",
    "Scope": "How far the destination is: link means directly attached on this segment, global means reachable via a gateway.",
    "PrefSrc": "The source address the kernel will use for traffic it originates down this route.",
    "Metric": "Tie-break between routes to the same destination; lower wins.",
    "Family": ("Which address family this route is for: ipv4 or ipv6. The two are\n                separate tables and a host can be healthy in one and broken in the other."),
    "Table": (
        "Which routing table holds this route. Most are in `main`, but policy "
        "routing puts routes in others — a VPN or overlay typically keeps its "
        "own. The table alone does not say whether a route wins; see "
        "RulePreference."
    ),
    "RulePreference": (
        "The lowest rule preference that selects this route's table. The kernel "
        "walks rules in ascending order and takes the first table that answers, "
        "so a smaller number here means this table is consulted earlier and its "
        "routes outrank those in tables checked later. main is usually 32766. "
        "Absent when no rule names the table."
    ),
    "ShadowsLocalPrefix": (
        "Present only when this route is in a table consulted before main AND "
        "main holds a directly-attached route for the same prefix — so this one "
        "wins for a segment the host is physically on. Traffic to those "
        "neighbours leaves down this route instead of the local link."
    ),
}

# Written after an operator read the resolver row's CurrentDNSServer beside
# the fallback list and reasonably concluded the host's primary DNS was a
# public resolver, while every real query went to the LAN (2026-08-12). The
# facts were all true; nothing on the screen said which scope each belonged
# to. That is exactly the LinkSpeed/LinkWidth lesson from the hardware
# glossary: native names carry scope a reader cannot infer.
_RESOLVER_GLOSSARY = {
    "CurrentDNSServer": (
        "The selected server of resolved's GLOBAL scope only — the scope "
        "backed by GlobalDNSServers or, when none are configured, the "
        "fallback list. It is sticky: it shows whichever server that scope "
        "last used, often chosen at boot before any link had DNS, and keeps "
        "showing it while the scope sits idle. It is NOT where ordinary "
        "queries go when a link carries the default route — see PerLinkDNS, "
        "whose per-link CurrentDNSServer is the one answering."
    ),
    "PerLinkDNS": (
        "Each link's DNS configuration: its servers, the server currently "
        "answering, the domains routed to it, and DefaultRoute — whether "
        "queries matching no domain go here. A link with DefaultRoute true "
        "is the host's working resolver path; DefaultRoute absent means "
        "this resolved predates the property, which is not a no."
    ),
    "GlobalDNSServers": (
        "Servers configured globally rather than on a link. Empty is normal "
        "on a host whose DNS arrives per-link via DHCP; ordinary queries "
        "then follow whichever link has DefaultRoute."
    ),
    "FallbackDNSServers": (
        "Compiled-in public resolvers used only when no global server is "
        "configured and no link takes the default route — or in the boot "
        "window before any link has DNS. Reachable last resort, not "
        "configuration."
    ),
    "DNSServersInUse": (
        "The union of every server configured globally or on any link — "
        "what could answer, not what answered last. The fallback list is "
        "deliberately excluded."
    ),
    "SearchDomains": (
        "Domains appended to single-label names, plus route-only entries "
        "(marked) that steer matching queries to a specific link without "
        "being used for completion. On a host without resolved this is the "
        "file's search line, last one winning, exactly as glibc reads it."
    ),
    "ResolverService": (
        "Which mechanism answers name lookups on this host: systemd-resolved "
        "(the stub at 127.0.0.53, with per-link routing), or libc-resolv.conf "
        "— glibc reading /etc/resolv.conf directly, the path every Unix has. "
        "Both are resolvers; the facts beside this one differ because the "
        "mechanisms genuinely do."
    ),
    "Nameservers": (
        "The servers named in /etc/resolv.conf, in file order. glibc uses "
        "only the first three; the rest are listed because they are in the "
        "file, and a file that names five servers is telling you something "
        "about how it is managed."
    ),
    "Options": (
        "The file's options lines, accumulated across resolv.conf exactly "
        "as glibc accumulates them — timeouts, attempts, rotation, ndots."
    ),
    "ResolvConfTarget": (
        "Where /etc/resolv.conf points when it is a symlink — usually the "
        "name of whoever manages resolution. A plain file has no target, "
        "and then the writer is whoever last wrote it (commonly dhcpcd or "
        "an operator)."
    ),
}

# Which network facts are not measured. The exposure row is why this exists
# at all: AdmittedFromCertain is a two-closure computation over a ruleset,
# it was WRONG FIVE TIMES in one review pass — a dport range inside a set
# dropped, `match.op` never read, guards unioned instead of intersected, the
# address family never consulted, an unreadable verdict dropped from both
# closures — and it rendered in the same plain table cell as a port number
# read straight out of /proc/net.
_NETWORK_KINDS = {
    "links": {
        # The kernel names a driver; what the device IS comes from reading
        # several of its attributes together.
        "Kind": "derived",
    },
    "listening": {
        # What the binding implies about reach, before any rule is read.
        "Scope": "derived",
    },
    "nft-chains": {
        # Nothing in nft's document says what calls a chain; this is every
        # rule in every table, read.
        "JumpedFrom": "derived", "Unreferenced": "derived",
        "BaseChain": "derived",
    },
    "nft-rules": {
        # The rendered line is this product's rendering of nft's JSON, and
        # the comprehension figures are what it could not render, computed
        # by subtraction.
        "Rendered": "derived", "Comprehension": "derived",
        "OpaqueReason": "derived", "Residue": "derived",
        "Position": "derived",
    },
    "port-exposure": {
        "AdmittingRules": "derived", "AdmittedFromCertain": "derived",
        "AdmittedFromPossible": "derived", "ClosureGap": "derived",
        "ClosureGapRules": "derived", "PathCoverage": "derived",
        "Scope": "derived",
    },
    "resolver": {},
    "routes": {},
    "tailscale": {},
    "lookups": {},
    # nft-tables documents none of its facts yet, so there is nothing here
    # to classify — an empty dict says somebody looked, which is the whole
    # point of it being distinct from None.
    "nft-tables": {},
}

_LISTENING_GLOSSARY = {
    "Protocol": "Which /proc/net table this socket came from — tcp, tcp6, udp or udp6. A host that binds both stacks appears twice, deliberately: they are two sockets and a ruleset can admit one and not the other.",
    "LocalAddress": "The address this socket is bound to. The wildcard (0.0.0.0 or ::) means every interface the host has now or gains later, which is the binding the firewall question actually hangs off.",
    "LocalPort": "The port this socket accepts on.",
    "Scope": "What the binding says about reach before any rule is consulted: all-interfaces, loopback, or specific-address. A loopback socket is unreachable from off the host whatever the ruleset permits, and a wildcard one is reachable from wherever the ruleset allows — so this is the fact that decides whether the firewall matters for this row at all.",
    "Uid": "The user that owns the socket, from /proc/net itself. It is not the process name and does not pretend to be; it is what can be said about ownership without the privilege the join below needs.",
    "SocketInode": "The socket's inode, which is the key /proc/<pid>/fd entries point at — the join a privileged reader would use to name the process.",
    "ProcessUnobservable": "Why no process is named on this row. A socket whose owner could not be established is not a socket nobody owns, and this states which it is.",
}

_NFT_RULE_GLOSSARY = {
    "Family": "The address family this rule's table belongs to — ip, ip6, inet, arp, bridge or netdev.",
    "Table": "The table holding this rule. On a real host the table name is an ownership label: docker, libvirt, firewalld and nixos-fw were each written by something different, and this observer sees all of them at once where a manager's own UI sees only its own.",
    "Chain": "The chain holding this rule.",
    "Handle": "The kernel's own identifier for this rule, and the join key to `nft -a list ruleset`. Stable while the rule object lives; a flush-and-restore reassigns handles, so it is not durable across a reload.",
    "Position": "This rule's ordinal within its chain. Evaluation is ordered and first-match-wins, so position is meaning, not presentation.",
    "Rendered": "What this rule says, in nft's own vocabulary, with every term present. A term whose meaning could not be expanded appears at its position as a placeholder rather than being dropped — omission would turn a narrow rule into a permissive-looking one.",
    "Verdict": "How this rule ends — accept, drop, reject, return, continue or queue — or absent where the rule ends in no verdict at all, which is what a pure counter or logging rule does.",
    "JumpTarget": "The chain this rule transfers control to. A jump is not a decision: what happens is decided by the chain it goes to.",
    "Comprehension": "How much of this rule the renderer could state: full where every statement was rendered, partial where some were not, opaque where the rule's conditions are absent from the source document entirely. Computed by subtracting what the renderer consumed from the rule's own expression list, never assumed.",
    "OpaqueReason": "Why a rule's conditions could not be read: xt where it calls an xtables extension whose parameters nft's JSON does not carry, text-fallback where nft emitted a bare string because it had no JSON encoder for the expression.",
    "Residue": "The expressions in this rule the renderer did not consume, verbatim. This is the measured extent of what the row above does not say.",
    "CounterPackets": "Packets this rule has matched, where the rule carries a counter. nftables has no implicit per-rule counters, so absence here means the rule was written without one — never that nothing has matched.",
    "CounterBytes": "Bytes this rule has matched, where the rule carries a counter. Absent means no counter was written, not zero traffic.",
}

_NFT_CHAIN_GLOSSARY = {
    "Family": "The address family this chain's table belongs to — ip, ip6, inet, arp, bridge or netdev. The same chain name in ip and ip6 is two chains, and a rule admitting a port in one says nothing about the other.",
    "Table": "The table holding this chain. On a real host the table name is an ownership label: docker, libvirt, firewalld and nixos-fw were each written by something different.",
    "Name": "The chain's name, as its author wrote it.",
    "Handle": "The kernel's own identifier for this chain object.",
    "BaseChain": "Whether the kernel calls this chain directly. A base chain is registered against a hook and every packet on that path enters it; a regular chain runs only when something jumps to it, which is why the two need telling apart before any rule in either is read.",
    "Hook": "The netfilter hook this base chain is registered against — prerouting, input, forward, output or postrouting. It is WHERE in the packet's journey this chain runs, and absent on a regular chain because nothing calls it directly.",
    "Type": "What the kernel lets this base chain do: filter chains decide, nat chains translate, route chains can re-run the routing decision. Absent on a regular chain.",
    "Priority": "The order this base chain runs in relative to others on the same hook, lowest first. Two chains on one hook are both traversed; this says which sees the packet first, and a negative number is normal.",
    "Policy": "What happens to a packet that reaches the end of this base chain matching nothing — accept or drop. It is the verdict the whole chain falls back to, so a chain of narrow accepts under an accept policy admits everything the rules did not mention. Absent on a regular chain, which returns to its caller instead.",
    "RuleCount": "How many rules this chain holds. Counted, never read: this says nothing about what any of them permits.",
    "JumpedFrom": "Every chain that transfers control here, by jump or goto — how a packet reaches this chain at all. Derived by reading every rule's target across the whole ruleset, and the elements of every named verdict map some rule uses, so it is the answer to 'what runs this' that no single chain's own document contains.",
    "Unreferenced": "Stated only when true, and only for a regular chain: no rule, and no named verdict map any rule uses, jumps or gotos here, and the kernel does not call it, so no packet can reach any rule in it. Usually a leftover; occasionally a rule that was meant to be reachable and is not.",
}

_EXPOSURE_GLOSSARY = {
    "Protocol": "The listening socket's protocol, joined from the listening collection.",
    "LocalAddress": "The address the socket is bound to; the wildcard means the ruleset alone decides what reaches it.",
    "LocalPort": "The port this row is about — the number an operator arrives asking after, which is why it is the row rather than a column on a rule.",
    "Scope": "What the binding says before any rule: a loopback socket is unreachable from off the host whatever the ruleset permits.",
    "AdmittingRules": "Every rule on the input path that admits this port, in evaluation order, each with its handle and rendered text. Evidence for the two answers below, and the thing to go and read.",
    "AdmittedFromCertain": "The source constraints of admitting rules that were rendered in full — where traffic can reach this port from, by rules this observer understood completely. A clause it could not read contributes nothing here, so this is a lower bound and can only ever under-claim.",
    "AdmittedFromPossible": "The same computation with every unreadable clause treated as matching — an upper bound. Where this is wider than the certain answer, the difference is the part of the ruleset this observer cannot interpret rather than a property of the firewall.",
    "ClosureGap": "Whether the two answers differ. True means the ruleset contains a clause this adapter could not read that bears on this port, and the rules responsible are named beside it.",
    "ClosureGapRules": "The handles of the rules whose unreadable clauses opened the gap — where to look to close it by hand.",
    "PathCoverage": "Which packet paths this row accounts for. Input only: a published container port is translated in prerouting and admitted in forward and is not covered, so an empty admitting list is not a statement that nothing can reach the port.",
}

_NETWORK_GLOSSARY = {"links": _LINK_GLOSSARY, "routes": _ROUTE_GLOSSARY,
                     "resolver": _RESOLVER_GLOSSARY,
                     "listening": _LISTENING_GLOSSARY,
                     "nft-chains": _NFT_CHAIN_GLOSSARY,
                     "nft-rules": _NFT_RULE_GLOSSARY,
                     "port-exposure": _EXPOSURE_GLOSSARY}


def _link_kind(link: dict) -> str | None:
    """The kernel's most specific name for what this device IS, or None.

    info_kind names the driver, and for tun/tap that is "tun" in either mode —
    so tailscale0 (a layer-3 tunnel with no address) and libvirt's vnet* (layer-2
    taps enslaved to a bridge) arrived indistinguishable. The kernel does draw
    the line, one level down in the same object: info_data.type is "tun" or
    "tap". Read, never inferred, and it degrades to the driver name if a kernel
    ever stops reporting the mode.

    Top-level info_kind only: linkinfo on a bridge port also carries
    info_slave_kind ("bridge"), which classes the enslavement rather than the
    device and would render a port as a bridge. Master already says a port is
    enslaved.

    A device the kernel gives no info_kind — every physical interface, and
    loopback, which carry no linkinfo at all — has no kind here. That absence is
    the statement "not a software device". LinkType is what names those, and
    copying an ARPHRD name in would put two taxonomies in one field: a bridge is
    "ether" as well as a bridge, so the two are not alternatives.
    """
    info = link.get("linkinfo") or {}
    kind = info.get("info_kind")
    if kind == "tun":
        return (info.get("info_data") or {}).get("type") or kind
    return kind

# Lookup descriptors double as usage documentation: the collection listing
# and the no-input observation are how both the UI and an agent learn what
# can be asked and how.
LOOKUPS = {
    "route-get": {
        "Question": "Which route does the kernel choose for this destination?",
        "Input": "an IPv4 or IPv6 destination address",
        "Example": "1.1.1.1",
    },
    "resolve": {
        "Question": "What does the resolver answer for this name (or, for an IP address, in reverse)?",
        "Input": "a hostname, or an IP address for a reverse lookup",
        "Example": "host.example.internal",
    },
}

# Safety gate for the D-Bus string, not RFC hostname validation: underscore
# labels (_dmarc.example.com) are legitimate debugging queries.
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,253}$")

# sd-resolved response flags (resolved-def.h): protocol in the low bits,
# SD_RESOLVED_AUTHENTICATED at 1 << 9. Only bits with settled meaning are
# decoded into facts; the raw value stays in evidence.
RESOLVED_AUTHENTICATED = 1 << 9


def _resolve_protocol(flags: int) -> str | None:
    if flags & 0b1:
        return "DNS"
    if flags & 0b110:
        return "LLMNR"
    if flags & 0b11000:
        return "mDNS"
    return None


def _ip_json(args: list[str]) -> list:
    proc = subprocess.run(["ip", "-j", *args], capture_output=True, text=True,
                          timeout=10, check=True)
    return json.loads(proc.stdout or "[]")


def _fdb_json() -> list:
    proc = subprocess.run(["bridge", "-j", "fdb", "show"], capture_output=True,
                          text=True, timeout=10, check=True)
    return json.loads(proc.stdout or "[]")


def _peer_macs_by_port() -> dict[str, list[str]]:
    """Learned unicast MACs per bridge port, from the forwarding database.

    This is what makes a veth attributable. A container's host-side veth is
    named randomly by libnetwork and carries its OWN MAC, not the container's,
    so nothing about the interface identifies the workload. But the bridge
    learns the container's MAC on the port it arrived through, and Docker
    reports that same MAC per attached container — so the fdb is the join, and
    it needs no privilege and no netns entry.

    Deliberately excluded: `self` and `permanent` entries (the bridge's and
    each port's own addresses, which would attribute a port to itself) and
    group addresses, identified by the multicast bit in the first octet.

    The table is LEARNED and ages out, so a container that has sent nothing
    recently simply has no entry. That is why the caller must treat a missing
    MAC as "cannot say" and fall back to naming the network — an absent entry
    is silence, not evidence that nothing is there.
    """
    by_port: dict[str, list[str]] = {}
    for entry in _fdb_json():
        port, mac = entry.get("ifname"), entry.get("mac")
        master = entry.get("master")
        if not port or not mac or not master or port == master:
            continue
        flags = entry.get("flags") or []
        if "self" in flags or entry.get("state") == "permanent":
            continue
        try:
            if int(mac.split(":")[0], 16) & 1:      # group/multicast address
                continue
        except ValueError:
            continue
        by_port.setdefault(port, []).append(mac)
    return by_port


def _lldp_json() -> dict:
    proc = subprocess.run(["networkctl", "lldp", "--json=short"], capture_output=True,
                          text=True, timeout=10, check=True)
    return json.loads(proc.stdout or "{}")


def _nft_json() -> dict:
    proc = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True,
                          text=True, timeout=10, check=True)
    return json.loads(proc.stdout or "{}")


def _tailscale_snapshot() -> tuple[dict, float] | None:
    """The root collector's `tailscale status --json` snapshot (and its
    write time), if the module's grantTailscaleAccess timer is running
    (see nix/module.nix)."""
    path = Path(TAILSCALE_SNAPSHOT)
    try:
        return json.loads(path.read_text()), path.stat().st_mtime
    except (OSError, ValueError):
        return None


def parse_resolv_conf(text: str) -> dict:
    """resolv.conf(5) into facts, by the file's own grammar.

    glibc semantics kept faithfully where they surprise: later `search`
    (or deprecated `domain`) lines REPLACE earlier ones, while `options`
    accumulate; comments open with # or ;. Nameservers are reported in
    file order, all of them — the glossary carries the caveat that glibc
    uses only the first three.
    """
    nameservers: list[str] = []
    search: list[str] = []
    options: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        keyword, _, rest = line.partition(" ")
        args = rest.split()
        if keyword == "nameserver" and args:
            nameservers.append(args[0])
        elif keyword in ("search", "domain") and args:
            search = args
        elif keyword == "options" and args:
            options.extend(args)
    return {"Nameservers": nameservers, "SearchDomains": search,
            "Options": options}


def peer_native_id(peer: dict) -> str | None:
    """A tailnet peer's native id: the DNS label, not the display name.

    The coordination map's DNSName carries the tailnet's own canonical
    machine name ("henrys-macbook-pro…"), already lowercase and
    whitespace-free — it is the identity `tailscale status` itself prints.
    HostName is the peer's self-reported display name, free text in every
    sense: a stock Mac calls itself "Henry's MacBook Pro", which put a space
    and a typographic apostrophe inside an object id whose grammar is
    `^[a-z][a-z0-9-]*:\\S+$` — live on every deployed host with the grant
    (found by the live check the day it was written, 2026-08-12), and
    unstable identity besides, since renaming the laptop would re-key the
    object (rule 7). HostName stays as a fact and never becomes an id: a
    peer the coordination map gives no DNS label is skipped by the caller,
    which is one fewer id shape in the world than patching free text into
    the grammar — review verdict over the first draft's sanitising fallback.
    Module-level and pure so conformance can exercise the derivation
    without a tailscaled snapshot.
    """
    return (peer.get("DNSName") or "").split(".")[0] or None


def _epoch_iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key_expiry(raw) -> tuple[str | None, int | None]:
    """Self.KeyExpiry → (normalised UTC ISO, whole days until expiry). The
    days are computed here so the expiry rule stays clockless (rules never
    read clocks). Tagged nodes' keys do not expire: the field is absent or
    Go's zero time — either way (None, None), never a verdict."""
    if not isinstance(raw, str):
        return None, None
    try:
        expiry = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if expiry.year <= 1:  # Go zero time: no expiry
            return None, None
        days = int((expiry - datetime.now(timezone.utc)).total_seconds() // 86400)
    except (TypeError, ValueError):
        return None, None
    return expiry.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), days


def _nonzero_time(raw) -> str | None:
    """Go stamps "never" as the zero time (0001-01-01T00:00:00Z); passed
    through raw, any future age arithmetic would read two millennia of
    staleness (audit 2026-08-10). Null carries the same meaning honestly."""
    if not isinstance(raw, str):
        return None
    try:
        if datetime.fromisoformat(raw.replace("Z", "+00:00")).year <= 1:
            return None
    except ValueError:
        return None
    return raw


def _addr_str(entry) -> str | None:
    """Render a resolve1 address payload (base64 marker or raw byte list)."""
    raw: bytes | None = None
    if isinstance(entry, dict) and "__bytes_base64__" in entry:
        raw = base64.b64decode(entry["__bytes_base64__"])
    elif isinstance(entry, (bytes, bytearray)):
        raw = bytes(entry)
    elif isinstance(entry, list) and entry and all(isinstance(b, int) for b in entry):
        raw = bytes(entry)
    if raw is None or len(raw) not in (4, 16):
        return None
    family = socket.AF_INET if len(raw) == 4 else socket.AF_INET6
    return socket.inet_ntop(family, raw)


def _server_addr(struct_entry) -> str | None:
    """Address from a resolve1 server struct; the address is the last-ish
    byte field regardless of the struct arity (Manager (iiay) vs Link (iay))."""
    if not isinstance(struct_entry, (list, tuple)):
        return None
    for field in reversed(struct_entry):
        addr = _addr_str(field)
        if addr:
            return addr
    return None


# lo is ifindex 1 by kernel construction: it is the first interface every
# netns registers.
_LOOPBACK_IFINDEX = 1


def global_dns_servers(entries: list) -> list[str]:
    """System-scope servers from Manager.DNS's (ifindex, family, addr)
    structs: ifindex 0 (the classic global scope) OR the loopback link.

    The loopback half is a measured systemd-261 behaviour, not a guess: a
    host whose resolved.conf plainly says `DNS=127.0.0.1 ::1` presented
    those servers with ifindex 1 in BOTH Manager.DNS and DNSEx (raw
    busctl probe, estate host, 2026-08-13) while resolvectl still filed
    them under "Global" — so an ifindex-0 filter reported empty globals
    and the fallback-carries-default rule fired a false warn on a host
    running a deliberate local recursive resolver. Servers homed on lo
    are system-scope by construction either way: loopback is not a
    network, so there is no per-link narrowing for them to mean."""
    return [addr for entry in entries
            if isinstance(entry, (list, tuple)) and len(entry) == 3
            and entry[0] in (0, _LOOPBACK_IFINDEX)
            and (addr := _server_addr(entry))]


# ── listening sockets ────────────────────────────────────────────────
#
# The question an operator arrives with on an internet-facing host is "what is
# listening, and who can reach it". This collection answers the first half; the
# firewall answers the second, and port-exposure below joins them. Splitting
# them this way is not a decomposition anyone here invented: ufw's `show
# listening` has presented sockets first and the rules bearing on each socket
# second for years, and GCP, Azure and AWS each independently built a derived
# per-interface view for the same reason — a rule list is evidence for the
# answer, never the answer.
#
# Read from /proc/net, which is world-readable, so this needs no privilege at
# all. What it CANNOT do without privilege is name the process behind a socket:
# that join goes through /proc/<pid>/fd, which is readable only by the process
# owner, and this agent runs as a DynamicUser. The uid is carried instead —
# it is in /proc/net itself and it already separates a root listener from a
# service one — and the absent half says why it is absent rather than being
# quietly dropped.
PROC_NET = "/proc/net"
LISTENING_REFERENCE = [
    "ss -lntu",
    "ss -lntup   # adds the process, and needs privilege this agent does not hold",
    "cat /proc/net/tcp", "cat /proc/net/tcp6",
    "cat /proc/net/udp", "cat /proc/net/udp6",
]

# /proc/net/tcp's st column. 0A is LISTEN; a UDP socket has no listen state, so
# a bound unconnected one (07) is the equivalent "accepting traffic" reading.
TCP_LISTEN = "0A"
UDP_UNCONNECTED = "07"

# Why a process cannot be named here, stated once and carried on every row that
# wants it. Named after the grant that would change the answer, the way every
# other declined capability in this adapter is.
LISTENING_NOTES = [
    "Sockets only. What may REACH them is the ruleset's answer, and this"
    " collection deliberately makes no claim about it — a socket on the"
    " wildcard address is not an exposed one until a rule admits it.",
    "No process is named on any row. That join reads /proc/<pid>/fd, which"
    " only the owning user may open, and this agent runs as a DynamicUser;"
    " the uid on each row is what /proc/net itself carries.",
]

PROCESS_UNOBSERVABLE = (
    "the listening process cannot be named from this agent: the socket-inode to"
    " process join reads /proc/<pid>/fd, which only the owning user may open,"
    " and the agent runs as a DynamicUser. The uid beside this fact is from"
    " /proc/net itself and is what can be said without that privilege."
)


def _read_text(path: str) -> str | None:
    """One /proc file, or None where it will not open. Every read here goes
    through this rather than calling open() directly: the reference-command
    lint resolves paths through a reviewed table of reader helpers, and a bare
    open() is invisible to it."""
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return None


def _hex_addr(raw: str) -> str | None:
    """/proc/net's address encoding: 32-bit words in HOST byte order, printed
    big-endian-looking. Getting this wrong silently produces plausible
    addresses — 0100007F reads as 1.0.0.127 rather than 127.0.0.1 — so it is
    decoded word-wise rather than by reversing the whole string, which is the
    form that also happens to be correct for IPv6's four words."""
    try:
        if len(raw) == 8:
            packed = int(raw, 16).to_bytes(4, "little")
            return socket.inet_ntop(socket.AF_INET, packed)
        if len(raw) == 32:
            words = [int(raw[i:i + 8], 16).to_bytes(4, "little")
                     for i in range(0, 32, 8)]
            return socket.inet_ntop(socket.AF_INET6, b"".join(words))
    except (ValueError, OSError):
        return None
    return None


def _family_of(destination: str) -> str | None:
    """The address family a route's destination is in, or None where the
    destination names no address (`default`, and anything unparseable).

    Read from the row so the label cannot contradict the address printed
    beside it — the failure that made this necessary was a Family fact
    derived from which subprocess the row arrived in.
    """
    try:
        return f"ipv{ipaddress.ip_network(destination, strict=False).version}"
    except ValueError:
        return None


def _proc_net_readable() -> bool:
    """Whether ANY of the four tables opens. All four failing is a different
    condition from all four being empty, and only one of them means this host
    is not listening for anything."""
    return any(_read_text(f"{PROC_NET}/{name}") is not None
               for name in ("tcp", "tcp6", "udp", "udp6"))


def _listening_scope(address: str) -> str:
    """What an address binding says about reach, in the words an operator
    would use. This is the fact the firewall question hangs off: a socket on
    the wildcard is reachable from wherever the ruleset allows, and one on
    loopback is reachable from nowhere off the host whatever the ruleset says.
    """
    if address in ("0.0.0.0", "::"):
        return "all-interfaces"
    if address.startswith("127.") or address in ("::1",):
        return "loopback"
    return "specific-address"


def _read_proc_net(name: str) -> tuple[list[dict], str | None]:
    """One /proc/net table's listening rows, or (partial, why-not)."""
    text = _read_text(f"{PROC_NET}/{name}")
    if text is None:
        return [], f"{PROC_NET}/{name} could not be read"
    wanted = TCP_LISTEN if name.startswith("tcp") else UDP_UNCONNECTED
    rows = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10 or fields[3] != wanted:
            continue
        local, _, port = fields[1].rpartition(":")
        address = _hex_addr(local)
        if address is None:
            continue
        try:
            rows.append({"Protocol": name, "LocalAddress": address,
                         "LocalPort": int(port, 16), "Uid": int(fields[7]),
                         "SocketInode": int(fields[9])})
        except ValueError:
            continue
    return rows, None


# ── nftables rules, one row each ─────────────────────────────────────
#
# The table-grained collection above counts rules and cannot say what one
# permits, which on a host whose whole posture is its ruleset means deleting
# the single rule confining sshd to one interface moves a count and changes
# nothing else. This collection is the rule itself.
#
# THE RENDERING DISCIPLINE, and it is the whole design. nftables' JSON
# grammar is wide, and it grows: measured against the emitter, the published
# man page omits flow, last, reset, tproxy, synproxy, secmark, ipsec, tunnel
# and ip option. A renderer that silently skipped a term it did not know
# would print `accept tcp dport 22` for a rule whose real text also says
# `iifname tailscale0` — not a smaller truth but the opposite claim, on the
# one surface where being confidently wrong is worst. Every shipped nftables
# exporter surveyed makes exactly that mistake; the two most popular never
# read `match.op` at all, so `ip saddr != 10.0.0.0/8` exports identically to
# its inverse.
#
# So ignorance is COMPUTED rather than assumed. Coverage is a data structure,
# not scattered branches: what the renderer consumed is subtracted from the
# rule's own expr array and whatever is left is the residue, carried on the
# row. That turns "an expression I did not understand" from an unobservable
# event into a per-row fact — which nobody in the survey does, and which is
# the only mechanism that makes this collection's ignorance measurable.
#
# And a term that cannot be expanded is rendered AT ITS POSITION rather than
# dropped, which is nft's own convention (`xt match "conntrack"`). The reader
# sees a rule of the right shape with an opaque slot in it, which cannot be
# confused with a rule that never carried that term. Omission inverts; a
# placeholder is structurally safe.

# Statements this renderer can state the meaning of. Anything outside this
# set becomes residue — deliberately a literal table rather than a series of
# isinstance checks, so "what do we cover" is answerable by reading one line.
RENDERED_STATEMENTS = frozenset({
    "match", "counter", "accept", "drop", "reject", "return",
    "jump", "goto", "continue", "log", "limit", "comment",
})
# The verdicts a rule can end in. `jump`/`goto` are verdicts too but they
# transfer control rather than deciding, which is why they are named
# separately wherever a decision is being claimed.
TERMINAL_VERDICTS = ("accept", "drop", "reject", "return", "continue", "queue")

# Left-hand sides of a match this renderer can name. Everything else — fib,
# socket, rt, osf, numgen, and whatever the next kernel adds — is residue.
RENDERED_MATCH_KEYS = frozenset({"payload", "meta", "ct"})

NFT_CHAIN_REFERENCE = [
    "nft list chains",
    "nft -a list ruleset            # chain handles and hooks",
    "nft list chain <family> <table> <chain>",
]

NFT_CHAIN_NOTES = [
    "A base chain is registered against a netfilter hook and every packet on"
    " that path enters it; a regular chain runs only when something jumps or"
    " gotos to it. The distinction decides whether any rule inside is reached"
    " at all, so it is the first thing on the row rather than a detail.",
    "JumpedFrom is derived by reading every rule in every table — and the"
    " elements of every named verdict map a rule uses — not from the chain's"
    " own document: nft's JSON does not say what calls a chain, and it is"
    " the fact that makes a large ruleset navigable.",
    "Rules are COUNTED here, never read. A chain of narrow accepts and a"
    " chain that admits everything are indistinguishable in this collection;"
    " nft-rules holds what each rule says, and port-exposure answers what"
    " actually reaches a listening port.",
]

NFT_RULE_REFERENCE = [
    "nft -a list ruleset            # the same rules, with '# handle N'",
    "nft -j list ruleset",
    "nft list chain <family> <table> <chain>",
    "iptables-nft -S                # renders the xt rules this cannot",
]

NFT_RULE_NOTES = [
    "One row per rule, keyed by the kernel's own handle. A handle is stable"
    " for the life of the rule object and is the right join key WITHIN a"
    " snapshot; a flush-and-restore makes new objects with new handles, so it"
    " is not a durable identity across a ruleset reload.",
    "Comprehension is computed, not assumed: the statements this renderer"
    " consumed are subtracted from the rule's own expression list, and"
    " anything left is carried as Residue. A row marked partial or opaque is"
    " one whose rendered text is thinner than the rule.",
    "An xt statement is an xtables extension called through the compat layer."
    " nft's JSON carries the extension's NAME and none of its parameters, so"
    " the conditions of such a rule are absent from the document rather than"
    " merely unparsed. iptables-nft -S renders them.",
]



def _render_match(match: dict) -> tuple[str | None, bool]:
    """(text, understood) for one match statement.

    Negation is rendered INSIDE the text rather than carried beside it as a
    flag. A separate `negated` boolean is ignorable, and it will be ignored —
    by a consumer selecting one column, by grep, by a model summarising a
    table — and the value it modifies reads as its own opposite when it is
    (osquery renders the same way, and the popular nftables exporters, which
    never read `match.op` at all, are the counter-example).
    """
    left, op, right = match.get("left"), match.get("op", "=="), match.get("right")
    if not isinstance(left, dict) or len(left) != 1:
        return None, False
    key = next(iter(left))
    # A masked comparison — nft writes `meta mark & 0xff0000 == 0x40000` and
    # its JSON nests the masked expression under "&". Tailscale writes every
    # one of its forward rules this way, so declining it left two rules per
    # host reading `<unrendered &> counter accept`: a mark test rendered as
    # an unconditional accept, which is the inversion this renderer exists to
    # prevent. The mask is part of the condition and is kept.
    mask = None
    if key == "&" and isinstance(left[key], list) and len(left[key]) == 2:
        inner_expr, mask = left[key]
        if not isinstance(inner_expr, dict) or len(inner_expr) != 1:
            return None, False
        left = inner_expr
        key = next(iter(left))
    if key not in RENDERED_MATCH_KEYS:
        return None, False
    inner = left[key]
    if key == "payload" and isinstance(inner, dict):
        name = f"{inner.get('protocol')} {inner.get('field')}"
    elif isinstance(inner, dict):
        name = f"{key} {inner.get('key')}"
    else:
        return None, False
    if mask is not None:
        if not isinstance(mask, int):
            return None, False
        # Hex, because that is how a mask is written and read — 0xff0000 is
        # recognisable as the third byte where 16711680 is arithmetic.
        name = f"{name} & {hex(mask)}"
    if isinstance(right, dict):
        if "prefix" in right and isinstance(right["prefix"], dict):
            value = f"{right['prefix'].get('addr')}/{right['prefix'].get('len')}"
        elif "set" in right and isinstance(right["set"], list):
            # An ANONYMOUS set carries its elements right here, so rendering
            # it as "{ ... }" would claim full comprehension while hiding the
            # membership that decides what the rule matches. A NAMED set
            # (@ports) is a reference whose membership is a separate object
            # and arrives as a plain string — the name is then what the rule
            # genuinely says, and is rendered as itself below.
            elements = []
            for element in right["set"]:
                if isinstance(element, (str, int)):
                    elements.append(str(element))
                elif (isinstance(element, dict)
                      and isinstance(element.get("range"), list)
                      and len(element["range"]) == 2):
                    lo, hi = element["range"]
                    elements.append(f"{lo}-{hi}")
                else:
                    return None, False
            value = "{ " + ", ".join(elements) + " }"
        else:
            return None, False
    elif isinstance(right, (str, int)):
        value = str(right)
    else:
        return None, False
    return f"{name} {'!= ' if op == '!=' else ''}{value}", True


def _render_rule(expr: list) -> dict:
    """A rule's text, its verdict, and the exact expressions not consumed.

    The residue is the point. Every statement is either rendered or recorded,
    and the two together account for the whole list — so a row can never be
    thinner than the rule without saying so.
    """
    parts: list[str] = []
    residue: list = []
    verdict = None
    jump_target = None
    packets = bytes_ = None
    opaque_reason = None
    for statement in expr:
        if not isinstance(statement, dict) or len(statement) != 1:
            # nft emits a bare string where it has no JSON encoder for an
            # expression, running its own text printer into a buffer instead.
            # The type change is the signal, and it is the one construct that
            # arrives already rendered — so it is kept verbatim and flagged.
            if isinstance(statement, str):
                parts.append(statement)
                opaque_reason = opaque_reason or "text-fallback"
                residue.append(statement)
                continue
            residue.append(statement)
            continue
        verb = next(iter(statement))
        body = statement[verb]
        if verb == "xt" and isinstance(body, dict):
            # nft's own convention, kept: the term appears at its position so
            # the rule keeps its shape, and the reader can see that a
            # condition exists whose content is not in this document.
            parts.append(f'xt {body.get("type")} "{body.get("name")}"')
            opaque_reason = "xt"
            residue.append(statement)
            continue
        if verb not in RENDERED_STATEMENTS:
            parts.append(f"<unrendered {verb}>")
            residue.append(statement)
            continue
        if verb == "match" and isinstance(body, dict):
            text, understood = _render_match(body)
            if understood and text:
                parts.append(text)
            else:
                # AT ITS POSITION, which is the whole discipline. Dropping an
                # unrendered condition from the text turns `fib oif lo accept`
                # into `accept` — a narrow rule reading as an unconditional
                # one, which is the inversion this collection exists to make
                # impossible. The residue below records it too, but the
                # placeholder is what a human reading the line sees.
                left = body.get("left")
                key = next(iter(left)) if isinstance(left, dict) and left else "expr"
                parts.append(f"<unrendered {key}>")
                residue.append(statement)
            continue
        if verb == "counter":
            if isinstance(body, dict):
                packets, bytes_ = body.get("packets"), body.get("bytes")
            parts.append("counter")
            continue
        if verb in ("jump", "goto"):
            jump_target = body.get("target") if isinstance(body, dict) else None
            parts.append(f"{verb} {jump_target}")
            continue
        if verb in TERMINAL_VERDICTS:
            verdict = verb
            parts.append(verb)
            continue
        parts.append(verb)
    return {"text": " ".join(parts), "residue": residue, "verdict": verdict,
            "jump_target": jump_target, "packets": packets, "bytes": bytes_,
            "opaque_reason": opaque_reason}


def _verdict_targets(node: object) -> list[str]:
    """Every chain this expression tree can hand control to, in document
    order, each named once.

    The WHOLE tree, not the top-level statements. nftables nests verdicts
    inside expression bodies — a ct-state verdict map carries its jumps two
    levels down, in the map's data — and the distribution firewall this
    product most often reads opens its input chain with exactly that shape.
    A discovery that iterated only the surface published the chain holding
    every inbound accept as Unreferenced, and the wrong answer went into the
    corpus as expected, where it rejected two independently written correct
    collectors (DESIGN 20). Generic descent over dicts and lists covers any
    verdict nested anywhere in the tree this function is GIVEN — and only
    that tree. A NAMED verdict map is the shape this cannot see: the rule
    dispatching through `vmap @dispatch` carries just the string, and the
    jumps live in the top-level map OBJECT's elem list, which no rule
    expression contains. Whoever holds the whole document must feed that
    elem list in separately; the chains derivation does.

    Both verbs, because both reach the chain. goto differs from jump in
    where it RETURNS to, not in whether it arrives — counting only jumps
    would report a goto-only chain as unreachable, which is the one fact
    here somebody would act on.

    Each target once: a vmap routing two ct states to one chain reaches it
    twice at runtime but references it once, and a caller walking the graph
    must not visit — or report — the same subtree per key that names it.
    """
    found: list[str] = []

    def descend(node: object) -> None:
        if isinstance(node, dict):
            for verb in ("jump", "goto"):
                body = node.get(verb)
                if (isinstance(body, dict) and body.get("target")
                        and body["target"] not in found):
                    found.append(body["target"])
            for value in node.values():
                descend(value)
        elif isinstance(node, list):
            for value in node:
                descend(value)

    descend(node)
    return found


def _map_references(node: object) -> set[str]:
    """Every named set or map this expression tree consults, @ stripped.

    "@name" is the one spelling libnftables-json has for such a reference,
    wherever the grammar lets one appear — a vmap or map lookup holds it in
    "data", a match against a named set in "right" — so collecting @-strings
    generically is the same no-recurrence choice as _verdict_targets'
    descent: the next expression that can consult a named object is covered
    without being foreseen. Names only, deliberately: which of them is a
    verdict map, and what its elements do, is a join the caller makes
    against the document's own map objects — this function must not decide.
    """
    found: set[str] = set()

    def descend(node: object) -> None:
        if isinstance(node, str):
            if node.startswith("@"):
                found.add(node[1:])
        elif isinstance(node, dict):
            for value in node.values():
                descend(value)
        elif isinstance(node, list):
            for value in node:
                descend(value)

    descend(node)
    return found


# ── port exposure: the socket, and the rules that admit it ───────────
#
# The derived collection, and the one that answers the question. Three cloud
# vendors and one unfashionable CLI converged on this shape independently:
# ufw's `show listening` puts the socket first with the rules bearing on it
# beneath, and GCP, Azure and AWS each built a per-interface effective view
# because a rule list did not answer "what can reach this". The rule list is
# evidence; the socket is the row.
#
# TWO ANSWERS, NOT ONE, and this is what makes it safe. Taken from Diekmann's
# machine-checked iptables semantics: replace what cannot be decided with
# Unknown, then compute an under- and an over-approximation. Certain treats
# every unrendered clause as NON-matching, so a rule this adapter does not
# fully understand contributes nothing to it; Possible treats the same clause
# as always matching. If the certain answer names tailscale0, that is a claim
# this product can defend. If the two differ, the gap is the headline rather
# than a footnote.
#
# The direction of failure is a property of the construction rather than a
# discipline someone has to remember: an unparsed clause can never STRENGTHEN
# the certain answer, so the worst case is "certainly admitted from nowhere I
# can prove, possibly from anywhere" — under-claiming, loudly.
#
# WHAT THIS DOES NOT DO, stated here and in the envelope because omitting it
# would rebuild the exact firewalld/Docker trap this product exists to avoid:
# it follows the INPUT path only. A container's published port is DNAT'd in
# prerouting and admitted in forward, so it is not covered. It does not
# resolve shadowing — an earlier drop that would pre-empt a later accept is
# listed, not applied — and it does not model conntrack, so the near-universal
# `ct state established,related accept` at the top of a chain is not treated
# as the shortcut it is. Consequently nothing here says "reachable". The
# honest ceiling for a static read is "this rule admits it, and no other rule
# does", and the next question belongs to `nft monitor trace`, which this
# product cannot arm because arming a trace is a write.
INPUT_HOOKS = ("input",)
# A jump chain can jump onward; the bound stops a cycle turning a page render
# into a hang, and a chain graph deeper than this is not something a static
# reader should be claiming to have followed anyway.
CHAIN_WALK_MAX_DEPTH = 8

EXPOSURE_REFERENCE = [
    "ss -lntu",
    "nft -a list ruleset",
    "nft list chain <family> <table> <chain>",
    "nft monitor trace   # the live answer this static read cannot give",
]

EXPOSURE_NOTES = [
    "INPUT PATH ONLY. A container's published port is translated in"
    " prerouting and admitted in forward, so it is not covered here — a"
    " socket that looks unadmitted may still be reachable through a"
    " published port, and this collection will not say so.",
    "Shadowing is not resolved: rules are listed in evaluation order, and an"
    " earlier drop that would pre-empt a later accept is shown rather than"
    " applied. Connection tracking is not modelled either.",
    "Two deliberate under-claims. A rule's address family must match the"
    " socket's, so an ip-family rule is not credited to a tcp6 socket even"
    " though a dual-stack socket bound to :: does receive IPv4-mapped"
    " traffic; and a match this adapter can read but not model — a negated"
    " port, a mark, a ct state — costs the rule its place in the certain"
    " answer rather than being treated as absent.",
    "Nothing here claims reachability. AdmittedFromCertain names the source"
    " constraints of rules that admit this socket and that were rendered in"
    " full; AdmittedFromPossible additionally treats every clause this"
    " adapter could not read as matching. Where they differ, the ruleset"
    " contains something this observer cannot interpret.",
]



def _input_chains(document: dict) -> dict:
    """{(family, table, chain): policy} for every base chain on the input
    hook. A rule only decides an inbound packet if control reaches it, and
    control starts at a base chain — so this is where the walk begins and
    anything unreachable from here is not on the input path at all."""
    found = {}
    for entry in document.get("nftables", []):
        chain = entry.get("chain") if isinstance(entry, dict) else None
        if isinstance(chain, dict) and chain.get("hook") in INPUT_HOOKS:
            found[(chain.get("family"), chain.get("table"),
                   chain.get("name"))] = chain.get("policy")
    return found


def _rules_by_chain(document: dict) -> dict:
    out: dict = {}
    for entry in document.get("nftables", []):
        rule = entry.get("rule") if isinstance(entry, dict) else None
        if isinstance(rule, dict):
            out.setdefault((rule.get("family"), rule.get("table"),
                            rule.get("chain")), []).append(rule)
    return out


def _walk_input_path(document: dict) -> list[tuple[dict, list]]:
    """Every rule reachable from an input base chain, in evaluation order,
    WITH the conditions guarding it.

    Jumps are followed because the estate's own firewalls are built out of
    them — a NixOS host's input chain is a jump to nixos-fw and nothing else,
    so a walk that stopped at base chains would report that no rule admits
    anything.

    The guarding conditions are carried, and getting this wrong is the
    dangerous direction. NixOS admits a port by jumping to nixos-fw-accept
    under `iifname tailscale0 tcp dport 22`, and nixos-fw-accept holds a bare
    `counter accept` with no conditions of its own. A walk that flattened the
    two would find an unconditional accept and report every port on the host
    as admitted from anywhere — the exact inversion this collection exists to
    prevent, arriving through the path instead of through the renderer.
    Measured against a live single-purpose cloud host's ruleset, 2026-08-13.

    Cycles and depth are bounded; a chain already on the current path is not
    re-entered, which is conservative in the right direction — it can only
    shorten the list, and a shorter list can only narrow the certain answer.
    """
    by_chain = _rules_by_chain(document)
    ordered: list[tuple[dict, list]] = []

    def walk(key, depth, seen, guards):
        if depth > CHAIN_WALK_MAX_DEPTH or key in seen:
            return
        seen = seen | {key}
        for rule in by_chain.get(key, []):
            expr = rule.get("expr") or []
            ordered.append((rule, guards))
            for target in _verdict_targets(expr):
                # Everything in the target chain runs only if this rule
                # matched, so its conditions guard the whole subtree.
                # EVERY statement of the jumping rule, not only the ones
                # this renderer understands. Keeping just the readable
                # matches turns an opaque guard into NO guard: a live host's
                # `xt match "conntrack" jump nixos-fw-accept` then made the
                # bare accept inside look unconditional, and every port on
                # the host reported "certainly admitted from anywhere" — the
                # inversion again, arriving through the path rather than the
                # renderer. Carrying the whole expression means the residue
                # travels with it and the descendant can never be certain.
                #
                # Only a BARE top-level jump/goto is dropped from the guards:
                # it is control transfer with no matching content of its own.
                # A statement that nests its verdict — a ct-state vmap — IS
                # the dispatch condition, so it stays, and it stays as
                # residue: a vmap-dispatched subtree can therefore never
                # reach the certain answer, which is under-claiming, loudly.
                walk((key[0], key[1], target), depth + 1,
                     seen, guards + [st for st in expr
                                     if not (isinstance(st, dict)
                                             and ("jump" in st or "goto" in st))])

    for key in _input_chains(document):
        walk(key, 0, frozenset(), [])
    return ordered


# Every match term this renderer can render is classified as exactly one of
# these, and the classification is what the closure below consults. It exists
# because the ICMP defect was not a parsing failure — the renderer understood
# `meta l4proto ipv6-icmp` perfectly and printed it — it was a COVERAGE
# MISMATCH: a term the renderer knew about that the closure silently ignored,
# so a rule constraining protocol read as a rule constraining nothing.
#
#   destination  narrows WHAT is reached (protocol, destination port), and so
#                decides whether a rule bears on a given socket at all.
#   source       narrows WHERE FROM, and so is the answer this collection
#                reports rather than a filter on it.
#   other        a real constraint that is neither — ct state, marks, rate
#                limits. Renderable, reported in the text, and NOT modelled.
#
# `other` is why this table is the safety property rather than bookkeeping: a
# term nobody classified must make a rule uncertain, never invisible. Adding a
# renderable shape without deciding which of the three it is now fails a
# conformance test instead of quietly widening the certain answer.
def _classify_match(match: dict) -> str | None:
    """"destination", "source", "other", or None where the term is not
    renderable at all (which the residue already accounts for)."""
    text, understood = _render_match(match)
    if not understood or not text:
        return None
    left = match.get("left")
    if not isinstance(left, dict) or not left:
        return None
    key = next(iter(left))
    inner = left[key] if isinstance(left[key], dict) else {}
    if key == "payload":
        field = inner.get("field")
        if field in ("dport", "protocol"):
            return "destination"
        if field in ("saddr",):
            return "source"
        return "other"
    if key == "meta":
        meta_key = inner.get("key")
        if meta_key == "l4proto":
            return "destination"
        if meta_key in ("iifname", "iif", "iifgroup", "iifkind"):
            return "source"
        return "other"
    return "other"


# Which address families can carry a socket's traffic. A rule in an `ip`
# table decides nothing about an IPv6 packet and vice versa, and crediting one
# with the other is a whole table's worth of rules landing on the wrong
# sockets — measured as ip6-only accepts certainly admitting IPv4 sockets.
# arp, bridge and netdev carry no IP traffic on the input path at all.
_SOCKET_FAMILIES = {"tcp": ("ip", "inet"), "udp": ("ip", "inet"),
                    "tcp6": ("ip6", "inet"), "udp6": ("ip6", "inet")}


def _family_bears_on(family: object, protocol: str) -> bool:
    """Whether a rule in this table's family can decide this socket at all.

    A dual-stack socket bound to :: does also receive IPv4-mapped traffic,
    which this does NOT model — an ip-family rule is not credited to a tcp6
    socket. That under-claims rather than over-claims, which is the only
    direction this collection is allowed to be wrong in, and it is stated in
    the collection's notes rather than left for a reader to discover.
    """
    return str(family) in _SOCKET_FAMILIES.get(protocol, ())


def _port_values(right: object) -> set[int] | None:
    """The ports a dport match admits, or None where the shape is unreadable.

    Ranges are the case that mattered. The RENDERER understands a range inside
    an anonymous set and prints `tcp dport { 8000-8100 }` with no residue, so
    a closure that extracted only the integers silently dropped the whole
    constraint — and an empty port set reads as "no port constraint", which
    made one range rule admit every port on the host, certainly, from
    anywhere. Discarding a reading the renderer got right is precisely the
    coverage mismatch _classify_match was introduced to stop.
    """
    if isinstance(right, int):
        return {right}
    if isinstance(right, dict) and isinstance(right.get("set"), list):
        ports: set[int] = set()
        for element in right["set"]:
            if isinstance(element, int):
                ports.add(element)
            elif (isinstance(element, dict)
                  and isinstance(element.get("range"), list)
                  and len(element["range"]) == 2
                  and all(isinstance(x, int) for x in element["range"])):
                low, high = element["range"]
                # Bounded: a rule may legitimately admit 1-65535, and
                # materialising that is fine, but a malformed pair must not
                # turn a page render into an allocation.
                if not 0 <= low <= high <= 65535:
                    return None
                ports.update(range(low, high + 1))
            else:
                return None
        return ports
    return None


def _rule_bears_on(rendered: dict, expr: list, protocol: str,
                   port: int) -> tuple[bool, bool]:
    """(certainly bears on this socket, possibly bears on it).

    "Bears on" is about the DESTINATION — does this rule's port and protocol
    constraint admit traffic to this socket. Source constraints (iifname,
    saddr) are not consulted here: they are the answer, not the filter.

    A rule with an unreadable clause is possible but never certain, which is
    the whole of the lower closure: ignorance cannot strengthen a claim.
    """
    readable = not rendered["residue"]
    # Constraints are INTERSECTED, and the accumulator is per-term rather than
    # one flat list, because a rule reached through a jump carries two sets of
    # them: the guard's and its own. Pooling those unions what should narrow —
    # `tcp dport 22 jump svc` guarding `tcp dport 443 accept` admits neither
    # port, and a single dports list containing both said it admits both.
    port_sets: list[set[int]] = []
    protocol_sets: list[set[str]] = []
    for statement in expr:
        if not isinstance(statement, dict) or "match" not in statement:
            continue
        body = statement["match"]
        # A renderable constraint this closure does not model cannot leave the
        # rule certain: it narrows the traffic in a way nothing here accounts
        # for, so treating it as absent is exactly the inversion.
        if _classify_match(body) == "other":
            readable = False
        left, right = body.get("left"), body.get("right")
        if not isinstance(left, dict):
            continue
        # NEGATION IS AN EXCLUSION, and this closure models inclusions. Reading
        # `tcp dport != 22` as though it said `== 22` turns a rule that admits
        # everything BUT ssh into one that admits only ssh — and the module
        # header calls this out as the mistake every shipped exporter makes,
        # which did not stop it being made here. Rather than model exclusion
        # sets, an inequality costs the rule its certainty: correct, and
        # conservative in the direction that cannot hurt.
        if body.get("op", "==") != "==":
            readable = False
            continue
        # A protocol can be constrained through meta as well as through the
        # packet's own header, and reading only the second credited an
        # ICMP-ONLY accept with admitting tcp/22 from anywhere. Found on a live
        # host, 2026-08-13: `meta l4proto ipv6-icmp counter accept` inside
        # nixos-fw-accept, fully rendered, and therefore CERTAIN — the worst
        # possible place for this to be wrong, because a certain answer is
        # the one an operator is told they can defend.
        if "meta" in left and isinstance(left["meta"], dict):
            if left["meta"].get("key") == "l4proto" and isinstance(right, str):
                protocol_sets.append({right})
            continue
        if "payload" not in left:
            continue
        payload = left["payload"]
        field, proto = payload.get("field"), payload.get("protocol")
        if field == "dport":
            ports = _port_values(right)
            if ports is None:
                readable = False          # a dport shape we cannot read
            else:
                port_sets.append(ports)
            if proto in ("tcp", "udp"):
                protocol_sets.append({proto})
        elif field == "protocol" and isinstance(right, str):
            protocol_sets.append({right})
    wire = protocol.replace("6", "")
    for allowed in protocol_sets:
        if wire not in allowed:
            return False, False           # a different protocol entirely
    for allowed_ports in port_sets:
        if port not in allowed_ports:
            return False, False           # a different port entirely
    # No dport constraint at all means the rule bears on every port, which is
    # what a blanket `iifname lo accept` does and is exactly the case an
    # operator most needs to see.
    return readable, True


def _sources_of(expr: list) -> list[str]:
    """Where a rule admits traffic FROM, in the rule's own words. A rule with
    no source constraint admits from anywhere, and saying so plainly is the
    point — an empty list would read as "no sources", the opposite."""
    sources = []
    for statement in expr:
        if not isinstance(statement, dict) or "match" not in statement:
            continue
        if _classify_match(statement["match"]) != "source":
            continue
        text, _understood = _render_match(statement["match"])
        if text:
            sources.append(text)
    return sources or ["anywhere"]


class Adapter:
    subsystem = "network"

    # A failed probe is retried after this long; success is cached forever.
    # Without the retry a probe racing boot (bus not up, capability not yet
    # granted) pinned "unavailable" into capabilities until agent restart
    # (backlog note, 2026-08-09).
    PROBE_RETRY_SECONDS = 60

    def __init__(self) -> None:
        self._nft_state: tuple[bool, str] | None = None
        self._nft_probed_at: float = 0.0

    def collections(self) -> list[str]:
        return ["links", "routes", "resolver", "listening", "nft-tables",
                "nft-chains", "nft-rules", "port-exposure", "tailscale",
                "lookups"]

    def fact_glossary(self, collection: str) -> dict[str, str]:
        return _NETWORK_GLOSSARY.get(collection, {})

    def fact_kinds(self, collection: str) -> dict[str, str] | None:
        return _NETWORK_KINDS.get(collection)

    async def _nft_available(self) -> tuple[bool, str]:
        stale = (self._nft_state is not None and not self._nft_state[0]
                 and time.monotonic() - self._nft_probed_at > self.PROBE_RETRY_SECONDS)
        if self._nft_state is None or stale:
            self._nft_probed_at = time.monotonic()
            if shutil.which("nft") is None:
                self._nft_state = (False, "nft not on PATH")
            else:
                try:
                    await anyio.to_thread.run_sync(_nft_json)
                    self._nft_state = (True, "")
                except subprocess.CalledProcessError as exc:
                    self._nft_state = (False, env.reason(
                        "nft cannot read the ruleset "
                        f"(CAP_NET_ADMIN not granted?): {exc.stderr}"))
                except Exception as exc:  # noqa: BLE001
                    self._nft_state = (False, env.reason(exc))
        return self._nft_state

    async def _resolver_available(self) -> tuple[bool, str]:
        try:
            await BUS.get_all(RESOLVE1, RESOLVE1_PATH, RESOLVE1_MANAGER)
            return True, ""
        except Exception as exc:  # noqa: BLE001
            return False, env.reason(
                f"resolve1 not available on the system bus: {exc}")

    async def _resolver_mode(self) -> tuple[str | None, str]:
        """Which resolver mechanism this host has: "resolve1", "file", or
        (None, reason). The question is universal and only the answer is not
        — the packages lesson, repeated here after a host that resolves
        names all day through a dhcpcd-written resolv.conf spent its life
        declined because ONE implementation was absent (asked live,
        2026-08-12: "it's still a resolver, just a different path to it")."""
        res_ok, res_reason = await self._resolver_available()
        if res_ok:
            return "resolve1", ""
        if await anyio.to_thread.run_sync(lambda: Path(RESOLV_CONF).is_file()):
            return "file", ""
        return None, env.reason(
            f"{res_reason}; and no {RESOLV_CONF} to read instead")

    async def capability(self) -> dict:
        unavailable: dict[str, str] = {
            "conntrack-summary": "netlink acquisition not yet implemented",
        }
        nft_ok, nft_reason = await self._nft_available()
        if not nft_ok:
            unavailable["nft-tables"] = nft_reason
            unavailable["nft-chains"] = nft_reason
            unavailable["nft-rules"] = nft_reason
        res_mode, res_reason = await self._resolver_mode()
        if res_mode is None:
            unavailable["resolver"] = res_reason
        if await anyio.to_thread.run_sync(_tailscale_snapshot) is None:
            unavailable["tailscale"] = TAILSCALE_UNAVAILABLE
        # A host whose /proc/net cannot be read has not stopped listening.
        # Serving an empty collection there reports a machine accepting no
        # traffic at all, which is the most confident possible way to be
        # wrong about exposure — and the collection had no way to say so,
        # because the fact that names an unreadable table rides on rows and
        # there were none.
        sockets_ok = await anyio.to_thread.run_sync(_proc_net_readable)
        if not sockets_ok:
            unavailable["listening"] = (
                f"none of {PROC_NET}/{{tcp,tcp6,udp,udp6}} could be read, so"
                " what this host is listening on is unobservable rather than"
                " nothing — an empty list here would report a machine"
                " accepting no traffic")
        # The join needs BOTH halves, and it names every half that failed
        # rather than whichever check ran last: a host missing both would
        # otherwise be told about one problem and left to find the other.
        # Declining by name is the difference between "no rule admits this"
        # and "the ruleset was unreadable".
        if not nft_ok or not sockets_ok:
            missing = []
            if not nft_ok:
                missing.append(
                    f"the ruleset could not be read ({nft_reason}), so an"
                    " unadmitted-looking port would be an unread ruleset"
                    " rather than a closed one")
            if not sockets_ok:
                missing.append(
                    "the listening sockets this joins against could not be"
                    f" read from {PROC_NET}, so there is nothing to attribute"
                    " a rule to")
            unavailable["port-exposure"] = "; and ".join(missing)
        collections = [c for c in self.collections() if c not in unavailable]
        return {"available": True, "collections": collections,
                "unavailable_collections": unavailable}

    # ── links ────────────────────────────────────────────────
    async def _lldp_by_link(self) -> dict[str, list[dict]]:
        """LLDP neighbours per interface via networkctl --json (networkd's
        capture; empty where nothing on the segment emits LLDP)."""
        try:
            raw = await anyio.to_thread.run_sync(_lldp_json)
        except Exception:  # noqa: BLE001 - no networkd or no capture => no facts
            return {}
        by_link: dict[str, list[dict]] = {}
        for n in raw.get("Neighbors") or []:
            ifname = n.get("InterfaceName")
            for neighbor in n.get("Neighbors") or []:
                by_link.setdefault(ifname, []).append({
                    "SystemName": neighbor.get("SystemName"),
                    "PortDescription": neighbor.get("PortDescription") or neighbor.get("PortID"),
                    "ChassisID": neighbor.get("ChassisID"),
                })
        return by_link

    async def _link_items(self) -> list[dict]:
        raw = await anyio.to_thread.run_sync(_ip_json, ["-d", "addr", "show"])
        lldp = await self._lldp_by_link()
        # Learned MACs per bridge port. A failure here must not cost the whole
        # links collection: attribution is an enrichment, and an interface list
        # that works is worth more than one that is complete or nothing.
        try:
            peer_macs = await anyio.to_thread.run_sync(_peer_macs_by_port)
        except Exception:  # noqa: BLE001 - no bridge(8), no bridges, no matter
            peer_macs = {}
        # Enslavement count per master, from the same payload: a bridge with
        # zero members is down by design (the kernel only raises a bridge
        # when a member port is up), and the empty-bridge rule keys on it.
        member_counts: dict[str, int] = {}
        for link in raw:
            if link.get("master"):
                member_counts[link["master"]] = member_counts.get(link["master"], 0) + 1
        items = []
        for link in raw:
            name = link["ifname"]
            facts = {
                "OperState": (link.get("operstate") or "").lower(),
                # See _link_kind. Null on every physical interface and on
                # loopback, because those carry no linkinfo at all — which is
                # why LinkType sits beside it, that being the field the kernel
                # fills in for everything.
                "Kind": _link_kind(link),
                # The kernel's hardware type (ARPHRD), present on every
                # interface: "ether", "loopback", or "none" for a device with no
                # link-layer header at all — a layer-3 tunnel, which is also why
                # such a device has no MAC. Read, never classified: a bridge is
                # "ether" as well, so this is not a physical/virtual
                # discriminator, and folding it into Kind would stop a bridge
                # being distinguishable from its own ports.
                #
                # It earns a column beside Kind by splitting a case Kind cannot.
                # tailscale0 and libvirt's vnet* are both Kind "tun", because one
                # tuntap driver creates both — but /sys/class/net/*/type says
                # tailscale0 is 65534 (ARPHRD_NONE, addr_len 0, a TUN carrying
                # bare IP) while vnet* are 1 (ARPHRD_ETHER, real MACs, enslaved
                # to a bridge — TAPs carrying Ethernet frames). Same Kind,
                # different devices; only this fact tells them apart.
                "LinkType": link.get("link_type"),
                "MTU": link.get("mtu"),
                "MACAddress": link.get("address"),
                "Master": link.get("master"),
                "Addresses": [f"{a['local']}/{a['prefixlen']}"
                              for a in link.get("addr_info", []) if "local" in a],
            }
            # Where the device physically is. Omitted rather than nulled,
            # because only a device on a bus has one: absence is "this is not
            # backed by hardware", a statement, not a gap (SPEC §2 rule 7). It
            # is also the join key to hardware/pci, which is why the raw address
            # is kept exactly as the kernel spells it.
            if link.get("parentdev"):
                facts["ParentBus"] = link.get("parentbus")
                facts["ParentDev"] = link["parentdev"]
            # The address burned into the hardware, when it differs from the one
            # in use — the tell that a MAC has been overridden, which otherwise
            # takes a reader to the device to discover.
            if link.get("permaddr") and link.get("permaddr") != link.get("address"):
                facts["PermanentMACAddress"] = link["permaddr"]
            if facts["Kind"] == "bridge":
                facts["BridgeMembers"] = member_counts.get(name, 0)
            # The MAC(s) the bridge has learned behind this port — the join key
            # that names the container on the other end of a veth. Omitted
            # rather than nulled where nothing has been learned: absence here
            # means the port has been quiet, which is not a fact about what is
            # attached (SPEC §2 rule 7).
            if peer_macs.get(name):
                facts["PeerMACAddresses"] = sorted(peer_macs[name])
            if lldp.get(name):
                facts["LLDPNeighbors"] = lldp[name]
            # "up" is the only positively-healthy operstate. The other quiet
            # states are carrier-detection absence (lo/wireguard/tun report
            # "unknown"): no judgment is derivable, so the severity field is
            # omitted rather than drawing a neutral dot two auditors misread
            # as a verdict (audit 2026-08-10). Everything else is neutral
            # unless the rule speaks.
            state = facts["OperState"]
            healthy = "ok" if state == "up" else (
                None if state in LINK_QUIET_STATES else "info")
            items.append(env.item_summary(f"link:{name}", "link", name, facts,
                                          opinions=link_opinions(facts),
                                          healthy=healthy))

        # Enslaved links sit under their master (bridge, bond) the way
        # partitions sit under disks — membership readable from the shape of
        # the list, not just a Master fact three clicks deep.
        by_name = {item["native_id"]: item for item in items}
        children: dict[str | None, list[dict]] = {}
        for item in items:
            master = item["facts"].get("Master")
            children.setdefault(master if master in by_name else None,
                                []).append(item)
        ordered: list[dict] = []

        def walk(item: dict, depth: int) -> None:
            item["depth"] = depth
            ordered.append(item)
            for child in children.get(item["native_id"], []):
                walk(child, depth + 1)

        for root in children.get(None, []):
            walk(root, 0)
        return ordered

    # ── routes ───────────────────────────────────────────────
    async def _route_items(self) -> list[dict]:
        """Every route the kernel holds, in every table — not just main.

        `ip route show` defaults to main, and for a year that is all this
        reported. It made a whole class of fault invisible: a host on a tailnet
        gets policy table 52 consulted at rule preference 5270 while main waits
        until 32766, so an accepted route for a segment the host is ON silently
        outranks its own connected route. That took a site LAN down twice
        on 2026-08-09 and again on 2026-08-11, and on every occasion this
        collection showed a healthy main table and nothing else — the shadowing
        route was not in the envelope at all, so no rule could see it and no
        screen could show it.

        Table and rule precedence together decide which route actually wins, so
        neither is optional. Routes carry their table; the rules are a sibling
        collection because they are per-host policy rather than per-route facts.
        """
        rules = await self._routing_rules()
        main_pref = rules.get("main", 32766)
        raw_by_family = {}
        # `-4` IS LOAD-BEARING, and its absence was not a cosmetic slip.
        # iproute2 only defaults a route dump to AF_INET when a table filter
        # is set, and `table all` unsets it — so this call went out as
        # AF_UNSPEC and the kernel returned BOTH families, every row of which
        # was then stamped with this loop's family. Every IPv6 route was
        # emitted twice: once truthfully, once labelled ipv4. Measured on
        # four live hosts (2026-08-14): on one of them 32 of 54 "ipv4"
        # rows were IPv6, and the two default routes collapsed onto a
        # single object id.
        for family, args in (("ipv4", ["-4", "route", "show", "table", "all"]),
                             ("ipv6", ["-6", "route", "show", "table", "all"])):
            raw_by_family[family] = await anyio.to_thread.run_sync(_ip_json, args)

        # Which destinations this host is DIRECTLY attached to, per family: a
        # kernel-scope link route in main is the definition of "on this
        # segment". A route to the same destination in a table consulted
        # earlier outranks it, and the host stops reaching its own neighbours
        # while ARP still answers — which is why the failure looks like a
        # half-alive host rather than a routing problem.
        connected = {
            family: {r.get("dst") for r in raw
                     if (r.get("table") or "main") == "main"
                     and r.get("scope") == "link" and r.get("dst")}
            for family, raw in raw_by_family.items()
        }

        items = []
        for family, raw in raw_by_family.items():
            for route in raw:
                dst = route.get("dst", "default")
                dev = route.get("dev", "?")
                # iproute2 omits `table` for main; naming it beats an absence a
                # reader has to know the default of.
                table = route.get("table") or "main"
                native = f"{dst} dev {dev}" + (f" via {route['gateway']}" if route.get("gateway") else "")
                if table != "main":
                    native += f" table {table}"
                facts = {
                    "Destination": dst, "Gateway": route.get("gateway"),
                    "Device": dev, "Protocol": route.get("protocol"),
                    "Scope": route.get("scope"), "PrefSrc": route.get("prefsrc"),
                    "Metric": route.get("metric"), "Family": family,
                    "Table": table,
                    # What preference this table is consulted at, and so whether
                    # it outranks main. Absent when no rule names the table.
                    "RulePreference": rules.get(table),
                }
                # Exact structural comparison, not a judgement: this route is in
                # a table the kernel consults BEFORE main, and main holds a
                # kernel-scope link route for the same destination. Both halves
                # are read; the conclusion follows by set membership.
                pref = rules.get(table)
                if (table != "main" and pref is not None and pref < main_pref
                        and dst in connected[family]):
                    facts["ShadowsLocalPrefix"] = True
                # Derived from the ROW, not from the call that produced it.
                # The label was previously an artefact of which subprocess
                # the row arrived in, which is what let a widened dump
                # mislabel a whole family; reading it from the destination
                # means the fact cannot disagree with the address beside it.
                # `default` carries no address, so it keeps the call's family
                # — the one case where the call is the only evidence.
                shown = _family_of(dst) or family
                facts["Family"] = shown
                items.append(env.item_summary(
                    f"route:{shown}/{table}/{dst}/{dev}", "route", native, facts,
                    opinions=route_opinions(facts), healthy=None))
        return items

    async def _routing_rules(self) -> dict[str, int]:
        """table name -> the lowest (most preferred) rule preference selecting it.

        Lowest wins: the kernel walks rules in ascending preference and takes
        the first table that answers, so the smallest number is the one that
        decides. main sits at 32766 unless something moves it.
        """
        prefs: dict[str, int] = {}
        try:
            raw = await anyio.to_thread.run_sync(_ip_json, ["rule", "show"])
        except Exception:  # noqa: BLE001 - no ip rule support is not a failure
            return prefs
        for rule in raw:
            table = rule.get("table")
            pref = rule.get("priority")
            if table is None or pref is None:
                continue
            if table not in prefs or pref < prefs[table]:
                prefs[table] = pref
        return prefs

    # ── resolver ─────────────────────────────────────────────
    async def _link_dns(self) -> dict[str, dict]:
        """Per-link resolver state via resolve1 GetLink — where DHCP-provided
        DNS actually lives; the Manager's global properties only carry
        statically configured servers."""
        per_link: dict[str, dict] = {}
        for ifindex, ifname in socket.if_nameindex():
            if ifname == "lo":
                continue
            try:
                path = (await BUS.call(RESOLVE1, RESOLVE1_PATH, RESOLVE1_MANAGER,
                                       "GetLink", "i", [ifindex]))[0]
                link = await BUS.get_all(RESOLVE1, path, RESOLVE1_LINK)
            except Exception:  # noqa: BLE001 - link may vanish mid-walk
                continue
            servers = [a for e in link.get("DNS") or [] if (a := _server_addr(e))]
            if not servers:
                continue
            entry: dict = {"DNSServers": servers}
            current = _server_addr(link.get("CurrentDNSServer"))
            if current:
                entry["CurrentDNSServer"] = current
            domains = [d[0] for d in link.get("Domains") or [] if d]
            if domains:
                entry["Domains"] = domains
            # The fact that decides where ordinary queries go — without it an
            # operator reading the manager-level CurrentDNSServer beside the
            # fallback list concluded a host's primary DNS was 1.1.1.1 while
            # every real query went to the LAN resolver (asked live,
            # 2026-08-12). Omitted, not defaulted, when resolve1 predates the
            # property: cannot-see is not "no".
            if "DefaultRoute" in link:
                entry["DefaultRoute"] = bool(link["DefaultRoute"])
            per_link[ifname] = entry
        return per_link

    async def _resolver_observation(self) -> dict:
        mode, _reason = await self._resolver_mode()
        if mode == "file":
            return await self._file_resolver_observation()
        return await self._resolve1_observation()

    async def _file_resolver_observation(self) -> dict:
        """The universal answer on a host without resolved: what glibc
        reads. ResolverService says which mechanism is speaking — the
        packages Manager pattern, now a rule (SPEC rule 16) — and
        ResolvConfTarget carries where the symlink points when it is one,
        which is usually the name of whoever manages the file."""
        def read() -> tuple[str, str | None]:
            path = Path(RESOLV_CONF)
            target = None
            if path.is_symlink():
                target = str(path.resolve())
            return path.read_text(), target
        text, target = await anyio.to_thread.run_sync(read)
        facts: dict = {"ResolverService": "libc-resolv.conf",
                       **parse_resolv_conf(text)}
        if target:
            facts["ResolvConfTarget"] = target
        obj = env.obj_ref(f"resolver:{env.HOST['hostname']}", "resolver",
                          env.HOST["hostname"])
        return env.observation(
            self.subsystem, obj,
            env.source("resolv-conf", "/etc/resolv.conf (glibc)",
                       FILE_RESOLVER_REFERENCE),
            facts, opinions=resolver_opinions(facts),
            evidence_ref=env.evidence_ref("network", "resolver", obj["id"]),
        )

    async def _resolve1_observation(self) -> dict:
        props = await BUS.get_all(RESOLVE1, RESOLVE1_PATH, RESOLVE1_MANAGER)
        servers = global_dns_servers(props.get("DNS") or [])
        fallback = [addr for entry in props.get("FallbackDNS") or []
                    if (addr := _server_addr(entry))]
        domains = [f"{d[1]}{' (route-only)' if d[2] else ''}"
                   for d in props.get("Domains") or []]
        per_link = await self._link_dns()

        # The union of everything configured, globally or per link.
        in_use = sorted({s for entry in per_link.values() for s in entry["DNSServers"]}
                        | set(servers))
        facts = {
            "ResolverService": "systemd-resolved",
            "CurrentDNSServer": _server_addr(props.get("CurrentDNSServer")),
            "DNSServersInUse": in_use,
            "GlobalDNSServers": servers,
            "PerLinkDNS": per_link,
            "FallbackDNSServers": fallback,
            "SearchDomains": domains,
            "DNSSEC": props.get("DNSSEC"),
            "DNSOverTLS": props.get("DNSOverTLS"),
            "LLMNR": props.get("LLMNR"),
            "MulticastDNS": props.get("MulticastDNS"),
            "ResolvConfMode": props.get("ResolvConfMode"),
        }
        obj = env.obj_ref(f"resolver:{env.HOST['hostname']}", "resolver", env.HOST["hostname"])
        return env.observation(
            self.subsystem, obj,
            env.source("resolve1-dbus", RESOLVE1, RESOLVER_REFERENCE,
                       method="Properties.GetAll + GetLink per interface"),
            facts, opinions=resolver_opinions(facts),
            evidence_ref=env.evidence_ref("network", "resolver", obj['id']),
        )

    # ── listening sockets ────────────────────────────────────
    def _listening_items(self) -> list[dict]:
        """One row per listening socket, across both stacks and both
        protocols.

        Ordered by port then address so the page reads the way an operator
        scans it — by the number they are looking for — rather than by the
        order the kernel happened to hash them into.
        """
        rows: list[dict] = []
        unread: list[str] = []
        for table in ("tcp", "tcp6", "udp", "udp6"):
            found, problem = _read_proc_net(table)
            if problem:
                unread.append(problem)
                continue
            rows.extend(found)
        items = []
        for row in sorted(rows, key=lambda r: (r["LocalPort"], r["Protocol"],
                                               r["LocalAddress"])):
            facts = dict(row)
            facts["Scope"] = _listening_scope(row["LocalAddress"])
            # Stated on every row rather than once on the collection: a
            # consumer reading one object must not have to have read the
            # source block to know the process is missing for a reason.
            facts["ProcessUnobservable"] = PROCESS_UNOBSERVABLE
            if unread:
                # A table that would not open is not a table with nothing in
                # it. Without this a host whose /proc/net/udp6 was unreadable
                # would publish a complete-looking list of TCP sockets.
                facts["TablesUnreadable"] = "; ".join(unread)
            items.append(env.item_summary(
                f"socket:{row['Protocol']}/{row['LocalAddress']}"
                f"/{row['LocalPort']}",
                "listening-socket",
                f"{row['Protocol']} {row['LocalAddress']}:{row['LocalPort']}",
                facts, opinions=[], healthy=None))
        return items

    # ── nftables ─────────────────────────────────────────────
    async def _nft_tables(self) -> list[dict]:
        data = await anyio.to_thread.run_sync(_nft_json)
        tables: dict[str, dict] = {}
        for entry in data.get("nftables", []):
            if "table" in entry:
                t = entry["table"]
                key = f"{t['family']}/{t['name']}"
                tables[key] = {"Family": t["family"], "Name": t["name"],
                               "Chains": [], "RuleCount": 0}
            elif "chain" in entry:
                c = entry["chain"]
                key = f"{c['family']}/{c['table']}"
                if key in tables:
                    label = c["name"] + (f" ({c['policy']})" if c.get("policy") else "")
                    tables[key]["Chains"].append(label)
            elif "rule" in entry:
                r = entry["rule"]
                key = f"{r['family']}/{r['table']}"
                if key in tables:
                    tables[key]["RuleCount"] += 1
        items = []
        for key, t in tables.items():
            facts = {"Family": t["Family"], "Chains": t["Chains"],
                     "ChainCount": len(t["Chains"]), "RuleCount": t["RuleCount"]}
            items.append(env.item_summary(
                f"nft-table:{key}", "table", key, facts))
        return items

    # ── nftables chains ──────────────────────────────────────
    async def _nft_chains(self) -> list[dict]:
        """The ruleset's shape: where the kernel enters it, and what runs what.

        This collection exists because the rule list was unreadable at estate
        scale and the reason was structural, not cosmetic — 222 rules on one
        host, 43 of them in a single chain, presented as a flat list with
        nothing saying which of them a packet ever reaches. Reported as "the
        firewall table isn't very human parsable" (2026-08-14).

        A ruleset is a graph and nft's own JSON has always carried it: the
        chain objects sit in the same document as the rules and were being
        skipped. Two facts here are not in that document and are the ones
        that make it navigable — JumpedFrom, which needs every rule in every
        table read, plus the element list of every named verdict map a rule
        uses, to answer "what runs this chain" — and Unreferenced, which
        falls out of it.

        No opinions, for the reason nft-rules has none: whether a policy or a
        stray chain is a problem depends on what the rules inside admit, and
        that question belongs to port-exposure, where it is answered with two
        closures rather than a dot.
        """
        data = await anyio.to_thread.run_sync(_nft_json)
        chains: dict[tuple, dict] = {}
        rule_counts: dict[tuple, int] = {}
        jumped: dict[tuple, set[str]] = {}
        map_targets: dict[tuple, list[str]] = {}
        map_users: dict[tuple, set[str]] = {}
        for entry in data.get("nftables", []):
            if "chain" in entry:
                c = entry["chain"]
                chains[(c.get("family"), c.get("table"), c.get("name"))] = c
            elif "rule" in entry:
                r = entry["rule"]
                key = (r.get("family"), r.get("table"), r.get("chain"))
                rule_counts[key] = rule_counts.get(key, 0) + 1
                # The whole expression tree, not the top-level statements: a
                # verdict map carries its jumps nested in the map's data, and
                # reading only the surface published the chain holding every
                # inbound accept as Unreferenced. Both verbs, at any depth —
                # _verdict_targets holds the reasoning for each.
                for target in _verdict_targets(r.get("expr") or []):
                    jumped.setdefault(
                        (r.get("family"), r.get("table"), target),
                        set()).add(r.get("chain"))
                # Which named objects this rule consults, keyed in the rule's
                # own (family, table) because "@dispatch" names THIS table's
                # object and no other's. Joined against the map objects below.
                for ref in _map_references(r.get("expr") or []):
                    map_users.setdefault(
                        (r.get("family"), r.get("table"), ref),
                        set()).add(r.get("chain"))
            elif "map" in entry:
                # A NAMED verdict map keeps its jumps HERE, in the top-level
                # map object's elem list — the rule dispatching through it
                # carries only the string "@dispatch" — so a derivation that
                # read rule expressions alone published a map-dispatched
                # chain as {"RuleCount": 0, "Unreferenced": true}: the vmap
                # defect again, one spelling further out. The same descent
                # as a rule expression, so an element wrapped for a comment
                # or timeout is covered too. Maps only, by grammar rather
                # than oversight: libnftables-json gives mapped data to the
                # map object alone (its "map" member names the data type,
                # "verdict" here) — a set object's elem list holds bare
                # keys, and verdict is not a key type, so a set has nowhere
                # for a jump to sit.
                m = entry["map"]
                map_targets[(m.get("family"), m.get("table"),
                             m.get("name"))] = _verdict_targets(
                                 m.get("elem") or [])
        # A map's targets count only where some rule consults the map: the
        # kernel never traverses a map no rule uses, so a jump inside an
        # unused map is latent — reachability through an UNREFERENCED map is
        # not reachability, and counting it would retire Unreferenced from
        # exactly the chains it is telling the truth about. APPROXIMATION,
        # stated: "some rule" means any rule in the map's own (family,
        # table), not a rule proven base-reachable — the same standard the
        # rule-sourced references above already apply, since a jump written
        # in an unreachable chain counts there too. The callers recorded are
        # the consulting rules' chains: control leaves that chain, goes
        # through the map, and lands on the target.
        for (family, table, mname), targets in map_targets.items():
            users = map_users.get((family, table, mname))
            if not users:
                continue
            for target in targets:
                jumped.setdefault((family, table, target),
                                  set()).update(users)
        items = []
        for (family, table, name), chain in chains.items():
            key = (family, table, name)
            # A base chain is one the kernel calls, and `hook` is what says
            # so. Absent members are omitted rather than nulled: a regular
            # chain has no policy, and a null one reads as "no policy set",
            # which is a different and much more alarming claim.
            base = bool(chain.get("hook"))
            facts: dict = {"Family": family, "Table": table, "Name": name,
                           "BaseChain": base}
            if chain.get("handle") is not None:
                facts["Handle"] = chain["handle"]
            for fact, member in (("Hook", "hook"), ("Type", "type"),
                                 ("Priority", "prio"), ("Policy", "policy")):
                if chain.get(member) is not None:
                    facts[fact] = chain[member]
            facts["RuleCount"] = rule_counts.get(key, 0)
            callers = sorted(jumped.get(key, ()))
            if callers:
                facts["JumpedFrom"] = callers
            elif not base:
                facts["Unreferenced"] = True
            # One assertion per chain: the table it belongs to (DESIGN 13/19).
            # Inbound dispatch is NOT asserted here even though JumpedFrom
            # holds it — a relation is directed because observation has a
            # vantage, and the vantage that saw the jump is the RULE that
            # writes it. Asserting it from this end too would put two
            # directed claims about one edge on the wire from one reading,
            # and the collator would have to decide which vantage it came
            # from. JumpedFrom stays a derived fact, which is what it is.
            item = env.item_summary(
                f"nft-chain:{family}/{table}/{name}", "chain",
                f"{family} {table} {name}", facts,
                opinions=[], healthy=None)
            # No facts member: the type declares carries_facts false, and an
            # empty object on the wire would be a fact channel opened for a
            # relation that has none.
            item["assertions"] = [{
                "type": "member-of",
                "target": {"kind": "nft-table", "name": f"{family} {table}"},
            }]
            items.append(item)
        return items

    # ── nftables rules ───────────────────────────────────────
    async def _nft_rules(self) -> list[dict]:
        """One row per rule, in evaluation order within each chain.

        Ordering is preserved because it IS the meaning: nftables evaluates
        top to bottom and the first match wins, so a rule list re-sorted for
        display would be a different ruleset.
        """
        data = await anyio.to_thread.run_sync(_nft_json)
        items: list[dict] = []
        position: dict[tuple, int] = {}
        for entry in data.get("nftables", []):
            if "rule" not in entry:
                continue
            rule = entry["rule"]
            family = rule.get("family")
            table = rule.get("table")
            chain = rule.get("chain")
            handle = rule.get("handle")
            key = (family, table, chain)
            index = position[key] = position.get(key, -1) + 1
            rendered = _render_rule(rule.get("expr") or [])
            facts: dict = {
                "Family": family, "Table": table, "Chain": chain,
                "Handle": handle, "Position": index,
                "Rendered": rendered["text"],
            }
            if rendered["verdict"]:
                facts["Verdict"] = rendered["verdict"]
            if rendered["jump_target"]:
                facts["JumpTarget"] = rendered["jump_target"]
            # Comprehension is derived from the residue rather than set where
            # a branch happened to notice something: one computation, so a
            # renderer that grows a case cannot forget to update the claim.
            if rendered["opaque_reason"]:
                facts["Comprehension"] = "opaque"
                facts["OpaqueReason"] = rendered["opaque_reason"]
            elif rendered["residue"]:
                facts["Comprehension"] = "partial"
            else:
                facts["Comprehension"] = "full"
            if rendered["residue"]:
                facts["Residue"] = [env.reason(json.dumps(item), 400)
                                    for item in rendered["residue"]]
            # Absent, never zero: nftables has no implicit per-rule counters,
            # so a rule without one has no traffic history at all and a 0
            # would report an idle rule that is simply uncounted.
            if rendered["packets"] is not None:
                facts["CounterPackets"] = rendered["packets"]
            if rendered["bytes"] is not None:
                facts["CounterBytes"] = rendered["bytes"]
            item = env.item_summary(
                f"nft-rule:{family}/{table}/{chain}/{handle}", "rule",
                f"{family} {table} {chain} handle {handle}", facts,
                opinions=[], healthy=None)
            # Two assertions, and the pair is the point. member-of names the
            # chain this rule sits in — a name nft-chains publishes, so it
            # RESOLVES whenever both collections are collected in one batch,
            # and is `asserted` when only nft-rules was asked for. Nothing
            # here can tell the difference, and nothing here should: whether
            # the far end was seen is a fact about another collector's
            # output, which only the collator holds (DESIGN 19).
            #
            # dispatches-to names the jump target, and it carries the
            # discriminator because a chain can jump to the same target from
            # several rules — Handle is what tells those apart, and it is
            # the rule's own identity in nftables rather than a position
            # that shifts when a rule above it is deleted.
            assertions = [{
                "type": "member-of",
                "target": {"kind": "nft-chain",
                           "name": f"{family} {table} {chain}"},
            }]
            if facts.get("JumpTarget"):
                assertions.append({
                    "type": "dispatches-to",
                    "target": {"kind": "nft-chain",
                               "name": f"{family} {table} {facts['JumpTarget']}"},
                    "facts": {"Handle": handle},
                })
            item["assertions"] = assertions
            items.append(item)
        return items

    # ── port exposure ────────────────────────────────────────
    async def _exposure_items(self) -> list[dict]:
        """One row per listening socket, with the input-path rules that admit
        it and the two-closure answer to where from."""
        document = await anyio.to_thread.run_sync(_nft_json)
        sockets = await anyio.to_thread.run_sync(self._listening_items)
        path = _walk_input_path(document)
        items = []
        for socket_item in sockets:
            facts = socket_item["facts"]
            protocol, port = facts["Protocol"], facts["LocalPort"]
            admitting: list[str] = []
            certain: list[str] = []
            possible: list[str] = []
            gap_rules: list[str] = []
            for rule, guards in path:
                if not _family_bears_on(rule.get("family"), protocol):
                    continue
                # The guards first: a rule inside a jumped-to chain is
                # reached only under the jumping rule's conditions, and they
                # constrain what it admits exactly as its own do.
                expr = guards + (rule.get("expr") or [])
                rendered = _render_rule(expr)
                # A rule whose VERDICT could not be read might be an accept —
                # a verdict map, or a statement nft could only emit as text.
                # Skipping it dropped it from BOTH closures, so the row
                # reported no admitting rule and no gap either: silence where
                # the honest answer is "something here might admit this and I
                # cannot tell".
                unreadable_verdict = (rendered["verdict"] is None
                                      and not rendered["jump_target"]
                                      and bool(rendered["residue"]))
                if rendered["verdict"] != "accept" and not unreadable_verdict:
                    continue
                sure, maybe = _rule_bears_on(rendered, expr, protocol, port)
                if unreadable_verdict:
                    sure = False
                if not maybe:
                    continue
                where = f"{rule.get('family')}/{rule.get('table')}/" \
                        f"{rule.get('chain')}/{rule.get('handle')}"
                admitting.append(f"{where}: {rendered['text']}")
                sources = _sources_of(expr)
                for source in sources:
                    if sure and source not in certain:
                        certain.append(source)
                    if source not in possible:
                        possible.append(source)
                if not sure:
                    gap_rules.append(where)
            out = {
                "Protocol": protocol, "LocalAddress": facts["LocalAddress"],
                "LocalPort": port, "Scope": facts["Scope"],
                # Stated on the row, not only in the source block: a consumer
                # holding one object must be able to see that an empty
                # admitting list is not a statement that nothing can reach
                # this port.
                "PathCoverage": "input path only; a port published through"
                                " prerouting/forward is not accounted for",
            }
            if admitting:
                out["AdmittingRules"] = admitting
            # Absent rather than an empty list where nothing was found: the
            # question "which rules admit this" was asked of the input path
            # alone, and an empty answer is about that path, never about the
            # port.
            if certain:
                out["AdmittedFromCertain"] = certain
            if possible:
                out["AdmittedFromPossible"] = possible
            if gap_rules:
                out["ClosureGap"] = True
                out["ClosureGapRules"] = gap_rules
            elif possible:
                out["ClosureGap"] = False
            items.append(env.item_summary(
                socket_item["id"], "port-exposure", socket_item["native_id"],
                out, opinions=[], healthy=None))
        return items

    # ── tailscale ────────────────────────────────────────────
    async def _tailscale_items(self) -> list[dict]:
        snapshot = await anyio.to_thread.run_sync(_tailscale_snapshot)
        if snapshot is None:
            # The HTTP layer renders this as an error envelope — errors are
            # observations; capability discovery names the same reason.
            raise RuntimeError(TAILSCALE_UNAVAILABLE)
        status, mtime = snapshot
        node = status.get("Self") or {}
        key_expiry, key_expiry_days = _key_expiry(node.get("KeyExpiry"))
        facts = {
            "HostName": node.get("HostName"),
            "DNSName": node.get("DNSName"),
            "TailscaleIPs": node.get("TailscaleIPs"),
            "OS": node.get("OS"),
            "Online": node.get("Online"),
            "Relay": node.get("Relay") or None,
            "ExitNodeOption": node.get("ExitNodeOption"),
            "KeyExpiry": key_expiry,
            "KeyExpiryDays": key_expiry_days,
            "MagicDNSSuffix": status.get("MagicDNSSuffix"),
            "BackendState": status.get("BackendState"),
            # Snapshot facts are only as fresh as the file — the SMART
            # contract exactly: stamp when the collector wrote it and how
            # old that is now, so the staleness rule stays pure.
            "TailscaleSnapshotAt": _epoch_iso(mtime),
            "TailscaleSnapshotAgeSeconds": max(0, int(time.time() - mtime)),
        }
        # The subnet-router channel: if the advertisement lapses the key
        # disappears — exactly the goes-dark change an expected-state check
        # needs to see (audit 2026-08-10). Health likewise rides only when
        # the daemon is actually saying something.
        if node.get("PrimaryRoutes") is not None:
            facts["PrimaryRoutes"] = node["PrimaryRoutes"]
        if status.get("Health"):
            facts["Health"] = status["Health"]
        # Same identity rule as the peers below: the tailnet's DNS label,
        # never the free-text HostName (which stays as a fact).
        items = [env.item_summary(
            "tailscale:self", "tailscale-self",
            peer_native_id(node) or "self", facts,
            opinions=tailscale_opinions(facts),
            healthy="ok" if facts["Online"] else "info")]
        for peer in (status.get("Peer") or {}).values():
            name = peer_native_id(peer)
            if not name:
                continue
            peer_facts = {
                "HostName": peer.get("HostName"),
                "DNSName": peer.get("DNSName"),
                "TailscaleIPs": peer.get("TailscaleIPs"),
                "OS": peer.get("OS"),
                "Online": peer.get("Online"),
                "LastSeen": _nonzero_time(peer.get("LastSeen")),
                "Relay": peer.get("Relay") or None,
                # tailscale reports "" while no direct path is in use —
                # relayed via DERP, or simply idle. Null says exactly that.
                "CurAddr": peer.get("CurAddr") or None,
                "RxBytes": peer.get("RxBytes"),
                "TxBytes": peer.get("TxBytes"),
                "ExitNode": peer.get("ExitNode"),
            }
            if peer.get("PrimaryRoutes"):
                peer_facts["PrimaryRoutes"] = peer["PrimaryRoutes"]
            items.append(env.item_summary(
                f"tailscale:{name}", "tailscale-peer", name, peer_facts,
                opinions=tailscale_opinions(peer_facts),
                healthy="ok" if peer_facts["Online"] else "info"))
        return items

    # ── lookups ──────────────────────────────────────────────
    async def _lookup_items(self) -> list[dict]:
        res_ok, res_reason = await self._resolver_available()
        items = []
        for name, spec in LOOKUPS.items():
            facts: dict = dict(spec)
            if name == "resolve" and not res_ok:
                facts["Available"] = False
                facts["Note"] = res_reason
            items.append(env.item_summary(f"lookup:{name}", "lookup", name, facts))
        return items

    def _lookup_source(self, name: str, arg: str | None) -> dict:
        if name == "route-get":
            return env.source("ip-json", "ip -j route get (rtnetlink)",
                              [f"ip route get {arg or '<address>'}"])
        return env.source("resolve1-dbus", RESOLVE1,
                          [f"resolvectl query {arg or '<name>'}"],
                          method="ResolveHostname / ResolveAddress")

    @staticmethod
    def _parse_lookup_id(object_id: str) -> tuple[str, str]:
        if not object_id.startswith("lookup:"):
            raise env.UnknownObject(object_id)
        name, _, arg = object_id[len("lookup:"):].partition("/")
        if name not in LOOKUPS:
            raise env.UnknownObject(object_id)
        return name, arg

    async def _route_get_raw(self, arg: str) -> list:
        """Validated address in, raw `ip -j route get` out. ValueError for a
        non-address; CalledProcessError when the kernel has no route."""
        addr = ipaddress.ip_address(arg)
        return await anyio.to_thread.run_sync(_ip_json, ["route", "get", str(addr)])

    async def _resolve_raw(self, arg: str) -> dict:
        """One resolve1 call, forward or reverse by input shape. The reply is
        returned raw (evidence); callers shape facts from it."""
        try:
            ip = ipaddress.ip_address(arg)
        except ValueError:
            ip = None
        started = time.monotonic()
        if ip is not None:
            family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
            names, flags = await BUS.call(
                RESOLVE1, RESOLVE1_PATH, RESOLVE1_MANAGER, "ResolveAddress",
                "iiayt", [0, int(family), ip.packed, 0])
            reply: dict = {"names": names, "flags": flags}
        else:
            if not HOSTNAME_RE.match(arg):
                raise ValueError(f"{arg!r} is not a hostname or IP address")
            addresses, canonical, flags = await BUS.call(
                RESOLVE1, RESOLVE1_PATH, RESOLVE1_MANAGER, "ResolveHostname",
                "isit", [0, arg, 0, 0])  # AF_UNSPEC, no flags
            reply = {"addresses": addresses, "canonical": canonical, "flags": flags}
        reply["query_time_ms"] = round((time.monotonic() - started) * 1000, 1)
        return reply

    async def _route_get_observation(self, obj: dict, arg: str) -> dict:
        src = self._lookup_source("route-get", arg)
        try:
            routes = await self._route_get_raw(arg)
        except ValueError:
            return env.observation(self.subsystem, obj, src, {"Destination": arg},
                                   status="error",
                                   errors=[f"{arg!r} is not an IPv4 or IPv6 address"])
        except subprocess.CalledProcessError as exc:
            # "RTNETLINK answers: Network is unreachable" is the kernel's
            # answer, not an acquisition failure.
            facts = {"Destination": arg, "RouteFound": False,
                     "KernelError": (exc.stderr or "").strip() or f"exit {exc.returncode}"}
            return env.observation(
                self.subsystem, obj, src, facts,
                opinions=[env.opinion("route-lookup", "warn",
                                      "The kernel has no route to this destination.",
                                      ["RouteFound", "KernelError"])])
        r = routes[0] if routes else {}
        facts = {
            "Destination": r.get("dst", arg), "RouteFound": True,
            "Gateway": r.get("gateway"), "Device": r.get("dev"),
            "PreferredSource": r.get("prefsrc"), "Table": r.get("table"),
            "Protocol": r.get("protocol"), "Scope": r.get("scope"),
            "Metric": r.get("metric"),
        }
        relationships = []
        if facts["Device"]:
            relationships.append(env.rel("routes-via", "out", f"link:{facts['Device']}"))
        return env.observation(
            self.subsystem, obj, src, facts, relationships=relationships,
            evidence_ref=env.evidence_ref("network", "lookups", obj['id']))

    async def _resolve_observation(self, obj: dict, arg: str) -> dict:
        src = self._lookup_source("resolve", arg)
        res_ok, res_reason = await self._resolver_available()
        if not res_ok:
            return env.observation(self.subsystem, obj, src, {"Query": arg},
                                   status="error", errors=[res_reason])
        try:
            reply = await self._resolve_raw(arg)
        except ValueError as exc:
            return env.observation(self.subsystem, obj, src, {"Query": arg},
                                   status="error", errors=[str(exc)])
        except CallError as exc:
            # NXDOMAIN, QueryTimedOut, NoNameServers … — answers, not failures.
            verdict = exc.error_name.rsplit(".", 1)[-1]
            facts = {"Query": arg, "Resolved": False, "Result": verdict}
            return env.observation(
                self.subsystem, obj, src, facts,
                opinions=[env.opinion("resolve-lookup", "warn",
                                      f"The resolver answered {verdict} for this query.",
                                      ["Resolved", "Result"])])
        flags = reply["flags"]
        facts = {"Query": arg, "Resolved": True}
        if "names" in reply:
            facts["Names"] = [n for _, n in reply["names"]]
        else:
            facts["Addresses"] = [self._scoped_addr(e) for e in reply["addresses"]]
            facts["CanonicalName"] = reply["canonical"]
        facts["Protocol"] = _resolve_protocol(flags)
        facts["Authenticated"] = bool(flags & RESOLVED_AUTHENTICATED)
        facts["QueryTimeMs"] = reply["query_time_ms"]
        return env.observation(
            self.subsystem, obj, src, facts,
            evidence_ref=env.evidence_ref("network", "lookups", obj['id']))

    @staticmethod
    def _scoped_addr(entry) -> str | None:
        """resolve1 address struct (ifindex, family, bytes) → '1.2.3.4' or
        'fe80::1%eth0'. resolve1 stamps every answer with the interface it
        arrived on; the scope suffix only carries meaning for link-local
        addresses, so it is added only there."""
        ifindex, _family, raw = entry
        addr = _addr_str(raw)
        if addr and ifindex and ipaddress.ip_address(addr).is_link_local:
            try:
                addr += f"%{socket.if_indextoname(ifindex)}"
            except OSError:
                pass
        return addr

    async def _lookup_observation(self, object_id: str) -> dict:
        name, arg = self._parse_lookup_id(object_id)
        obj = env.obj_ref(object_id, "lookup", object_id[len("lookup:"):])
        if not arg:
            facts: dict = dict(LOOKUPS[name])
            facts["Usage"] = f"GET /v1/network/lookups/lookup:{name}/<input>"
            if name == "resolve":
                res_ok, res_reason = await self._resolver_available()
                if not res_ok:
                    facts["Available"] = False
                    facts["Note"] = res_reason
            return env.observation(self.subsystem, obj,
                                   self._lookup_source(name, None), facts)
        if name == "route-get":
            return await self._route_get_observation(obj, arg)
        return await self._resolve_observation(obj, arg)

    # ── protocol ─────────────────────────────────────────────
    def _source_for(self, collection: str) -> dict:
        table: dict[str, tuple] = {
            "links": ("ip-json", "ip -j (rtnetlink)", LINK_REFERENCE),
            "routes": ("ip-json", "ip -j (rtnetlink)", ROUTE_REFERENCE),
            "resolver": ("resolve1-dbus", RESOLVE1, RESOLVER_REFERENCE),
            "listening": ("proc-net", "/proc/net", LISTENING_REFERENCE,
                          LISTENING_NOTES),
            "nft-tables": ("nft-json", "nft -j", NFT_REFERENCE, NFT_NOTES),
            "nft-chains": ("nft-json", "nft -j", NFT_CHAIN_REFERENCE,
                           NFT_CHAIN_NOTES),
            "nft-rules": ("nft-json", "nft -j", NFT_RULE_REFERENCE,
                          NFT_RULE_NOTES),
            "port-exposure": ("proc-net + nft-json", "/proc/net + nft -j",
                              EXPOSURE_REFERENCE, EXPOSURE_NOTES),
            "tailscale": ("tailscale-json",
                          f"tailscale status --json snapshots ({TAILSCALE_SNAPSHOT})",
                          TAILSCALE_REFERENCE),
            "lookups": ("network-lookups", "ip -j route get (rtnetlink) / resolve1",
                        ["ip route get <address>", "resolvectl query <name>"]),
        }
        entry = table[collection]
        adapter, iface, refs = entry[0], entry[1], entry[2]
        notes = entry[3] if len(entry) > 3 else None
        return env.source(adapter, iface, list(refs),
                          notes=list(notes) if notes else None)

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        """The full materialisation, shared: collect() pages it, get_object
        searches it, and main.py's status/snapshot/changes sweeps consume it
        directly instead of re-acquiring per page. lookups is here like any
        other collection — the catalog's items ARE the documentation.
        Single-flighted so concurrent callers ride one acquisition
        (envelope.single_flight — coalescing, not caching)."""
        if collection == "links":
            return await self._link_items()
        if collection == "routes":
            return await self._route_items()
        if collection == "listening":
            return await anyio.to_thread.run_sync(self._listening_items)
        if collection == "nft-tables":
            return await self._nft_tables()
        if collection == "nft-chains":
            return await self._nft_chains()
        if collection == "nft-rules":
            return await self._nft_rules()
        if collection == "port-exposure":
            return await self._exposure_items()
        if collection == "tailscale":
            return await self._tailscale_items()
        if collection == "lookups":
            return await self._lookup_items()
        if collection == "resolver":
            obs = await self._resolver_observation()
            return [env.item_summary(
                obs["object"]["id"], "resolver", obs["object"]["native_id"],
                obs["facts"],
                opinions=resolver_opinions(obs["facts"]))]
        raise env.UnknownCollection(collection)

    async def _resolver_source(self) -> dict:
        """The envelope-level source follows the MECHANISM that answered —
        rule 16's provenance half. Verified live after the file shape
        deployed (2026-08-12): two dhcpcd hosts answered from
        /etc/resolv.conf while the collection page's source still claimed
        resolve1-dbus with resolvectl reference commands — an interface
        that never spoke and commands that cannot run there. The opened
        object already carried the honest source; the page now agrees."""
        mode, _reason = await self._resolver_mode()
        if mode == "file":
            return env.source("resolv-conf", "/etc/resolv.conf (glibc)",
                              FILE_RESOLVER_REFERENCE)
        return self._source_for("resolver")

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        source = (await self._resolver_source() if collection == "resolver"
                  else self._source_for(collection))
        return env.collection_page(self.subsystem, collection, source,
                                   page, applied, next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    # One evaluator per collection (agent/rules/network.py), shared verbatim
    # with the summary path — rows and opened objects cannot disagree. The
    # resolver applies its evaluator inside _resolver_observation; routes and
    # nft-tables carry facts only, no verdict.
    _RULES = {"links": link_opinions, "tailscale": tailscale_opinions}

    def _opinions(self, collection: str, match: dict) -> list[dict]:
        rule = self._RULES.get(collection)
        return rule(match["facts"]) if rule else []

    @staticmethod
    def _nft_edges(collection: str, facts: dict) -> list[dict]:
        """The ruleset as a graph, from whichever object was opened.

        A jump is the whole of how a ruleset composes, and reading one used
        to mean copying a chain name out of a rendered rule and going to find
        it by hand — across 222 rules on one host. The edges are all drawn
        from facts already on the row; nothing new is acquired to state them.
        """
        family, table = facts.get("Family"), facts.get("Table")
        if not family or not table:
            return []
        chain = f"nft-chain:{family}/{table}"
        edges = []
        if collection == "nft-rules":
            edges.append(env.rel("member-of", "out", f"{chain}/{facts['Chain']}"))
            if facts.get("JumpTarget"):
                edges.append(env.rel("dispatches-to", "out",
                                     f"{chain}/{facts['JumpTarget']}"))
        elif collection == "nft-chains":
            edges.append(env.rel("member-of", "out",
                                 f"nft-table:{family}/{table}"))
            # Inbound, from the derived fact: the chains that transfer control
            # here. This is the edge a reader follows BACKWARDS to answer "how
            # does a packet ever get to this rule", which no chain's own
            # document can say.
            for caller in facts.get("JumpedFrom") or []:
                edges.append(env.rel("dispatches-to", "in", f"{chain}/{caller}"))
        return edges

    async def get_object(self, collection: str, object_id: str) -> dict:
        if collection == "lookups":
            return await self._lookup_observation(object_id)
        if collection == "resolver":
            obs = await self._resolver_observation()
            if obs["object"]["id"] != object_id:
                raise env.UnknownObject(object_id)
            return obs

        items = await self.acquire(collection)
        match = next((i for i in items if i["id"] == object_id), None)
        if match is None:
            raise env.UnknownObject(object_id)

        relationships = []
        if collection == "links" and match["facts"].get("Master"):
            relationships.append(env.rel("attached-to", "out",
                                         f"link:{match['facts']['Master']}"))
        if collection == "routes" and match["facts"].get("Device"):
            relationships.append(env.rel("routes-via", "out",
                                         f"link:{match['facts']['Device']}"))
        relationships += self._nft_edges(collection, match["facts"])

        return env.observation(
            self.subsystem,
            env.obj_ref(object_id, match["type"], match["native_id"]),
            self._source_for(collection),
            match["facts"], opinions=self._opinions(collection, match),
            relationships=relationships,
            evidence_ref=env.evidence_ref("network", collection, object_id),
        )

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        if collection == "links":
            payload = {"ip_addr": await anyio.to_thread.run_sync(_ip_json, ["-d", "addr", "show"]),
                       "lldp": await self._lldp_by_link()}
        elif collection == "routes":
            payload = {"ipv4": await anyio.to_thread.run_sync(_ip_json, ["-4", "route", "show"]),
                       "ipv6": await anyio.to_thread.run_sync(_ip_json, ["-6", "route", "show"])}
        elif collection == "resolver":
            payload = {"manager": await BUS.get_all(RESOLVE1, RESOLVE1_PATH, RESOLVE1_MANAGER),
                       "links": await self._link_dns()}
        elif collection in ("nft-tables", "nft-rules"):
            payload = await anyio.to_thread.run_sync(_nft_json)
        elif collection == "listening":
            # The four tables verbatim, including one that would not open —
            # shown as the reason it did not, because an unreadable table is
            # the evidence for the fact that says so.
            payload = {f"{PROC_NET}/{name}": (_read_text(f"{PROC_NET}/{name}")
                                              or "could not be read")
                       for name in ("tcp", "tcp6", "udp", "udp6")}
        elif collection == "port-exposure":
            # Both halves, because the row is a join and neither half alone
            # lets a reader check it.
            payload = {"sockets": {f"{PROC_NET}/{name}":
                                   (_read_text(f"{PROC_NET}/{name}") or "could not be read")
                                   for name in ("tcp", "tcp6", "udp", "udp6")},
                       "ruleset": await anyio.to_thread.run_sync(_nft_json)}
        elif collection == "tailscale":
            # The raw snapshot verbatim — captured fresh from the file, the
            # very document the facts were shaped from.
            snapshot = await anyio.to_thread.run_sync(_tailscale_snapshot)
            if snapshot is None:
                raise RuntimeError(TAILSCALE_UNAVAILABLE)
            payload, _mtime = snapshot
        elif collection == "lookups":
            # Evidence re-runs the lookup — captured fresh, never cached,
            # through the same validated helpers as the observation.
            name, arg = self._parse_lookup_id(object_id)
            if not arg:
                raise env.UnknownObject(object_id)   # descriptors carry no evidence
            if name == "route-get":
                payload = {"route_get": await self._route_get_raw(arg)}
            else:
                payload = {"resolve1": await self._resolve_raw(arg)}
        else:
            raise env.UnknownCollection(collection)
        return {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": self._source_for(collection)["interface"],
            "payload": payload,
        }
