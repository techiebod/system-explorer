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
from ..rules import worst_level
from ..rules.network import (LINK_QUIET_STATES, link_opinions,
                             resolver_opinions, tailscale_opinions)
from ..sysbus import BUS, CallError

RESOLVE1 = "org.freedesktop.resolve1"
RESOLVE1_PATH = "/org/freedesktop/resolve1"
RESOLVE1_MANAGER = "org.freedesktop.resolve1.Manager"
RESOLVE1_LINK = "org.freedesktop.resolve1.Link"

LINK_REFERENCE = ["ip -d addr show", "networkctl status <link>"]
ROUTE_REFERENCE = ["ip route show", "ip -6 route show"]
RESOLVER_REFERENCE = ["resolvectl status", "resolvectl dns"]
NFT_REFERENCE = ["nft list ruleset"]
TAILSCALE_REFERENCE = ["tailscale status --json"]

TAILSCALE_SNAPSHOT = "/run/system-explorer-tailscale/status.json"
TAILSCALE_UNAVAILABLE = (f"no tailscale snapshot at {TAILSCALE_SNAPSHOT} "
                         "(grantTailscaleAccess off, or tailscaled absent)")

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
        return ["links", "routes", "resolver", "nft-tables", "tailscale", "lookups"]

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

    async def capability(self) -> dict:
        unavailable: dict[str, str] = {
            "conntrack-summary": "netlink acquisition not yet implemented",
        }
        nft_ok, nft_reason = await self._nft_available()
        if not nft_ok:
            unavailable["nft-tables"] = nft_reason
        res_ok, res_reason = await self._resolver_available()
        if not res_ok:
            unavailable["resolver"] = res_reason
        if await anyio.to_thread.run_sync(_tailscale_snapshot) is None:
            unavailable["tailscale"] = TAILSCALE_UNAVAILABLE
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
                "Kind": (link.get("linkinfo") or {}).get("info_kind"),
                "MTU": link.get("mtu"),
                "MACAddress": link.get("address"),
                "Master": link.get("master"),
                "Addresses": [f"{a['local']}/{a['prefixlen']}"
                              for a in link.get("addr_info", []) if "local" in a],
            }
            if facts["Kind"] == "bridge":
                facts["BridgeMembers"] = member_counts.get(name, 0)
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
            worst = worst_level(link_opinions(facts), healthy=healthy)
            items.append(env.item_summary(f"link:{name}", "link", name, facts,
                                          worst_opinion_level=worst))

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
        items = []
        for family, args in (("ipv4", ["route", "show"]), ("ipv6", ["-6", "route", "show"])):
            for route in await anyio.to_thread.run_sync(_ip_json, args):
                dst = route.get("dst", "default")
                dev = route.get("dev", "?")
                native = f"{dst} dev {dev}" + (f" via {route['gateway']}" if route.get("gateway") else "")
                facts = {
                    "Destination": dst, "Gateway": route.get("gateway"),
                    "Device": dev, "Protocol": route.get("protocol"),
                    "Scope": route.get("scope"), "PrefSrc": route.get("prefsrc"),
                    "Metric": route.get("metric"), "Family": family,
                }
                items.append(env.item_summary(
                    f"route:{family}/{dst}/{dev}", "route", native, facts))
        return items

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
            per_link[ifname] = entry
        return per_link

    async def _resolver_observation(self) -> dict:
        props = await BUS.get_all(RESOLVE1, RESOLVE1_PATH, RESOLVE1_MANAGER)
        # Manager.DNS aggregates global and per-link servers; global entries
        # carry ifindex 0 in the (iiay) struct.
        servers = [addr for entry in props.get("DNS") or []
                   if isinstance(entry, (list, tuple)) and len(entry) == 3 and entry[0] == 0
                   and (addr := _server_addr(entry))]
        fallback = [addr for entry in props.get("FallbackDNS") or []
                    if (addr := _server_addr(entry))]
        domains = [f"{d[1]}{' (route-only)' if d[2] else ''}"
                   for d in props.get("Domains") or []]
        per_link = await self._link_dns()

        # The union of everything configured, globally or per link.
        in_use = sorted({s for entry in per_link.values() for s in entry["DNSServers"]}
                        | set(servers))
        facts = {
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
            evidence_ref=f"/v1/network/resolver/{obj['id']}/evidence",
        )

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
        items = [env.item_summary(
            "tailscale:self", "tailscale-self",
            facts["HostName"] or "self", facts,
            worst_opinion_level=worst_level(
                tailscale_opinions(facts),
                healthy="ok" if facts["Online"] else "info"))]
        for peer in (status.get("Peer") or {}).values():
            name = peer.get("HostName") or (peer.get("DNSName") or "").split(".")[0]
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
                worst_opinion_level=worst_level(
                    tailscale_opinions(peer_facts),
                    healthy="ok" if peer_facts["Online"] else "info")))
        return items

    # ── lookups ──────────────────────────────────────────────
    async def _lookup_items(self) -> list[dict]:
        res_ok, res_reason = await self._resolver_available()
        items = []
        for name, spec in LOOKUPS.items():
            facts = dict(spec)
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
            evidence_ref=f"/v1/network/lookups/{obj['id']}/evidence")

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
        facts: dict = {"Query": arg, "Resolved": True}
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
            evidence_ref=f"/v1/network/lookups/{obj['id']}/evidence")

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
            facts = dict(LOOKUPS[name])
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
        table = {
            "links": ("ip-json", "ip -j (rtnetlink)", LINK_REFERENCE),
            "routes": ("ip-json", "ip -j (rtnetlink)", ROUTE_REFERENCE),
            "resolver": ("resolve1-dbus", RESOLVE1, RESOLVER_REFERENCE),
            "nft-tables": ("nft-json", "nft -j", NFT_REFERENCE),
            "tailscale": ("tailscale-json",
                          f"tailscale status --json snapshots ({TAILSCALE_SNAPSHOT})",
                          TAILSCALE_REFERENCE),
            "lookups": ("network-lookups", "ip -j route get (rtnetlink) / resolve1",
                        ["ip route get <address>", "resolvectl query <name>"]),
        }
        adapter, iface, refs = table[collection]
        return env.source(adapter, iface, refs)

    async def _items(self, collection: str) -> list[dict]:
        if collection == "links":
            return await self._link_items()
        if collection == "routes":
            return await self._route_items()
        if collection == "nft-tables":
            return await self._nft_tables()
        if collection == "tailscale":
            return await self._tailscale_items()
        if collection == "lookups":
            return await self._lookup_items()
        if collection == "resolver":
            obs = await self._resolver_observation()
            return [env.item_summary(
                obs["object"]["id"], "resolver", obs["object"]["native_id"],
                obs["facts"],
                worst_opinion_level=worst_level(resolver_opinions(obs["facts"])))]
        raise env.UnknownCollection(collection)

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        items = env.apply_fact_filters(await self._items(collection), query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, self._source_for(collection),
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

    async def get_object(self, collection: str, object_id: str) -> dict:
        if collection == "lookups":
            return await self._lookup_observation(object_id)
        if collection == "resolver":
            obs = await self._resolver_observation()
            if obs["object"]["id"] != object_id:
                raise env.UnknownObject(object_id)
            return obs

        items = await self._items(collection)
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

        return env.observation(
            self.subsystem,
            env.obj_ref(object_id, match["type"], match["native_id"]),
            self._source_for(collection),
            match["facts"], opinions=self._opinions(collection, match),
            relationships=relationships,
            evidence_ref=f"/v1/network/{collection}/{object_id}/evidence",
        )

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        if collection == "links":
            payload = {"ip_addr": await anyio.to_thread.run_sync(_ip_json, ["-d", "addr", "show"]),
                       "lldp": await self._lldp_by_link()}
        elif collection == "routes":
            payload = {"ipv4": await anyio.to_thread.run_sync(_ip_json, ["route", "show"]),
                       "ipv6": await anyio.to_thread.run_sync(_ip_json, ["-6", "route", "show"])}
        elif collection == "resolver":
            payload = {"manager": await BUS.get_all(RESOLVE1, RESOLVE1_PATH, RESOLVE1_MANAGER),
                       "links": await self._link_dns()}
        elif collection == "nft-tables":
            payload = await anyio.to_thread.run_sync(_nft_json)
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
