"""vms subsystem: libvirt domains over the read-only socket.

libvirt-python with virConnectOpenReadOnly — the connection cannot mutate
domain state by construction. Disk paths and bridge attachments come from
the domain XML; the bridge edge points into the network subsystem.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET

import anyio

from .. import envelope as env
from ..rules.vms import domain_address_opinions, domain_opinions

SOCKET_RO = "/var/run/libvirt/libvirt-sock-ro"
URI = "qemu:///system"

STATES = {0: "nostate", 1: "running", 2: "blocked", 3: "paused",
          4: "shutdown", 5: "shutoff", 6: "crashed", 7: "pmsuspended"}

REFERENCE = ["virsh list --all", "virsh dominfo <name>", "virsh dumpxml <name>"]

# The row's fact subset, in display order. Keys are copied only when the
# object carries them: _facts() emits the address facts in three mutually
# exclusive shapes (addresses observed; running but unobservable — null with
# a reason sibling; not running — both omitted as inapplicable, rule 7), and
# a copy that indexed the tuple unconditionally assumed the one shape that
# sets the pair. Every domain in either other shape blanked its host's whole
# collection: found live on two deployed hosts at once, 2026-08-12, as two
# different KeyErrors from one deploy. Present-only is the rule for EVERY
# key, not an allowlist of the two that broke — omission is a legitimate
# shape for any fact under rule 7, so the next conditionally-emitted fact
# must not be able to reintroduce the outage by missing a second table.
_SUMMARY_KEYS = ("State", "IPAddresses", "IPAddressesUnobservable",
                 "MemoryMiB", "VCPUs", "Autostart", "Persistent", "HostTaps")


def summary_facts(facts: dict) -> dict:
    """The collection-row subset of a domain's facts, shape-tolerant.

    Module-level and pure so conformance can feed it every shape _facts()
    produces without a libvirt socket — the failure this guards against
    reached two deployed hosts before any test saw it.
    """
    return {k: facts[k] for k in _SUMMARY_KEYS if k in facts}


# Which source an address came from is a provenance fact the operator needs:
# a lease is a record with a lifetime, ARP is a cache that expires, and the
# guest agent sees interfaces the host cannot.
ADDRESS_SOURCE_NOTES = {
    "guest-agent": None,
    "dhcp-lease": "IP addresses from the DHCP lease libvirt holds for this "
                  "guest (the guest agent needs more than read-only access).",
    "arp": "IP addresses from the host ARP table, which expires when a guest "
           "goes idle (the guest agent needs more than read-only access).",
}


def _interface_addresses(dom) -> tuple[dict[str, list[str]], str | None]:
    """IPs by MAC, from the best source that will answer.

    Three sources, deliberately in this order (mac -> ips, note-when-degraded):

    - guest-agent is richest (every interface the guest itself sees), and
      libvirt refuses it outright on a read-only connection: "operation
      forbidden: read only access prevents virDomainInterfaceAddresses". This
      agent only ever opens read-only, so in practice it never answers — it
      stays first so a future privileged deployment gets the better data.
    - DHCP lease is authoritative for guests on a libvirt-managed network and
      works read-only. It was missing, and its absence is what made a running
      guest show a blank address: the guest had gone quiet, its ARP entry
      aged out, and the row emptied while dnsmasq still held a valid lease.
      A lease is a statement of record with a lifetime; ARP is a cache.
    - ARP covers guests on a bridge this host does not manage a lease file
      for, which the lease source cannot see at all.
    """
    import libvirt

    for source, label in (
        (libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT, "guest-agent"),
        (libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE, "dhcp-lease"),
        (libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_ARP, "arp"),
    ):
        try:
            raw = dom.interfaceAddresses(source)
        except libvirt.libvirtError:
            continue
        by_mac: dict[str, list[str]] = {}
        for iface in raw.values():
            mac = iface.get("hwaddr")
            if not mac:
                continue
            ips = [a["addr"] for a in iface.get("addrs") or [] if a.get("addr")]
            if ips:
                by_mac.setdefault(mac, []).extend(ips)
        if by_mac:
            return by_mac, ADDRESS_SOURCE_NOTES.get(label)
    # Say which sources were asked, so a blank address column is traceable
    # rather than mysterious — an empty list here means "nobody could tell us",
    # not "this guest has no address".
    return {}, ("No address source answered: the guest agent is unavailable on "
                "a read-only libvirt connection, no DHCP lease is held for this "
                "guest, and the host ARP table has no entry for it (an idle "
                "guest's entry expires).")


def _probe_connection() -> None:
    import libvirt  # deferred: only vm hosts need the C library present

    libvirt.openReadOnly(URI).close()


def _domains_raw() -> list[dict]:
    import libvirt  # deferred: only vm hosts need the C library present

    conn = libvirt.openReadOnly(URI)
    try:
        out = []
        for dom in conn.listAllDomains():
            state, max_kib, cur_kib, vcpus, _cpu_time = dom.info()
            ips: dict[str, list[str]] = {}
            ip_note: str | None = None
            if state == 1:  # running
                ips, ip_note = _interface_addresses(dom)
            out.append({
                "name": dom.name(),
                "uuid": dom.UUIDString(),
                "state": STATES.get(state, str(state)),
                "memory_mib": round(cur_kib / 1024),
                "max_memory_mib": round(max_kib / 1024),
                "vcpus": vcpus,
                "autostart": bool(dom.autostart()),
                "persistent": bool(dom.isPersistent()),
                "xml": dom.XMLDesc(0),
                "ips_by_mac": ips,
                "ip_note": ip_note,
            })
        return out
    finally:
        conn.close()


def _devices(xml: str) -> tuple[list[dict], list[dict], list[dict]]:
    """(disks, NICs, passed-through hostdevs) from domain XML."""
    disks: list[dict] = []
    nics: list[dict] = []
    hostdevs: list[dict] = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return disks, nics, hostdevs
    for disk in root.findall("./devices/disk"):
        source = disk.find("source")
        target = disk.find("target")
        driver = disk.find("driver")
        disks.append({
            "Source": (source.get("file") or source.get("dev")) if source is not None else None,
            "Target": target.get("dev") if target is not None else None,
            "Bus": target.get("bus") if target is not None else None,
            "Format": driver.get("type") if driver is not None else None,
            "Device": disk.get("device"),
            "ReadOnly": disk.find("readonly") is not None,
        })
    for iface in root.findall("./devices/interface"):
        mac = iface.find("mac")
        source = iface.find("source")
        nic = {"MAC": mac.get("address") if mac is not None else None,
               "Bridge": source.get("bridge") if source is not None else None}
        target = iface.find("target")
        if target is not None and target.get("dev"):
            nic["HostTap"] = target.get("dev")
        nics.append(nic)
    for hostdev in root.findall("./devices/hostdev"):
        kind = hostdev.get("type")
        source = hostdev.find("source")
        if source is None:
            continue
        if kind == "pci":
            addr = source.find("address")
            if addr is not None:
                # addr binds as a default, not a closure: same-iteration use
                # is safe today, but a closure over a loop variable is one
                # refactor from reading a later iteration's element.
                def hexpart(key: str, _addr: ET.Element = addr) -> int:
                    return int(_addr.get(key) or "0", 16)
                hostdevs.append({"Type": "pci", "Address":
                                 f"{hexpart('domain'):04x}:{hexpart('bus'):02x}"
                                 f":{hexpart('slot'):02x}.{hexpart('function'):x}"})
        elif kind == "usb":
            # USB identity lives in <source><vendor id=…/><product id=…/>;
            # <address> only carries bus/device numbers.
            vendor = source.find("vendor")
            product = source.find("product")
            hostdevs.append({"Type": "usb", "VendorProduct": ":".join(
                ((el.get("id") or "?").removeprefix("0x") if el is not None else "?")
                for el in (vendor, product))})
    return disks, nics, hostdevs


# Documents the fact whose whole purpose is to be read: a null address with no
# stated reason is exactly the ambiguity this sibling removes. State is on
# conformance's UNDOCUMENTED_EVIDENCE register — a stated gap, not a silent one.
_DOMAIN_GLOSSARY = {
    "IPAddressesUnobservable": (
        "Why this running guest's address could not be determined. It appears "
        "with a null IPAddresses, and the pair means the guest has an address "
        "that this agent cannot see — not that it has none. Normal for a "
        "bridged guest: the guest agent needs more than a read-only libvirt "
        "connection, libvirt sees leases only from its own DHCP server, and the "
        "host's ARP entry expires while the guest is idle."
    ),
}


class Adapter:
    subsystem = "vms"

    def collections(self) -> list[str]:
        return ["domains"]

    def fact_glossary(self, collection: str) -> dict[str, str]:
        return _DOMAIN_GLOSSARY if collection == "domains" else {}

    async def capability(self) -> dict:
        """Socket presence alone is optimistic; open the read-only connection
        so the reason distinguishes missing socket from unanswering daemon."""
        if not os.path.exists(SOCKET_RO):
            return {"available": False,
                    "reason": f"no libvirt read-only socket at {SOCKET_RO}"}
        try:
            await anyio.to_thread.run_sync(_probe_connection)
        except ImportError:
            # A hypervisor is running but the bindings are absent — a
            # deployment gap, not a broken daemon, and worth saying so
            # plainly. libvirt-python is the [vms] extra: `pip install
            # system-explorer[vms]`, python3-libvirt on Debian/Ubuntu,
            # python3-libvirt on Fedora, or withVms on the nix package.
            return {"available": False,
                    "reason": f"libvirt is listening on {SOCKET_RO} but the "
                              "libvirt-python bindings are not installed "
                              "(the [vms] extra)"}
        except Exception as exc:  # noqa: BLE001 - the reason is the fact
            return {"available": False,
                    "reason": env.reason(
                        f"read-only socket exists but openReadOnly failed: {exc}")}
        return {"available": True, "collections": self.collections()}

    def _check(self, collection: str) -> None:
        if collection != "domains":
            raise env.UnknownCollection(collection)

    @staticmethod
    def _facts(dom: dict) -> dict:
        disks, nics, hostdevs = _devices(dom["xml"])
        for nic in nics:
            if nic.get("MAC") and dom["ips_by_mac"].get(nic["MAC"]):
                nic["IPs"] = dom["ips_by_mac"][nic["MAC"]]
        addresses = sorted({ip for ips in dom["ips_by_mac"].values() for ip in ips})
        facts = {
            "State": dom["state"],
            "MemoryMiB": dom["memory_mib"],
            "MaxMemoryMiB": dom["max_memory_mib"],
            "VCPUs": dom["vcpus"],
            "Autostart": dom["autostart"],
            "Persistent": dom["persistent"],
            "UUID": dom["uuid"],
            "NICs": nics,
            "Disks": disks,
            "Bridges": sorted({n["Bridge"] for n in nics if n.get("Bridge")}),
            # The host-side tap devices this domain owns. Already parsed per
            # NIC; lifted to its own fact because it is the ONLY authoritative
            # answer to "which domain owns vnet4", and network/links cannot
            # derive it — a tap carries no domain identity in sysfs, and the
            # fe:54:/52:54: MAC resemblance is a QEMU convention, not a
            # record. Without this the operator meets four unattributed vnet
            # rows and a bridge (seen on a VM host, 2026-08-11).
            "HostTaps": sorted({n["HostTap"] for n in nics if n.get("HostTap")}),
            "PassedThroughDevices": hostdevs,
        }
        # SPEC section 2 rule 7, third arm: the value exists and this agent
        # cannot see it, so the fact is null and a sibling carries the reason.
        # An empty list said "this guest has no addresses", which is a different
        # and false claim — an appliance guest read [] while sitting on
        # 192.168.200.80, because all three libvirt sources happened to be
        # silent at once. For a BRIDGED guest that is the normal case, not a
        # transient one: the guest agent needs more than a read-only connection,
        # libvirt only sees leases from its own dnsmasq (an externally-leased
        # guest has none it can read), and the host ARP entry ages out.
        #
        # A guest that is not running is a different statement again: it has no
        # address because it is off, which is inapplicability, so the fact is
        # omitted rather than nulled.
        if addresses:
            facts["IPAddresses"] = addresses
        elif dom["state"] == "running":
            facts["IPAddresses"] = None
            if dom.get("ip_note"):
                facts["IPAddressesUnobservable"] = dom["ip_note"]
        return facts

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        """The full materialisation, shared: collect() pages it and main.py's
        status/snapshot/changes sweeps consume it directly instead of
        re-acquiring per page. Single-flighted so concurrent callers ride one
        domain walk (envelope.single_flight — coalescing, not caching).
        get_object() does NOT search this list: the summary rows drop the
        domain XML and address-source note it builds from, so it keeps its
        own _find() over the raw walk."""
        self._check(collection)
        items = []
        for dom in await anyio.to_thread.run_sync(_domains_raw):
            facts = self._facts(dom)
            # HostTaps rides on the ROW, not just the opened object: the
            # consumer that needs it is looking at network/links and wants to
            # name every tap from one request, without opening each domain.
            summary = summary_facts(facts)
            # Rules see the summary facts (State and Autostart both there), so
            # the row carries the same worst opinion an opened object would.
            item = env.item_summary(
                f"domain:{dom['name']}", "domain", dom["name"], summary,
                opinions=domain_opinions(summary) + domain_address_opinions(summary),
                healthy="ok" if dom["state"] == "running" else "info")
            # Law 1: the UUID is the one identifier that survives a rename,
            # and it was read, used and dropped. Without it the collator keys
            # a domain on its NAME alone, so `virsh domrename` retires the
            # object and mints a new one — the domain's whole history gone,
            # and nothing anywhere saying it was the same guest.
            if dom.get("uuid"):
                item["names"] = {"stable": {"uuid": dom["uuid"]}}
            items.append(item)
        return items

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        items = env.apply_fact_filters(await self.acquire(collection), query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(
            self.subsystem, collection,
            env.source("libvirt-ro", "libvirt (read-only)", REFERENCE,
                       method="listAllDomains"),
            page, applied, next_cursor, requested_limit=limit,
            total=total, filters=query or None)

    async def _find(self, object_id: str) -> dict:
        if not object_id.startswith("domain:"):
            raise env.UnknownObject(object_id)
        name = object_id.split(":", 1)[1]
        for dom in await anyio.to_thread.run_sync(_domains_raw):
            if dom["name"] == name:
                return dom
        raise env.UnknownObject(object_id)

    async def get_object(self, collection: str, object_id: str) -> dict:
        self._check(collection)
        dom = await self._find(object_id)
        facts = self._facts(dom)

        # Same evaluator as the summary path (agent/rules/vms.py) — rows and
        # opened objects cannot disagree.
        opinions = domain_opinions(facts) + domain_address_opinions(facts)

        relationships = [env.rel("attached-to", "out", f"link:{bridge}", subsystem="network")
                         for bridge in facts["Bridges"]]
        # The tap edge, distinct from the bridge edge: the bridge is shared by
        # every guest on the network, the tap belongs to this domain alone, so
        # it is the edge that actually attributes a link to a workload.
        relationships += [env.rel("owns", "out", f"link:{tap}", subsystem="network")
                          for tap in facts["HostTaps"]]
        relationships += [env.rel("backs", "in", f"file:{d['Source']}")
                          for d in facts["Disks"] if d.get("Source")]
        relationships += [env.rel("attached-to", "out", f"pci:{d['Address']}",
                                  subsystem="hardware")
                          for d in facts["PassedThroughDevices"]
                          if d.get("Type") == "pci" and d.get("Address")]

        return env.observation(
            self.subsystem, env.obj_ref(object_id, "domain", dom["name"]),
            env.source("libvirt-ro", "libvirt (read-only)", REFERENCE,
                       method="listAllDomains + XMLDesc + interfaceAddresses",
                       notes=[dom["ip_note"]] if dom.get("ip_note") else None),
            facts, opinions=opinions, relationships=relationships,
            evidence_ref=env.evidence_ref("vms", "domains", object_id),
        )

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        self._check(collection)
        dom = await self._find(object_id)
        return {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": "libvirt (read-only)",
            "method": "XMLDesc",
            "payload": {"info": {k: v for k, v in dom.items() if k != "xml"},
                        "domain_xml": dom["xml"]},
        }
