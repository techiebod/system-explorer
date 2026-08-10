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
from ..rules import worst_level
from ..rules.vms import domain_opinions

SOCKET_RO = "/var/run/libvirt/libvirt-sock-ro"
URI = "qemu:///system"

STATES = {0: "nostate", 1: "running", 2: "blocked", 3: "paused",
          4: "shutdown", 5: "shutoff", 6: "crashed", 7: "pmsuspended"}

REFERENCE = ["virsh list --all", "virsh dominfo <name>", "virsh dumpxml <name>"]


def _interface_addresses(dom) -> tuple[dict[str, list[str]], str | None]:
    """IPs by MAC. Guest-agent data is richest but usually needs more than a
    read-only connection; the host ARP table covers bridged guests. Returns
    (mac -> ips, note-when-degraded)."""
    import libvirt

    for source, label in (
        (libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT, "guest-agent"),
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
            note = None if label == "guest-agent" else (
                "IP addresses from the host ARP table "
                "(guest agent needs more than read-only access).")
            return by_mac, note
    return {}, "No IP source available (no guest agent access, nothing in ARP)."


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
            ips, ip_note = ({}, None)
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
    disks, nics, hostdevs = [], [], []
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
                def hexpart(key: str) -> int:
                    return int(addr.get(key) or "0", 16)
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


class Adapter:
    subsystem = "vms"

    def collections(self) -> list[str]:
        return ["domains"]

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
                    "reason": "read-only socket exists but openReadOnly failed: "
                              f"{str(exc)[:140]}"}
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
        return {
            "State": dom["state"],
            "IPAddresses": sorted({ip for ips in dom["ips_by_mac"].values() for ip in ips}),
            "MemoryMiB": dom["memory_mib"],
            "MaxMemoryMiB": dom["max_memory_mib"],
            "VCPUs": dom["vcpus"],
            "Autostart": dom["autostart"],
            "Persistent": dom["persistent"],
            "UUID": dom["uuid"],
            "NICs": nics,
            "Disks": disks,
            "Bridges": sorted({n["Bridge"] for n in nics if n.get("Bridge")}),
            "PassedThroughDevices": hostdevs,
        }

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        self._check(collection)
        items = []
        for dom in await anyio.to_thread.run_sync(_domains_raw):
            facts = self._facts(dom)
            summary = {k: facts[k] for k in
                       ("State", "IPAddresses", "MemoryMiB", "VCPUs", "Autostart", "Persistent")}
            # Rules see the summary facts (State and Autostart both there), so
            # the row carries the same worst opinion an opened object would.
            worst = worst_level(domain_opinions(summary),
                                healthy="ok" if dom["state"] == "running" else "info")
            items.append(env.item_summary(f"domain:{dom['name']}", "domain",
                                          dom["name"], summary,
                                          worst_opinion_level=worst))
        items = env.apply_fact_filters(items, query)
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
        opinions = domain_opinions(facts)

        relationships = [env.rel("attached-to", "out", f"link:{bridge}", subsystem="network")
                         for bridge in facts["Bridges"]]
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
            evidence_ref=f"/v1/vms/domains/{object_id}/evidence",
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
