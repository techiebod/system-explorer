"""VM opinions: libvirt domain state and autostart intent.

State names are libvirt's own (adapters/vms.py STATES). Running is the only
positively-healthy state; shutoff is neutral unless the domain is marked
autostart — then something meant to be up is down.
"""

from __future__ import annotations

from .. import envelope as env


def domain_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    state = facts.get("State")
    if state == "crashed":
        opinions.append(env.opinion(
            "domain-health", "critical", "Domain has crashed.", ["State"]))
    if state in ("paused", "blocked"):
        opinions.append(env.opinion(
            "domain-health", "warn", f"Domain is {state}.", ["State"]))
    if state == "shutoff" and facts.get("Autostart"):
        opinions.append(env.opinion(
            "domain-health", "warn",
            "Domain is marked autostart but is shut off.",
            ["State", "Autostart"]))
    return opinions


def domain_address_opinions(facts: dict) -> list[dict]:
    """A running guest whose address nothing could observe.

    The row used to say `ok` beside an empty address list, which is the shape
    this whole level exists to prevent: the agent vouching for something it
    could not see. tub's unifi-os read `IPAddresses: []` with a healthy row
    while answering on 192.168.200.80 — and the very next poll showed the
    address, because a ping in between had repopulated the host's ARP table.
    An observation that changes when you observe it is not a health verdict.

    info, not warn: for a bridged guest leased by an external DHCP server this
    is the ordinary state, not a fault. The guest agent needs more than a
    read-only libvirt connection, libvirt only sees leases from its own dnsmasq,
    and the host's ARP entry ages out when the guest is idle. Nothing is wrong;
    the agent simply cannot answer, and should say so rather than imply an
    answer of "none".
    """
    if facts.get("State") != "running":
        return []
    if not facts.get("IPAddressesUnobservable"):
        return []
    return [env.opinion(
        "domain-address-unobservable", "info",
        "No address source could answer for this running guest, so its address "
        "is unknown rather than absent: " + str(facts["IPAddressesUnobservable"]),
        ["State", "IPAddressesUnobservable"])]
