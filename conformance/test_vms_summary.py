"""The vms collection row survives every fact shape the adapter produces.

Regression, found live 2026-08-12: collect() built its row by indexing a
fixed key tuple into the facts dict, but _facts() emits the two address
facts in three mutually exclusive shapes (SPEC section 2, rule 7: observed;
null-with-reason; omitted as inapplicable). Only the middle shape sets both
keys, so a host whose domain was running-and-observed raised
KeyError('IPAddressesUnobservable') while a host whose domain was shut off
raised KeyError('IPAddresses') — one bug, two spellings, and the whole
collection dark on both hosts while /v1/status said "partial" to nobody.

summary_facts() is module-level and pure so these cases can feed it every
shape without a libvirt socket, and the row evaluators run over each result
exactly as collect() composes them — the same evaluator both places is
rule 14, and a shape the summary tolerates must be one the rules tolerate.
"""

from system_explorer.agent.adapters.vms import summary_facts
from system_explorer.agent.rules.vms import (domain_address_opinions,
                                             domain_opinions)

ALWAYS = ("State", "MemoryMiB", "VCPUs", "Autostart", "Persistent", "HostTaps")

# Everything _facts() always carries, including keys the summary does not
# take (UUID, NICs, ...) so the subset selection itself is exercised.
BASE = {
    "MemoryMiB": 2048, "VCPUs": 2, "Autostart": False, "Persistent": True,
    "UUID": "0e2a3c1e-6f7b-4d55-9f3e-2f2f4b7a2f00",
    "NICs": [], "Disks": [], "Bridges": [], "HostTaps": ["vnet4"],
    "PassedThroughDevices": [],
}


def test_observed_shape_keeps_addresses_and_omits_the_reason_fact():
    facts = {**BASE, "State": "running",
             "IPAddresses": {"52:54:00:12:34:56": ["192.168.200.80"]}}
    summary = summary_facts(facts)
    assert summary["IPAddresses"] == facts["IPAddresses"]
    assert "IPAddressesUnobservable" not in summary
    for key in ALWAYS:
        assert key in summary
    assert domain_opinions(summary) == []
    assert domain_address_opinions(summary) == []


def test_unobservable_shape_keeps_the_null_and_its_reason():
    note = ("no address source could answer (guest agent forbidden read-only;"
            " no libvirt lease; ARP aged out)")
    facts = {**BASE, "State": "running",
             "IPAddresses": None, "IPAddressesUnobservable": note}
    summary = summary_facts(facts)
    assert summary["IPAddresses"] is None
    assert summary["IPAddressesUnobservable"] == note
    fired = {(op["key"], op["level"])
             for op in domain_address_opinions(summary)}
    assert fired == {("domain-address-unobservable", "info")}


def test_not_running_shape_carries_neither_address_fact():
    # A shut-off domain omits both facts as inapplicable (rule 7, third arm).
    facts = {**BASE, "State": "shutoff", "Autostart": True}
    summary = summary_facts(facts)
    assert "IPAddresses" not in summary
    assert "IPAddressesUnobservable" not in summary
    for key in ALWAYS:
        assert key in summary
    # The row evaluators still see the shape they need: autostart-but-off
    # warns, and the address rule stays silent on a domain that is off.
    fired = {(op["key"], op["level"]) for op in domain_opinions(summary)}
    assert fired == {("domain-health", "warn")}
    assert domain_address_opinions(summary) == []


def test_summary_takes_only_its_declared_subset():
    facts = {**BASE, "State": "running",
             "IPAddresses": {"52:54:00:12:34:56": ["192.168.200.80"]}}
    summary = summary_facts(facts)
    assert "UUID" not in summary
    assert "NICs" not in summary
    assert "PassedThroughDevices" not in summary
