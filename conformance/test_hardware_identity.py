"""The world-wide name, taken the same way on both drive families.

hardware/scsi carried WWN from the day it shipped; hardware/nvme never did.
That is one identity fact treated two ways inside one subsystem, and identity
is what every join in the product is made of — a kernel name renumbers
(`nvme0n1` returns as `nvme1n1` when enumeration order shifts, which on a
four-drive host is not hypothetical) and a wwid does not.

The obvious source is wrong, which is the reason this file exists rather than
a one-line change: udisks2 exposes `Drive.WWN` and it is the EMPTY STRING on
every NVMe drive on this estate. Reading it would publish a fact that asserts
an identity and carries none — worse than the gap it appears to close.
"""

from __future__ import annotations

from system_explorer.agent.adapters import hardware


def fake_reads(monkeypatch, table):
    monkeypatch.setattr(hardware, "_read", lambda path: table.get(path))


def test_a_single_namespace_lends_its_wwid_to_the_controller(monkeypatch):
    """The universal case on real hardware: one controller, one namespace, so
    the namespace's identity is the device's."""
    fake_reads(monkeypatch, {"/sys/block/nvme0n1/wwid": "eui.0025385A71B0F2C6"})
    assert hardware._nvme_wwn(["nvme0n1"]) == {"WWN": "eui.0025385A71B0F2C6"}


def test_several_namespaces_agreeing_still_name_the_device(monkeypatch):
    fake_reads(monkeypatch, {"/sys/block/nvme0n1/wwid": "eui.AAAA",
                             "/sys/block/nvme0n2/wwid": "eui.AAAA"})
    assert hardware._nvme_wwn(["nvme0n1", "nvme0n2"]) == {"WWN": "eui.AAAA"}


def test_several_namespaces_disagreeing_say_so_rather_than_picking_one(monkeypatch):
    """A wwid belongs to a namespace. Taking the first would publish one
    namespace's identity as the controller's, which is the quiet kind of wrong
    — every later join would follow it."""
    fake_reads(monkeypatch, {"/sys/block/nvme0n1/wwid": "eui.AAAA",
                             "/sys/block/nvme0n2/wwid": "eui.BBBB"})
    facts = hardware._nvme_wwn(["nvme0n1", "nvme0n2"])
    assert "WWN" not in facts
    assert "namespace" in facts["WWNUnobservable"]


def test_an_unreadable_wwid_yields_no_fact_rather_than_an_empty_one(monkeypatch):
    """The udisks2 failure mode, refused at the source that replaced it: an
    empty string is not an identity, and publishing one is worse than absence
    because a join would key on it."""
    fake_reads(monkeypatch, {"/sys/block/nvme0n1/wwid": ""})
    assert hardware._nvme_wwn(["nvme0n1"]) == {"WWN": None}
    fake_reads(monkeypatch, {})
    assert hardware._nvme_wwn(["nvme0n1"]) == {"WWN": None}


def test_a_controller_with_no_namespaces_claims_nothing(monkeypatch):
    fake_reads(monkeypatch, {})
    assert hardware._nvme_wwn([]) == {}


def test_both_drive_families_name_the_fact_the_same_way():
    """The point of the change. A consumer joining on identity must not have to
    know which kind of drive it is looking at — and the sentence has to be true
    of both, because the two families share one glossary."""
    adapter = hardware.Adapter()
    for collection in ("scsi", "nvme"):
        entry = adapter.fact_glossary(collection).get("WWN")
        assert entry, f"{collection} publishes WWN and does not document it"
        assert "NVMe" in entry and "SCSI" in entry, (
            "the shared entry must say where the read comes from on each family")
