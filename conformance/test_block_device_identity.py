"""One row per block device, however many parents lsblk lists it under.

SPEC rule 15 makes the object id the identity a consumer keys on, and
lsblk -J breaks it for md: the array is listed as a child of EVERY member it
was assembled from, so a two-disk mirror publishes the array node twice.
Walking that tree and emitting a row per appearance put block-device:md126 in
one collection page twice (measured live, 2026-08-13, GET
/v1/storage/block-devices) — which makes `total` overstate what exists and
get_object's matches[0] an arbitrary choice between rows that differ.

The fixture below is a synthetic two-member mirror: example serials, no
estate device names.
"""

import asyncio

import pytest

from system_explorer.agent.adapters import storage

# lsblk -J -o NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL,ROTA,RM,TRAN
# on a host with one md mirror across two disks. The array node — and its
# partition — appear once under each member, which is what lsblk really does:
# containment here is a graph, not a tree.
MIRROR_NODE = {
    "name": "md126", "kname": "md126", "type": "raid1", "size": "1.8T",
    "fstype": "ext4", "mountpoints": ["/srv"], "model": None,
    "serial": None, "rota": True, "rm": False, "tran": None,
    "children": [
        {"name": "md126p1", "kname": "md126p1", "type": "part",
         "size": "1.8T", "fstype": "ext4", "mountpoints": ["/srv"],
         "model": None, "serial": None, "rota": True, "rm": False,
         "tran": None},
    ],
}


def _member(disk: str, serial: str) -> dict:
    return {
        "name": disk, "kname": disk, "type": "disk", "size": "1.8T",
        "fstype": None, "mountpoints": [None], "model": "EXAMPLE-MODEL",
        "serial": serial, "rota": True, "rm": False, "tran": "sata",
        "children": [
            {"name": f"{disk}1", "kname": f"{disk}1", "type": "part",
             "size": "1.8T", "fstype": "linux_raid_member",
             "mountpoints": [None], "model": None, "serial": None,
             "rota": True, "rm": False, "tran": None,
             # The same node object under both members, exactly as lsblk
             # renders the array twice.
             "children": [MIRROR_NODE]},
        ],
    }


TWO_MEMBER_MIRROR = {"blockdevices": [_member("sda", "EXAMPLE0001"),
                                      _member("sdb", "EXAMPLE0002")]}


@pytest.fixture
def block_items(monkeypatch):
    monkeypatch.setattr(storage, "_lsblk", lambda: TWO_MEMBER_MIRROR)
    return asyncio.run(storage.Adapter()._block_items())


def test_the_mirrored_array_is_one_object_not_two(block_items):
    """The bug, pinned. Two appearances, one identity."""
    ids = [item["id"] for item in block_items]
    assert ids.count("block-device:md126") == 1, (
        f"block-device:md126 appears {ids.count('block-device:md126')} times "
        "in one page")
    assert len(ids) == len(set(ids)), (
        f"duplicate object ids: {sorted({i for i in ids if ids.count(i) > 1})}")


def test_the_page_counts_what_exists(block_items):
    """`total` is what a consumer sizes a fetch loop and a capacity claim
    from; per-appearance rows inflated it by one per extra mirror member."""
    page = asyncio.run(storage.Adapter().collect("block-devices", {}, None, None))
    assert page["total"] == len(block_items) == 6
    assert {item["id"] for item in page["items"]} == {
        "block-device:sda", "block-device:sda1", "block-device:sdb",
        "block-device:sdb1", "block-device:md126", "block-device:md126p1"}


def test_the_array_states_every_member_it_is_assembled_from(block_items):
    """The parents are where truth beats tidiness: keeping only the first
    would say the array is assembled from sda1, which is false — and the
    falsehood would travel as a member-of relationship."""
    array = next(item for item in block_items if item["id"] == "block-device:md126")
    assert array["facts"]["Parents"] == ["sda1", "sdb1"]
    disk = next(item for item in block_items if item["id"] == "block-device:sda")
    assert disk["facts"]["Parents"] == []


def test_depth_is_the_first_path_to_a_device_reachable_by_several(block_items):
    """A multi-parent device HAS no single tree coordinate, so depth states
    the first path to it rather than a truth about it — small enough to
    honour, and the Parents fact is what stops it reading as the whole
    story. Children keep counting from that first appearance."""
    by_id = {item["id"]: item for item in block_items}
    assert by_id["block-device:sda"]["depth"] == 0
    assert by_id["block-device:sda1"]["depth"] == 1
    assert by_id["block-device:md126"]["depth"] == 2
    assert by_id["block-device:md126p1"]["depth"] == 3
    # The second member is still a root, and its partition still its child:
    # deduplicating the array must not renumber the tree around it.
    assert by_id["block-device:sdb"]["depth"] == 0
    assert by_id["block-device:sdb1"]["depth"] == 1


def test_every_parent_becomes_its_own_relationship(monkeypatch):
    """One member-of edge per parent, from the row's own fact — the shape a
    cross-object trace walks."""
    monkeypatch.setattr(storage, "_lsblk", lambda: TWO_MEMBER_MIRROR)
    monkeypatch.setattr(storage, "_md_holders", lambda kname: [])
    adapter = storage.Adapter()
    array = next(item for item in asyncio.run(adapter._block_items())
                 if item["id"] == "block-device:md126")
    rels = asyncio.run(adapter._relationships("block-devices", array))
    parents = [rel["target"]["id"] for rel in rels
               if rel["type"] == "member-of" and rel["direction"] == "out"
               and rel["target"]["id"].startswith("block-device:")]
    assert parents == ["block-device:sda1", "block-device:sdb1"]


def test_a_plain_tree_is_unchanged():
    """No md, no duplication: the ordinary host must keep the exact walk it
    had, depth-first and in lsblk's order."""
    plain = {"blockdevices": [
        {"name": "nvme0n1", "type": "disk", "children": [
            {"name": "nvme0n1p1", "type": "part"},
            {"name": "nvme0n1p2", "type": "part"},
        ]},
    ]}
    walked = [(node["name"], parents, depth)
              for node, parents, depth in storage._flatten_devices(plain["blockdevices"])]
    assert walked == [("nvme0n1", [], 0),
                      ("nvme0n1p1", ["nvme0n1"], 1),
                      ("nvme0n1p2", ["nvme0n1"], 1)]
