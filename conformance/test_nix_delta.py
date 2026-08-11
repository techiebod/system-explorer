"""The generation-delta row builders, against synthetic trees.

These are pure functions over dicts and a temporary directory, so they need no
NixOS host — which matters, because every bug this code has had so far was a row
that reported a change and then rendered the two sides identically. Each case
below is one of them.
"""

from __future__ import annotations

import os
from pathlib import Path

from system_explorer.agent.adapters import nix


STORE = "/nix/store"
HASH_A = "a" * 32
HASH_B = "b" * 32


def test_package_row_pairs_an_upgrade_rather_than_splitting_it():
    rows = nix._package_rows(
        {"hello-2.12.1": f"{STORE}/{HASH_A}-hello-2.12.1"},
        {"hello-2.12.2": f"{STORE}/{HASH_B}-hello-2.12.2"})
    assert rows == [{"Kind": "package", "Name": "hello",
                     "From": "2.12.1", "To": "2.12.2"}]


def test_package_row_nulls_the_absent_side():
    added = nix._package_rows({}, {"tree-2.3.2": f"{STORE}/{HASH_A}-tree-2.3.2"})
    removed = nix._package_rows({"tree-2.3.2": f"{STORE}/{HASH_A}-tree-2.3.2"}, {})
    assert added == [{"Kind": "package", "Name": "tree", "From": None, "To": "2.3.2"}]
    assert removed == [{"Kind": "package", "Name": "tree", "From": "2.3.2", "To": None}]


def test_unchanged_packages_produce_no_rows():
    same = {"hello-2.12.1": f"{STORE}/{HASH_A}-hello-2.12.1"}
    assert nix._package_rows(same, same) == []


def test_input_row_that_restates_the_revision_is_suppressed():
    """A configuration's own source is usually also one of its inputs, so
    reporting both said the same thing twice."""
    rows = nix._delta_rows(
        {"revision": "aaa", "inputs": {"self": {"revision": "aaa"},
                                       "nixpkgs": {"revision": "1"}}},
        {"revision": "bbb", "inputs": {"self": {"revision": "bbb"},
                                       "nixpkgs": {"revision": "2"}}})
    assert rows == [
        {"Kind": "revision", "Name": "configuration", "From": "aaa", "To": "bbb"},
        {"Kind": "input", "Name": "nixpkgs", "From": "1", "To": "2"},
    ]


def test_an_input_moving_with_a_different_revision_is_still_reported():
    """The suppression matches the from/to pair, not the name, so an input that
    happens to be called self but moved differently must survive."""
    rows = nix._delta_rows(
        {"revision": "aaa", "inputs": {"self": {"revision": "xxx"}}},
        {"revision": "bbb", "inputs": {"self": {"revision": "yyy"}}})
    assert {"Kind": "input", "Name": "self", "From": "xxx", "To": "yyy"} in rows


def test_input_identity_falls_back_to_nar_hash():
    """A path or tarball input has no commit to name."""
    rows = nix._delta_rows(
        {"revision": "a", "inputs": {"local": {"narHash": "sha256-one"}}},
        {"revision": "a", "inputs": {"local": {"narHash": "sha256-two"}}})
    assert rows == [{"Kind": "input", "Name": "local",
                     "From": "sha256-one", "To": "sha256-two"}]


def build_etc(root: Path, entries: dict[str, str], files: dict[str, str]) -> str:
    """A miniature /etc: symlinks into a fake store, plus real sidecar files."""
    etc = root / "etc"
    etc.mkdir(parents=True)
    for name, target in entries.items():
        path = etc / name
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path)
    for name, text in files.items():
        path = etc / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return str(etc)


def test_etc_rows_name_the_files_that_changed(tmp_path):
    old_root = build_etc(
        tmp_path / "old",
        {"fstab": f"{STORE}/{HASH_A}-etc-fstab",
         "ssh/sshd_config": f"{STORE}/{HASH_A}-etc-sshd_config",
         "gone": f"{STORE}/{HASH_A}-etc-gone"},
        {"sudoers.gid": "0\n"})
    new_root = build_etc(
        tmp_path / "new",
        {"fstab": f"{STORE}/{HASH_A}-etc-fstab",
         "ssh/sshd_config": f"{STORE}/{HASH_B}-etc-sshd_config",
         "probe": f"{STORE}/{HASH_B}-etc-probe"},
        {"sudoers.gid": "1\n"})

    rows = nix._etc_rows(old_root, new_root,
                         nix._etc_entries(old_root), nix._etc_entries(new_root))
    by_name = {row["Name"]: row for row in rows}

    # Unchanged entries stay out of it.
    assert "etc/fstab" not in by_name
    # A changed symlink names the file, and the two sides differ visibly.
    changed = by_name["etc/ssh/sshd_config"]
    assert changed["From"] != changed["To"]
    assert changed["From"] and changed["To"]
    # Added and removed null the absent side.
    assert by_name["etc/probe"]["From"] is None
    assert by_name["etc/gone"]["To"] is None
    # A real file compares by content, not by name or mtime.
    assert by_name["etc/sudoers.gid"]["From"] != by_name["etc/sudoers.gid"]["To"]


def test_identical_etc_trees_produce_no_rows(tmp_path):
    entries = {"fstab": f"{STORE}/{HASH_A}-etc-fstab"}
    old_root = build_etc(tmp_path / "old", entries, {"mtab.mode": "0644\n"})
    new_root = build_etc(tmp_path / "new", entries, {"mtab.mode": "0644\n"})
    walked_old, walked_new = nix._etc_entries(old_root), nix._etc_entries(new_root)
    assert walked_old == walked_new
    # Same root string: nothing differs and no fallback row is invented.
    assert nix._etc_rows(old_root, old_root, walked_old, walked_new) == []


def test_differing_roots_with_no_file_difference_still_report_something(tmp_path):
    """Losing a change silently is worse than reporting it uselessly."""
    entries = {"fstab": f"{STORE}/{HASH_A}-etc-fstab"}
    old_root = build_etc(tmp_path / "old", entries, {})
    new_root = build_etc(tmp_path / "new", entries, {})
    rows = nix._etc_rows(f"{STORE}/{HASH_A}-etc/etc", f"{STORE}/{HASH_B}-etc/etc",
                         nix._etc_entries(old_root), nix._etc_entries(new_root))
    assert len(rows) == 1
    assert rows[0]["From"] != rows[0]["To"]


def test_a_symlinked_directory_is_followed(tmp_path):
    """NixOS builds those aggregates so /etc can declare their contents, and
    stopping at them reported "etc/systemd/system changed" without naming a unit."""
    target = tmp_path / "store-units"
    (target / "sockets.target.wants").mkdir(parents=True)
    (target / "polkit.service").write_text("x")
    (target / "sockets.target.wants" / "one.socket").write_text("y")
    root = build_etc(tmp_path / "gen", {"systemd/system": str(target)}, {})
    walked = nix._etc_entries(root)
    assert "systemd/system" in walked, "the link itself is still recorded"
    assert "systemd/system/polkit.service" in walked
    assert "systemd/system/sockets.target.wants/one.socket" in walked


def test_individual_units_are_named_rather_than_their_directory(tmp_path):
    old_units, new_units = tmp_path / "old-units", tmp_path / "new-units"
    for units, text in ((old_units, "old"), (new_units, "new")):
        units.mkdir(parents=True)
        (units / "polkit.service").write_text(text)
        (units / "steady.service").write_text("same")
    old_root = build_etc(tmp_path / "old", {"systemd/system": str(old_units)}, {})
    new_root = build_etc(tmp_path / "new", {"systemd/system": str(new_units)}, {})

    names = [r["Name"] for r in nix._etc_rows(
        old_root, new_root, nix._etc_entries(old_root), nix._etc_entries(new_root))]
    assert "etc/systemd/system/polkit.service" in names
    assert "etc/systemd/system/steady.service" not in names, "unchanged unit stays out"
    # The aggregate adds nothing once its members are named individually.
    assert "etc/systemd/system" not in names


def test_a_wholesale_directory_change_collapses_with_its_count(tmp_path):
    """terminfo is one symlink to ~2500 files that move together whenever ncurses
    does; listing them would bury the units an operator wants to see."""
    old_db, new_db = tmp_path / "old-db", tmp_path / "new-db"
    for db, text in ((old_db, "old"), (new_db, "new")):
        db.mkdir(parents=True)
        for index in range(nix.ETC_COLLAPSE_OVER + 5):
            (db / f"term{index}").write_text(text)
    old_root = build_etc(tmp_path / "old", {"terminfo": str(old_db)}, {})
    new_root = build_etc(tmp_path / "new", {"terminfo": str(new_db)}, {})

    rows = nix._etc_rows(old_root, new_root,
                         nix._etc_entries(old_root), nix._etc_entries(new_root))
    assert len(rows) == 1, rows
    # A summary, not a silent truncation: the row says how many.
    assert rows[0]["Name"].startswith("etc/terminfo (")
    assert f"{nix.ETC_COLLAPSE_OVER + 5} entries changed" in rows[0]["Name"]


def test_a_symlink_cycle_terminates(tmp_path):
    """The one shape here that is unbounded rather than merely large."""
    etc = tmp_path / "gen" / "etc"
    etc.mkdir(parents=True)
    os.symlink(".", etc / "loop")
    walked = nix._etc_entries(str(etc))
    assert "loop" in walked


def test_etc_identity_does_not_collapse_to_the_literal_etc():
    """$out/etc points at `<store path>/etc`, so a basename is "etc" for every
    generation ever built — which is how a change rendered as "etc -> etc"."""
    older = nix._etc_identity(f"{STORE}/{HASH_A}-etc/etc")
    newer = nix._etc_identity(f"{STORE}/{HASH_B}-etc/etc")
    assert older != newer
    assert older != "etc" and newer != "etc"


def test_abbreviation_never_hides_the_difference():
    """The -dirty suffix case: two identities differing only late must not both
    abbreviate to the same token."""
    before, after = nix._distinguishable("5867713451a1005c", "5867713451a1005c-dirty")
    assert before != after
    short_before, short_after = nix._distinguishable("aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb")
    assert (short_before, short_after) == ("aaaaaaaaaaaa", "bbbbbbbbbbbb")
