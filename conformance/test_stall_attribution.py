"""A slice's stall belongs to the unit inside it, or to nobody, or to neither.

Per-unit PSI made attribution possible and immediately produced a second
problem: the slice CONTAINING the stalling unit reports the same stall, so an
overview listing the worst stalls showed a container scope at 65.27% and,
directly beneath it, the system.slice holding it at 56.35% — one condition,
twice, the second time with the culprit's name taken off. The arithmetic is
why the slice row is always the weaker of the two: a cgroup's "full" share
counts only the time in which every non-idle task in it AND its descendants
was stalled, so a member that is making progress lowers it. A member that
caused the stall reads at least as high; a slice that no member matches is
stalling as a whole, which is a different and much more interesting claim.

The adapter's join is what these fix. It runs inside the units collection —
the cgroup tree the kernel aggregates over is the tree the pressure walk
already reads — and it has to distinguish three answers, never two: explained,
unexplained, and could-not-be-established. Collapsing the third into the
second is this product's characteristic failure (a reading that was not taken
reported as a reading of zero), and it is the one an operator would act on,
since "nothing inside this slice explains it" is precisely the finding worth
someone's night.

The second half covers the join in the other direction: docker publishes the
scope its container runs in, so that a units row named for nothing but a
hexadecimal id can be turned back into a container. That name is derived, not
observed, so the spelling is checked against the pattern units.py reads it
back with rather than against a comment.
"""

import errno
import os

import pytest

from system_explorer.agent import envelope as env
from system_explorer.agent.adapters import docker as docker_adapter
from system_explorer.agent.adapters import units as units_adapter
from system_explorer.agent.rules import units as units_rules

IO = "PsiIoFullAvg60"
MEMORY = "PsiMemoryFullAvg60"
CPU = "PsiCpuSomeAvg60"

# A container id, invented here. Real estate names never appear in the suite,
# and an id is exactly the thing a reader cannot recognise anyway — which is
# the whole reason the scope fact exists.
CONTAINER_ID = ("4d1f9c02ab77e3b1c58d0f6a92e4173b"
                "8c5a0d2f6e91b47c3a8d5f0e2b1c7a49")


def nodes(*spec: tuple[str, str | None, dict]) -> dict[str, dict]:
    """The node map _pressure_nodes() produces, built from (name, parent,
    readings). Depth and path are derived from the parent chain so a case
    states the shape it means and nothing else.

    Every name here is unique, which is exactly what this helper cannot say
    anything about: a cgroup basename repeats across the real tree, and the
    graft that follows from joining on one is only visible to the walk tests
    below, which build directories instead of dicts.
    """
    built = {name: {"facts": dict(readings), "parent": parent, "depth": 0,
                    "path": "", "unit": True, "managed": True, "pruned": False}
             for name, parent, readings in spec}
    for name, node in built.items():
        chain = [name]
        walk = node["parent"]
        while walk:
            chain.append(walk)
            walk = built[walk]["parent"]
        node["depth"] = len(chain) - 1
        node["path"] = "/".join([units_adapter.CGROUP_ROOT, *reversed(chain)])
        # Derived, not asserted: a cgroup is this host's systemd's only where
        # every cgroup above it is a slice, and a fixture that claimed
        # otherwise would prove the delegation rule against a tree systemd
        # cannot build.
        node["managed"] = all(above.endswith(".slice") for above in chain[1:])
    return built


def attribution(tree: dict[str, dict], slice_name: str) -> dict:
    return units_adapter._stall_attribution(tree).get(slice_name, {})


# ── explained: the member is the specific, larger statement ──────────────

def test_a_member_reading_higher_accounts_for_the_slice():
    """The reported shape, exactly: the scope at 65.27% inside the slice at
    56.35%."""
    tree = nodes(("system.slice", None, {IO: 56.35}),
                 ("docker-4d1f9c02ab77.scope", "system.slice", {IO: 65.27}),
                 ("example-quiet.service", "system.slice", {IO: 0.0}))
    facts = attribution(tree, "system.slice")
    assert facts["StallExplainedBy"] == {IO: "docker-4d1f9c02ab77.scope"}
    assert "StallUnexplained" not in facts
    assert "StallAttributionUnobservable" not in facts


def test_attribution_names_the_deepest_unit_that_explains_it():
    """A slice inside a slice inside a slice, all printing the same number:
    naming the first one found would move the vagueness down a level and
    keep it. The deepest is the only one that answers the question."""
    tree = nodes(("system.slice", None, {IO: 40.0}),
                 ("system-example.slice", "system.slice", {IO: 40.0}),
                 ("example@1.service", "system-example.slice", {IO: 40.0}))
    assert attribution(tree, "system.slice")["StallExplainedBy"] == {
        IO: "example@1.service"}
    # And each interior slice makes the same, correct, statement about its
    # own subtree — the chain does not depend on where a reader entered it.
    assert attribution(tree, "system-example.slice")["StallExplainedBy"] == {
        IO: "example@1.service"}


def test_the_worst_member_is_named_over_a_nearer_one():
    """Two members both read above the slice. The one whose own row will
    carry the warning is the deep, loud one, not the sibling that scraped
    over the line."""
    tree = nodes(("system.slice", None, {IO: 20.0}),
                 ("example-near.scope", "system.slice", {IO: 20.4}),
                 ("system-deep.slice", "system.slice", {IO: 30.0}),
                 ("example-deep.service", "system-deep.slice", {IO: 91.2}))
    assert attribution(tree, "system.slice")["StallExplainedBy"] == {
        IO: "example-deep.service"}


@pytest.mark.parametrize("member,why", [
    (56.34, "one printed decimal below: two roundings can cost that much "
            "between them"),
    (54.10, "inside the relative allowance: the two averages decay on their "
            "own ticks and the skew scales with the value"),
])
def test_a_member_a_hair_below_the_slice_still_accounts_for_it(member, why):
    """Exact >= is brittle against rounding, and its failure mode is the bad
    one: it would report the interesting finding — a slice nothing inside it
    explains — every time a busy member printed a hundredth low."""
    tree = nodes(("system.slice", None, {IO: 56.35}),
                 ("example.service", "system.slice", {IO: member}))
    assert attribution(tree, "system.slice")["StallExplainedBy"] == {
        IO: "example.service"}, why


def test_the_allowance_does_not_swallow_a_real_difference():
    tree = nodes(("system.slice", None, {IO: 56.35}),
                 ("example.service", "system.slice", {IO: 48.0}))
    facts = attribution(tree, "system.slice")
    assert "StallExplainedBy" not in facts
    assert IO in facts["StallUnexplained"]


# ── unexplained: the finding no member row can state ─────────────────────

def test_every_member_read_and_none_accounting_is_stated_positively():
    """Stated as a fact rather than left to be inferred from the absence of
    the other two: a consumer that reasons from absence cannot tell this
    apart from a slice nobody attributed at all."""
    tree = nodes(("system.slice", None, {IO: 33.43}),
                 ("example-a.service", "system.slice", {IO: 4.1}),
                 ("example-b.scope", "system.slice", {IO: 0.0}))
    statement = attribution(tree, "system.slice")["StallUnexplained"][IO]
    assert "every member cgroup" in statement and "(2 of them)" in statement
    assert "example-a.service" in statement and "4.1%" in statement
    assert "33.43%" in statement


def test_the_rule_reports_the_unexplained_slice_and_stays_silent_on_the_rest():
    """The two ends joined: the same facts the adapter builds, through the
    evaluator both the row and the object view use."""
    explained = {"ActiveState": "active", IO: 56.35,
                 "StallExplainedBy": {IO: "docker-4d1f9c02ab77.scope"}}
    assert units_rules.slice_unit_opinions(explained) == []

    tree = nodes(("system.slice", None, {IO: 33.43}),
                 ("example-a.service", "system.slice", {IO: 4.1}))
    facts = {"ActiveState": "active", IO: 33.43,
             **attribution(tree, "system.slice")}
    [opinion] = units_rules.slice_unit_opinions(facts)
    assert opinion["key"] == "slice-stall-unexplained"
    assert "no unit inside it accounts for it" in opinion["message"]
    assert opinion["look"] == units_rules.SLICE_STALL_LOOK[IO]
    # And it claims attention, at the bar a single unit must clear. At info,
    # envelope.attention() strips it and the one condition no member row will
    # ever state reaches neither /v1/findings nor the estate roll-up.
    assert opinion["level"] == "warn"
    assert env.attention([opinion]) == [opinion]


# ── unobservable: a member that was not read is not a member that is quiet ─

def test_a_member_with_no_reading_blocks_the_unexplained_claim():
    tree = nodes(("system.slice", None, {IO: 33.43}),
                 ("example-a.service", "system.slice", {IO: 4.1}),
                 ("example-dark.scope", "system.slice", {}))
    facts = attribution(tree, "system.slice")
    assert "StallUnexplained" not in facts
    assert "StallExplainedBy" not in facts
    assert "example-dark.scope" in facts["StallAttributionUnobservable"][IO]


def test_an_unread_member_never_outranks_one_that_does_account_for_it():
    """Explained wins: a member reading at least as high answers the
    question whatever else could not be read."""
    tree = nodes(("system.slice", None, {IO: 33.43}),
                 ("example-loud.scope", "system.slice", {IO: 40.0}),
                 ("example-dark.scope", "system.slice", {}))
    facts = attribution(tree, "system.slice")
    assert facts["StallExplainedBy"] == {IO: "example-loud.scope"}
    assert "StallAttributionUnobservable" not in facts


def test_a_slice_with_nothing_under_it_is_not_a_slice_nothing_explains():
    tree = nodes(("system.slice", None, {IO: 33.43}))
    facts = attribution(tree, "system.slice")
    assert "StallUnexplained" not in facts
    assert "no member cgroup was found" in facts["StallAttributionUnobservable"][IO]


def test_the_rule_words_an_unattributable_stall_as_a_gap_in_the_reading():
    tree = nodes(("system.slice", None, {IO: 33.43}),
                 ("example-dark.scope", "system.slice", {}))
    facts = {"ActiveState": "active", IO: 33.43,
             **attribution(tree, "system.slice")}
    [opinion] = units_rules.slice_unit_opinions(facts)
    assert opinion["key"] == "slice-stall-unattributed"
    assert "could not be established" in opinion["message"]
    assert "no unit inside it accounts" not in opinion["message"]


# ── per resource, because one verdict across three would be false for one ─

def test_a_slice_can_be_explained_for_one_reading_and_not_another():
    tree = nodes(("system.slice", None, {IO: 56.35, MEMORY: 11.02}),
                 ("docker-4d1f9c02ab77.scope", "system.slice",
                  {IO: 65.27, MEMORY: 0.4}),
                 ("example-b.service", "system.slice", {IO: 0.0, MEMORY: 1.2}))
    facts = attribution(tree, "system.slice")
    assert facts["StallExplainedBy"] == {IO: "docker-4d1f9c02ab77.scope"}
    assert set(facts["StallUnexplained"]) == {MEMORY}


def test_the_cpu_share_is_never_attributed():
    """`some` is the share of time at least one task was stalled, and that
    aggregates as a union UP the tree: a parent normally reads at least its
    children, so "a member reads at least as high" would be true of nearly
    every slice and would state nothing. The row carries the number; nothing
    is concluded from it."""
    tree = nodes(("system.slice", None, {CPU: 71.2}),
                 ("example.service", "system.slice", {CPU: 3.0}))
    assert attribution(tree, "system.slice") == {}
    assert CPU not in units_adapter.ATTRIBUTED_PRESSURE_FACTS


def test_a_slice_that_is_not_stalling_is_not_attributed_at_all():
    tree = nodes(("system.slice", None, {IO: 0.0}),
                 ("example.service", "system.slice", {IO: 0.0}))
    assert attribution(tree, "system.slice") == {}


# ── membership: the cgroup tree, and where it stops being ours ───────────

def test_a_delegated_subtree_is_the_delegating_unit_and_not_its_contents():
    """Descent stops at anything that is not a slice. What runs below a
    service or scope was delegated to it — user@<uid>.service runs a second
    systemd, a container scope runs a container's own hierarchy — and those
    units belong to another manager. Naming one would be a reference this
    collection cannot resolve, and their names collide with system units, so
    it could resolve to the wrong object. The delegating unit carries their
    aggregate and is a row here."""
    tree = nodes(("user.slice", None, {IO: 30.0}),
                 ("user-1000.slice", "user.slice", {IO: 30.0}),
                 ("user@1000.service", "user-1000.slice", {IO: 31.0}),
                 # The user manager's own tree, sharing names with system
                 # units, below the delegation boundary.
                 ("app.slice", "user@1000.service", {IO: 40.0}),
                 ("dbus.service", "app.slice", {IO: 99.0}))
    assert attribution(tree, "user.slice")["StallExplainedBy"] == {
        IO: "user@1000.service"}


def test_a_subtree_the_walk_cut_short_cannot_be_ruled_out():
    tree = nodes(("system.slice", None, {IO: 33.43}),
                 ("system-deep.slice", "system.slice", {IO: 1.0}))
    tree["system-deep.slice"]["pruned"] = True
    facts = attribution(tree, "system.slice")
    assert "StallUnexplained" not in facts
    # Worded for a subtree left unread, not for the depth bound specifically:
    # a directory the walk could not list carries the same flag, and only one
    # of the two reasons is about depth.
    assert "was not read to the bottom" in facts["StallAttributionUnobservable"][IO]


# ── the walk itself, over a real directory tree ──────────────────────────

def write_pressure(directory, io_full: float | None) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if io_full is not None:
        (directory / "io.pressure").write_text(
            "some avg10=0.00 avg60=1.00 avg300=0.50 total=1\n"
            f"full avg10=0.00 avg60={io_full:.2f} avg300=0.20 total=1\n")


def walk_tree(monkeypatch, root, spec) -> dict[str, dict]:
    """Build a real cgroup tree from (path below the root, io full avg60) and
    run the walk over it. Directories rather than a node map, because the
    shapes below are ones a hand-built map cannot hold: a basename that occurs
    twice, and a directory the walk cannot get into."""
    for relative, io_full in spec:
        write_pressure(root / relative, io_full)
    monkeypatch.setattr(units_adapter, "CGROUP_ROOT", str(root))
    return units_adapter._pressure_nodes()


def test_the_walk_records_parentage_readability_and_the_shallower_name(tmp_path, monkeypatch):
    """Three things the attribution depends on and no other test can see: the
    parent link (the join itself), a cgroup that yielded nothing (kept, so it
    can be told apart from one reading zero), and the name collision a user
    manager creates — init.scope exists at the root and again inside
    user@<uid>.service, and merging by name let whichever the walk reached
    last decide whose pressure a row reports."""
    monkeypatch.setattr(units_adapter, "CGROUP_ROOT", str(tmp_path))
    write_pressure(tmp_path / "system.slice", 56.35)
    write_pressure(tmp_path / "system.slice" / "example.service", 65.27)
    write_pressure(tmp_path / "system.slice" / "example-dark.scope", None)
    write_pressure(tmp_path / "init.scope", 1.0)
    write_pressure(tmp_path / "user.slice" / "user-1000.slice"
                   / "user@1000.service" / "init.scope", 99.0)

    found = units_adapter._pressure_nodes()
    assert found["example.service"]["parent"] == "system.slice"
    assert found["system.slice"]["parent"] is None
    assert found["example-dark.scope"]["facts"] == {}
    assert found["example-dark.scope"]["parent"] == "system.slice"
    assert found["init.scope"]["facts"][IO] == 1.0, "the deeper namesake won"
    assert units_adapter._pressure_by_unit(found)["example.service"][IO] == 65.27
    assert "example-dark.scope" not in units_adapter._pressure_by_unit(found)


def test_the_walk_marks_the_slice_whose_children_it_refused_to_descend(tmp_path, monkeypatch):
    """The bound is what stops a pathological tree turning a page render into
    a filesystem walk; it is lowered here rather than nesting eight real
    directories, because the behaviour under test is the marking, not the
    number."""
    monkeypatch.setattr(units_adapter, "CGROUP_ROOT", str(tmp_path))
    monkeypatch.setattr(units_adapter, "CGROUP_MAX_DEPTH", 3)
    write_pressure(tmp_path / "system.slice", 33.43)
    write_pressure(tmp_path / "system.slice" / "system-deep.slice", 1.0)
    write_pressure(tmp_path / "system.slice" / "system-deep.slice"
                   / "example.service", 99.0)

    found = units_adapter._pressure_nodes()
    assert "example.service" not in found
    # The flag sits on the cgroup whose children were left unread, which is
    # the only node that can still be seen from above.
    assert found["system-deep.slice"]["pruned"] is True
    assert found["system.slice"]["pruned"] is False
    facts = units_adapter._stall_attribution(found)["system.slice"]
    assert "StallUnexplained" not in facts
    assert IO in facts["StallAttributionUnobservable"]


def test_the_object_path_answers_with_the_same_attribution_as_the_row(tmp_path, monkeypatch):
    """One evaluator serves both views, so a detail page that skipped the
    member readings would judge the same slice on less than the list did and
    the two would disagree about one unit."""
    monkeypatch.setattr(units_adapter, "CGROUP_ROOT", str(tmp_path))
    write_pressure(tmp_path / "system.slice", 56.35)
    write_pressure(tmp_path / "system.slice" / f"docker-{CONTAINER_ID}.scope", 65.27)

    facts = units_adapter._unit_pressure("system.slice")
    assert facts[IO] == 56.35
    assert facts["StallExplainedBy"] == {IO: f"docker-{CONTAINER_ID}.scope"}
    assert units_rules.slice_unit_opinions({"ActiveState": "active", **facts}) == []
    # The member keeps the finding, with a name on it.
    member = units_adapter._unit_pressure(f"docker-{CONTAINER_ID}.scope")
    [opinion] = units_rules.unit_opinions({"ActiveState": "active", **member})
    assert opinion["key"] == "unit-io-stall"


# ── a second systemd inside the first: names that occur twice ────────────
#
# Every case above builds a node map by hand, and every name in one is unique.
# That is the one thing a hand-built map cannot be wrong about, and it is what
# the tree join actually got wrong: cgroup basenames repeat, because a host
# that runs systemd inside a container, a VM or a user session has a second
# system.slice (or user.slice, or dbus.service) below the delegation boundary.
# The shallowest occurrence wins the name, and everything nested under the
# LOSER then had to be attached to the winner — a guest's units becoming
# direct members of the host's slice, and getting named as what explains its
# stall. Only a real directory tree can state this shape.

HOST_SYSTEM_SLICE = (("system.slice", 56.35),
                     ("system.slice/dbus.service", 0.10),
                     ("system.slice/sshd.service", 0.00))
# systemd-nspawn (or LXC, or a libvirt guest): a whole second init below
# machine.slice, its own system.slice among the loudest things on the host.
NSPAWN_GUEST = (
    ("machine.slice", 58.0),
    ("machine.slice/machine-guest.scope", 61.0),
    ("machine.slice/machine-guest.scope/system.slice", 60.5),
    ("machine.slice/machine-guest.scope/system.slice/postgresql.service", 60.0))
# systemd inside a docker container: the same collision one level shallower,
# and the scope holding it is a real row with the aggregate on it.
DOCKER_HOST = (("system.slice", 40.0),
               ("system.slice/example-quiet.service", 0.0),
               ("system.slice/docker-4d1f9c02ab77.scope", 41.5))
DOCKER_GUEST = (
    ("system.slice/docker-4d1f9c02ab77.scope/system.slice", 60.0),
    # Louder than the scope holding it, which is ordinary — a scope's "full"
    # share only counts time in which everything under it was stalled — and is
    # what makes it the member a basename join would name.
    ("system.slice/docker-4d1f9c02ab77.scope/system.slice/apache2.service", 60.5))
# rootless podman: the user manager's own user.slice, three levels inside the
# user@<uid>.service that _slice_members must never name past.
USER_HOST = (("user.slice", 22.0),
             ("user.slice/user-1000.slice", 22.0),
             ("user.slice/user-1000.slice/user@1000.service", 23.0))
USER_GUEST = (
    ("user.slice/user-1000.slice/user@1000.service/user.slice", 60.5),
    ("user.slice/user-1000.slice/user@1000.service/user.slice/"
     "libpod-abc123.scope", 60.0))


@pytest.mark.parametrize("host,delegated,slice_name,explained_by", [
    (HOST_SYSTEM_SLICE, NSPAWN_GUEST, "system.slice", None),
    (DOCKER_HOST, DOCKER_GUEST, "system.slice", "docker-4d1f9c02ab77.scope"),
    (USER_HOST, USER_GUEST, "user.slice", "user@1000.service"),
], ids=["nspawn-guest", "systemd-in-docker", "rootless-podman"])
def test_a_delegated_hierarchy_leaves_the_slice_beside_it_saying_the_same_thing(
        tmp_path, monkeypatch, host, delegated, slice_name, explained_by):
    """The invariant, stated as an equality: starting a guest changes nothing
    about what the host's own slice says. Without it, the host's largest stall
    is 'explained by' a unit inside the guest, the finding this feature exists
    to surface is suppressed, and the overview panel drops the row on the
    strength of a member reference the collection cannot resolve."""
    alone = walk_tree(monkeypatch, tmp_path / "alone", host)
    nested = walk_tree(monkeypatch, tmp_path / "nested", tuple(host) + tuple(delegated))
    answer_alone = units_adapter._stall_attribution(alone).get(slice_name, {})
    answer_nested = units_adapter._stall_attribution(nested).get(slice_name, {})
    assert answer_nested == answer_alone

    if explained_by is None:
        assert IO in answer_nested["StallUnexplained"]
        assert "StallExplainedBy" not in answer_nested
    else:
        assert answer_nested["StallExplainedBy"] == {IO: explained_by}
    # Whatever is named has to be a row in this collection: a member reference
    # that resolves to nothing is a click-through landing nowhere, and one
    # that resolves to a same-named host unit is worse.
    rows = units_adapter._pressure_by_unit(nested)
    for named in answer_nested.get("StallExplainedBy", {}).values():
        assert named in rows, f"{named} explains a slice but has no row"


def test_a_cgroup_below_a_losing_namesake_is_a_member_of_nothing(tmp_path, monkeypatch):
    """The mechanism, at the walk. The guest's system.slice loses the name to
    the host's (depth 3 against 1) and is dropped, so a join on the enclosing
    directory's BASENAME made postgresql.service a direct member of the host's
    system.slice. Parentage is resolved by path instead, and a cgroup inside a
    hierarchy this walk declined to represent is a member of nothing — which
    is the correct answer, since the delegating scope carries its aggregate
    and is itself a row."""
    found = walk_tree(monkeypatch, tmp_path,
                      HOST_SYSTEM_SLICE + NSPAWN_GUEST)
    assert found["system.slice"]["depth"] == 1, "the host's, not the guest's"
    assert found["system.slice"]["facts"][IO] == 56.35
    assert found["postgresql.service"]["parent"] is None

    facts = units_adapter._stall_attribution(found)["system.slice"]
    statement = facts["StallUnexplained"][IO]
    assert "(2 of them)" in statement, "dbus.service and sshd.service, no more"
    assert "postgresql.service" not in statement
    [opinion] = units_rules.slice_unit_opinions(
        {"ActiveState": "active", IO: 56.35, **facts})
    assert opinion["key"] == "slice-stall-unexplained"


# ── and whose readings a row may show as its own ─────────────────────────
#
# Attaching the tree by path stops a guest's units becoming MEMBERS of a host
# slice, but the row facts are a second join on the same names: the walk
# returns {name: readings} and the collection asks for each unit by name. A
# guest unit whose name is unique in the tree survives the collision rule with
# no host namesake to lose to — and hands its readings to a host unit of that
# name that owns no cgroup at all.

def test_a_guest_unit_does_not_hand_its_readings_to_the_host_row_of_that_name(
        tmp_path, monkeypatch):
    """The live shape: a container runs systemd with its own nginx.service;
    the host has nginx.service loaded but inactive, so it owns no cgroup and
    the name collides with nothing. The host's ROW then showed the container's
    stall as its own — a bare fact on a row that is not about it, with nothing
    to mark it, and no slice to argue about. A reading is a row's only where
    the cgroup is that unit's own: every cgroup between it and the root a
    slice, the boundary _slice_members already refuses to descend past."""
    scope = "system.slice/docker-4d1f9c02ab77.scope"
    found = walk_tree(monkeypatch, tmp_path,
                      (("system.slice", 40.0),
                       ("system.slice/sshd.service", 1.0),
                       (scope, 41.5),
                       (f"{scope}/system.slice", 60.0),
                       (f"{scope}/system.slice/nginx.service", 60.5)))
    assert found["nginx.service"]["managed"] is False
    assert found["sshd.service"]["managed"] is True

    rows = units_adapter._pressure_by_unit(found)
    assert "nginx.service" in found, "the walk saw it; the ROW is what it may not reach"
    assert "nginx.service" not in rows
    # Spelled the way the collection spells it (see acquire): absent, so the
    # row carries no such fact at all. A zero would read as measured calm on a
    # unit that was never measured.
    for key in units_adapter.ROW_PRESSURE_FACTS:
        assert rows.get("nginx.service", {}).get(key) is None
    assert units_adapter._unit_pressure("nginx.service") == {}, "the object view agrees"

    # And nothing was stripped from the units that legitimately have readings.
    assert rows["sshd.service"][IO] == 1.0
    assert rows["docker-4d1f9c02ab77.scope"][IO] == 41.5, "the delegating unit owns its own"
    assert rows["system.slice"][IO] == 40.0


def test_a_guest_slice_does_not_publish_its_members_on_the_host_row_of_that_name(
        tmp_path, monkeypatch):
    """The same second join, for the derived facts, and worse: attribution is
    keyed by name too, so a delegated slice with a name of its own would put
    StallExplainedBy on the host's slice of that name — a member reference
    into a hierarchy this collection cannot resolve, on a row that never
    contained it."""
    scope = "system.slice/docker-4d1f9c02ab77.scope"
    found = walk_tree(monkeypatch, tmp_path,
                      (("system.slice", 5.0),
                       (scope, 41.5),
                       (f"{scope}/app-guest.slice", 60.0),
                       (f"{scope}/app-guest.slice/worker.service", 60.5)))
    assert "app-guest.slice" not in units_adapter._stall_attribution(found)
    assert units_adapter._unit_pressure("app-guest.slice") == {}
    # The host's own slice keeps its answer, and it is the scope: the
    # delegating unit is where the guest's aggregate legitimately lands.
    assert units_adapter._stall_attribution(found)["system.slice"][
        "StallExplainedBy"] == {IO: "docker-4d1f9c02ab77.scope"}


@pytest.mark.parametrize("path,name", [
    ("system.slice/example.service", "example.service"),
    ("system.slice/system-example.slice/example@1.service", "example@1.service"),
    ("system.slice/docker-4d1f9c02ab77.scope", "docker-4d1f9c02ab77.scope"),
    ("init.scope", "init.scope"),
    ("user.slice/user-1000.slice/user@1000.service", "user@1000.service"),
])
def test_a_unit_whose_cgroup_is_its_own_keeps_every_reading(
        tmp_path, monkeypatch, path, name):
    """The half that must not move. Slices nest and a service or scope hangs
    from one: that is the shape of every ordinary row on the host, including
    the delegating units themselves, which own their cgroup however foreign
    the hierarchy below it is."""
    found = walk_tree(monkeypatch, tmp_path, ((path, 33.0),))
    assert units_adapter._pressure_by_unit(found)[name][IO] == 33.0
    assert units_adapter._unit_pressure(name)[IO] == 33.0


# ── a walk that stopped early must not report a complete tree ────────────

def test_a_member_directory_that_cannot_be_listed_is_not_a_member_that_is_quiet(
        tmp_path, monkeypatch):
    """os.walk discards a subtree it cannot list without a word, so the
    members inside it were neither counted, nor named as unread, nor recorded
    as a cut — and the slice above went on to state positively that every
    member had been read. Two members existed, one of them at 60% was the
    answer, and the product asserted the opposite as its headline finding."""
    if os.geteuid() == 0:
        pytest.skip("root can list a 0o000 directory, so the denial cannot happen")
    locked = tmp_path / "system.slice" / "system-locked.slice"
    spec = (("system.slice", 50.0),
            ("system.slice/sshd.service", 0.0),
            ("system.slice/system-locked.slice", 50.0),
            ("system.slice/system-locked.slice/loud.service", 60.0))
    for relative, io_full in spec:
        write_pressure(tmp_path / relative, io_full)
    locked.chmod(0o000)
    try:
        monkeypatch.setattr(units_adapter, "CGROUP_ROOT", str(tmp_path))
        found = units_adapter._pressure_nodes()
    finally:
        locked.chmod(0o755)

    assert "loud.service" not in found, "unreachable, and known to be"
    assert found["system-locked.slice"]["facts"] == {}
    assert found["system-locked.slice"]["parent"] == "system.slice"
    facts = units_adapter._stall_attribution(found)["system.slice"]
    assert "StallUnexplained" not in facts
    assert "system-locked.slice" in facts["StallAttributionUnobservable"][IO]
    [opinion] = units_rules.slice_unit_opinions(
        {"ActiveState": "active", IO: 50.0, **facts})
    assert opinion["key"] == "slice-stall-unattributed"


def test_a_cgroup_removed_between_the_listing_and_the_descent_is_still_a_member(
        tmp_path, monkeypatch):
    """The same silence with no permissions involved, and the likelier half:
    a transient scope whose cgroup systemd removes between its parent's
    listing and the walk's descent into it. avg60 covers the minute that just
    ended, so a unit that stopped inside it is exactly the one that could
    still account for the number. The error is injected at the syscall that
    races — everything above it is the real walk."""
    spec = (("system.slice", 50.0),
            ("system.slice/sshd.service", 0.0),
            ("system.slice/example-vanishing.scope", 60.0))
    for relative, io_full in spec:
        write_pressure(tmp_path / relative, io_full)
    doomed = str(tmp_path / "system.slice" / "example-vanishing.scope")
    real_scandir = os.scandir

    def racing_scandir(path=".", *args, **kwargs):
        if str(path) == doomed:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),
                                    str(path))
        return real_scandir(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", racing_scandir)
    monkeypatch.setattr(units_adapter, "CGROUP_ROOT", str(tmp_path))
    found = units_adapter._pressure_nodes()

    assert found["example-vanishing.scope"]["facts"] == {}
    facts = units_adapter._stall_attribution(found)["system.slice"]
    assert "StallUnexplained" not in facts
    assert "example-vanishing.scope" in facts["StallAttributionUnobservable"][IO]


def test_a_cgroup_no_systemd_named_is_counted_and_never_named(tmp_path, monkeypatch):
    """A cgroupfs-driver runtime under --cgroup-parent puts a cgroup straight
    under a slice with a name no unit has. Skipping it made its 60% invisible
    to the census — not counted, not unread, not a cut — while the slice above
    claimed every member had been read. It is kept as what it is: a member
    whose reading belongs to no row here, so it can neither be attributed nor
    ruled out."""
    found = walk_tree(monkeypatch, tmp_path,
                      (("system.slice", 50.0),
                       ("system.slice/sshd.service", 0.0),
                       ("system.slice/loudpod", 60.0)))
    pod = str(tmp_path / "system.slice" / "loudpod")
    assert found[pod]["unit"] is False, "keyed by path: it has no name to be"
    assert found[pod]["parent"] == "system.slice"
    assert pod not in units_adapter._pressure_by_unit(found)

    facts = units_adapter._stall_attribution(found)["system.slice"]
    assert "StallUnexplained" not in facts
    assert "StallExplainedBy" not in facts, "a cgroup with no row is never the answer"
    statement = facts["StallAttributionUnobservable"][IO]
    assert "not systemd units" in statement and pod in statement
    [opinion] = units_rules.slice_unit_opinions(
        {"ActiveState": "active", IO: 50.0, **facts})
    assert opinion["key"] == "slice-stall-unattributed"


@pytest.mark.parametrize("bottom,expected", [
    ("payload", "not systemd units"),
    ("e.slice", "was not read to the bottom"),
])
def test_a_cut_at_the_depth_bound_is_not_swallowed_by_the_directory_name(
        tmp_path, monkeypatch, bottom, expected):
    """The same tree twice with one directory renamed. Both stop the walk at
    the same depth with a 99% service below the bound; the unit-named one
    carries the cut, and the other used to be dropped entirely, taking the cut
    with it and leaving the slice above reporting that every member was read.
    Different sentences, but neither of them is StallUnexplained."""
    monkeypatch.setattr(units_adapter, "CGROUP_MAX_DEPTH", 6)
    deep = f"a.slice/b.slice/c.slice/d.slice/{bottom}"
    found = walk_tree(monkeypatch, tmp_path,
                      (("a.slice", 50.0), ("a.slice/b.slice", 0.5),
                       ("a.slice/b.slice/c.slice", 0.5),
                       ("a.slice/b.slice/c.slice/d.slice", 0.5),
                       (deep, 0.5), (f"{deep}/loud.service", 99.0)))
    assert "loud.service" not in found, "past the depth bound"
    facts = units_adapter._stall_attribution(found)["a.slice"]
    assert "StallUnexplained" not in facts
    assert expected in facts["StallAttributionUnobservable"][IO]


# ── what the row says when the rule says nothing ─────────────────────────

def test_a_slice_whose_stall_a_member_explains_is_neutral_and_not_healthy():
    """The rule's silence is right — the member's row carries the finding,
    with the name on it — but silence reaches the row as the NO-OPINION
    severity, and "ok" is the positively-healthy value there. A green dot
    titled "worst opinion on this row: ok" beside 56.35% of the last minute
    says the evaluator looked and found nothing wrong; neutral is the honest
    mark for a number nobody judged."""
    facts = {"ActiveState": "active", IO: 56.35,
             "StallExplainedBy": {IO: "docker-4d1f9c02ab77.scope"}}
    assert units_rules.slice_unit_opinions(facts) == []
    row = env.item_summary(
        "unit:system.slice", "slice", "system.slice", facts,
        opinions=units_rules.slice_unit_opinions(facts),
        healthy=units_adapter._row_health("system.slice", "active", facts))
    assert row["worst_opinion_level"] == "info"
    assert "opinions" not in row, "nothing was carried, and nothing is claimed"


@pytest.mark.parametrize("name,active,facts,expected", [
    ("system.slice", "active",
     {IO: 56.35, "StallExplainedBy": {IO: "example.scope"}}, "info"),
    # Under the floor the rule was never going to speak, so nothing was
    # suppressed and nothing is owed.
    ("system.slice", "active",
     {IO: 0.42, "StallExplainedBy": {IO: "example.scope"}}, "ok"),
    # The unexplained slice keeps its vouch as the no-opinion value: it has an
    # opinion, which is what the row's severity comes from.
    ("system.slice", "active", {IO: 33.43, "StallUnexplained": {IO: "…"}}, "ok"),
    ("system.slice", "active", {IO: 0.0}, "ok"),
    ("system.slice", "inactive", {}, "info"),
    # Only slices defer; a service's stall is its own and its row says so.
    ("example.service", "active",
     {IO: 56.35, "StallExplainedBy": {IO: "example.scope"}}, "ok"),
])
def test_only_a_deferred_slice_stall_gives_up_the_positive_vouch(
        name, active, facts, expected):
    assert units_adapter._row_health(name, active, facts) == expected


def test_the_slice_knobs_are_keyed_by_the_same_readings():
    """Three tables keyed by the readings a slice is judged on: the wording,
    the route hint, and the attention bar. A fact in one and not another is
    either a KeyError inside the evaluator or a stall it silently never
    judges, and neither shows up as a failing case."""
    judged = {fact for fact, _resource in units_rules.SLICE_STALL_RESOURCES}
    assert judged == set(units_rules.SLICE_STALL_LOOK)
    assert judged == set(units_rules.SLICE_STALL_ATTENTION)
    assert judged == set(units_adapter.ATTRIBUTED_PRESSURE_FACTS)


# ── the other direction: turning that scope back into a container ────────

def test_docker_publishes_the_scope_name_units_reads_back():
    """The name is derived from the id rather than observed, so the spelling
    is proven against the pattern that consumes it — units.py matches the
    scope name to recover the short id, and a mismatch would leave both
    sides talking about a unit neither could find."""
    scope = docker_adapter._scope_unit(CONTAINER_ID)
    assert scope == f"docker-{CONTAINER_ID}.scope"
    match = units_adapter.DOCKER_SCOPE_RE.match(scope)
    assert match, f"units.py cannot read back {scope!r}"
    # The id the units row publishes as ContainerID, and the id the docker
    # row publishes under the same fact name, are the same twelve characters.
    assert match.group(1) == CONTAINER_ID[:12]
    assert units_adapter._workload_facts(scope) == {"ContainerID": CONTAINER_ID[:12]}


def test_the_full_id_is_what_the_scope_carries_not_the_short_form():
    """The rows carry ContainerID short because that is what an operator
    reads; the scope name is the full id, and building it from the short form
    would name a unit that does not exist."""
    assert docker_adapter._scope_unit(CONTAINER_ID[:12]) != f"docker-{CONTAINER_ID}.scope"
    assert units_adapter.DOCKER_SCOPE_RE.match(
        docker_adapter._scope_unit(CONTAINER_ID[:12]))


def test_no_id_means_no_claim():
    """A listing entry with no Id is a container this cannot name a scope
    for; an empty string would build `docker-.scope`, a unit that exists
    nowhere."""
    assert docker_adapter._scope_unit("") is None
