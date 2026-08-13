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

import pytest

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
    readings). Depth is derived from the parent chain so a case states the
    shape it means and nothing else."""
    built = {name: {"facts": dict(readings), "parent": parent,
                    "depth": 0, "pruned": False}
             for name, parent, readings in spec}
    for node in built.values():
        depth, walk = 0, node["parent"]
        while walk:
            depth += 1
            walk = built[walk]["parent"]
        node["depth"] = depth
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
    assert "deeper than this walk reads" in facts["StallAttributionUnobservable"][IO]


# ── the walk itself, over a real directory tree ──────────────────────────

def write_pressure(directory, io_full: float | None) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if io_full is not None:
        (directory / "io.pressure").write_text(
            "some avg10=0.00 avg60=1.00 avg300=0.50 total=1\n"
            f"full avg10=0.00 avg60={io_full:.2f} avg300=0.20 total=1\n")


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
