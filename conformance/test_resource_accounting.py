"""What each workload CONSUMED, and the part of the host that is nobody's.

The stall half of this subsystem is held by test_stall_attribution.py, which
moved with the walk. This file covers what the move added: the utilisation
counters, the root cgroup as a row, and the unattributed CPU remainder.

The remainder is the piece worth the most scrutiny, because it is arithmetic
this product performs rather than a number the kernel hands over — and the
design it replaced published a percentage remainder for I/O that no
denominator supports. So the tests below pin both directions: that the CPU
figure is computed from the one total that is unambiguous, and that no
remainder is offered for the two resources where it would be invented.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from system_explorer.agent.adapters import resources as adapter

IO = "PsiIoFullAvg60"


# ── building a fake cgroup tree on disk ──────────────────────────────────

def write_cgroup(root, relative, **files):
    """One cgroup directory with whatever kernel files the case needs.

    Files are written by name rather than through a fixture that always
    writes the full set: half of what is under test is what happens when a
    file is NOT there, and a helper that always wrote memory.current could
    never express that.
    """
    path = root / relative if relative else root
    path.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (path / name.replace("__", ".")).write_text(text)
    return path


def tree(monkeypatch, tmp_path, controllers=True):
    monkeypatch.setattr(adapter, "CGROUP_ROOT", str(tmp_path))
    if controllers:
        (tmp_path / "cgroup.controllers").write_text("cpuset cpu io memory pids\n")
    return tmp_path


def proc_stat(monkeypatch, tmp_path, line):
    path = tmp_path / "proc-stat"
    path.write_text(line)
    monkeypatch.setattr(adapter, "PROC_STAT", str(path))
    return path


def items(monkeypatch, tmp_path):
    return {item["native_id"]: item for item in adapter.Adapter()._items()}


# ── the counters ─────────────────────────────────────────────────────────

CPU_STAT = ("usage_usec 4182993001\n"
            "user_usec 3001000000\n"
            "system_usec 1181993001\n"
            "nr_periods 55\n"
            "nr_throttled 7\n"
            "throttled_usec 218000\n")

IO_STAT = ("8:0 rbytes=918273645 wbytes=41028374650 rios=10 wios=20 dbytes=0 dios=0\n"
           "8:16 rbytes=1000 wbytes=2000 rios=1 wios=2 dbytes=0 dios=0\n")


def test_the_counters_are_read_as_the_kernel_writes_them(tmp_path):
    write_cgroup(tmp_path, "example.service", cpu__stat=CPU_STAT,
                 memory__current="2411724800", memory__peak="3006477312",
                 memory__swap__current="4096", io__stat=IO_STAT,
                 memory__events="low 0\nhigh 0\nmax 3\noom 2\noom_kill 1\n")
    facts = adapter._read_counters(str(tmp_path / "example.service"))
    assert facts["CpuUsageUsec"] == 4182993001
    assert facts["CpuUserUsec"] == 3001000000
    assert facts["CpuSystemUsec"] == 1181993001
    assert facts["CpuThrottledUsec"] == 218000
    assert facts["CpuThrottledPeriods"] == 7
    assert facts["MemoryCurrentBytes"] == 2411724800
    assert facts["MemoryPeakBytes"] == 3006477312
    assert facts["MemorySwapCurrentBytes"] == 4096
    assert facts["MemoryOomKills"] == 1
    assert facts["MemoryOomEvents"] == 2
    # Summed across both devices, because the question this collection
    # answers is which WORKLOAD is doing the I/O; which device it landed on
    # is storage's object, not this one's.
    assert facts["IoReadBytes"] == 918273645 + 1000
    assert facts["IoWrittenBytes"] == 41028374650 + 2000
    assert facts["IoReadOps"] == 11
    assert facts["IoWriteOps"] == 22


def test_a_file_the_kernel_does_not_keep_is_absent_and_never_zero(tmp_path):
    """The distinction the whole module is built on. memory.current is absent
    on the root cgroup by design, absent where the controller is off, and
    absent on older kernels; a zero there would report a workload using no
    memory, which is a measurement nobody took."""
    write_cgroup(tmp_path, "sparse.service", cpu__stat="usage_usec 5\n")
    facts = adapter._read_counters(str(tmp_path / "sparse.service"))
    assert facts == {"CpuUsageUsec": 5}
    assert "MemoryCurrentBytes" not in facts
    assert "IoReadBytes" not in facts


def test_a_counter_file_that_will_not_parse_is_dropped_not_guessed(tmp_path):
    write_cgroup(tmp_path, "odd.service", memory__current="unbounded\n",
                 cpu__stat="usage_usec notanumber\nuser_usec 12\n")
    facts = adapter._read_counters(str(tmp_path / "odd.service"))
    assert "MemoryCurrentBytes" not in facts
    assert "CpuUsageUsec" not in facts
    assert facts["CpuUserUsec"] == 12, "one bad line does not poison the file"


# ── the PSI vocabulary is closed, and matches what is documented ─────────

def test_every_psi_fact_the_parser_produces_has_a_dictionary_entry(tmp_path):
    """The names are built from the file's contents, so nothing but this
    declared set stops the product publishing a fact with no sentence beside
    it — which is a fact an operator cannot look up."""
    (tmp_path / "io.pressure").write_text(
        "some avg10=1.00 avg60=2.00 avg300=3.00 total=1\n"
        "full avg10=4.00 avg60=5.00 avg300=6.00 total=2\n")
    produced = adapter._read_pressure(str(tmp_path / "io.pressure"))
    assert set(produced) <= adapter.PSI_FACTS
    assert adapter.PSI_FACTS <= set(adapter._GLOSSARY), (
        "a PSI fact with no glossary entry: "
        f"{sorted(adapter.PSI_FACTS - set(adapter._GLOSSARY))}")


def test_a_window_the_kernel_invents_is_not_published_undocumented(tmp_path):
    """A future kernel adding avg900 would otherwise reach the wire under a
    name nothing describes. Dropping it is the lesser of the two: the fact
    dictionary is the contract, and an undocumented fact breaks it silently
    where an absent one does not."""
    (tmp_path / "io.pressure").write_text(
        "full avg10=1.00 avg60=2.00 avg300=3.00 avg900=4.00 total=2\n")
    produced = adapter._read_pressure(str(tmp_path / "io.pressure"))
    assert "PsiIoFullAvg900" not in produced
    assert produced["PsiIoFullAvg60"] == 2.0


# ── the root cgroup is a row, which is the point of the walk change ──────

def test_the_root_is_a_row_under_systemds_own_name_for_it(monkeypatch, tmp_path):
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "", cpu__stat="usage_usec 100\n")
    write_cgroup(root, "system.slice", cpu__stat="usage_usec 60\n")
    proc_stat(monkeypatch, tmp_path, "cpu 10 0 0 900 0 0 0 0 0 0\n")

    rows = items(monkeypatch, tmp_path)
    assert "-.slice" in rows, "the host total had no row until the root was walked"
    assert rows["-.slice"]["facts"]["Depth"] == 0
    assert rows["-.slice"]["type"] == "slice"
    assert rows["-.slice"]["id"] == "unit:-.slice"
    # And a top-level slice now hangs from something, which is what makes the
    # ladder walkable in one direction rather than starting nowhere.
    assert rows["system.slice"]["facts"]["Parent"] == "-.slice"


def test_the_host_stall_the_units_page_could_not_reconcile_is_now_stated(
        monkeypatch, tmp_path):
    """The reported case. The host read 54.55% I/O-stalled while the worst
    unit read 5.14%, and nothing said the difference was kernel work in no
    cgroup — because the root had no row for the answer to sit on."""
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "", io__pressure="full avg10=0 avg60=54.55 avg300=0 total=1\n")
    write_cgroup(root, "system.slice",
                 io__pressure="full avg10=0 avg60=5.14 avg300=0 total=1\n")
    write_cgroup(root, "system.slice/nix-daemon.service",
                 io__pressure="full avg10=0 avg60=5.14 avg300=0 total=1\n")

    rows = items(monkeypatch, tmp_path)
    unexplained = rows["-.slice"]["facts"]["StallUnexplained"]
    assert IO in unexplained
    assert "5.14%" in unexplained[IO] and "54.55%" in unexplained[IO]
    [opinion] = [o for o in rows["-.slice"]["opinions"]
                 if o["key"] == "slice-stall-unexplained"]
    assert opinion["level"] == "warn"


# ── the unattributed remainder ───────────────────────────────────────────

def test_the_cpu_remainder_is_the_host_total_less_the_top_level_cgroups(
        monkeypatch, tmp_path):
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "", cpu__stat="usage_usec 999999\n")
    write_cgroup(root, "system.slice", cpu__stat="usage_usec 3000000\n")
    write_cgroup(root, "user.slice", cpu__stat="usage_usec 1000000\n")
    # Deep enough to prove the sum is over depth 1 and not over every node:
    # counting this child as well as its parent would double-count it.
    write_cgroup(root, "system.slice/example.service",
                 cpu__stat="usage_usec 2500000\n")
    # 10 ticks busy at 100 Hz = 100_000 usec... so pick numbers that leave a
    # visible remainder: 600 ticks = 6_000_000 usec.
    proc_stat(monkeypatch, tmp_path, "cpu 300 100 200 5000 0 0 0 0 0 0\n")

    facts = items(monkeypatch, tmp_path)["-.slice"]["facts"]
    per_tick = 1_000_000 // (os.sysconf("SC_CLK_TCK") or 100)
    assert facts["HostCpuBusyUsec"] == 600 * per_tick
    assert facts["UnattributedCpuUsec"] == 600 * per_tick - 4_000_000


def test_guest_time_is_not_counted_twice_in_the_host_total(
        monkeypatch, tmp_path):
    """The kernel already includes guest and guest_nice inside user and nice.
    Adding them would inflate the denominator, and every inflation lands in
    the remainder — the one figure here nobody can check against a file."""
    tree(monkeypatch, tmp_path)
    proc_stat(monkeypatch, tmp_path, "cpu 100 0 0 0 0 0 0 0 90 5\n")
    per_tick = 1_000_000 // (os.sysconf("SC_CLK_TCK") or 100)
    assert adapter._host_cpu_totals() == (100 * per_tick, 0)


def test_idle_and_iowait_are_not_busy(monkeypatch, tmp_path):
    tree(monkeypatch, tmp_path)
    proc_stat(monkeypatch, tmp_path, "cpu 10 10 10 99999 88888 1 1 1 0 0\n")
    per_tick = 1_000_000 // (os.sysconf("SC_CLK_TCK") or 100)
    busy, stolen = adapter._host_cpu_totals()
    assert busy == 32 * per_tick, "the 1 tick of steal is not this host's work"
    assert stolen == 1 * per_tick


# ── stolen time is neither busy nor idle ─────────────────────────────────

def test_stolen_time_is_kept_out_of_the_remainder(monkeypatch, tmp_path):
    """The defect the estate found and no fixture could. Steal is time the
    hypervisor gave to somebody else — the vCPU was not running — so it is
    not work this host did and cannot be work belonging to no workload on it.
    Counting it as busy inflated the remainder by exactly the stolen time,
    which is 0 on every bare-metal host and grows with how contended a VM's
    neighbours are (measured: 18.5 s of a 101 s remainder on the estate's one
    shared VPS)."""
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "", cpu__stat="usage_usec 1\n")
    write_cgroup(root, "system.slice", cpu__stat="usage_usec 1000000\n")
    # 400 busy ticks, 200 stolen. At 100 Hz that is 4 s of work and 2 s lost.
    proc_stat(monkeypatch, tmp_path, "cpu 200 100 100 900 0 0 0 200 0 0\n")

    facts = items(monkeypatch, tmp_path)["-.slice"]["facts"]
    per_tick = 1_000_000 // (os.sysconf("SC_CLK_TCK") or 100)
    assert facts["HostCpuBusyUsec"] == 400 * per_tick
    assert facts["HostCpuStolenUsec"] == 200 * per_tick
    assert facts["UnattributedCpuUsec"] == 400 * per_tick - 1_000_000, (
        "the remainder is busy-minus-attributed; stolen time is in neither")


def test_bare_metal_carries_no_stolen_fact_at_all(monkeypatch, tmp_path):
    """Absent rather than zero, like every other reading here: a standing
    zero would report a condition the machine cannot have."""
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "", cpu__stat="usage_usec 1\n")
    write_cgroup(root, "system.slice", cpu__stat="usage_usec 5\n")
    proc_stat(monkeypatch, tmp_path, "cpu 500 0 0 100 0 0 0 0 0 0\n")
    facts = items(monkeypatch, tmp_path)["-.slice"]["facts"]
    assert "HostCpuStolenUsec" not in facts
    assert facts["HostCpuBusyUsec"] == 500 * (1_000_000 // (os.sysconf("SC_CLK_TCK") or 100))


def test_the_remainder_names_the_slice_boundary_not_the_cgroup_boundary():
    """Wording, pinned. Measured across five hosts: on four of them the root
    cgroup's own cpu.stat equals the host total, so the leftover tasks DO sit
    in a cgroup — the root. Calling it work in no cgroup at all was wrong
    about where it lives, and the sentence is what an operator reads."""
    entry = adapter._GLOSSARY["UnattributedCpuUsec"]
    assert "no top-level slice" in entry
    assert "no cgroup at all" not in entry.replace(
        "deliberately not called work in no cgroup at all", "")


def test_the_remainder_cannot_go_negative_because_the_total_is_read_last(
        monkeypatch, tmp_path):
    """Both sides are monotonic counters, so a total sampled after its parts
    can only be larger. The ordering is what makes this safe; clamping a
    negative afterwards would hide a real inconsistency behind a plausible
    number, which is the failure mode this whole subsystem is built against.

    Here the cgroups are made to claim MORE than the host — the state a
    simultaneous read could never produce — and the guard holds anyway.
    """
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "system.slice", cpu__stat="usage_usec 999999999\n")
    proc_stat(monkeypatch, tmp_path, "cpu 1 0 0 0 0 0 0 0 0 0\n")
    facts = items(monkeypatch, tmp_path)["-.slice"]["facts"]
    assert facts["UnattributedCpuUsec"] == 0


def test_no_remainder_is_offered_for_memory_or_block_io(monkeypatch, tmp_path):
    """The restraint, pinned. Memory's host total is a heuristic and block
    I/O's double-counts every stacked device, so a remainder for either would
    be this product inventing precision — which is exactly what the earlier
    design did with a per-workload 'share of I/O time'."""
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "", cpu__stat="usage_usec 10\n")
    write_cgroup(root, "system.slice", cpu__stat="usage_usec 5\n",
                 memory__current="100", io__stat=IO_STAT)
    proc_stat(monkeypatch, tmp_path, "cpu 100 0 0 0 0 0 0 0 0 0\n")

    facts = items(monkeypatch, tmp_path)["-.slice"]["facts"]
    assert "UnattributedCpuUsec" in facts
    assert not [fact for fact in facts
                if fact.startswith("Unattributed") and fact != "UnattributedCpuUsec"]
    assert not [fact for fact in adapter._GLOSSARY
                if fact.startswith("Unattributed") and fact != "UnattributedCpuUsec"]


def test_the_remainder_is_absent_when_the_host_total_cannot_be_read(
        monkeypatch, tmp_path):
    """Unobservable is not zero. A /proc that will not open leaves the
    workloads' own counters standing and says nothing about the host."""
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "", cpu__stat="usage_usec 9\n")
    write_cgroup(root, "system.slice", cpu__stat="usage_usec 5\n")
    monkeypatch.setattr(adapter, "PROC_STAT", str(tmp_path / "nope"))
    facts = items(monkeypatch, tmp_path)["-.slice"]["facts"]
    assert facts["CpuUsageUsec"] == 9, "the root's own reading still stands"
    assert "UnattributedCpuUsec" not in facts
    assert "HostCpuBusyUsec" not in facts


def test_a_host_with_no_cpu_accounting_states_no_remainder(monkeypatch, tmp_path):
    """Nothing at depth 1 reports CPU — the controller is off. A remainder
    computed against an empty attributed sum would report the entire host as
    unattributed, which is a confident answer produced by a missing one."""
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "", io__stat=IO_STAT)
    write_cgroup(root, "system.slice", io__stat=IO_STAT)
    proc_stat(monkeypatch, tmp_path, "cpu 500 0 0 0 0 0 0 0 0 0\n")
    facts = items(monkeypatch, tmp_path)["-.slice"]["facts"]
    assert "UnattributedCpuUsec" not in facts
    assert "HostCpuBusyUsec" not in facts, (
        "a total published beside no attributed sum invites the reader to do "
        "the subtraction this refused to do")


# ── delegation is stated, because it is why a figure stops decomposing ───

def test_a_delegating_unit_says_its_total_covers_a_hierarchy_it_cannot_break_down(
        monkeypatch, tmp_path):
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "system.slice", cpu__stat="usage_usec 10\n")
    write_cgroup(root, "system.slice/docker-4d1f9c02ab77.scope",
                 cpu__stat="usage_usec 9\n")
    write_cgroup(root, "system.slice/docker-4d1f9c02ab77.scope/init.scope",
                 cpu__stat="usage_usec 4\n")

    rows = items(monkeypatch, tmp_path)
    assert rows["docker-4d1f9c02ab77.scope"]["facts"]["Delegated"] is True
    # The guest's own units are another manager's and get no row here.
    assert "init.scope" not in rows
    # A slice is not "delegated": its members ARE rows, and the ladder below
    # it is walkable, which is the whole difference the fact records.
    assert "Delegated" not in rows["system.slice"]["facts"]


# ── the two projections agree, and the row is a subset ───────────────────

def test_the_row_is_trimmed_and_the_opened_object_is_not(monkeypatch, tmp_path):
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "system.slice/example.service", cpu__stat=CPU_STAT,
                 io__pressure=("some avg10=1 avg60=2 avg300=3 total=1\n"
                               "full avg10=4 avg60=5 avg300=6 total=2\n"))
    proc_stat(monkeypatch, tmp_path, "cpu 1 0 0 0 0 0 0 0 0 0\n")

    page = asyncio.run(adapter.Adapter().collect("workloads", {}, None, None))
    [row] = [item for item in page["items"]
             if item["native_id"] == "example.service"]
    assert set(row["facts"]) <= set(adapter.ROW_FACTS)
    assert "PsiIoFullAvg300" not in row["facts"], "the shape belongs to the object"
    assert "CpuUserUsec" not in row["facts"]

    opened = asyncio.run(
        adapter.Adapter().get_object("workloads", "unit:example.service"))
    assert opened["facts"]["PsiIoFullAvg300"] == 6.0
    assert opened["facts"]["CpuUserUsec"] == 3001000000
    assert opened["facts"]["PsiIoFullAvg60"] == row["facts"]["PsiIoFullAvg60"]


def test_a_row_severity_is_judged_on_the_full_facts_not_the_trimmed_ones(
        monkeypatch, tmp_path):
    """The trim happens after the verdict deliberately. Judging the carried
    subset would let a row's dot depend on which facts a display decision
    happened to keep."""
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "system.slice/hot.service",
                 io__pressure="full avg10=0 avg60=99.0 avg300=0 total=1\n")
    proc_stat(monkeypatch, tmp_path, "cpu 1 0 0 0 0 0 0 0 0 0\n")
    page = asyncio.run(adapter.Adapter().collect("workloads", {}, None, None))
    [row] = [item for item in page["items"] if item["native_id"] == "hot.service"]
    assert row["worst_opinion_level"] == "warn"
    assert row["opinions"][0]["key"] == "workload-io-stall"


# ── capability, evidence and the routes that refuse ──────────────────────

def test_a_host_with_no_cgroup_v2_declines_with_the_reason(monkeypatch, tmp_path):
    tree(monkeypatch, tmp_path, controllers=False)
    answer = asyncio.run(adapter.Adapter().capability())
    assert answer["available"] is False
    assert "cgroup v2" in answer["reason"]
    assert "cgroup v1" in answer["reason"], "says what the host has, not only what it lacks"


def test_evidence_shows_the_kernel_files_the_row_was_folded_from(
        monkeypatch, tmp_path):
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "system.slice/example.service", cpu__stat=CPU_STAT)
    proc_stat(monkeypatch, tmp_path, "cpu 1 0 0 0 0 0 0 0 0 0\n")

    evidence = asyncio.run(
        adapter.Adapter().get_evidence("workloads", "unit:example.service"))
    payload = evidence["payload"]
    cpu = [text for path, text in payload.items() if path.endswith("cpu.stat")]
    assert cpu == [CPU_STAT]
    # A file the kernel does not keep is shown as the reason it did not open,
    # never omitted: the same distinction the fact side preserves.
    missing = [text for path, text in payload.items()
               if path.endswith("memory.current")]
    assert missing and "FileNotFoundError" in missing[0]


def test_only_the_root_owes_the_denominator_it_subtracted_from(
        monkeypatch, tmp_path):
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "", cpu__stat="usage_usec 1\n")
    write_cgroup(root, "system.slice/example.service", cpu__stat=CPU_STAT)
    stat = proc_stat(monkeypatch, tmp_path, "cpu 1 0 0 0 0 0 0 0 0 0\n")

    leaf = asyncio.run(
        adapter.Adapter().get_evidence("workloads", "unit:example.service"))
    assert str(stat) not in leaf["payload"]
    rootev = asyncio.run(
        adapter.Adapter().get_evidence("workloads", "unit:-.slice"))
    assert str(stat) in rootev["payload"]


def test_a_name_that_only_exists_inside_a_delegated_hierarchy_has_no_evidence(
        monkeypatch, tmp_path):
    """Evidence that vouched for it would be publishing another manager's
    cgroup as though this collection had served it."""
    root = tree(monkeypatch, tmp_path)
    write_cgroup(root, "system.slice/docker-4d1f9c02ab77.scope",
                 cpu__stat="usage_usec 9\n")
    write_cgroup(root, "system.slice/docker-4d1f9c02ab77.scope/nginx.service",
                 cpu__stat="usage_usec 4\n")
    with pytest.raises(LookupError):
        asyncio.run(adapter.Adapter().get_evidence("workloads",
                                                   "unit:nginx.service"))


def test_an_unknown_collection_is_refused(monkeypatch, tmp_path):
    tree(monkeypatch, tmp_path)
    with pytest.raises(KeyError):
        asyncio.run(adapter.Adapter().acquire("cgroups"))
    with pytest.raises(KeyError):
        asyncio.run(adapter.Adapter().get_evidence("cgroups", "unit:-.slice"))
