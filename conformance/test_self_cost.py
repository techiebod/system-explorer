"""What this product costs the host it observes, measured by the product.

The gap this closes was found from OUTSIDE. The estate timed the agents over
a 960-second window and found one /v1/findings sweep burning 2.4 s of CPU on
a single-core host — roughly three quarters of that agent's entire standing
bill, at a cadence nothing had ever measured. The figure was correct and
nothing in the product could have produced it: an observer of Linux that
could not observe itself, which is the exact gap it exists to close
everywhere else.

The tests below pin what may and may not be claimed, because the temptation
here is a per-adapter CPU column that would look authoritative and be
invention: a sweep runs every subsystem concurrently in one process, so
process CPU across it belongs to the sweep and cannot be split. Per-request
attribution IS exact, because one request runs one adapter — and that
asymmetry is the whole design.
"""

from __future__ import annotations

import warnings

import pytest

from system_explorer.agent import envelope as env

warnings.filterwarnings("ignore")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from system_explorer.agent.main import app
    return TestClient(app)


MEASURES = ("wall_ms", "cpu_ms", "child_cpu_ms")


# ── the instrument itself ────────────────────────────────────────────────

def test_a_stopwatch_measures_the_span_and_nothing_before_it():
    with env.Stopwatch() as cost:
        sum(range(400_000))
    assert set(MEASURES) <= set(cost.elapsed)
    assert cost.elapsed["wall_ms"] > 0
    assert all(cost.elapsed[key] >= 0 for key in MEASURES), (
        "a negative interval means the clocks are being read out of order")


def test_the_reading_is_taken_on_exit_not_on_entry():
    """The mistake this file exists to have caught once: stamping the
    envelope INSIDE the with-block reads `elapsed` before __exit__ has run,
    which ships an empty object on every response and looks like an agent
    that simply does not report cost."""
    watch = env.Stopwatch()
    with watch:
        assert watch.elapsed == {}, "a span reported a duration before it ended"
    assert watch.elapsed["wall_ms"] >= 0


def test_memory_is_the_agents_own_and_is_never_split_by_adapter():
    """Python offers the runtime no per-object ownership to attribute, so a
    per-adapter memory column would be invention. The honest per-adapter
    answer is the cost figures, which are measured."""
    memory = env.self_memory()
    assert memory, "no memory reading at all on a platform that has one"
    assert all(isinstance(v, int) and v > 0 for v in memory.values())
    assert set(memory) <= {"rss_bytes", "peak_rss_bytes"}


# ── every answer says what it cost ───────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/v1/system/identity",
    "/v1/units/units?limit=3",
    "/v1/packages/packages?limit=1",   # declines on a non-Linux dev machine
])
def test_every_collection_answer_carries_its_cost(client, path):
    timing = client.get(path).json().get("timing")
    assert timing, f"{path} answered without saying what it cost"
    assert set(MEASURES) <= set(timing)


def test_a_collection_that_declines_still_reports_what_declining_cost(client):
    """A capability probe can shell out, so a decline is not free — and a
    cost that appears only on the successful path hides exactly the surprise
    somebody is looking for."""
    body = client.get("/v1/packages/packages?limit=1").json()
    assert body["timing"]["wall_ms"] >= 0
    # Whether it declined here or not, the shape is the same either way.
    assert "wall_ms" in body["timing"]


def test_an_opened_object_carries_its_cost_too(client):
    timing = client.get("/v1/system/identity/identity:host").json().get("timing")
    assert timing and "wall_ms" in timing


# ── what a sweep may and may not claim ───────────────────────────────────

@pytest.mark.parametrize("path", ["/v1/status", "/v1/findings"])
def test_a_sweep_reports_its_own_cpu_and_wall_per_subsystem(client, path):
    timing = client.get(path).json()["timing"]
    assert set(MEASURES) <= set(timing)
    assert timing["subsystems"], "a sweep with no per-subsystem breakdown"


@pytest.mark.parametrize("path", ["/v1/status", "/v1/findings"])
def test_a_sweep_never_claims_cpu_per_subsystem(client, path):
    """The restraint IS the design. Subsystems run concurrently in one
    process; a per-adapter CPU column would be a number nobody can produce,
    and it would look more authoritative than the wall figure beside it."""
    for name, entry in client.get(path).json()["timing"]["subsystems"].items():
        assert set(entry) == {"wall_ms"}, (
            f"{path} claims {sorted(set(entry) - {'wall_ms'})} for {name}, "
            "which concurrent execution cannot attribute")


def test_a_sweep_reports_the_agents_memory(client):
    timing = client.get("/v1/status").json()["timing"]
    assert "rss_bytes" in timing or "peak_rss_bytes" in timing


# ── and it stays out of the record ───────────────────────────────────────

# ── the mode that CAN attribute ──────────────────────────────────────────

@pytest.mark.parametrize("path", ["/v1/status", "/v1/findings"])
def test_profiling_runs_sequentially_and_attributes_cpu_per_subsystem(client, path):
    """The answer to "you are measuring the external commands, not the code
    we have written". Sequential execution removes the ambiguity concurrency
    creates: this span's process CPU is this adapter's own arithmetic, and
    its child CPU is the commands it ran."""
    timing = client.get(f"{path}?profile=1").json()["timing"]
    assert timing["attribution"] == "exact"
    entries = timing["subsystems"]
    assert entries, "a profiled sweep with no breakdown"
    for name, entry in entries.items():
        assert {"wall_ms", "cpu_ms", "child_cpu_ms"} <= set(entry), name
    # Our own compute is stated, not merely implied by subtracting commands
    # from wall — which is what "you are measuring the commands" meant.
    assert any(entry["cpu_ms"] > 0 for entry in entries.values())


@pytest.mark.parametrize("path", ["/v1/status", "/v1/findings"])
def test_the_default_says_it_is_wall_only_rather_than_leaving_it_to_be_guessed(
        client, path):
    """A consumer reading per-subsystem numbers must be able to tell an
    overlapping wall figure from an attributable one WITHOUT knowing how the
    request was made — a model summarising the table certainly cannot."""
    timing = client.get(path).json()["timing"]
    assert timing["attribution"] == "wall-only"


def test_a_profiled_sweep_still_answers_the_same_question(client):
    """Profiling changes the timing, never the findings: it is the same
    sweep, run in a different order."""
    plain = client.get("/v1/findings").json()
    profiled = client.get("/v1/findings?profile=1").json()
    assert plain["schema"] == profiled["schema"]
    assert ({f["object"]["id"] for f in plain.get("findings") or []}
            == {f["object"]["id"] for f in profiled.get("findings") or []})


# ── the agent as an observable object ────────────────────────────────────

def test_the_agent_reports_what_it_held_before_it_served_anything(client):
    """"Why is the observer the largest process on my small host" had no
    answer inside the product. Absolute RSS mostly measures Python — 62 MiB
    before a single request on a development machine, 26 of it the web
    framework — only about 13 of which is FastAPI above Starlette — so the baseline is what turns one unanswerable number
    into two answerable ones."""
    facts = client.get("/v1/system/self").json()["items"][0]["facts"]
    assert facts["RssAtStartBytes"] > 0
    assert "RssGrowthBytes" in facts
    assert facts["RssGrowthBytes"] == (
        facts.get("RssBytes", facts["PeakRssBytes"]) - facts["RssAtStartBytes"])


def test_the_agent_separates_its_own_cpu_from_the_commands_it_runs(client):
    """The two lead to different levers: a high self share means optimising
    this codebase would pay, a low one means the cost is which external
    commands run and how often, and no Python tuning touches it."""
    facts = client.get("/v1/system/self").json()["items"][0]["facts"]
    assert facts["CpuSelfSeconds"] >= 0 and facts["CpuChildrenSeconds"] >= 0
    assert 0 <= facts["CpuSelfShare"] <= 100
    assert facts["AdaptersLoaded"] > 0


def test_cost_rides_on_envelopes_and_never_on_items(client):
    """History snapshots ITEMS, not envelopes. A figure that differs on every
    request would otherwise churn /v1/changes into a permanent diff — the
    product reporting its own measurement as an estate change."""
    for item in client.get("/v1/units/units?limit=5").json().get("items", []):
        assert "timing" not in item
        assert "timing" not in item.get("facts", {})
