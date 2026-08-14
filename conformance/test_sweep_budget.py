"""Cadence declared as a share of a core, not as a number of seconds.

An interval is a blunt instrument for something whose cost varies fivefold
across an estate: one number serves a twelve-core storage server and a
one-core cloud host, and choosing it means guessing at a figure nobody had
measured. Measured, the guess was poor — a sweep costing 2.4 s of CPU every
60 s was roughly three quarters of the smallest host's entire standing bill.

The three properties below are what make it safe to enable, and each is here
because the obvious implementation gets it wrong: a budget that could hurry a
sweep would make hosts MORE expensive than the interval they have today; one
that guessed a cost for an agent that reports none would be inventing the
input; and one with no ceiling would let an expensive host quietly stop being
attended to, which is worse than an expensive host.
"""

from __future__ import annotations

import pytest

from system_explorer.hub import server


@pytest.fixture
def budget(monkeypatch):
    def configure(percent, floor=60.0, ceiling=900.0):
        monkeypatch.setattr(server, "FINDINGS_SWEEP_BUDGET", percent)
        monkeypatch.setattr(server, "FINDINGS_SWEEP_SECONDS", floor)
        monkeypatch.setattr(server, "FINDINGS_SWEEP_MAX_SECONDS", ceiling)
    return configure


def test_no_budget_means_the_interval_every_deployment_has_today(budget):
    budget(0)
    assert server.sweep_interval(2360) == 60.0
    assert server.sweep_interval(None) == 60.0


def test_a_costly_sweep_is_slowed_to_hold_the_declared_share(budget):
    """2.36 s of CPU at one percent of a core is one sweep every 236 s —
    the measured beacon figure, which is where the number came from."""
    budget(1)
    assert server.sweep_interval(2360) == pytest.approx(236.0)
    budget(2)
    assert server.sweep_interval(2360) == pytest.approx(118.0)


def test_a_budget_can_only_ever_slow_a_sweep_down(budget):
    """The floor is the configured interval, so enabling a budget cannot make
    any host more expensive than it is now — and a host already inside its
    budget is swept exactly as often as before."""
    budget(1)
    assert server.sweep_interval(100) == 60.0, "a cheap host was hurried"
    assert server.sweep_interval(600) == 60.0, "exactly at budget, still floor"
    assert server.sweep_interval(601) > 60.0


def test_an_agent_that_reports_no_cost_keeps_the_fixed_interval(budget):
    """Agents predating the timing field report nothing, and guessing a cost
    for them would be the invention this product refuses everywhere else."""
    budget(1)
    for unmeasured in (None, 0, 0.0):
        assert server.sweep_interval(unmeasured) == 60.0


def test_an_expensive_host_is_still_looked_at(budget):
    """An attention surface that quietly stops attending is worse than an
    expensive one."""
    budget(0.1, ceiling=900.0)
    assert server.sweep_interval(60_000) == 900.0


def test_the_ceiling_never_undercuts_the_floor(budget):
    """A misconfiguration where the ceiling is below the configured interval
    must not sweep FASTER than configured — the floor is the promise."""
    budget(1, floor=300.0, ceiling=120.0)
    assert server.sweep_interval(2360) >= 300.0
