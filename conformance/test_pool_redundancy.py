"""What a pool survives losing — as a fact, graded by nothing.

The restraint is the design. Whether a pool with no parity is a problem
depends entirely on what sits on it: a stripe holding replicas of data that
lives elsewhere is a capacity decision, and the same stripe under an
irreplaceable dataset with no other copy is a real exposure. This adapter
knows the layout and cannot know the second thing, so it states the layout
and grades nothing — which is also the conclusion two reviewers reached
independently after one of them ranked "no redundancy" as the estate's top
risk and was corrected by the operator.

The parsing is tested hard because the parity level is not where anyone would
look for it. Measured against zpool status -j on two live layouts: a raidz1
vdev reports vdev_type "raidz" with NO nparity key anywhere in the document,
and the only place the number appears is the name zpool assigned, "raidz1-0".
A reader that trusted the type would report "raidz" for every parity level.
"""

from __future__ import annotations

import pytest

from system_explorer.agent.adapters.storage import _POOL_GLOSSARY, _redundancy


def vdev(name, depth, kind, **extra):
    return {"Name": name, "Depth": depth, "Type": kind, **extra}


def disks(n, depth=2):
    return [vdev(f"wwn-{i}", depth, "disk") for i in range(n)]


# ── the two layouts that actually exist on the estate ────────────────────

def test_a_raidz1_vdev_reports_its_parity_from_the_name():
    """The measured case. vdev_type is "raidz" for every parity level, so the
    number has to come from zpool's own name for the vdev — and a reader that
    used the type would say "raidz" and tolerate nothing it could justify."""
    layout, tolerated = _redundancy([vdev("raidz1-0", 1, "raidz"), *disks(5)])
    assert (layout, tolerated) == ("raidz1", 1)


def test_a_two_disk_stripe_tolerates_nothing():
    """Bare disks directly under the root, which is what zpool emits for a
    stripe — there is no intermediate vdev to read a type from."""
    assert _redundancy([vdev("wwn-a", 1, "disk"), vdev("wwn-b", 1, "disk")]) == (
        "stripe", 0)


@pytest.mark.parametrize("name,parity", [
    ("raidz1-0", 1), ("raidz2-0", 2), ("raidz3-1", 3),
    ("draid2:4d:12c:1s-0", 2),
])
def test_every_parity_level_is_read_from_the_name(name, parity):
    kind = "draid" if name.startswith("draid") else "raidz"
    assert _redundancy([vdev(name, 1, kind)]) == (name.split("-")[0].split(":")[0],
                                                  parity)


# ── mirrors count their own members ──────────────────────────────────────

def test_a_mirror_survives_all_but_one_member():
    assert _redundancy([vdev("mirror-0", 1, "mirror"), *disks(2)]) == ("mirror", 1)
    assert _redundancy([vdev("mirror-0", 1, "mirror"), *disks(3)]) == ("mirror", 2)


def test_two_mirrors_do_not_lend_each_other_disks():
    """Members are counted as the walk passes them, not globally — a pool of
    two mirrors would otherwise credit each with the other's disks and report
    a tolerance of three where the truth is one."""
    tree = [vdev("mirror-0", 1, "mirror"), *disks(2),
            vdev("mirror-1", 1, "mirror"), *disks(2)]
    assert _redundancy(tree) == ("mirror", 1)


def test_a_mirror_with_one_member_left_is_not_read_as_redundant():
    """Rather than reporting a tolerance of zero for something the walk did
    not really understand, this declines — the shape is unexpected and a
    confident number about a degraded mirror is worse than none."""
    assert _redundancy([vdev("mirror-0", 1, "mirror"), *disks(1)]) == (None, None)


# ── the weakest vdev decides, because losing any one loses the pool ──────

def test_a_mirror_beside_a_bare_disk_is_named_in_full_and_tolerates_nothing():
    """The half-truth this fact exists not to print. Summarising this pool as
    "mirror" would describe the good half of a layout whose next disk failure
    takes everything."""
    tree = [vdev("mirror-0", 1, "mirror"), *disks(2),
            vdev("wwn-lone", 1, "disk")]
    layout, tolerated = _redundancy(tree)
    assert tolerated == 0
    assert "mirror" in layout and "stripe" in layout


def test_mixed_parity_takes_the_lower():
    tree = [vdev("raidz2-0", 1, "raidz"), vdev("raidz1-1", 1, "raidz")]
    layout, tolerated = _redundancy(tree)
    assert tolerated == 1
    assert layout == "raidz2 + raidz1"


# ── what is not redundancy ───────────────────────────────────────────────

@pytest.mark.parametrize("group", ["spares", "logs", "l2cache"])
def test_a_spare_or_a_log_device_is_not_counted(group):
    """A cache or log device leaving is not a pool leaving, and a spare is
    protection that is not attached to anything yet — counting either would
    report redundancy the pool does not have."""
    tree = [vdev("raidz1-0", 1, "raidz"), *disks(3),
            vdev("extra", 1, "disk", Group=group)]
    assert _redundancy(tree) == ("raidz1", 1)


def test_an_unrecognised_vdev_type_declines_rather_than_assuming():
    """Claiming tolerance this walk cannot justify is the direction that gets
    somebody hurt, so a shape nobody taught it about yields no fact at all."""
    assert _redundancy([vdev("weird-0", 1, "newthing")]) == (None, None)
    assert _redundancy([vdev("raidz-0", 1, "raidz")]) == (None, None), (
        "a raidz vdev whose name carries no parity level is unreadable, "
        "not raidz1"
    )


def test_an_empty_pool_yields_no_fact():
    assert _redundancy([]) == (None, None)


# ── the restraint, pinned ────────────────────────────────────────────────

def test_the_glossary_says_who_grades_this_and_that_it_is_not_here():
    """Two reviewers reached this independently after one ranked "no
    redundancy" as the estate's top risk and the operator corrected it: the
    layout is a fact, and only something that knows what lives on the pool
    can turn it into a verdict."""
    entry = _POOL_GLOSSARY["DeviceFailuresTolerated"]
    assert "protection inventory" in entry
    assert "graded by nothing here" in entry


def test_redundancy_draws_no_opinion():
    """The pool rulebook must not learn to judge this fact by the back door:
    an opinion keyed on layout alone would fire on every replica pool in the
    estate, which is the noise this restraint exists to avoid."""
    from system_explorer.agent.rules import storage as rules
    facts = {"State": "ONLINE", "Errors": 0, "Redundancy": "stripe",
             "DeviceFailuresTolerated": 0}
    keys = {o["key"] for o in rules.pool_opinions(facts)}
    assert not [k for k in keys if "redund" in k.lower()]
