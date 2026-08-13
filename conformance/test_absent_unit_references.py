"""The backwards walk: who references a unit that is not present on this host.

A unit ordered After=, wanting or requiring a name systemd cannot load reads
as silent success today — the name turns up in ListUnits as not-found,
inactive, with no other facts and nobody's name on it. The finding belongs to
the unit that WROTE the reference, and the only affordable way to find that
unit is to ask the absent name who points at it: systemd stores every
dependency together with its inverse, so a not-found unit's WantedBy and
Before are populated even though it has no fragment at all.

What is exercised here is the cost and the honesty of that walk, neither of
which the rulebook can see:

  * one probe per NOT-FOUND unit, never one per unit — the whole reason the
    reverse direction was chosen over reading After=/Wants=/Requires= off
    eight hundred units;
  * a host with nothing not-found pays nothing, which is the ordinary case
    and the one a cost regression would hide in;
  * a probe that fails, or a listing too large to probe in full, is stated as
    unread on the absent name's own row and never reaches a reader as "nothing
    references this" (SPEC section 2, rule 7);
  * the row's backwards reading and the detail view's forwards reading of the
    same edge produce the same fact, because they go through one formatter.

No estate hostnames and no real unit names: every unit below is invented, and
the shapes are what matter — a host serving these exact names would be a
strange host, but the walk cannot tell.
"""

import asyncio

import pytest

from system_explorer.agent.adapters import units

UNIT_IFACE = "org.freedesktop.systemd1.Unit"

# The ListUnits row, which is what the probe is handed: (name, description,
# load state, active state, sub state, following, object path, job id, job
# type, job path). Only the name, the load state and the path are read, and
# the full arity is kept so an index that moved would fail here rather than
# quietly reading the wrong column.
def listed(name: str, load: str = "loaded") -> tuple:
    path = "/org/freedesktop/systemd1/unit/" + name.replace(".", "_2e")
    return (name, f"description of {name}", load, "inactive", "dead", "",
            path, 0, "", "/")


class FakeBus:
    """A system bus that answers GetAll from a table and counts the asking.

    The count is the assertion: this module exists because the honest reading
    of the dependency graph is a per-unit round trip, and the only thing that
    makes it shippable is that it is paid per ABSENT unit instead. A change
    that quietly starts probing every unit would still be correct, and would
    still pass every fact assertion below.
    """

    def __init__(self, properties: dict[str, dict], fail: dict[str, Exception] | None = None):
        self.properties = properties
        self.fail = fail or {}
        self.probed: list[str] = []

    async def get_all(self, destination: str, path: str, interface: str) -> dict:
        assert interface == UNIT_IFACE, interface
        name = path.rsplit("/", 1)[-1].replace("_2e", ".")
        self.probed.append(name)
        if name in self.fail:
            raise self.fail[name]
        return self.properties.get(name, {})


class DeniedCall(RuntimeError):
    """A D-Bus error reply, in the shape sysbus.CallError carries: the error
    NAME is the part worth keeping, because it is what separates a denied call
    from a unit that went away, and it is the part with nothing interpolated
    into it."""

    error_name = "org.freedesktop.DBus.Error.AccessDenied"


def walk(rows, properties, fail=None, monkeypatch=None):
    """The reverse walk over one host's listing, with the bus faked."""
    bus = FakeBus(properties, fail)
    monkeypatch.setattr(units, "BUS", bus)
    refs, unread = asyncio.run(units.Adapter()._absent_unit_references(rows))
    return refs, unread, bus


# ---------------------------------------------------------------------------
# Cost. The first two are the reason the reverse direction exists at all.
# ---------------------------------------------------------------------------

def test_a_host_with_nothing_not_found_makes_no_call_at_all(monkeypatch):
    """The common case, and the one a cost regression hides in: every unit
    loaded, so there is nothing to walk backwards from and the collection page
    must not pay a single round trip for this feature."""
    rows = [listed(f"worker-{index}.service") for index in range(400)]
    refs, unread, bus = walk(rows, {}, monkeypatch=monkeypatch)
    assert bus.probed == []
    assert refs == {} and unread == {}


def test_the_probe_count_is_the_not_found_count_not_the_unit_count(monkeypatch):
    """One call per absent name. Reading the forward properties instead would
    be one per unit — 400 here, and ~800 on a real host — which is precisely
    the shape this adapter reads Slice from cgroupfs to avoid."""
    rows = ([listed(f"worker-{index}.service") for index in range(400)]
            + [listed(f"absent-{index}.service", "not-found") for index in range(6)])
    _refs, _unread, bus = walk(rows, {}, monkeypatch=monkeypatch)
    assert len(bus.probed) == 6
    assert set(bus.probed) == {f"absent-{index}.service" for index in range(6)}


def test_the_cap_bounds_a_pathological_listing_and_says_what_it_skipped(monkeypatch):
    """A dependency graph gone wrong must not turn a collection page into
    hundreds of round trips. Units past the cap are not silently dropped —
    dropping them would put "nothing references this" on rows nobody looked
    at, which is the failure this whole module is built against."""
    count = units.MISSING_UNIT_PROBE_LIMIT + 25
    rows = [listed(f"absent-{index:04d}.service", "not-found") for index in range(count)]
    _refs, unread, bus = walk(rows, {}, monkeypatch=monkeypatch)
    assert len(bus.probed) == units.MISSING_UNIT_PROBE_LIMIT
    assert len(unread) == 25
    # Deterministic: the same 25 names every collection, so the gap does not
    # wander around the listing between polls.
    assert sorted(unread) == [f"absent-{index:04d}.service"
                              for index in range(units.MISSING_UNIT_PROBE_LIMIT, count)]
    for reason in unread.values():
        assert str(units.MISSING_UNIT_PROBE_LIMIT) in reason
        assert "not none" in reason


# ---------------------------------------------------------------------------
# The dependency kinds, one fixture each. The consequence is what groups them
# and the directive is what the value must keep.
# ---------------------------------------------------------------------------

KIND_CASES = [
    # (reverse property on the absent unit, the directive its author wrote,
    #  the fact it lands in)
    ("RequiredBy", "Requires", "MissingRequirements"),
    ("RequisiteOf", "Requisite", "MissingRequirements"),
    ("BoundBy", "BindsTo", "MissingRequirements"),
    ("WantedBy", "Wants", "MissingWants"),
    ("UpheldBy", "Upholds", "MissingWants"),
    ("Before", "After", "MissingOrdering"),
    ("After", "Before", "MissingOrdering"),
]


@pytest.mark.parametrize("prop,directive,fact", KIND_CASES,
                         ids=[case[1] for case in KIND_CASES])
def test_each_kind_lands_on_the_referencing_unit_naming_the_directive(
        prop, directive, fact, monkeypatch):
    """The fact is on the unit that wrote the reference — the one with a
    fragment, an owner and a fix — and it states the directive, because
    Wants= a missing unit and Requires= a missing unit are the same shape with
    different consequences and must not read alike."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found")]
    refs, unread, _bus = walk(
        rows, {"message-broker.service": {prop: ["ingest-worker.service"]}},
        monkeypatch=monkeypatch)
    assert unread == {}
    assert refs == {"ingest-worker.service":
                    {fact: [f"message-broker.service ({directive}=)"]}}
    # And nothing lands on the absent name itself: it has no fragment to
    # change and no owner to tell.
    assert "message-broker.service" not in refs


def test_the_three_consequences_stay_three_facts(monkeypatch):
    """One unit referencing three absent names under three classes gets three
    facts, not one merged list. A reader has to be able to tell the reference
    that stops this unit starting from the two that do nothing."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found"),
            listed("metrics-shipper.service", "not-found"),
            listed("storage-barrier.target", "not-found")]
    refs, _unread, _bus = walk(rows, {
        "message-broker.service": {"RequiredBy": ["ingest-worker.service"],
                                   "Before": ["ingest-worker.service"]},
        "metrics-shipper.service": {"WantedBy": ["ingest-worker.service"]},
        "storage-barrier.target": {"Before": ["ingest-worker.service"]},
    }, monkeypatch=monkeypatch)
    assert refs["ingest-worker.service"] == {
        "MissingOrdering": ["message-broker.service (After=)",
                            "storage-barrier.target (After=)"],
        "MissingRequirements": ["message-broker.service (Requires=)"],
        "MissingWants": ["metrics-shipper.service (Wants=)"],
    }


def test_conflicts_and_partof_are_not_probed_into_facts(monkeypatch):
    """Both say what to do when the other unit starts or stops, and a unit
    that does not exist never does either. Carrying them would put a fact on a
    row with no consequence behind it and no fix to make."""
    rows = [listed("ingest-worker.service"),
            listed("legacy-daemon.service", "not-found")]
    refs, _unread, _bus = walk(rows, {"legacy-daemon.service": {
        "ConflictedBy": ["ingest-worker.service"],
        "ConsistsOf": ["ingest-worker.service"],
        "TriggeredBy": ["ingest-worker.socket"],
    }}, monkeypatch=monkeypatch)
    assert refs == {}


def test_several_units_referencing_one_absent_name_each_get_their_own_row(monkeypatch):
    """The absent name is one row and the defect is many. Attributing it to
    the absent name would give one finding nobody can act on instead of three
    that each name a file somebody owns."""
    rows = [listed("ingest-worker.service"), listed("relay.service"),
            listed("archiver.service"), listed("message-broker.service", "not-found")]
    refs, _unread, _bus = walk(rows, {"message-broker.service": {
        "WantedBy": ["relay.service", "archiver.service"],
        "RequiredBy": ["ingest-worker.service"],
    }}, monkeypatch=monkeypatch)
    assert set(refs) == {"ingest-worker.service", "relay.service", "archiver.service"}
    assert refs["relay.service"] == {"MissingWants": ["message-broker.service (Wants=)"]}
    assert refs["ingest-worker.service"] == {
        "MissingRequirements": ["message-broker.service (Requires=)"]}


# ---------------------------------------------------------------------------
# Rule 7: a probe that could not be made.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("error,marker", [
    (DeniedCall("denied"), "AccessDenied"),
    # The ordinary end of a not-found unit: systemd keeps its Unit object only
    # while something references it, so a reload landing between the listing
    # and the probe collects it and the path stops answering.
    (RuntimeError("gone"), "RuntimeError"),
])
def test_a_probe_that_failed_is_stated_not_read_as_nothing(error, marker, monkeypatch):
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found")]
    refs, unread, _bus = walk(rows, {}, fail={"message-broker.service": error},
                              monkeypatch=monkeypatch)
    assert refs == {}, "a failed probe must not produce reference facts"
    reason = unread["message-broker.service"]
    assert marker in reason, "the error name is what tells the two failures apart"
    assert "unknown rather than none" in reason


def test_one_failed_probe_does_not_take_the_others_with_it(monkeypatch):
    """The walk is per absent name, so a denied read of one is a gap about
    that one. Returning nothing at all would turn a single unreadable unit
    into silence about every reference on the host."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found"),
            listed("metrics-shipper.service", "not-found")]
    refs, unread, _bus = walk(
        rows, {"metrics-shipper.service": {"WantedBy": ["ingest-worker.service"]}},
        fail={"message-broker.service": DeniedCall("denied")},
        monkeypatch=monkeypatch)
    assert refs == {"ingest-worker.service":
                    {"MissingWants": ["metrics-shipper.service (Wants=)"]}}
    assert set(unread) == {"message-broker.service"}


def test_the_unread_note_lands_on_the_absent_name_not_on_a_guess(monkeypatch):
    """It cannot land on the referencing unit, because the thing that went
    unread is which unit that is. So it goes on the row of the name nobody
    could ask about — the one place a reader is looking when they wonder what
    this inert entry is doing in the listing."""
    rows = [listed("message-broker.service", "not-found")]
    _refs, unread, _bus = walk(rows, {}, fail={"message-broker.service": DeniedCall("x")},
                               monkeypatch=monkeypatch)
    assert set(unread) == {"message-broker.service"}


# ---------------------------------------------------------------------------
# One formatter, two directions. The row walks the edges backwards because it
# cannot afford a property read per unit; the opened object reads the same
# edges forwards out of properties it already holds. They must agree.
# ---------------------------------------------------------------------------

def test_the_forwards_and_backwards_readings_of_one_edge_agree(monkeypatch):
    """The list and the detail view describing one unit differently is the
    failure this codebase has already paid for once, in the slice attribution
    facts. Here it is prevented structurally: both callers hand pairs to
    _absent_reference_facts, so the only way they can diverge is by disagreeing
    about which names are absent."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found"),
            listed("metrics-shipper.service", "not-found")]
    backwards, _unread, _bus = walk(rows, {
        "message-broker.service": {"RequiredBy": ["ingest-worker.service"],
                                   "Before": ["ingest-worker.service"]},
        "metrics-shipper.service": {"WantedBy": ["ingest-worker.service"]},
    }, monkeypatch=monkeypatch)

    # What get_object does: this unit's own directives, filtered to the names
    # systemd could not load.
    unloadable = {"message-broker.service", "metrics-shipper.service"}
    forward_properties = {
        "Requires": ["message-broker.service", "local-socket.socket"],
        "Wants": ["metrics-shipper.service"],
        "After": ["message-broker.service", "local-socket.socket"],
    }
    forwards = units._absent_reference_facts(
        (directive, dep)
        for directive in units.ABSENT_REFERENCE_FACTS
        for dep in forward_properties.get(directive) or []
        if dep in unloadable)
    assert forwards == backwards["ingest-worker.service"]
    # And a dependency that IS present says nothing in either direction.
    assert not any("local-socket.socket" in value
                   for values in forwards.values() for value in values)


def test_every_directive_the_formatter_accepts_has_an_inverse_to_find_it_by():
    """The two tables are one contract read from two ends. A directive the
    detail view can report with no reverse property behind it would be a fact
    that appears when a unit is opened and never on its row."""
    assert (set(units.ABSENT_REFERENCE_INVERSE.values())
            == set(units.ABSENT_REFERENCE_FACTS))
