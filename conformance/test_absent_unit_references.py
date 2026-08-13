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


def synthesised(name: str) -> dict:
    """What LoadUnit followed by GetAll really returns for a name nobody ever
    wrote: a complete, inert, not-found Unit object.

    Verified against a live systemd 260. This is the whole reason LoadUnit can
    never decide on its own whether an object exists, and therefore the whole
    reason the listing is the discriminator — an invented name is byte-for-byte
    this shape, and so is a name the host genuinely lists.
    """
    return {"Id": name, "LoadState": "not-found", "ActiveState": "inactive",
            "SubState": "dead", "Description": name,
            "UnitFileState": "", "FragmentPath": "", "ActiveEnterTimestamp": 0,
            "LoadError": ["org.freedesktop.systemd1.NoSuchUnit",
                          f"Unit {name} not found."]}


# The type-specific interfaces answer for a not-found unit too, with defaults
# describing nothing — Result "success" on a unit with no file. Serving these
# is the fabrication the object route must never commit, so the fake offers
# them and the tests assert they are never asked for.
FABRICATED_SERVICE_DEFAULTS = {"MainPID": 0, "NRestarts": 0, "Result": "success",
                               "TasksCurrent": 2**64 - 1, "Restart": "no",
                               "ExecMainStartTimestamp": 0}


class FakeBus:
    """A system bus that answers from tables and counts the asking.

    The counts are assertions in their own right: this module exists because
    the honest reading of the dependency graph is a per-unit round trip, and
    the only thing that makes it shippable is that it is paid per ABSENT unit
    instead. A change that quietly starts probing every unit would still be
    correct, and would still pass every fact assertion below.
    """

    def __init__(self, properties: dict[str, dict], fail: dict[str, Exception] | None = None,
                 rows: list | None = None, typed: dict[str, dict] | None = None,
                 list_error: Exception | None = None):
        self.properties = properties
        self.fail = fail or {}
        self.rows = rows or []
        self.typed = typed or {}
        self.list_error = list_error
        self.probed: list[str] = []
        self.interfaces: list[str] = []
        self.listings = 0

    async def call(self, destination: str, path: str, interface: str, member: str,
                   signature: str = "", body: list | None = None) -> list:
        if member == "ListUnits":
            self.listings += 1
            if self.list_error is not None:
                raise self.list_error
            return [self.rows]
        if member == "LoadUnit":
            # Never refuses. That is the point of the whole gate.
            name = (body or [""])[0]
            return ["/org/freedesktop/systemd1/unit/" + name.replace(".", "_2e")]
        raise AssertionError(f"unexpected manager call: {member}")

    async def get_all(self, destination: str, path: str, interface: str) -> dict:
        name = path.rsplit("/", 1)[-1].replace("_2e", ".")
        self.interfaces.append(interface)
        if interface != UNIT_IFACE:
            return self.typed.get(name, dict(FABRICATED_SERVICE_DEFAULTS))
        self.probed.append(name)
        if name in self.fail:
            raise self.fail[name]
        return self.properties.get(name) or synthesised(name)


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
    refs, absent = asyncio.run(units.Adapter()._absent_unit_references(rows))
    return refs, absent, bus


# ---------------------------------------------------------------------------
# Cost. The first two are the reason the reverse direction exists at all.
# ---------------------------------------------------------------------------

def test_a_host_with_nothing_not_found_makes_no_call_at_all(monkeypatch):
    """The common case, and the one a cost regression hides in: every unit
    loaded, so there is nothing to walk backwards from and the collection page
    must not pay a single round trip for this feature."""
    rows = [listed(f"worker-{index}.service") for index in range(400)]
    refs, absent, bus = walk(rows, {}, monkeypatch=monkeypatch)
    assert bus.probed == []
    assert refs == {} and absent == {}


def test_the_probe_count_is_the_not_found_count_not_the_unit_count(monkeypatch):
    """One call per absent name. Reading the forward properties instead would
    be one per unit — 400 here, and ~800 on a real host — which is precisely
    the shape this adapter reads Slice from cgroupfs to avoid."""
    rows = ([listed(f"worker-{index}.service") for index in range(400)]
            + [listed(f"absent-{index}.service", "not-found") for index in range(6)])
    _refs, _absent, bus = walk(rows, {}, monkeypatch=monkeypatch)
    assert len(bus.probed) == 6
    assert set(bus.probed) == {f"absent-{index}.service" for index in range(6)}


def test_the_cap_bounds_a_pathological_listing_and_says_what_it_skipped(monkeypatch):
    """A dependency graph gone wrong must not turn a collection page into
    hundreds of round trips. Units past the cap are not silently dropped —
    dropping them would put "nothing references this" on rows nobody looked
    at, which is the failure this whole module is built against."""
    count = units.MISSING_UNIT_PROBE_LIMIT + 25
    rows = [listed(f"absent-{index:04d}.service", "not-found") for index in range(count)]
    _refs, absent, bus = walk(rows, {}, monkeypatch=monkeypatch)
    assert len(bus.probed) == units.MISSING_UNIT_PROBE_LIMIT
    assert len(absent) == 25
    # Deterministic: the same 25 names every collection, so the gap does not
    # wander around the listing between polls.
    assert sorted(absent) == [f"absent-{index:04d}.service"
                              for index in range(units.MISSING_UNIT_PROBE_LIMIT, count)]
    for facts in absent.values():
        assert str(units.MISSING_UNIT_PROBE_LIMIT) in facts["MissingReferenceUnobservable"]
        assert "not none" in facts["MissingReferenceUnobservable"]
        assert "ReferencedBy" not in facts, (
            "a name that was never probed must not also appear to have been "
            "answered")


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
    refs, absent, _bus = walk(
        rows, {"message-broker.service": {prop: ["ingest-worker.service"]}},
        monkeypatch=monkeypatch)
    assert refs == {"ingest-worker.service":
                    {fact: [f"message-broker.service ({directive}=)"]}}
    # No FINDING lands on the absent name: it has no fragment to change and no
    # owner to tell. What lands there is the other half of the same edge —
    # which unit asked for it — because that is the one question its row can
    # answer and the only reason it is in the listing at all.
    assert "message-broker.service" not in refs
    assert absent == {"message-broker.service":
                      {"ReferencedBy": [f"ingest-worker.service ({directive}=)"]}}


def test_the_three_consequences_stay_three_facts(monkeypatch):
    """One unit referencing three absent names under three classes gets three
    facts, not one merged list. A reader has to be able to tell the reference
    that stops this unit starting from the two that do nothing."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found"),
            listed("metrics-shipper.service", "not-found"),
            listed("storage-barrier.target", "not-found")]
    refs, _absent, _bus = walk(rows, {
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


def test_conflicts_and_partof_reach_the_absent_page_but_never_a_finding(monkeypatch):
    """The two maps answer different questions and the split is deliberate.

    Conflicts= and PartOf= both say what to do when the other unit starts or
    stops, and a unit that does not exist never does either — so no finding,
    no fact on the referencing row, nothing for anyone to fix. But they are
    still the reason the absent name is in the listing, and on ITS page that is
    the whole question. A page reading "absent, and nobody wanted it" for a
    name two units conflict with would be wrong; found live before this split
    existed.
    """
    rows = [listed("ingest-worker.service"), listed("relay.service"),
            listed("legacy-daemon.service", "not-found")]
    refs, absent, _bus = walk(rows, {"legacy-daemon.service": {
        "ConflictedBy": ["ingest-worker.service"],
        "ConsistsOf": ["relay.service"],
    }}, monkeypatch=monkeypatch)
    assert refs == {}, "neither directive may put a fact on a referencing row"
    assert absent["legacy-daemon.service"] == {
        "ReferencedBy": ["ingest-worker.service (Conflicts=)",
                         "relay.service (PartOf=)"]}


def test_activation_alone_is_not_spelled_as_a_directive(monkeypatch):
    """TriggeredBy names no directive — socket activation pairs by unit name —
    so writing it as "(Triggers=)" would put a word in an author's mouth. The
    activating unit reaches the page through the ordering edge systemd adds
    beside it, which is a directive and is real."""
    rows = [listed("legacy-daemon.service", "not-found")]
    _refs, absent, _bus = walk(rows, {"legacy-daemon.service": {
        "TriggeredBy": ["legacy-daemon.socket"],
        "After": ["legacy-daemon.socket"],
    }}, monkeypatch=monkeypatch)
    assert absent["legacy-daemon.service"] == {
        "ReferencedBy": ["legacy-daemon.socket (Before=)"]}


def test_several_units_referencing_one_absent_name_each_get_their_own_row(monkeypatch):
    """The absent name is one row and the defect is many. Attributing it to
    the absent name would give one finding nobody can act on instead of three
    that each name a file somebody owns."""
    rows = [listed("ingest-worker.service"), listed("relay.service"),
            listed("archiver.service"), listed("message-broker.service", "not-found")]
    refs, _absent, _bus = walk(rows, {"message-broker.service": {
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
    refs, absent, _bus = walk(rows, {}, fail={"message-broker.service": error},
                              monkeypatch=monkeypatch)
    assert refs == {}, "a failed probe must not produce reference facts"
    facts = absent["message-broker.service"]
    reason = facts["MissingReferenceUnobservable"]
    assert marker in reason, "the error name is what tells the two failures apart"
    assert "unknown rather than none" in reason
    assert "ReferencedBy" not in facts, (
        "the two are mutually exclusive: a row must never carry an answer "
        "beside the note saying nobody could be asked")


def test_one_failed_probe_does_not_take_the_others_with_it(monkeypatch):
    """The walk is per absent name, so a denied read of one is a gap about
    that one. Returning nothing at all would turn a single unreadable unit
    into silence about every reference on the host."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found"),
            listed("metrics-shipper.service", "not-found")]
    refs, absent, _bus = walk(
        rows, {"metrics-shipper.service": {"WantedBy": ["ingest-worker.service"]}},
        fail={"message-broker.service": DeniedCall("denied")},
        monkeypatch=monkeypatch)
    assert refs == {"ingest-worker.service":
                    {"MissingWants": ["metrics-shipper.service (Wants=)"]}}
    assert "MissingReferenceUnobservable" in absent["message-broker.service"]
    assert absent["metrics-shipper.service"] == {
        "ReferencedBy": ["ingest-worker.service (Wants=)"]}


def test_the_unread_note_lands_on_the_absent_name_not_on_a_guess(monkeypatch):
    """It cannot land on the referencing unit, because the thing that went
    unread is which unit that is. So it goes on the row of the name nobody
    could ask about — the one place a reader is looking when they wonder what
    this inert entry is doing in the listing."""
    rows = [listed("message-broker.service", "not-found")]
    _refs, absent, _bus = walk(rows, {}, fail={"message-broker.service": DeniedCall("x")},
                               monkeypatch=monkeypatch)
    assert set(absent) == {"message-broker.service"}


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
    backwards, _absent, _bus = walk(rows, {
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
    """The tables are one contract read from two ends. A directive the detail
    view can report with no reverse property behind it would be a fact that
    appears when a unit is opened and never on its row.

    REFERRER_PROPERTIES is allowed to know MORE — it answers "why is this name
    listed" rather than "what has a consequence" — but it may never know less,
    or a referrer would reach the referencing row while its own page denied it.
    """
    assert (set(units.ABSENT_REFERENCE_INVERSE.values())
            == set(units.ABSENT_REFERENCE_FACTS))
    assert (set(units.ABSENT_REFERENCE_INVERSE)
            <= set(units.REFERRER_PROPERTIES))


# ---------------------------------------------------------------------------
# Opening one of these rows.
#
# The collection SERVES units systemd could not load, deliberately: systemctl
# reports them, and the operator's ruling is that their emptiness can itself
# tell an administrator something. A row a collection serves that 404s when
# opened is the product contradicting itself — the grid offers a link that
# fails, which reads as a bug in the tool rather than a fact about the host.
#
# But the refusal that link replaces is load-bearing and must not weaken.
# LoadUnit synthesises a Unit object for ANY name, so without a gate
# `unit:whatever-i-typed.service` would answer 200 with a plausible-looking
# object. Both halves are pinned here, adjacent and in one section, because
# the next person to touch either needs to see the other.
# ---------------------------------------------------------------------------

def open_object(rows, properties, monkeypatch, typed=None, list_error=None,
                object_id="unit:message-broker.service", evidence=False):
    bus = FakeBus(properties, rows=rows, typed=typed, list_error=list_error)
    monkeypatch.setattr(units, "BUS", bus)
    adapter = units.Adapter()
    route = adapter.get_evidence if evidence else adapter.get_object
    return asyncio.run(route("units", object_id)), bus


REFERENCED = {"message-broker.service": {
    **synthesised("message-broker.service"),
    "WantedBy": ["ingest-worker.service"], "Before": ["ingest-worker.service"]}}


def test_a_not_found_unit_the_host_lists_can_be_opened(monkeypatch):
    """The row exists in the collection, so the object behind it must too."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found")]
    obj, _bus = open_object(rows, REFERENCED, monkeypatch)
    assert obj["object"]["native_id"] == "message-broker.service"
    assert obj["facts"]["LoadState"] == "not-found"


def test_a_name_the_host_never_listed_is_still_refused(monkeypatch):
    """The other half, and the reason the gate is the LISTING rather than the
    load state: LoadUnit hands back an identical not-found object for a name
    nobody ever wrote, so a route that trusted it would serve an invented unit
    as a real one."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found")]
    with pytest.raises(units.env.UnknownObject):
        open_object(rows, {}, monkeypatch,
                    object_id="unit:i-just-made-this-up.service")
    # And the same refusal on the evidence route, which shares the contract.
    with pytest.raises(units.env.UnknownObject):
        open_object(rows, {}, monkeypatch, evidence=True,
                    object_id="unit:i-just-made-this-up.service")


def test_an_unreadable_listing_fails_closed(monkeypatch):
    """Unprovable existence must refuse, or a degraded manager becomes the
    route by which an invented name gets served."""
    with pytest.raises(units.env.UnknownObject):
        open_object([], REFERENCED, monkeypatch, list_error=RuntimeError("denied"))


def test_the_opened_object_answers_who_references_it(monkeypatch):
    """The question a reader arrives with. Without this the row is honest and
    still useless: it says a name is missing and nothing about who wanted it."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found")]
    obj, _bus = open_object(rows, REFERENCED, monkeypatch)
    assert obj["facts"]["ReferencedBy"] == ["ingest-worker.service (After=)",
                                            "ingest-worker.service (Wants=)"]
    assert obj["facts"]["LoadError"] == "Unit message-broker.service not found."


def test_the_opened_object_and_its_row_answer_alike(monkeypatch):
    """One formatter, so the grid and the page cannot disagree about who asked
    for a name that is not here."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found")]
    obj, _bus = open_object(rows, REFERENCED, monkeypatch)
    _refs, absent, _bus2 = walk(rows, REFERENCED, monkeypatch=monkeypatch)
    assert obj["facts"]["ReferencedBy"] == absent["message-broker.service"]["ReferencedBy"]


def test_the_opened_object_invents_no_runtime(monkeypatch):
    """A unit with no file has no file state, no fragment, no start moment, no
    cgroup and no service runtime. systemd answers for all of them anyway, with
    "" and 0 — and a not-found .service reports Result "success". Absent facts,
    never empties: an omitted fact reads as does-not-apply where an empty string
    reads as a measured emptiness, and "success" reads as a healthy unit."""
    rows = [listed("message-broker.service", "not-found")]
    obj, bus = open_object(rows, REFERENCED, monkeypatch)
    for invented in ("UnitFileState", "FragmentPath", "ActiveEnterTimestamp",
                     "MainPID", "NRestarts", "Result", "TasksCurrent",
                     "ExecMainStartTimestamp", "Slice"):
        assert invented not in obj["facts"], invented
    assert not any(value in ("", 0) for value in obj["facts"].values())
    # The typed interface is never even asked for: it would answer, and its
    # answer is several hundred properties of nothing.
    assert bus.interfaces == [UNIT_IFACE]


def test_a_loaded_unit_still_gets_its_runtime(monkeypatch):
    """The contrast that makes the omission above mean something — the same
    route, on a unit that did load, still fetches the type-specific interface
    and reports it."""
    rows = [listed("ingest-worker.service")]
    loaded = {"ingest-worker.service": {
        "Id": "ingest-worker.service", "LoadState": "loaded",
        "ActiveState": "active", "SubState": "running",
        "Description": "an ingest worker", "UnitFileState": "enabled",
        "FragmentPath": "/etc/systemd/system/ingest-worker.service",
        "ActiveEnterTimestamp": 1_755_000_000_000_000, "LoadError": ["", ""]}}
    obj, bus = open_object(rows, loaded, monkeypatch, typed={
        "ingest-worker.service": {"MainPID": 4242, "NRestarts": 0,
                                  "Result": "success", "TasksCurrent": 9,
                                  "ExecMainStartTimestamp": 1_755_000_000_000_000}},
        object_id="unit:ingest-worker.service")
    assert obj["facts"]["MainPID"] == 4242
    assert obj["facts"]["FragmentPath"].endswith("ingest-worker.service")
    assert "LoadError" not in obj["facts"], (
        "a unit that loaded cleanly must not carry an empty reason")
    assert UNIT_IFACE in bus.interfaces and len(bus.interfaces) == 2


def test_evidence_is_servable_and_shows_no_fabricated_interface(monkeypatch):
    """An object this adapter serves must be able to show its own document, or
    provenance has a hole exactly where a reader goes to check a surprising
    claim. There IS a document — the Unit interface answers for these names,
    which is how the reference facts are acquired at all — and it carries only
    the interface that was really about this unit."""
    rows = [listed("message-broker.service", "not-found")]
    doc, bus = open_object(rows, REFERENCED, monkeypatch, evidence=True)
    assert doc["object_id"] == "unit:message-broker.service"
    assert set(doc["payload"]) == {UNIT_IFACE}
    assert doc["payload"][UNIT_IFACE]["WantedBy"] == ["ingest-worker.service"]
    assert bus.interfaces == [UNIT_IFACE]


def test_opening_one_of_these_costs_one_listing_not_two(monkeypatch):
    """The gate and the absent-dependency facts want the same call, so it is
    fetched once and handed on. Two would double the cost of every unit page
    on the host to answer one question twice."""
    rows = [listed("ingest-worker.service"),
            listed("message-broker.service", "not-found")]
    _obj, bus = open_object(rows, REFERENCED, monkeypatch)
    assert bus.listings == 1
