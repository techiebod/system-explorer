"""Every collection the shipping product serves is ported, or says why not.

**This is the guard that was missing, and its absence carried a gate.**
Gate 3 declared twenty of twenty collectors ported and nineteen of
nineteen clean. Both were true and neither was the question: a collector
is "ported" at the granularity of a BINARY, and the parity comparator
drives a hand-maintained list of collections which had been filled in
with exactly what the port implements. So both sides were asked only for
what the port already had, agreed, and reported clean — while eighteen
collections the reference serves were never asked for at all.

That is this estate's most repeated defect, in the guard built to catch
it: a check that enumerates what its author thought of and reports
success about the rest. The comparator's own comment even names the
shape — "a collection served but never compared is the hole `nft-rules`
sat in" — and fixes the one instance rather than inverting the rule.

So this test is **deny-by-default over the reference**. Every collection
an adapter serves must be ported, or be listed below with a reason. A
collection that is neither fails, and nothing about adding a collector
can make it pass quietly.

Found on 2026-08-20 by a person opening the UI and saying it looked
empty, which no assertion in this suite had managed to say.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
ADAPTERS = REPO / "src" / "system_explorer" / "agent" / "adapters"

#: Collections the rewrite deliberately does not carry, each with the
#: ruling that settled it. A reason here is a decision somebody made, not
#: a note that the work is outstanding — for that, see NOT_YET_PORTED.
DELIBERATELY_DROPPED: dict[str, str] = {
    "network/lookups": "lookup is a VERB in the new contract, not a collection "
                       "(DESIGN 18): the collector serves `lookup` and there is "
                       "nothing to enumerate.",
    "storage/lookups": "same ruling as network/lookups.",
    "system/self": "the collator reports its own cost per collection (DESIGN 19), "
                   "so a self collection would be a second account of it.",
}

#: Collections that ARE owed and are not built. Every entry is a hole in
#: the product a person would notice, and the list is what stops gate 6
#: being reachable while they are open.
NOT_YET_PORTED: dict[str, str] = {
    "network/links": "interfaces on every Linux host; the largest single hole.",
    "network/routes": "routing table; present on every host.",
    "network/listening": "listening sockets — half of 'what is exposed'.",
    "network/resolver": "resolver configuration.",
    "network/nft-tables": "the table-grained view above nft-chains.",
    "network/port-exposure": "the joined answer nft + listening produce together.",
    "network/tailscale": "a discovery source membership depends on (DESIGN 23).",
    "storage/block-devices": "block devices on every host.",
    "storage/mounts": "mount points on every host.",
    "storage/arrays": "md arrays.",
    "storage/datasets": "ZFS datasets — the level protection joins against.",
    "system/time": "clock and sync state, which §09's skew work needs.",
    "system/boot": "boot time and kernel command line.",
    "system/overview": "the per-host summary the old UI opened on.",
    "plex/requests": "seerr requests.",
}


#: Ported collections the live comparator does not drive, each with why.
#: A ported collection nobody compares is a second way to be wrong that
#: nothing would catch, so the list is short and every entry is owed work
#: rather than a decision.
NOT_YET_COMPARED: dict[str, str] = {
    "system/identity": "gate 3 recorded that system 'has no second implementation "
                       "to disagree with'. That is not true — adapters/system.py "
                       "serves identity — and comparing it needs a replay seam "
                       "defined for that adapter, which does not exist yet. The "
                       "claim is corrected in PLAN; the work is owed here.",
}


def old_collections() -> dict[str, set[str]]:
    """What each shipping adapter serves, read from its own collections()."""
    out: dict[str, set[str]] = {}
    for path in sorted(ADAPTERS.glob("*.py")):
        if path.stem == "__init__":
            continue
        text = path.read_text()
        match = re.search(
            r"def collections\(self\)[^\n]*\n(?:\s*#[^\n]*\n)*\s*return \[(.*?)\]",
            text, re.S)
        if match:
            out[path.stem] = set(re.findall(r'"([a-z][a-z0-9-]*)"', match.group(1)))
    return out


def ported_collections() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for path in sorted((REPO / "go" / "cmd").glob("se-collect-*/declaration.json")):
        document = json.loads(path.read_text())
        out[document["collector"]] = {c["name"] for c in document["collections"]}
    return out


OLD = old_collections()
NEW = ported_collections()


def test_the_scan_finds_the_adapters_we_know_about() -> None:
    """Anti-vacuity. A regex that stopped matching would make the whole
    file pass by measuring nothing — which is the failure this file is
    about, one level up."""
    assert len(OLD) >= 18, f"only found collections() in {sorted(OLD)}"
    for expected in ("network", "storage", "system", "units"):
        assert OLD.get(expected), f"{expected} adapter's collections() went unread"
    assert len(OLD["network"]) >= 10 and len(OLD["storage"]) >= 6


def test_every_served_collection_is_ported_or_accounted_for() -> None:
    unexplained: list[str] = []
    for adapter, collections in sorted(OLD.items()):
        for collection in sorted(collections - NEW.get(adapter, set())):
            key = f"{adapter}/{collection}"
            if key not in DELIBERATELY_DROPPED and key not in NOT_YET_PORTED:
                unexplained.append(key)
    assert not unexplained, (
        "these collections are served by the shipping product, are not ported, "
        "and nothing says why:\n  " + "\n  ".join(unexplained) +
        "\n\nAdd each to DELIBERATELY_DROPPED with its ruling, or to "
        "NOT_YET_PORTED as owed work. Silence is what let eighteen of them "
        "sit behind a green gate."
    )


def test_the_owed_list_is_honest_in_both_directions() -> None:
    """A collection listed as owed that HAS been ported is a stale list,
    and a stale list is how a hole gets forgotten twice."""
    stale = [key for key in list(NOT_YET_PORTED) + list(DELIBERATELY_DROPPED)
             if key.split("/")[1] in NEW.get(key.split("/")[0], set())]
    assert not stale, f"these are ported and still listed as missing: {stale}"


def test_the_comparator_drives_every_ported_collection() -> None:
    """The other half of the hole. Comparing a subset of what the port
    serves is how `nft-rules` hid; comparing exactly what the port serves
    is how the eighteen hid. This asserts the first, and the test above
    asserts the second."""
    source = (REPO / "harness" / "bin" / "se-compare").read_text()
    match = re.search(r"SERVES\s*=\s*\{(.*?)\n\}", source, re.S)
    assert match, "se-compare no longer has a SERVES table"
    served: dict[str, set[str]] = {}
    for line in match.group(1).splitlines():
        entry = re.match(r'\s*"([a-z-]+)":\s*\[(.*?)\]', line)
        if entry:
            served[entry.group(1)] = set(re.findall(r'"([a-z0-9-]+)"', entry.group(2)))
    missing = sorted(
        f"{collector}/{collection}"
        for collector, collections in NEW.items()
        for collection in collections - served.get(collector, set())
    )
    unexplained = [key for key in missing if key not in NOT_YET_COMPARED]
    assert not unexplained, (
        "the comparator never asks for these ported collections, and nothing "
        f"says why: {unexplained}"
    )


def test_the_uncompared_list_is_not_stale() -> None:
    source = (REPO / "harness" / "bin" / "se-compare").read_text()
    match = re.search(r"SERVES\s*=\s*\{(.*?)\n\}", source, re.S)
    served: dict[str, set[str]] = {}
    for line in match.group(1).splitlines():
        entry = re.match(r'\s*"([a-z-]+)":\s*\[(.*?)\]', line)
        if entry:
            served[entry.group(1)] = set(re.findall(r'"([a-z0-9-]+)"', entry.group(2)))
    now_compared = [
        key for key in NOT_YET_COMPARED
        if key.split("/")[1] in served.get(key.split("/")[0], set())
    ]
    assert not now_compared, (
        f"these are compared now and still listed as not: {now_compared}"
    )


@pytest.mark.parametrize("adapter", sorted(OLD))
def test_no_adapter_lost_more_than_it_kept_without_saying_so(adapter: str) -> None:
    """A per-adapter view, so a single number cannot hide where the holes
    are. network kept 2 of 10 and storage 1 of 6, and both are recorded."""
    old, new = OLD[adapter], NEW.get(adapter, set())
    if len(new) >= len(old):
        return
    for collection in old - new:
        key = f"{adapter}/{collection}"
        assert key in DELIBERATELY_DROPPED or key in NOT_YET_PORTED, key
