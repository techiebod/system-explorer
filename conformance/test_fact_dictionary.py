"""The fact dictionary, and the drift that would make it worse than nothing.

Facts carry native property names (SPEC section 5) and native names are not
self-explanatory: a reader looking at LinkSpeed "8.0 GT/s PCIe" beside
LinkWidth 2 reasonably asked whether lanes and speed were the same thing, and
nothing on the screen could tell them. /v1/facts is the answer — one sentence
per fact, owned by the adapter that emits it.

Prose beside code rots the same way reference commands did (SPEC rule 5): the
fact moves and the sentence does not, and a confidently wrong description is
worse than an absent one. Two guards, in the two directions drift runs:

  * every documented name still appears in its adapter's source — a fact that
    was renamed or deleted must not leave a sentence behind describing it;
  * every fact the rulebook CITES as evidence is documented — those are, by
    construction, exactly the facts a reader is being asked to understand, so
    they are the ones that may not be left unexplained.

Coverage beyond that is deliberately partial: an undocumented fact is absent
from the document, which says no sentence has been written yet, and that is a
statement rather than a failure.
"""

import ast

import pytest

from common import AGENT_DIR
from test_rules import CASES

from system_explorer.agent.adapters import build_adapters

ADAPTERS = build_adapters()


def glossaries():
    """(subsystem, collection, {fact: sentence}) for everything documented."""
    out = []
    for name, adapter in sorted(ADAPTERS.items()):
        glossary = getattr(adapter, "fact_glossary", None)
        if glossary is None:
            continue
        for collection in adapter.collections():
            entries = glossary(collection)
            if entries:
                out.append(pytest.param(name, collection, entries,
                                        id=f"{name}/{collection}"))
    return out


GLOSSARIES = glossaries()


def test_some_subsystem_documents_its_facts():
    """The discovery above must actually be finding a dictionary — otherwise
    every guard below passes vacuously."""
    assert GLOSSARIES, "no adapter exposes fact_glossary(); /v1/facts is empty"


def names_the_adapter_uses(subsystem: str) -> set[str]:
    """Every string literal in an adapter's source EXCEPT the ones inside its
    own glossary constants.

    The exclusion is the whole point. Scanning the raw text would match the
    glossary's own keys — the check would pass by reading itself back and prove
    nothing, which is how a vacuous test survives review.
    """
    tree = ast.parse((AGENT_DIR / "adapters" / f"{subsystem}.py").read_text())
    glossary_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id.endswith("GLOSSARY")
                   for t in targets):
                glossary_nodes.update(id(child) for child in ast.walk(node))
    return {node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and id(node) not in glossary_nodes}


@pytest.mark.parametrize("subsystem,collection,entries", GLOSSARIES)
def test_documented_facts_still_exist_in_the_adapter(subsystem, collection, entries):
    """A sentence about a fact nobody emits is drift: the fact was renamed or
    dropped and its description stayed behind, now describing nothing."""
    orphans = sorted(set(entries) - names_the_adapter_uses(subsystem))
    assert not orphans, (
        f"{subsystem}/{collection} documents facts that appear nowhere in "
        f"adapters/{subsystem}.py: {orphans}. Either the fact was renamed and "
        "the sentence was not, or the entry describes something that no longer "
        "exists — a confidently wrong description is worse than none."
    )


def test_the_orphan_check_is_not_reading_its_own_glossary_back():
    """The guard above is only worth having if the exclusion works. A name that
    exists ONLY as a glossary key must be invisible to the scan."""
    hardware_names = names_the_adapter_uses("hardware")
    assert "LinkWidth" in hardware_names, "scan lost a name the adapter really emits"
    assert "SmartOverallPassed" in hardware_names
    assert "ThisFactDoesNotExist" not in hardware_names


@pytest.mark.parametrize("subsystem,collection,entries", GLOSSARIES)
def test_descriptions_say_the_concept_not_the_label(subsystem, collection, entries):
    """Descriptions, never labels — presentation belongs to clients (SPEC
    section 5). A sentence that only restates the fact name teaches nothing;
    the name is already on screen beside it."""
    for fact, sentence in sorted(entries.items()):
        assert len(sentence) > len(fact) + 20, (
            f"{subsystem}/{collection}.{fact}: {sentence!r} is a label, not an "
            "explanation")
        assert sentence[0].isupper() and sentence.rstrip().endswith("."), (
            f"{subsystem}/{collection}.{fact}: {sentence!r} is not a sentence")


def cited_facts_by_subsystem() -> dict[str, set[str]]:
    """Every fact name the rulebook's characteristic cases cite as evidence,
    grouped by the rules module that cited it."""
    cited: dict[str, set[str]] = {}
    for _name, evaluator, facts, _expected in CASES:
        subsystem = evaluator.__module__.rsplit(".", 1)[-1]
        for opinion in evaluator(facts):
            for path in opinion["evidence"]:
                cited.setdefault(subsystem, set()).add(path.split(".")[0])
    return cited


# Facts an opinion cites that carry no sentence yet, listed deliberately and in
# review rather than by loosening the check — the same shape as
# SUBPROCESS_ALLOWLIST. Shrinking this list is the work; growing it is a
# decision someone made on purpose.
UNDOCUMENTED_EVIDENCE: dict[str, set[str]] = {
    "docker": {"ExitCode", "Health", "OOMKilled", "RestartCount", "State",
               "Status"},
    "logs": {"Container", "Priority", "RepeatCount", "RepeatWindow"},
    # links is documented; what remains here is tailscale and resolver.
    "network": {"BackendState", "DNSServersInUse", "GlobalDNSServers", "Health",
                "KeyExpiry", "KeyExpiryDays", "Online", "PerLinkDNS",
                "TailscaleSnapshotAgeSeconds", "TailscaleSnapshotAt"},
    "nix": {"Current", "Deployment", "Profile", "ReceiptsExpected"},
    "storage": {"CapacityPercent", "Degraded", "Members", "ScanAgeDays",
                "ScanEndTime", "ScanFunction", "ScanState", "State",
                "SyncAction", "SyncPercent", "UsePercent", "Vdevs"},
    "system": {"ArcSizeBytes", "BootEntries", "BootNext", "BootOrder",
               "BootedSystem", "CurrentSystem", "MemAvailableBytes",
               "MemTotalBytes", "NFailedUnits", "NTP", "NTPSynchronized",
               "PsiCpuSomeAvg60", "PsiIoFullAvg60", "PsiMemoryFullAvg60",
               "SecureBoot", "SwapTotalBytes", "SwapUsedBytes",
               "SystemProfile", "SystemState"},
    "units": {"ActiveState", "NRestarts", "PsiIoFullAvg60",
              "PsiMemoryFullAvg60", "Result", "SubState"},
    "vms": {"Autostart", "State"},
}


@pytest.mark.parametrize("subsystem,cited", sorted(cited_facts_by_subsystem().items()))
def test_facts_an_opinion_cites_are_documented(subsystem, cited):
    """The facts a rule cites are the facts a reader is asked to reason about —
    the exact place an unexplained native name costs someone their afternoon.
    A new one lands documented or listed above, never silently neither."""
    adapter = ADAPTERS.get(subsystem)
    documented: set[str] = set()
    glossary = getattr(adapter, "fact_glossary", None)
    if glossary is not None:
        for collection in adapter.collections():
            documented |= set(glossary(collection))
    missing = sorted(cited - documented - UNDOCUMENTED_EVIDENCE.get(subsystem, set()))
    assert not missing, (
        f"{subsystem} opinions cite facts with no sentence in the dictionary: "
        f"{missing}. Add them to that adapter's fact_glossary, or to "
        "UNDOCUMENTED_EVIDENCE if the gap is deliberate."
    )


def test_undocumented_list_does_not_outlive_the_gap():
    """The exemption list is a debt register, not a dumping ground: an entry
    that has since been documented must come off it, or the list stops meaning
    what it says."""
    stale: dict[str, list[str]] = {}
    for subsystem, exempt in UNDOCUMENTED_EVIDENCE.items():
        adapter = ADAPTERS.get(subsystem)
        glossary = getattr(adapter, "fact_glossary", None) if adapter else None
        if glossary is None:
            continue
        documented: set[str] = set()
        for collection in adapter.collections():
            documented |= set(glossary(collection))
        if overlap := sorted(exempt & documented):
            stale[subsystem] = overlap
    assert not stale, f"documented facts still listed as undocumented: {stale}"
