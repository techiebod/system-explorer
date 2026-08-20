"""The intent declaration as the hub holds it: identity, hash, refusal.

The document under test is DESIGN 22's own worked example, extracted from
the design document rather than copied — a copy would keep passing after
the document changed, which is the fourth-copy defect this suite exists
to refuse.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

from system_explorer.hub.intent import (
    Intent,
    IntentInvalid,
    canonical,
    federation_refusal,
    intent_hash,
)

DESIGN = Path(__file__).resolve().parent.parent / "docs" / "DESIGN.md"
FENCE = re.compile(r"^```json schema=se\.intent/1\n(.*?)^```$", re.M | re.S)


@pytest.fixture(scope="module")
def document() -> dict:
    matches = FENCE.findall(DESIGN.read_text())
    assert matches, "DESIGN 22's worked intent example has gone missing"
    return json.loads(matches[0])


def test_the_documents_own_example_loads(document) -> None:
    intent = Intent.load(document)
    assert intent.estate == "home"
    assert intent.revision == 41
    assert intent.declared_hosts() == ("edge-1", "storage-1")
    assert intent.hash.startswith("sha256:")


def test_protection_is_a_plugin_stanza_carried_verbatim(document) -> None:
    """Under the 2026-08-20 ruling the estate owns protection, so the hub
    carries its intent and does not parse it."""
    intent = Intent.load(document)
    stanza = intent.plugin("protection")
    assert stanza is not None
    assert stanza["targets"][0]["target"] == "tank/photos"
    assert intent.plugin("nothing-declared-this") is None
    # And it is reachable ONLY through the plugin accessor: a first-party
    # attribute would be the estate's concern back in this repository.
    assert not hasattr(intent, "protection")


def test_estate_identity_is_declared_never_correlated(document) -> None:
    intent = Intent.load(document)
    assert intent.denotes("storage-1", "b2:bucket/vault") == "repository:offsite-vault"
    assert intent.denotes("nas-1", "/srv/restic/vault") == "repository:offsite-vault"
    # A name nobody declared stays host-scoped. Silence is not an
    # invitation to correlate.
    assert intent.denotes("storage-1", "some/other/path") is None


def test_a_denotation_is_instance_scoped(document) -> None:
    """Acceptance item 1, arriving through the intent document. Absent
    means host-native, never any-instance — a denotation matching every
    instance would merge them."""
    doc = copy.deepcopy(document)
    doc["objects"] = [
        {"id": "indexer:shared", "kind": "indexer",
         "denoted_by": [{"host": "storage-1", "name": "indexer:3", "instance": "radarr"}]},
    ]
    intent = Intent.load(doc)
    assert intent.denotes("storage-1", "indexer:3", instance="radarr") == "indexer:shared"
    assert intent.denotes("storage-1", "indexer:3") is None, (
        "the host-native object is a different object from the instance's"
    )


def test_one_name_denoting_two_objects_is_refused(document) -> None:
    doc = copy.deepcopy(document)
    doc["objects"] = [
        {"id": "repository:a", "kind": "restic-repository",
         "denoted_by": [{"host": "storage-1", "name": "same/path"}]},
        {"id": "repository:b", "kind": "restic-repository",
         "denoted_by": [{"host": "storage-1", "name": "same/path"}]},
    ]
    with pytest.raises(IntentInvalid) as caught:
        Intent.load(doc)
    assert "does not choose between them" in str(caught.value)


def test_the_hash_ignores_formatting_and_notices_content(document) -> None:
    """Two sites generate this document from their own configuration, so
    byte-identity is unavailable and the hash must survive re-rendering
    while still refusing a different estate."""
    reordered = json.loads(json.dumps(document, sort_keys=False))
    reordered = dict(reversed(list(reordered.items())))
    assert intent_hash(reordered) == intent_hash(document)

    moved = copy.deepcopy(document)
    moved["revision"] = document["revision"] + 1
    assert intent_hash(moved) != intent_hash(document)

    forgotten = copy.deepcopy(document)
    forgotten["membership"]["hosts"].pop("edge-1")
    assert intent_hash(forgotten) != intent_hash(document), (
        "a hub that forgot a host must not agree with one that did not"
    )


def test_array_order_is_significant_and_that_is_stated(document) -> None:
    """Recorded as a test because it is a constraint on whoever generates
    intent, and an unstated one would cost a day of false federation
    failures."""
    swapped = copy.deepcopy(document)
    swapped["reachability"] = list(reversed(swapped["reachability"] + [
        {"role": "storage", "permitted_ports": [22]},
    ]))
    reference = copy.deepcopy(document)
    reference["reachability"] = reference["reachability"] + [
        {"role": "storage", "permitted_ports": [22]},
    ]
    assert intent_hash(swapped) != intent_hash(reference)


def test_canonical_is_deterministic_and_utf8(document) -> None:
    assert canonical(document) == canonical(json.loads(json.dumps(document)))
    assert isinstance(canonical(document), bytes)


def test_federation_refuses_legibly(document) -> None:
    intent = Intent.load(document)
    assert federation_refusal(intent, intent.hash) is None
    message = federation_refusal(intent, "sha256:def456")
    assert message is not None
    # Both hashes named: "connection error" is what an operator cannot
    # act on, and this is what they can.
    assert intent.hash in message and "sha256:def456" in message
    assert "unavailable until they agree" in message


@pytest.mark.parametrize("missing", ["schema", "estate", "revision", "reviewed", "membership"])
def test_a_half_read_intent_is_refused(document, missing) -> None:
    doc = copy.deepcopy(document)
    doc.pop(missing)
    with pytest.raises(IntentInvalid):
        Intent.load(doc)


def test_membership_without_hosts_is_refused(document) -> None:
    doc = copy.deepcopy(document)
    doc["membership"] = {"discovery": []}
    with pytest.raises(IntentInvalid):
        Intent.load(doc)
