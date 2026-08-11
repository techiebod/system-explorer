"""SPEC section 11, rules 2, 3 and parts schemas cannot express."""

from common import resolve_fact_path


def test_opinion_evidence_resolves_into_facts(example):
    """Rule 2: every opinion cites fact paths that actually exist.

    This is the enforcement of 'evidence before opinion' — an opinion whose
    citations do not resolve is interpretation without evidence.
    """
    path, doc = example
    if doc["schema"] != "se.observation/1":
        return
    for opinion in doc.get("opinions", []):
        for evidence_path in opinion["evidence"]:
            resolve_fact_path(doc["facts"], evidence_path)


def test_errors_listed_when_status_not_ok(example):
    """status partial/error must say what failed, non-emptily.

    Not every envelope has one: the fact dictionary is static prose with no
    acquisition behind it, so it can neither succeed partially nor fail.
    """
    path, doc = example
    if "status" not in doc:
        return
    if doc["status"] != "ok":
        assert doc.get("errors"), f"{path.name}: status={doc['status']} but errors is empty"
    else:
        assert not doc.get("errors"), f"{path.name}: status=ok yet errors are listed"


def test_collection_ids_unique_and_within_limit(example):
    """A page never exceeds its applied limit and never repeats an object."""
    path, doc = example
    if doc["schema"] != "se.collection/1":
        return
    ids = [item["id"] for item in doc["items"]]
    assert len(ids) == len(set(ids)), f"{path.name}: duplicate object ids in page"
    assert len(ids) <= doc["applied_limit"], (
        f"{path.name}: {len(ids)} items exceeds applied_limit={doc['applied_limit']}"
    )


def test_collection_pagination_is_explicit(example):
    """SPEC section 6: the client never infers truncation.

    A page that hits its applied limit must say whether more exists —
    next_cursor non-null, or total present and accounted for.
    """
    path, doc = example
    if doc["schema"] != "se.collection/1":
        return
    if len(doc["items"]) == doc["applied_limit"]:
        assert doc["next_cursor"] is not None or "total" in doc, (
            f"{path.name}: full page with no next_cursor and no total — truncation ambiguous"
        )


def test_relationship_targets_are_not_self(example):
    path, doc = example
    if doc["schema"] != "se.observation/1":
        return
    for rel in doc.get("relationships", []):
        assert rel["target"]["id"] != doc["object"]["id"] or rel["target"].get("machine_id"), (
            f"{path.name}: relationship targets the object itself"
        )
