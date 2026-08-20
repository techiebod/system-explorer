"""The contract package must refuse, not merely accept.

Every constraint was once deleted from all five schemas and this suite's
sibling passed unchanged: nothing anywhere asserted that a schema REJECTS
anything, so the contract's teeth existed only as good intentions — the
subset-guard shape applied to validation itself. This file is the other
direction of the pact: for every rule the schemas carry, the smallest
document that violates it, asserted rejected.

Two disciplines keep these tests honest:

- Every rejection document is a mutation of a base document this suite first
  proves ACCEPTED, so a failure is attributable to the mutation and never to
  an accidentally-invalid base — a rejection test whose base never validated
  would reject everything and discriminate nothing.
- A gutted-schema tripwire strips a schema to its identity keys in memory and
  asserts a rejection document now passes. That is the proof this suite would
  go red if the constraints were deleted again, which is the exact event that
  motivated writing it.

Validation runs through the same registry construction test_corpus_replay.py's
_validator() uses: every contract/*.json loaded by $id, so cross-file $refs
resolve exactly as they will for any consumer.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

REPO = Path(__file__).resolve().parent.parent
CONTRACT = REPO / "contract"

STREAM = "se.stream.1.json"
DECLARATION = "se.declaration.1.json"
INTENT = "se.intent.1.json"
ANSWER = "se.answer.1.json"
CHECKPOINT = "se.checkpoint.1.json"


def _registry(override: dict | None = None) -> Registry:
    registry = Registry()
    for path in sorted(CONTRACT.glob("*.json")):
        schema = json.loads(path.read_text())
        if override and schema["$id"] == override["$id"]:
            schema = override
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def _validator(schema_file: str) -> Draft202012Validator:
    schema = json.loads((CONTRACT / schema_file).read_text())
    return Draft202012Validator(schema, registry=_registry())


def _errors(schema_file: str, document: dict) -> list:
    return list(_validator(schema_file).iter_errors(document))


# ── base documents, each proven accepted below ───────────────────────────
#
# Minimal on purpose: a rejection case mutates exactly one thing, so the
# base carries nothing a mutation could hide behind.

BEGIN = {
    "record": "begin",
    "request": "rq-1",
    "batch": "b-1",
    "declaration": "sha256:aa",
    # full 8-4-4-4-12: the base once carried "4f2a", which the shape rule now
    # rejects — that truncation lives on below as the boot-id-not-uuid case
    "boot_id": "4f2a91cc-8f60-4ae5-b60c-7b3ba27ea55e",
    "timens": 0,
    "instance": None,
    "generations": {"pools": 1},
}

OBJECT = {
    "record": "object",
    "collection": "pools",
    "name": "tank",
    "names": {"stable": {"guid": "1155", "devices": ["by-id/wwn-0x5000"]}},
    "facts": {"Health": "ONLINE"},
    "at": 214697.204,
}

RELATION = {
    "record": "relation_assertion",
    "collection": "pools",
    "name": "tank",
    "type": "backed-by",
    "vantage": "pools",
    "target": {"kind": "block-device", "name": "by-id/wwn-0x5000"},
}

UNOBSERVABLE = {
    "record": "unobservable",
    "collection": "pools",
    "name": "tank",
    "fact": "SlowIos",
    "reason": "unsupported",
}

DECLINE = {"record": "decline", "collection": "arrays", "reason": "absent"}

COMMIT = {
    "record": "commit",
    "collection": "pools",
    "generation": 1,
    "objects": 1,
    "assertions": 0,
    "unobservable": 0,
}

END = {"record": "end", "request": "rq-1", "batch": "b-1"}

DECLARATION_DOC = {
    "schema": "se.declaration/1",
    "collector": "storage",
    "version": "1.0.0",
    "collections": [
        {
            "name": "pools",
            "question": "are my pools healthy?",
            "prefix": "pool",
            "freshness": "60s",
            "perishability": "sampled",
            "answer": ["Health"],
            "facts": {
                "Health": {
                    "type": "string",
                    "temperament": "state",
                    "kind": "observed",
                    "discloses": "nothing",
                    "sentence": "The pool's verdict.",
                }
            },
            "redaction_exemption": "counters only; no credential surface.",
        }
    ],
}

INTENT_DOC = {
    "schema": "se.intent/1",
    "estate": "home",
    "revision": 1,
    "reviewed": "2026-08-14",
    "membership": {
        "discovery": [{"collection": "net/peers", "independence": "control-plane"}],
        "hosts": {"storage-1": {"roles": ["storage"]}},
    },
    # Protection's intent is a plugin's since the 2026-08-20 ruling, so it
    # rides in `plugins` — which is also what keeps this base document a
    # worked example of the extension member rather than of a first-party
    # concern the contract no longer names.
    "plugins": {
        "protection": {
            "targets": [
                {
                    "target": "tank/photos",
                    "owner": "storage-1",
                    "class": "irreplaceable",
                    "destinations": ["repository:offsite"],
                }
            ]
        }
    },
}

ANSWER_DOC = {
    "id": "question:data-protected",
    "scope": "storage-1",
    "question": "is my data protected?",
    "answer": "Yes; every declared target has a current receipt.",
    "verdict": "healthy",
    "epistemic": "complete",
    "freshness": "current",
    "basis": [
        {
            "claim": "tank/photos is declared irreplaceable",
            "kind": "declared",
            "origin": "intent@r1",
            "value_as_read": "irreplaceable",
            "ref": "/hub/intent/r1#protection/tank-photos",
        }
    ],
    "reach": {"consulted": ["storage-1/protection"]},
}

OBSERVED_BASIS = {
    "claim": "the receipt is 2 days old",
    "kind": "observed",
    "origin": "storage-1/protection/receipts",
    "value_as_read": "2026-08-14T02:14:00Z",
    "batch": "b-1",
    "generation": 1,
    "from": "/receipts/0/time",
    "evidence_digest": "sha256:aa",
    "ref": "/v1/protection/receipts/r1",
}

DERIVED_BASIS = {
    "claim": "the copy is unconfirmed in the window",
    "kind": "derived",
    "origin": "hub",
    "rule": "protection.unconfirmed-copy@3",
    "consumed": ["/hub/intent/r1#protection/tank-photos"],
}


def _stream(record: dict, **changes) -> dict:
    out = copy.deepcopy(record)
    out.update(copy.deepcopy(changes))
    return out


def _without(record: dict, *members: str) -> dict:
    out = copy.deepcopy(record)
    for member in members:
        del out[member]
    return out


def _declaration(**collection_changes) -> dict:
    out = copy.deepcopy(DECLARATION_DOC)
    out["collections"][0].update(copy.deepcopy(collection_changes))
    return out


def _fact(**changes) -> dict:
    out = _declaration()
    out["collections"][0]["facts"]["Health"].update(copy.deepcopy(changes))
    return out


def _answer(**changes) -> dict:
    out = copy.deepcopy(ANSWER_DOC)
    out.update(copy.deepcopy(changes))
    return out


def _answer_with_basis(element: dict) -> dict:
    out = copy.deepcopy(ANSWER_DOC)
    out["basis"] = [copy.deepcopy(element)]
    return out


def _intent(**changes) -> dict:
    out = copy.deepcopy(INTENT_DOC)
    out.update(copy.deepcopy(changes))
    return out


# ── the round's own three wrong documents, named ─────────────────────────
#
# Each of these was emitted, accepted, and shipped before this suite
# existed; each is asserted rejected below and is the red/green proof that
# closure is doing work rather than decoration.

# A Go port marshalled the names split through its exported struct fields,
# so every stable name left the join and nothing went red.
GO_MARSHALLED_NAMES = _stream(
    OBJECT,
    names={"Stable": {"guid": "1155"}, "Ephemeral": {"kernel": ["/dev/sdc"]}},
)

# A JSON evidence commitment with no named canonicalisation is a coin toss
# over key ordering — re-digesting cannot say whether the document changed.
CANONLESS_JSON_EVIDENCE = _stream(
    OBJECT, evidence={"media_type": "application/json", "digest": "sha256:5e11"}
)

# A dark host beside a complete answer is ignorance laundered into
# knowledge — the monotonicity rule's cheapest checkable corner (DESIGN 25).
COMPLETE_BESIDE_DARK = _answer(
    epistemic="complete",
    reach={
        "consulted": ["storage-1/protection"],
        "dark": [{"host": "edge-1", "since": "2026-08-13T22:04:11Z"}],
    },
)


# ── the bases are accepted, or every rejection below is vacuous ──────────


# ── the checkpoint's bases (DESIGN 06) ───────────────────────────────────

MANIFEST = {
    "record": "manifest",
    "checkpoint": "cp-1",
    "host": "storage-1",
    "boot_id": "5e000000-0000-4000-8000-000000000001",
    "declarations": ["sha256:11e4"],
    "collections": [{"collection": "pools", "generation": 412, "freshness": "current"}],
}

COLLECTION_STATE = {
    "record": "collection_state",
    "checkpoint": "cp-1",
    "collection": "pools",
    "generation": 412,
    "objects": [],
}

TERMINAL = {
    "record": "terminal",
    "checkpoint": "cp-1",
    "collections": 1,
    "history_gap": None,
}


def _checkpoint(base: dict, **overrides) -> dict:
    document = copy.deepcopy(base)
    document.update(overrides)
    return document


def _manifest_entry(**overrides) -> dict:
    """A manifest carrying exactly one collection entry, mutated."""
    entry = {"collection": "pools", "generation": 412, "freshness": "current"}
    entry.update(overrides)
    return _checkpoint(MANIFEST, collections=[entry])


@pytest.mark.parametrize(
    "schema_file,document",
    [
        pytest.param(STREAM, BEGIN, id="begin"),
        pytest.param(STREAM, OBJECT, id="object"),
        pytest.param(STREAM, RELATION, id="relation_assertion"),
        pytest.param(STREAM, UNOBSERVABLE, id="unobservable"),
        pytest.param(STREAM, DECLINE, id="decline"),
        pytest.param(STREAM, COMMIT, id="commit"),
        pytest.param(STREAM, END, id="end"),
        pytest.param(DECLARATION, DECLARATION_DOC, id="declaration"),
        pytest.param(INTENT, INTENT_DOC, id="intent"),
        pytest.param(ANSWER, ANSWER_DOC, id="answer"),
        pytest.param(ANSWER, _answer_with_basis(OBSERVED_BASIS), id="observed-basis"),
        pytest.param(ANSWER, _answer_with_basis(DERIVED_BASIS), id="derived-basis"),
        # host reachability is expressible in reach at last: unswept beside
        # dark (appendix A), with the epistemic honestly degraded.
        pytest.param(
            ANSWER,
            _answer(
                epistemic="partial",
                reach={"consulted": ["storage-1/protection"], "unswept": ["edge-1"]},
            ),
            id="unswept-expressible",
        ),
        # null instance is the one legal null: host-native scope (DESIGN 19).
        pytest.param(STREAM, _stream(BEGIN, instance=None), id="instance-null"),
        pytest.param(CHECKPOINT, MANIFEST, id="manifest"),
        pytest.param(CHECKPOINT, COLLECTION_STATE, id="collection_state"),
        pytest.param(CHECKPOINT, TERMINAL, id="terminal"),
        # A stale collection carries the reason that made it stale, and a
        # never-applied one is generation 0 — both readings, both accepted.
        pytest.param(
            CHECKPOINT,
            _manifest_entry(generation=0, freshness="stale", stale_reason="unsupported"),
            id="never-applied-and-stale",
        ),
        # An empty object array is the reading a decline of `absent` leaves:
        # the collection applied and holds nothing.
        pytest.param(CHECKPOINT, COLLECTION_STATE, id="collection-state-empty"),
        # A gap that happened, stated with both ends.
        pytest.param(
            CHECKPOINT,
            _checkpoint(TERMINAL, history_gap={"from": 81422.5, "to": 98301.0}),
            id="history-gap-stated",
        ),
    ],
)
def test_the_base_documents_are_accepted(schema_file: str, document: dict) -> None:
    errors = _errors(schema_file, document)
    assert not errors, (
        "a base document this suite mutates does not itself validate — every "
        "rejection case would reject for the wrong reason:\n"
        + "\n".join(f"- {e.json_path}: {e.message}" for e in errors)
    )


# ── rejections: one minimal violating document per rule ──────────────────

REJECTIONS = [
    # -- the checkpoint (DESIGN 06). Every rule here exists because the
    #    failure it prevents is quiet: a hub that promotes a fragment
    #    recomputes an estate finding over a subset and RESOLVES it, during
    #    recovery, when nobody is looking. --
    #
    # Closure, on all three records, for the reason se.stream/1 states.
    pytest.param(CHECKPOINT, _checkpoint(MANIFEST, swept=True), id="cp-manifest-unknown-member"),
    pytest.param(CHECKPOINT, _checkpoint(COLLECTION_STATE, stale=True), id="cp-state-unknown-member"),
    pytest.param(CHECKPOINT, _checkpoint(TERMINAL, complete=True), id="cp-terminal-unknown-member"),
    # A manifest naming no collection: completeness over an empty promise is
    # vacuous, and a collator that declares nothing has nothing to checkpoint.
    pytest.param(CHECKPOINT, _checkpoint(MANIFEST, collections=[]), id="cp-manifest-empty"),
    # And one carrying no declaration hash: the hub cannot render or serve MCP
    # without the fact axes, so a checkpoint whose declarations are unstated is
    # state the receiver has no vocabulary for.
    pytest.param(CHECKPOINT, _checkpoint(MANIFEST, declarations=[]), id="cp-manifest-no-declarations"),
    # STALE WITHOUT ITS REASON. The pair that matters most in the manifest: a
    # stale collection whose reason is not carried tells a hub that something
    # is wrong and not what, which is the shape an operator cannot act on.
    pytest.param(CHECKPOINT, _manifest_entry(freshness="stale"), id="cp-stale-without-reason"),
    # And the inverse, which is the one a permissive schema would let through:
    # `current` with a decline reason attached is a collection claiming to be
    # both fine and refused, and only one of those can be a reading.
    pytest.param(
        CHECKPOINT,
        _manifest_entry(freshness="current", stale_reason="unavailable"),
        id="cp-current-with-reason",
    ),
    # A stale reason outside the closed decline vocabulary — invented reasons
    # are how a decline stops being checkable one tier down.
    pytest.param(
        CHECKPOINT,
        _manifest_entry(freshness="stale", stale_reason="dark"),
        id="cp-stale-reason-invented",
    ),
    # A negative generation: the authority issues from zero upward, so this is
    # a number no collator minted.
    pytest.param(CHECKPOINT, _manifest_entry(generation=-1), id="cp-generation-negative"),
    # Generation 0 on a STATE record. Zero is a legal manifest reading — never
    # applied — and an illegal one here: a collection that never applied has no
    # objects to send, so a state record under it is a claim about a
    # generation that does not exist.
    pytest.param(
        CHECKPOINT, _checkpoint(COLLECTION_STATE, generation=0), id="cp-state-generation-zero"
    ),
    # The objects array omitted rather than empty. An absent array and an empty
    # one would be the hub's only evidence of the difference between a
    # collection that holds nothing and one nobody sent.
    pytest.param(
        CHECKPOINT,
        {k: v for k, v in COLLECTION_STATE.items() if k != "objects"},
        id="cp-state-objects-omitted",
    ),
    # The terminal's count omitted. A receiver that inferred completeness from
    # the terminal's mere arrival could not tell a checkpoint that finished
    # from one whose middle was lost.
    pytest.param(
        CHECKPOINT,
        {k: v for k, v in TERMINAL.items() if k != "collections"},
        id="cp-terminal-without-count",
    ),
    # history_gap OMITTED rather than null. The whole point of the member: a
    # missing one and a stated absence of gap are the difference between a
    # timeline with a hole in it and a timeline that says where its hole is.
    pytest.param(
        CHECKPOINT,
        {k: v for k, v in TERMINAL.items() if k != "history_gap"},
        id="cp-terminal-gap-omitted",
    ),
    # A half-stated gap: one end is not an interval.
    pytest.param(
        CHECKPOINT,
        _checkpoint(TERMINAL, history_gap={"from": 81422.5}),
        id="cp-gap-half-stated",
    ),
    # The nil boot id and the dashless machine-id spelling, refused here for
    # the reasons se.stream/1 refuses them: a checkpoint's ages are meaningless
    # without the clock domain they belong to.
    pytest.param(
        CHECKPOINT,
        _checkpoint(MANIFEST, boot_id="00000000-0000-0000-0000-000000000000"),
        id="cp-boot-id-nil",
    ),
    pytest.param(
        CHECKPOINT,
        _checkpoint(MANIFEST, boot_id="5e0000000000400080000000000000001"),
        id="cp-boot-id-dashless",
    ),
    # An empty host: a join over "" merges everything it touches, and the hub
    # keys a collator's whole state on this.
    pytest.param(CHECKPOINT, _checkpoint(MANIFEST, host=""), id="cp-host-empty"),
    # A collection name the declaration could not have declared.
    pytest.param(
        CHECKPOINT, _manifest_entry(collection="Pools"), id="cp-collection-name-shape"
    ),
    # -- closure (the finding: constraint-free schemas; nothing asserted
    #    rejection, so unknown members rode every record unchallenged) --
    # the Go-marshalled stability classes: names is closed to
    # {stable, ephemeral}, so {"Stable":…} fails instead of leaving the join
    pytest.param(STREAM, GO_MARSHALLED_NAMES, id="names-go-marshalled"),
    # a collector minting a judgement one tier down: {"confirmed":true} on an
    # assertion validated as decoration before closure
    pytest.param(STREAM, _stream(RELATION, confirmed=True), id="assertion-confirmed"),
    # v1 has no partial commit; {"partial":true} must not ride a commit
    pytest.param(STREAM, _stream(COMMIT, partial=True), id="commit-partial"),
    # a misspelt member beside the real one: closure is what notices
    pytest.param(STREAM, _stream(BEGIN, bootid="4f2a"), id="begin-typo-member"),
    pytest.param(STREAM, _stream(END, wallms=1.0), id="end-typo-member"),
    # the explicit ruling: an assertion never states observability
    pytest.param(
        STREAM, _stream(RELATION, observability="confirmed"), id="assertion-observability"
    ),
    # a target carries a name, never an id (DESIGN 13)
    pytest.param(
        STREAM,
        _stream(RELATION, target={"kind": "block-device", "name": "n", "id": "x"}),
        id="target-id",
    ),
    # a record type the contract does not define
    pytest.param(STREAM, {"record": "snapshot"}, id="unknown-record"),
    # -- names values are scalars or lists of scalars, never structures --
    pytest.param(
        STREAM, _stream(OBJECT, names={"stable": {"guid": True}}), id="name-boolean"
    ),
    pytest.param(
        STREAM,
        _stream(OBJECT, names={"stable": {"guid": {"value": "1155"}}}),
        id="name-object",
    ),
    pytest.param(
        STREAM, _stream(OBJECT, names={"stable": {"devices": [None]}}), id="name-null"
    ),
    pytest.param(
        STREAM, _stream(OBJECT, names={"stable": {"guid": ""}}), id="name-empty",
    ),
    # -- identity strings are non-empty: "" joins everything it touches --
    pytest.param(STREAM, _stream(OBJECT, name=""), id="object-name-empty"),
    pytest.param(STREAM, _stream(BEGIN, request=""), id="request-empty"),
    pytest.param(STREAM, _stream(BEGIN, batch=""), id="batch-empty"),
    pytest.param(STREAM, _stream(BEGIN, declaration=""), id="declaration-hash-empty"),
    pytest.param(STREAM, _stream(BEGIN, boot_id=""), id="boot-id-empty"),
    # -- boot_id is UUID-shaped and never nil (DESIGN 19): the repair that
    #    closed blank left constant-but-plausible open, and nil is the
    #    plausible stub every runtime hands out for free; a constant VALID
    #    id is a cross-boot variant's to catch, not a schema's --
    pytest.param(
        STREAM,
        _stream(BEGIN, boot_id="00000000-0000-0000-0000-000000000000"),
        id="boot-id-nil",
    ),
    pytest.param(STREAM, _stream(BEGIN, boot_id="4f2a"), id="boot-id-not-uuid"),
    # machine-id's spelling — 32 hex, no dashes — is the id a port reaches
    # for when it wanted /proc/sys/kernel/random/boot_id, and it is stable
    # across boots, which defeats the member's whole purpose
    pytest.param(
        STREAM,
        _stream(BEGIN, boot_id="4f2a91cc8f604ae5b60c7b3ba27ea55e"),
        id="boot-id-machine-id-spelling",
    ),
    pytest.param(STREAM, _stream(RELATION, type=""), id="relation-type-empty"),
    pytest.param(STREAM, _stream(RELATION, vantage=""), id="vantage-empty"),
    pytest.param(
        STREAM,
        _stream(RELATION, target={"kind": "block-device", "name": ""}),
        id="target-name-empty",
    ),
    pytest.param(STREAM, _stream(UNOBSERVABLE, fact=""), id="unobservable-fact-empty"),
    # instance is nullable, never empty: "" would mint a third scope
    pytest.param(STREAM, _stream(BEGIN, instance=""), id="instance-empty"),
    # -- collection names mirror the declaration's pattern --
    pytest.param(STREAM, _stream(OBJECT, collection="Pools"), id="collection-case"),
    pytest.param(STREAM, _stream(DECLINE, collection=""), id="collection-empty"),
    pytest.param(
        STREAM, _stream(BEGIN, generations={"Pools": 1}), id="generations-key-case"
    ),
    pytest.param(
        STREAM, _stream(BEGIN, generations={"pools": -1}), id="generation-negative"
    ),
    # -- a commit without its three counts has disabled the truncation
    #    check (DESIGN 19: required members, not optional ones) --
    pytest.param(STREAM, _without(COMMIT, "objects"), id="commit-no-objects"),
    pytest.param(STREAM, _without(COMMIT, "assertions"), id="commit-no-assertions"),
    pytest.param(STREAM, _without(COMMIT, "unobservable"), id="commit-no-unobservable"),
    pytest.param(STREAM, _stream(COMMIT, assertions=-1), id="commit-count-negative"),
    # -- a fact's value is never null: each of the three statements has its
    #    own channel and a null names none of them (DESIGN 19) --
    pytest.param(STREAM, _stream(OBJECT, facts={"Health": None}), id="fact-null"),
    pytest.param(
        STREAM, _stream(RELATION, facts={"VdevPath": None}), id="relation-fact-null"
    ),
    # -- absent entries name declared facts; "" names nothing --
    pytest.param(STREAM, _stream(OBJECT, absent=[""]), id="absent-empty-string"),
    # -- at is boot-scale and stamped, never zero, negative or wall-clock --
    pytest.param(STREAM, _stream(OBJECT, at=0), id="at-zero"),
    pytest.param(STREAM, _stream(OBJECT, at=-1.0), id="at-negative"),
    pytest.param(STREAM, _stream(OBJECT, at=1000000001), id="at-wall-clock"),
    pytest.param(STREAM, _stream(OBJECT, at="214697.204"), id="at-string"),
    # -- the evidence commitment names its regime (DESIGN 19): JSON digests
    #    under a canon, anything else digests exact bytes --
    pytest.param(STREAM, CANONLESS_JSON_EVIDENCE, id="evidence-json-no-canon"),
    pytest.param(
        STREAM,
        _stream(
            OBJECT,
            evidence={"media_type": "text/plain", "digest": "sha256:aa", "canon": "jcs/1"},
        ),
        id="evidence-bytes-with-canon",
    ),
    # -- unobservable draws from the decline vocabulary minus absent:
    #    could-not-read-because-not-there is the absent list's statement --
    pytest.param(STREAM, _stream(UNOBSERVABLE, reason="absent"), id="unobservable-absent"),
    # ── answer ───────────────────────────────────────────────────────────
    # the epistemic conditional (DESIGN 25): anything dark, declined,
    # unswept or unreadable forbids complete
    pytest.param(ANSWER, COMPLETE_BESIDE_DARK, id="complete-beside-dark"),
    pytest.param(
        ANSWER,
        _answer(
            reach={
                "consulted": ["storage-1/protection"],
                "declined": [
                    {"host": "nas-1", "collection": "datasets", "reason": "unavailable"}
                ],
            }
        ),
        id="complete-beside-declined",
    ),
    pytest.param(
        ANSWER,
        _answer(reach={"consulted": ["storage-1/protection"], "unswept": ["edge-1"]}),
        id="complete-beside-unswept",
    ),
    pytest.param(
        ANSWER,
        _answer(
            scope="estate",
            reach={
                "consulted": ["storage-1/protection"],
                "coverage": {"declared": ["storage-1"], "sources_unreadable": ["dhcp"]},
            },
        ),
        id="complete-beside-unreadable-source",
    ),
    # law 4 wired: a derived claim's origin is the tier that computed it
    pytest.param(
        ANSWER,
        _answer_with_basis({**DERIVED_BASIS, "origin": "browser"}),
        id="derived-origin-not-a-tier",
    ),
    # unswept carries host names, not structures and not ""
    pytest.param(
        ANSWER,
        _answer(
            epistemic="partial",
            reach={"consulted": ["storage-1/protection"], "unswept": [""]},
        ),
        id="unswept-empty-host",
    ),
    pytest.param(
        ANSWER,
        _answer(
            epistemic="partial",
            reach={"consulted": ["storage-1/protection"], "unswept": [{"host": "edge-1"}]},
        ),
        id="unswept-structured",
    ),
    # closure at every level of the answer
    pytest.param(ANSWER, _answer(confidence=0.9), id="answer-unknown-member"),
    pytest.param(
        ANSWER,
        _answer(
            epistemic="partial",
            reach={"consulted": ["storage-1/protection"], "unreachable": []},
        ),
        id="reach-unknown-member",
    ),
    # an observed element carrying a derived member is two kinds pretending
    # to be one — unevaluatedProperties is what catches the cross-branch ride
    pytest.param(
        ANSWER,
        _answer_with_basis({**OBSERVED_BASIS, "rule": "r@1"}),
        id="observed-basis-with-rule",
    ),
    pytest.param(
        ANSWER,
        _answer_with_basis({**DERIVED_BASIS, "note": "x"}),
        id="basis-unknown-member",
    ),
    # ── declaration ──────────────────────────────────────────────────────
    # an enum without members is an open set a renderer must guess at
    pytest.param(DECLARATION, _fact(type="enum"), id="enum-without-values"),
    pytest.param(DECLARATION, _fact(type="enum", values=[]), id="enum-empty-values"),
    pytest.param(DECLARATION, _fact(values=["a"]), id="values-on-non-enum"),
    # labels belong to booleans alone (DESIGN 27)
    pytest.param(
        DECLARATION, _fact(labels=["on", "off"]), id="labels-on-non-boolean"
    ),
    # law 4: a derivation names its inputs
    pytest.param(DECLARATION, _fact(kind="derived"), id="derived-without-inputs"),
    # a percentage names what it is over (DESIGN 27)
    pytest.param(
        DECLARATION,
        _fact(type="number", unit="percent"),
        id="percent-without-denominator",
    ),
    # carries_facts is a promise the facts map keeps, both ways
    pytest.param(
        DECLARATION,
        _declaration(relations=[{"type": "contains", "carries_facts": True}]),
        id="carries-facts-without-facts",
    ),
    pytest.param(
        DECLARATION,
        _declaration(
            relations=[{"type": "contains", "carries_facts": True, "facts": {}}]
        ),
        id="carries-facts-empty-facts",
    ),
    pytest.param(
        DECLARATION,
        _declaration(
            relations=[
                {
                    "type": "contains",
                    "carries_facts": False,
                    "facts": {
                        "X": {
                            "type": "string",
                            "temperament": "state",
                            "kind": "observed",
                            "discloses": "nothing",
                            "sentence": "s.",
                        }
                    },
                }
            ]
        ),
        id="facts-without-carries-facts",
    ),
    # redactions or an exemption, exactly one: neither is a build failure
    # (DESIGN 19) and both is two rulings contradicting each other
    pytest.param(
        DECLARATION,
        _declaration(
            redactions=[{"path": "/p", "discloses": "identity"}],
            redaction_exemption="no credential surface.",
        ),
        id="redactions-and-exemption",
    ),
    pytest.param(
        DECLARATION,
        {
            **copy.deepcopy(DECLARATION_DOC),
            "collections": [_without(DECLARATION_DOC["collections"][0], "redaction_exemption")],
        },
        id="neither-redactions-nor-exemption",
    ),
    pytest.param(
        DECLARATION, _declaration(redaction_exemption=""), id="exemption-empty"
    ),
    # freshness carries its unit or two consumers read two numbers
    pytest.param(DECLARATION, _declaration(freshness="60"), id="freshness-unitless"),
    pytest.param(
        DECLARATION, _declaration(freshness="60 seconds"), id="freshness-prose"
    ),
    # closure: a misspelt declaration member is a sandbox path not granted
    pytest.param(DECLARATION, _declaration(colour="blue"), id="collection-unknown-member"),
    pytest.param(
        DECLARATION,
        {**copy.deepcopy(DECLARATION_DOC), "probes": "x"},
        id="declaration-unknown-member",
    ),
    pytest.param(DECLARATION, _fact(units="bytes"), id="fact-typo-member"),
    # ── intent ───────────────────────────────────────────────────────────
    # a protection row protecting to nowhere reads as protected
    pytest.param(
        INTENT,
        _intent(
            protection=[
                {
                    "target": "tank/photos",
                    "owner": "storage-1",
                    "class": "irreplaceable",
                    "destinations": [],
                }
            ]
        ),
        id="protection-no-destinations",
    ),
    # a ruling carries the revision that made it; -1 names none
    pytest.param(
        INTENT,
        _intent(
            membership={
                **copy.deepcopy(INTENT_DOC["membership"]),
                "not_hosts": [
                    {
                        "id": "nh-1",
                        "denoted_by": [{"source": "net/peers", "name": "phone-1"}],
                        "why": "a handset",
                        "by": "estate-owner",
                        "revision": -1,
                    }
                ],
            }
        ),
        id="not-host-negative-revision",
    ),
    # review age is a fact, so reviewed is a date, not prose
    pytest.param(INTENT, _intent(reviewed="yesterday"), id="reviewed-not-a-date"),
    # the typo that validates as no-policy-at-all: closure is the teeth
    pytest.param(
        INTENT,
        _intent(protecton=[{"target": "tank/photos"}]),
        id="intent-typo-member",
    ),
    pytest.param(
        INTENT,
        _intent(
            membership={
                **copy.deepcopy(INTENT_DOC["membership"]),
                "hosts": {"storage-1": {"expected_disk": 3}},
            }
        ),
        id="host-typo-member",
    ),
]


@pytest.mark.parametrize("schema_file,document", REJECTIONS)
def test_the_schema_rejects(schema_file: str, document: dict) -> None:
    assert _errors(schema_file, document), (
        f"{schema_file} accepted a document that violates the contract — "
        f"the rule this case pins has lost its teeth:\n"
        f"{json.dumps(document, indent=2)[:1500]}"
    )


# ── the tripwire: this suite notices a gutting ───────────────────────────


def test_a_gutted_schema_is_caught_by_this_suite() -> None:
    """Strip the stream schema to its identity keys and prove a rejection
    document sails through.

    This is the event that motivated the whole file: every constraint was
    deleted from all five schemas once and the suite stayed green. If this
    test ever fails, the rejection cases above are passing for some reason
    other than the schemas' constraints — which would mean a gutting could
    again go unnoticed.
    """
    gutted = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": STREAM,
    }
    validator = Draft202012Validator(gutted, registry=_registry(override=gutted))
    assert not list(validator.iter_errors(GO_MARSHALLED_NAMES)), (
        "a schema stripped of every constraint still rejected the "
        "Go-marshalled names document — the rejection above is not coming "
        "from the schema, so this suite could not notice a gutting"
    )


def test_a_gutted_checkpoint_schema_is_caught_by_this_suite() -> None:
    """The same tripwire for the checkpoint, on the rule it exists for.

    The stream's tripwire proves the stream's cases come from the stream's
    constraints; it says nothing about a schema added later, and a per-schema
    tripwire is the only shape that does. `stale` without its reason is the
    case chosen because it is the one a permissive schema most obviously
    lets through: both members are well-typed and the defect is only in
    their combination, so it is the rejection that would survive longest
    while coming from nowhere.
    """
    gutted = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": CHECKPOINT,
    }
    validator = Draft202012Validator(gutted, registry=_registry(override=gutted))
    assert not list(validator.iter_errors(_manifest_entry(freshness="stale"))), (
        "a checkpoint schema stripped of every constraint still rejected a "
        "stale collection with no reason — that rejection is not coming from "
        "the schema, so this suite could not notice a gutting of it"
    )
