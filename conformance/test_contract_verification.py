"""Contract verification: does the collector do what its declaration says?

DESIGN 18 names this check and calls it cheap — "run `declare`, run
`collect`, and assert that every fact emitted was declared, every declared
fact has a sentence, every value matches its declared type" — and describes
it as the genuinely new thing the tier split buys, "because today the
declaration and the code are one artefact". It did not exist. Every other
judge in this repository grades a collector against the *corpus*; nothing
graded it against its own promises, so a collector could declare four facts,
emit a fifth, and be green everywhere.

Three properties, and each fails a different way of lying:

- **Emitted implies declared.** A fact on the wire that the declaration does
  not carry has no sentence, no type, no disclosure class and no `from` path,
  so nothing downstream can render it, redact it or check it against the
  evidence document. It is a fact the product cannot describe.
- **Declared implies observed, or named.** The other direction, which is the
  one that rots quietly: a declaration listing facts no capture ever produces
  is a promise nobody has tested, and the fact dictionary this generates
  would document values the collector cannot emit. The escape is the corpus's
  own residual ledger, not silence — `storage/device-resolution` is exactly
  such a fact and is already named there.
- **The digest anchors the bytes.** `begin.declaration` must be the hash of
  the bytes `declare` actually emits. That is what lets a collator refetch on
  a mismatch instead of spawning `declare` on every collect, and it only
  works if both sides hash the same artefact rather than a re-serialisation
  of it.

Everything here drives the collector as a binary over stdin and stdout. It is
the same generic harness for every collector in any language — which is what
DESIGN 18 means by one implementation, every collector.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from conftest import GO_COLLECTORS, go_collector_binary
from se_harness import corpus, differential, replay

REPO = Path(__file__).resolve().parent.parent

VARIANTS = corpus.all_variants()

# The collectors this module can grade. A Python-adapter collector has no
# declaration to grade against — the shim wears a collector's face and
# declares nothing — so the ported set is the whole subject, and it grows as
# the fleet ports rather than being enumerated here.
PORTED = sorted(GO_COLLECTORS)

# Declared type -> what a legal value looks like on the wire. bool is tested
# before int everywhere because bool IS int to isinstance, and the wire's
# `true` is not the wire's `1` (DESIGN 19, typed equality).
_TYPE_CHECKS = {
    "boolean": lambda v: isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "string": lambda v: isinstance(v, str),
    "enum": lambda v: isinstance(v, str),
    "timestamp": lambda v: isinstance(v, str),
    "duration": lambda v: isinstance(v, str),
    "list": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}


def _declaration_validator() -> Draft202012Validator:
    registry = Registry()
    for path in sorted((REPO / "contract").glob("*.json")):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return Draft202012Validator(
        json.loads((REPO / "contract" / "se.declaration.1.json").read_text()),
        registry=registry,
    )


def _run(collector: str, request: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [go_collector_binary(collector)],
        input=f"{request}\n",
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture(scope="module")
def _declarations() -> dict[str, tuple[bytes, dict]]:
    return {}


def _declaration(collector: str) -> tuple[str, dict]:
    """The exact bytes `declare` emits, and their parse."""
    proc = _run(collector, "declare")
    assert proc.returncode == 0, (
        f"{collector}: declare exited {proc.returncode} — a collector that "
        f"cannot state its contract cannot be held to it\n{proc.stderr[:1000]}"
    )
    assert proc.stdout, f"{collector}: declare emitted nothing"
    return proc.stdout, json.loads(proc.stdout)


def _declared_facts(declaration: dict) -> dict[str, dict]:
    """collection -> {fact name -> its declared spec}."""
    return {
        collection["name"]: collection.get("facts", {})
        for collection in declaration.get("collections", [])
    }


def _declared_relations(declaration: dict) -> dict[str, dict[str, dict]]:
    """collection -> {relation type -> its declared spec}."""
    return {
        collection["name"]: {r["type"]: r for r in collection.get("relations", [])}
        for collection in declaration["collections"]
    }


def _root_fact(reference: str) -> str:
    """The declared fact a fact REFERENCE names.

    An `unobservable` record addresses a fact by path — storage's reads
    `Vdevs/wwn-0x…/Device`, one member inside a list-typed fact — because the
    thing that could not be read is nested inside a value, not beside it. The
    declaration declares the fact, not its interior, so the first segment is
    what must be declared and the rest is the address within it.
    """
    return reference.split("/", 1)[0]


# ── the declaration is a legal declaration ───────────────────────────────


def test_there_is_a_ported_collector_to_grade() -> None:
    """Non-vacuity. Every test below parametrises over PORTED, and an empty
    set would make this whole module a green run establishing nothing —
    which is the shape the product is written against."""
    assert PORTED, "no ported collector; contract verification grades nothing"


@pytest.mark.parametrize("collector", PORTED)
def test_the_declaration_validates_against_the_contract(collector: str) -> None:
    """`declare` emits a legal se.declaration/1.

    The declaration is the contract's teeth (DESIGN 19) and six other things
    are generated from it, so one that does not validate is six broken
    artefacts and a build that did not notice.
    """
    _, declaration = _declaration(collector)
    errors = sorted(_declaration_validator().iter_errors(declaration), key=str)
    assert not errors, f"{collector}: declaration is not legal:\n" + "\n".join(
        f"- {e.json_path}: {e.message}" for e in errors
    )


@pytest.mark.parametrize("collector", PORTED)
def test_the_declaration_names_the_collector_it_came_from(collector: str) -> None:
    """A declaration is addressed by the collector it describes, and the two
    are joined on that name everywhere downstream — the corpus keys on it,
    the module's authority check reads it, the hub routes on it. A binary
    declaring somebody else's name is a join that silently succeeds."""
    _, declaration = _declaration(collector)
    assert declaration["collector"] == collector, (
        f"the {collector} binary declares itself {declaration['collector']!r}"
    )


@pytest.mark.parametrize("collector", PORTED)
def test_probe_answers_with_a_verdict_not_an_exit_code(collector: str) -> None:
    """DESIGN 18: probe is "a verdict, not an exit code".

    A collector that answered "can I run here" by exiting non-zero would be
    indistinguishable from one that crashed, which is the founding failure
    this product is about — absence read as an answer.
    """
    proc = _run(collector, "probe")
    assert proc.returncode == 0, (
        f"{collector}: probe exited {proc.returncode}; a probe reports its "
        f"verdict in the document, and non-zero means only 'I could not run'"
        f"\n{proc.stderr[:1000]}"
    )
    verdict = json.loads(proc.stdout)
    assert verdict.get("verdict") in ("yes", "no"), (
        f"{collector}: probe said {verdict!r}; the verdict is yes or no"
    )
    assert verdict.get("reason"), (
        f"{collector}: probe gave no reason — a verdict a person cannot act "
        "on is a verdict they will ignore"
    )


# ── the stream honours the declaration ───────────────────────────────────


def _ported_variants() -> list[corpus.Variant]:
    return [v for v in VARIANTS if v.meta["collector"] in GO_COLLECTORS]


@pytest.mark.parametrize(
    "variant", _ported_variants(), ids=lambda v: v.name
)
def test_every_emitted_fact_was_declared(variant: corpus.Variant) -> None:
    """Emitted implies declared, across all three fact channels.

    A value, an absence and an unobservability are three statements about the
    same declared fact (DESIGN 19), so all three are held to the declaration:
    a collector cannot smuggle an undeclared fact in by only ever saying it is
    missing.
    """
    collector = variant.meta["collector"]
    _, declaration = _declaration(collector)
    declared = _declared_facts(declaration)

    proc = replay.run_collector([go_collector_binary(collector)], variant)
    assert proc.returncode == 0, (
        f"{variant.name}: collector exited {proc.returncode}\n{proc.stderr[:1000]}"
    )
    records = replay.parse_stream(proc.stdout)

    problems: list[str] = []
    for record in records:
        collection = record.get("collection")
        if collection is None:
            continue
        if collection not in declared:
            if record.get("record") == "decline":
                continue  # declining an unserved collection is the right answer
            problems.append(
                f"{record['record']} record for {collection!r}, which the "
                "declaration does not carry"
            )
            continue
        facts = declared[collection]
        if record.get("record") == "object":
            for name, value in (record.get("facts") or {}).items():
                if name not in facts:
                    problems.append(f"{collection}: emitted undeclared fact {name!r}")
                    continue
                spec = facts[name]
                check = _TYPE_CHECKS.get(spec["type"])
                if check and not check(value):
                    problems.append(
                        f"{collection}/{name}: declared {spec['type']!r}, "
                        f"emitted {value!r}"
                    )
                if spec["type"] == "enum" and spec.get("values") is not None:
                    if value not in spec["values"]:
                        problems.append(
                            f"{collection}/{name}: {value!r} is outside the "
                            f"declared values {spec['values']!r}"
                        )
            for name in record.get("absent") or []:
                if name not in facts:
                    problems.append(
                        f"{collection}: declared absent an undeclared fact {name!r}"
                    )
        elif record.get("record") == "unobservable":
            root = _root_fact(str(record.get("fact")))
            if root not in facts:
                problems.append(
                    f"{collection}: unobservable names {record.get('fact')!r}, "
                    f"whose root {root!r} is not a declared fact"
                )
        elif record.get("record") == "relation_assertion":
            # DESIGN 18: "every relation type and discriminator was declared".
            # An undeclared type has no discriminator and no confirmation
            # rule, so the collator can neither key it nor judge it — and the
            # collator refuses the batch when it arrives. Catching it here
            # means the collector is wrong at build time rather than the
            # host losing a collection at run time.
            relations = _declared_relations(declaration).get(collection, {})
            rel_type = record.get("type")
            if rel_type not in relations:
                problems.append(
                    f"{collection}: asserted undeclared relation type {rel_type!r}"
                )
                continue
            spec = relations[rel_type]
            emitted_facts = record.get("facts") or {}
            for name in spec.get("discriminator") or []:
                if name not in emitted_facts:
                    problems.append(
                        f"{collection}/{rel_type}: declares {name!r} as its "
                        "discriminator and the assertion does not carry it — "
                        "parallel instances would collide on a key missing "
                        "the value that tells them apart"
                    )
            # carries_facts is a claim, and both directions of breaking it
            # matter: a type that says it carries none and does is smuggling
            # an unreviewed fact channel; one that says it carries facts and
            # emits none has a declaration nothing holds it to.
            if not spec.get("carries_facts") and emitted_facts:
                problems.append(
                    f"{collection}/{rel_type}: declares carries_facts false "
                    f"and emitted {sorted(emitted_facts)}"
                )
            for name, value in emitted_facts.items():
                declared_fact = (spec.get("facts") or {}).get(name)
                if declared_fact is None:
                    problems.append(
                        f"{collection}/{rel_type}: emitted undeclared relation "
                        f"fact {name!r}"
                    )
                    continue
                check = _TYPE_CHECKS.get(declared_fact["type"])
                if check and not check(value):
                    problems.append(
                        f"{collection}/{rel_type}/{name}: declared "
                        f"{declared_fact['type']!r}, emitted {value!r}"
                    )

    assert not problems, f"{variant.name}:\n" + "\n".join(f"  - {p}" for p in problems)


@pytest.mark.parametrize("collector", PORTED)
def test_the_begin_digest_is_the_digest_of_the_declared_bytes(collector: str) -> None:
    """`begin.declaration` hashes exactly what `declare` emits.

    A collator that holds a different declaration refetches rather than
    spawning `declare` on every collect (DESIGN 19) — which works only if the
    two sides hash the same artefact. Hash a re-serialisation and the digest
    drifts from the bytes on every key-order change, so the refetch fires
    forever or never.
    """
    raw, _ = _declaration(collector)
    expected = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()

    variants = [v for v in VARIANTS if v.meta["collector"] == collector]
    assert variants, f"{collector}: no corpus variant, so no begin to check"
    for variant in variants:
        proc = replay.run_collector([go_collector_binary(collector)], variant)
        begin = next(
            r for r in replay.parse_stream(proc.stdout) if r["record"] == "begin"
        )
        assert begin["declaration"] == expected, (
            f"{variant.name}: begin carries {begin['declaration']!r}, but the "
            f"bytes declare emits hash to {expected!r}"
        )


def _observe(binary: list[str], variant, observed: dict[str, set[str]],
             payload_dir=None) -> None:
    """Fold one run's fact references into the observed set, all channels."""
    proc = replay.run_collector(binary, variant, payload_dir=payload_dir)
    for record in replay.parse_stream(proc.stdout):
        collection = record.get("collection")
        if collection not in observed:
            continue
        if record.get("record") == "object":
            observed[collection].update(record.get("facts") or {})
            observed[collection].update(record.get("absent") or [])
        elif record.get("record") == "unobservable":
            observed[collection].add(_root_fact(str(record.get("fact"))))


@pytest.mark.parametrize("collector", PORTED)
def test_every_declared_fact_is_observed_somewhere_or_named(collector: str) -> None:
    """Declared implies observed, or named in the residual ledger.

    The direction that rots quietly. A declaration listing facts no capture
    produces is a set of promises nothing tests, and the fact dictionary
    generated from it documents values the collector may be unable to emit at
    all. Any of the three channels counts as observation — a fact declared
    absent, or reported unobservable, has still been exercised.

    Ownership is the same three-way partition the mutation guard uses over its
    closed classes: a fact is reached by a committed capture, or minted by a
    mutation operator, or named in the residual ledger with the venue that
    owns it. All three are real coverage and the ledger is the only one that
    is a statement of absence.

    The operator arm is not a formality. It is how this check found
    LastScrubEndTime and its Unobservable sibling — two facts the shipping
    adapter emits only where a resilver has overwritten the scrub record,
    declared and implemented and reached by no capture at all, existing
    because a live host once read ScanAgeDays 9 off a resilver beside a
    months-old scrub. Mintable, therefore an operator rather than a residual,
    per the guard's own rule that a residual is only for what cannot be
    staged.
    """
    _, declaration = _declaration(collector)
    declared = _declared_facts(declaration)
    variants = [v for v in VARIANTS if v.meta["collector"] == collector]
    assert variants, f"{collector}: no corpus variant to observe anything in"

    binary = [go_collector_binary(collector)]
    observed: dict[str, set[str]] = {name: set() for name in declared}
    for variant in variants:
        _observe(binary, variant, observed)

    seed_name = differential.SEEDS.get(collector)
    if seed_name:
        seed = next(v for v in VARIANTS if v.name == seed_name)
        for operator in differential.OPERATORS:
            if operator.collector != collector:
                continue
            payloads = differential.mutated_payloads(operator, seed)
            with tempfile.TemporaryDirectory(prefix="se-declared-") as tmp:
                directory = Path(tmp)
                differential.write_payloads(payloads, directory,
                                            seed.payload_suffixes)
                _observe(binary, seed, observed, payload_dir=directory)

    orphans = []
    for collection, facts in sorted(declared.items()):
        for name in sorted(set(facts) - observed[collection]):
            if any(
                key.startswith(f"{collector}/") and name.lower() in reason.lower()
                for key, reason in corpus.NAMED_RESIDUALS.items()
            ):
                continue
            orphans.append(f"{collection}/{name}")
    assert not orphans, (
        f"{collector} declares facts no capture ever produces, in any channel, "
        f"and names none of them: {orphans}. A promise nothing tests is what "
        "the fact dictionary would document and the collector might not be "
        "able to emit. Capture a variant that reaches it, or name it in "
        "corpus.NAMED_RESIDUALS with the venue that owns it."
    )
