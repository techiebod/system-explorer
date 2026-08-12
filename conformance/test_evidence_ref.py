"""The evidence URL is spelled in exactly one place, and it encodes.

env.evidence_ref()'s docstring claims it is "the one place an evidence URL
is spelled". Nothing held that promise (cross-file review, 2026-08-12): a
resurrected f-string would pass every schema check — the published pattern
is only `^/v1/` — and fail live, at click time, on a deployed host. The
walk below makes the promise structural: every `evidence_ref=` keyword in
every adapter must be a call to the helper, never a string expression.

The encoding cases pin the other half of the same review finding: the ref
is followed verbatim by the UI, so the emitter owns percent-encoding. An
unencoded `#` would be cut off as a URL fragment by the browser, silently
fetching a different object's evidence with HTTP 200.
"""

import ast

from common import AGENT_DIR

from system_explorer.agent import envelope as env

ADAPTERS_DIR = AGENT_DIR / "adapters"


def test_every_adapter_evidence_ref_goes_through_the_helper():
    offenders = []
    seen = 0
    for path in sorted(ADAPTERS_DIR.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "evidence_ref":
                    continue
                seen += 1
                value = keyword.value
                is_helper_call = (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Attribute)
                    and value.func.attr == "evidence_ref")
                if not is_helper_call:
                    offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, (
        "evidence_ref built outside env.evidence_ref() — the URL shape has "
        f"exactly one owner: {offenders}")
    # Anti-vacuity: the walk must actually be seeing the adapters' emissions.
    assert seen >= 18, f"walker found only {seen} evidence_ref sites"


def test_the_ref_is_prefix_form_and_preserves_id_punctuation():
    ref = env.evidence_ref("storage", "pools", "pool:media")
    assert ref == "/v1/evidence/storage/pools/pool:media"


def test_slashes_in_ids_survive():
    ref = env.evidence_ref("storage", "datasets", "dataset:tank/photos")
    assert ref == "/v1/evidence/storage/datasets/dataset:tank/photos"


def test_fragment_and_query_characters_are_encoded():
    # An unencoded '#' is cut off as a fragment by the browser; '?' starts a
    # query string. Either way the agent would serve a DIFFERENT object's
    # evidence with HTTP 200 — the parent's-evidence bug through the other door.
    assert "%23" in env.evidence_ref("storage", "mounts", "mount:/data/#scratch")
    assert "%3F" in env.evidence_ref("network", "lookups", "lookup:resolve/a?b")
    assert "#" not in env.evidence_ref("storage", "mounts", "mount:/data/#scratch")
