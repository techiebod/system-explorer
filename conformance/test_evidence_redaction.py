"""Evidence redacts what it should, and says so honestly.

`evidence_ref` serves the raw native payload on an unauthenticated API (SPEC
section 7: the trust boundary is whatever network the agent binds to, and three
agents on this estate bind 0.0.0.0). Two adapters already refused to serve a
secret through it — docker for Config.Env, units for a service's Environment=.
Both fixes were found by adversarial review, and the entry recording the second
one says the real finding out loud: **nothing asserts that evidence redacts
what it should.** Writing this file found a third, system serving
org.freedesktop.systemd1.Manager.Environment, which is that same property one
interface up.

So there are two halves here, and the second is the one that generalises:

  * the redactors do what they claim — values gone, names kept, and a declared
    path meaning something was ACTUALLY withheld. That last property was false:
    both redactors declared a path whenever a watched key was present, so every
    container published `redacted: ["Config.Cmd"]` while serving its Cmd in
    full. An envelope that claims to have withheld what it served is worse than
    one that stays quiet, because a reader trusts it.
  * every evidence-serving path either redacts or is exempt IN WRITING — at
    the grain of get_evidence's `collection == "<name>"` branches, because a
    per-adapter rule let one redacting family cover its raw siblings (servarr's
    history redactor covered raw apps/health/queue evidence, and evicted the
    written reason for them from the table). Ten-plus adapters define
    get_evidence; the next one is the one this is for.
"""

import ast

import pytest

from common import AGENT_DIR, EVIDENCE_REDACTION_EXEMPTIONS, resolve_fact_path

from system_explorer.agent import envelope as env
from system_explorer.agent.adapters.docker import _redact_env
from system_explorer.agent.adapters.units import SECRET_LIST_PROPERTIES

DBUS_KEYS = SECRET_LIST_PROPERTIES


# ── the primitive: NAME=VALUE ────────────────────────────────────────────

def test_the_value_goes_and_the_name_stays():
    """The name is the diagnostically useful half — "is DATABASE_URL even
    set?" is a real question — and the value is the credential."""
    out, changed = env.redact_assignments(["DATABASE_URL=postgres://u:pw@h/db"])
    assert out == [f"DATABASE_URL={env.REDACTED}"]
    assert changed


def test_a_value_containing_equals_is_cut_at_the_first_one():
    out, _ = env.redact_assignments(["KEY=a=b=c"])
    assert out == [f"KEY={env.REDACTED}"], "the value's own '=' must not survive"


def test_a_token_with_no_value_stays_legible():
    """Deny-by-default applies to values, not to words: a bare Cmd token is
    what makes the evidence readable at all."""
    out, changed = env.redact_assignments(["nginx", "-g", "daemon off;"])
    assert out == ["nginx", "-g", "daemon off;"]
    assert not changed


def test_redaction_is_idempotent():
    once, _ = env.redact_assignments(["K=v"])
    twice, changed = env.redact_assignments(once)
    assert twice == once
    assert not changed, "a second pass must not claim to have withheld anything"


def test_a_non_string_element_does_not_crash_the_evidence_route():
    """The type test and the operation disagreed: `"=" in str(e)` gated while
    `e.split(...)` executed, so a bytes element raised TypeError inside a
    request handler — a 500 where an envelope belonged."""
    out, _ = env.redact_assignments([b"K=V", 7, None])
    assert all(isinstance(item, str) for item in out)


# ── the D-Bus shape, shared by units and system ──────────────────────────

def test_a_dbus_property_is_redacted_and_its_path_declared():
    payload = {"org.freedesktop.systemd1.Service": {"Environment": ["TOKEN=abc"]}}
    out, paths = env.redact_list_properties(payload, DBUS_KEYS)
    assert out["org.freedesktop.systemd1.Service"]["Environment"] == [f"TOKEN={env.REDACTED}"]
    assert paths == ["org.freedesktop.systemd1.Service.Environment"]


def test_the_input_payload_is_not_mutated():
    """Load-bearing: the redactors rewrite in place and only the deepcopy
    stands between that and the caller's live D-Bus reply."""
    payload = {"iface": {"Environment": ["TOKEN=abc"]}}
    env.redact_list_properties(payload, DBUS_KEYS)
    assert payload["iface"]["Environment"] == ["TOKEN=abc"]


def test_pass_environment_declares_nothing_because_it_can_withhold_nothing():
    """systemd's PassEnvironment is a list of bare NAMES. Redacting it is a
    no-op, and it used to announce one anyway."""
    payload = {"iface": {"PassEnvironment": ["HOME", "PATH"]}}
    out, paths = env.redact_list_properties(payload, DBUS_KEYS)
    assert out == payload
    assert paths == []


def test_environment_files_stay_legible():
    """A deliberate exclusion that until now existed only in a comment: the
    paths are not secret, and naming them is how an operator finds where the
    credential actually comes from."""
    payload = {"iface": {"EnvironmentFiles": [["/run/secrets/app.env", True]]}}
    out, paths = env.redact_list_properties(payload, DBUS_KEYS)
    assert out == payload and paths == []


# ── the docker shape: a recursive walk over an inspect document ──────────

def test_container_env_is_redacted_and_cmd_is_kept():
    payload = {"Config": {"Env": ["SECRET=s"], "Cmd": ["nginx", "-g"]}}
    out, paths = _redact_env(payload)
    assert out["Config"]["Env"] == [f"SECRET={env.REDACTED}"]
    assert out["Config"]["Cmd"] == ["nginx", "-g"]
    assert paths == ["Config.Env"], "Cmd withheld nothing and must not be declared"


def test_a_secret_nested_under_a_list_is_still_redacted():
    """The docstring has always promised "every Env list in an inspect
    document"; the walk returned on anything that was not a dict."""
    out, paths = _redact_env({"Mounts": [{"Env": ["SECRET=s"]}]})
    assert out["Mounts"][0]["Env"] == [f"SECRET={env.REDACTED}"]
    assert paths == ["Mounts.0.Env"]


def test_nesting_is_walked_to_any_depth():
    out, paths = _redact_env({"a": {"b": {"c": {"Env": ["S=s"]}}}})
    assert paths == ["a.b.c.Env"]
    assert out["a"]["b"]["c"]["Env"] == [f"S={env.REDACTED}"]


def test_the_inspect_document_is_not_mutated():
    payload = {"Config": {"Env": ["SECRET=s"]}}
    _redact_env(payload)
    assert payload["Config"]["Env"] == ["SECRET=s"]


@pytest.mark.parametrize("payload", [
    {"Config": {"Env": ["S=s"], "Cmd": ["sh", "-c", "--pw=x"]}},
    {"Mounts": [{"Env": ["S=s"]}], "Config": {"Entrypoint": ["/bin/x"]}},
])
def test_every_declared_path_resolves_into_the_returned_payload(payload):
    """A path a consumer cannot follow is not a declaration, it is noise —
    the same property test_invariants asserts for opinion evidence."""
    out, paths = _redact_env(payload)
    for path in paths:
        resolve_fact_path(out, path)


@pytest.mark.parametrize("payload", [
    {"Config": {"Env": ["S=s"]}},
    {"Config": {"Cmd": ["nginx"]}},
    {"Config": {"Env": []}},
])
def test_a_declared_path_means_something_was_actually_withheld(payload):
    """The property that was false. Compare the before and after at each
    declared path: if they are equal, the envelope lied."""
    out, paths = _redact_env(payload)
    for path in paths:
        assert resolve_fact_path(out, path) != resolve_fact_path(payload, path), (
            f"{path} is declared redacted but is byte-identical to the input"
        )


# ── the structural half: every evidence path is accounted for ────────────

def evidence_adapters() -> list[str]:
    """Every adapter defining get_evidence, discovered rather than listed —
    a new adapter must not be able to arrive outside this check."""
    found = []
    for source in sorted((AGENT_DIR / "adapters").glob("*.py")):
        tree = ast.parse(source.read_text(), filename=str(source))
        if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name == "get_evidence" for node in ast.walk(tree)):
            found.append(source.stem)
    return found


EVIDENCE_ADAPTERS = evidence_adapters()


def _evidence_function(subsystem: str) -> ast.AST:
    tree = ast.parse((AGENT_DIR / "adapters" / f"{subsystem}.py").read_text())
    return next(node for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "get_evidence")


def _redaction_calls(node: ast.AST) -> list[str]:
    """Calls to something named like a redactor, matched on the AST call and
    never on the source text. `"redact" in source` would pass on a comment —
    that is the same shape as the some-command-appears check that let smartctl
    ride along unlisted for two days (test_adapter_lint's docstring)."""
    names = []
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        name = (sub.func.attr if isinstance(sub.func, ast.Attribute)
                else sub.func.id if isinstance(sub.func, ast.Name) else "")
        if "redact" in name:
            names.append(name)
    return names


def _collection_branches(func: ast.AST) -> dict[str, list[list[ast.stmt]]]:
    """Each `collection == "<name>"` If/elif branch of get_evidence, name to
    body — an elif chain nests in orelse and is walked as its own If, and a
    name compared twice keeps every body. Only the branch's own body counts:
    its orelse belongs to the next branch or to shared code."""
    branches: dict[str, list[list[ast.stmt]]] = {}
    for node in ast.walk(func):
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)):
            continue
        test = node.test
        if (isinstance(test.left, ast.Name) and test.left.id == "collection"
                and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
                and isinstance(test.comparators[0], ast.Constant)
                and isinstance(test.comparators[0].value, str)):
            branches.setdefault(test.comparators[0].value, []).append(node.body)
    return branches


def _calls_in(body: list[ast.stmt]) -> list[str]:
    names: list[str] = []
    for stmt in body:
        names.extend(_redaction_calls(stmt))
    return names


def _binds_payload(target: ast.expr) -> bool:
    if isinstance(target, ast.Name):
        return target.id == "payload"
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_binds_payload(elt) for elt in target.elts)
    return False  # a subscript store augments a payload; it does not bind one


def _serves_payload(body: list[ast.stmt]) -> bool:
    """A branch is payload-serving when it returns from inside itself or
    binds the `payload` name the shared tail return serves. A branch that
    only raises, or only augments an already-bound payload (system's time
    branch adding the timesync interface), is judged by the shared path
    that actually serves — and redacts — it."""
    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Return):
                return True
            if isinstance(node, ast.Assign) and any(
                    _binds_payload(target) for target in node.targets):
                return True
            if isinstance(node, (ast.AnnAssign, ast.AugAssign)) \
                    and node.value is not None \
                    and _binds_payload(node.target):
                return True
    return False


def _branch_redacts(func: ast.AST, branches: dict[str, list[list[ast.stmt]]],
                    bodies: list[list[ast.stmt]]) -> bool:
    """Redaction attributable to THIS branch: a redact call in its own body,
    or — the chokepoint shape — a redact call in shared code after it, when
    the branch falls through (no return of its own) to the tail that serves
    it. A call in a SIBLING branch covers nothing; that blanket rule is the
    one this lint replaced."""
    if any(_calls_in(body) for body in bodies):
        return True
    if any(isinstance(node, ast.Return)
           for body in bodies for stmt in body for node in ast.walk(stmt)):
        return False  # serves from inside itself; only its own body counts
    spans = [(body[0].lineno, body[-1].end_lineno)
             for named in branches.values() for body in named]
    last = max(body[-1].end_lineno for body in bodies)
    for sub in ast.walk(func):
        if not isinstance(sub, ast.Call):
            continue
        name = (sub.func.attr if isinstance(sub.func, ast.Attribute)
                else sub.func.id if isinstance(sub.func, ast.Name) else "")
        if "redact" in name and sub.lineno > last and not any(
                start <= sub.lineno <= end for start, end in spans):
            return True
    return False


def _require_reason(subsystem: str, key: str,
                    fallback: str | None = None) -> None:
    reason = EVIDENCE_REDACTION_EXEMPTIONS.get(key)
    if reason is None and fallback is not None and fallback != key:
        reason = EVIDENCE_REDACTION_EXEMPTIONS.get(fallback)
    assert reason, (
        f"adapters/{subsystem}.py serves evidence without redacting it and "
        f"{key!r} is not in EVIDENCE_REDACTION_EXEMPTIONS. Either redact, or "
        "add a reason specific enough that a reviewer could prove it wrong."
    )
    assert len(reason) > 40 and reason.rstrip().endswith("."), (
        f"{key}'s exemption reason is too thin to review: {reason!r}"
    )


def test_the_redaction_lint_is_armed():
    """Ten adapters serve evidence today. If discovery finds far fewer, the
    glob broke and every check below passes over an empty list."""
    assert len(EVIDENCE_ADAPTERS) >= 9, EVIDENCE_ADAPTERS
    redacting = [s for s in EVIDENCE_ADAPTERS if _redaction_calls(_evidence_function(s))]
    assert len(redacting) >= 3, (
        f"only {redacting} redact; docker, units and system all should"
    )


@pytest.mark.parametrize("subsystem", EVIDENCE_ADAPTERS)
def test_every_evidence_path_redacts_or_is_exempt_with_a_reason(subsystem):
    """The generalising half, at branch grain. An adapter serving a raw
    native payload has either thought about its credential surface or
    written down why it need not — never neither, and never silently. The
    old rule was per-adapter — any redact call anywhere covered the whole
    function — so one redacting family hid every raw sibling: servarr's
    history redactor silently covered its raw apps/health/queue evidence
    AND forced the written reason for those three families off the table.
    Now every `collection == "<name>"` branch that serves a payload must
    redact — in its own body or on its fall-through path — or carry a
    "<module>:<collection>" (or bare "<module>") exemption."""
    func = _evidence_function(subsystem)
    branches = _collection_branches(func)
    if not branches:
        # No collection branches: the whole function is the one path, and
        # a redact call anywhere in it is that path's redaction.
        if not _redaction_calls(func):
            _require_reason(subsystem, subsystem)
        return
    for name, bodies in sorted(branches.items()):
        if not any(_serves_payload(body) for body in bodies):
            continue
        if _branch_redacts(func, branches, bodies):
            continue
        _require_reason(subsystem, f"{subsystem}:{name}", fallback=subsystem)


@pytest.mark.parametrize("key", sorted(EVIDENCE_REDACTION_EXEMPTIONS))
def test_an_exemption_does_not_outlive_the_gap(key):
    """A debt register, not a dumping ground: once the code an entry excuses
    starts redacting, the entry has to come off or the table stops meaning
    what it says. The ratchet is per-key: a bare "<module>" entry ratchets
    on the whole function, a "<module>:<collection>" entry only on THAT
    branch — so an adapter redacting one family can keep the written
    reasons for its raw siblings on the table."""
    module, _, coll = key.partition(":")
    assert module in EVIDENCE_ADAPTERS, (
        f"{key} is exempted but adapters/{module}.py serves no evidence at all"
    )
    func = _evidence_function(module)
    if not coll:
        assert not _redaction_calls(func), (
            f"{module} now redacts — remove it from EVIDENCE_REDACTION_EXEMPTIONS"
        )
        return
    branches = _collection_branches(func)
    assert coll in branches, (
        f"{key} names a collection branch {module}.get_evidence does not have"
    )
    assert not _branch_redacts(func, branches, branches[coll]), (
        f"{module}'s {coll} branch now redacts — remove {key} from "
        "EVIDENCE_REDACTION_EXEMPTIONS"
    )


@pytest.mark.parametrize("subsystem", ["docker", "units", "system"])
def test_a_redacting_adapter_declares_what_it_withheld(subsystem):
    """Redaction that hides its own existence breaks the provenance contract
    just as surely as redaction that never happened."""
    source = (AGENT_DIR / "adapters" / f"{subsystem}.py").read_text()
    assert '"redacted"' in source, (
        f"{subsystem} redacts but never sets the envelope's `redacted` member"
    )


def test_domain_xml_is_requested_without_the_secure_flag():
    """vms is exempt only because XMLDesc(0) omits VIR_DOMAIN_XML_SECURE
    material — <graphics passwd=...> among it — and a read-only connection
    could not ask for it anyway. That is a libvirt contract nothing in this
    repository states, so the exemption's premise is asserted here.

    The non-empty check comes FIRST and is the whole point: renaming or
    wrapping XMLDesc would otherwise make this pass over an empty list for
    ever, which is exactly how a guard becomes decorative.
    """
    tree = ast.parse((AGENT_DIR / "adapters" / "vms.py").read_text())
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
             and node.func.attr == "XMLDesc"]
    assert calls, (
        "vms.py no longer calls XMLDesc — the premise of its redaction "
        "exemption is gone and the exemption must be re-argued"
    )
    for call in calls:
        assert not call.keywords and len(call.args) == 1, f"unexpected XMLDesc{ast.dump(call)}"
        flag = call.args[0]
        assert isinstance(flag, ast.Constant) and flag.value == 0, (
            "XMLDesc must be called with flag 0. A non-zero flag can request "
            "VIR_DOMAIN_XML_SECURE, which puts <graphics passwd=...> into "
            "evidence served on an unauthenticated API."
        )
