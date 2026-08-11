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
  * every adapter serving evidence either redacts or is exempt IN WRITING. Ten
    adapters define get_evidence; the next one is the one this is for.
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
    """The generalising half. An adapter serving a raw native payload has
    either thought about its credential surface or written down why it need
    not — never neither, and never silently."""
    if _redaction_calls(_evidence_function(subsystem)):
        return
    reason = EVIDENCE_REDACTION_EXEMPTIONS.get(subsystem)
    assert reason, (
        f"adapters/{subsystem}.py serves evidence without redacting anything "
        "and is not in EVIDENCE_REDACTION_EXEMPTIONS. Either redact, or add a "
        "reason specific enough that a reviewer could prove it wrong."
    )
    assert len(reason) > 40 and reason.rstrip().endswith("."), (
        f"{subsystem}'s exemption reason is too thin to review: {reason!r}"
    )


@pytest.mark.parametrize("subsystem", sorted(EVIDENCE_REDACTION_EXEMPTIONS))
def test_an_exemption_does_not_outlive_the_gap(subsystem):
    """A debt register, not a dumping ground: once an adapter starts redacting,
    its exemption has to come off or the table stops meaning what it says."""
    assert subsystem in EVIDENCE_ADAPTERS, (
        f"{subsystem} is exempted but serves no evidence at all"
    )
    assert not _redaction_calls(_evidence_function(subsystem)), (
        f"{subsystem} now redacts — remove it from EVIDENCE_REDACTION_EXEMPTIONS"
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
