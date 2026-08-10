"""SPEC section 11, rule 5: reference commands are documentation, never execution.

Adapters acquire through D-Bus, native libraries, and kernel interfaces.
subprocess is permitted only for the structured-output commands in
common.SUBPROCESS_ALLOWLIST, and the allow-listed flag must appear in the
same argv literal that invokes the command — no parsing of human-readable
output can slip in as a 'temporary' measure, because that is exactly how the
v0.1 prototype diverged from its own specification.

Enforcement extracts argv list literals from the AST rather than grepping
for command names: the old form ("some allow-listed command string appears
in the file") let any command ride along in a file that already invoked an
allow-listed one — smartctl did exactly that for two days. Commands built
from non-literal strings can still evade extraction, which is why a
subprocess-using file with zero extractable argvs fails rather than passes.

The suite runs (and passes vacuously) while agent/ does not exist, so the
lint is armed from the first adapter file onward.
"""

import ast
import re

import pytest

from common import AGENT_DIR, SUBPROCESS_ALLOWLIST, UI_DIR

FORBIDDEN_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "spawnv"),
    ("os", "execv"),
    ("os", "execvp"),
}


def agent_sources():
    if not AGENT_DIR.is_dir():
        return []
    return sorted(AGENT_DIR.rglob("*.py"))


def uses_subprocess(tree: ast.AST, text: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] == "subprocess" for alias in node.names):
                return True
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "subprocess":
                return True
    # asyncio.create_subprocess_exec/shell would bypass the import check.
    return "create_subprocess" in text


@pytest.mark.parametrize("source", agent_sources(), ids=lambda p: str(p.relative_to(AGENT_DIR)))
def test_no_shell_escape_hatches(source):
    tree = ast.parse(source.read_text(), filename=str(source))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            assert (func.value.id, func.attr) not in FORBIDDEN_CALLS, (
                f"{source}: {func.value.id}.{func.attr}() is forbidden"
            )


# A bare program name: lowercase, no path, no leading dash. Deliberately
# broad — the flag requirement below is what separates argv literals from
# ordinary string lists like ["block-devices", "mounts", "arrays"].
COMMAND_HEAD = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


def command_argvs(tree: ast.AST):
    """Every list literal shaped like a command argv: a program-name head
    followed by at least one option token. Argvs reach subprocess through
    helpers and variables in this codebase, so heads are extracted wherever
    the literal is built, not only at the call site."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.List) and node.elts):
            continue
        head = node.elts[0]
        if not (isinstance(head, ast.Constant) and isinstance(head.value, str)):
            continue
        if not COMMAND_HEAD.match(head.value):
            continue
        rest = [elt.value for elt in node.elts[1:]
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
        if any(token.startswith("-") for token in rest):
            yield head.value, rest


@pytest.mark.parametrize("source", agent_sources(), ids=lambda p: str(p.relative_to(AGENT_DIR)))
def test_subprocess_only_for_allowlisted_structured_commands(source):
    text = source.read_text()
    tree = ast.parse(text, filename=str(source))
    if not uses_subprocess(tree, text):
        return
    argvs = list(command_argvs(tree))
    assert argvs, (
        f"{source}: uses subprocess but no command argv literal could be "
        "extracted — dynamically built commands cannot be linted and are "
        "forbidden (SPEC section 11, rule 5)"
    )
    for cmd, rest in argvs:
        assert cmd in SUBPROCESS_ALLOWLIST, (
            f"{source}: invokes {cmd!r}, which is not in the subprocess "
            f"allow-list ({sorted(SUBPROCESS_ALLOWLIST)}) — allow-list "
            "changes are deliberate, reviewed additions to common.py"
        )
        # Flags are argv tokens ('-o', 'json'), so require each token in the
        # same argv literal rather than anywhere in the file.
        for token in SUBPROCESS_ALLOWLIST[cmd].split():
            assert token in rest, (
                f"{source}: invokes {cmd!r} without its structured-output token {token!r} — "
                "parsing human-readable output is forbidden (SPEC section 2, rule 8)"
            )


# The UI's no-HTML-sink construction is why envelope data (log messages,
# container env, XML) can never become markup. Keep it an invariant, not a
# habit: the CSP in the agent's main.py is the second layer of the same
# defence.
UI_FORBIDDEN = ["innerHTML", "outerHTML", "insertAdjacentHTML",
                "document.write", "eval(", "new Function", "srcdoc"]


@pytest.mark.parametrize("source", sorted(UI_DIR.glob("*.js")) if UI_DIR.is_dir() else [],
                         ids=lambda p: p.name)
def test_ui_has_no_html_injection_sinks(source):
    text = source.read_text()
    for sink in UI_FORBIDDEN:
        assert sink not in text, (
            f"{source.name}: {sink!r} found — the UI renders envelope data via "
            "textContent only; HTML string construction is forbidden"
        )


def test_lint_is_armed():
    """Fails loudly if the agent tree appears but the glob finds nothing to lint."""
    if AGENT_DIR.is_dir():
        assert agent_sources(), f"{AGENT_DIR} exists but contains no Python sources to lint"
    else:
        pytest.skip("agent/ not created yet (Phase 1); lint arms automatically when it appears")
