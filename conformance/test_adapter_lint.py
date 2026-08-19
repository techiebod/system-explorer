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
import pathlib
import re
import subprocess

import pytest

from common import AGENT_DIR, PROJECT_DIR, SUBPROCESS_ALLOWLIST, UI_DIR

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


# Failure text is bounded in exactly one place (system_explorer.text via
# env.reason). Six adapter sites used to clip it locally at four different
# limits — 120, 140, 160, 200 — and one of them cut a live reason mid-word,
# discarding the words that named the cause. A slice literal on an exception
# or on command output is that mistake returning.
CLIP_SLICE = re.compile(r"(?:str\(\s*exc\s*\)|\.stderr|\.stdout|\.text|"
                        r"\.strip\(\))\s*\[\s*:\s*\d+\s*\]")


@pytest.mark.parametrize("source", agent_sources(), ids=lambda p: str(p.relative_to(AGENT_DIR)))
def test_failure_text_is_bounded_centrally(source):
    text = source.read_text()
    offenders = [
        f"line {index}: {line.strip()}"
        for index, line in enumerate(text.splitlines(), 1)
        if CLIP_SLICE.search(line)
    ]
    assert not offenders, (
        f"{source}: failure text clipped with a slice literal:\n  "
        + "\n  ".join(offenders)
        + "\nUse env.reason(...) — it bounds on a word boundary, marks what it "
          "dropped, and applies one limit everywhere (SPEC section 2, rule 7)."
    )


# ── refactor hazard: self.<name> that no longer exists ───────────────────
#
# Moving a helper out of an adapter and leaving one call site behind is a
# runtime AttributeError, and adapters are exactly where that hides: the suite
# validates fixtures and lints source text but never calls a collect() (the
# logged gap), so nothing else notices. It happened for real — _pointers moved
# to agent/nixos.py with the nix subsystem split and system/boot broke on every
# NixOS host, surfacing only as an error envelope in the browser.
#
# Deliberately conservative: it checks names DEFINED nowhere in the class, so a
# genuinely dynamic attribute is the only false positive, and there are none.

def _class_defined_names(node: ast.ClassDef) -> set[str]:
    """Every attribute this class body establishes: methods, class-level
    assignments, and anything assigned to self anywhere inside it."""
    names: set[str] = set()
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(item.name)
        elif isinstance(item, ast.Assign):
            names.update(t.id for t in item.targets if isinstance(t, ast.Name))
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            names.add(item.target.id)
    for sub in ast.walk(node):
        # self.x = ... in __init__ or anywhere else
        targets = (sub.targets if isinstance(sub, ast.Assign)
                   else [sub.target] if isinstance(sub, (ast.AnnAssign, ast.AugAssign))
                   else [])
        for target in targets:
            # Unpacked too: `self.a, self.b = f()` puts a Tuple in targets and
            # the attributes one level down. Without this the walk reported
            # both halves as undefined — a false positive that would fire on
            # any adapter assigning a pair, and did (2026-08-14).
            for node_ in ([target] if not isinstance(target, (ast.Tuple, ast.List))
                          else target.elts):
                if (isinstance(node_, ast.Attribute)
                        and isinstance(node_.value, ast.Name)
                        and node_.value.id == "self"):
                    names.add(node_.attr)
    return names


def _self_attributes(node: ast.ClassDef) -> set[str]:
    return {sub.attr for sub in ast.walk(node)
            if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name)
            and sub.value.id == "self" and isinstance(sub.ctx, ast.Load)}


@pytest.mark.parametrize("source", agent_sources(), ids=lambda p: str(p.relative_to(AGENT_DIR)))
def test_no_self_attribute_survives_its_definition(source):
    tree = ast.parse(source.read_text(), filename=str(source))
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        defined = _class_defined_names(node)
        missing = sorted(name for name in _self_attributes(node) if name not in defined)
        assert not missing, (
            f"{source}: class {node.name} reads self.{{{', '.join(missing)}}} which "
            "the class does not define — a helper was moved or renamed and a call "
            "site was left behind (SPEC section 11: the suite is the teeth)"
        )


# ---------------------------------------------------------------------------
# This is a public product repo. Estate records — host names, machine ids, real
# addresses — live with the deployment that raised them, not here: each finding
# only makes sense with its evidence, and that evidence is somebody's
# infrastructure. Comments kept citing the host that raised them because it
# made them credible, which is true and still the wrong place; the finding
# survives the rename intact.
#
# 20 instances had accumulated before this existed, including one real,
# stable machine-id in a UI fixture.
# ---------------------------------------------------------------------------

# Deliberately a list rather than a clever pattern: a reviewer must be able to
# see what is banned. Add a host here when the estate gains one.
ESTATE_NAMES = ("silo", "vat", "jar", "tub", "mess", "naxos", "red house",
                "redhouse", "unifi-os", "haos")

# The org name is unavoidable — it is the repository URL, the flake input and
# the package metadata. Everything else is fair game.
ESTATE_EXEMPT_FILES = {"README.md", "AGENTS.md", "pyproject.toml",
                       "nix/package.nix", "flake.nix", "flake.lock"}


def _repo_sources():
    """Everything git considers part of the repository — tracked, PLUS
    untracked-and-not-ignored. .venv, result symlinks and build output are not
    the repository, and scanning them produces nothing but false positives
    (httpx has a cookie `jar`); --exclude-standard honours .gitignore, so the
    second list keeps that exclusion while closing the hole the first one had.

    THE HOLE, because it has now cost two pushes to a public repository. Listing
    only tracked files makes this lint blind to a file that has just been
    WRITTEN, which is the state every leak is in at the moment it could still be
    caught for free. It read as green for `harness/scrub/servarr.json` carrying
    `jar`, and again for a protection manifest and meta carrying `silo` — both
    times because the suite was run before the files were staged, and both times
    the leak was found by CI after the push. A guard that can only see what has
    already been committed reports success about precisely the window in which
    it is useful.

    A missing git BINARY is the same situation as a missing .git directory:
    no repository context, nothing to scan, the lint bites on developer
    checkouts where git exists. check=False already covered "git ran and
    failed" (a GitHub-archive source inside a nix build has no .git), but a
    `path:` flake override copies the working tree WITH .git into a sandbox
    that has no git on PATH, and subprocess raised FileNotFoundError before
    check=False could matter — every hostname case failed the package build
    the first time SE_LOCAL was used after this lint landed (2026-08-12)."""
    listed: list[str] = []
    for argv in (["git", "ls-files"],
                 ["git", "ls-files", "--others", "--exclude-standard"]):
        try:
            listed += subprocess.run(argv, cwd=PROJECT_DIR, capture_output=True,
                                     text=True, check=False).stdout.split()
        except FileNotFoundError:
            pass
    exts = {".py", ".js", ".mjs", ".md", ".sh", ".json", ".jsonl", ".yml", ".nix", ".css", ".html"}
    for name in listed:
        rel = pathlib.Path(name)
        if rel.suffix not in exts or str(rel) in ESTATE_EXEMPT_FILES:
            continue
        path = PROJECT_DIR / rel
        if path.is_file():
            yield rel, path


@pytest.mark.parametrize("name", ESTATE_NAMES)
def test_no_estate_hostnames_in_the_public_repo(name):
    """A host name in a comment is a small leak that compounds: it names a
    machine, and the finding beside it says what is wrong with it."""
    pattern = re.compile(rf"\b{re.escape(name)}\b", re.I)
    hits = []
    for rel, path in _repo_sources():
        # This file necessarily contains the list.
        if rel.name == "test_adapter_lint.py":
            continue
        for number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if pattern.search(line):
                hits.append(f"{rel}:{number}: {line.strip()[:90]}")
    assert not hits, (
        f"estate host name {name!r} in a public repo:\n  " + "\n  ".join(hits[:10])
        + "\nDescribe the role instead — 'a storage host', 'a bridged guest'. "
        "The finding does not need the hostname to be true."
    )


def test_no_real_machine_ids_in_the_public_repo():
    """A machine-id is stable and unique — the one identifier that follows a
    host forever.

    Scoped to lines that actually name machine_id: a bare 32-hex literal is
    also how systemd spells a catalog MessageId, and those are public
    constants that belong in fixtures (the coredump and duplicate-name ids
    are both used by the log rules' characteristic cases).
    """
    # A reviewed list, not a pattern: every one of these is visibly synthetic,
    # and a new entry should be a decision somebody made rather than something
    # a regex happened to wave through.
    placeholder = {
        "0123456789abcdef0123456789abcdef",
        "fedcba9876543210fedcba9876543210",
        "abcdef0123456789abcdef0123456789",
        "00112233445566778899aabbccddeeff",
        "0" * 32, "f" * 32,
    }
    line_pat = re.compile(r"machine[_-]?id", re.I)
    hexes = re.compile(r"\b[0-9a-f]{32}\b")
    hits = []
    for rel, path in _repo_sources():
        if rel.name == "test_adapter_lint.py":
            continue
        for number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if not line_pat.search(line):
                continue
            for found in hexes.findall(line):
                if found not in placeholder:
                    hits.append(f"{rel}:{number}: {found}")
    assert not hits, (
        "a real machine-id in the public repo:\n  " + "\n  ".join(hits[:10])
        + "\nUse 0123456789abcdef0123456789abcdef in fixtures."
    )


def test_every_adapter_has_single_flighted_acquire():
    """The acquire() contract is load-bearing for main.py's sweeps: the
    status roll-up, the snapshot task and /v1/changes call it directly, so
    an adapter without one fails at runtime on a deployed host — status for
    that subsystem goes dark, which is precisely the absence-as-health shape
    this product exists to kill. logs is the documented exception (a bounded
    journal query has no "all items" to materialise) and every sweep
    declines logs/journal by name before calling."""
    from system_explorer.agent.adapters import build_adapters

    for name, adapter in build_adapters().items():
        if name == "logs":
            assert not hasattr(adapter, "acquire"), (
                "logs grew an acquire(); update the sweeps' decline tables "
                "and this test together")
            continue
        acquire = getattr(adapter, "acquire", None)
        assert acquire is not None, f"{name}: no acquire()"
        # single_flight wraps with functools.wraps, so the marker is the
        # wrapper's closure — assert on the documented decorator, not a name.
        assert acquire.__wrapped__ is not None, (
            f"{name}: acquire() is not @env.single_flight-decorated — "
            "concurrent sweeps and UI polls would stack acquisitions")


def test_adapter_selection_is_exact_or_refused():
    """SE_ADAPTERS (Phase 3): a selection runs exactly what it names, the
    default runs everything, and a typo refuses to start — a unit whose
    grants were audited against one list must not silently run another."""
    from system_explorer.agent.adapters import build_adapters

    everything = build_adapters()
    assert set(build_adapters(None)) == set(everything)
    subset = build_adapters(["network", "system"])
    assert set(subset) == {"network", "system"}
    with pytest.raises(ValueError) as err:
        build_adapters(["network", "sytem"])
    assert "sytem" in str(err.value) and "known" in str(err.value)


def test_the_self_attribute_walk_sees_an_unpacked_pair():
    """Anti-vacuity for the fix above, because the failure was a FALSE
    POSITIVE and those are invisible once the code is rearranged to avoid
    them. `self.a, self.b = f()` is ordinary Python; a walk that cannot see
    it makes the lint a reason to write worse code."""
    tree = ast.parse(
        "class C:\n"
        "    def load(self):\n"
        "        self.a, self.b = 1, 2\n"
        "        [self.c] = [3]\n"
        "    def use(self):\n"
        "        return self.a + self.b + self.c\n")
    klass = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
    defined = _class_defined_names(klass)
    assert {"a", "b", "c"} <= defined, sorted(defined)
