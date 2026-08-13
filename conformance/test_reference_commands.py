"""Reference commands are a promise, and the promise had drifted.

SPEC section 2, rule 5: every `source` block names commands an administrator
could run to reproduce the observation. That makes them a CORRECTNESS surface,
not documentation — and they rot silently, because a fact lands and the
reference list does not move. hardware/scsi named lsscsi, by-path and enclosure
while also reading scsi_host/proc_name, udev over the PCI function, ata_link,
sas_phy, sas_device, /sys/block/*/size and VPD page 0x80; hardware/nvme named
three commands while reading the entire PCIe link state and the bridge above
it. Every gap arrived the same way, and nothing could have caught any of them.

WHAT IS ENFORCED HERE IS WEAKER THAN RULE 5, DELIBERATELY. Rule 5's promise is
per observation; this lint is per MODULE — a path named by any of that module's
reference lists passes, even if a sibling collection is the one that reads it.

Collection granularity is achievable and wrong. Shared helpers defeat the
attribution: hardware's _pci_addr_of and _drive_health serve scsi AND nvme, and
agent/nixos.py's readers serve system AND nix, which crosses modules. A
collection-level lint must therefore over-approximate, and its failure mode is
demanding a reference command for a collection that does not read that path —
coercing an author into writing a FALSE promise, which is the exact thing rule 5
exists to prevent. Module granularity under-enforces instead, and
under-enforcement is visible and recoverable where a plausible-looking false
command is not.

The other thing not to do, when this lint is inconvenient: generate the
reference commands from the resolved paths. It would go green for ever and turn
a human promise into the code echoing itself.

The promise has an API half, held at the bottom of this file: app adapters
read no /sys — they GET paths and write control-socket commands, and those
drifted the same way. downloaders built its client rows from session-get and
session-stats while REFERENCE showed only torrent-get; plex fetched
/library/sections and every section's /all count under a list that never
named either. The extractor takes what a module CALLS (fetch-helper path
arguments, httpx verbs on adapter-held clients, socket command words), the
corpus is the RUNNABLE commands only — a source block's method line is a
description, not a command — and the same rule stands: never generate the
commands from the calls.
"""

import ast
import fnmatch
import re

import pytest

from common import (AGENT_DIR, API_REFERENCE_EXEMPTIONS, PATH_REFERENCE_EXEMPTIONS,
                    UNLINTABLE_API_MODULES, UNLINTABLE_READ_MODULES,
                    UNVERIFIED_API_REFERENCE_BUDGET, UNVERIFIED_REFERENCE_BUDGET)

# Calls that reach the filesystem. An explicit reviewed table, not a bare name
# set: matching any callable named `walk` swept up the local walk() helpers
# inside docker's redactor and nix's closure diff and reported their trails as
# paths. Module-local helpers are matched bare; everything else must be dotted.
FILESYSTEM_READS = {
    "_read", "_listdir", "_sys_read", "_sys_list", "_read_pressure",
    "Path",
    "os.listdir", "os.scandir", "os.walk", "os.readlink",
    "os.path.realpath", "os.path.isdir", "os.path.isfile", "os.path.exists",
    "nx.read", "nx.read_json", "nx.realpath", "nx.listdir",
}
# The bodies of the helpers above: `Path(path)` inside _read is the helper
# itself, not a read site, and its argument resolves to nothing useful.
READER_DEFINITIONS = {"_read", "_listdir", "_sys_read", "_sys_list", "_read_pressure",
                      "read", "read_json", "realpath", "listdir"}
# Readers that answer with the NAMES INSIDE a directory rather than with the
# directory. `for ctrl in _listdir(NVME_DEVICES)` binds ctrl to an entry, so it
# must resolve to a wildcard; treating it like the argument produced
# /sys/class/nvme/sys/class/nvme/model, and a lint that fabricates paths would
# fill the exemption table with fiction.
DIRECTORY_LISTERS = {"_listdir", "_sys_list", "os.listdir", "os.scandir",
                     "nx.listdir", "glob", "iterdir"}
# Calls worth following through to their first argument: the answer is a path
# derived from that path. Anything else resolves to a wildcard rather than
# being guessed at.
PATH_TRANSFORMS = {"os.path.dirname", "os.path.realpath", "os.path.abspath",
                   "os.path.join", "str"}
INTERESTING_ROOTS = ("/sys", "/proc", "/dev", "/run", "/etc", "/nix", "/var")
MAX_DEPTH = 6
# A socket is a transport, not a reading. `cat /var/run/docker.sock` reproduces
# nothing; `docker inspect` does, and that is what those adapters name.
def is_transport(path: str) -> bool:
    return "sock" in path.rsplit("/", 1)[-1]
# agent/nixos.py is a shared reader with no source block of its own — the nix
# and system adapters both call it, and their reference lists are where its
# paths have to appear. Checked against the union, because either naming a path
# lets a reader reproduce it.
SHARED_READER_CORPUS = {"nixos": ("nix", "system")}


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def module_constants(tree: ast.AST) -> dict[str, object]:
    """Module-level NAME = "/sys/..." and NAME = ("a", "b") — the latter is
    what makes OVERVIEW_FILES, SW_SUBDIRS and PRESSURE_RESOURCES resolvable
    instead of exempt, and those are three of the modules the audit flagged."""
    constants: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            constants[target.id] = value.value
        elif isinstance(value, ast.JoinedStr):
            # SW = f"{CURRENT_SYSTEM}/sw" — a constant built from a constant.
            # Resolved against what this module has already declared, in file
            # order, which is all these chains ever depend on.
            text = ""
            for part in value.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    text += part.value
                elif (isinstance(part, ast.FormattedValue)
                      and isinstance(part.value, ast.Name)
                      and isinstance(constants.get(part.value.id), str)):
                    text += constants[part.value.id]
                else:
                    text += "*"
            constants[target.id] = text
        elif isinstance(value, (ast.Tuple, ast.List)):
            items = [e.value for e in value.elts
                     if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if items and len(items) == len(value.elts):
                constants[target.id] = items
    return constants


class Resolver:
    """Resolve a read call's path argument to the longest literal prefix it
    can prove, with everything unknown collapsed to `*`."""

    def __init__(self, tree: ast.AST, constants: dict[str, object]):
        self.constants = constants
        # Class-level EXTRA_PATH = "/wanted/cutoff", reached as
        # self.EXTRA_PATH from a method: a ClassDef body carries the same
        # assignment shapes module_constants already reads.
        self.class_constants: dict[str, object] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                self.class_constants.update(module_constants(node))
        # Assignments are SCOPED to their enclosing function, and a function's
        # parameters resolve to a wildcard. Without this, `base` assigned in
        # _nvme_link_facts satisfied the `base` PARAMETER of the shared
        # _host_transport helper, and the lint reported that nvme reads
        # /sys/class/nvme/*/device/host_sas_address — a path that does not
        # exist, on a device class that has no SAS address. Fabricating paths
        # is how an exemption table fills up with fiction.
        self.scope_of: dict[int, int | None] = {}
        self.parameters: dict[int | None, set[str]] = {None: set()}
        for parent in ast.walk(tree):
            enclosing = (id(parent) if isinstance(
                parent, (ast.FunctionDef, ast.AsyncFunctionDef)) else None)
            for child in ast.iter_child_nodes(parent):
                self.scope_of[id(child)] = enclosing if enclosing is not None \
                    else self.scope_of.get(id(parent))
            if enclosing is not None:
                args = parent.args
                self.parameters[enclosing] = {
                    a.arg for a in (args.posonlyargs + args.args + args.kwonlyargs)
                } | {a.arg for a in filter(None, (args.vararg, args.kwarg))}
        # (name, lineno) -> value node, for every assignment anywhere. Resolution
        # picks the NEAREST PRECEDING one, not the last: hardware._scsi_items
        # rebinds `base` three times in one function, and last-write-wins
        # reported /sys/bus/scsi/devices/*/proc_name for a read that is really
        # under /sys/class/scsi_host. A lint that fabricates paths would fill
        # the exemption table with fiction.
        self.assignments: dict[tuple[int | None, str], list[tuple[int, ast.AST]]] = {}

        def record(scope_key, name: str, line: int, value: ast.AST) -> None:
            self.assignments.setdefault((scope_key, name), []).append((line, value))

        for node in ast.walk(tree):
            scope = self.scope_of.get(id(node))
            targets = (node.targets if isinstance(node, ast.Assign)
                       else [node.target] if isinstance(node, ast.AnnAssign) else [])
            for target in targets:
                if isinstance(target, ast.Name):
                    record(scope, target.id, node.lineno, node.value)
            # `for path in OVERVIEW_FILES:` binds the loop variable to each
            # item — but `for ctrl in _listdir(DIR)` binds it to a NAME inside
            # DIR, which is a wildcard, not DIR itself.
            if isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(node.target, ast.Name):
                iterated = node.iter
                if isinstance(iterated, ast.Call) and (
                        dotted(iterated.func) in DIRECTORY_LISTERS
                        or dotted(iterated.func).rsplit(".", 1)[-1] in DIRECTORY_LISTERS):
                    iterated = ast.Constant(value="*")
                record(scope, node.target.id, node.lineno, iterated)
        for entries in self.assignments.values():
            entries.sort()

    def _nearest(self, name: str, before: int, scope: int | None) -> ast.AST | str | None:
        """Innermost scope first, then module level. A parameter of the
        enclosing function is caller-supplied and resolves to a wildcard."""
        for key in (scope, None) if scope is not None else (None,):
            candidates = [(line, node) for line, node in
                          self.assignments.get((key, name), []) if line <= before]
            if candidates:
                return candidates[-1][1]
            if name in self.parameters.get(key, set()):
                return "*"
        return None

    def resolve(self, node: ast.AST, before: int, depth: int = 0) -> list[str]:
        """A list, because a for-target over a tuple of names fans out."""
        if depth > MAX_DEPTH:
            return ["*"]
        if isinstance(node, ast.Constant):
            return [node.value] if isinstance(node.value, str) else ["*"]
        if isinstance(node, ast.JoinedStr):
            out = [""]
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    out = [prefix + part.value for prefix in out]
                else:
                    resolved = self.resolve(part.value, before, depth + 1) \
                        if isinstance(part, ast.FormattedValue) else ["*"]
                    out = [prefix + piece for prefix in out for piece in resolved[:4]]
            return out
        if isinstance(node, ast.Name):
            assigned = self._nearest(node.id, before, self.scope_of.get(id(node)))
            if assigned == "*":
                return ["*"]
            if assigned is not None:
                return self.resolve(assigned, node.lineno, depth + 1)
            value = self.constants.get(node.id)
            if isinstance(value, str):
                return [value]
            if isinstance(value, list):
                return value
            return ["*"]
        if isinstance(node, ast.Attribute):
            # nx.SW, nx.CURRENT_SYSTEM — another module's constant table.
            for module, table in FOREIGN_CONSTANTS.items():
                if dotted(node) == f"{module}.{node.attr}":
                    value = table.get(node.attr)
                    if isinstance(value, str):
                        return [value]
                    if isinstance(value, list):
                        return value
            # self.EXTRA_PATH — a class-level constant of this module.
            if isinstance(node.value, ast.Name) and node.value.id == "self":
                value = self.class_constants.get(node.attr)
                if isinstance(value, str):
                    return [value]
                if isinstance(value, list):
                    return value
            return ["*"]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # "lease4" + "-wipe": a literal concatenation is a literal.
            # A partial half carries its `*` and falls out downstream.
            return [left + right
                    for left in self.resolve(node.left, before, depth + 1)[:4]
                    for right in self.resolve(node.right, before, depth + 1)[:4]]
        if isinstance(node, ast.Call) and node.args:
            name = dotted(node.func)
            if name in DIRECTORY_LISTERS or name.rsplit(".", 1)[-1] in DIRECTORY_LISTERS:
                return ["*"]
            # os.path.dirname(os.path.realpath(base)) and friends: the answer is
            # derived from the inner path, so that path is the best prefix
            # available. Every other call resolves to a wildcard rather than
            # being guessed at — .split("/") used to yield "/".
            if name in PATH_TRANSFORMS or name in FILESYSTEM_READS:
                return self.resolve(node.args[0], before, depth + 1)
        return ["*"]


FOREIGN_CONSTANTS: dict[str, dict[str, object]] = {}


def _load_foreign() -> None:
    """agent/nixos.py's constants, reached as nx.SW / nx.PROFILES from two
    adapters. Loaded once, keyed by the alias those adapters import it under."""
    if FOREIGN_CONSTANTS:
        return
    source = AGENT_DIR / "nixos.py"
    if source.is_file():
        FOREIGN_CONSTANTS["nx"] = module_constants(ast.parse(source.read_text()))


def normalise(path: str) -> str:
    path = re.sub(r"\*+", "*", path)
    path = re.sub(r"/{2,}", "/", path)
    return path.rstrip("/") or "/"


def read_paths(source) -> dict[str, list[int]]:
    """Absolute filesystem paths this module reads -> the lines that read them."""
    _load_foreign()
    tree = ast.parse(source.read_text(), filename=str(source))
    resolver = Resolver(tree, module_constants(tree))
    inside_reader = {
        id(child)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in READER_DEFINITIONS
        for child in ast.walk(node)
    }
    found: dict[str, list[int]] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and node.args):
            continue
        if dotted(node.func) not in FILESYSTEM_READS or id(node) in inside_reader:
            continue
        for candidate in resolver.resolve(node.args[0], node.lineno):
            if not isinstance(candidate, str) or not candidate.startswith(INTERESTING_ROOTS):
                continue
            if is_transport(candidate):
                continue
            found.setdefault(normalise(candidate), []).append(node.lineno)
    return found


# ── the corpus: what this module's reference commands actually name ──────

def _strings_under(node: ast.AST) -> list[str]:
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            out.append(sub.value)
        elif isinstance(sub, ast.JoinedStr):
            out.append("".join(
                part.value if isinstance(part, ast.Constant) and isinstance(part.value, str)
                else "*" for part in sub.values))
    return out


def reference_corpus(source) -> set[str]:
    """Every reference command this module can emit, from all three idioms:
    a *REFERENCE* module constant (including a dict of them, as packages keys
    by manager), and the reference_commands argument of any env.source() call,
    which is how storage's and system's inline lists get in."""
    tree = ast.parse(source.read_text(), filename=str(source))
    commands: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and "REFERENCE" in t.id for t in node.targets):
            commands.update(_strings_under(node.value))
    for node in ast.walk(tree):
        # Every string inside a _source_for / _source builder. storage keeps its
        # commands in a dict of tuples there and hands env.source() a variable,
        # so following only the call's third argument finds a bare Name and
        # comes back with nothing — which would empty the comparison set and
        # pass the module for free.
        if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("_source")):
            commands.update(_strings_under(node))
            continue
        if not (isinstance(node, ast.Call) and dotted(node.func).endswith("source")):
            continue
        argument = (node.args[2] if len(node.args) > 2 else next(
            (kw.value for kw in node.keywords if kw.arg == "reference_commands"), None))
        if argument is not None:
            # A BinOp is system/boot's `[...] + ([...] if _is_nixos() else [])`;
            # _strings_under walks both operands.
            commands.update(_strings_under(argument))
    return commands


BRACE = re.compile(r"\{([^{}]*,[^{}]*)\}")
PLACEHOLDER = re.compile(r"<[^>]+>")


def path_tokens(commands: set[str]) -> set[str]:
    """The absolute paths named by a set of commands, brace-expanded and with
    <addr>-style placeholders normalised to a wildcard."""
    tokens: set[str] = set()
    for command in commands:
        for word in command.replace("|", " ").split():
            word = PLACEHOLDER.sub("*", word).rstrip(",;)")
            if not word.startswith("/"):
                continue
            expanded = [word]
            while any(BRACE.search(item) for item in expanded):
                nxt = []
                for item in expanded:
                    match = BRACE.search(item)
                    if not match:
                        nxt.append(item)
                        continue
                    nxt.extend(item[:match.start()] + option + item[match.end():]
                               for option in match.group(1).split(","))
                expanded = nxt
            tokens.update(normalise(item) for item in expanded)
    return tokens


def names(path: str, token: str) -> bool:
    """True when a reference command's path token accounts for a read path.

    Segment-wise, and a prefix in EITHER direction. `cat /sys/class/x/y*/z`
    names a listdir of /sys/class/x — an administrator running it has evidently
    found the directory — and `ls /sys/class/enclosure` names everything under
    it. Prefix containment is deliberately loose: requiring every attribute to
    be named individually would explode the lists into hundreds of entries
    nobody would maintain, and unmaintained lists are the thing being fixed.
    """
    left, right = path.strip("/").split("/"), token.strip("/").split("/")
    # strict=False is the semantics, not an oversight: the shorter side being
    # a prefix of the longer is exactly the containment described above.
    for mine, theirs in zip(left, right, strict=False):
        if not (fnmatch.fnmatch(mine, theirs) or fnmatch.fnmatch(theirs, mine)):
            return False
    return True


def adapter_sources():
    directory = AGENT_DIR / "adapters"
    extra = [AGENT_DIR / "nixos.py"] if (AGENT_DIR / "nixos.py").is_file() else []
    return sorted(directory.glob("*.py")) + extra


MODULES = [pytest.param(s, id=s.stem) for s in adapter_sources()]
_BY_STEM = {s.stem: s for s in adapter_sources()}


def corpus_for(stem: str) -> set[str]:
    commands = reference_corpus(_BY_STEM[stem])
    for lender in SHARED_READER_CORPUS.get(stem, ()):
        if lender in _BY_STEM:
            commands |= reference_corpus(_BY_STEM[lender])
    return commands


UNNAMED: dict[str, dict[str, list[int]]] = {}
for _source in adapter_sources():
    _tokens = path_tokens(corpus_for(_source.stem))
    UNNAMED[_source.stem] = {
        path: lines for path, lines in read_paths(_source).items()
        if not any(names(path, token) for token in _tokens)
    }


def exemption_for(module: str, path: str) -> str | None:
    for key, reason in PATH_REFERENCE_EXEMPTIONS.items():
        prefix_module, _, prefix = key.partition(":")
        if prefix_module == module and (path == prefix or path.startswith(prefix + "/")):
            return reason
    return None


# ── the obligation ───────────────────────────────────────────────────────

@pytest.mark.parametrize("source", MODULES)
def test_every_path_read_is_named_by_a_reference_command(source):
    """The promise, module-scoped. A path this module reads that none of its
    reference commands names is a reader who cannot reproduce the observation."""
    if source.stem in UNLINTABLE_READ_MODULES:
        pytest.skip(UNLINTABLE_READ_MODULES[source.stem])
    unaccounted = {path: lines for path, lines in UNNAMED[source.stem].items()
                   if exemption_for(source.stem, path) is None}
    assert not unaccounted, (
        f"adapters/{source.name} reads paths no reference command names:\n  "
        + "\n  ".join(f"{path}  (line{'s' if len(lines) > 1 else ''} "
                      f"{', '.join(map(str, sorted(set(lines))))})"
                      for path, lines in sorted(unaccounted.items()))
        + "\nName them in this module's reference commands (SPEC rule 5: an "
          "administrator must be able to reproduce the observation), or add a "
          "PATH_REFERENCE_EXEMPTIONS entry if a named TOOL reproduces them."
    )


# ── anti-vacuity: this lint has more ways to pass wrongly than any other ──

def test_the_matcher_rejects_a_path_no_command_names():
    """The single most important guard. A matcher that drifts permissive makes
    every other assertion in this file green for ever."""
    assert names("/sys/class/nvme", "/sys/class/nvme/*/firmware_rev")
    assert names("/sys/class/enclosure/x/y/slot", "/sys/class/enclosure")
    assert names("/sys/class/ata_link/link1/sata_spd", "/sys/class/ata_link/link*/sata_spd")
    assert not names("/proc/meminfo", "/proc/loadavg")
    assert not names("/sys/class/scsi_host/host0/state", "/sys/class/scsi_host/host*/proc_name")
    assert not names("/sys/fs/cgroup", "/sys/class/nvme")
    assert not names("/etc/machine-id", "/proc")


@pytest.mark.parametrize("module,expected", [
    ("hardware", {"/sys/class/nvme", "/sys/class/scsi_host"}),
    ("system", {"/proc/loadavg"}),
    ("units", {"/sys/fs/cgroup"}),
    ("storage", {"/sys/block"}),
])
def test_the_resolver_still_finds_the_paths_we_know_about(module, expected):
    """Canaries. If the resolver quietly stops resolving, every module reads
    nothing and the obligation above passes over an empty set."""
    found = read_paths(AGENT_DIR / "adapters" / f"{module}.py")
    missing = {path for path in expected
               if not any(seen == path or seen.startswith(path + "/") for seen in found)}
    assert not missing, f"{module}: resolver lost {missing} (found {sorted(found)[:12]})"


def reads_the_filesystem(source) -> bool:
    """AST, not text: `Path(` appears in a type annotation and an import."""
    tree = ast.parse(source.read_text(), filename=str(source))
    inside_reader = {
        id(child)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in READER_DEFINITIONS
        for child in ast.walk(node)
    }
    return any(isinstance(node, ast.Call) and node.args
               and dotted(node.func) in FILESYSTEM_READS
               and id(node) not in inside_reader
               for node in ast.walk(tree))


@pytest.mark.parametrize("source", MODULES)
def test_a_module_that_reads_the_filesystem_resolves_at_least_one_path(source):
    """The analogue of the subprocess lint's rule that a file it cannot parse
    FAILS rather than passes: unresolvable reads must not be a way out.

    A module reaching only a socket satisfies this — the transport is a real
    resolved path, it just names no observation.
    """
    if not reads_the_filesystem(source) or source.stem in UNLINTABLE_READ_MODULES:
        return
    tree = ast.parse(source.read_text())
    resolver = Resolver(tree, module_constants(tree))
    anything = any(
        isinstance(candidate, str) and candidate.startswith(INTERESTING_ROOTS)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and node.args and dotted(node.func) in FILESYSTEM_READS
        for candidate in resolver.resolve(node.args[0], node.lineno))
    assert anything, (
        f"{source.name} calls a filesystem reader but no absolute path could "
        "be resolved from it — paths built so dynamically that they cannot be "
        "linted need an UNLINTABLE_READ_MODULES entry, in review"
    )


@pytest.mark.parametrize("source", MODULES)
def test_a_module_with_resolvable_reads_has_a_reference_corpus(source):
    """Corpus extraction breaking would empty the comparison set and pass
    everything, which is the same failure as a permissive matcher."""
    if not read_paths(source) or source.stem in UNLINTABLE_READ_MODULES:
        return
    assert corpus_for(source.stem), (
        f"{source.name} reads paths but no reference command could be "
        "extracted — the *_REFERENCE constant or env.source() call moved"
    )


def test_the_reference_lint_is_armed():
    assert len(MODULES) >= 10, f"only {len(MODULES)} adapter sources found"
    assert any(UNNAMED.values()) or PATH_REFERENCE_EXEMPTIONS, (
        "no module reads an unnamed path and no exemptions exist — the "
        "comparison is almost certainly not running"
    )


# ── the ratchet ──────────────────────────────────────────────────────────

def test_the_unverified_backlog_only_shrinks():
    """Every path family that has no verified reference command yet is carried
    as a marked exemption, and the count is a number a commit can only move
    down. Without this the table is a suppression file wearing a debt-register
    costume, and the lint's arrival would make things worse by looking
    enforced."""
    unverified = [key for key, reason in PATH_REFERENCE_EXEMPTIONS.items()
                  if reason.startswith("TODO")]
    assert len(unverified) <= UNVERIFIED_REFERENCE_BUDGET, (
        f"{len(unverified)} unverified exemptions against a budget of "
        f"{UNVERIFIED_REFERENCE_BUDGET}: {sorted(unverified)}"
    )
    assert UNVERIFIED_REFERENCE_BUDGET == len(unverified), (
        f"the budget is {UNVERIFIED_REFERENCE_BUDGET} but only {len(unverified)} "
        "entries remain — lower the budget in common.py so it keeps ratcheting"
    )


@pytest.mark.parametrize("key", sorted(PATH_REFERENCE_EXEMPTIONS))
def test_an_exemption_still_matches_something_the_module_reads(key):
    """A debt register, not a dumping ground: an exemption for a path nobody
    reads any more, or one a reference command has since started naming, must
    come off or the table stops meaning what it says."""
    module, _, prefix = key.partition(":")
    assert module in UNNAMED, f"{key} names no adapter"
    covered = [path for path in UNNAMED[module]
               if path == prefix or path.startswith(prefix + "/")]
    assert covered, (
        f"{key} exempts nothing: either the read is gone, or a reference "
        "command now names it and the exemption should be deleted"
    )


# ── the API analogue: what a module CALLS, held to the same promise ──────

# Calls that reach an API. An explicit reviewed table, the FILESYSTEM_READS
# reasoning: matching any callable named `get` would sweep every dict lookup
# in every adapter. Matched as self.<name> or bare, nothing dotted deeper.
API_FETCHERS = {"_get", "_get_list", "_plex_get", "_sab", "_rpc", "_command"}
# httpx verbs on any one- or two-dotted receiver in a module that imports
# httpx: self._seerr.get, a locally-aliased client.get, an AsyncClient
# constructed in a with-block — the transports inside the helpers included,
# so servarr's in-helper client.get yields a benign /api/* surface its
# REFERENCE tokens already account for. Only URL-shaped resolutions count —
# a dict's .get is the same spelling, so an argument with no literal path
# portion is discarded rather than guessed at; that guard, not the
# receiver's spelling, is what screens out nix's self._RULES.get(collection).
CLIENT_VERBS = {"get", "post"}
# A command word is unbound's `status`, kea's `version-get`, sabnzbd's
# `queue`: one token, fully literal. A partial resolution ("stat-*") cannot
# be honestly matched and is dropped — and dropping is SILENT for any module
# that already extracts another surface, because the must-extract test below
# only fires on total extraction failure. So the extractor resolves every
# literal shape first (keyword-argument paths, literal `+` concatenations,
# self.CLASS_CONST), each pinned below, and drops only genuine partials.
COMMAND_SHAPE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _surface_path(text: str) -> str | None:
    """The URL path inside a resolved argument or a reference-command word:
    `/api/overview`, `*/api` (an f-string's unresolved host half), or
    `http://localhost/_ping`. The query string is transport dressing on both
    sides of the comparison and is cut; a path that is nothing but
    wildcards proves no name and resolves to nothing."""
    if "://" in text:
        text = text.split("://", 1)[1]
        slash = text.find("/")
        text = text[slash:] if slash >= 0 else ""
    elif text.startswith("*") and "/" in text:
        text = text[text.index("/"):]
    if not text.startswith("/"):
        return None
    path = normalise(text.split("?", 1)[0])
    if path != "/" and not path.strip("/*"):
        return None
    return path


def _imports_httpx(tree: ast.AST) -> bool:
    """Both import forms, mirroring the subprocess lint's uses_subprocess:
    `from httpx import AsyncClient` is the same transport as `import httpx`,
    and matching only ast.Import let a module escape the whole API lint by
    import style."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
                alias.name.split(".")[0] == "httpx" for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "httpx":
            return True
    return False


def api_surface(source) -> dict[str, list[int]]:
    """HTTP paths and socket commands this module calls -> the lines that
    call them. Paths keep their leading slash and command words have none —
    the comparison below dispatches on exactly that."""
    tree = ast.parse(source.read_text(), filename=str(source))
    resolver = Resolver(tree, module_constants(tree))
    http = _imports_httpx(tree)
    found: dict[str, list[int]] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and (node.args or node.keywords)):
            continue
        name = dotted(node.func)
        if name.removeprefix("self.") in API_FETCHERS:
            # Every positional AND keyword argument, because servarr's path
            # rides second (self._get(spec, "/health")) and the refactor to
            # path="/health" must not drop the obligation: the spec, params
            # and dict arguments resolve to a wildcard and fall out on
            # their own.
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                for candidate in resolver.resolve(arg, node.lineno):
                    if not isinstance(candidate, str) or candidate == "*":
                        continue
                    path = _surface_path(candidate)
                    if path:
                        found.setdefault(path, []).append(node.lineno)
                    elif COMMAND_SHAPE.match(candidate):
                        found.setdefault(candidate, []).append(node.lineno)
        elif (http and node.args and 1 <= name.count(".") <= 2
                and name.rsplit(".", 1)[-1] in CLIENT_VERBS):
            for candidate in resolver.resolve(node.args[0], node.lineno):
                if isinstance(candidate, str):
                    path = _surface_path(candidate)
                    if path:
                        found.setdefault(path, []).append(node.lineno)
    return found


def speaks_an_api(source) -> bool:
    """AST, not text: `httpx` in a docstring must not conscript a module.
    Importing httpx or opening a unix control socket is what makes the API
    obligation apply; vms speaks libvirt through a binding, which is a
    different surface and the transport rule's business."""
    tree = ast.parse(source.read_text(), filename=str(source))
    return _imports_httpx(tree) or any(
        isinstance(node, ast.Call)
        and dotted(node.func) in ("asyncio.open_unix_connection", "open_unix_connection")
        for node in ast.walk(tree))


def api_reference_corpus(source) -> set[str]:
    """The RUNNABLE corpus: *REFERENCE* constants and env.source()'s
    reference_commands argument. Deliberately narrower than
    reference_corpus: that walk also sweeps every string inside a _source
    builder, and an env.source(method=...) line is a description, not a
    command an administrator could run — downloaders' method line said
    "session-get/session-stats" for as long as REFERENCE showed only
    torrent-get, and a corpus that counted it would have blessed the exact
    drift this half of the lint exists to catch."""
    tree = ast.parse(source.read_text(), filename=str(source))
    commands: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and "REFERENCE" in t.id for t in node.targets):
            commands.update(_strings_under(node.value))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and dotted(node.func).endswith("source")):
            continue
        argument = (node.args[2] if len(node.args) > 2 else next(
            (kw.value for kw in node.keywords if kw.arg == "reference_commands"), None))
        if argument is not None:
            commands.update(_strings_under(argument))
    return commands


def api_path_tokens(commands: set[str]) -> set[str]:
    """The URL paths named by a set of reference commands, with <token>
    placeholders collapsed to a wildcard. `<url>/api/overview` and
    `http://localhost/_ping` both carry one; a word with no slash (a socket
    command, a flag) carries none and is the word matcher's business."""
    tokens: set[str] = set()
    for command in commands:
        for word in command.replace("|", " ").split():
            path = _surface_path(
                PLACEHOLDER.sub("*", word).strip("'\"").rstrip(",;)"))
            if path:
                tokens.add(path)
    return tokens


COMMAND_SITES = re.compile(
    r'"(?:command|method)"\s*:\s*"([A-Za-z0-9_.-]+)"|[?&]mode=([A-Za-z0-9_.-]+)')


def command_named(command: str, corpus: set[str]) -> bool:
    """Word-boundary containment where '-' binds: version-get must not ride
    on statistic-get-all's spelling. An entry that declares its command — a
    "command"/"method" JSON value or a mode= query parameter — is matched at
    those sites ONLY: torrent-get's fields array is data, and "status" inside
    it must not bless a future _sab("status"). An entry with no such site
    (unbound-control ... status) is searched whole."""
    pattern = re.compile(rf"(?<![\w-]){re.escape(command)}(?![\w-])")
    for entry in corpus:
        sites = [g for m in COMMAND_SITES.finditer(entry) for g in m.groups() if g]
        if sites:
            if any(pattern.fullmatch(site) for site in sites):
                return True
        elif pattern.search(entry):
            return True
    return False


def names_api(path: str, token: str) -> bool:
    """True when a reference command's path token accounts for a called
    path. The same segment-wise, prefix-in-either-direction containment as
    names(), plus an alignment offset INTO THE TOKEN only: servarr's fetch
    helper interposes /api/{family} between the URL receipt and the literal
    the call site holds, so `<url>/api/v3/system/status` must account for a
    call to "/system/status". The offset never runs the other way — a token
    the CALL outgrows at the head (`<url>/health` against a call to
    /api/v3/health) is a curl that 404s, the false promise rule 5 exists to
    prevent. And the offset is ANCHORED to that interposition — 0, or 2 only
    when the token starts with /api — because any-offset alignment blessed
    siblings: a call to "/status" must not ride on /api/v3/queue/status's
    tail, a token whose curl does not reproduce /api/v3/status."""
    left = path.strip("/").split("/")
    segments = token.strip("/").split("/")
    offsets = [0]
    if len(segments) > 2 and segments[0] == "api":
        offsets.append(2)
    for offset in offsets:
        if all(fnmatch.fnmatch(mine, theirs) or fnmatch.fnmatch(theirs, mine)
               for mine, theirs in zip(left, segments[offset:], strict=False)):
            return True
    return False


def api_surface_named(surface: str, tokens: set[str], corpus: set[str]) -> bool:
    if surface.startswith("/"):
        return any(names_api(surface, token) for token in tokens)
    return command_named(surface, corpus)


API_SURFACES: dict[str, dict[str, list[int]]] = {}
API_UNNAMED: dict[str, dict[str, list[int]]] = {}
for _source in adapter_sources():
    _commands = api_reference_corpus(_source)
    _api_tokens = api_path_tokens(_commands)
    API_SURFACES[_source.stem] = api_surface(_source)
    API_UNNAMED[_source.stem] = {
        surface: lines for surface, lines in API_SURFACES[_source.stem].items()
        if not api_surface_named(surface, _api_tokens, _commands)
    }


def api_exemption_for(module: str, surface: str) -> str | None:
    for key, reason in API_REFERENCE_EXEMPTIONS.items():
        prefix_module, _, prefix = key.partition(":")
        if prefix_module != module:
            continue
        if surface == prefix or (prefix.startswith("/")
                                 and surface.startswith(prefix + "/")):
            return reason
    return None


# ── the API obligation ───────────────────────────────────────────────────

@pytest.mark.parametrize("source", MODULES)
def test_every_api_call_is_named_by_a_reference_command(source):
    """Rule 5's other half, module-scoped like the filesystem half. A path
    or socket command this module calls that none of its reference commands
    names is a reader who cannot reproduce the observation."""
    if source.stem in UNLINTABLE_API_MODULES:
        pytest.skip(UNLINTABLE_API_MODULES[source.stem])
    unaccounted = {surface: lines
                   for surface, lines in API_UNNAMED[source.stem].items()
                   if api_exemption_for(source.stem, surface) is None}
    assert not unaccounted, (
        f"adapters/{source.name} calls API surfaces no reference command names:\n  "
        + "\n  ".join(f"{surface}  (line{'s' if len(lines) > 1 else ''} "
                      f"{', '.join(map(str, sorted(set(lines))))})"
                      for surface, lines in sorted(unaccounted.items()))
        + "\nName them in this module's reference commands (SPEC rule 5: an "
          "administrator must be able to reproduce the observation), or add "
          "an API_REFERENCE_EXEMPTIONS entry if a named TOOL reproduces them."
    )


# ── anti-vacuity, API half: the same ways to pass wrongly exist here ─────

def test_the_api_matcher_rejects_a_surface_no_command_names():
    """The permissive-matcher guard, again: every assertion below is a real
    shape from the adapters, not a synthetic one."""
    assert names_api("/api/system/status", "/api/system/status")
    assert names_api("/system/status", "/api/v3/system/status")
    assert names_api("/library/sections/*/all", "/library/sections")
    assert names_api("/", "/")
    assert not names_api("/", "/api/v1/request")
    assert not names_api("/history", "/api/v3/health")
    assert not names_api("/api/version", "/api/overview")
    assert not names_api("/api/v3/health", "/health")
    # The anchored offset: a sibling endpoint must not ride a token's tail.
    # /api/v3/queue's curl does not reproduce a call to /api/v3/status.
    assert not names_api("/status", "/api/v3/queue/status")
    assert command_named(
        "queue", {"curl '<url>/api?mode=queue&output=json&apikey=<key>'"})
    assert command_named(
        "stats_noreset",
        {"unbound-control -c /etc/unbound/unbound.conf stats_noreset"})
    assert not command_named(
        "version-get",
        {"echo '{\"command\": \"statistic-get-all\"}' | socat - UNIX-CONNECT:<socket>"})
    assert not command_named(
        "lease4-get",
        {"echo '{\"command\": \"lease4-get-all\"}' | socat - UNIX-CONNECT:<socket>"})
    assert not command_named("get", {"torrent-get"})
    # A JSON data token is not a command site: "status" in torrent-get's
    # fields array must not bless a future _sab("status").
    assert not command_named(
        "status",
        {'curl -X POST <url>/transmission/rpc -d \'{"method": "torrent-get",'
         ' "arguments": {"fields": ["hashString", "name", "status"]}}\''})


def test_the_token_extractor_reads_urls_the_way_commands_write_them():
    tokens = api_path_tokens({
        "curl -H 'X-Plex-Token: <token>' -H 'Accept: application/json' <url>/",
        "curl -H 'X-Api-Key: <key>' '<url>/api/v1/request?take=100'",
        "curl --unix-socket /var/run/docker.sock http://localhost/_ping",
        "echo '{\"command\": \"status-get\"}' | socat - UNIX-CONNECT:<socket>",
    })
    assert "/" in tokens
    assert "/api/v1/request" in tokens
    assert "/_ping" in tokens
    # A socket command is not a path; letting one through as a token would
    # hand the path matcher a job the word matcher owns.
    assert not any("status-get" in token for token in tokens)


@pytest.mark.parametrize("module,expected", [
    ("plex", {"/", "/status/sessions", "/library/sections",
              "/library/sections/*/all", "/api/v1/request"}),
    ("downloaders", {"session-get", "session-stats", "torrent-get",
                     "queue", "fullstatus", "/transmission/rpc"}),
    ("kea", {"version-get", "status-get", "statistic-get-all", "config-get"}),
    ("unbound", {"status", "stats_noreset"}),
    ("traefik", {"/api/overview", "/api/version", "/api/http/routers"}),
])
def test_the_api_extractor_still_finds_the_calls_we_know_about(module, expected):
    """Canaries. If the extractor quietly stops extracting, every module
    calls nothing and the obligation above passes over an empty set."""
    found = api_surface(AGENT_DIR / "adapters" / f"{module}.py")
    missing = expected - set(found)
    assert not missing, (
        f"{module}: extractor lost {sorted(missing)} (found {sorted(found)[:12]})")


def test_the_api_gate_sees_both_import_spellings(tmp_path):
    """`from httpx import AsyncClient` is the same transport as `import
    httpx`, and `from asyncio import open_unix_connection` the same socket
    opener — a module must not escape conscription by import style. The
    subprocess lint's uses_subprocess handles both forms; this gate
    follows it."""
    fromstyle = tmp_path / "fromstyle.py"
    fromstyle.write_text(
        "from httpx import AsyncClient\n\n\n"
        "async def probe(url):\n"
        "    async with AsyncClient() as client:\n"
        "        await client.get(url)\n")
    assert _imports_httpx(ast.parse(fromstyle.read_text()))
    assert speaks_an_api(fromstyle)
    socketstyle = tmp_path / "socketstyle.py"
    socketstyle.write_text(
        "from asyncio import open_unix_connection\n\n\n"
        "async def probe(path):\n"
        "    return await open_unix_connection(path)\n")
    assert speaks_an_api(socketstyle)


def test_the_extractor_sees_a_locally_aliased_client(tmp_path):
    """Only the self.<attr>.<verb> spelling was matched once: a local alias
    (client = self._clients[...]; client.get) or a client constructed in a
    with-block was invisible, and an endpoint fetched that way never had to
    be named. Any one- or two-dotted receiver in an httpx-importing module
    counts now — the URL-shape guard is what keeps dict .get out."""
    module = tmp_path / "aliased.py"
    module.write_text(
        "import httpx\n\n\n"
        "class Probe:\n"
        "    async def collect(self, spec):\n"
        "        client = self._clients[spec['name']]\n"
        "        await client.get('http://unit:8989/api/v3/update')\n"
        "        async with httpx.AsyncClient() as c:\n"
        "            await c.get('http://unit:9696/api/v1/tag')\n")
    found = api_surface(module)
    assert "/api/v3/update" in found
    assert "/api/v1/tag" in found


def test_the_extractor_resolves_the_literal_argument_shapes(tmp_path):
    """Keyword-argument paths, literal concatenations and class-level
    constants are fully literal shapes, and dropping one is silent for any
    module that extracts anything else — so each is pinned."""
    module = tmp_path / "shapes.py"
    module.write_text(
        "import httpx\n\n\n"
        "class Probe:\n"
        "    EXTRA_PATH = '/wanted/cutoff'\n\n"
        "    async def collect(self, spec):\n"
        "        await self._get(spec, path='/wanted/missing')\n"
        "        await self._command('lease4' + '-wipe')\n"
        "        await self._get(spec, self.EXTRA_PATH)\n")
    found = api_surface(module)
    assert "/wanted/missing" in found
    assert "lease4-wipe" in found
    assert "/wanted/cutoff" in found


def test_a_method_description_is_not_a_reference_command():
    """downloaders states 'session-get/session-stats + mode=queue' as its
    clients method line. The runnable corpus must not include it, or every
    future gap could be closed by describing the call instead of naming a
    command that reproduces it."""
    corpus = api_reference_corpus(_BY_STEM["downloaders"])
    assert corpus, "downloaders lost its REFERENCE constant"
    assert not any("session-get/session-stats" in entry for entry in corpus)


@pytest.mark.parametrize("source", MODULES)
def test_a_module_that_speaks_an_api_extracts_at_least_one_surface(source):
    """The unparseable-must-fail posture, API half: a module that imports
    httpx or opens a control socket and yields nothing to the extractor is
    not clean, it is invisible — which is how the next drift arrives.
    Dynamism that genuinely defeats extraction needs an
    UNLINTABLE_API_MODULES entry, in review."""
    if not speaks_an_api(source) or source.stem in UNLINTABLE_API_MODULES:
        return
    assert API_SURFACES[source.stem], (
        f"{source.name} speaks an API but no path or command could be "
        "extracted from it — calls built so dynamically that they cannot "
        "be linted need an UNLINTABLE_API_MODULES entry, in review"
    )


@pytest.mark.parametrize("source", MODULES)
def test_a_module_with_api_calls_has_an_api_reference_corpus(source):
    """Corpus extraction breaking would empty the comparison set and pass
    everything — the permissive-matcher failure wearing different clothes."""
    if not API_SURFACES.get(source.stem) or source.stem in UNLINTABLE_API_MODULES:
        return
    assert api_reference_corpus(source), (
        f"{source.name} calls an API but no reference command could be "
        "extracted — the *_REFERENCE constant or env.source() call moved"
    )


def test_the_api_reference_lint_is_armed():
    speakers = [s for s in adapter_sources() if speaks_an_api(s)]
    assert len(speakers) >= 8, (
        f"only {len(speakers)} API-speaking adapters found — the detector "
        "has gone blind, not the estate quiet")
    total = sum(len(API_SURFACES[s.stem]) for s in speakers)
    assert total >= 24, (
        f"only {total} API surfaces extracted across the fleet — the "
        "comparison is almost certainly not running")


# ── the API ratchet ──────────────────────────────────────────────────────

def test_the_unverified_api_backlog_only_shrinks():
    """Same register discipline as the filesystem half, and the budget is
    zero because the lint lands with its gaps closed, not suppressed."""
    unverified = [key for key, reason in API_REFERENCE_EXEMPTIONS.items()
                  if reason.startswith("TODO")]
    assert len(unverified) <= UNVERIFIED_API_REFERENCE_BUDGET, (
        f"{len(unverified)} unverified API exemptions against a budget of "
        f"{UNVERIFIED_API_REFERENCE_BUDGET}: {sorted(unverified)}"
    )
    assert UNVERIFIED_API_REFERENCE_BUDGET == len(unverified), (
        f"the budget is {UNVERIFIED_API_REFERENCE_BUDGET} but only "
        f"{len(unverified)} entries remain — lower the budget in common.py "
        "so it keeps ratcheting"
    )


@pytest.mark.parametrize("key", sorted(API_REFERENCE_EXEMPTIONS))
def test_an_api_exemption_still_matches_something_the_module_calls(key):
    """A debt register, not a dumping ground, same as the path table."""
    module, _, prefix = key.partition(":")
    assert module in API_UNNAMED, f"{key} names no adapter"
    covered = [surface for surface in API_UNNAMED[module]
               if surface == prefix or (prefix.startswith("/")
                                        and surface.startswith(prefix + "/"))]
    assert covered, (
        f"{key} exempts nothing: either the call is gone, or a reference "
        "command now names it and the exemption should be deleted"
    )
