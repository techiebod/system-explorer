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
"""

import ast
import fnmatch
import re

import pytest

from common import (AGENT_DIR, PATH_REFERENCE_EXEMPTIONS, UNLINTABLE_READ_MODULES,
                    UNVERIFIED_REFERENCE_BUDGET)

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
            return ["*"]
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
