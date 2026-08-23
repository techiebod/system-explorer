"""The staged hub must import, or the lab guest cannot start.

PLAN's standing rule 3 makes the lab guest the whole world until gate 5,
and `harness/estate/lab-up.sh` is the one vehicle that runs the rewrite
hub on one. It staged thirteen modules BY NAME and rewrote exactly one
parent import with a `sed` — both hand-kept lists, so the day the hub
grew a module or an import the guest stopped starting.

It did. `from ..views import load_views` landed in `hub/http.py` on
2026-08-23 and the staged package raised "attempted relative import
beyond top-level package" before binding anything. That is a deploy-time
crash rather than a missing route: `systemctl` reports a unit failing,
which is a different debugging session from the one anybody reading the
record would expect. Nothing in the hub could be seen running at all,
while every test passed.

This test performs the staging the way `lab-up.sh` does and imports the
result. It is deliberately a REPRODUCTION rather than an assertion about
the script's text: a guard that checked the copy list would be the same
hand-kept list a third time.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "src" / "system_explorer"
LAB_UP = REPO / "harness" / "estate" / "lab-up.sh"

#: Modules a guest cannot import because they need dependencies it does
#: not have. Each is named with its reason: a module excluded silently is
#: indistinguishable from one nobody noticed.
GUEST_EXCLUDED = {
    "server": "the SHIPPING hub, which needs FastAPI; the guest runs the "
              "rewrite and never imports it",
}

#: Staged, and not importable without an optional dependency. Distinct
#: from an exclusion: the module IS on the guest, and a deployment that
#: configures a broker uses it.
GUEST_OPTIONAL = {
    "mqtt": "optional broker support, imported only where a broker is "
            "configured",
}


def stage(into: Path) -> Path:
    """The staging lab-up.sh performs, as a function."""
    package = into / "sehub"
    (package / "surface").mkdir(parents=True)
    for module in sorted((SOURCE / "hub").glob("*.py")):
        shutil.copy(module, package / module.name)
    for name in ("__init__.py", "render.py"):
        shutil.copy(SOURCE / "surface" / name, package / "surface" / name)
    shutil.copy(SOURCE / "surface" / "tokens.css", package / "surface")
    for name in ("views.py", "text.py", "paths.py"):
        if (SOURCE / name).exists():
            shutil.copy(SOURCE / name, package / name)
    for name in GUEST_EXCLUDED:
        (package / f"{name}.py").unlink(missing_ok=True)
    (package / "__init__.py").write_text('"""staged"""\n')
    for module in sorted(package.glob("*.py")):
        module.write_text(re.sub(r"^from \.\.([a-z_]+) import ",
                                 r"from .\1 import ",
                                 module.read_text(), flags=re.MULTILINE))
    return package


def test_the_staged_hub_imports(tmp_path) -> None:
    """Every staged module, imported. The one that broke the guest was
    `http`, and it broke on an import line rather than at any call."""
    package = stage(tmp_path)
    sys.path.insert(0, str(tmp_path))
    try:
        failures = {}
        imported = 0
        for module in sorted(package.glob("*.py")):
            if module.stem in {"__init__"} | set(GUEST_OPTIONAL):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"sehub.{module.stem}", module)
                loaded = importlib.util.module_from_spec(spec)
                sys.modules[f"sehub.{module.stem}"] = loaded
                spec.loader.exec_module(loaded)
                imported += 1
            except Exception as exc:  # noqa: BLE001
                failures[module.stem] = f"{type(exc).__name__}: {exc}"
        assert imported >= 10, (
            f"only {imported} modules imported; the staging has stopped "
            f"copying the package")
        assert not failures, (
            f"the staged hub does not import, so the lab guest cannot "
            f"start: {failures}")
    finally:
        sys.path.remove(str(tmp_path))
        for name in list(sys.modules):
            if name.startswith("sehub"):
                del sys.modules[name]


def test_no_parent_import_survives_the_rewrite(tmp_path) -> None:
    """A `from ..x import` left in a flat package is the exact failure
    that broke the guest, and it fails at import rather than at use — so
    a module that merely LOADED would still not prove it."""
    package = stage(tmp_path)
    survivors = {}
    for module in sorted(package.glob("*.py")):
        remaining = re.findall(r"^from \.\.\S*", module.read_text(),
                               flags=re.MULTILINE)
        if remaining:
            survivors[module.name] = remaining
    assert not survivors, (
        f"parent imports the flattening did not reach: {survivors}")


def test_every_excluded_module_is_excluded_on_purpose() -> None:
    """An exclusion list is only better than an inclusion list while each
    entry carries a reason a reader can check. A module dropped from the
    staging without one is indistinguishable from one nobody noticed."""
    script = LAB_UP.read_text()
    for name, reason in GUEST_EXCLUDED.items():
        assert f"rm -f \"${{STAGE}}/sehub/{name}.py\"" in script, (
            f"{name} is excluded here and not by the staging")
        assert len(reason) > 40, f"{name}: state why"
    removed = set(re.findall(r'rm -f "\$\{STAGE\}/sehub/(\w+)\.py"', script))
    assert removed == set(GUEST_EXCLUDED), (
        f"the staging removes {sorted(removed)}; this test knows about "
        f"{sorted(GUEST_EXCLUDED)} — a silent exclusion is the defect")


def test_the_staging_script_copies_the_package_rather_than_a_list() -> None:
    """The defect underneath the crash: a hand-kept list of a package's
    own modules is the guard-that-checks-a-subset shape in a shell
    script, and it goes stale in the direction that breaks the guest."""
    script = LAB_UP.read_text()
    assert "src/system_explorer/hub/*.py" in script, (
        "lab-up.sh must stage the whole hub package; a named list stops "
        "being true the day the hub grows a module")
    assert re.search(r"sed .*from \\\.\\\.\(\[a-z_\]\+\)", script) or \
        "from \\.\\.([a-z_]+) import" in script, (
        "the parent-import rewrite must be generic; rewriting one named "
        "import stops being true the day another arrives")


def test_every_sibling_module_the_hub_imports_is_staged() -> None:
    """Derived from the CODE, not from a list — and not from this file's
    own reproduction of the staging either.

    `stage()` above is a second copy of what lab-up.sh does, so it can
    drift from the script in exactly the direction that hides a defect:
    planting the removal of `views.py` from lab-up.sh on 2026-08-23 left
    every other test here green, because the reproduction went on copying
    it. This test reads the hub's real parent imports and requires the
    SCRIPT to name each one, so the thing being checked is the script.
    """
    wanted = set()
    for module in sorted((SOURCE / "hub").glob("*.py")):
        if module.stem in GUEST_EXCLUDED:
            continue
        wanted |= set(re.findall(r"^from \.\.([a-z_]+) import",
                                 module.read_text(), flags=re.MULTILINE))
    # `surface` is a package and is staged as one; the rest are modules.
    modules = sorted(wanted - {"surface"})
    assert modules, (
        "the hub imports no sibling modules at all, which would make this "
        "guard pass over nothing — check the extraction")
    script = LAB_UP.read_text()
    unstaged = [name for name in modules if f"{name}.py" not in script
                and f"{{{name}," not in script.replace(" ", "")
                and f",{name}," not in script.replace(" ", "")
                and f",{name}}}" not in script.replace(" ", "")]
    assert not unstaged, (
        f"the hub imports these from the parent package and lab-up.sh does "
        f"not stage them: {unstaged}. On a flat guest package that is "
        f"'attempted relative import beyond top-level package' at start-up, "
        f"which is a failing unit rather than a missing route.")
    if "surface" in wanted:
        assert "surface/{__init__,render}.py" in script, (
            "the hub imports ..surface and the staging must carry it")


def test_the_guest_serving_script_only_imports_what_is_staged(tmp_path) -> None:
    """lab-serve.py is what the unit runs. An import it makes that the
    staging does not provide is the same crash one file over."""
    serve = (REPO / "harness" / "estate" / "lab-serve.py")
    if not serve.exists():
        pytest.skip("no lab-serve.py in this tree")
    package = stage(tmp_path)
    staged = {module.stem for module in package.glob("*.py")}
    wanted = set(re.findall(r"^from sehub\.(\w+) import", serve.read_text(),
                            flags=re.MULTILINE))
    wanted |= set(re.findall(r"^\s*from sehub\.(\w+) import", serve.read_text(),
                             flags=re.MULTILINE))
    missing = sorted(wanted - staged)
    assert not missing, (
        f"lab-serve.py imports modules the staging does not provide: {missing}")
