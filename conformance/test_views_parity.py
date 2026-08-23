"""Two implementations of one truth, required to agree (DESIGN §1892).

`se.views/1` is "served by both tiers like every other projection", and
the two tiers are two languages whose toolchains cannot read each other's
tree. That is the same situation `tokens.css` is in, and it is handled
the same way: one corpus of documents, both implementations driven over
it, identical verdicts required.

Where they disagree, **views.py is right**. It is the shipping product's
reference and an estate already deploys documents against it; the Go
port is the newcomer.

Register row 20 read "built" for this surface while the collator served
none of it — its probe reads only the hub's routes file, which is the
one-tier probe defect rows 1, 2, 3 and 17 also carried. A parity test
over an empty or one-sided corpus would repeat that mistake one layer
up, so the corpus is asserted to hold both acceptable and refused
documents.
"""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
import pathlib
from pathlib import Path

import pytest

from system_explorer.views import view_problem

REPO = Path(__file__).resolve().parent.parent

#: Every document both implementations must agree about. Each names the
#: rule it exercises, because a corpus entry nobody can explain is one
#: nobody will maintain.
DOCUMENTS: dict[str, object] = {
    "a whole view": {
        "name": "storage", "title": "Storage",
        "panels": [{"key": "pools", "title": "Pools",
                    "subsystem": "storage", "collection": "pools"}]},
    "a view scoped to hosts": {
        "name": "s", "title": "S", "hosts": ["host-a"],
        "panels": [{"key": "p", "title": "P",
                    "subsystem": "storage", "collection": "pools"}]},
    "hosts absent is every host": {
        "name": "n", "title": "T",
        "panels": [{"key": "p", "title": "P", "subsystem": "s",
                    "collection": "c"}]},
    "no name": {"title": "T", "panels": [{"key": "p", "title": "P",
                "subsystem": "s", "collection": "c"}]},
    "empty name": {"name": "", "title": "T", "panels": [
        {"key": "p", "title": "P", "subsystem": "s", "collection": "c"}]},
    "no title": {"name": "n", "panels": [{"key": "p", "title": "P",
                 "subsystem": "s", "collection": "c"}]},
    # A view that tried to narrow itself and failed must not widen
    # silently: that inversion made the ZFS dashboard an estate-wide
    # default on 2026-08-12.
    "empty hosts list": {"name": "n", "title": "T", "hosts": [],
                         "panels": [{"key": "p", "title": "P",
                                     "subsystem": "s", "collection": "c"}]},
    "hosts not a list": {"name": "n", "title": "T", "hosts": "host-a",
                         "panels": [{"key": "p", "title": "P",
                                     "subsystem": "s", "collection": "c"}]},
    "a host that is not a string": {
        "name": "n", "title": "T", "hosts": [7],
        "panels": [{"key": "p", "title": "P", "subsystem": "s",
                    "collection": "c"}]},
    "no panels": {"name": "n", "title": "T"},
    "empty panels": {"name": "n", "title": "T", "panels": []},
    "panel not an object": {"name": "n", "title": "T", "panels": ["x"]},
    "panel missing a member": {"name": "n", "title": "T", "panels": [
        {"key": "p", "title": "P", "subsystem": "s"}]},
    "a pipeline": {"name": "n", "title": "T", "panels": [
        {"kind": "pipeline", "key": "p", "title": "P", "stages": [
            {"key": "a", "title": "A", "subsystem": "s", "collection": "c"},
            {"key": "b", "title": "B", "subsystem": "s", "collection": "d"}]}]},
    "a pipeline with one stage": {"name": "n", "title": "T", "panels": [
        {"kind": "pipeline", "key": "p", "title": "P", "stages": [
            {"key": "a", "title": "A", "subsystem": "s", "collection": "c"}]}]},
    "a pipeline stage missing a member": {"name": "n", "title": "T", "panels": [
        {"kind": "pipeline", "key": "p", "title": "P", "stages": [
            {"key": "a", "title": "A", "subsystem": "s"},
            {"key": "b", "title": "B", "subsystem": "s", "collection": "d"}]}]},
    # A half-joined stage would silently relate nothing, which is the
    # dropped-panel shape in miniature.
    "a half-declared join": {"name": "n", "title": "T", "panels": [
        {"kind": "pipeline", "key": "p", "title": "P", "stages": [
            {"key": "a", "title": "A", "subsystem": "s", "collection": "c",
             "join": {"fact": "Id"}},
            {"key": "b", "title": "B", "subsystem": "s", "collection": "d"}]}]},
    "a whole join": {"name": "n", "title": "T", "panels": [
        {"kind": "pipeline", "key": "p", "title": "P", "stages": [
            {"key": "a", "title": "A", "subsystem": "s", "collection": "c",
             "join": {"fact": "Id", "targetFact": "Ref"}},
            {"key": "b", "title": "B", "subsystem": "s", "collection": "d"}]}]},
}

GO_DRIVER = textwrap.dedent("""
    package main

    import (
        "encoding/json"
        "fmt"
        "os"

        "github.com/techiebod/system-explorer/go/internal/collate"
    )

    func main() {
        var documents map[string]any
        if err := json.NewDecoder(os.Stdin).Decode(&documents); err != nil {
            panic(err)
        }
        verdicts := map[string]string{}
        for name, raw := range documents {
            document, ok := raw.(map[string]any)
            if !ok {
                verdicts[name] = "not a JSON object"
                continue
            }
            verdicts[name] = collate.ViewProblem(document)
        }
        out, _ := json.Marshal(verdicts)
        fmt.Println(string(out))
    }
""")


@pytest.fixture(scope="module")
def go_verdicts() -> dict[str, str]:
    # The driver lives INSIDE the module tree, because `collate` is an
    # internal package and Go refuses an internal import from outside it.
    # A temp directory under go/ rather than a tracked file: this is a
    # test harness, not a shipped binary, and a main package in cmd/
    # would be one more thing the fleet build has to know is not a
    # collector.
    import shutil, tempfile
    driver_dir = pathlib.Path(tempfile.mkdtemp(prefix=".parity-", dir=REPO / "go"))
    driver = driver_dir / "main.go"
    driver.write_text(GO_DRIVER)
    try:
        answer = subprocess.run(
            ["go", "run", str(driver)], cwd=REPO / "go",
            input=json.dumps(DOCUMENTS), capture_output=True, text=True,
            timeout=300, env={**os.environ, "CGO_ENABLED": "0"})
    except FileNotFoundError:
        shutil.rmtree(driver_dir, ignore_errors=True)
        pytest.skip("go is not on this machine")
    finally:
        shutil.rmtree(driver_dir, ignore_errors=True)
    if answer.returncode != 0:
        # A driver that will not build is a BROKEN PROBE, never a pass:
        # skipping here would report agreement this test never measured.
        raise AssertionError(f"the Go views driver did not run:\n{answer.stderr}")
    return json.loads(answer.stdout)


def test_the_corpus_discriminates() -> None:
    """Anti-vacuity. A parity corpus whose documents are all acceptable —
    or all refused — proves the two implementations agree about nothing
    in particular."""
    verdicts = {name: view_problem(doc) for name, doc in DOCUMENTS.items()}
    accepted = [n for n, v in verdicts.items() if v is None]
    refused = [n for n, v in verdicts.items() if v is not None]
    assert len(accepted) >= 4, f"the corpus must hold whole views: {accepted}"
    assert len(refused) >= 10, f"the corpus must hold refused ones: {refused}"


def test_both_tiers_reach_the_same_verdict_on_every_document(go_verdicts) -> None:
    """§1892 says both tiers serve this surface, so both tiers decide what
    is servable — and two implementations that disagree mean a document
    an operator deployed is shown by one tier and refused by the other,
    with nothing saying which is right."""
    disagreements = {}
    for name, document in DOCUMENTS.items():
        reference = view_problem(document) or ""
        port = go_verdicts.get(name, "<absent>")
        if reference != port:
            disagreements[name] = {"views.py": reference, "collate": port}
    assert not disagreements, (
        "the two tiers disagree about what is servable: "
        f"{json.dumps(disagreements, indent=2)}. views.py is right — it is "
        "the reference an estate already deploys against.")
