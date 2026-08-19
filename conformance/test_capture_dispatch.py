"""Every collector's capture arm must be closed, and closed by itself.

`se-capture-guest` chooses what to read with one `case $collector in` whose
arms each assign the `acquisitions` array. An arm that forgets its `)` or its
`;;` does not fail: bash parses the file, the missing `)` is supplied by the
NEXT arm's label — which becomes a stray array element — and control then falls
into that arm, which reassigns `acquisitions` wholesale. **The capture then
reads a different collector's interfaces and writes their payloads into the
requested collector's variant directory.**

That is not hypothetical. `kea)` shipped unterminated: asking for a kea capture
ran the downloaders adapter's RPC calls, and only the absence of a transmission
URL on that guest turned it into a visible traceback rather than a directory of
downloaders payloads committed as a kea variant.

`bash -n` cannot see any of this, which is why the defect survived a repair pass
whose whole purpose was parse errors — the file is VALID, it just dispatches to
the wrong collector. So the check is structural and static: every arm of that
case ends with `;;`, and nothing between an arm's `acquisitions=(` and its
terminator looks like another arm's label.

Deny-by-default over the arms the script actually declares, so a collector added
tomorrow is covered without being listed here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "harness" / "bin" / "se-capture-guest"

ARM = re.compile(r"^\s{0,8}([a-z0-9|_-]+)\)\s*$")
CASE_HEAD = re.compile(r"^\s*case\s+.*\bcollector\b.*\bin\s*$")


def _dispatch_arms() -> list[tuple[str, int, bool]]:
    """(arm label, 1-based line, whether it terminates) for the dispatch case.

    Read from the script's text rather than by running it: the failure being
    checked for is that running it succeeds while doing the wrong thing.
    """
    lines = SCRIPT.read_text().splitlines()
    starts = [i for i, line in enumerate(lines) if CASE_HEAD.match(line)]
    assert starts, (
        "no `case ... $collector ... in` found in se-capture-guest — this "
        "check is reading the wrong file or the dispatch has been rewritten, "
        "and either way it is now passing over nothing"
    )

    arms: list[tuple[str, int, bool]] = []
    for start in starts:
        current: list | None = None
        for i in range(start + 1, len(lines)):
            line = lines[i]
            if re.match(r"^\s*esac\b", line):
                if current:
                    arms.append(tuple(current))  # type: ignore[arg-type]
                break
            match = ARM.match(line)
            if match:
                if current:
                    arms.append(tuple(current))  # type: ignore[arg-type]
                current = [match.group(1), i + 1, False]
            elif current and re.search(r";;\s*$", line):
                current[2] = True
    return arms


ARMS = _dispatch_arms()


def test_the_dispatch_declares_arms_at_all() -> None:
    """A parse that found no arms would make every case below vacuous."""
    assert len(ARMS) >= 10, (
        f"only {len(ARMS)} dispatch arms parsed out of se-capture-guest; the "
        "script serves twenty collectors, so this check has stopped seeing "
        "the thing it is meant to check"
    )


@pytest.mark.parametrize("label,line,terminated",
                         ARMS, ids=[f"{a[0]}@{a[1]}" for a in ARMS])
def test_every_capture_arm_is_terminated(label: str, line: int,
                                         terminated: bool) -> None:
    """An unterminated arm captures the NEXT collector's interfaces.

    The consequence is a corpus variant whose payloads came from a collector
    nobody asked for — committed under a directory that names a different one,
    with a green capture run behind it.
    """
    assert terminated, (
        f"se-capture-guest line {line}: the `{label})` arm never reaches `;;`, "
        "so a capture of this collector falls through into the arm below and "
        "reads that collector's interfaces instead. bash parses this happily; "
        "only this check sees it."
    )


@pytest.mark.parametrize("label,line,_terminated",
                         ARMS, ids=[f"{a[0]}@{a[1]}" for a in ARMS])
def test_every_capture_arm_decides_what_to_acquire(label: str, line: int,
                                                   _terminated: bool) -> None:
    """An arm that never assigns `acquisitions` inherits the previous one's.

    A distinct failure from the unterminated arm above and not covered by it:
    the array is a plain shell variable, so an arm that only prints a note, or
    whose assignment is lost in an edit, leaves whatever the last arm set. The
    capture then runs, succeeds, and writes another collector's payloads —
    the same wrong outcome by a different route.

    An arm is allowed to set it EMPTY (`acquisitions=()`); that is a decision
    and the collector-specific code below the case supplies its work. What is
    refused is an arm that never mentions the variable at all.
    """
    lines = SCRIPT.read_text().splitlines()
    body = []
    for text in lines[line:]:
        if re.search(r";;\s*$", text):
            break
        body.append(text)
    assert any("acquisitions=" in text for text in body), (
        f"se-capture-guest line {line}: the `{label})` arm never assigns "
        "`acquisitions`, so it captures whatever the arm above it decided to "
        "capture — a green run over another collector's interfaces."
    )
