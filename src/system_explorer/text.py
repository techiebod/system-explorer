"""Bounding failure text, once, for every surface that shows it.

A capability reason is the product's answer to "why can this host not answer
that?" — read by the operator in the UI, by an LLM over MCP, and by the
/v1/status roll-up (SPEC section 2, rule 7). Clipping one mid-word throws away
the part that names the cause. Observed live on two hosts:

    resolve1 not available on the system bus: org.freedesktop.DBus.Error.
    NameHasNoOwner: ["Could not activate remote pe

— and the words that got cut, *activation request failed: unknown unit*, were
the entire diagnosis.

The real finding was not the cut, though: it was that six call sites clipped
the same concept at four different limits (120, 140, 160, 200), each invented
locally. So this lives in one stdlib-only module that the agent, the hub and
the aggregator all use, because they all put failure text in front of the same
readers.

Reasons are **bounded, not clipped**: one line, whole words, an explicit
marker when anything was dropped, and a limit sized for real native failures
rather than for a terminal — the longest measured on a live estate was 234
characters, so 400 leaves headroom while still refusing an unbounded blob.
"""

from __future__ import annotations

MAX_LENGTH = 400

# Trailing punctuation left dangling by a word-boundary cut reads as damage
# rather than as a deliberate bound.
_DANGLING = " ,;:.([{-"


def one_line(value: object, limit: int = MAX_LENGTH) -> str:
    """Collapse to one line and bound to `limit` on a word boundary.

    Idempotent: bounding an already-bounded string returns it unchanged, so a
    reason may pass through more than one layer without accumulating markers.
    """
    flat = " ".join(str(value).split())
    if len(flat) <= limit:
        return flat
    head = flat[:limit].rpartition(" ")[0] or flat[:limit]
    return f"{head.rstrip(_DANGLING)} … (truncated)"
