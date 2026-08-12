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

import os
import re

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


# ── credential scrubbing (SPEC section 11, rule 10 extended) ─────────────
#
# Failure text is a channel. httpx stringifies HTTPStatusError with the full
# request URL, and two of the estate's planned upstreams (Tautulli, sabnzbd)
# accept their API key ONLY as a query parameter — so one 401 during a key
# rotation would publish the key into a capability reason, which
# /v1/status and /v1/capabilities then serve to every unauthenticated
# poller. Found by adversarial review BEFORE the first credentialed adapter
# exists, which is the only acceptable time to find it.
#
# Two defences, both at the envelope boundary so a new adapter inherits
# them for free:
#   1. URL query strings in failure text are stripped wholesale — the path
#      identifies the endpoint, the query is where credentials hide, and no
#      diagnosis has ever needed the query string back.
#   2. The VALUES of secret-shaped environment variables are substituted by
#      name. The names come from the process's own environment at call
#      time: any variable whose name ends in a recognised secret suffix is
#      assumed to hold something that must never appear in an envelope.

_QUERY_STRING = re.compile(r"""\?[^\s"'<>]+""")
# URL userinfo is the OTHER place a URL carries a credential, and httpx
# stringifies HTTPStatusError with the full request URL — so an operator
# who configured basic-auth userinfo into an app URL would publish it in
# every error envelope. Stripped wholesale like the query string: the
# scheme and host that remain are the diagnostically useful halves.
_URL_USERINFO = re.compile(r"(?<=://)[^/\s\"'<>@]+@")
SECRET_ENV_SUFFIXES = ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_PASS")


def _secret_values() -> list[tuple[str, str]]:
    """(value, env name) pairs worth substituting, longest value first so a
    secret that contains another is replaced whole. Read per call, not
    cached: the EnvironmentFile can change across a reload, and a scrub
    that missed a rotated-in secret is the exact failure this exists for."""
    pairs = [(value, name) for name, value in os.environ.items()
             if name.endswith(SECRET_ENV_SUFFIXES) and len(value) >= 8]
    return sorted(pairs, key=lambda pair: len(pair[0]), reverse=True)


def scrub(value: str) -> str:
    """Failure text with credentials removed, marked where anything was.

    Substitution names the VARIABLE, not the value: `[redacted:$NAME]` tells
    the operator which secret leaked into which failure without re-leaking
    it — the redaction suite's rule that withholding must say what it
    withheld.
    """
    out = _QUERY_STRING.sub("?[query-stripped]", value)
    out = _URL_USERINFO.sub("[userinfo-stripped]@", out)
    for secret, name in _secret_values():
        if secret in out:
            out = out.replace(secret, f"[redacted:${name}]")
    return out
