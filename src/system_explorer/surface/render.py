"""The estate page, rendered on the server (DESIGN 06, 27, 28).

**The producer renders, so the renderer knows nothing the producer does
not.** §27's rule is satisfied trivially when the two are the same
process, and the whole class of browser-side fourth-copy bugs — three of
which this product has already shipped — becomes structurally impossible.
There is no severity table here, no state table, and no fact glossary: a
level comes from the opinion, a sentence comes from the declaration, and
anything this file decided for itself would be the fourth copy again.

**Everything interpolated is escaped, without exception.** Once app-tier
collectors publish media titles, release names and container labels, an
envelope carries text written by strangers on the internet. That text
reaches this renderer, and a page that trusted it would turn a read-only
observer into a delivery mechanism. Escaping is not a nicety here, it is
the same discipline as marking third-party text for a model.

**A problem-domain page needs three things a table has no room for**
(§28): the answer first in a sentence, the reasoning with each basis
element's kind and origin visible, and the reach — what was consulted,
what declined, what was dark, and what the coverage was.
"""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Iterable, Mapping

TOKENS = (Path(__file__).resolve().parent / "tokens.css").read_text()

#: The three levels, worst first. Not a severity table — it is the order
#: they are DISPLAYED in, which is a rendering decision and the only kind
#: this file is allowed to make. The names themselves come from the
#: contract's closed vocabulary, and a level this does not know still
#: renders, unstyled, rather than erroring (DESIGN 25-26).
LEVEL_ORDER = ("critical", "warn", "info")


def _e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def page(title: str, body: str) -> str:
    return (
        "<!doctype html>\n"
        f'<html lang="en"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(title)}</title><style>{TOKENS}</style></head>"
        f"<body><main>{body}</main></body></html>\n"
    )


def _chip(text: str, kind: str = "") -> str:
    return f'<span class="chip {_e(kind)}">{_e(text)}</span>'


def _opinion_row(opinion: Any) -> str:
    level = getattr(opinion, "level", "")
    grounds = getattr(opinion, "grounds", "")
    cites = ", ".join(_e(c) for c in getattr(opinion, "cites", ()))
    # Grounds beside level, never folded into it: `threshold` says the
    # number is ours, and a reader deciding whether to act needs to know
    # that before they read the sentence.
    # THE HOST, on an estate page. This table sorted BY host and never
    # showed it, so a `critical` on the estate could not be attributed to
    # a machine — the reader is told something is wrong and not where —
    # and two hosts with the same condition rendered as duplicate rows
    # with no way to tell them apart. It is the first column because on
    # an estate page "which machine" is the question before "what".
    return (
        "<tr>"
        f'<td><span class="ident">{_e(getattr(opinion, "host", ""))}</span></td>'
        f"<td>{_chip(level, level)}</td>"
        f'<td><span class="grounds {_e(grounds)}">{_e(grounds)}</span></td>'
        f'<td><span class="ident">{_e(getattr(opinion, "object_id", ""))}</span></td>'
        f"<td>{_e(getattr(opinion, 'sentence', ''))}</td>"
        f'<td class="faint">{cites}</td>'
        "</tr>"
    )


def opinions_panel(held: Iterable[Any]) -> str:
    rows = sorted(
        held,
        key=lambda o: (
            LEVEL_ORDER.index(o.level) if o.level in LEVEL_ORDER else len(LEVEL_ORDER),
            o.host, o.object_id, o.key,
        ),
    )
    if not rows:
        # Said rather than left blank: an empty page and a page reporting
        # nothing wrong are the same pixels, and only one of them is a
        # claim. Which of the two this is depends on reach, shown above.
        return (
            '<section class="panel"><h2>Opinions</h2>'
            '<p class="dim">No opinion fired on anything the hub can currently see. '
            "That is a statement about what was judged, not about what exists — "
            "the reach above says how much was.</p></section>"
        )
    body = "".join(_opinion_row(o) for o in rows)
    return (
        '<section class="panel"><h2>Opinions</h2><div class="scroll"><table>'
        "<thead><tr><th>host</th><th>level</th><th>grounds</th><th>object</th>"
        "<th>says</th><th>cites</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div></section>"
    )


#: Reach is a CLOSED enum (hub/checkpoint.py: unswept | connected | dark)
#: and each member means something different, so each gets its own mark.
#:
#: This was `"ok" if state == "connected" else "warn"`, which is a
#: two-entry severity table in a renderer — the thing DESIGN §27 forbids,
#: and it collapsed the two states that matter most: `unswept` means this
#: hub has never swept the host, and `dark` means it swept and got
#: nothing. One is a gap in our looking, the other is a fault on the
#: estate, and rendering both as `warn` is absence and failure wearing one
#: face on the page that exists to tell them apart.
#:
#: A member not in this table renders UNSTYLED rather than being lumped in
#: with the nearest one — a newer hub's vocabulary is shown, never
#: guessed at.
_REACH_MARK = {
    "connected": "ok",
    "dark": "critical",
    "unswept": "muted",
}


def reach_panel(reach: Mapping[str, Any], coverage: Any) -> str:
    chips = "".join(
        _chip(f"{host} · {getattr(state, 'value', state)}",
              _REACH_MARK.get(getattr(state, "value", state), ""))
        for host, state in sorted(reach.items())
    )
    def _list(label: str, values: Iterable[str]) -> str:
        values = list(values)
        if not values:
            return ""
        # Identities, never counts: "six of six" tells a reader nothing
        # they can check, and a list tells them at once that the host they
        # were thinking of is not in it.
        return (f'<div><span class="dim">{_e(label)}:</span> '
                f'<span class="ident">{", ".join(_e(v) for v in values)}</span></div>')
    lists = "".join([
        _list("declared", coverage.declared),
        _list("discovered, not declared", coverage.discovered_not_declared),
        _list("unclassified", coverage.unclassified),
        _list("sources readable", coverage.sources_readable),
        _list("sources unreadable", coverage.sources_unreadable),
    ])
    return (
        '<section class="panel"><h2>Reach</h2>'
        f'<div class="reach">{chips}</div>{lists}</section>'
    )


def _as_read(value: Any) -> str:
    """One basis element's value, as a reader should see it.

    A list arrived here and was rendered with Python's repr, so the estate
    page carried the literal text `[&#x27;lab-a&#x27;, &#x27;lab-b&#x27;]`
    — a language's internal notation shown to an operator, and the same
    class of defect as comma-joining a structured value: the reader has to
    decode our data structure instead of reading their estate.
    """
    if isinstance(value, (list, tuple)):
        if not value:
            # Measured emptiness, not a missing value.
            return '<span class="empty-list">none</span>'
        return '<span class="chips">' + "".join(
            f'<span class="chip item">{_e(v)}</span>' for v in value) + "</span>"
    if isinstance(value, Mapping):
        return '<span class="chips">' + "".join(
            f'<span class="chip item">{_e(k)}={_e(v)}</span>'
            for k, v in sorted(value.items())) + "</span>"
    return _e(value)


def answer_panel(answer: Mapping[str, Any]) -> str:
    basis = "".join(
        "<tr>"
        f'<td>{_chip(_e(element.get("kind")))}</td>'
        f'<td class="ident">{_e(element.get("origin"))}</td>'
        f"<td>{_e(element.get('claim'))}</td>"
        f'<td class="faint">{_as_read(element.get("value_as_read"))}</td>'
        "</tr>"
        for element in answer.get("basis", ())
    )
    verdict = _e(answer.get("verdict"))
    return (
        '<section class="panel">'
        f"<h2>{_e(answer.get('question'))}</h2>"
        # The answer first, in a sentence — never a table that implies one.
        f'<p class="answer">{_e(answer.get("answer"))}</p>'
        f'<div class="reach">{_chip(verdict, verdict)}'
        f'{_chip("knows: " + str(answer.get("epistemic")))}'
        f'{_chip("evidence: " + str(answer.get("freshness")))}</div>'
        '<div class="scroll"><table><thead><tr><th>kind</th><th>origin</th>'
        "<th>claim</th><th>as read</th></tr></thead>"
        f"<tbody>{basis}</tbody></table></div></section>"
    )


def index_panel(rows: Iterable[Any], collections: Iterable[Any] = ()) -> str:
    """Host and collection, with counts and a link into each.

    A flat table of every object in the estate is not a page. Measured on
    two lab guests, 2026-08-20: twenty collectors produce ~2,000 objects
    and half a megabyte of HTML, which renders and cannot be read. The
    estate scale answers *where should I look*; the collection page
    answers *what is there*. Splitting them is what makes either legible.

    **Driven by what each host REPORTED, not by the objects it published.**
    This counted objects, so a collection with none — declined, absent,
    never read, or read and genuinely empty — produced no entry and was
    absent from the estate view. Measured on the lab 2026-08-24: 29 of
    lab-a's 52 collections were invisible from the hub, and they were
    precisely the ones not answering. Absence rendering as non-existence,
    at estate scale, on the page whose job is to say where to look.

    `collections` is optional so a caller with only rows still gets the
    old counting behaviour rather than an empty table — but the estate
    page passes it, and the difference is 29 rows.
    """
    counts: dict[tuple[str, str], int] = {}
    for row in rows:
        for member in row.members:
            counts[(member.host, member.collection)] = (
                counts.get((member.host, member.collection), 0) + 1)

    reported = list(collections)
    if reported:
        body = "".join(_index_row(entry) for entry in sorted(
            reported, key=lambda e: (e["host"], e["collection"])))
    else:
        body = "".join(
            f'<tr><td class="ident">{_e(host)}</td>'
            f'<td><a href="/hosts/{_e(host)}/collections/{_e(collection)}">'
            f'{_e(collection)}</a></td>'
            f'<td class="num">{count}</td><td></td><td></td></tr>'
            for (host, collection), count in sorted(counts.items())
        )
    if not body:
        return ('<section class="panel"><h2>Collections</h2>'
                '<p class="dim">No host has promoted a collection yet. The reach '
                'above says whether that is because nobody has called in.</p></section>')
    return (
        '<section class="panel"><h2>Collections</h2><div class="scroll"><table>'
        "<thead><tr><th>host</th><th>collection</th><th>objects</th>"
        "<th>state</th><th>host last spoke</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div></section>"
    )


def _index_row(entry: Mapping[str, Any]) -> str:
    host = entry.get("host", "")
    name = entry.get("collection", "")
    generation = entry.get("generation", 0)
    # An object count is a MEASUREMENT only where something applied.
    if generation == 0:
        objects = '<span class="state-unstated">not counted</span>'
        state = _chip("never read", "muted")
    else:
        objects = f'{entry.get("objects", 0)}'
        reason = entry.get("stale_reason")
        if reason:
            state = _chip(f"stale · {reason}", "warn")
        else:
            state = _chip(str(entry.get("freshness") or "current"), "ok")
    # A host that is dark is serving LAST-KNOWN state, and the row says so
    # rather than presenting it as current.
    told = entry.get("told_at") or "never"
    if entry.get("reach") != "connected":
        told = f'{told} · {entry.get("reach")}'
    return (
        f'<tr><td class="ident">{_e(host)}</td>'
        f'<td><a href="/hosts/{_e(host)}/collections/{_e(name)}">{_e(name)}</a></td>'
        f'<td class="num">{objects}</td>'
        f"<td>{state}</td>"
        f'<td class="faint">{_e(told)}</td></tr>'
    )


def collection_page(host: str, collection: str, rows: Iterable[Any]) -> str:
    """One collection on one host — the scale at which objects are read."""
    listed = [row for row in rows
              if any(m.host == host and m.collection == collection
                     for m in row.members)]
    return page(
        f"{collection} on {host}",
        f'<h1><span class="ident">{_e(host)}</span> · {_e(collection)}</h1>'
        f'<p class="dim"><a href="/">← the estate</a> · {len(listed)} objects</p>'
        + rows_panel(listed)
        + "<footer>Facts appear only where a declaration backs them; anything "
          "refused or withheld is named on its row.</footer>",
    )


def rows_panel(rows: Iterable[Any]) -> str:
    body = []
    for row in rows:
        facts = ", ".join(f"{_e(k)}={_e(v)}" for k, v in sorted(row.facts.items()))
        # Refused facts are NAMED on the row rather than dropped quietly:
        # an operator looking for a fact they know a collector emits must
        # see that it was refused and why.
        refused = (
            f'<div class="faint">no declared axis: {", ".join(_e(f) for f in row.undeclared)}</div>'
            if row.undeclared else ""
        )
        # Named, never valued. An operator must be able to tell a withheld
        # credential from an absent fact, and the NAME is not the secret.
        held = (
            f'<div class="faint">withheld (declared secret): '
            f'{", ".join(_e(f) for f in row.withheld)}</div>'
            if row.withheld else ""
        )
        body.append(
            f'<tr><td class="ident">{_e(row.id)}</td>'
            f'<td>{_chip("estate" if row.estate_scoped else "host")}</td>'
            f"<td>{facts}{refused}{held}</td></tr>"
        )
    return (
        '<section class="panel"><h2>Objects</h2><div class="scroll"><table>'
        "<thead><tr><th>id</th><th>scope</th><th>facts</th></tr></thead>"
        f'<tbody>{"".join(body)}</tbody></table></div></section>'
    )


def estate_page(view: Any, answer: Mapping[str, Any], held: Iterable[Any]) -> str:
    return page(
        "Estate",
        "<h1>Estate</h1>"
        + answer_panel(answer)
        + reach_panel(view.reach, view.coverage)
        + opinions_panel(held)
        + index_panel(view.rows, getattr(view, "collections", ()))
        + "<footer>Server-rendered from the declarations each host published. "
          "Nothing on this page was decided by the page.</footer>",
    )
