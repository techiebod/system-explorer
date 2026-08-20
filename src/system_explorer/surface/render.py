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
    return (
        "<tr>"
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
        "<thead><tr><th>level</th><th>grounds</th><th>object</th>"
        "<th>says</th><th>cites</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div></section>"
    )


def reach_panel(reach: Mapping[str, Any], coverage: Any) -> str:
    chips = "".join(
        _chip(f"{host} · {getattr(state, 'value', state)}",
              "ok" if getattr(state, "value", state) == "connected" else "warn")
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


def answer_panel(answer: Mapping[str, Any]) -> str:
    basis = "".join(
        "<tr>"
        f'<td>{_chip(_e(element.get("kind")))}</td>'
        f'<td class="ident">{_e(element.get("origin"))}</td>'
        f"<td>{_e(element.get('claim'))}</td>"
        f'<td class="faint">{_e(element.get("value_as_read"))}</td>'
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
        + rows_panel(view.rows)
        + "<footer>Server-rendered from the declarations each host published. "
          "Nothing on this page was decided by the page.</footer>",
    )
