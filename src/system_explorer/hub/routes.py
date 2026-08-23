"""The hub's read surface, as one table two consumers read.

**A tool per route, structurally.** The UI, the JSON API and MCP are the
same envelopes rendered differently — there is no UI-private API and no
agent-private one, and if the two ever needed different data the envelope
would be wrong. So the routes are declared once, here, and both the HTTP
server and the MCP surface are generated from this table. Parity is then
a property of the construction rather than a check somebody remembers to
run, and the check that exists is anti-vacuity: it fails if the table
ever stops being the source.

**MCP comes free for a plugin, and that is why the tools are per ROUTE.**
`get_collection(host, collection)` reaches a plugin's collection the day
it exists, because nothing in the tool signature names a first-party one.
A tool per collection would have made every plugin a code change here.

**Nothing on this surface is a write.** Every route is registered with a
GET method and no other verb exists to misconfigure — read-only as a
structural property rather than a policy, which is what lets the hub bind
where it does. Acknowledgement — the product's first write — is READ
here and written on a listener of its own (`writes.py`), which is the
whole of why that second socket exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class Route:
    """One read route, and the tool it becomes."""

    path: str
    tool: str
    summary: str
    #: Path segments the caller supplies, in order. Named rather than
    #: parsed out of the path so a tool signature is data rather than a
    #: regular expression somebody has to keep in step.
    params: tuple[str, ...] = ()
    handler: Callable[..., Any] | None = None

    def matches(self, path: str) -> dict[str, str] | None:
        want = [p for p in self.path.strip("/").split("/") if p]
        got = [p for p in path.strip("/").split("/") if p]
        if len(want) != len(got):
            return None
        bound: dict[str, str] = {}
        for expect, actual in zip(want, got):
            if expect.startswith("{") and expect.endswith("}"):
                bound[expect[1:-1]] = actual
            elif expect != actual:
                return None
        return bound


def render_hosts(state: Any) -> dict[str, Any]:
    """The hosts body — module-level so the sibling answer serves the SAME
    spelling the local surface does, rather than a second one to drift."""
    return {"hosts": {h: r.value for h, r in state.view.reach.items()}}


def render_objects(state: Any) -> dict[str, Any]:
    return {"objects": [
        {"id": row.id, "estate_scoped": row.estate_scoped,
         "facts": dict(row.facts), "undeclared": list(row.undeclared),
         "withheld": list(row.withheld),
         "members": [{"host": m.host, "collection": m.collection,
                      "object": m.object_id, "instance": m.instance}
                     for m in row.members]}
        for row in state.view.rows]}


def render_opinions(state: Any) -> dict[str, Any]:
    return {"opinions": [
        {"host": o.host, "collection": o.collection, "object": o.object_id,
         "instance": o.instance, "key": o.key, "level": o.level,
         "grounds": o.grounds, "sentence": o.sentence, "cites": list(o.cites)}
        for o in state.opinions]}


def table(view_of: Callable[[], Any],
          views_of: Callable[[], Any] | None = None,
          sibling_of: Callable[[str], Any] | None = None,
          acks_of: Callable[[], Any] | None = None,
          findings_of: Callable[[], Any] | None = None) -> tuple[Route, ...]:
    """Build the route table over a callable returning the current view.

    `view_of` is passed rather than a view, because the hub's answer is
    computed fresh on every request: the hub holds no observation of its
    own, and serving a remembered one would be exactly the last-known-good
    that belongs with findings instead.

    `views_of` returns this site's se.views/1 envelope — the ruled-
    unchanged surface, read fresh from the deployed directory per request
    by the same shared loader both old servers use. Optional because a
    deployment that made no views is an empty list, not an error, and a
    caller that passes nothing gets exactly that.

    `findings_of` returns the lifecycle registry's OPEN SET. It is the
    one surface that answers "what needs attention, and how long has it
    been true" — the question the shipping product's own attention page
    answers and which had no route at either tier until 2026-08-23: the
    lifecycle landed at R3e and its surface did not. `get_opinions` is
    not it, because an opinion has no lifecycle; a finding is an opinion
    at warn or above WITH one.

    `acks_of` folds the transition log into a per-finding acknowledgement
    state. It DECORATES and never filters: no route here consults it to
    decide what to serve, so an acknowledged finding is in every body it
    was in before. That is the ruling's own clause — acknowledgement
    changes what is shouted, not what is known — and it holds here by the
    surface never asking, rather than by asking and then including.
    """

    def hosts() -> Any:
        return render_hosts(view_of())

    def objects() -> Any:
        return render_objects(view_of())

    def collection(host: str, name: str) -> Any:
        state = view_of()
        return {"objects": [
            {"id": row.id, "facts": dict(row.facts), "undeclared": list(row.undeclared),
             "withheld": list(row.withheld)}
            for row in state.view.rows
            for m in row.members if m.host == host and m.collection == name]}

    def opinions() -> Any:
        return render_opinions(view_of())

    def sites(site: str) -> Any:
        # Never from a store: a hub answers for a sibling's hosts only by
        # asking the sibling, live, per request — replicating observations
        # between hubs is the shortcut that stays forbidden outright
        # (DESIGN 06). Unconfigured is stated, and stated differently
        # from a sibling that is configured and not answering, which is
        # the injected callable's to report.
        if sibling_of is None:
            return {"error": "no sibling session is configured for this hub",
                    "site": site}
        return sibling_of(site)

    def questions() -> Any:
        state = view_of()
        return {"questions": [
            {"id": answer["id"], "question": answer["question"]}
            for answer in state.answers]}

    def answer(question: str) -> Any:
        state = view_of()
        for candidate in state.answers:
            if candidate["id"] == question:
                return candidate
        return {"error": "no such question", "question": question}

    def coverage() -> Any:
        state = view_of()
        c = state.view.coverage
        return {"declared": list(c.declared),
                "discovered_not_declared": list(c.discovered_not_declared),
                "unclassified": list(c.unclassified),
                "sources_readable": list(c.sources_readable),
                "sources_unreadable": list(c.sources_unreadable)}

    def views() -> Any:
        if views_of is None:
            return {"schema": "se.views/1", "views": [], "errors": []}
        return views_of()

    def acknowledgements() -> Any:
        if acks_of is None:
            # An unconfigured log is an estate where nothing has been
            # acknowledged yet, which is a real and ordinary state — and
            # it is stated as an empty mapping rather than an error, for
            # the same reason a deployment with no views gets an empty
            # list. What it must never do is suppress a finding.
            return {"acknowledgements": {}}
        return acks_of()

    def findings() -> Any:
        if findings_of is None:
            # No registry wired. NOT an empty finding list: "nothing is
            # wrong" and "nobody is keeping the lifecycle" are the two
            # readings this product exists to keep apart, and a bare
            # empty list here would be absence rendered as health on the
            # one surface whose whole subject is attention.
            return {"findings": None,
                    "unanswered": "no findings registry is wired to this hub, "
                                  "so what is open cannot be stated. This is "
                                  "not a report that nothing is open."}
        held = findings_of()
        return {"findings": held, "count": len(held)}

    def intent() -> Any:
        state = view_of()
        # The HASH and the revision, never the document: intent is an
        # estate's own configuration, it carries a plugin's stanzas
        # verbatim, and a read surface that returned all of it would
        # publish somebody's private arrangement to whoever can reach the
        # hub. What a consumer needs is whether two hubs agree.
        return {"hash": state.intent.hash, "revision": state.intent.revision,
                "estate": state.intent.estate, "reviewed": state.intent.reviewed,
                "declared_hosts": list(state.intent.declared_hosts()),
                "plugins": sorted(state.intent.plugins)}

    return (
        Route("/v1/hosts", "list_hosts",
              "Every host this hub knows and whether it is connected, dark or "
              "unswept. Unswept is not dark: nobody has told us is a different "
              "claim from told us and stopped.", (), hosts),
        Route("/v1/objects", "list_objects",
              "Every object in the estate view, with the facts a declaration "
              "backs and the names of any it refused.", (), objects),
        Route("/v1/hosts/{host}/collections/{name}", "get_collection",
              "One host's collection. Reaches a plugin's collection the day it "
              "exists, because nothing here names a first-party one.",
              ("host", "name"), collection),
        Route("/v1/opinions", "get_opinions",
              "Every opinion currently held, with its level and its grounds — "
              "`interface` means the system declared the fault, `threshold` "
              "means the number is ours.", (), opinions),
        Route("/v1/questions", "list_questions",
              "The problem domains this hub can answer, so a caller can "
              "discover them rather than guess a string.", (), questions),
        Route("/v1/questions/{question}", "get_answer",
              "One problem-domain answer: the sentence, the verdict, how much "
              "of the question the evidence covered, and the reach.",
              ("question",), answer),
        Route("/v1/coverage", "get_coverage",
              "The estate boundary as identities: declared, discovered but not "
              "declared, unclassified, and which discovery sources were "
              "readable.", (), coverage),
        Route("/v1/sites/{site}", "get_site",
              "A sibling site's hosts, asked from the sibling live — one hop, "
              "never forwarded, never stored — with both ages visible: when "
              "each host told its own hub, and when that hub answered this "
              "one.", ("site",), sites),
        Route("/v1/views", "get_views",
              "This site's operator-authored view documents (se.views/1), "
              "read fresh from the deployed directory — the operator edits a "
              "file and refreshes. No directory means a deployment that made "
              "no views: an empty list, not an error.", (), views),
        Route("/v1/acknowledgements", "get_acknowledgements",
              "Which findings somebody has said they have seen, who said so and "
              "when. Acknowledgement changes what is shouted, never what is "
              "known: an acknowledged finding is still in every other body on "
              "this surface. Written on the hub's write listener, never here.",
              (), acknowledgements),
        Route("/v1/findings", "get_findings",
              "What needs attention, and how long it has been true: every "
              "OPEN finding with its first-seen, its last-seen and its "
              "verdict. A finding is an opinion at warn or above with a "
              "lifecycle — `get_opinions` serves the opinions and has no "
              "lifecycle, so it cannot answer this. Where a finding's "
              "first-seen is the post-cut reset rather than the condition's "
              "own age, the row says so rather than claiming an age it does "
              "not have. An acknowledged finding is still here: "
              "acknowledgement changes what is shouted, never what is "
              "known.", (), findings),
        Route("/v1/intent", "get_intent",
              "The intent hash and revision this hub holds — what a sibling "
              "compares against. Never the document itself.", (), intent),
    )
