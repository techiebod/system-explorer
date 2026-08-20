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
where it does.
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


def table(view_of: Callable[[], Any]) -> tuple[Route, ...]:
    """Build the route table over a callable returning the current view.

    `view_of` is passed rather than a view, because the hub's answer is
    computed fresh on every request: the hub holds no observation of its
    own, and serving a remembered one would be exactly the last-known-good
    that belongs with findings instead.
    """

    def hosts() -> Any:
        state = view_of()
        return {"hosts": {h: r.value for h, r in state.view.reach.items()}}

    def objects() -> Any:
        state = view_of()
        return {"objects": [
            {"id": row.id, "estate_scoped": row.estate_scoped,
             "facts": dict(row.facts), "undeclared": list(row.undeclared),
             "withheld": list(row.withheld),
             "members": [{"host": m.host, "collection": m.collection,
                          "object": m.object_id, "instance": m.instance}
                         for m in row.members]}
            for row in state.view.rows]}

    def collection(host: str, name: str) -> Any:
        state = view_of()
        return {"objects": [
            {"id": row.id, "facts": dict(row.facts), "undeclared": list(row.undeclared),
             "withheld": list(row.withheld)}
            for row in state.view.rows
            for m in row.members if m.host == host and m.collection == name]}

    def opinions() -> Any:
        state = view_of()
        return {"opinions": [
            {"host": o.host, "collection": o.collection, "object": o.object_id,
             "instance": o.instance, "key": o.key, "level": o.level,
             "grounds": o.grounds, "sentence": o.sentence, "cites": list(o.cites)}
            for o in state.opinions]}

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
        Route("/v1/intent", "get_intent",
              "The intent hash and revision this hub holds — what a sibling "
              "compares against. Never the document itself.", (), intent),
    )
