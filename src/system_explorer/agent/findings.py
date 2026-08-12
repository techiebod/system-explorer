"""The findings surface: every warn/critical opinion this host derives, in
one envelope (the read side SPEC section 6.3 promised the hub registry).

The hub attaches lifecycle to the rule-15 identity
`(host.machine_id, container?, app?, object.id, opinion.key)` — and that
identity needs opinion KEYS, which live on rows and objects, never in
/v1/status's counts. Deriving them hub-side by walking every collection of
every host would cost O(hosts × collections) requests per roll-up — the
exact shape /v1/status was built to avoid. So the derivation stays on the
host: one sweep, the same acquisition /v1/status makes, lifting the
attention opinions the rows already carry (envelope.item_summary). The
agent stays stateless; lifecycle is the hub's.

Pure over its inputs, the views.py stance: acquisition and capability
probes live in agent/main.py with the other async orchestration, and what
is HERE is the part conformance can hold still — which rows become
findings, and what the envelope must say when a collection could not be
evaluated.

`unobserved` is the load-bearing member. Section 6.3 rule 4 makes
resolution OBSERVED: a finding leaves the roll-up when the host stops
deriving it. But "the host stopped deriving it" and "the host could not
look" are different statements, and only the first is resolution — an
adapter that breaks must not read as every one of its findings clearing
at once (the absence-as-health shape, in the one place it would corrupt
history rather than a single screen). Every collection that would have
been swept and was not is named here with its reason, so the hub can
freeze that collection's findings instead of resolving them.
"""

from __future__ import annotations

from . import envelope as env

SCHEMA_FINDINGS = "se.findings/1"


def finding_records(subsystem: str, collection: str, items: list[dict]) -> list[dict]:
    """The findings a collection's rows carry: one record per warn/critical
    opinion, identified by the object id and opinion key the row already
    published — no second evaluation, so this surface cannot disagree with
    the red dot it explains. Rows without carried opinions contribute
    nothing (info is commentary, not attention — see envelope.attention)."""
    out: list[dict] = []
    for item in items:
        opinions = item.get("opinions")
        if not opinions:
            continue
        obj = {key: item[key] for key in ("id", "type", "native_id")}
        if item.get("name"):
            obj["name"] = item["name"]
        ref = env.evidence_ref(subsystem, collection, item["id"])
        out.extend({
            "subsystem": subsystem,
            "collection": collection,
            "object": obj,
            "opinion": opinion,
            "evidence_ref": ref,
        } for opinion in opinions)
    return out


def locator_scoped(entries: list[dict], host_block: dict | None) -> list[dict]:
    """Stamp an app adapter's narrowed locator onto finding records or
    unobserved entries. The envelope's root host block describes the
    PROCESS; one process can front host-scoped and app-scoped subsystems
    at once, and a finding's rule-15 identity must match the locator its
    collection and evidence envelopes declare — without this stamp, the
    hub would key an app's finding under the host-native locator and the
    same condition would carry two identities depending on which surface
    stated it (adversarial review, 2026-08-12). None (a host-scoped
    adapter) stamps nothing."""
    if host_block is None:
        return entries
    return [{**entry, "host": host_block} for entry in entries]


DESELECTED_REASON = ("subsystem not selected in this process (SE_ADAPTERS)"
                     " — another instance on this host may serve it")


def deselected_unobserved(collections_by_subsystem: dict[str, list[str]],
                          declines: set[tuple[str, str]]) -> list[dict]:
    """The unobserved entries a narrowed process owes for what it is NOT
    running. SE_ADAPTERS selection (the per-process split) removes whole
    subsystems from the sweep — and a sweep that says nothing about them
    emits the envelope's "everything evaluable was evaluated" statement
    falsely, so the hub reads their standing findings as resolved-by-
    observation (adversarial review, 2026-08-12: reproduced end-to-end
    with a deselected docker subsystem's critical finding). Naming them
    here makes the hub's existing freeze do the right thing with no hub
    change. Declined pairs and lookups are skipped exactly as the sweep
    skips them: they can never bear findings from any process."""
    return [{"subsystem": name, "collection": collection,
             "reason": DESELECTED_REASON}
            for name, collections in sorted(collections_by_subsystem.items())
            for collection in collections
            if collection != "lookups" and (name, collection) not in declines]


def findings_envelope(now: str, findings: list[dict], unobserved: list[dict],
                      errors: list[str] | None = None,
                      host: dict | None = None,
                      locators: list[dict] | None = None) -> dict:
    """One se.findings/1 envelope. `unobserved` is required even when empty:
    an explicit empty list is the statement "everything evaluable was
    evaluated", which is what licenses the hub to treat a finding's absence
    as resolution. `locators` is that statement's scope — every locator
    this process fronts, affirmatively, so the hub can tell "this process
    swept the app and found nothing" from "no process mentioned the app at
    all" (only the first is resolution). Errors are scrubbed and bounded
    at this boundary like every other envelope's (SPEC section 11,
    rule 10 extended)."""
    out: dict = {
        "schema": SCHEMA_FINDINGS,
        "host": host or env.HOST,
        "observed_at": now,
        "status": "partial" if errors else "ok",
    }
    if errors:
        out["errors"] = [env.reason(entry) for entry in errors]
    out["findings"] = findings
    out["unobserved"] = unobserved
    if locators:
        out["locators"] = locators
    return out
