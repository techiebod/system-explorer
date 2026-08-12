#!/usr/bin/env python3
"""Release gate: walk deployed agents and hold live envelopes to the contract.

Conformance validates hand-written fixtures, which are correct by
construction — they cannot catch a route resolving to the wrong handler, a
filter answering a typo with a clean empty page, or an adapter emitting a
relationship type the schema never published. All three shipped while the
suite was green (2026-08-12). This walks the real surface instead:

  1. /v1/capabilities, /v1/status, /v1/facts validate against their schemas.
  2. AVAILABILITY REGRESSION: every collection capabilities calls available
     must answer /v1/status without an `error` entry, and its collection
     page must not be an error envelope. A collection that was observable
     and stops being so is a failure here even though the error envelope
     itself is schema-valid — /v1/status saying "partial" to nobody is how
     the vms adapter stayed dark for 17 hours.
  3. Object detail: the first item of every collection page is fetched as an
     observation and validated — relationships live only on the detail
     route, so a collection-only sweep sees zero edges.
  4. Evidence is fetched via the envelope's own evidence_ref, followed
     verbatim, so the walk works across the route migration.

The VM lab cannot exercise most of this (no docker socket, no libvirt, no
zpool — ROADMAP section 5), which is why this targets deployed agents.
Read-only throughout: every request is a GET the UI makes anyway.

Usage: live-check.py http://agent-a:8091 http://agent-b:8091 ...
Exit 0 all good; 1 any validation failure or availability regression.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import jsonschema

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schema"

# Keyed by each schema's own discriminator (properties.schema.const), so a
# renamed or added schema updates this map by existing rather than by a
# hand-maintained table drifting from conformance/common.py's — a false
# "unknown schema" from this gate would block a release over nothing.
# Validators are compiled once: jsonschema.validate() re-checks and
# re-builds per call, and a fleet walk validates hundreds of payloads
# against five fixed schemas.
VALIDATORS = {
    schema["properties"]["schema"]["const"]: jsonschema.Draft202012Validator(schema)
    for schema in (json.loads(path.read_text())
                   for path in sorted(SCHEMA_DIR.glob("*.schema.json")))
    if "schema" in schema.get("properties", {})
}


class Report:
    def __init__(self) -> None:
        self.routes = 0
        self.failures: list[str] = []

    def fail(self, line: str) -> None:
        self.failures.append(line)
        print(f"  FAIL {line}")


def validate(report: Report, payload: dict, where: str) -> None:
    """Validate a payload against the schema its own discriminator names."""
    declared = payload.get("schema")
    validator = VALIDATORS.get(declared)
    if validator is None:
        report.fail(f"{where}: undeclared or unknown schema {declared!r}")
        return
    for exc in validator.iter_errors(payload):
        report.fail(f"{where}: {declared} invalid at "
                    f"{'/'.join(str(p) for p in exc.absolute_path)}: {exc.message[:160]}")
        break


def get(client: httpx.Client, report: Report, path: str) -> dict | None:
    report.routes += 1
    try:
        response = client.get(path)
    except httpx.HTTPError as exc:
        report.fail(f"GET {path}: {type(exc).__name__}: {exc}")
        return None
    if response.status_code != 200:
        report.fail(f"GET {path}: HTTP {response.status_code}")
        return None
    return response.json()


def available_collections(capabilities: dict) -> list[tuple[str, str]]:
    out = []
    for name, sub in capabilities.get("subsystems", {}).items():
        if not sub.get("available"):
            continue
        unavailable = sub.get("unavailable_collections", {})
        out.extend((name, coll) for coll in sub.get("collections", [])
                   if coll not in unavailable)
    return out


def check_agent(base: str) -> Report:
    report = Report()
    print(f"== {base}")
    with httpx.Client(base_url=base, timeout=30.0) as client:
        capabilities = get(client, report, "/v1/capabilities")
        if capabilities is None:
            return report
        validate(report, capabilities, "/v1/capabilities")

        status = get(client, report, "/v1/status")
        if status is not None:
            validate(report, status, "/v1/status")

        facts = get(client, report, "/v1/facts")
        if facts is not None:
            validate(report, facts, "/v1/facts")

        findings = get(client, report, "/v1/findings")
        if findings is not None:
            validate(report, findings, "/v1/findings")
            # The unobserved list is the member the hub's lifecycle relies
            # on (SPEC section 6.3): a collection capabilities calls
            # available must not be unevaluable for findings — that skew
            # is an availability regression wearing the honest envelope.
            unevaluable = {(entry["subsystem"], entry["collection"])
                           for entry in findings.get("unobserved", [])}
            for pair in available_collections(capabilities):
                if pair in unevaluable:
                    report.fail(f"/v1/findings: {pair[0]}/{pair[1]} is available"
                                " per capabilities but unobserved in the sweep")

        for subsystem, collection in available_collections(capabilities):
            where = f"/v1/{subsystem}/{collection}"

            # Availability regression, status side: available in
            # capabilities must not be an error entry in the roll-up.
            entry = (status or {}).get("subsystems", {}).get(subsystem, {}).get(collection)
            if entry is not None and "error" in entry:
                report.fail(f"{where}: capabilities says available, /v1/status says "
                            f"error: {entry['error']}")

            page = get(client, report, f"{where}?limit=3")
            if page is None:
                continue
            validate(report, page, where)
            if page.get("status") == "error":
                report.fail(f"{where}: capabilities says available, collection "
                            f"answers an error envelope: {page.get('errors')}")
                continue

            items = page.get("items", [])
            if not items:
                continue
            object_id = items[0]["id"]
            obs = get(client, report, f"{where}/{object_id}")
            if obs is None:
                continue
            validate(report, obs, f"{where}/{object_id}")
            # get_object turns any adapter exception into a schema-valid
            # error observation at HTTP 200, so without this check the gate
            # would print ok while object detail is dark fleet-wide — the
            # exact regression class this file was written for, on the leg
            # where the relationships actually live.
            if obs.get("status") == "error":
                report.fail(f"{where}/{object_id}: object detail is an error "
                            f"observation: {obs.get('errors')}")
                continue
            ref = obs.get("evidence_ref")
            if ref:
                evidence = get(client, report, ref)
                if evidence is not None and "error" in evidence:
                    report.fail(f"{ref}: evidence error: {evidence['error']}")

    verdict = "ok" if not report.failures else f"{len(report.failures)} FAILURES"
    print(f"   {report.routes} routes, {verdict}")
    return report


def main() -> int:
    bases = sys.argv[1:]
    if not bases:
        print(__doc__)
        return 2
    reports = [check_agent(base) for base in bases]
    total = sum(len(r.failures) for r in reports)
    print(f"== {len(bases)} agents, {sum(r.routes for r in reports)} routes, "
          f"{total} failures")
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
