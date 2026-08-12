"""Shared paths, schema loading, and invariant helpers for the conformance suite.

The suite is the teeth of docs/SPEC.md section 11: adapters cannot merge red.
It exercises the contract three ways: schema validity, fixture invariants,
and source lint over the agent and UI sources. Rule evaluators
(system_explorer/agent/rules/) are pure and are tested directly in
test_rules.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

CONFORMANCE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = CONFORMANCE_DIR.parent
SRC_DIR = PROJECT_DIR / "src"
PACKAGE_DIR = SRC_DIR / "system_explorer"
# The schemas stay at the repo root: they are the published contract, read by
# these tests and by anyone implementing against it, and nothing serves them
# at runtime — so they are not package data.
SCHEMA_DIR = PROJECT_DIR / "schema"
EXAMPLES_DIR = SCHEMA_DIR / "examples"
AGENT_DIR = PACKAGE_DIR / "agent"
UI_DIR = PACKAGE_DIR / "ui"

SCHEMA_FILES = {
    "se.observation/1": SCHEMA_DIR / "observation.schema.json",
    "se.collection/1": SCHEMA_DIR / "collection.schema.json",
    "se.status/1": SCHEMA_DIR / "status.schema.json",
    "se.changes/1": SCHEMA_DIR / "changes.schema.json",
    "se.facts/1": SCHEMA_DIR / "facts.schema.json",
    "se.capabilities/1": SCHEMA_DIR / "capabilities.schema.json",
    "se.hub-hosts/1": SCHEMA_DIR / "hub-hosts.schema.json",
    "se.evidence/1": SCHEMA_DIR / "evidence.schema.json",
}

SCHEMAS: dict[str, dict] = {
    schema_id: json.loads(path.read_text()) for schema_id, path in SCHEMA_FILES.items()
}

# The published schemas deliberately permit unknown members, because a hub
# fans out across agents of different versions and a consumer that rejects an
# envelope for carrying a field it does not know is not conformant (SPEC
# section 5.1). Losing that check on the wire must not license this agent to
# emit whatever it likes, so strictness moves to the producer: the same
# schemas, every declared object closed, applied only to our own fixtures.
#
# Published schema = the consumer contract. Strict profile = the producer
# contract. An undeclared or misspelt field still fails CI.
#
# Anything already carrying additionalProperties is left alone, which is how
# status.schema.json's `counts` stays closed in both profiles: its keys ARE
# the severity levels, so a new one is a break and must fail everywhere.
def strict(schema: Any) -> Any:
    """A copy of `schema` with every object that declares properties closed."""
    if isinstance(schema, list):
        return [strict(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    out = {key: strict(value) for key, value in schema.items()}
    if (out.get("type") == "object" and "properties" in out
            and "additionalProperties" not in out):
        out["additionalProperties"] = False
    return out

# SPEC section 2 rule 8 / section 11 rule 5: parsing human-readable command
# output is forbidden. subprocess is permitted only for these commands, and
# only with their structured-output flag present in the same argv literal.
# Adapters add entries here deliberately, in review — never by broadening a
# pattern. (smartctl joined 2026-08-09 when the lint learned to extract argv
# heads; it had been invoked unlisted since the hardware adapter landed —
# the exact ride-along the old some-command-appears check could not see.)
# SPEC section 11 rule 9's escape hatch: a path an adapter reads that a named
# TOOL reproduces, rather than a cat an administrator would ever type. Keyed
# "<module>:<path prefix>", because a family is the unit a reviewer can judge.
# Same discipline as SUBPROCESS_ALLOWLIST: deliberate reviewed additions, never
# a broadened pattern, and never a way to make the lint quiet.
#
# A reason beginning "TODO" marks a family with no verified reference command
# yet; test_the_unverified_backlog_only_shrinks holds that count to a number a
# commit can only move down. It is zero today because the lint landed with its
# gaps closed rather than suppressed.
PATH_REFERENCE_EXEMPTIONS: dict[str, str] = {
    "hardware:/sys/devices/virtual/dmi/id":
        "dmidecode -t system reads this DMI table and is named in "
        "PLATFORM_REFERENCE. Catting the raw attributes is not what an "
        "administrator would run, and the decoded output is the reproduction.",
    "hardware:/run/system-explorer-smart":
        "written by the module's own root SMART collector (grantDiskAccess), "
        "not by the system. The reproducible command is smartctl -H -A "
        "/dev/<disk>, already named — the snapshot is this product's plumbing.",
    "network:/run/system-explorer-tailscale":
        "written by the module's own root tailscale collector "
        "(grantTailscaleAccess). The reproducible command is "
        "tailscale status --json, already named.",
}

# Modules whose reads cannot be resolved statically at all, listed so that
# unresolvability is a reviewed decision rather than a silent pass.
UNLINTABLE_READ_MODULES: dict[str, str] = {
    "nix": "every read is rooted at a generation target obtained from "
           "os.readlink(/nix/var/nix/profiles/system-<n>-link) — a /nix/store "
           "path that exists only at runtime, so no literal prefix can be "
           "resolved from the source. GENERATIONS_REFERENCE names the profile "
           "directory and the readlink, which is the reproducible form an "
           "administrator would actually run.",
}

# The ratchet. Only ever lower this.
UNVERIFIED_REFERENCE_BUDGET = 0

# Adapters whose get_evidence serves a payload with no credential surface, so
# it passes through unredacted. Same review discipline as SUBPROCESS_ALLOWLIST
# below: entries are deliberate, reviewed additions, and each reason has to be
# specific enough to be falsifiable. "Probably fine" is not a reason.
#
# The list exists because the exposure was found by an adversarial design pass,
# not by the suite: units served a service's Environment= verbatim, and while
# writing this table system turned out to be serving the manager-wide one.
# Whether an evidence payload can carry a secret is now a question someone has
# to answer in writing before an adapter ships.
EVIDENCE_REDACTION_EXEMPTIONS: dict[str, str] = {
    "logs": "a journal record IS the line the operator asked to see; there is "
            "no key/value structure to redact and censoring the message would "
            "defeat the collection.",
    "hardware": "sysfs attributes and udev properties — device identity, "
                "model, firmware, SMART counters. No credential surface.",
    "packages": "names, versions and store paths from the link farm.",
    "nix": "generation manifests and deployment receipts: store paths, kernel "
           "versions, unit names.",
    "storage": "lsblk/zpool/findmnt documents. ZFS keylocation names WHERE key "
               "material lives, never the key itself.",
    "network": "an `ip -j` dump, an nft ruleset, or a tailscale status "
               "snapshot — which carries node PUBLIC keys and DERP topology. "
               "The one member worth watching is AuthURL, a single-use login "
               "URL present only while the node is logged out.",
    "vms": "libvirt domain XML from XMLDesc(0). Flag 0 omits "
           "VIR_DOMAIN_XML_SECURE material such as <graphics passwd=...>, and "
           "a read-only connection cannot request it. That premise is what "
           "test_domain_xml_is_requested_without_the_secure_flag holds.",
}

SUBPROCESS_ALLOWLIST: dict[str, str] = {
    "zpool": "-j",
    "zfs": "-j",
    "lsblk": "-J",
    "findmnt": "-J",
    "ip": "-j",
    "nft": "-j",
    "journalctl": "-o json",
    "networkctl": "--json=short",
    "udevadm": "--json=short",
    "lscpu": "-J",
    "smartctl": "--json=c",
    # iproute2's bridge(8): the forwarding database is what attributes a veth
    # to the container behind it, and it speaks JSON.
    "bridge": "-j",
    # Neither dpkg nor rpm has a --json, but both take a FORMAT STRING supplied
    # by the caller — which is the opposite of parsing human output: the fields
    # and their order are ours and cannot drift under a locale or a version.
    # That is what is allow-listed here, not the tool.
    "dpkg-query": "-f",
    "rpm": "--qf",
}


def example_files() -> list[Path]:
    return sorted(EXAMPLES_DIR.glob("*.json"))


def load_example(path: Path) -> dict:
    return json.loads(path.read_text())


def resolve_fact_path(facts: dict, path: str) -> Any:
    """Resolve a dotted evidence path ('vdevs.degraded') within facts.

    Raises KeyError with a useful message when the path does not resolve —
    an opinion citing evidence that is not in the envelope is a contract
    violation, not a soft miss.
    """
    node: Any = facts
    walked: list[str] = []
    for part in path.split("."):
        walked.append(part)
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            raise KeyError(
                f"evidence path {path!r} does not resolve: "
                f"{'.'.join(walked)!r} not found in facts"
            )
    return node


def assert_stable_ids(collect: Callable[[], dict], rounds: int = 2) -> None:
    """SPEC section 11 rule 7: unchanged objects keep their IDs across collections.

    Phase 1 adapter tests call this with a live collect() function. Object
    churn between rounds is tolerated (units genuinely start and stop); an
    ID appearing in every round under a different native_id, or a native_id
    changing its ID, is not.
    """
    pages = [collect() for _ in range(rounds)]
    mappings: list[dict[str, str]] = [
        {item["id"]: item["native_id"] for item in page["items"]} for page in pages
    ]
    for later in mappings[1:]:
        for object_id in mappings[0].keys() & later.keys():
            assert mappings[0][object_id] == later[object_id], (
                f"object id {object_id!r} changed native identity between "
                f"collections: {mappings[0][object_id]!r} -> {later[object_id]!r}"
            )
