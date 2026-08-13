"""SPEC section 11, rule 8: the rulebook is exercised directly.

Characteristic fact dicts in, opinions out — no acquisition, no fixtures.
Every case asserts which keys fire at which levels, healthy shapes fire
nothing, and each emitted citation resolves into the very facts that
produced it (SPEC section 2, rule 3: evidence before opinion). Purity and
absent-fact tolerance are enforced structurally over every module in
agent/rules/, so a new evaluator is born under both invariants.
"""

import ast
import importlib
import pkgutil
import re
import sys

import pytest

from common import AGENT_DIR, UI_DIR, resolve_fact_path

from system_explorer.agent import rules
from system_explorer.agent.rules import (bazarr, docker, downloaders,
                                         hardware, kea, logs, network, nix,
                                         paperless, plex, protection, resources,
                                         servarr, storage, system, traefik, units,
                                         vms)

RULES_DIR = AGENT_DIR / "rules"


# ---------------------------------------------------------------------------
# Characteristic inputs: (case id, evaluator, facts, expected {(key, level)}).
# Facts mirror what the owning adapter puts in the envelope, including the
# neighbours each rule cites as evidence. An empty expected set is the
# healthy case: the evaluator must stay silent.
# ---------------------------------------------------------------------------

CASES = [
    # protection: the five states graded. Built-and-green is quiet, admitted
    # debt is info, an irreplaceable target with no durable copy is warn, a
    # restore tried and failed is worse than one never tried, and a job that
    # has never once succeeded is the only critical here.
    ("protection-fully-built-and-proven", protection.target_opinions,
     {"Class": "backup", "Destinations": ["offsite"],
      "IndependentDestinations": ["offsite"],
      "ImplementedHops": ["offsite"], "ProvenRungs": ["offsite"],
      "LastProvenAt": ["offsite: 2026-08-13"]}, set()),
    ("protection-unbuilt-hop-is-admitted-debt", protection.target_opinions,
     {"Class": "replicate", "Destinations": ["near", "offsite"],
      "IndependentDestinations": ["offsite"],
      "UnimplementedHops": ["offsite"],
      "LastProvenAt": ["offsite: 2026-08-13"]},
     {("protection-hop-unimplemented", "info")}),
    # Proven from the rung an operator reaches for FIRST, which is not a
    # destination and survives neither the disk nor the site. A single
    # cross-rung date reads this as a proven target.
    ("protection-proven-at-one-rung-only", protection.target_opinions,
     {"Class": "backup", "Destinations": ["near", "offsite"],
      "IndependentDestinations": ["offsite"],
      "ImplementedHops": ["near", "offsite"],
      "ProvenRungs": ["local-snapshots"],
      "UnprovenRungs": ["near", "offsite"],
      "LastProvenAt": ["local-snapshots: 2026-08-13"]},
     {("protection-unproven", "info")}),
    # Proven off-site and NOT from the near rung: the estate's live shape.
    ("protection-proven-off-site-with-a-rung-unproven",
     protection.target_opinions,
     {"Class": "backup", "Destinations": ["near", "offsite"],
      "IndependentDestinations": ["offsite"],
      "ImplementedHops": ["near", "offsite"],
      "ProvenRungs": ["offsite"], "UnprovenRungs": ["near"],
      "LastProvenAt": ["offsite: 2026-08-13"]},
     {("protection-unproven", "info")}),
    # Tried and failed is not never-tried, and is worse.
    ("protection-restore-tried-and-failed", protection.target_opinions,
     {"Class": "backup", "Destinations": ["near", "offsite"],
      "IndependentDestinations": ["offsite"],
      "ImplementedHops": ["near", "offsite"],
      "UnprovenRungs": ["near", "offsite"],
      "FailedProofRungs": ["offsite"], "LastFailedProofAt": "2026-08-13",
      "ProofRecord": "docs/recovery-proofs.md"},
     {("protection-proof-failed", "warn"), ("protection-unproven", "info")}),
    ("protection-irreplaceable-with-no-durable-copy",
     protection.target_opinions,
     {"Class": "backup", "Kind": "zfs-dataset",
      "Destinations": ["near", "offsite"],
      "IndependentDestinations": ["offsite"],
      "ImplementedHops": ["near"], "UnimplementedHops": ["offsite"]},
     {("protection-no-durable-copy", "warn"),
      ("protection-unproven", "info")}),
    # Same class, same unbuilt hop, DIFFERENT kind: a provider still holds
    # the tree, so the loss is the deletion history rather than the data.
    # Grading it beside the row above overstates two of the estate's rows
    # and teaches the operator to distrust the severity column.
    ("protection-cloud-mirror-loses-only-its-history",
     protection.target_opinions,
     {"Class": "backup", "Kind": "saas-pull",
      "Destinations": ["near", "offsite"],
      "IndependentDestinations": ["offsite"],
      "ImplementedHops": ["near"], "UnimplementedHops": ["offsite"]},
     {("protection-no-durable-history", "info"),
      ("protection-unproven", "info")}),
    ("protection-green-but-never-restored", protection.target_opinions,
     {"Class": "backup", "Destinations": ["offsite"],
      "IndependentDestinations": ["offsite"],
      "ImplementedHops": ["offsite"], "UnprovenRungs": ["offsite"]},
     {("protection-unproven", "info")}),
    ("protection-job-green", protection.job_opinions,
     {"Job": "example", "State": "ok", "Basis": "last-success",
      "AgeSeconds": 3600, "MaxAgeSeconds": 90000,
      "LastResult": "success", "TargetClass": "backup"}, set()),
    ("protection-job-never-succeeded-irreplaceable", protection.job_opinions,
     {"Job": "example", "State": "stale",
      "Basis": "registered-never-succeeded", "AgeSeconds": 200000,
      "MaxAgeSeconds": 90000, "TargetClass": "backup"},
     {("protection-never-succeeded", "critical")}),
    ("protection-job-never-succeeded-derived", protection.job_opinions,
     {"Job": "example", "State": "stale",
      "Basis": "registered-never-succeeded", "AgeSeconds": 200000,
      "MaxAgeSeconds": 90000, "TargetClass": "replicate"},
     {("protection-never-succeeded", "warn")}),
    ("protection-job-stale-after-success", protection.job_opinions,
     {"Job": "example", "State": "stale", "Basis": "last-success",
      "AgeSeconds": 200000, "MaxAgeSeconds": 90000,
      "LastSuccessAt": "2026-08-01T02:00:00+00:00"},
     {("protection-stale", "warn")}),
    ("protection-job-failed-inside-its-window", protection.job_opinions,
     {"Job": "example", "State": "ok", "Basis": "last-success",
      "AgeSeconds": 3600, "MaxAgeSeconds": 90000, "LastResult": "exit-code",
      "LastFinishedAt": "2026-08-13T04:00:00+00:00"},
     {("protection-last-run-failed", "warn")}),
    # A failed run with no success behind it is not the row above: it is
    # unstale only because its first window has not passed yet.
    ("protection-job-first-run-failed-inside-its-window",
     protection.job_opinions,
     {"Job": "example", "State": "ok", "Basis": "registered-never-succeeded",
      "AgeSeconds": 7200, "MaxAgeSeconds": 129600, "LastResult": "exit-code",
      "LastFinishedAt": "2026-08-13T01:00:00+00:00", "TargetClass": "backup"},
     {("protection-first-run-failed", "warn")}),
    # The class did not join: the gentler grade is deliberate AND stated.
    ("protection-job-never-succeeded-class-unjoined", protection.job_opinions,
     {"Job": "example-offsite", "State": "stale",
      "Basis": "registered-never-succeeded", "AgeSeconds": 200000,
      "MaxAgeSeconds": 90000,
      "TargetClassUnjoined": "no declared target names this job"},
     {("protection-never-succeeded", "warn")}),
    # A verdict nobody has recomputed is not a current green row.
    ("protection-job-verdict-frozen", protection.job_opinions,
     {"Job": "example", "State": "ok", "Basis": "last-success",
      "AgeSeconds": 3600, "MaxAgeSeconds": 90000, "LastResult": "success",
      "CheckedAt": "2026-07-04T11:18:36Z", "CheckedAgeSeconds": 3456000,
      "TargetClass": "backup"},
     {("protection-verdict-stale", "warn")}),
    # A receipt that exists and will not open is not a job that never ran.
    ("protection-job-receipt-unreadable", protection.job_opinions,
     {"Job": "example", "State": "ok", "Basis": "last-success",
      "AgeSeconds": 3600, "MaxAgeSeconds": 90000,
      "ReceiptsUnobservable": "example.last-success.json: JSONDecodeError: "
                              "Expecting ',' delimiter: line 1 column 25"},
     {("protection-receipt-unreadable", "warn")}),
    # kea: pool arithmetic that fails silently when it runs out.
    ("kea-pool-comfortable", kea.subnet_opinions,
     {"SubnetId": 1, "Subnet": "192.0.2.0/24", "TotalAddresses": 200,
      "AssignedAddresses": 100, "DeclinedAddresses": 0}, set()),
    ("kea-pool-tight", kea.subnet_opinions,
     {"SubnetId": 1, "TotalAddresses": 200, "AssignedAddresses": 181},
     {("kea-pool-capacity", "warn")}),
    ("kea-pool-dry", kea.subnet_opinions,
     {"SubnetId": 1, "TotalAddresses": 200, "AssignedAddresses": 192},
     {("kea-pool-capacity", "critical")}),
    ("kea-declined-ground", kea.subnet_opinions,
     {"SubnetId": 1, "TotalAddresses": 200, "AssignedAddresses": 10,
      "DeclinedAddresses": 3},
     {("kea-declined", "warn")}),

    # plex family: activity is not health; only configured-but-dark alarms.
    ("plex-server-reachable", plex.server_opinions,
     {"FriendlyName": "example", "Version": "1.41.0"}, set()),
    ("plex-server-dark", plex.server_opinions,
     {"StatusUnobservable": "ConnectError: connection refused"},
     {("plex-unreachable", "critical")}),
    ("plex-server-tokenless", plex.server_opinions,
     {"ConfigMissing": ["SE_PLEX_TOKEN"]},
     {("plex-unconfigured", "warn")}),
    ("plex-request-pending-is-info", plex.request_opinions,
     {"Status": "pending", "Type": "movie"},
     {("request-pending", "info")}),
    ("plex-request-approved-quiet", plex.request_opinions,
     {"Status": "approved", "Type": "tv"}, set()),

    # bazarr: an ungraded health list mirrors as one warn carrying it.
    ("bazarr-clean", bazarr.instance_opinions,
     {"Version": "1.4.5", "HealthIssues": []}, set()),
    ("bazarr-issues", bazarr.instance_opinions,
     {"Version": "1.4.5",
      "HealthIssues": ["Sonarr is not available", "wanted search failed"]},
     {("bazarr-health", "warn")}),
    ("bazarr-dark", bazarr.instance_opinions,
     {"StatusUnobservable": "ConnectError: connection refused"},
     {("bazarr-unreachable", "critical")}),

    # units, slices: interior cgroup nodes, where the number is an aggregate
    # over everything nested under them. A slice's "full" share only counts
    # time in which every non-idle task under it was stalled, so a member
    # making progress lowers it: the slice is the less specific AND smaller
    # statement of the same condition, and saying it again is noise. Whether
    # a member accounts for it is a fact the adapter joins inside its own
    # collection; these cases fix what the rule does with each answer.
    ("slice-stall-a-member-accounts-for-says-nothing",
     resources.slice_opinions,
     {"ActiveState": "active", "PsiIoFullAvg60": 56.35,
      "StallExplainedBy": {"PsiIoFullAvg60": "docker-4d1f9c02ab77.scope"}},
     set()),
    # The case no member row can state, and the reason the slice keeps an
    # opinion at all — so it is also the only one of the three that claims
    # attention. At info, envelope.attention() strips it and the condition
    # reaches neither /v1/findings nor the estate roll-up nor the row's dot:
    # the vaguer stall a member's own row already warns about would alert,
    # and this one, which nothing else states, would not.
    ("slice-stall-no-member-accounts-for", resources.slice_opinions,
     {"ActiveState": "active", "PsiIoFullAvg60": 33.43,
      "StallUnexplained": {
          "PsiIoFullAvg60": "every member cgroup under this slice was read "
                            "for I/O pressure (12 of them) and the highest, "
                            "example-worker.service at 4.1%, is below this "
                            "slice's own 33.43%."}},
     {("slice-stall-unexplained", "warn")}),
    # The bar is the one a single unit must clear, not the floor: between the
    # two the finding is real but too small to be woken for, and the floor's
    # "coin toss dressed as a finding" reasoning stays where it was.
    ("slice-stall-unexplained-under-the-attention-bar",
     resources.slice_opinions,
     {"ActiveState": "active", "PsiIoFullAvg60": 4.2,
      "StallUnexplained": {
          "PsiIoFullAvg60": "every member cgroup under this slice was read "
                            "for I/O pressure (12 of them) and the highest, "
                            "example-worker.service at 0.3%, is below this "
                            "slice's own 4.2%."}},
     {("slice-stall-unexplained", "info")}),
    # A member whose pressure could not be read is not a member that is
    # quiet. Reporting this as "nothing inside explains it" would invent the
    # interesting finding out of a gap in the reading, so it gets its own key
    # and its own wording.
    ("slice-stall-attribution-unobservable", resources.slice_opinions,
     {"ActiveState": "active", "PsiMemoryFullAvg60": 4.1,
      "StallAttributionUnobservable": {
          "PsiMemoryFullAvg60": "no memory pressure reading for 2 of the 12 "
                                "member cgroups under this slice "
                                "(example-a.service, example-b.scope), so a "
                                "member could still account for this."}},
     {("slice-stall-unattributed", "info")}),
    # Per resource, not per slice: the same minute can be explained for one
    # reading and unexplained for another, and a single verdict across both
    # would be false for one of them. Also the case where both route hints
    # are picked out of SLICE_STALL_LOOK at once.
    ("slice-stall-explained-for-one-resource-only",
     resources.slice_opinions,
     {"ActiveState": "active", "PsiIoFullAvg60": 56.35,
      "PsiMemoryFullAvg60": 11.02,
      "StallExplainedBy": {"PsiIoFullAvg60": "docker-4d1f9c02ab77.scope"},
      "StallUnexplained": {
          "PsiMemoryFullAvg60": "every member cgroup under this slice was "
                                "read for memory pressure (12 of them) and "
                                "the highest, example-worker.service at 1.2%, "
                                "is below this slice's own 11.02%."}},
     {("slice-stall-unexplained", "warn")}),
    # Facts from something other than this adapter: no attribution either
    # way, so the aggregate wording stands. Silence here would be the
    # inference the three branches above exist to stop anyone making.
    ("slice-stall-without-attribution-keeps-the-aggregate-wording",
     resources.slice_opinions,
     {"ActiveState": "active", "PsiIoFullAvg60": 33.43},
     {("slice-stall", "info")}),
    # Under the floor the difference between a slice and its members is
    # inside the slack two decaying averages carry anyway.
    ("slice-stall-below-the-floor", resources.slice_opinions,
     {"ActiveState": "active", "PsiIoFullAvg60": 0.42,
      "StallUnexplained": {"PsiIoFullAvg60": "every member cgroup under this "
                                             "slice was read for I/O pressure "
                                             "(12 of them) and the highest, "
                                             "example.service at 0.0%, is "
                                             "below this slice's own 0.42%."}},
     set()),
    # State stayed in rules/units when consumption moved out: a failed slice
    # is the slice itself, not an aggregate over anything under it.
    ("slice-failed-is-still-critical", units.slice_unit_opinions,
     {"ActiveState": "failed", "SubState": "failed"},
     {("unit-health", "critical")}),
    ("slice-quiet", resources.slice_opinions,
     {"ActiveState": "active", "PsiIoFullAvg60": 0}, set()),

    # downloaders: the transfer tier's own statements, mirrored.
    ("downloader-client-healthy", downloaders.client_opinions,
     {"Client": "transmission", "Version": "4.0.6",
      "DiskFreeBytes": 500_000_000_000}, set()),
    ("downloader-client-dark", downloaders.client_opinions,
     {"Client": "transmission",
      "StatusUnobservable": "ConnectError: connection refused"},
     {("downloader-unreachable", "critical")}),
    ("downloader-client-keyless", downloaders.client_opinions,
     {"Client": "sabnzbd", "ConfigMissing": ["SE_SABNZBD_API_KEY"]},
     {("downloader-unconfigured", "warn")}),
    ("downloader-disk-tight", downloaders.client_opinions,
     {"Client": "sabnzbd", "DiskTotalBytes": 100, "DiskFreeBytes": 8},
     {("downloader-disk", "warn")}),
    ("downloader-disk-crammed", downloaders.client_opinions,
     {"Client": "sabnzbd", "DiskTotalBytes": 100, "DiskFreeBytes": 4},
     {("downloader-disk", "critical")}),
    ("downloader-queue-paused", downloaders.client_opinions,
     {"Client": "sabnzbd", "Paused": True},
     {("downloader-paused", "warn")}),
    ("transfer-local-error", downloaders.transfer_opinions,
     {"Client": "transmission", "Error": 3,
      "ErrorString": "No data found! Ensure your drives are connected"},
     {("transfer-error", "critical")}),
    ("transfer-tracker-warning-and-stalled", downloaders.transfer_opinions,
     {"Client": "transmission", "Error": 1,
      "ErrorString": "Tracker gave a warning", "IsStalled": True},
     {("transfer-error", "warn"), ("transfer-stalled", "warn")}),
    ("transfer-clean", downloaders.transfer_opinions,
     {"Client": "sabnzbd", "Status": "Downloading"}, set()),

    # servarr: the managers' own self-diagnosis, mirrored.
    ("servarr-app-clean", servarr.app_opinions,
     {"App": "example-manager", "Version": "4.0.0", "HealthErrors": 0,
      "HealthWarnings": 0, "QueueTotal": 3}, set()),
    ("servarr-app-self-reported-warnings", servarr.app_opinions,
     {"App": "example-manager", "HealthErrors": 0, "HealthWarnings": 2},
     {("servarr-health", "warn")}),
    ("servarr-app-self-reported-errors", servarr.app_opinions,
     {"App": "example-manager", "HealthErrors": 1, "HealthWarnings": 2},
     {("servarr-health", "critical")}),
    ("servarr-app-unconfigured", servarr.app_opinions,
     {"App": "example-manager", "ConfigMissing": ["SE_EXAMPLE_MANAGER_URL"]},
     {("servarr-unconfigured", "warn")}),
    ("servarr-app-dark", servarr.app_opinions,
     {"App": "example-manager",
      "StatusUnobservable": "ConnectError: connection refused"},
     {("servarr-unreachable", "critical")}),
    ("servarr-health-error-mirrors-critical", servarr.health_opinions,
     {"App": "example-manager", "Source": "DownloadClientCheck",
      "Type": "error", "Message": "All download clients are unavailable"},
     {("servarr-health-item", "critical")}),
    ("servarr-health-warning-mirrors-warn", servarr.health_opinions,
     {"App": "example-manager", "Source": "IndexerStatusCheck",
      "Type": "warning", "Message": "Indexers unavailable due to failures"},
     {("servarr-health-item", "warn")}),
    ("servarr-queue-stuck-import", servarr.queue_opinions,
     {"App": "example-manager", "TrackedDownloadStatus": "warning",
      "TrackedDownloadState": "importBlocked",
      "StatusMessages": "Found archive file, might need to be extracted"},
     {("queue-item-stuck", "warn")}),
    ("servarr-queue-clean", servarr.queue_opinions,
     {"App": "example-manager", "TrackedDownloadStatus": "ok",
      "TrackedDownloadState": "downloading"}, set()),

    # traefik: the ingress speaks for itself.
    ("traefik-router-clean", traefik.router_opinions,
     {"Rule": "Host(`app.example.internal`)", "Status": "enabled",
      "Service": "app@docker"}, set()),
    ("traefik-router-rejected", traefik.router_opinions,
     {"Rule": "Host(`app.example.internal`)", "Status": "disabled",
      "Error": ["middleware \"missing@docker\" does not exist"]},
     {("router-error", "critical"), ("router-disabled", "warn")}),
    ("traefik-router-warning-still-routes", traefik.router_opinions,
     {"Rule": "Host(`app.example.internal`)", "Status": "warning",
      "Error": ["entryPoint \"typo\" doesn't exist"]},
     {("router-warning", "warn")}),
    ("traefik-service-degraded", traefik.service_opinions,
     {"Status": "enabled", "ServersUp": 1, "ServersDown": 1,
      "DownServers": ["http://172.18.0.9:8000"]},
     {("service-servers-down", "warn")}),
    ("traefik-service-dead", traefik.service_opinions,
     {"Status": "enabled", "ServersUp": 0, "ServersDown": 2,
      "DownServers": ["http://172.18.0.9:8000", "http://172.18.0.10:8000"]},
     {("service-servers-down", "critical")}),
    ("traefik-overview-middleware-errors", traefik.overview_opinions,
     {"MiddlewaresTotal": 4, "MiddlewaresErrors": 1},
     {("middlewares-errors", "warn")}),
    ("traefik-overview-clean", traefik.overview_opinions,
     {"MiddlewaresTotal": 4, "MiddlewaresErrors": 0}, set()),

    # paperless: the archive's own answers, not its wrapper's.
    ("paperless-healthy", paperless.instance_opinions,
     {"DocumentCount": 38, "InboxCount": 2, "DatabaseStatus": "OK",
      "RedisStatus": "OK", "CeleryStatus": "OK"}, set()),
    ("paperless-emptied-library", paperless.instance_opinions,
     {"DocumentCount": 0, "DatabaseStatus": "OK"},
     {("paperless-empty", "critical")}),
    ("paperless-database-error", paperless.instance_opinions,
     {"DocumentCount": 38, "DatabaseStatus": "ERROR",
      "DatabaseError": "connection refused"},
     {("paperless-database", "critical")}),
    ("paperless-classifier-warning", paperless.instance_opinions,
     {"DocumentCount": 38, "ClassifierStatus": "WARNING",
      "ClassifierError": "too little training data"},
     {("paperless-classifier", "warn")}),
    ("paperless-storage-tight", paperless.instance_opinions,
     {"DocumentCount": 38, "StorageTotalBytes": 100, "StorageAvailableBytes": 8},
     {("paperless-storage", "warn")}),

    # storage: mounts and datasets share the 90/95 capacity ladder.
    ("mount-92-warn", storage.mount_opinions,
     {"UsePercent": 92}, {("mount-capacity", "warn")}),
    ("mount-95-critical", storage.mount_opinions,
     {"UsePercent": 95}, {("mount-capacity", "critical")}),
    ("mount-healthy", storage.mount_opinions,
     {"UsePercent": 41}, set()),
    ("mount-unreadable-quiet", storage.mount_opinions,
     {"UsePercent": None}, set()),
    ("dataset-97-critical", storage.dataset_opinions,
     {"UsePercent": 97}, {("dataset-capacity", "critical")}),
    ("dataset-healthy", storage.dataset_opinions,
     {"UsePercent": 12}, set()),

    # storage: md arrays.
    ("array-degraded", storage.array_opinions,
     {"Degraded": 1, "RaidDisks": 4, "SyncAction": "idle", "SyncPercent": None,
      "Members": [{"Device": "block-device:sda1", "Errors": 0}]},
     {("array-degraded", "critical")}),
    ("array-member-errors", storage.array_opinions,
     {"Degraded": 0, "RaidDisks": 2, "SyncAction": "idle", "SyncPercent": None,
      "Members": [{"Device": "block-device:sdb1", "Errors": 12}]},
     {("array-member-errors", "warn")}),
    ("array-recover-warns", storage.array_opinions,
     {"Degraded": 0, "RaidDisks": 2, "SyncAction": "recover", "SyncPercent": 40,
      "Members": []},
     {("array-sync", "warn")}),
    ("array-check-info", storage.array_opinions,
     {"Degraded": 0, "RaidDisks": 2, "SyncAction": "check", "SyncPercent": 7,
      "Members": []},
     {("array-sync", "info")}),
    ("array-healthy", storage.array_opinions,
     {"Degraded": 0, "RaidDisks": 2, "SyncAction": "idle", "SyncPercent": None,
      "Members": [{"Device": "block-device:sda1", "Errors": 0}]},
     set()),

    # storage: zpools — the row/detail divergence that motivated the rulebook.
    ("pool-92-critical", storage.pool_opinions,
     {"State": "ONLINE", "CapacityPercent": 92, "Vdevs": [],
      "UnhealthyVdevs": [], "VdevsWithErrors": [], "ScanState": None,
      "ScanFunction": None},
     {("pool-capacity", "critical")}),
    ("pool-84-warn", storage.pool_opinions,
     {"State": "ONLINE", "CapacityPercent": 84, "Vdevs": [],
      "UnhealthyVdevs": [], "VdevsWithErrors": [], "ScanState": None,
      "ScanFunction": None},
     {("pool-capacity", "warn")}),
    ("pool-degraded", storage.pool_opinions,
     {"State": "DEGRADED", "CapacityPercent": 40,
      "Vdevs": [{"Name": "mirror-0", "State": "DEGRADED"}],
      "UnhealthyVdevs": ["mirror-0"], "VdevsWithErrors": [],
      "ScanState": None, "ScanFunction": None},
     {("pool-health", "critical"), ("vdev-health", "critical")}),
    ("pool-vdev-errors-scrubbing", storage.pool_opinions,
     {"State": "ONLINE", "CapacityPercent": 40,
      "Vdevs": [{"Name": "sda", "State": "ONLINE"}],
      "UnhealthyVdevs": [], "VdevsWithErrors": ["sda"],
      "ScanState": "SCANNING", "ScanFunction": "SCRUB"},
     {("vdev-errors", "warn"), ("pool-scan", "info")}),
    ("pool-healthy", storage.pool_opinions,
     {"State": "ONLINE", "CapacityPercent": 40, "Vdevs": [],
      "UnhealthyVdevs": [], "VdevsWithErrors": [], "ScanState": None,
      "ScanFunction": None},
     set()),
    # Scrub staleness: the age is adapter-computed (ScanAgeDays) so the
    # rule needs no clock; the locale-string fallback carries no age and
    # must stay silent — honest degradation, not a guess.
    ("pool-scrub-36-days-stale", storage.pool_opinions,
     {"State": "ONLINE", "CapacityPercent": 40, "Vdevs": [],
      "UnhealthyVdevs": [], "VdevsWithErrors": [],
      "ScanFunction": "SCRUB", "ScanState": "FINISHED",
      "ScanEndTime": "2026-07-04T03:50:21Z", "ScanAgeDays": 36},
     {("pool-scrub-stale", "warn")}),
    # A resilver replaced the scrub's record: the stale rule cannot
    # evaluate, so the pair below turns silence into a stated unknown
    # (backlogged from a foreign shelf reading ScanAgeDays 9 off a
    # resilver while the true scrub age was unknowable).
    ("pool-resilver-record-states-unknown", storage.pool_opinions,
     {"State": "ONLINE", "CapacityPercent": 40, "Vdevs": [],
      "UnhealthyVdevs": [], "VdevsWithErrors": [],
      "ScanFunction": "RESILVER", "ScanState": "FINISHED",
      "ScanEndTime": "2026-08-11T03:50:21Z", "ScanAgeDays": 1,
      "LastScrubEndTime": None,
      "LastScrubEndTimeUnobservable": "the last recorded scan is a resilver, "
      "and ZFS keeps only the most recent scan's record — the time since the "
      "last completed scrub cannot be read from this pool"},
     {("pool-scrub-age-unknown", "info")}),
    ("pool-scrub-34-days-quiet", storage.pool_opinions,
     {"State": "ONLINE", "CapacityPercent": 40, "Vdevs": [],
      "UnhealthyVdevs": [], "VdevsWithErrors": [],
      "ScanFunction": "SCRUB", "ScanState": "FINISHED",
      "ScanEndTime": "2026-07-06T03:50:21Z", "ScanAgeDays": 34},
     set()),
    ("pool-scrub-finished-no-age-quiet", storage.pool_opinions,
     {"State": "ONLINE", "CapacityPercent": 40, "Vdevs": [],
      "UnhealthyVdevs": [], "VdevsWithErrors": [],
      "ScanFunction": "SCRUB", "ScanState": "FINISHED",
      "ScanEndTime": "Sun 1 Feb 16:14:52 GMT 2026"},
     set()),

    # network: a policy-table route that outranks the host's own connected
    # route. A site LAN went dark three times on this before the routes
    # collection could even see the shadowing route — it read main only.
    ("route-shadows-own-lan", network.route_opinions,
     {"Table": "52", "RulePreference": 5270, "Destination": "192.168.123.0/24",
      "Device": "tailscale0", "Family": "ipv4", "ShadowsLocalPrefix": True},
     {("route-shadows-local", "warn")}),
    # The same overlay route on a host that is NOT on that segment: legitimate,
    # and the only reason to accept routes at all.
    ("route-policy-table-not-local", network.route_opinions,
     {"Table": "52", "RulePreference": 5270, "Destination": "192.168.200.0/24",
      "Device": "tailscale0", "Family": "ipv4"},
     set()),
    # Ordinary main-table routes never speak.
    ("route-main-connected", network.route_opinions,
     {"Table": "main", "RulePreference": 32766, "Destination": "192.168.123.0/24",
      "Device": "eno1", "Scope": "link", "Family": "ipv4"},
     set()),
    ("route-default", network.route_opinions,
     {"Table": "main", "Destination": "default", "Device": "eth0",
      "Gateway": "192.168.200.1", "Family": "ipv4"},
     set()),

    # units: a .mount unit systemd invented from the mount table. A storage host
    # carried
    # this for two days with five stacks believing they depended on it.
    # Silent by design: the fact is reported, no opinion is drawn from it. On a
    # container host 50 of these are docker's own overlay mounts.
    ("mount-unit-synthesised", units.mount_unit_opinions,
     {"ActiveState": "active", "SubState": "mounted", "RuntimeSynthesised": True},
     set()),
    ("mount-unit-declared", units.mount_unit_opinions,
     {"ActiveState": "active", "SubState": "mounted"}, set()),

    # vms: a running guest whose address no source could answer for. The row
    # used to say ok beside an empty list, then show the address on the next
    # poll once a ping had repopulated the host's ARP table.
    ("domain-address-unobservable", vms.domain_address_opinions,
     {"State": "running", "IPAddresses": None,
      "IPAddressesUnobservable": "No address source answered: the guest agent "
                                 "is unavailable on a read-only libvirt connection."},
     {("domain-address-unobservable", "info")}),
    ("domain-address-known", vms.domain_address_opinions,
     {"State": "running", "IPAddresses": ["192.168.200.80"]}, set()),
    # A stopped guest has no address because it is off — inapplicable, and the
    # adapter omits the fact rather than nulling it.
    ("domain-stopped-address-quiet", vms.domain_address_opinions,
     {"State": "shut off"}, set()),

    # units.
    ("unit-failed", units.unit_opinions,
     {"ActiveState": "failed", "SubState": "failed", "Result": "exit-code"},
     {("unit-health", "critical")}),
    ("unit-restart-churn", units.unit_opinions,
     {"ActiveState": "active", "SubState": "running",
      "NRestarts": units.RESTART_CHURN_THRESHOLD},
     {("restart-churn", "warn")}),
    ("unit-failed-and-churning", units.unit_opinions,
     {"ActiveState": "failed", "SubState": "failed", "Result": "exit-code",
      "NRestarts": 7},
     {("unit-health", "critical"), ("restart-churn", "warn")}),
    ("unit-healthy", units.unit_opinions,
     {"ActiveState": "active", "SubState": "running", "NRestarts": 0},
     set()),
    # Per-unit PSI: attribution for host-level stall. A running unit is not
    # "healthy" if it spends the minute waiting on a saturated device.
    ("workload-io-stalled", resources.workload_opinions,
     {"ActiveState": "active", "SubState": "running",
      "PsiIoFullAvg60": resources.WORKLOAD_IO_STALL_WARN},
     {("workload-io-stall", "warn")}),
    ("workload-memory-stalled", resources.workload_opinions,
     {"ActiveState": "active", "SubState": "running",
      "PsiMemoryFullAvg60": resources.WORKLOAD_MEMORY_STALL_WARN},
     {("workload-memory-stall", "warn")}),
    # Below threshold, and a kernel with PSI reporting genuine calm: the
    # facts are present and the unit stays silent, which is what makes the
    # opinion mean something when it does fire.
    ("workload-not-stalled", resources.workload_opinions,
     {"PsiIoFullAvg60": 0.0, "PsiCpuSomeAvg60": 0.0, "PsiMemoryFullAvg60": 0.0},
     set()),

    # units: a unit naming another unit that is not present on this host. One
    # shape, three severities, and the split is the point — systemd's own
    # documentation makes an unresolvable Requires= fatal to the start job and
    # an unresolvable Wants= ignored, so a single level would have to be wrong
    # about one of them.
    ("absent-reference-requires-blocks-the-start", units.absent_dependency_opinions,
     {"ActiveState": "inactive", "SubState": "dead",
      "MissingRequirements": ["message-broker.service (Requires=)"]},
     {("unit-requires-absent-unit", "warn")}),
    # Requisite= and BindsTo= share the hard fact because they share the
    # consequence; the directive that was actually written stays in the value,
    # so nothing about which word the author used is flattened away.
    ("absent-reference-requisite-and-bindsto-are-the-same-consequence",
     units.absent_dependency_opinions,
     {"ActiveState": "active", "SubState": "running",
      "MissingRequirements": ["ledger-store.service (BindsTo=)",
                              "message-broker.service (Requisite=)"]},
     {("unit-requires-absent-unit", "warn")}),
    # The common real case: a distribution-agnostic unit file wanting a service
    # this host does not have. Nothing fails, so nothing is raised — but the
    # file is asking for something that has never once happened.
    ("absent-reference-wants-is-a-documented-no-op", units.absent_dependency_opinions,
     {"ActiveState": "active", "SubState": "running",
      "MissingWants": ["container-runtime.service (Wants=)"]},
     {("unit-wants-absent-unit", "info")}),
    ("absent-reference-upholds-is-the-same-softness", units.absent_dependency_opinions,
     {"ActiveState": "active", "SubState": "running",
      "MissingWants": ["watchdog-keeper.service (Upholds=)"]},
     {("unit-wants-absent-unit", "info")}),
    # Both directives against the same absent name, which is what a unit file
    # ordinarily writes. Two opinions at two levels, because the reader has to
    # be able to tell which half of the sentence is the one that stops it.
    ("absent-reference-hard-and-soft-together", units.absent_dependency_opinions,
     {"ActiveState": "inactive", "SubState": "dead",
      "MissingRequirements": ["message-broker.service (Requires=)"],
      "MissingWants": ["container-runtime.service (Wants=)"],
      "MissingOrdering": ["message-broker.service (After=)"]},
     {("unit-requires-absent-unit", "warn"), ("unit-wants-absent-unit", "info")}),
    # Ordering alone states the fact and says nothing. After= against a unit
    # that is not there orders nothing, and on real hosts the population is
    # dominated by barriers systemd adds implicitly to units with no fragment
    # anyone could edit — an opinion here would be dozens of permanently red
    # rows per host with no fix behind any of them.
    ("absent-reference-ordering-carries-no-opinion", units.absent_dependency_opinions,
     {"ActiveState": "active", "SubState": "running",
      "MissingOrdering": ["storage-barrier.target (After=)",
                          "early-setup.service (Before=)"]},
     set()),
    # Rule 7: the probe could not be made. Stated, and standing IN PLACE OF the
    # reference facts rather than beside them — an unread dependency graph must
    # never reach a reader as an empty one.
    ("absent-reference-unobservable", units.absent_dependency_opinions,
     {"ActiveState": "inactive", "SubState": "dead",
      "MissingReferenceUnobservable":
          "the dependency properties of this absent name could not be read "
          "(org.freedesktop.DBus.Error.UnknownObject), so which units "
          "reference it is unknown rather than none"},
     {("unit-absent-references-unobservable", "info")}),
    # The overwhelmingly common row: a unit that names nothing absent. The
    # facts are simply not there, and silence here is what makes the opinions
    # above mean something when they do fire.
    ("absent-reference-none", units.absent_dependency_opinions,
     {"ActiveState": "active", "SubState": "running"}, set()),

    # hardware: a drive that yielded no reading must not be vouched for. Five
    # raidz1 members read "ok" for days on snapshots holding only an smartctl
    # error, because State == running was treated as positive health.
    ("scsi-disk-running-but-unmeasured", hardware.scsi_disk_opinions,
     {"State": "running", "SmartSnapshotAt": "2026-08-11T06:14:18Z",
      "SmartSnapshotAgeSeconds": 195,
      "SmartUnobservable": "the root smartctl snapshot for this device carried "
                           "no reading."},
     {("smart-unmeasured", "info")}),
    # Once a real reading arrives the notice must go away, even if the adapter
    # still carries the fact from a previous pass.
    ("scsi-disk-measured-and-healthy", hardware.scsi_disk_opinions,
     {"State": "running", "SmartFailing": False, "SmartTemperatureC": 36,
      "SmartPowerOnHours": 57551, "SmartSelftestStatus": "success",
      "SmartUnobservable": "stale reason that no longer applies"},
     set()),
    # A genuinely failing drive is never softened by the notice.
    ("scsi-disk-unmeasured-yet-failing", hardware.scsi_disk_opinions,
     {"State": "running", "SmartFailing": True,
      "SmartUnobservable": "should be ignored: a reading exists"},
     {("smart-health", "critical")}),

    # docker containers.
    ("container-restarting", docker.container_opinions,
     {"State": "restarting", "Status": "Restarting (1) 5 seconds ago",
      "RestartCount": 12},
     {("container-health", "critical")}),
    ("container-unhealthy-inspect", docker.container_opinions,
     {"State": "running", "Health": "unhealthy"},
     {("container-health", "critical")}),
    ("container-unhealthy-status-string", docker.container_opinions,
     {"State": "running", "Status": "Up 3 hours (unhealthy)"},
     {("container-health", "critical")}),
    ("container-paused", docker.container_opinions,
     {"State": "paused", "Status": "Up 2 hours (Paused)"},
     {("container-health", "warn")}),
    ("container-exited-137-exitcode", docker.container_opinions,
     {"State": "exited", "ExitCode": 137},
     {("container-exit", "warn")}),
    ("container-exited-137-status-string", docker.container_opinions,
     {"State": "exited", "Status": "Exited (137) 2 hours ago"},
     {("container-exit", "warn")}),
    ("container-oom", docker.container_opinions,
     {"State": "exited", "ExitCode": 137, "OOMKilled": True},
     {("container-exit", "warn"), ("container-oom", "critical")}),
    ("container-exited-0-quiet", docker.container_opinions,
     {"State": "exited", "Status": "Exited (0) 2 hours ago", "ExitCode": 0},
     set()),
    ("container-healthy", docker.container_opinions,
     {"State": "running", "Status": "Up 3 hours (healthy)",
      "Health": "healthy"},
     set()),

    # vms.
    ("domain-crashed", vms.domain_opinions,
     {"State": "crashed", "Autostart": False},
     {("domain-health", "critical")}),
    ("domain-paused", vms.domain_opinions,
     {"State": "paused", "Autostart": False},
     {("domain-health", "warn")}),
    ("domain-autostart-shutoff", vms.domain_opinions,
     {"State": "shutoff", "Autostart": True},
     {("domain-health", "warn")}),
    ("domain-shutoff-no-autostart", vms.domain_opinions,
     {"State": "shutoff", "Autostart": False}, set()),
    ("domain-healthy", vms.domain_opinions,
     {"State": "running", "Autostart": True}, set()),

    # network links: outside LINK_QUIET_STATES, a down link with configured
    # addresses warns; one with nothing configured is inventory (info) —
    # the intent heuristic until expected-state (ROADMAP slice 3).
    ("link-down", network.link_opinions,
     {"OperState": "down", "Kind": None, "Addresses": ["192.168.1.2/24"]},
     {("link-state", "warn")}),
    ("link-down-unconfigured", network.link_opinions,
     {"OperState": "down", "Kind": None, "Addresses": []},
     {("link-state", "info")}),
    # Bridges: empty ones are down by design (idle docker0's daemon-assigned
    # address must not trip the configured-addresses heuristic — audit
    # 2026-08-10); a bridge that HAS members and is down lost its ports.
    ("link-empty-bridge-down", network.link_opinions,
     {"OperState": "down", "Kind": "bridge", "Addresses": ["172.17.0.1/16"],
      "BridgeMembers": 0},
     {("link-state", "info")}),
    ("link-membered-bridge-down", network.link_opinions,
     {"OperState": "down", "Kind": "bridge", "Addresses": ["192.168.4.1/24"],
      "BridgeMembers": 3},
     {("link-state", "warn")}),
    ("link-dormant", network.link_opinions,
     {"OperState": "dormant", "Kind": None, "Addresses": ["10.0.0.2/24"]},
     {("link-state", "warn")}),
    ("link-veth-down-quiet", network.link_opinions,
     {"OperState": "lowerlayerdown", "Kind": "veth"}, set()),
    ("link-up-healthy", network.link_opinions,
     {"OperState": "up", "Kind": None}, set()),
    ("link-unknown-quiet", network.link_opinions,
     {"OperState": "unknown", "Kind": None}, set()),

    # network resolver.
    ("resolver-no-servers", network.resolver_opinions,
     {"CurrentDNSServer": None, "DNSServersInUse": [],
      "GlobalDNSServers": [], "PerLinkDNS": {}},
     {("resolver-servers", "warn")}),
    # The file shape (SPEC rule 16): a host without resolved answers the
    # universal question from resolv.conf, and its one health rule is
    # whether the file names any server.
    ("resolver-file-healthy", network.resolver_opinions,
     {"ResolverService": "libc-resolv.conf",
      "Nameservers": ["192.168.123.1"], "SearchDomains": ["red.example"],
      "Options": []},
     set()),
    ("resolver-file-empty", network.resolver_opinions,
     {"ResolverService": "libc-resolv.conf", "Nameservers": [],
      "SearchDomains": [], "Options": []},
     {("resolver-servers", "warn")}),
    ("resolver-healthy", network.resolver_opinions,
     {"CurrentDNSServer": "192.168.1.1", "DNSServersInUse": ["192.168.1.1"],
      "GlobalDNSServers": [], "PerLinkDNS": {"eth0": ["192.168.1.1"]}},
     set()),
    # A link owns the default route: ordinary queries go there, and the
    # sticky global CurrentDNSServer showing a fallback server is boot
    # residue, not a finding (asked live, 2026-08-12: "is my primary DNS
    # really 1.1.1.1?" — it was not).
    ("resolver-link-owns-default", network.resolver_opinions,
     {"CurrentDNSServer": "1.1.1.1", "DNSServersInUse": ["192.168.1.1"],
      "GlobalDNSServers": [], "FallbackDNSServers": ["1.1.1.1"],
      "PerLinkDNS": {"br0": {"DNSServers": ["192.168.1.1"],
                             "DefaultRoute": True}}},
     set()),
    # Nothing owns the default route and no global servers exist: every
    # non-domain query rides the compiled-in public fallback.
    ("resolver-fallback-carries-default", network.resolver_opinions,
     {"CurrentDNSServer": "1.1.1.1", "DNSServersInUse": ["192.168.1.1"],
      "GlobalDNSServers": [], "FallbackDNSServers": ["1.1.1.1"],
      "PerLinkDNS": {"br0": {"DNSServers": ["192.168.1.1"],
                             "DefaultRoute": False}}},
     {("resolver-fallback-carries-default", "warn")}),
    # DefaultRoute unobservable (resolved predates the property): cannot-see
    # is not a misconfiguration, so the rule stays silent.
    ("resolver-default-route-unobservable", network.resolver_opinions,
     {"CurrentDNSServer": "1.1.1.1", "DNSServersInUse": ["192.168.1.1"],
      "GlobalDNSServers": [], "FallbackDNSServers": ["1.1.1.1"],
      "PerLinkDNS": {"br0": {"DNSServers": ["192.168.1.1"]}}},
     set()),

    # network tailscale: node-key expiry ladder, self connectivity, snapshot
    # age. Only the self item carries BackendState, KeyExpiryDays and the
    # snapshot facts, so peers stay quiet by presence — an offline peer is
    # expected-state territory (ROADMAP slice 3), never an opinion here.
    ("tailscale-key-5-days-critical", network.tailscale_opinions,
     {"KeyExpiry": "2026-08-15T10:00:00Z", "KeyExpiryDays": 5,
      "BackendState": "Running", "Online": True},
     {("key-expiry", "critical")}),
    ("tailscale-key-20-days-warn", network.tailscale_opinions,
     {"KeyExpiry": "2026-08-30T10:00:00Z", "KeyExpiryDays": 20,
      "BackendState": "Running", "Online": True},
     {("key-expiry", "warn")}),
    ("tailscale-key-200-days-quiet", network.tailscale_opinions,
     {"KeyExpiry": "2027-02-26T10:00:00Z", "KeyExpiryDays": 200,
      "BackendState": "Running", "Online": True},
     set()),
    ("tailscale-self-offline", network.tailscale_opinions,
     {"BackendState": "Stopped", "Online": False,
      "KeyExpiry": None, "KeyExpiryDays": None},
     {("node-offline", "warn")}),
    ("tailscale-snapshot-stale", network.tailscale_opinions,
     {"BackendState": "Running", "Online": True,
      "TailscaleSnapshotAt": "2026-08-09T11:00:00Z",
      "TailscaleSnapshotAgeSeconds": network.TAILSCALE_SNAPSHOT_STALE_SECONDS + 1},
     {("tailscale-snapshot-stale", "warn")}),
    # Health rides the self item only when the daemon is saying something
    # (the adapter drops an empty array), so presence is the trigger.
    ("tailscale-health", network.tailscale_opinions,
     {"BackendState": "Running", "Online": True,
      "Health": ["router: setting up filter: unknown table",
                 "not in map poll"]},
     {("tailscale-health", "info")}),
    ("tailscale-self-healthy", network.tailscale_opinions,
     {"KeyExpiry": "2027-02-26T10:00:00Z", "KeyExpiryDays": 200,
      "BackendState": "Running", "Online": True,
      "TailscaleSnapshotAt": "2026-08-09T11:00:00Z",
      "TailscaleSnapshotAgeSeconds": 45},
     set()),

    # logs: priority <= 2 critical, == 3 info (err is used too
    # promiscuously to imply attention on its own), higher neutral.
    ("journal-priority-2", logs.journal_opinions,
     {"Priority": 2}, {("journal-priority", "critical")}),
    ("journal-priority-3", logs.journal_opinions,
     {"Priority": 3}, {("journal-priority", "info")}),
    ("journal-priority-6-quiet", logs.journal_opinions,
     {"Priority": 6}, set()),
    # Container stderr: the journald driver maps it to err, so a p3 from a
    # container says which stream, not which severity.
    ("journal-priority-3-container-stderr", logs.journal_opinions,
     {"Priority": 3, "Container": "example-app",
      "Message": "ImproperlyConfigured: SECRET_KEY is not set"},
     {("journal-priority", "info")}),
    # Repetition is the discrimination priority cannot give. It never moves a
    # level — it fires alongside whatever the priority already said.
    ("journal-repeated-spam", logs.journal_opinions,
     {"Priority": 3, "MessageId": "24dc708d9e6a4226a3efe2033bb744de",
      "Message": "Ignoring duplicate name 'org.example.Thing' in service file",
      "RepeatCount": 72, "RepeatWindow": 72},
     {("journal-priority", "info"), ("journal-repeated", "info")}),
    ("journal-repeated-critical-coredumps", logs.journal_opinions,
     {"Priority": 2, "MessageId": "fc2e22bc6ee647b6b90729ab34a250b1",
      "Message": "Process 75001 (dhcpcd) of user 999 dumped core.",
      "RepeatCount": 8, "RepeatWindow": 8},
     {("journal-priority", "critical"), ("journal-repeated", "info")}),
    ("journal-repeat-below-threshold-quiet", logs.journal_opinions,
     {"Priority": 3, "Message": "End of file while reading data: I/O error",
      "RepeatCount": 2, "RepeatWindow": 30},
     {("journal-priority", "info")}),
    # A count with no window is not a measurement: presence-driven, so quiet.
    ("journal-repeat-window-missing-quiet", logs.journal_opinions,
     {"Priority": 3, "Message": "x", "RepeatCount": 9},
     {("journal-priority", "info")}),
    # Above p3 nothing is judged at all, repetition included — a thousand-row
    # kernel page must not grow a thousand opinions.
    ("journal-priority-4-repeats-quiet", logs.journal_opinions,
     {"Priority": 4, "Message": "link up", "RepeatCount": 40, "RepeatWindow": 40},
     set()),
    ("journal-priority-absent-quiet", logs.journal_opinions,
     {"Message": "hello"}, set()),

    # hardware: SMART verdicts shared by scsi and nvme.
    ("smart-failing", hardware.smart_opinions,
     {"SmartFailing": True}, {("smart-health", "critical")}),
    ("smart-nvme-critical-warning", hardware.smart_opinions,
     {"SmartFailing": False, "SmartCriticalWarning": ["temperature"]},
     {("smart-health", "warn")}),
    ("smart-overall-failed", hardware.smart_opinions,
     {"SmartOverallPassed": False}, {("smart-health", "critical")}),
    ("smart-endurance-92-warn", hardware.smart_opinions,
     {"SmartPercentUsed": 92}, {("smart-endurance", "warn")}),
    ("smart-endurance-101-critical", hardware.smart_opinions,
     {"SmartPercentUsed": 101}, {("smart-endurance", "critical")}),
    ("smart-spare-exhausted", hardware.smart_opinions,
     {"SmartAvailableSparePct": 5, "SmartSpareThresholdPct": 10},
     {("smart-spare", "critical")}),
    ("smart-media-errors", hardware.smart_opinions,
     {"SmartMediaErrors": 3}, {("smart-media-errors", "warn")}),
    # Self-test verdicts share one fact name across transports; only the
    # failed vocabulary fires (known_seg_fail, seen on a real NVMe drive).
    ("smart-selftest-failed", hardware.smart_opinions,
     {"SmartSelftestStatus": "known_seg_fail"},
     {("smart-selftest", "warn")}),
    ("smart-selftest-success-quiet", hardware.smart_opinions,
     {"SmartSelftestStatus": "success", "SmartOverallPassed": True}, set()),
    # Stale with nothing recorded about why: still a warning, because an
    # unexplained gap really might be a wedged collector.
    ("smart-snapshot-stale-unexplained", hardware.smart_opinions,
     {"SmartSnapshotAt": "2026-08-09T11:00:00Z",
      "SmartSnapshotAgeSeconds": hardware.SMART_SNAPSHOT_STALE_SECONDS + 1},
     {("smart-snapshot-stale", "warn")}),
    # Stale BECAUSE the collector deliberately did not wake a sleeping disk.
    # info, not warn: that is normal operation on a spun-down bulk drive, and
    # a warning there trains the operator to ignore the rule. Observed in the wild,
    # whose pool disks idle into standby (2026-08-11).
    ("smart-snapshot-stale-drive-asleep", hardware.smart_opinions,
     {"SmartSnapshotAt": "2026-08-09T11:00:00Z",
      "SmartSnapshotAgeSeconds": hardware.SMART_SNAPSHOT_STALE_SECONDS + 1,
      "SmartSnapshotReason": "Device is in STANDBY mode, exit(2)"},
     {("smart-snapshot-stale", "info")}),
    # Stale for a reason that is NOT standby — an unsupported transport, a
    # permission failure. Still a warning, now with the cause quoted.
    ("smart-snapshot-stale-explained-fault", hardware.smart_opinions,
     {"SmartSnapshotAt": "2026-08-09T11:00:00Z",
      "SmartSnapshotAgeSeconds": hardware.SMART_SNAPSHOT_STALE_SECONDS + 1,
      "SmartSnapshotReason": "Unsupported device type 'scsi'"},
     {("smart-snapshot-stale", "warn")}),
    ("smart-snapshot-fresh-healthy", hardware.smart_opinions,
     {"SmartSnapshotAt": "2026-08-09T11:00:00Z",
      "SmartSnapshotAgeSeconds": 300, "SmartOverallPassed": True,
      "SmartPercentUsed": 3}, set()),
    # link_opinions. The slot's capability is what separates "wired that way"
    # from "trained down", and severity follows it: warning about an immutable
    # board property is warning about something nobody can act on, which is what
    # the first version did to a real host.
    ("link-at-full-rate-quiet", hardware.link_opinions,
     {"LinkSpeed": "6.0 Gbit", "LinkSpeedMax": "6.0 Gbit"}, set()),
    ("link-speed-alone-is-not-a-verdict", hardware.link_opinions,
     {"LinkSpeed": "6.0 Gbps"}, set()),
    # An x4 drive in an M.2 socket that provides two lanes. Permanent,
    # so INFO — it caps bandwidth and no operator can change it.
    ("pcie-width-explained-by-the-slot", hardware.link_opinions,
     {"LinkSpeed": "8.0 GT/s PCIe", "LinkSpeedMax": "8.0 GT/s PCIe",
      "LinkWidth": 2, "LinkWidthMax": 4, "SlotLinkWidthMax": 2,
      "LinkBandwidthBytesPerSec": 1_969_230_768,
      "LinkBandwidthMaxBytesPerSec": 3_938_461_536},
     {("link-width-degraded", "info")}),
    # Both ends capable of x4 and the link came up at x2: a real fault.
    ("pcie-width-degraded-both-ends-capable", hardware.link_opinions,
     {"LinkWidth": 2, "LinkWidthMax": 4, "SlotLinkWidthMax": 4},
     {("link-width-degraded", "warn")}),
    # No slot capability to compare (SAS, SATA): cannot attribute it, so warn
    # rather than silently excusing it.
    ("link-width-degraded-slot-unknown", hardware.link_opinions,
     {"LinkWidth": 2, "LinkWidthMax": 4},
     {("link-width-degraded", "warn")}),
    ("link-speed-degraded-both-ends-capable", hardware.link_opinions,
     {"LinkSpeed": "1.5 Gbps", "LinkSpeedMax": "6.0 Gbps",
      "SlotLinkSpeedMax": "6.0 Gbps"},
     {("link-degraded", "warn")}),
    ("scsi-disk-offline", hardware.scsi_disk_opinions,
     {"State": "offline"}, {("device-state", "warn")}),
    ("scsi-disk-healthy", hardware.scsi_disk_opinions,
     {"State": "running", "SmartOverallPassed": True}, set()),
    ("scsi-disk-state-unreadable-quiet", hardware.scsi_disk_opinions,
     {"State": None}, set()),
    ("nvme-resetting", hardware.nvme_opinions,
     {"State": "resetting"}, {("controller-state", "warn")}),
    ("nvme-live-but-worn", hardware.nvme_opinions,
     {"State": "live", "SmartPercentUsed": 100},
     {("smart-endurance", "critical")}),
    ("nvme-healthy", hardware.nvme_opinions,
     {"State": "live", "SmartPercentUsed": 3}, set()),

    # system: time.
    ("time-unsynchronised", system.time_opinions,
     {"NTP": True, "NTPSynchronized": False}, {("time-sync", "warn")}),
    ("time-healthy", system.time_opinions,
     {"NTP": True, "NTPSynchronized": True}, set()),
    ("time-ntp-off-quiet", system.time_opinions,
     {"NTP": False, "NTPSynchronized": False}, set()),

    # system: boot. EFI facts are presence-driven — BIOS hosts never carry them.
    ("boot-secure-boot", system.boot_opinions,
     {"SecureBoot": True, "SystemState": "running"},
     {("secure-boot", "warn")}),
    ("boot-order-stale", system.boot_opinions,
     {"SecureBoot": False, "SystemState": "running",
      "BootOrder": ["Boot0001", "Boot0000"],
      "BootEntries": [
          {"ID": "Boot0001", "Stale": True, "OrderPosition": 1},
          {"ID": "Boot0000", "Stale": False, "OrderPosition": 2},
          {"ID": "Boot0007", "Stale": True, "OrderPosition": None}]},
     {("boot-order-stale", "warn")}),
    ("boot-next-armed", system.boot_opinions,
     {"SecureBoot": False, "SystemState": "running", "BootNext": "Boot0002"},
     {("boot-next", "info")}),
    # info, deliberately: degraded IS ">=1 failed unit", and each failed
    # unit already carries its own critical on the units collection — a
    # second critical here double-reported one failure onto the estate
    # attention surface (operator report, 2026-08-13).
    ("boot-degraded-with-failures", system.boot_opinions,
     {"SystemState": "degraded", "NFailedUnits": 2},
     {("system-state", "info")}),
    ("boot-maintenance-state", system.boot_opinions,
     {"SystemState": "maintenance", "NFailedUnits": 0},
     {("system-state", "warn")}),
    ("boot-test-activation", system.boot_opinions,
     {"SystemState": "running",
      "CurrentSystem": "/nix/store/aaa-nixos-system",
      "BootedSystem": "/nix/store/aaa-nixos-system",
      "SystemProfile": "/nix/store/bbb-nixos-system"},
     {("system-pointers", "warn")}),
    ("boot-switch-since-boot", system.boot_opinions,
     {"SystemState": "running",
      "CurrentSystem": "/nix/store/bbb-nixos-system",
      "BootedSystem": "/nix/store/aaa-nixos-system",
      "SystemProfile": "/nix/store/bbb-nixos-system"},
     {("system-pointers", "info")}),
    ("boot-healthy", system.boot_opinions,
     {"SecureBoot": False, "SystemState": "running", "NFailedUnits": 0,
      "CurrentSystem": "/nix/store/aaa-nixos-system",
      "BootedSystem": "/nix/store/aaa-nixos-system",
      "SystemProfile": "/nix/store/aaa-nixos-system",
      "BootOrder": ["Boot0000"],
      "BootEntries": [{"ID": "Boot0000", "Stale": False, "OrderPosition": 1}]},
     set()),

    # system: overview — kernel-precomputed aggregates (ROADMAP slice 1).
    # A high load average is now deliberately SILENT: load-pressure was retired
    # in favour of psi-cpu, which measures the same question directly instead of
    # via a proxy that counts uninterruptible sleep. Pinned as a case so the
    # rule cannot quietly come back and start double-judging one condition.
    ("overview-high-load-is-not-judged", system.overview_opinions,
     {"LoadAvg1": 17.3, "CpuCount": 4, "LoadPerCpu1": 4.33}, set()),
    ("overview-memory-91-warn", system.overview_opinions,
     {"MemTotalBytes": 8 * 2**30, "MemAvailableBytes": 700 * 2**20,
      "MemUsedPercent": 91},
     {("memory-available", "warn")}),
    ("overview-memory-96-critical", system.overview_opinions,
     {"MemTotalBytes": 8 * 2**30, "MemAvailableBytes": 300 * 2**20,
      "MemUsedPercent": 96},
     {("memory-available", "critical")}),
    # ZFS ARC discount: high raw usage, low usage outside the cache —
    # occupancy, not pressure. Info, never warn.
    ("overview-memory-arc-occupancy-info", system.overview_opinions,
     {"MemTotalBytes": 32 * 2**30, "MemAvailableBytes": 2 * 2**30,
      "MemUsedBytes": 30 * 2**30, "MemUsedPercent": 94,
      "ArcSizeBytes": 26 * 2**30},
     {("memory-available", "info")}),
    # ARC present but genuinely tight even after the discount: still warns.
    ("overview-memory-arc-still-tight-warn", system.overview_opinions,
     {"MemTotalBytes": 64 * 2**30, "MemAvailableBytes": 2 * 2**30,
      "MemUsedBytes": 62 * 2**30, "MemUsedPercent": 97,
      "ArcSizeBytes": 2 * 2**30},
     {("memory-available", "warn")}),
    ("overview-swap-pressure", system.overview_opinions,
     {"SwapTotalBytes": 2 * 2**30, "SwapUsedBytes": 2**30,
      "SwapUsedPercent": 50},
     {("swap-pressure", "warn")}),
    ("overview-swapless-quiet", system.overview_opinions,
     {"SwapTotalBytes": 0, "SwapUsedBytes": 0, "SwapUsedPercent": None},
     set()),
    ("overview-psi-memory-warn", system.overview_opinions,
     {"PsiMemoryFullAvg60": 6.51}, {("psi-memory", "warn")}),
    ("overview-psi-memory-critical", system.overview_opinions,
     {"PsiMemoryFullAvg60": 24.8}, {("psi-memory", "critical")}),
    ("overview-psi-cpu-warn", system.overview_opinions,
     {"PsiCpuSomeAvg60": 71.2}, {("psi-cpu", "warn")}),
    ("overview-psi-io-warn", system.overview_opinions,
     {"PsiIoFullAvg60": 33.0}, {("psi-io", "warn")}),
    ("overview-healthy", system.overview_opinions,
     {"LoadAvg1": 0.42, "CpuCount": 8, "LoadPerCpu1": 0.05,
      "MemTotalBytes": 8 * 2**30, "MemAvailableBytes": 5 * 2**30,
      "MemUsedPercent": 38, "SwapTotalBytes": 2 * 2**30,
      "SwapUsedBytes": 0, "SwapUsedPercent": 0,
      "PsiCpuSomeAvg60": 0.12, "PsiMemoryFullAvg60": 0.0,
      "PsiIoFullAvg60": 0.31},
     set()),

    # system: generations.
    ("generation-pending", nix.generation_opinions,
     {"Profile": True, "Current": False}, {("generation-pending", "info")}),
    ("generation-current-healthy", nix.generation_opinions,
     {"Profile": True, "Current": True}, set()),
    ("generation-old-non-profile-quiet", nix.generation_opinions,
     {"Profile": False, "Current": False}, set()),
    ("generation-unattested", nix.generation_opinions,
     {"Profile": True, "Current": True, "ReceiptsExpected": True,
      "Deployment": None},
     {("deployment-unattested", "warn")}),
    ("generation-attested-quiet", nix.generation_opinions,
     {"Profile": True, "Current": True, "ReceiptsExpected": True,
      "Deployment": {"Mode": "switch", "Outcome": "VERIFIED",
                     "VerifiedAt": "2026-08-11T13:00:00+00:00", "Risks": []}},
     set()),
    ("generation-deployment-failed", nix.generation_opinions,
     {"Profile": True, "Current": True, "ReceiptsExpected": True,
      "Deployment": {"Mode": "switch", "Outcome": "FAILED",
                     "VerifiedAt": "2026-08-11T13:00:00+00:00", "Risks": []}},
     {("deployment-not-verified", "warn")}),
    # A generation from before receipts existed, or a host that keeps none, is
    # not judged: no ReceiptsExpected fact, so the rule does not evaluate.
    ("generation-receipts-not-expected-quiet", nix.generation_opinions,
     {"Profile": True, "Current": True}, set()),
]

CASE_IDS = [case[0] for case in CASES]


@pytest.mark.parametrize("_name,evaluator,facts,expected", CASES, ids=CASE_IDS)
def test_characteristic_inputs_fire_documented_keys(_name, evaluator, facts, expected):
    """Rule 8: characteristic inputs fire the documented keys at the
    documented levels; healthy shapes fire nothing."""
    fired = {(op["key"], op["level"]) for op in evaluator(facts)}
    assert fired == expected


@pytest.mark.parametrize("_name,evaluator,facts,expected", CASES, ids=CASE_IDS)
def test_emitted_evidence_resolves_into_input_facts(_name, evaluator, facts, expected):
    """SPEC section 2, rule 3: every emitted opinion cites paths that
    resolve into the facts that produced it."""
    for op in evaluator(facts):
        assert op["evidence"], f"opinion {op['key']!r} cites no evidence"
        for path in op["evidence"]:
            resolve_fact_path(facts, path)


def test_link_opinion_quantifies_the_cap_when_the_adapter_derived_it():
    """A capped link says what the cap COSTS, in bytes, citing the derived
    facts rather than asserting a figure the envelope does not contain.

    "it does cap the bandwidth available to it" separates a one-percent cap
    from a halving not at all — the reader who hit this had to leave the
    screen and do PCIe arithmetic by hand. The sentence carries the concept too,
    because the reasonable reading of "8.0 GT/s" beside "x2" is that speed and
    width say the same thing twice.
    """
    op = hardware.link_opinions({
        "LinkSpeed": "8.0 GT/s PCIe", "LinkSpeedMax": "8.0 GT/s PCIe",
        "LinkWidth": 2, "LinkWidthMax": 4, "SlotLinkWidthMax": 2,
        "LinkBandwidthBytesPerSec": 1_969_230_768,
        "LinkBandwidthMaxBytesPerSec": 3_938_461_536})[0]
    assert "2.0 GB/s each way" in op["message"]
    assert "3.9 GB/s" in op["message"]
    assert "rate of one lane" in op["message"]
    assert {"LinkBandwidthBytesPerSec", "LinkBandwidthMaxBytesPerSec"} <= set(op["evidence"])


@pytest.mark.parametrize("facts,why", [
    ({"LinkSpeed": "128.0 GT/s PCIe", "LinkSpeedMax": "128.0 GT/s PCIe",
      "LinkWidth": 2, "LinkWidthMax": 4, "SlotLinkWidthMax": 2},
     "a PCIe generation the conversion table has not met"),
    ({"LinkSpeed": "1.5 Gbps", "LinkSpeedMax": "6.0 Gbps",
      "SlotLinkSpeedMax": "6.0 Gbps"}, "a SATA link, which has no lanes"),
])
def test_link_opinion_stays_qualitative_when_bandwidth_is_underivable(facts, why):
    """Rule 7 at the level of prose: no derived figure means no figure, not an
    invented one. The message keeps its qualitative ending and cites only what
    it was actually given."""
    for op in hardware.link_opinions(facts):
        assert "GB/s" not in op["message"] and "MB/s" not in op["message"], why
        assert not [p for p in op["evidence"] if "Bandwidth" in p]


# ---------------------------------------------------------------------------
# Structural invariants over every module in agent/rules/, present and future.
# ---------------------------------------------------------------------------

def all_rule_evaluators():
    """Every public *_opinions function in every agent.rules module."""
    evaluators = []
    for info in sorted(pkgutil.iter_modules(rules.__path__), key=lambda m: m.name):
        module = importlib.import_module(f"{rules.__name__}.{info.name}")
        for name in sorted(vars(module)):
            fn = getattr(module, name)
            if name.endswith("_opinions") and not name.startswith("_") and callable(fn):
                evaluators.append(pytest.param(fn, id=f"{info.name}.{name}"))
    return evaluators


@pytest.mark.parametrize("evaluator", all_rule_evaluators())
def test_evaluators_tolerate_absent_facts(evaluator):
    """Rule 8: rules are presence-driven — an empty facts dict (a host or
    capability that never acquired the deciding facts) yields no opinions."""
    assert evaluator({}) == []


def test_rulebook_is_covered():
    """A new evaluator must land with characteristic cases above, and the
    discovery glob must actually be finding the rulebook."""
    discovered = {param.id for param in all_rule_evaluators()}
    assert discovered, f"{RULES_DIR} yielded no *_opinions evaluators"
    exercised = {f"{fn.__module__.rsplit('.', 1)[-1]}.{fn.__name__}"
                 for _, fn, _, _ in CASES}
    assert discovered == exercised, (
        "evaluators without characteristic cases (add them to CASES): "
        f"{sorted(discovered - exercised)}; cases naming unknown evaluators: "
        f"{sorted(exercised - discovered)}"
    )


# ---------------------------------------------------------------------------
# Purity lint: SPEC section 11, rule 8 — rules import nothing beyond the
# stdlib and the envelope builders. Enforced by AST like test_adapter_lint.
# ---------------------------------------------------------------------------

def rules_sources():
    return sorted(RULES_DIR.glob("*.py")) if RULES_DIR.is_dir() else []


@pytest.mark.parametrize("source", rules_sources(), ids=lambda p: p.name)
def test_rules_modules_import_only_stdlib_and_envelope(source):
    tree = ast.parse(source.read_text(), filename=str(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root in sys.stdlib_module_names, (
                    f"{source.name}: imports {alias.name!r} — rules are pure "
                    "(stdlib + agent.envelope only; no adapters, no I/O)"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                root = (node.module or "").split(".")[0]
                assert root in sys.stdlib_module_names, (
                    f"{source.name}: imports from {node.module!r} — rules are "
                    "pure (stdlib + agent.envelope only)"
                )
            elif node.level == 1 and node.module is None:
                # from . import <sibling rules module> — stays in the rulebook.
                continue
            else:
                # The only sanctioned reach out of the package: the envelope
                # builders (from .. import envelope / from ..envelope import x).
                target = node.module or ",".join(a.name for a in node.names)
                assert node.level == 2 and target == "envelope", (
                    f"{source.name}: relative import beyond the rulebook "
                    f"(level={node.level}, {target!r}) — only agent.envelope "
                    "is permitted"
                )


# ---------------------------------------------------------------------------
# The rulebook's vocabulary, as the operator UI holds it.
#
# No endpoint publishes the level enum, so app.js is forced to keep its own
# copy — and app.js's own comment says a fourth copy of something the agent
# knows is a fourth thing to disagree with it. It was right: three severity
# tables in that file had already drifted, and one of them painted an `info`
# opinion warn-yellow directly above a sentence saying the reading was not
# alarming. The copy is unavoidable; a SILENT copy is not. Conformance is
# pytest and cannot execute JavaScript, so these read it as text.
# ---------------------------------------------------------------------------

def test_ui_mirrors_the_rulebook_level_order():
    source = (UI_DIR / "app.js").read_text()
    match = re.search(r"^const OPINION_LEVELS = \[([^\]]*)\];", source, re.M)
    assert match, (
        "app.js no longer declares OPINION_LEVELS at top level — the operator "
        "UI's severity order must stay greppable so this lint can check it"
    )
    mirrored = tuple(re.findall(r'"([a-z]+)"', match.group(1)))
    assert mirrored == rules.OPINION_LEVELS, (
        f"app.js orders opinion levels {mirrored}; the rulebook says "
        f"{rules.OPINION_LEVELS} (agent/rules/__init__.py)"
    )


def test_ui_keeps_info_out_of_the_attention_channels():
    """`info` says "recorded, explained, not claiming your attention".

    Badging it rebuilds the noise the three-level taxonomy was built to escape
    (rules/logs.py records the audit). This is policy rather than ordering, so
    it is asserted separately from the level order above.
    """
    source = (UI_DIR / "app.js").read_text()
    match = re.search(r"^const ATTENTION_LEVELS = \[([^\]]*)\];", source, re.M)
    assert match, "app.js no longer declares ATTENTION_LEVELS at top level"
    attention = tuple(re.findall(r'"([a-z]+)"', match.group(1)))
    assert "info" not in attention, (
        f"ATTENTION_LEVELS is {attention} — an info opinion must not earn a nav "
        "badge, a subsystem dot or an attention chip"
    )
    unknown = set(attention) - set(rules.OPINION_LEVELS)
    assert not unknown, (
        f"ATTENTION_LEVELS names {sorted(unknown)}, which the rulebook cannot "
        f"emit (levels are {rules.OPINION_LEVELS})"
    )


# Every class the JS emits for a severity must have a rule behind it. The node
# smoke test asserts the class reaches the DOM; only this can see whether the
# stylesheet says anything about it — and .dot.none's entire behaviour is one
# CSS line, so an unstyled one is an invisible regression.
SEVERITY_SELECTORS = [
    ".dot.none",       # absent severity: an unfilled ring, not a neutral verdict
    ".dot.info",
    ".opinion.info",   # restates the base border, so neutrality is a decision
    ".meter.info",     # ditto for the overview meters
]


@pytest.mark.parametrize("selector", SEVERITY_SELECTORS)
def test_every_severity_class_the_ui_emits_is_styled(selector):
    styles = (UI_DIR / "styles.css").read_text()
    assert selector in styles, (
        f"app.js can emit {selector} but styles.css never mentions it"
    )


def test_ui_priority_badge_matches_the_rulebook_threshold():
    """The syslog Priority badge is the only place the UI colours a raw kernel
    value against a rule's own ladder. It read `<= 3 ? crit : === 4 ? warn`,
    which reddened every err row the rulebook calls `info` and ambered every
    warning row it says nothing about at all.
    """
    source = (UI_DIR / "app.js").read_text()
    match = re.search(r"^const PRIORITY_CRITICAL = (\d+);", source, re.M)
    assert match, "app.js no longer declares PRIORITY_CRITICAL at top level"
    assert int(match.group(1)) == logs.PRIORITY_CRITICAL, (
        f"app.js reddens syslog priorities <= {match.group(1)}; the rulebook "
        f"trusts the number alone only at <= {logs.PRIORITY_CRITICAL} "
        "(agent/rules/logs.py)"
    )


# VALUE_CLASS colours a raw state word — ActiveState, SubState, State, Health,
# OperState, LoadState — with ONE table shared across every collection. That is
# the difficulty: `dead` is a normal systemd SubState and a warned-about docker
# container, `down` is a fault on a NIC with addresses and correct on an empty
# bridge. A word whose severity depends on who said it cannot be coloured.
#
# The badge may under-claim freely: the row's dot carries the rulebook's verdict
# per collection. It may not over-claim, because a warning beside a row the
# rulebook declined to judge is a second opinion nobody wrote down.
#
# So attention colours are a reviewed list, and adding one is a decision — the
# same discipline as SUBPROCESS_ALLOWLIST. Each entry names why the word means
# trouble no matter which collection emitted it.
UI_ATTENTION_STATES = {
    "failed": "systemd's own verdict on a unit, and rules/units.py warns on it",
    "crashed": "no collection uses this word for a healthy object",
    "unhealthy": "a docker healthcheck that reports failure; critical in rules/docker.py",
    "degraded": "an array or pool missing redundancy; critical in rules/storage.py",
    "paused": "a deliberately suspended container; warned in rules/docker.py",
    "blocked": "a scsi device the kernel has stopped issuing to; warned in rules/hardware.py",
    "restarting": "a container stuck in a restart loop; critical in rules/docker.py",
}


def test_the_ui_colours_no_state_the_rulebook_declines_to_judge():
    """`down` and `exited` used to be ambered here, and both re-asserted a
    judgement the rulebook had specifically removed: rules/network.py calls a
    down link info in three of its four shapes (the docker0 false positive and
    the unwired-spare-NIC operator call), and rules/docker.py warns on an exit
    only when the code is non-zero, so a clean exit wore an amber badge beside
    its own faint info dot."""
    source = (UI_DIR / "app.js").read_text()
    block = re.search(r"^const VALUE_CLASS = \{(.*?)^\};", source, re.M | re.S)
    assert block, "app.js no longer declares VALUE_CLASS at top level"
    coloured = dict(re.findall(r"(\w+):\s*\"(\w+)\"", block.group(1)))
    assert coloured, "VALUE_CLASS parsed as empty — the lint would pass vacuously"
    attention = {state for state, cls in coloured.items() if cls in ("warn", "crit")}
    undeclared = sorted(attention - set(UI_ATTENTION_STATES))
    assert not undeclared, (
        f"app.js colours {undeclared} as attention, but they are not in "
        "UI_ATTENTION_STATES. A state word only earns a colour if it means "
        "trouble whatever collection emitted it — otherwise the row's dot, "
        "which comes from rules/ per collection, is what says so."
    )


def test_the_attention_list_does_not_outlive_its_use():
    """A debt register, not a wish list: a word nobody colours any more must
    come off, or the reasons stop describing the code."""
    source = (UI_DIR / "app.js").read_text()
    block = re.search(r"^const VALUE_CLASS = \{(.*?)^\};", source, re.M | re.S)
    coloured = dict(re.findall(r"(\w+):\s*\"(\w+)\"", block.group(1)))
    stale = sorted(state for state in UI_ATTENTION_STATES
                   if coloured.get(state) not in ("warn", "crit"))
    assert not stale, f"UI_ATTENTION_STATES justifies {stale}, which the UI no longer colours"


# ---------------------------------------------------------------------------
# The link kind, which is a shaping decision rather than a rule but has the same
# failure mode: a value the kernel did not say. Pure, so it is tested directly.
# ---------------------------------------------------------------------------

LINK_KIND_CASES = [
    # tailscale0 and libvirt's vnet* both report info_kind "tun", because one
    # tuntap driver creates both. The kernel draws the line in info_data.type,
    # and they are genuinely different devices — layer 3 with no address, vs
    # layer 2 enslaved to a bridge with a real MAC.
    ("tun-is-a-tun", {"linkinfo": {"info_kind": "tun",
                                   "info_data": {"type": "tun"}}}, "tun"),
    ("tap-is-not-a-tun", {"linkinfo": {"info_kind": "tun",
                                       "info_data": {"type": "tap"}}}, "tap"),
    # Degrades to the driver name rather than guessing, if a kernel ever stops
    # reporting the mode.
    ("tuntap-without-a-mode", {"linkinfo": {"info_kind": "tun"}}, "tun"),
    ("tuntap-with-empty-info-data",
     {"linkinfo": {"info_kind": "tun", "info_data": {}}}, "tun"),
    # Every other kind passes through untouched.
    ("bridge", {"linkinfo": {"info_kind": "bridge"}}, "bridge"),
    ("veth", {"linkinfo": {"info_kind": "veth"}}, "veth"),
    # A physical NIC and loopback carry no linkinfo, or only the enslavement.
    # Neither has a kind, and info_slave_kind must never become one: it says
    # "this is a bridge port", which Master already says.
    ("loopback-has-no-linkinfo", {"link_type": "loopback"}, None),
    ("physical-nic-has-no-linkinfo", {"link_type": "ether"}, None),
    ("bridge-port-is-not-a-bridge",
     {"linkinfo": {"info_slave_kind": "bridge",
                   "info_slave_data": {"state": "forwarding"}}}, None),
    ("empty-linkinfo", {"linkinfo": {}}, None),
    ("nothing-at-all", {}, None),
]


@pytest.mark.parametrize("case,link,expected",
                         LINK_KIND_CASES, ids=[c[0] for c in LINK_KIND_CASES])
def test_link_kind_reports_what_the_kernel_said(case, link, expected):
    from system_explorer.agent.adapters.network import _link_kind
    assert _link_kind(link) == expected
