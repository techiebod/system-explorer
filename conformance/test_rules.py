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
from system_explorer.agent.rules import (docker, hardware, logs, network, nix,
                                         storage, system, units, vms)

RULES_DIR = AGENT_DIR / "rules"


# ---------------------------------------------------------------------------
# Characteristic inputs: (case id, evaluator, facts, expected {(key, level)}).
# Facts mirror what the owning adapter puts in the envelope, including the
# neighbours each rule cites as evidence. An empty expected set is the
# healthy case: the evaluator must stay silent.
# ---------------------------------------------------------------------------

CASES = [
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
    ("unit-io-stalled", units.unit_opinions,
     {"ActiveState": "active", "SubState": "running",
      "PsiIoFullAvg60": units.UNIT_IO_STALL_WARN},
     {("unit-io-stall", "warn")}),
    ("unit-memory-stalled", units.unit_opinions,
     {"ActiveState": "active", "SubState": "running",
      "PsiMemoryFullAvg60": units.UNIT_MEMORY_STALL_WARN},
     {("unit-memory-stall", "warn")}),
    # Below threshold, and a kernel with PSI reporting genuine calm: the
    # facts are present and the unit stays silent, which is what makes the
    # opinion mean something when it does fire.
    ("unit-not-stalled", units.unit_opinions,
     {"ActiveState": "active", "SubState": "running",
      "PsiIoFullAvg60": 0.0, "PsiCpuSomeAvg60": 0.0, "PsiMemoryFullAvg60": 0.0},
     set()),

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
    ("resolver-healthy", network.resolver_opinions,
     {"CurrentDNSServer": "192.168.1.1", "DNSServersInUse": ["192.168.1.1"],
      "GlobalDNSServers": [], "PerLinkDNS": {"eth0": ["192.168.1.1"]}},
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
    # a warning there trains the operator to ignore the rule. Observed on vat,
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
    # the first version did to jar.
    ("link-at-full-rate-quiet", hardware.link_opinions,
     {"LinkSpeed": "6.0 Gbit", "LinkSpeedMax": "6.0 Gbit"}, set()),
    ("link-speed-alone-is-not-a-verdict", hardware.link_opinions,
     {"LinkSpeed": "6.0 Gbps"}, set()),
    # jar: an x4 drive in an M.2 socket that provides two lanes. Permanent,
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
    ("boot-degraded-with-failures", system.boot_opinions,
     {"SystemState": "degraded", "NFailedUnits": 2},
     {("system-state", "critical")}),
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
    from a halving not at all — the reader who hit this on jar had to leave the
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
