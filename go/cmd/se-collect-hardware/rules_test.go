// The declared rule table, FIRED — not merely pinned.
//
// The tables here are the largest in the estate and the corpus can reach
// almost none of their inputs: the lab has no SMART depth, no udisks2 on the
// bus and no PCI slot that publishes a capability, all of which
// corpus.NAMED_RESIDUALS states. So the characteristic inputs live here, run
// through the collator's own evaluator against this collector's own shipped
// declaration — the same shape conformance/test_rules.py uses on the
// reference's evaluators, and the cases are deliberately the same cases.
//
// COVERAGE, stated because a check that quietly covers less than it looks
// like is this estate's most repeated defect: this proves the DECLARED table
// fires as intended on these inputs, and that a healthy row is silent. That
// it agrees with agent/rules/hardware.py is asserted by the cases being
// written from that file, which is a correspondence no machine here checks.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func judge(t *testing.T, collection string, facts map[string]any) map[string]string {
	t.Helper()
	rules, err := collate.RulesFor(string(declarationBytes), collection)
	if err != nil {
		t.Fatalf("rules for %s: %v", collection, err)
	}
	if len(rules) == 0 {
		t.Fatalf("%s declares no rules", collection)
	}
	fired := map[string]string{}
	for _, opinion := range collate.Judge(rules, "object", nil, facts) {
		fired[opinion.Key] = opinion.Level
	}
	return fired
}

func same(got map[string]string, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, level := range want {
		if got[key] != level {
			return false
		}
	}
	return true
}

func TestTheHardwareRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		// A drive that yielded no health reading says so, and the row must
		// not read as healthy: "the device exists and is running" is not a
		// measurement. This is the case five raidz1 members failed, each
		// displaying a vouched-for ok while their snapshots held nothing but
		// an smartctl error.
		{"a disk with no reading is not vouched for", "scsi", map[string]any{
			"DeviceType": "disk", "State": "running",
			"SmartUnobservable": "no root smartctl snapshot exists for this device",
		}, map[string]string{"smart-unmeasured": "info"}},
		// The same row with a reading in hand is SILENT: nothing is wrong,
		// and an unmeasured claim beside a measurement would be a lie.
		{"a healthy disk is silent", "scsi", map[string]any{
			"DeviceType": "disk", "State": "running",
			"SmartFailing": false, "SmartSelftestStatus": "success",
			"SmartTemperatureC": float64(36),
		}, map[string]string{}},
		{"a failing disk is critical", "scsi", map[string]any{
			"DeviceType": "disk", "State": "running", "SmartFailing": true,
		}, map[string]string{"smart-health": "critical"}},
		// A drive already reporting FAILING says the worse thing; the warning
		// does not pile on beside it, which is the reference's own elif.
		{"a critical warning does not pile onto a failure", "scsi", map[string]any{
			"DeviceType": "disk", "State": "running", "SmartFailing": true,
			"SmartCriticalWarning": []any{"temperature"},
		}, map[string]string{"smart-health": "critical"}},
		{"a critical warning alone is a warning", "nvme", map[string]any{
			"State": "live", "SmartCriticalWarning": []any{"spare"},
		}, map[string]string{"smart-critical-warning": "warn"}},
		// An EMPTY warning list is a reading, not a fault: the drive was
		// asked and answered nothing wrong.
		{"an empty warning list is a reading", "nvme", map[string]any{
			"State": "live", "SmartCriticalWarning": []any{},
			"SmartOverallPassed": true,
		}, map[string]string{}},
		{"a device out of its running state is a warning", "scsi", map[string]any{
			"DeviceType": "disk", "State": "offline",
			"SmartFailing": false,
		}, map[string]string{"device-state": "warn"}},
		// A host and an expander are TOPOLOGY, not health subjects, and the
		// reference dispatches them away from every drive rule. Here the
		// DeviceType condition is what keeps them unjudged, which is why the
		// fact is on the wire at all.
		{"a controller in another state is not a disk finding", "scsi", map[string]any{
			"DeviceType": "scsi-host", "State": "blocked",
		}, map[string]string{}},
		{"a controller off its live state is a warning", "nvme", map[string]any{
			"State": "resetting",
		}, map[string]string{"controller-state": "warn"}},
		{"endurance past the rating is critical", "nvme", map[string]any{
			"State": "live", "SmartPercentUsed": float64(101),
		}, map[string]string{"smart-endurance-spent": "critical"}},
		{"endurance approaching the rating is a warning", "nvme", map[string]any{
			"State": "live", "SmartPercentUsed": float64(92),
		}, map[string]string{"smart-endurance": "warn"}},
		// The boundary in both directions: 90 warns, 89 is silent, and 100 is
		// spent rather than approaching — the thresholds are ours, so they are
		// the ones worth pinning.
		{"endurance at the warn boundary", "nvme", map[string]any{
			"State": "live", "SmartPercentUsed": float64(90),
		}, map[string]string{"smart-endurance": "warn"}},
		{"endurance below the warn boundary is silent", "nvme", map[string]any{
			"State": "live", "SmartPercentUsed": float64(89),
		}, map[string]string{}},
		{"spare at its own threshold is critical", "nvme", map[string]any{
			"State": "live", "SmartAvailableSparePct": float64(9),
			"SmartSpareThresholdPct":   float64(10),
			"SmartSpareBelowThreshold": true,
		}, map[string]string{"smart-spare": "critical"}},
		{"media errors are a warning", "nvme", map[string]any{
			"State": "live", "SmartMediaErrors": float64(3),
		}, map[string]string{"smart-media-errors": "warn"}},
		// Zero media errors IS a reading and must stay silent: at_least 1 is
		// the boundary, and a truthiness test here would have called a healthy
		// drive faulty for reporting a count of nothing.
		{"zero media errors is silence", "nvme", map[string]any{
			"State": "live", "SmartMediaErrors": float64(0),
		}, map[string]string{}},
		{"a failed self-test is a warning", "scsi", map[string]any{
			"DeviceType": "disk", "State": "running",
			"SmartSelftestStatus": "error_read",
		}, map[string]string{"smart-selftest": "warn"}},
		// Everything that is not a failure verdict stays silent — the
		// aborted/interrupted family is not a fault.
		{"an interrupted self-test is not a failure", "scsi", map[string]any{
			"DeviceType": "disk", "State": "running",
			"SmartSelftestStatus": "inprogress",
		}, map[string]string{}},
		// A drive left asleep on purpose wears INFO, not a warning: waking a
		// sleeping disk every five minutes to take its temperature would cost
		// more than the reading is worth.
		{"a sleeping drive's stale snapshot is normal", "scsi", map[string]any{
			"DeviceType": "disk", "State": "running",
			"SmartTemperatureC": float64(31), "SmartSnapshotAt": "2026-08-21T09:00:00Z",
			"SmartSnapshotAgeSeconds": float64(7200),
			"SmartSnapshotReason":     "Device is in STANDBY mode, exit(2)",
			"SmartSnapshotAsleep":     true,
		}, map[string]string{"smart-snapshot-asleep": "info"}},
		{"a stale snapshot with a reason is a warning", "scsi", map[string]any{
			"DeviceType": "disk", "State": "running",
			"SmartTemperatureC": float64(31), "SmartSnapshotAt": "2026-08-21T09:00:00Z",
			"SmartSnapshotAgeSeconds": float64(7200),
			"SmartSnapshotReason":     "Read Device Identity failed",
			"SmartSnapshotAsleep":     false,
		}, map[string]string{"smart-snapshot-stale": "warn"}},
		{"a stale snapshot with no reason is a warning", "scsi", map[string]any{
			"DeviceType": "disk", "State": "running",
			"SmartTemperatureC": float64(31), "SmartSnapshotAt": "2026-08-21T09:00:00Z",
			"SmartSnapshotAgeSeconds": float64(7200),
		}, map[string]string{"smart-snapshot-unexplained": "warn"}},
		// Fresh is silent, and 900 seconds is the boundary: three collector
		// periods, so the period after that is the first that is late.
		{"a fresh snapshot is silent", "scsi", map[string]any{
			"DeviceType": "disk", "State": "running",
			"SmartTemperatureC": float64(31), "SmartSnapshotAt": "2026-08-21T11:55:00Z",
			"SmartSnapshotAgeSeconds": float64(900),
		}, map[string]string{}},
		// The link, and the distinction the whole rule exists for.
		{"a link at its own maximum is silent", "nvme", map[string]any{
			"State": "live", "LinkSpeed": "8.0 GT/s PCIe",
			"LinkSpeedMax": "8.0 GT/s PCIe", "LinkSpeedStatus": "at-maximum",
			"LinkWidth": float64(4), "LinkWidthMax": float64(4),
			"LinkWidthStatus": "at-maximum",
		}, map[string]string{}},
		{"a link the slot accounts for is information", "nvme", map[string]any{
			"State": "live", "LinkWidth": float64(2), "LinkWidthMax": float64(4),
			"SlotLinkWidthMax": float64(2), "LinkWidthStatus": "capped-by-slot",
		}, map[string]string{"link-width-slot-capped": "info"}},
		{"a link below both ends is a warning", "nvme", map[string]any{
			"State": "live", "LinkWidth": float64(2), "LinkWidthMax": float64(4),
			"SlotLinkWidthMax": float64(4), "LinkWidthStatus": "degraded",
			"LinkSpeed": "2.5 GT/s PCIe", "LinkSpeedMax": "8.0 GT/s PCIe",
			"SlotLinkSpeedMax": "8.0 GT/s PCIe", "LinkSpeedStatus": "degraded",
		}, map[string]string{"link-width-degraded": "warn", "link-degraded": "warn"}},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			got := judge(t, testcase.collection, testcase.facts)
			if !same(got, testcase.want) {
				t.Errorf("fired %v, want %v", got, testcase.want)
			}
		})
	}
}

// Acceptance item 7 at the rule table: every fact a rule cites is declared by
// the same collection, so an operator following the evidence finds it. Refused
// at load rather than at judgement, which is what RulesFor answering with an
// error means.
func TestEveryRuleTableLoadsWithItsCitationsDeclared(t *testing.T) {
	for _, collection := range []string{"scsi", "nvme"} {
		if _, err := collate.RulesFor(string(declarationBytes), collection); err != nil {
			t.Errorf("%s: %v", collection, err)
		}
	}
}
