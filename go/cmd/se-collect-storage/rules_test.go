// The declared rule tables, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration:
// the champions' pattern (se-collect-hardware/rules_test.go), with the
// cases written from agent/rules/storage.py, which is a correspondence no
// machine here checks.
//
// COVERAGE: this proves the DECLARED tables fire as intended on these
// inputs and that a healthy row is silent. The pools cases arrive with the
// pools table (R3d's rulebook wave); the datasets, arrays and mounts tables
// landed with their collections and are fired here too, because until this
// file existed nothing in this package fired any of them.
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

func TestTheStorageRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"a healthy pool is silent", "pools",
			map[string]any{"State": "ONLINE", "CapacityPercent": 40.0,
				"ScanFunction": "SCRUB", "ScanState": "FINISHED", "ScanAgeDays": 10.0},
			map[string]string{}},
		{"a non-ONLINE state is the pool's own verdict", "pools",
			map[string]any{"State": "DEGRADED"},
			map[string]string{"pool-health": "critical"}},
		// Presence-driven: an absent or unreadable state is neutral-unknown,
		// not an indictment — the rule is silent, never firing on absence.
		{"an absent state is not an indictment", "pools",
			map[string]any{"CapacityPercent": 40.0},
			map[string]string{}},
		{"unhealthy vdevs", "pools",
			map[string]any{"State": "ONLINE", "UnhealthyVdevs": []any{"raidz1-0"}},
			map[string]string{"vdev-health": "critical"}},
		{"vdev errors", "pools",
			map[string]any{"State": "ONLINE", "VdevsWithErrors": []any{"sda"}},
			map[string]string{"vdev-errors": "warn"}},
		{"the capacity warn band", "pools",
			map[string]any{"State": "ONLINE", "CapacityPercent": 85.0},
			map[string]string{"pool-capacity": "warn"}},
		{"the capacity critical band", "pools",
			map[string]any{"State": "ONLINE", "CapacityPercent": 92.0},
			map[string]string{"pool-capacity-critical": "critical"}},
		{"a scan in progress", "pools",
			map[string]any{"State": "ONLINE", "ScanFunction": "SCRUB", "ScanState": "SCANNING"},
			map[string]string{"pool-scan": "info"}},
		{"an unknowable scrub age is stated, not silent", "pools",
			map[string]any{"State": "ONLINE", "ScanFunction": "RESILVER",
				"ScanState":                    "FINISHED",
				"LastScrubEndTimeUnobservable": "a resilver replaced the scrub's record"},
			map[string]string{"pool-scrub-age-unknown": "info"}},
		{"a stale scrub", "pools",
			map[string]any{"State": "ONLINE", "ScanFunction": "SCRUB",
				"ScanState": "FINISHED", "ScanAgeDays": 40.0},
			map[string]string{"pool-scrub-stale": "warn"}},
		// A finished resilver at any age is not a stale SCRUB.
		{"a resilver's age never fires the scrub rule", "pools",
			map[string]any{"State": "ONLINE", "ScanFunction": "RESILVER",
				"ScanState": "FINISHED", "ScanAgeDays": 400.0},
			map[string]string{}},

		{"a dataset in the warn band", "datasets",
			map[string]any{"UsePercent": 92.0},
			map[string]string{"dataset-capacity": "warn"}},
		{"a dataset in the critical band", "datasets",
			map[string]any{"UsePercent": 96.0},
			map[string]string{"dataset-capacity-critical": "critical"}},
		{"a comfortable dataset is silent", "datasets",
			map[string]any{"UsePercent": 40.0},
			map[string]string{}},

		{"a degraded array", "arrays",
			map[string]any{"Degraded": 1.0, "RaidDisks": 2.0},
			map[string]string{"array-degraded": "critical"}},
		{"member errors", "arrays",
			map[string]any{"Degraded": 0.0, "MembersWithErrors": []any{"vdb1"}},
			map[string]string{"array-member-errors": "warn"}},
		{"a recover in progress", "arrays",
			map[string]any{"Degraded": 1.0, "SyncAction": "recover"},
			map[string]string{"array-degraded": "critical", "array-sync-recover": "warn"}},
		{"a routine check", "arrays",
			map[string]any{"Degraded": 0.0, "SyncAction": "check"},
			map[string]string{"array-sync": "info"}},

		{"a filling mount", "mounts",
			map[string]any{"UsePercent": 91.0},
			map[string]string{"mount-capacity": "warn"}},
		{"a nearly full mount", "mounts",
			map[string]any{"UsePercent": 97.0},
			map[string]string{"mount-capacity-critical": "critical"}},
	} {
		fired := judge(t, testcase.collection, testcase.facts)
		if len(fired) != len(testcase.want) {
			t.Errorf("%s: fired %v, want %v", testcase.name, fired, testcase.want)
			continue
		}
		for key, level := range testcase.want {
			if fired[key] != level {
				t.Errorf("%s: fired %v, want %v", testcase.name, fired, testcase.want)
			}
		}
	}
}
