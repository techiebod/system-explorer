// The declared rule tables, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/servarr.py, which is a correspondence no machine
// here checks.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheServarrRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"a healthy app is silent", "apps",
			map[string]any{"App": "radarr", "HealthErrors": 0.0, "HealthWarnings": 0.0},
			map[string]string{}},
		{"a duplicated name", "apps",
			map[string]any{"App": "radarr", "ConfigDuplicate": []any{"radarr"}},
			map[string]string{"servarr-duplicate": "warn"}},
		{"missing receipts", "apps",
			map[string]any{"App": "radarr", "ConfigMissing": []any{"SE_RADARR_URL"}},
			map[string]string{"servarr-unconfigured": "warn"}},
		{"a dark instance", "apps",
			map[string]any{"App": "radarr", "StatusUnobservable": "did not answer"},
			map[string]string{"servarr-unreachable": "critical"}},
		{"health errors outrank warnings", "apps",
			map[string]any{"App": "radarr", "HealthErrors": 2.0, "HealthWarnings": 3.0},
			map[string]string{"servarr-health": "critical"}},
		{"warnings alone", "apps",
			map[string]any{"App": "radarr", "HealthErrors": 0.0, "HealthWarnings": 1.0},
			map[string]string{"servarr-health": "warn"}},
		{"an error item mirrors critical", "health",
			map[string]any{"Type": "error", "Message": "Indexers unavailable"},
			map[string]string{"servarr-health-item": "critical"}},
		{"a notice mirrors info", "health",
			map[string]any{"Type": "notice", "Message": "New update available"},
			map[string]string{"servarr-health-item": "info"}},
		{"an unknown grade is still the app raising its hand", "health",
			map[string]any{"Type": "urgent", "Message": "?"},
			map[string]string{"servarr-health-item": "warn"}},
		{"a passing check is silence", "health",
			map[string]any{"Type": "ok", "Message": "All good"},
			map[string]string{}},
		{"a typed item without words is not mirrored", "health",
			map[string]any{"Type": "error"},
			map[string]string{}},
		{"the app's own queue verdict", "queue",
			map[string]any{"TrackedDownloadStatus": "warning"},
			map[string]string{"queue-item-stuck": "warn"}},
		{"an ok record is silence", "queue",
			map[string]any{"TrackedDownloadStatus": "ok"},
			map[string]string{}},
	} {
		rules, err := collate.RulesFor(string(declarationBytes), testcase.collection)
		if err != nil {
			t.Fatalf("rules for %s: %v", testcase.collection, err)
		}
		if len(rules) == 0 {
			t.Fatalf("%s declares no rules", testcase.collection)
		}
		fired := map[string]string{}
		for _, opinion := range collate.Judge(rules, "object", nil, testcase.facts) {
			fired[opinion.Key] = opinion.Level
		}
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
