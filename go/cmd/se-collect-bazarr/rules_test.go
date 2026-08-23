// The declared rule table, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/bazarr.py, which is a correspondence no machine
// here checks.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheBazarrRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"a healthy instance is silent", "instance",
			map[string]any{"Version": "1.6.0", "HealthIssues": []any{}},
			map[string]string{}},
		{"incomplete receipts", "instance",
			map[string]any{"ConfigMissing": []any{"SE_BAZARR_API_KEY"}},
			map[string]string{"bazarr-unconfigured": "warn"}},
		{"a dark instance", "instance",
			map[string]any{"StatusUnobservable": "did not answer"},
			map[string]string{"bazarr-unreachable": "critical"}},
		{"the app's own health list", "instance",
			map[string]any{"HealthIssues": []any{"Missing languages profile"}},
			map[string]string{"bazarr-health": "warn"}},
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
