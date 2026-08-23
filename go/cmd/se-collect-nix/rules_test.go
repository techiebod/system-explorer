// The declared rule table, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/nix.py, which is a correspondence no machine
// here checks.
// COVERAGE: deployment-not-verified is NOT declared — its condition reads
// Deployment.Outcome, a nested member the flat fact vocabulary cannot
// reach, so it stays the reference evaluator's until a flat outcome fact is
// minted on both implementations.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheGenerationRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"the activated generation is silent", "generations",
			map[string]any{"Profile": true, "Current": true, "Booted": true},
			map[string]string{}},
		{"a pending profile", "generations",
			map[string]any{"Profile": true, "Current": false},
			map[string]string{"generation-pending": "info"}},
		{"an unattested activation", "generations",
			map[string]any{"Profile": false, "Current": false, "ReceiptsExpected": true},
			map[string]string{"deployment-unattested": "warn"}},
		{"a receipted generation is silent", "generations",
			map[string]any{"ReceiptsExpected": true, "Deployment": []any{"stub"}},
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
