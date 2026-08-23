// The declared rule table, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/nix.py, which is a correspondence no machine
// here checks.
// COVERAGE: deployment-not-verified went the derived-fact route on
// 2026-08-23 — DeploymentOutcome is minted flat on both implementations
// where the receipt states one, so the rule is declared and fired here.
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
		{"a verified deployment is silent", "generations",
			map[string]any{"ReceiptsExpected": true, "Deployment": []any{"stub"},
				"DeploymentOutcome": "VERIFIED"},
			map[string]string{}},
		{"an unverified deployment", "generations",
			map[string]any{"ReceiptsExpected": true, "Deployment": []any{"stub"},
				"DeploymentOutcome": "ROLLED-BACK"},
			map[string]string{"deployment-not-verified": "warn"}},
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
