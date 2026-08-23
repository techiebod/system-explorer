// The declared rule table, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/resources.py, which is a correspondence no machine
// here checks.
// COVERAGE: the slice rules (unexplained stall, unreadable member) are NOT
// declared — they read the StallExplainedBy map per fact, which the flat
// vocabulary cannot express, so they stay the reference evaluator's.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheWorkloadRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"a quiet workload is silent", "workloads",
			map[string]any{"PsiIoFullAvg60": 0.4, "PsiMemoryFullAvg60": 0.0},
			map[string]string{}},
		{"an I/O stall", "workloads",
			map[string]any{"PsiIoFullAvg60": 25.5},
			map[string]string{"workload-io-stall": "warn"}},
		{"a memory stall", "workloads",
			map[string]any{"PsiMemoryFullAvg60": 12.0},
			map[string]string{"workload-memory-stall": "warn"}},
		{"both at once", "workloads",
			map[string]any{"PsiIoFullAvg60": 30.0, "PsiMemoryFullAvg60": 15.0},
			map[string]string{"workload-io-stall": "warn", "workload-memory-stall": "warn"}},
		{"no PSI is no verdict", "workloads",
			map[string]any{"CpuUsageUsec": 1000.0},
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
