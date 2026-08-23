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

// The three slice rules, EVALUATOR-decided (DESIGN 17, ruled
// 2026-08-23). Their test reads StallExplainedBy — a map indexed by
// another fact's own NAME — which the condition vocabulary cannot
// express: it tests a fact against a value, never a map against a key it
// computes from the fact it is already reading.
//
// The case the whole family exists for is the third one: an unread
// member is not a quiet one, and reporting it as "nothing explains this"
// would invent the interesting finding out of a gap in the reading.
func TestTheSliceRulesAreDecidedByTheirEvaluator(t *testing.T) {
	for _, testcase := range []struct {
		name  string
		facts map[string]any
		want  map[string]string
	}{
		{"a member accounts for the stall, so the slice states nothing",
			// One stall reported twice, the second time with the culprit's
			// name removed — found by the operator on 2026-08-13.
			map[string]any{"PsiIoFullAvg60": 56.35,
				"StallExplainedBy": map[string]any{"PsiIoFullAvg60": "cache-1.scope"}},
			map[string]string{}},
		{"every member was read and none accounts for it",
			map[string]any{"PsiIoFullAvg60": 54.55,
				"StallUnexplained": map[string]any{"PsiIoFullAvg60": true}},
			map[string]string{"slice-stall-unexplained": "warn"}},
		{"unexplained below the bar a single workload must clear",
			map[string]any{"PsiIoFullAvg60": 4.2,
				"StallUnexplained": map[string]any{"PsiIoFullAvg60": true}},
			map[string]string{"slice-stall-unexplained-minor": "info"}},
		{"a member could not be read, which is not a member that was quiet",
			map[string]any{"PsiIoFullAvg60": 54.55,
				"StallAttributionUnobservable": map[string]any{
					"PsiIoFullAvg60": "cgroup unreadable"}},
			map[string]string{"slice-stall-unattributed": "info"}},
		{"below the floor a slice states nothing at all",
			map[string]any{"PsiIoFullAvg60": 0.4,
				"StallUnexplained": map[string]any{"PsiIoFullAvg60": true}},
			map[string]string{}},
		{"each resource is judged on its own facts",
			// Explained for I/O and unexplained for memory in the same
			// minute: one boolean across both would be false for one.
			map[string]any{"PsiIoFullAvg60": 61.0, "PsiMemoryFullAvg60": 33.0,
				"StallExplainedBy": map[string]any{"PsiIoFullAvg60": "cache-1.scope"},
				"StallUnexplained": map[string]any{"PsiMemoryFullAvg60": true}},
			map[string]string{"slice-stall-unexplained": "warn"}},
	} {
		rules, err := collate.RulesFor(string(declarationBytes), "workloads")
		if err != nil {
			t.Fatalf("rules for workloads: %v", err)
		}
		fired := map[string]string{}
		for _, opinion := range collate.Judge(rules, "object", nil, testcase.facts) {
			fired[opinion.Key] = opinion.Level
		}
		// The workload rules share this collection and fire on the same
		// facts, so only the slice family is compared here.
		for key := range fired {
			if key != "slice-stall-unexplained" &&
				key != "slice-stall-unexplained-minor" &&
				key != "slice-stall-unattributed" {
				delete(fired, key)
			}
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
