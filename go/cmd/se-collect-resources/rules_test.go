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
	"strings"
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
		// Judged AS A WORKLOAD: these rules address the leaf shapes and
		// not slices, so the shape is part of the case rather than a
		// detail the harness can leave unstated.
		for _, opinion := range collate.JudgeShaped(rules, "object", nil,
			"service", testcase.facts) {
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
		// Judged AS A SLICE, and compared whole.
		//
		// This loop used to judge with no shape and then delete every key
		// that was not one of the three slice keys, "because the workload
		// rules share this collection and fire on the same facts". That
		// filter removed the evidence of a real defect: the workload
		// stall rules were firing on slice rows, restoring the operator
		// report of 2026-08-13 — a slice at 56.35% listed beneath the
		// container scope that explains it, one stall reported twice with
		// the culprit's name removed — and at warn rather than the info
		// the reference suppresses entirely. The first case below asserts
		// that a slice whose stall a member explains states NOTHING, and
		// with the filter in place it passed while the collator emitted a
		// warn on that row. A guard that deletes what it does not expect
		// is a guard that cannot fail.
		fired := map[string]string{}
		for _, opinion := range collate.JudgeShaped(rules, "object", nil,
			"slice", testcase.facts) {
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

// The shape split itself, which is what stops one table judging two kinds
// of row. Written from the reference's own dispatch
// (agent/adapters/resources.py:884 — `is_slice = name.endswith(".slice")`,
// then slice_opinions OR workload_opinions and never both).
func TestASliceIsNeverJudgedByTheWorkloadRulesOrTheReverse(t *testing.T) {
	rules, err := collate.RulesFor(string(declarationBytes), "workloads")
	if err != nil {
		t.Fatal(err)
	}
	// A slice whose stall a member accounts for: the member's row carries
	// the condition with the name on it, and the slice states nothing.
	explained := map[string]any{
		"PsiIoFullAvg60":   56.35,
		"StallExplainedBy": map[string]any{"PsiIoFullAvg60": "cache-1.scope"},
	}
	if fired := collate.JudgeShaped(rules, "o", nil, "slice", explained); len(fired) != 0 {
		t.Fatalf("a slice whose stall a member explains states nothing, got %+v", fired)
	}
	// The very same numbers on the member itself DO state the condition.
	member := collate.JudgeShaped(rules, "o", nil, "scope",
		map[string]any{"PsiIoFullAvg60": 56.35})
	if len(member) != 1 || member[0].Key != "workload-io-stall" {
		t.Fatalf("the member's own row carries it: %+v", member)
	}
	// And a slice never picks up the workload wording, which would put
	// "This workload made no progress" on an object whose type is slice.
	unexplained := map[string]any{
		"PsiIoFullAvg60":   54.55,
		"StallUnexplained": map[string]any{"PsiIoFullAvg60": true},
	}
	for _, opinion := range collate.JudgeShaped(rules, "o", nil, "slice", unexplained) {
		if opinion.Key == "workload-io-stall" || opinion.Key == "workload-memory-stall" {
			t.Fatalf("a workload rule fired on a slice: %+v", opinion)
		}
	}

	// **And the other direction, which the first version of this test
	// could not see.** A leaf workload carrying the slice attribution
	// facts must not pick up the SLICE wording: "no workload inside it
	// accounts for it" is a sentence about a container of other rows, and
	// a scope has nothing inside it. Written after removing the slice
	// rules' own applies_to left every assertion above still green —
	// proven 2026-08-23 — because no case here had a workload-shaped row
	// carrying facts a slice rule reads.
	for _, opinion := range collate.JudgeShaped(rules, "o", nil, "scope", unexplained) {
		if strings.HasPrefix(opinion.Key, "slice-") {
			t.Fatalf("a slice rule fired on a leaf workload: %+v", opinion)
		}
	}
}

// Every shape this collector emits is addressed by some rule, and the
// work list comes from the COLLECTOR rather than from the corpus.
//
// applies_to was first written from the types the committed corpus
// happened to contain — service, scope, mount, socket — and the
// collector's own vocabulary is six wide: cgroupUnitSuffixes adds
// `.slice` and `.swap`. A `.swap` unit sits directly under `-.slice`,
// so it is emitted with type "swap", and it silently lost BOTH workload
// rules: the reference dispatches on one shape only (is_slice, else
// workload) and judges a swap unit with the workload rules. A corpus
// that happens not to contain a shape is not evidence that the shape
// does not exist, which is the subset-guard defect sourcing a list.
func TestEveryShapeThisCollectorEmitsIsJudgedBySomething(t *testing.T) {
	rules, err := collate.RulesFor(string(declarationBytes), "workloads")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("workloads declares no rules")
	}
	for _, suffix := range cgroupUnitSuffixes {
		shape := strings.TrimPrefix(suffix, ".")
		addressed := false
		for _, rule := range rules {
			if len(rule.AppliesTo) == 0 {
				addressed = true // an unscoped rule judges every shape
				break
			}
			for _, want := range rule.AppliesTo {
				if want == shape {
					addressed = true
				}
			}
		}
		if !addressed {
			t.Errorf("this collector emits type %q and no rule addresses it; "+
				"a shape nothing judges is a row that cannot be wrong", shape)
		}
	}
}

func TestASwapUnitIsJudgedAsAWorkloadNotAsASlice(t *testing.T) {
	// The reference judges it with the workload rules — it dispatches on
	// `is_slice` and nothing else — and this port judged it with neither.
	rules, err := collate.RulesFor(string(declarationBytes), "workloads")
	if err != nil {
		t.Fatal(err)
	}
	fired := collate.JudgeShaped(rules, "o", nil, "swap",
		map[string]any{"PsiIoFullAvg60": 56.35})
	if len(fired) != 1 || fired[0].Key != "workload-io-stall" {
		t.Fatalf("a swap unit stalling states it: %+v", fired)
	}
	// And not the slice wording, which is about a container of rows.
	for _, opinion := range collate.JudgeShaped(rules, "o", nil, "swap",
		map[string]any{"PsiIoFullAvg60": 54.55,
			"StallUnexplained": map[string]any{"PsiIoFullAvg60": true}}) {
		if strings.HasPrefix(opinion.Key, "slice-") {
			t.Fatalf("a slice rule fired on a swap unit: %+v", opinion)
		}
	}
}
