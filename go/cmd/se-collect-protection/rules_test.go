// The declared rule table, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/protection.py, which is a correspondence no machine
// here checks.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheProtectionJobRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"a green job is silent", "jobs",
			map[string]any{"State": "ok", "Basis": "receipt", "LastResult": "success", "CheckedAgeSeconds": 600.0},
			map[string]string{}},
		{"a frozen verdict", "jobs",
			map[string]any{"State": "ok", "LastResult": "success", "CheckedAgeSeconds": 90000.0},
			map[string]string{"protection-verdict-stale": "warn"}},
		{"never succeeded on irreplaceable data", "jobs",
			map[string]any{"State": "stale", "Basis": "registered-never-succeeded", "TargetClass": "backup", "CheckedAgeSeconds": 600.0},
			map[string]string{"protection-never-succeeded": "critical"}},
		{"never succeeded, class unjoined", "jobs",
			map[string]any{"State": "stale", "Basis": "registered-never-succeeded", "CheckedAgeSeconds": 600.0},
			map[string]string{"protection-never-succeeded": "warn"}},
		{"stale over a standing success", "jobs",
			map[string]any{"State": "stale", "Basis": "receipt", "LastResult": "success", "CheckedAgeSeconds": 600.0},
			map[string]string{"protection-stale": "warn"}},
		{"a first run that failed", "jobs",
			map[string]any{"State": "ok", "Basis": "registered-never-succeeded", "LastResult": "failure", "CheckedAgeSeconds": 600.0},
			map[string]string{"protection-first-run-failed": "warn"}},
		{"a last run that failed over a standing success", "jobs",
			map[string]any{"State": "ok", "Basis": "receipt", "LastResult": "failure", "CheckedAgeSeconds": 600.0},
			map[string]string{"protection-last-run-failed": "warn"}},
		{"an unreadable receipt rides beside the ladder", "jobs",
			map[string]any{"State": "stale", "Basis": "receipt", "LastResult": "success", "ReceiptsUnobservable": "permission denied", "CheckedAgeSeconds": 600.0},
			map[string]string{"protection-stale": "warn", "protection-receipt-unreadable": "warn"}},
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

// The three target rules, which are EVALUATOR-decided rather than
// condition-decided (DESIGN 17, ruled 2026-08-23): their test is set
// algebra over two carried hop lists, which the closed condition
// vocabulary cannot express and was deliberately not widened to reach.
// The rows are still declared — key, level, grounds, sentence, cites —
// so only the test is code.
//
// The cases that matter are the EXCLUSIONS. The reference is an
// if/elif/else and rules here evaluate independently, so a target must
// state exactly one of these, never three severities of one condition.
func TestTheTargetRulesAreDecidedByTheirEvaluatorAndStayExclusive(t *testing.T) {
	for _, testcase := range []struct {
		name  string
		facts map[string]any
		want  map[string]string
	}{
		{"every hop built is silent",
			map[string]any{"Class": "backup", "UnimplementedHops": []any{},
				"IndependentDestinations": []any{"offsite"}},
			map[string]string{}},
		{"irreplaceable with every independent destination unbuilt",
			map[string]any{"Class": "backup", "Kind": "push",
				"UnimplementedHops":       []any{"offsite", "local"},
				"IndependentDestinations": []any{"offsite"}},
			map[string]string{"protection-no-durable-copy": "warn"}},
		{"a mirror's history, graded apart from data that exists nowhere else",
			map[string]any{"Class": "backup", "Kind": "saas-pull",
				"UnimplementedHops":       []any{"offsite"},
				"IndependentDestinations": []any{"offsite"}},
			map[string]string{"protection-no-durable-history": "info"}},
		{"an unbuilt hop that is not the whole independent set",
			map[string]any{"Class": "backup", "Kind": "push",
				"UnimplementedHops":       []any{"local"},
				"IndependentDestinations": []any{"offsite"}},
			map[string]string{"protection-hop-unimplemented": "info"}},
		{"declaring no independent destination is not a durable gap",
			// The empty set is trivially contained in anything, and
			// treating it as a gap would fire on every target in the
			// estate.
			map[string]any{"Class": "backup", "Kind": "push",
				"UnimplementedHops":       []any{"local"},
				"IndependentDestinations": []any{}},
			map[string]string{"protection-hop-unimplemented": "info"}},
		{"replaceable data with an unbuilt hop states the residual only",
			map[string]any{"Class": "cache", "Kind": "push",
				"UnimplementedHops":       []any{"offsite"},
				"IndependentDestinations": []any{"offsite"}},
			map[string]string{"protection-hop-unimplemented": "info"}},
	} {
		rules, err := collate.RulesFor(string(declarationBytes), "targets")
		if err != nil {
			t.Fatalf("rules for targets: %v", err)
		}
		if len(rules) == 0 {
			t.Fatal("targets declares no rules")
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
