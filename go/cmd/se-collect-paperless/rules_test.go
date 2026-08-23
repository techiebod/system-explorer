// The declared rule table, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/paperless.py, which is a correspondence no machine
// here checks.
// COVERAGE: paperless-storage is NOT declared — its percentage is
// arithmetic over two facts, which the closed condition vocabulary cannot
// express, so it stays the reference evaluator's until a StorageUsedPercent
// fact is minted on both implementations.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestThePaperlessRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"a healthy archive is silent", "instance",
			map[string]any{"DocumentCount": 38.0, "DatabaseStatus": "OK", "RedisStatus": "OK", "CeleryStatus": "OK", "IndexStatus": "OK", "ClassifierStatus": "OK"},
			map[string]string{}},
		{"the emptied-library shape", "instance",
			map[string]any{"DocumentCount": 0.0, "DatabaseStatus": "OK"},
			map[string]string{"paperless-empty": "critical"}},
		{"a failing database check", "instance",
			map[string]any{"DocumentCount": 38.0, "DatabaseStatus": "ERROR"},
			map[string]string{"paperless-database": "critical"}},
		{"a failing celery check", "instance",
			map[string]any{"DocumentCount": 38.0, "CeleryStatus": "WARNING"},
			map[string]string{"paperless-celery": "warn"}},
		{"permission-scoped components are not judged", "instance",
			map[string]any{"DocumentCount": 38.0},
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
