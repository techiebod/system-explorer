// The declared rule table, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/logs.py, which is a correspondence no machine
// here checks.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheJournalRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"an ordinary entry is silent", "journal",
			map[string]any{"Priority": 6.0, "Message": "started"},
			map[string]string{}},
		{"crit and below are trusted from priority alone", "journal",
			map[string]any{"Priority": 2.0},
			map[string]string{"journal-priority": "critical"}},
		{"a container's err is its stderr stream", "journal",
			map[string]any{"Priority": 3.0, "Container": "sabnzbd"},
			map[string]string{"journal-priority": "info"}},
		{"a bare err is recorded, not judged", "journal",
			map[string]any{"Priority": 3.0},
			map[string]string{"journal-priority": "info"}},
		{"repetition is the signal priority cannot give", "journal",
			map[string]any{"Priority": 3.0, "RepeatCount": 40.0, "RepeatWindow": 100.0},
			map[string]string{"journal-priority": "info", "journal-repeated": "info"}},
		{"repetition above the priority gate stays silent", "journal",
			map[string]any{"Priority": 4.0, "RepeatCount": 40.0, "RepeatWindow": 100.0},
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
