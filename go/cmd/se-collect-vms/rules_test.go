// The declared rule table, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/vms.py, which is a correspondence no machine
// here checks.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheDomainRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"a running guest with a visible address is silent", "domains",
			map[string]any{"State": "running"},
			map[string]string{}},
		{"a crashed domain", "domains",
			map[string]any{"State": "crashed"},
			map[string]string{"domain-health": "critical"}},
		{"a paused domain", "domains",
			map[string]any{"State": "paused"},
			map[string]string{"domain-health": "warn"}},
		{"shutoff with autostart is something meant to be up", "domains",
			map[string]any{"State": "shutoff", "Autostart": true},
			map[string]string{"domain-health": "warn"}},
		{"shutoff without autostart is neutral", "domains",
			map[string]any{"State": "shutoff", "Autostart": false},
			map[string]string{}},
		{"a running guest nobody could address", "domains",
			map[string]any{"State": "running", "IPAddressesUnobservable": "no source answered"},
			map[string]string{"domain-address-unobservable": "info"}},
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
