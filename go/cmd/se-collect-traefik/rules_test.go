// The declared rule tables, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/traefik.py, which is a correspondence no machine
// here checks.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheTraefikRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"a healthy router is silent", "routers",
			map[string]any{"Status": "enabled"},
			map[string]string{}},
		{"a rejected router", "routers",
			map[string]any{"Status": "disabled", "Error": []any{"invalid rule"}},
			map[string]string{"router-error": "critical", "router-disabled": "warn"}},
		{"a router loaded with warnings", "routers",
			map[string]any{"Status": "enabled", "Error": []any{"deprecated option"}},
			map[string]string{"router-warning": "warn"}},
		{"a disabled router with no error", "routers",
			map[string]any{"Status": "disabled"},
			map[string]string{"router-disabled": "warn"}},
		{"an unrecognised status is stated", "routers",
			map[string]any{"Status": "draining"},
			map[string]string{"router-warning": "warn"}},
		{"every backend down", "services",
			map[string]any{"Status": "enabled", "ServersDown": 2.0, "ServersUp": 0.0, "DownServers": []any{"a", "b"}},
			map[string]string{"service-servers-down": "critical"}},
		{"some backends down", "services",
			map[string]any{"Status": "enabled", "ServersDown": 1.0, "ServersUp": 2.0, "DownServers": []any{"a"}},
			map[string]string{"service-servers-down": "warn"}},
		{"middlewares in error", "overview",
			map[string]any{"MiddlewaresErrors": 1.0},
			map[string]string{"middlewares-errors": "warn"}},
		{"a clean overview is silent", "overview",
			map[string]any{"MiddlewaresErrors": 0.0},
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
