// The declared subnet rule table, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern). Cases are written from agent/rules/kea.py,
// which is a correspondence no machine here checks.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheSubnetRulesFireOnCharacteristicReadings(t *testing.T) {
	rules, err := collate.RulesFor(string(declarationBytes), "subnets")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("subnets declares no rules")
	}
	for _, testcase := range []struct {
		name  string
		facts map[string]any
		want  map[string]string
	}{
		{"a comfortable pool is silent",
			map[string]any{"UsedPercent": 3.0, "DeclinedAddresses": 0.0},
			map[string]string{}},
		{"the warn band — new devices soon get nothing",
			map[string]any{"UsedPercent": 92.0},
			map[string]string{"kea-pool-capacity": "warn"}},
		{"the critical band",
			map[string]any{"UsedPercent": 97.0},
			map[string]string{"kea-pool-capacity-critical": "critical"}},
		{"any declined address is poisoned ground",
			map[string]any{"UsedPercent": 3.0, "DeclinedAddresses": 1.0},
			map[string]string{"kea-declined": "warn"}},
		// A subnet with no pool arithmetic (no UsedPercent minted) is
		// undecidable, and undecidable is silence — never alarm.
		{"a poolless subnet is silent",
			map[string]any{"TotalAddresses": 0.0},
			map[string]string{}},
	} {
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
