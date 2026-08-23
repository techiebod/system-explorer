// The declared container rule table, FIRED — not merely pinned — through
// the collator's own evaluator against this collector's shipped
// declaration (the champions' pattern). Cases are written from
// agent/rules/docker.py, which is a correspondence no machine here checks.
//
// COVERAGE: the OOMKilled rule is NOT declared — it is inspect-only with no
// list-endpoint carrier at all, the reference's own documented acquisition
// gap — and the reference's Status-substring fallbacks are not ported as
// rules because the ported rows now carry Health and ExitCode as facts,
// which is what the substring parses existed to approximate.
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheContainerRulesFireOnCharacteristicReadings(t *testing.T) {
	rules, err := collate.RulesFor(string(declarationBytes), "containers")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("containers declares no rules")
	}
	for _, testcase := range []struct {
		name  string
		facts map[string]any
		want  map[string]string
	}{
		{"a running healthy container is silent",
			map[string]any{"State": "running", "Health": "healthy"}, map[string]string{}},
		{"a running container with no healthcheck is silent",
			map[string]any{"State": "running"}, map[string]string{}},
		{"the container's own healthcheck verdict",
			map[string]any{"State": "running", "Health": "unhealthy"},
			map[string]string{"container-health": "critical"}},
		{"stuck restarting",
			map[string]any{"State": "restarting"},
			map[string]string{"container-health": "critical"}},
		{"paused is a container not doing its job",
			map[string]any{"State": "paused"},
			map[string]string{"container-health": "warn"}},
		{"a non-zero exit",
			map[string]any{"State": "exited", "ExitCode": 137.0},
			map[string]string{"container-exit": "warn"}},
		{"a clean exit is neutral",
			map[string]any{"State": "exited", "ExitCode": 0.0}, map[string]string{}},
		{"an exited container whose code nothing parsed is not judged",
			map[string]any{"State": "exited"}, map[string]string{}},
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
