// The declared rule tables, FIRED — not merely pinned — through the
// collator's own evaluator against this collector's shipped declaration
// (the champions' pattern, se-collect-hardware/rules_test.go). Cases are
// written from agent/rules/downloaders.py, which is a correspondence no machine
// here checks.
// COVERAGE: downloader-disk is NOT declared — its percentage is arithmetic
// over two facts, which the closed condition vocabulary cannot express, so
// it stays the reference evaluator's until a DiskUsedPercent fact is minted
// on both implementations (the champions' derived-fact route).
package main

import (
	"testing"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func TestTheDownloadersRulesFireOnCharacteristicReadings(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		collection string
		facts      map[string]any
		want       map[string]string
	}{
		{"a healthy client is silent", "clients",
			map[string]any{"Client": "transmission", "Paused": false},
			map[string]string{}},
		{"incomplete receipts", "clients",
			map[string]any{"ConfigMissing": []any{"SE_SABNZBD_API_KEY"}},
			map[string]string{"downloader-unconfigured": "warn"}},
		{"a dark client", "clients",
			map[string]any{"Client": "sabnzbd", "StatusUnobservable": "did not answer"},
			map[string]string{"downloader-unreachable": "critical"}},
		{"a comfortable volume is silent", "clients",
			map[string]any{"Client": "sabnzbd", "DiskUsedPercent": 39.0},
			map[string]string{}},
		{"a filling volume", "clients",
			map[string]any{"Client": "sabnzbd", "DiskUsedPercent": 92.0},
			map[string]string{"downloader-disk": "warn"}},
		{"a nearly full volume", "clients",
			map[string]any{"Client": "sabnzbd", "DiskUsedPercent": 97.0},
			map[string]string{"downloader-disk-critical": "critical"}},
		{"a paused queue", "clients",
			map[string]any{"Client": "sabnzbd", "Paused": true},
			map[string]string{"downloader-paused": "warn"}},
		{"a local error is the client's severest", "transfers",
			map[string]any{"Error": 3.0, "ErrorString": "No data found"},
			map[string]string{"transfer-error": "critical"}},
		{"a tracker error", "transfers",
			map[string]any{"Error": 2.0, "ErrorString": "announce failed"},
			map[string]string{"transfer-error": "warn"}},
		{"an error code with no words is not judged", "transfers",
			map[string]any{"Error": 1.0},
			map[string]string{}},
		{"the client's own stalled verdict", "transfers",
			map[string]any{"Error": 0.0, "IsStalled": true},
			map[string]string{"transfer-stalled": "warn"}},
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
