package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestDeclareEmitsTheEmbeddedBytesExactlyAndStably(t *testing.T) {
	code, first, stderr := runWith(t, "declare\n", nil)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if first != string(declarationBytes) {
		t.Fatal("declare must emit the embedded declaration verbatim — any re-serialisation un-anchors the hash begin carries")
	}
	_, second, _ := runWith(t, "declare\n", nil)
	if first != second {
		t.Fatal("declare is static and must be byte-stable across runs")
	}

	sum := sha256.Sum256([]byte(first))
	if want := "sha256:" + hex.EncodeToString(sum[:]); declarationDigest != want {
		t.Fatalf("begin's declaration digest %q does not cover the declare bytes (%q)", declarationDigest, want)
	}
}

type declaredFact struct {
	Type        string `json:"type"`
	Unit        string `json:"unit"`
	Temperament string `json:"temperament"`
	Kind        string `json:"kind"`
	Discloses   string `json:"discloses"`
	Sentence    string `json:"sentence"`
}

type declaredCollection struct {
	Name       string                  `json:"name"`
	Prefix     string                  `json:"prefix"`
	Freshness  string                  `json:"freshness"`
	Answer     []string                `json:"answer"`
	Facts      map[string]declaredFact `json:"facts"`
	Redactions []any                   `json:"redactions"`
	Exemption  string                  `json:"redaction_exemption"`
	Commands   []struct {
		Purpose string   `json:"purpose"`
		Argv    []string `json:"argv"`
	} `json:"reference_commands"`
}

func decodeDeclaration(t *testing.T) declaredCollection {
	t.Helper()
	var declaration struct {
		Schema      string               `json:"schema"`
		Collector   string               `json:"collector"`
		Collections []declaredCollection `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "unbound" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 1 {
		t.Fatalf("one collection, daemon; got %d", len(declaration.Collections))
	}
	return declaration.Collections[0]
}

// The pinned members, asserted from the wire side: the schema-validation half
// (se.declaration.1.json is closed) runs in the Python harness, which owns the
// contract registry.
func TestTheDeclarationCarriesThePinnedContract(t *testing.T) {
	collection := decodeDeclaration(t)
	if collection.Name != collectionDaemon || collection.Freshness != "60s" {
		t.Fatalf("collection %q at freshness %q", collection.Name, collection.Freshness)
	}
	// The prefix and the row's name are what the collator mints the id from,
	// and `daemon:unbound` is the id the shipping adapter mints — so a port
	// that moved either would publish a second object for one resolver.
	if collection.Prefix != "daemon" {
		t.Fatalf("prefix %q: the id is <prefix>:<name>, and the adapter's is daemon:%s", collection.Prefix, daemonName)
	}

	// Temperament decides whether a fact churns the snapshot diff (DESIGN 12),
	// which is why it is pinned rather than left to reading: every figure here
	// moves on every sample, so a counter or a gauge each one must be. Uptime
	// in particular — declared `configuration` it would report this host as
	// changed on every single collect, for ever.
	temperament := map[string]string{
		"Version":                 "configuration",
		"Uptime":                  "gauge",
		"NumQueries":              "counter",
		"CacheHits":               "counter",
		"CacheMiss":               "counter",
		"Prefetches":              "counter",
		"RequestListCurrent":      "gauge",
		"RecursionTimeAvgSeconds": "gauge",
	}
	if len(collection.Facts) != len(temperament) {
		t.Fatalf("declared facts %v", collection.Facts)
	}
	// The declared set and the set this code can emit are one set: a fact
	// declared and never emitted is a promise nothing tests, and one emitted
	// and never declared has no sentence, no type and no disclosure class.
	emitted := map[string]bool{"Version": true, "Uptime": true}
	for _, fact := range counters {
		emitted[fact] = true
	}
	for fact, want := range temperament {
		declared, ok := collection.Facts[fact]
		if !ok {
			t.Errorf("fact %s is not declared", fact)
			continue
		}
		if !emitted[fact] {
			t.Errorf("%s is declared and this collector cannot emit it", fact)
		}
		if declared.Temperament != want {
			t.Errorf("%s is declared %q, pinned %q", fact, declared.Temperament, want)
		}
		if declared.Kind != "observed" {
			t.Errorf("%s is %q: every figure here is read off the daemon, including the average it computed for us", fact, declared.Kind)
		}
		if declared.Discloses != "nothing" {
			t.Errorf("%s discloses %q, pinned nothing", fact, declared.Discloses)
		}
		if declared.Sentence == "" {
			t.Errorf("%s has no sentence, and a sentence is what a consumer renders", fact)
		}
	}
	for fact := range emitted {
		if _, ok := collection.Facts[fact]; !ok {
			t.Errorf("%s is emitted and not declared", fact)
		}
	}

	if len(collection.Redactions) != 0 || collection.Exemption == "" {
		t.Fatal("an exemption beside a redaction list is two rulings contradicting each other in one document")
	}
}

// The _noreset suffix is what keeps this collector read-only: plain `stats`
// ZEROES every counter it reports. A reference command that named it would
// hand an administrator a command that destroys the reading they were checking
// — and would document this collector as a thing that must not be run twice.
func TestNoReferenceCommandNamesThePlainStatsCommand(t *testing.T) {
	collection := decodeDeclaration(t)
	found := map[string]bool{}
	for _, command := range collection.Commands {
		if command.Purpose == "" {
			t.Errorf("reference command %v states no purpose", command.Argv)
		}
		for _, token := range command.Argv {
			if token == "stats" {
				t.Errorf("reference command %v names the counter-zeroing `stats`", command.Argv)
			}
			switch token {
			case commandStatus:
				found[commandStatus] = true
			case commandStats:
				found[commandStats] = true
			}
		}
	}
	if !found[commandStatus] || !found[commandStats] {
		t.Fatalf("the declared reference commands have drifted from the commands in source.go: %v", found)
	}
}

// The socket path is deployment configuration, so it is named by SE_UNBOUND_SOCKET
// and not declared as a read path: a path invented here would be granted on the
// hosts that put the socket elsewhere and denied on the ones that do not. What
// the deployment must grant is the socket's GROUP, and that is the claim this
// pins — the reference's own capability reason names the same fix.
func TestTheDeclarationAsksForTheSocketsGroupAndNoInventedPath(t *testing.T) {
	var declaration struct {
		Authority struct {
			ReadPaths []string `json:"read_paths"`
			Groups    []string `json:"groups"`
		} `json:"authority"`
		Probe string `json:"probe"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	for _, path := range declaration.Authority.ReadPaths {
		if !strings.HasPrefix(path, "/proc/") {
			t.Errorf("read path %q: the only paths this collector opens are the two /proc files the envelope needs", path)
		}
	}
	if len(declaration.Authority.Groups) == 0 {
		t.Error("a control socket this collector may not open is the unauthorised decline; the group is what the deployment grants")
	}
	if !strings.Contains(declaration.Probe, socketVariable) {
		t.Errorf("the probe prose must name %s, which is where the socket's path comes from", socketVariable)
	}
}
