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
	Type        string   `json:"type"`
	Values      []string `json:"values"`
	Temperament string   `json:"temperament"`
	Kind        string   `json:"kind"`
	Discloses   string   `json:"discloses"`
	Sentence    string   `json:"sentence"`
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
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "units" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 1 {
		t.Fatalf("one collection, units; got %d", len(declaration.Collections))
	}
	return declaration.Collections[0]
}

// The declared set and the set this code can emit are ONE set, in both
// directions: a fact declared and never emitted is a promise nothing tests, and
// one emitted and never declared has no sentence, no type and no disclosure
// class. The emittable side is derived from the source's own tables where there
// is one, so a directive added to the walk without a declaration fails here.
func TestTheDeclaredFactsAreExactlyTheEmittableOnes(t *testing.T) {
	collection := decodeDeclaration(t)
	emittable := map[string]bool{
		"LoadState": true, "ActiveState": true, "SubState": true,
		"Description": true, "RuntimeSynthesised": true, "ContainerID": true,
		"MachineName": true, "Slice": true, "ReferencedBy": true,
		"MissingReferenceUnobservable": true,
	}
	for _, fact := range absentReferenceFacts {
		emittable[fact] = true
	}
	for name := range emittable {
		if _, declared := collection.Facts[name]; !declared {
			t.Errorf("%s is emitted and not declared", name)
		}
	}
	for name := range collection.Facts {
		if !emittable[name] {
			t.Errorf("%s is declared and this collector cannot emit it", name)
		}
	}
}

// The pinned members, asserted from the wire side: the schema-validation half
// (se.declaration.1.json is closed) runs in the Python harness, which owns the
// contract registry.
func TestTheDeclarationCarriesThePinnedContract(t *testing.T) {
	collection := decodeDeclaration(t)
	if collection.Name != collectionUnits || collection.Freshness != "60s" {
		t.Fatalf("collection %q at freshness %q", collection.Name, collection.Freshness)
	}
	// The prefix and the row's name are what the collator mints the id from,
	// and `unit:<name>` is the id the shipping adapter mints — so a port that
	// moved either would publish a second object for one unit.
	if collection.Prefix != "unit" {
		t.Fatalf("prefix %q: the id is <prefix>:<name>, and the adapter's is unit:<name>", collection.Prefix)
	}

	// Temperament decides whether a fact churns the snapshot diff (DESIGN 12),
	// which is why it is pinned rather than left to reading. Every fact here is
	// either a state systemd reports or a piece of the unit's declaration, and
	// nothing is a counter or a gauge: this collection carries no measurement
	// at all, which is the boundary that keeps /v1/changes from reporting every
	// cgroup-bearing unit as changed on every poll.
	temperament := map[string]string{
		"LoadState": "state", "ActiveState": "state", "SubState": "state",
		"Description": "configuration", "RuntimeSynthesised": "configuration",
		"ContainerID": "existence", "MachineName": "existence",
		"Slice": "configuration", "MissingRequirements": "configuration",
		"MissingWants": "configuration", "MissingOrdering": "configuration",
		"ReferencedBy": "configuration", "MissingReferenceUnobservable": "state",
	}
	if len(collection.Facts) != len(temperament) {
		t.Fatalf("declared facts %v", collection.Facts)
	}
	for fact, want := range temperament {
		declared, ok := collection.Facts[fact]
		if !ok {
			t.Errorf("fact %s is not declared", fact)
			continue
		}
		if declared.Temperament != want {
			t.Errorf("%s is declared %q, pinned %q", fact, declared.Temperament, want)
		}
		if declared.Sentence == "" {
			t.Errorf("%s has no sentence, and a sentence is what a consumer renders", fact)
		}
	}

	// The four facts that carry words somebody chose — a unit's description, a
	// slice's name, a domain name, and the referrer lists that are made of unit
	// names — are `content` and the rest disclose nothing. Pinned because the
	// class is what a policy acts on (DESIGN 21) and it is one word per fact in
	// a file being written anyway, which is exactly how a forgotten one gets
	// published.
	content := map[string]bool{
		"Description": true, "MachineName": true, "Slice": true,
		"MissingRequirements": true, "MissingWants": true,
		"MissingOrdering": true, "ReferencedBy": true,
	}
	for fact, declared := range collection.Facts {
		want := "nothing"
		if content[fact] {
			want = "content"
		}
		if declared.Discloses != want {
			t.Errorf("%s discloses %q, pinned %q", fact, declared.Discloses, want)
		}
	}

	if len(collection.Redactions) != 0 || collection.Exemption == "" {
		t.Fatal("an exemption beside a redaction list is two rulings contradicting each other in one document")
	}
}

// LoadState and ActiveState are the two closed sets, and a value outside a
// declared enum fails contract verification — so the members are pinned here
// against what this collector actually reads off the wire, not against a
// vocabulary somebody remembered.
func TestTheTwoEnumsCarryTheStatesSystemdReports(t *testing.T) {
	facts := decodeDeclaration(t).Facts
	for name, required := range map[string][]string{
		"LoadState":   {"loaded", "not-found", "masked", "error"},
		"ActiveState": {"active", "inactive", "failed", "activating", "deactivating"},
	} {
		declared := map[string]bool{}
		for _, value := range facts[name].Values {
			declared[value] = true
		}
		if facts[name].Type != "enum" {
			t.Errorf("%s is declared %q; a closed set is an enum or a renderer has to guess", name, facts[name].Type)
		}
		for _, value := range required {
			if !declared[value] {
				t.Errorf("%s does not declare %q, which systemd reports", name, value)
			}
		}
	}
	// SubState is deliberately NOT an enum: its vocabulary is decided by the
	// unit's TYPE — mounted, plugged, exited, listening, waiting — so a closed
	// set here would refuse a legal reading the first time a unit type nobody
	// had met turned up.
	if facts["SubState"].Type != "string" || facts["SubState"].Values != nil {
		t.Error("SubState's vocabulary belongs to the unit type, not to systemd as a whole")
	}
}

// The declared reference commands must be the ones this collector actually
// makes, or an operator checking a surprising claim runs something else and
// gets a different answer. busctl is named because it IS the native document
// (DESIGN's 2026-08-19 ruling) — the bytes an operator gets by hand are the
// bytes this binary parses.
func TestTheReferenceCommandsAreTheCallsThisCollectorMakes(t *testing.T) {
	collection := decodeDeclaration(t)
	found := map[string]bool{}
	for _, command := range collection.Commands {
		if command.Purpose == "" {
			t.Errorf("reference command %v states no purpose", command.Argv)
		}
		for _, token := range command.Argv {
			switch token {
			case "ListUnits", "ListUnitFiles", "GetAll", "Get":
				found[token] = true
			}
		}
	}
	for _, member := range []string{"ListUnits", "ListUnitFiles", "GetAll", "Get"} {
		if !found[member] {
			t.Errorf("no reference command names %s, which the acquisition path calls", member)
		}
	}
	// Every busctl command must ask for the JSON rendering, because that IS
	// the document: a reference command that printed busctl's default output
	// would hand an operator a shape no `from` path addresses.
	for _, command := range collection.Commands {
		if command.Argv[0] != busctl {
			continue
		}
		if !strings.Contains(strings.Join(command.Argv, " "), "--json=short") {
			t.Errorf("reference command %v does not ask for the native rendering", command.Argv)
		}
	}
}
