package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
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
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "packages" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 1 {
		t.Fatalf("one collection, packages; got %d", len(declaration.Collections))
	}
	return declaration.Collections[0]
}

// The pinned members, asserted from the wire side: the schema-validation half
// (se.declaration.1.json is closed) runs in the Python harness, which owns the
// contract registry.
func TestTheDeclarationCarriesThePinnedContract(t *testing.T) {
	collection := decodeDeclaration(t)
	if collection.Name != "packages" || collection.Freshness != "1h" {
		t.Fatalf("collection %q at freshness %q", collection.Name, collection.Freshness)
	}

	discloses := map[string]string{
		"Name":         "nothing",
		"Version":      "nothing",
		"Manager":      "nothing",
		"Architecture": "nothing",
		"StorePath":    "nothing",
	}
	if len(collection.Facts) != len(discloses) {
		t.Fatalf("declared facts %v", collection.Facts)
	}
	for fact, want := range discloses {
		declared, ok := collection.Facts[fact]
		if !ok {
			t.Errorf("fact %s is not declared", fact)
			continue
		}
		if declared.Discloses != want {
			t.Errorf("%s discloses %q, pinned %q", fact, declared.Discloses, want)
		}
		if declared.Temperament != "configuration" || declared.Kind != "observed" {
			t.Errorf("%s: %s/%s — an installed set is configuration read off the interface", fact, declared.Temperament, declared.Kind)
		}
		if declared.Sentence == "" {
			t.Errorf("%s has no sentence, and a sentence is what a consumer renders", fact)
		}
	}

	// Manager is the one enum, and its members are the closed set the code
	// switches on. A value outside it would render unstyled at one consumer
	// and be refused by contract verification at the other, so the two sets
	// are held together here rather than by reading.
	manager := collection.Facts["Manager"]
	if manager.Type != "enum" || !slices.Equal(manager.Values, []string{managerNix, managerDpkg, managerRPM}) {
		t.Fatalf("Manager is declared %q over %v", manager.Type, manager.Values)
	}

	if len(collection.Redactions) != 0 || collection.Exemption == "" {
		t.Fatal("an exemption beside a redaction list is two rulings contradicting each other in one document")
	}
}

// The format strings are the whole reason these two commands are allow-listed
// on a flag rather than on a --json neither tool has: the fields and their
// order are this collector's, so nothing about a locale or a version can move
// them. A reference command that spelled the format differently would hand an
// administrator a different document from the one the facts were read out of.
func TestTheReferenceCommandsCarryTheFormatStringsTheCodeUses(t *testing.T) {
	collection := decodeDeclaration(t)
	found := map[string]bool{}
	for _, command := range collection.Commands {
		if command.Purpose == "" {
			t.Errorf("reference command %v states no purpose", command.Argv)
		}
		for _, token := range command.Argv {
			switch token {
			case dpkgFormat:
				found["dpkg"] = true
			case rpmFormat:
				found["rpm"] = true
			}
		}
	}
	if !found["dpkg"] || !found["rpm"] {
		t.Fatalf("the declared reference commands have drifted from the format strings in source.go: %v", found)
	}
}
