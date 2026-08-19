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
	Temperament string `json:"temperament"`
	Kind        string `json:"kind"`
	Discloses   string `json:"discloses"`
	Sentence    string `json:"sentence"`
}

type declaredCollection struct {
	Name      string                  `json:"name"`
	Prefix    string                  `json:"prefix"`
	Answer    []string                `json:"answer"`
	Facts     map[string]declaredFact `json:"facts"`
	Exemption string                  `json:"redaction_exemption"`
	Commands  []struct {
		Purpose string   `json:"purpose"`
		Argv    []string `json:"argv"`
	} `json:"reference_commands"`
}

func decodeDeclaration(t *testing.T) []declaredCollection {
	t.Helper()
	var declaration struct {
		Schema      string               `json:"schema"`
		Collector   string               `json:"collector"`
		Collections []declaredCollection `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatalf("the embedded declaration is not JSON: %v", err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "hardware" {
		t.Fatalf("declaration names %q/%q", declaration.Schema, declaration.Collector)
	}
	return declaration.Collections
}

// The declaration and the collect loop must serve the same five collections.
// Two lists is two things to disagree, and the disagreement is silent in the
// direction that matters: a collection declared and not served answers every
// request with `unsupported`, which a reader takes for a statement about the
// host.
func TestTheDeclarationServesExactlyWhatTheCollectLoopServes(t *testing.T) {
	declared := map[string]bool{}
	for _, collection := range decodeDeclaration(t) {
		declared[collection.Name] = true
	}
	for name := range served {
		if !declared[name] {
			t.Errorf("the collect loop serves %q and the declaration does not carry it", name)
		}
	}
	for name := range declared {
		if !served[name] {
			t.Errorf("the declaration carries %q and the collect loop declines it as unsupported", name)
		}
	}
}

// Every fact a row can carry has a sentence saying what it MEANS, and every
// answer names a fact that exists. The first is what the fact dictionary is
// generated from; the second is what decides which facts land on a row, so a
// typo there silently empties a table column.
func TestEveryDeclaredFactCarriesASentenceAndEveryAnswerNamesOne(t *testing.T) {
	for _, collection := range decodeDeclaration(t) {
		for name, fact := range collection.Facts {
			if strings.TrimSpace(fact.Sentence) == "" {
				t.Errorf("%s/%s has no sentence", collection.Name, name)
			}
			if fact.Discloses == "" || fact.Type == "" {
				t.Errorf("%s/%s is missing a required member", collection.Name, name)
			}
		}
		for _, name := range collection.Answer {
			if _, ok := collection.Facts[name]; !ok {
				t.Errorf("%s: answer names %q, which is not a declared fact", collection.Name, name)
			}
		}
		if strings.TrimSpace(collection.Exemption) == "" {
			t.Errorf("%s declares neither redactions nor an exemption", collection.Name)
		}
	}
}

// A reference command is a promise: an administrator can reproduce the
// observation by running it. That makes it a truthfulness surface, and the one
// way it rots is a collector growing a source nothing names — which is what
// happened to this subsystem once, when link rates, host identity and serials
// were all being read from places no listed command mentioned.
func TestEveryCommandThisCollectorRunsIsNamedByAReferenceCommand(t *testing.T) {
	named := map[string]bool{}
	for _, collection := range decodeDeclaration(t) {
		for _, command := range collection.Commands {
			if len(command.Argv) == 0 || strings.TrimSpace(command.Purpose) == "" {
				t.Errorf("%s: a reference command with no argv or no purpose", collection.Name)
				continue
			}
			named[command.Argv[0]] = true
		}
	}
	// The four binaries the live source can actually execute. Held against the
	// declaration rather than against a comment, because a command a person
	// cannot re-run is an observation they have to take on trust.
	for _, binary := range []string{"udevadm", "lscpu", "busctl", "smartctl"} {
		if !named[binary] {
			t.Errorf("this collector runs %s and no reference command names it", binary)
		}
	}
}
