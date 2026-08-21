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
	Name       string                  `json:"name"`
	Prefix     string                  `json:"prefix"`
	Answer     []string                `json:"answer"`
	Facts      map[string]declaredFact `json:"facts"`
	Exemption  string                  `json:"redaction_exemption"`
	Redactions []struct {
		Path      string `json:"path"`
		Discloses string `json:"discloses"`
	} `json:"redactions"`
	Commands []struct {
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
		// The message said "neither redactions nor an exemption" and the
		// check only ever looked at the exemption, so a collection that
		// declared a real redaction list read as undeclared — found when
		// platform grew one at R3c. The contract makes the two exclusive;
		// this asks for exactly one.
		exempt := strings.TrimSpace(collection.Exemption) != ""
		if exempt == (len(collection.Redactions) > 0) {
			t.Errorf("%s declares %d redactions and an exemption %q: exactly "+
				"one of the two, because both together are two rulings "+
				"contradicting each other in one document",
				collection.Name, len(collection.Redactions), collection.Exemption)
		}
	}
}

// What the platform collection withholds, path by path. Its exemption used to
// say that DMI carries product_serial, chassis_serial, board_serial and
// product_uuid, that they ARE identity, and that this collector read none of
// them — true until R3c, when the evidence verb began reading the DMI
// directory WHOLE. The exemption became false the moment that landed, so it
// was replaced by this list rather than reworded, and the list is pinned here
// because a forgotten redaction publishes a machine's own identity.
func TestThePlatformEvidenceWithholdsTheMachinesIdentity(t *testing.T) {
	var platform *declaredCollection
	for _, collection := range decodeDeclaration(t) {
		if collection.Name == "platform" {
			found := collection
			platform = &found
		}
	}
	if platform == nil {
		t.Fatal("no platform collection")
	}
	withheld := map[string]bool{}
	for _, redaction := range platform.Redactions {
		if redaction.Discloses != "identity" {
			t.Errorf("%s is withheld as %q; a machine's serial is identity",
				redaction.Path, redaction.Discloses)
		}
		withheld[redaction.Path] = true
	}
	for _, attribute := range []string{"product_serial", "chassis_serial",
		"board_serial", "product_uuid"} {
		if !withheld["/dmi/"+attribute] {
			t.Errorf("DMI %s is not withheld from evidence", attribute)
		}
	}
	if len(platform.Redactions) != 4 {
		t.Errorf("%d redactions declared; a fifth means the ruling moved and "+
			"this pin must move with it", len(platform.Redactions))
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
