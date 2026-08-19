package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
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
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "logs" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 1 {
		t.Fatalf("one collection, journal; got %d", len(declaration.Collections))
	}
	return declaration.Collections[0]
}

// The pinned members, asserted from the wire side: the schema-validation half
// (se.declaration.1.json is closed) runs in the Python harness, which owns the
// contract registry.
func TestTheDeclarationCarriesThePinnedContract(t *testing.T) {
	collection := decodeDeclaration(t)
	if collection.Name != collectionJournal || collection.Prefix != "entry" {
		t.Fatalf("collection %q with prefix %q", collection.Name, collection.Prefix)
	}

	// Disclosure is a fact about the value and the only thing a policy can act
	// on (DESIGN 21), so it is pinned rather than left to whoever edits the
	// file next. Message and Container are the two that carry somebody's words
	// — a log line is whatever a program chose to print, and a container name
	// is a word an operator typed — and every other fact here is a state, a
	// count, a catalogue constant or software's own name for itself.
	discloses := map[string]string{
		"Message":          "content",
		"MessageId":        "nothing",
		"Priority":         "nothing",
		"SyslogIdentifier": "nothing",
		"Transport":        "nothing",
		"SystemdUnit":      "nothing",
		"SystemdUserUnit":  "nothing",
		"Container":        "content",
		"Command":          "nothing",
		"PID":              "nothing",
		"Timestamp":        "nothing",
		"RepeatCount":      "nothing",
		"RepeatWindow":     "nothing",
	}
	if len(collection.Facts) != len(discloses) {
		t.Fatalf("declared %d facts, pinned %d: %v", len(collection.Facts), len(discloses), collection.Facts)
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
		if declared.Sentence == "" {
			t.Errorf("%s has no sentence, and a sentence is what a consumer renders", fact)
		}
	}

	// The two integers, held apart from the strings: Priority is parsed out of
	// a string by this collector and the repeat figures are counted here, so a
	// declaration calling any of them a string would describe a wire nobody
	// emits.
	for _, fact := range []string{"Priority", "RepeatCount", "RepeatWindow"} {
		if collection.Facts[fact].Type != "integer" {
			t.Errorf("%s is declared %q", fact, collection.Facts[fact].Type)
		}
	}

	// Transport is the one enum, and its members are systemd's own closed set
	// (systemd.journal-fields(7)). A value outside it would render unstyled at
	// one consumer and be refused by contract verification at the other.
	transport := collection.Facts["Transport"]
	if transport.Type != "enum" || !slices.Equal(transport.Values,
		[]string{"audit", "driver", "syslog", "journal", "stdout", "kernel"}) {
		t.Fatalf("Transport is declared %q over %v", transport.Type, transport.Values)
	}

	if len(collection.Redactions) != 0 || collection.Exemption == "" {
		t.Fatal("an exemption beside a redaction list is two rulings contradicting each other in one document")
	}
}

// Every fact `answer` names must be a fact this collection declares. `answer`
// decides what lands on a row (DESIGN 19), so a name here that no fact carries
// is a column the renderer asks for and nothing fills.
func TestTheAnswerNamesDeclaredFacts(t *testing.T) {
	collection := decodeDeclaration(t)
	if len(collection.Answer) == 0 {
		t.Fatal("a collection with no answer leaves the row's columns to whoever renders it")
	}
	for _, fact := range collection.Answer {
		if _, ok := collection.Facts[fact]; !ok {
			t.Errorf("answer names %q, which this collection does not declare", fact)
		}
	}
}

// The declared reference command must be the argv this binary actually runs. It
// is the whole of DESIGN 25's checkable-reading property here: a reader with
// the payload and the command can re-run one thing and compare, and a command
// that had drifted would hand them a different document from the one the facts
// were read out of.
func TestTheReferenceCommandIsTheArgvTheCodeRuns(t *testing.T) {
	collection := decodeDeclaration(t)
	want := append([]string{"journalctl"}, journalArgv(defaultLimit)...)
	found := false
	for _, command := range collection.Commands {
		if command.Purpose == "" {
			t.Errorf("reference command %v states no purpose", command.Argv)
		}
		if slices.Equal(command.Argv, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no declared reference command is %v; the declaration and source.go have drifted", want)
	}
}

// The probe's declared prose must name the authority the probe actually needs.
// journalctl on PATH is not the question — an unprivileged reader is answered
// with its own uid's entries and nothing else — so a declaration that promised
// only the binary would describe a collector that reports one user's session as
// the machine's journal.
func TestTheDeclaredAuthorityNamesTheJournalGroup(t *testing.T) {
	var declaration struct {
		Authority struct {
			Groups   []string `json:"groups"`
			Commands []string `json:"commands"`
		} `json:"authority"`
		Probe string `json:"probe"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(declaration.Authority.Groups, "systemd-journal") {
		t.Errorf("authority.groups is %v; without the journal group this collector reads its own uid's entries", declaration.Authority.Groups)
	}
	if !slices.Contains(declaration.Authority.Commands, "journalctl") {
		t.Errorf("authority.commands is %v, and journalctl is the whole interface", declaration.Authority.Commands)
	}
	if !strings.Contains(declaration.Probe, "uid") {
		t.Error("the probe's prose does not say what an unprivileged reader gets, which is the one way this collector reports a subset as the whole")
	}
}
