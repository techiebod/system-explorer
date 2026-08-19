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
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "resources" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 1 {
		t.Fatalf("one collection, workloads; got %d", len(declaration.Collections))
	}
	return declaration.Collections[0]
}

// The declared set and the set this code can emit are one set: a fact declared
// and never emitted is a promise nothing tests, and one emitted and never
// declared has no sentence, no type and no disclosure class. Both directions,
// and the emitted side is DERIVED from the tables the derivation actually
// reads rather than retyped, so adding a counter without declaring it fails
// here instead of at the contract harness.
func TestTheDeclaredFactsAreExactlyTheFactsThisCollectorCanEmit(t *testing.T) {
	collection := decodeDeclaration(t)
	if collection.Name != collectionWorkloads || collection.Prefix != "unit" {
		t.Fatalf("collection %q under prefix %q — the id is unit:<name>, which is "+
			"what units/units already publishes and what makes the two projections join",
			collection.Name, collection.Prefix)
	}

	emitted := map[string]bool{
		"Parent": true, "Depth": true, "Delegated": true,
		"CpuUsageUsec": true, "CpuUserUsec": true, "CpuSystemUsec": true,
		"CpuThrottledUsec": true, "CpuThrottledPeriods": true,
		"MemoryCurrentBytes": true, "MemoryPeakBytes": true,
		"MemorySwapCurrentBytes": true,
		"MemoryOomKills":         true, "MemoryOomEvents": true,
		"IoReadBytes": true, "IoWrittenBytes": true,
		"IoReadOps": true, "IoWriteOps": true,
		"HostCpuBusyUsec": true, "HostCpuStolenUsec": true,
		"UnattributedCpuUsec": true,
		factExplainedBy:       true, factUnexplained: true, factUnobservable: true,
	}
	for fact := range psiFacts {
		emitted[fact] = true
	}

	for fact := range emitted {
		declared, ok := collection.Facts[fact]
		if !ok {
			t.Errorf("%s is emitted and not declared", fact)
			continue
		}
		if declared.Sentence == "" {
			t.Errorf("%s has no sentence, and a sentence is what a consumer renders", fact)
		}
		if declared.Discloses != "nothing" {
			t.Errorf("%s discloses %q: every value here is a counter, a share or "+
				"systemd's own name for a cgroup", fact, declared.Discloses)
		}
	}
	for fact := range collection.Facts {
		if !emitted[fact] {
			t.Errorf("%s is declared and this collector cannot emit it", fact)
		}
	}
}

// Temperament decides whether a fact churns the snapshot diff (DESIGN 12), and
// this collection exists because it was churning one: a decaying kernel
// average diffed every fifteen minutes reports every cgroup-bearing unit as
// changed. So every measurement here is a counter or a gauge, and only the
// three structural facts are configuration.
func TestOnlyTheStructuralFactsAreConfiguration(t *testing.T) {
	collection := decodeDeclaration(t)
	structural := map[string]bool{"Parent": true, "Depth": true, "Delegated": true}
	for fact, declared := range collection.Facts {
		if structural[fact] {
			if declared.Temperament != "configuration" {
				t.Errorf("%s is %q, pinned configuration", fact, declared.Temperament)
			}
			continue
		}
		if declared.Temperament == "configuration" || declared.Temperament == "existence" {
			t.Errorf("%s is declared %q: a measurement declared configuration "+
				"reports this host as changed on every single collect, for ever",
				fact, declared.Temperament)
		}
	}
}

// The remainder is arithmetic across two files read moments apart, and it is
// the figure most likely to be quoted as though the kernel had stated it — so
// it declares the facts it was derived FROM, and the attribution states do
// too. Everything else here is read off cgroupfs.
func TestTheDerivedFiguresSayWhatTheyWereDerivedFrom(t *testing.T) {
	var declaration struct {
		Collections []struct {
			Facts map[string]struct {
				Kind        string   `json:"kind"`
				DerivedFrom []string `json:"derived_from"`
			} `json:"facts"`
		} `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	derived := map[string]bool{
		"Depth": true, "Delegated": true,
		"UnattributedCpuUsec": true,
		factExplainedBy:       true, factUnexplained: true, factUnobservable: true,
	}
	for fact := range derived {
		spec := declaration.Collections[0].Facts[fact]
		if spec.Kind != "derived" || len(spec.DerivedFrom) == 0 {
			t.Errorf("%s is %q from %v — a figure assembled here must name its inputs",
				fact, spec.Kind, spec.DerivedFrom)
		}
	}
}

// The row is what an operator ranks by, and this collection's whole purpose is
// that ranking, so `answer` is pinned against the reference's own ROW_FACTS.
func TestTheRowCarriesTheFactsAnOperatorRanksBy(t *testing.T) {
	collection := decodeDeclaration(t)
	want := []string{
		"Parent", "Depth", "Delegated",
		"CpuUsageUsec", "CpuThrottledUsec",
		"MemoryCurrentBytes", "MemoryPeakBytes", "MemoryOomKills",
		"IoReadBytes", "IoWrittenBytes",
		"PsiIoFullAvg60", "PsiCpuSomeAvg60", "PsiMemoryFullAvg60",
		"HostCpuBusyUsec", "UnattributedCpuUsec",
		factExplainedBy, factUnexplained, factUnobservable,
	}
	if len(collection.Answer) != len(want) {
		t.Fatalf("answer is %v", collection.Answer)
	}
	for i, fact := range want {
		if collection.Answer[i] != fact {
			t.Fatalf("answer[%d] is %q, want %q", i, collection.Answer[i], fact)
		}
		if _, ok := collection.Facts[fact]; !ok {
			t.Fatalf("answer names %q, which is not a declared fact", fact)
		}
	}
}

// A reference command is what lets a reader check the reading by hand, so
// every file this collector opens by name must be reachable from one — and
// /proc/stat in particular, because a subtraction is only checkable if both
// sides are.
func TestEveryFileTheDerivationOpensIsNamedByAReferenceCommand(t *testing.T) {
	collection := decodeDeclaration(t)
	joined := ""
	for _, command := range collection.Commands {
		if command.Purpose == "" {
			t.Errorf("reference command %v states no purpose", command.Argv)
		}
		joined += " " + strings.Join(command.Argv, " ")
	}
	for _, file := range []string{
		"cpu.stat", "memory.current", "memory.events", "io.stat",
		"io.pressure", procStat,
	} {
		if !strings.Contains(joined, file) {
			t.Errorf("no reference command names %s, which the derivation reads", file)
		}
	}
	if len(collection.Redactions) != 0 || collection.Exemption == "" {
		t.Fatal("an exemption beside a redaction list is two rulings contradicting each other in one document")
	}
}

// The authority is the paths this binary actually opens, and nothing wider: a
// declaration asking for more than it reads is a sandbox granted on a promise
// nobody checked.
func TestTheAuthorityNamesTheTreeAndTheDenominatorAndNoCommands(t *testing.T) {
	var declaration struct {
		Authority struct {
			ReadPaths []string `json:"read_paths"`
			Commands  []string `json:"commands"`
		} `json:"authority"`
		Probe string `json:"probe"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if len(declaration.Authority.Commands) != 0 {
		t.Errorf("this collector runs nothing: it opens files. Commands: %v", declaration.Authority.Commands)
	}
	wanted := map[string]bool{cgroupRoot: false, procStat: false}
	for _, path := range declaration.Authority.ReadPaths {
		if _, ok := wanted[path]; ok {
			wanted[path] = true
		}
	}
	for path, found := range wanted {
		if !found {
			t.Errorf("the authority does not ask for %s, which the derivation reads", path)
		}
	}
	if !strings.Contains(declaration.Probe, "cgroup.controllers") {
		t.Error("the probe prose must name the file the capability question is asked of")
	}
}
