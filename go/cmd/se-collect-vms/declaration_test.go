package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// The declaration must name every fact this collector can put on the wire and
// nothing it cannot: the fact dictionary, the renderer's semantics and the MCP
// tool descriptions are all generated from it, so a fact emitted and not
// declared arrives at a consumer with no sentence, and a fact declared and
// never emitted is a promise the collector does not keep.
func TestTheDeclarationNamesExactlyTheFactsThisCollectorEmits(t *testing.T) {
	var declaration struct {
		Schema    string `json:"schema"`
		Collector string `json:"collector"`
		Authority struct {
			ReadPaths []string `json:"read_paths"`
			Commands  []string `json:"commands"`
		} `json:"authority"`
		Collections []struct {
			Name   string   `json:"name"`
			Prefix string   `json:"prefix"`
			Answer []string `json:"answer"`
			Facts  map[string]struct {
				Type      string   `json:"type"`
				Kind      string   `json:"kind"`
				Values    []string `json:"values"`
				Sentence  string   `json:"sentence"`
				Discloses string   `json:"discloses"`
			} `json:"facts"`
			Names      map[string]any `json:"names"`
			Relations  []any          `json:"relations"`
			Redactions []any          `json:"redactions"`
			Exemption  string         `json:"redaction_exemption"`
		} `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "vms" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 1 || declaration.Collections[0].Name != "domains" {
		t.Fatalf("one collection, domains; got %v", declaration.Collections)
	}
	collection := declaration.Collections[0]

	// Every key the emitter can put in `facts`, or name on an unobservable
	// record, held beside the declaration so the two cannot drift.
	emitted := []string{
		"State", "IPAddresses", "IPAddressesUnobservable", "MemoryMiB", "VCPUs",
		"Autostart", "Persistent", "HostTaps",
	}
	if len(collection.Facts) != len(emitted) {
		t.Errorf("declared %d facts, this collector emits %d", len(collection.Facts), len(emitted))
	}
	for _, fact := range emitted {
		declared, ok := collection.Facts[fact]
		if !ok {
			t.Errorf("%s reaches the wire and is not declared", fact)
			continue
		}
		if declared.Sentence == "" {
			t.Errorf("%s has no sentence, and a sentence is what a consumer renders", fact)
		}
		if declared.Discloses == "" {
			t.Errorf("%s declares no disclosure class, and there is no safe default", fact)
		}
		if declared.Kind != "observed" {
			t.Errorf("%s is class %q: every fact this row carries is copied from "+
				"the domain walk, and calling one derived would tell a reader "+
				"this collector computed something it read", fact, declared.Kind)
		}
	}
	// State is the one closed vocabulary here, and the members are libvirt's,
	// not this port's: adapters/vms.py STATES maps the eight enum values the C
	// library defines. A port that shipped a shorter list would publish a
	// value outside its own declaration the first time a guest crashed.
	if got := len(collection.Facts["State"].Values); got != 8 {
		t.Errorf("State declares %d values; libvirt defines eight domain states "+
			"and a renderer switching on a shorter set meets one it cannot name", got)
	}
	for _, fact := range collection.Answer {
		if _, ok := collection.Facts[fact]; !ok {
			t.Errorf("the row answers with %s, which is not declared", fact)
		}
	}

	// Two absences that are decisions rather than omissions, each pinned so
	// nobody adds one without meeting the reason it is not there.
	//
	// No `names`: the reference's row publishes no name family, so the
	// collator keys a domain on its NAME alone. The domain UUID is the
	// identifier that would survive a rename, and declaring a family here
	// while the stream carries none would be a join key nobody may join on.
	//
	// No `relations`: the bridge, tap and disk edges belong to the opened
	// object, and this collector does not serve that verb yet.
	if len(collection.Names) != 0 {
		t.Error("a names family is declared and the stream carries none")
	}
	if len(collection.Relations) != 0 {
		t.Error("a relation type is declared and this collection asserts none")
	}
	// And one presence that is the same kind of decision. The contract wants
	// exactly one of `redactions` and `redaction_exemption`, and the exemption
	// is the false half here: a domain definition CAN carry a credential —
	// <graphics passwd=…>, a <secret> under a disk's <auth> — so the reviewed
	// "this source has no credential surface" storage and network carry would
	// be a statement nobody could stand behind.
	//
	// What the list can say is what the scrub manifest already performs on the
	// same paths: the name and the definition are operator-authored content,
	// the domain UUID and the interface MACs are identity, and a guest address
	// is location. What it cannot say is anything about the credential INSIDE
	// the definition, because the definition is one JSON string and no path
	// addresses into it — a residual owed to whoever lands the evidence verb.
	if collection.Exemption != "" {
		t.Error("a domain definition has a credential surface, so the reviewed " +
			"no-credential-surface statement would be false here")
	}
	if len(collection.Redactions) == 0 {
		t.Error("the payload carries operator-authored text and two identifiers, " +
			"none of which is served verbatim to a public corpus")
	}

	if collection.Prefix != "domain" {
		t.Errorf("prefix %q: a target's kind names a declared prefix, and the "+
			"reference publishes these objects as domain:<name>", collection.Prefix)
	}
	// The socket is the whole of what this process opens, and a sandbox that
	// omits it does not fail loudly — it makes every host's domains absent,
	// which is the one decline that retires them.
	granted := map[string]bool{}
	for _, path := range declaration.Authority.ReadPaths {
		granted[path] = true
	}
	if !granted[socketReadOnly] {
		t.Errorf("read_paths omits %s, which this process opens directly", socketReadOnly)
	}
}
