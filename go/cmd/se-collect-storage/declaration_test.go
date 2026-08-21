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

// The declaration must name every fact this collector can put on the wire
// and nothing it cannot: the fact dictionary, the renderer's semantics and
// the MCP tool descriptions are all generated from it, so a fact emitted and
// not declared arrives at a consumer with no sentence, and a fact declared
// and never emitted is a promise the collector does not keep. DESIGN 19's
// storage example is illustrative and declares neither set.
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
				Type        string   `json:"type"`
				Kind        string   `json:"kind"`
				DerivedFrom []string `json:"derived_from"`
				Sentence    string   `json:"sentence"`
				Discloses   string   `json:"discloses"`
			} `json:"facts"`
			Names map[string]struct {
				Class string `json:"class"`
			} `json:"names"`
			Redactions []any  `json:"redactions"`
			Exemption  string `json:"redaction_exemption"`
		} `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "storage" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 3 || declaration.Collections[0].Name != "pools" ||
		declaration.Collections[1].Name != "block-devices" ||
		declaration.Collections[2].Name != "mounts" {
		t.Fatalf("three collections — pools, block-devices, mounts; got %v",
			declaration.Collections)
	}
	collection := declaration.Collections[0]

	// Every key the emitter can put in `facts`, or name on an unobservable
	// record, held beside the declaration so the two cannot drift.
	emitted := []string{
		"State", "StatusMessage", "Errors",
		"ScanFunction", "ScanState", "ScanEndTime", "ScanAgeDays",
		"LastScrubEndTime", "LastScrubEndTimeUnobservable",
		"SizeBytes", "AllocatedBytes", "FreeBytes",
		"CapacityPercent", "FragmentationPercent",
		"Vdevs", "UnhealthyVdevs", "VdevsWithErrors",
		"Redundancy", "DeviceFailuresTolerated",
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
		// Law 4: a derivation with no stated inputs cannot be re-checked.
		if declared.Kind == "derived" && len(declared.DerivedFrom) == 0 {
			t.Errorf("%s is derived and names no inputs", fact)
		}
	}
	// The three facts this reading computes rather than reads. Getting one
	// of them classed `observed` would tell a reader a regex over a vdev
	// name was a figure the pool published.
	for _, fact := range []string{"Redundancy", "DeviceFailuresTolerated", "ScanAgeDays"} {
		if collection.Facts[fact].Kind != "derived" {
			t.Errorf("%s is this reading's own derivation, not something zpool reported", fact)
		}
	}
	for _, fact := range collection.Answer {
		if _, ok := collection.Facts[fact]; !ok {
			t.Errorf("the row answers with %s, which is not declared", fact)
		}
	}

	// The names families the object record actually carries.
	for family, class := range map[string]string{"guid": "stable", "devices": "stable", "kernel": "ephemeral"} {
		if collection.Names[family].Class != class {
			t.Errorf("names.%s is class %q, want %q", family, collection.Names[family].Class, class)
		}
	}

	// An exemption beside a redaction list is two rulings contradicting each
	// other in one document.
	if collection.Exemption == "" || len(collection.Redactions) != 0 {
		t.Error("this collector declares a reviewed exemption and no redactions")
	}

	// The three alias trees are the part most easily forgotten: a sandbox
	// that omits them does not fail loudly, it makes every leaf's Device an
	// unobservable — a reading silently degraded by our own deployment.
	granted := map[string]bool{}
	for _, path := range declaration.Authority.ReadPaths {
		granted[path] = true
	}
	for _, tree := range devlinkTrees {
		if !granted[tree] {
			t.Errorf("read_paths omits %s, which this process opens directly", tree)
		}
	}
	want := []string{"zpool", "lsblk", "findmnt"}
	if len(declaration.Authority.Commands) != len(want) {
		t.Errorf("commands %v, want %v — zpool for pools (and not zfs), the "+
			"two util-linux readers for the R3b collections", declaration.Authority.Commands, want)
	} else {
		for i, command := range want {
			if declaration.Authority.Commands[i] != command {
				t.Errorf("commands[%d] = %q, want %q", i, declaration.Authority.Commands[i], command)
			}
		}
	}
}
