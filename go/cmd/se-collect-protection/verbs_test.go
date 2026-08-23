// The two verbs, replayed against the committed corpus capture
// (corpus/protection/healthy): the row behind an object answer, the status
// document and both receipts behind a job's evidence, the manifest behind a
// target's, the checkable digest, and the declines.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func corpusHealthy(t *testing.T) map[string]string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "protection", "healthy", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the protection healthy payloads are not here: %v", err)
	}
	return map[string]string{"SE_REPLAY_DIR": source}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusHealthy(t))
}

func TestObjectServesTheRowTheCollectionPublishes(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object jobs appliance-config")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != collectionTypes["jobs"] || object["name"] != "appliance-config" {
		t.Fatalf("%+v", object)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestJobEvidenceCarriesTheStatusAndBothReceipts(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence jobs appliance-config")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("header, payload, terminator: %d lines", len(lines))
	}
	var header evidenceDocumentRecord
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatal(err)
	}
	payload := lines[1]
	if header.Bytes != len(payload) || header.Truncated {
		t.Fatalf("%+v vs %d payload bytes", header, len(payload))
	}
	sum := sha256.Sum256([]byte(payload))
	if header.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("the served digest must match the served bytes")
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatal(err)
	}
	status, ok := document[statusPath].(map[string]any)
	if !ok || status["jobs"] == nil {
		t.Fatalf("the status document: %v", document[statusPath])
	}
	receipts, ok := document[receiptsDir].(map[string]any)
	if !ok {
		t.Fatalf("the receipts: %v", document[receiptsDir])
	}
	// The pair IS the distinction between a run that failed and a job that
	// has never run.
	for _, suffix := range []string{"last", "last-success"} {
		if receipts[suffix] == nil {
			t.Fatalf("receipt %s missing: %v", suffix, receipts)
		}
	}
	if _, present := document[receiptsDir+" (unreadable)"]; present {
		t.Fatal("a healthy capture read both receipts; the faults member must be absent")
	}
}

func TestATargetsEvidenceIsTheManifestWhole(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence targets photo-library")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	manifest, ok := document[manifestPath].(map[string]any)
	if !ok || manifest["targets"] == nil || manifest["destinations"] == nil {
		t.Fatalf("%v", document)
	}
}

func TestAVerbDeclineIsDataNotACrash(t *testing.T) {
	code, stdout, _ := runVerb(t, "object pools tank")
	if code != exitOK {
		t.Fatalf("%d", code)
	}
	records := parseRecords(t, stdout)
	if decline := ofKind(records, "decline")[0]; decline["reason"] != "unsupported" {
		t.Fatalf("%+v", decline)
	}
	for _, request := range []string{
		"evidence jobs no-such-job",
		"evidence destinations tape-vault",
	} {
		code, stdout, _ = runVerb(t, request)
		if code != exitOK {
			t.Fatalf("%q: %d", request, code)
		}
		records = parseRecords(t, stdout)
		if decline := ofKind(records, "decline")[0]; decline["reason"] != "unavailable" {
			t.Fatalf("%q: %+v", request, decline)
		}
		if len(ofKind(records, "evidence_document")) != 0 {
			t.Fatalf("%q: a decline serves no document", request)
		}
		if len(ofKind(records, "verb_end")) != 1 {
			t.Fatalf("%q: every verb response ends with its terminator", request)
		}
	}
}

func TestTheVerbRequestShapeIsExactlyThreeTokens(t *testing.T) {
	for _, request := range []string{"object jobs", "object jobs a b", "evidence targets"} {
		code, _, _ := runVerb(t, request)
		if code != exitRequest {
			t.Fatalf("%q must be refused whole: %d", request, code)
		}
	}
}

// The bounds the verbs enforce are the bounds the declaration promises: a
// bound only in the declaration is a promise, one only in verbs.go is
// undeclared authority.
func TestTheVerbBoundsAreTheDeclaredOnes(t *testing.T) {
	var declaration struct {
		Collections []struct {
			Name  string `json:"name"`
			Verbs map[string]struct {
				Bytes int `json:"bytes"`
				Ms    int `json:"ms"`
			} `json:"verbs"`
		} `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if len(declaration.Collections) == 0 {
		t.Fatal("no collections")
	}
	for _, collection := range declaration.Collections {
		if len(collection.Verbs) != 2 {
			t.Errorf("%s declares %d verbs; this collector serves object and "+
				"evidence on every collection it publishes",
				collection.Name, len(collection.Verbs))
			continue
		}
		if collection.Verbs["object"].Bytes != objectVerbBytes {
			t.Errorf("%s declares %d object bytes, the verb enforces %d",
				collection.Name, collection.Verbs["object"].Bytes, objectVerbBytes)
		}
		if collection.Verbs["evidence"].Bytes != evidenceVerbBytes {
			t.Errorf("%s declares %d evidence bytes, the verb enforces %d",
				collection.Name, collection.Verbs["evidence"].Bytes, evidenceVerbBytes)
		}
		for verb, bounds := range collection.Verbs {
			if bounds.Ms <= 0 {
				t.Errorf("%s/%s declares no time bound, and an unbounded verb "+
					"is a hung collator", collection.Name, verb)
			}
		}
	}
}
