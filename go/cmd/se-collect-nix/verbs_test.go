// The two verbs, replayed against the committed corpus capture
// (corpus/nix/attested): the row behind an object answer, the closure's own
// files behind evidence — pointers, version, kernel, manifest, receipt —
// the checkable digest, and the declines. This package had no test file
// until the verbs landed, so the request harness helpers live here.
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

func runWith(t *testing.T, stdin string, env map[string]string) (int, string, string) {
	t.Helper()
	getenv := func(key string) string { return env[key] }
	var stdout, stderr strings.Builder
	code := run(strings.NewReader(stdin), &stdout, &stderr, getenv)
	return code, stdout.String(), stderr.String()
}

func parseRecords(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stream), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("stream line is not JSON: %v\n%s", err, line)
		}
		records = append(records, record)
	}
	return records
}

func ofKind(records []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, record := range records {
		if record["record"] == kind {
			out = append(out, record)
		}
	}
	return out
}

func corpusAttested(t *testing.T) map[string]string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "nix", "attested", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the nix attested payloads are not here: %v", err)
	}
	return map[string]string{"SE_REPLAY_DIR": source}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusAttested(t))
}

func TestObjectServesTheRowAndItsNameFamily(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object generations 4")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != "generation" || object["name"] != "4" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["NixosVersion"] == nil {
		t.Fatalf("%+v", facts)
	}
	names := object["names"].(map[string]any)
	if names["stable"].(map[string]any)["store-path"] == nil {
		t.Fatalf("the store-path family must ride the object answer: %v", names)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestEvidenceServesTheClosuresOwnFiles(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence generations 4")
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
	if document["link"] != "/nix/var/nix/profiles/system-4-link" {
		t.Fatalf("%v", document["link"])
	}
	if !strings.HasPrefix(document["target"].(string), "/nix/store/") {
		t.Fatalf("%v", document["target"])
	}
	pointers, ok := document["pointers"].(map[string]any)
	if !ok || pointers["current"] == nil || pointers["booted"] == nil || pointers["default"] == nil {
		t.Fatalf("the three pointers whose disagreement is the point: %v", document["pointers"])
	}
	if !strings.Contains(document["kernel"].(string), "linux-") {
		t.Fatalf("%v", document["kernel"])
	}
	if document["nixos-version"] == nil {
		t.Fatalf("%v", document)
	}
	// Generation 4 carries both halves in this capture: the build manifest
	// and the deployment receipt it promised.
	receipt, ok := document["deployment-receipt"].(map[string]any)
	if !ok || receipt["generation"] != float64(4) {
		t.Fatalf("%v", document["deployment-receipt"])
	}
	manifest, ok := document["se-generation.json"].(map[string]any)
	if !ok || manifest["receiptsExpected"] != true {
		t.Fatalf("%v", document["se-generation.json"])
	}
}

func TestAGenerationWithoutAReceiptServesNull(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence generations 3")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	// The member is PRESENT and null: asked, and there is no receipt —
	// distinguishable from never asked.
	value, present := document["deployment-receipt"]
	if !present || value != nil {
		t.Fatalf("deployment-receipt = %v (present %v)", value, present)
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
	code, stdout, _ = runVerb(t, "evidence generations 99")
	if code != exitOK {
		t.Fatalf("%d", code)
	}
	records = parseRecords(t, stdout)
	if decline := ofKind(records, "decline")[0]; decline["reason"] != "unavailable" {
		t.Fatalf("%+v", decline)
	}
	if len(ofKind(records, "evidence_document")) != 0 {
		t.Fatal("a decline serves no document")
	}
	if len(ofKind(records, "verb_end")) != 1 {
		t.Fatal("every verb response ends with its terminator")
	}
}

func TestTheVerbRequestShapeIsExactlyThreeTokens(t *testing.T) {
	for _, request := range []string{"object generations", "object generations a b", "evidence generations"} {
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
