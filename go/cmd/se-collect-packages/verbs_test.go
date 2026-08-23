// The two verbs, replayed against the committed corpus capture
// (corpus/packages/healthy, a dpkg host): the row behind an object answer,
// the tool's own fields behind evidence, the checkable digest, and the
// declines — because a decline is data under every verb.
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
	source := filepath.Join("..", "..", "..", "corpus", "packages", "healthy", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the packages healthy payloads are not here: %v", err)
	}
	return map[string]string{"SE_REPLAY_DIR": source}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusHealthy(t))
}

func TestObjectServesTheRowTheInventoryPublishes(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object packages adduser")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != "package" || object["name"] != "adduser" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["Manager"] != "dpkg" || facts["Name"] != "adduser" || facts["Version"] == nil {
		t.Fatalf("%+v", facts)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestEvidenceServesTheToolsOwnFieldsAndTheDigestChecks(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence packages adduser")
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
	// The fields exactly as dpkg-query printed them, and the format string
	// that ordered them — so a reader can re-run the listed command and get
	// these bytes back.
	fields, ok := document["fields"].([]any)
	if !ok || len(fields) != 4 || fields[0] != "adduser" {
		t.Fatalf("%v", document["fields"])
	}
	if document["manager"] != "dpkg" || !strings.Contains(document["format"].(string), "${Package}") {
		t.Fatalf("%v", document)
	}
	// The nix link enumeration is deliberately not served (see verbs.go):
	// this capture format carries no link farm, and a member the live path
	// could serve while replay could not is drift by construction.
	if _, present := document["links"]; present {
		t.Fatal("links is omitted until a capture carries the sw farm")
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
	code, stdout, _ = runVerb(t, "evidence packages not-a-package-here")
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
	for _, request := range []string{"object packages", "object packages a b", "evidence packages"} {
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
