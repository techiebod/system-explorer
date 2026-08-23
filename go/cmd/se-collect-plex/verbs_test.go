// The two verbs, replayed against the committed corpus captures — the
// healthy variant for the Plex side, the queue variant for the seerr side:
// the row behind an object answer, the fetched-once documents behind
// evidence, the checkable digest, and the declines.
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

func corpusVariant(t *testing.T, variant string) map[string]string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "plex", variant, "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the plex %s payloads are not here: %v", variant, err)
	}
	return map[string]string{"SE_REPLAY_DIR": source}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusVariant(t, "healthy"))
}

func TestObjectServesTheRowTheCollectionPublishes(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object libraries 1")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != collectionTypes["libraries"] || object["name"] != "1" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["Title"] != "Movies" {
		t.Fatalf("%+v", facts)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestServerEvidenceIsTheRootDocument(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence server plex")
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
	if document["MediaContainer"] == nil {
		t.Fatalf("%v", document)
	}
}

func TestLibraryEvidenceIsTheListingWholeAndMembershipIsInIt(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence libraries 3")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	directory := document["MediaContainer"].(map[string]any)["Directory"].([]any)
	if len(directory) < 2 {
		t.Fatalf("the listing whole, not one entry: %v", document)
	}
}

func TestRequestEvidenceIsThePageWalk(t *testing.T) {
	code, stdout, stderr := runWith(t, "evidence requests 43\n", corpusVariant(t, "queue"))
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	// One page: served as itself, seerr's own envelope included.
	results, ok := document["results"].([]any)
	if !ok || len(results) != 3 || document["pageInfo"] == nil {
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
	code, stdout, _ = runVerb(t, "evidence libraries 99")
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
	for _, request := range []string{"object server", "object server a b", "evidence sessions"} {
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
