// The two verbs, replayed against the committed corpus captures — the
// arrays variant (a degraded md pair over a zfs pool) and the datasets
// variant: the collection's own records re-served byte-for-byte behind an
// object answer, the whole native documents behind evidence, the md scrape
// in the reference's assembled shape, the checkable digest, and the
// declines.
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

func corpusStorage(t *testing.T, variant string) map[string]string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "storage", variant, "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the storage %s payloads are not here: %v", variant, err)
	}
	return replayEnv(source)
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusStorage(t, "arrays"))
}

func TestObjectReservesTheCollectionsOwnRecords(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object arrays md126")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["name"] != "md126" || object["collection"] != "arrays" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["Degraded"] == nil || facts["Level"] == nil {
		t.Fatalf("%+v", facts)
	}
	if commits := ofKind(records, "commit"); len(commits) != 0 {
		t.Fatal("a commit is a collection-stream statement, not a verb's")
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" {
		t.Fatalf("%+v", terminator)
	}
}

func TestDatasetObjectAnswersByItsSlashedName(t *testing.T) {
	code, stdout, stderr := runWith(t, "object datasets host-5797a2/data/tight\n",
		corpusStorage(t, "datasets"))
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	objects := ofKind(parseRecords(t, stdout), "object")
	if len(objects) != 1 || objects[0]["name"] != "host-5797a2/data/tight" {
		t.Fatalf("%v", objects)
	}
}

func TestArrayEvidenceIsTheScrapeInTheReferencesShape(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence arrays md126")
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
	// Every array on the host — the scrape is the whole scrape.
	array, ok := document["md126"].(map[string]any)
	if !ok || document["md127"] == nil {
		t.Fatalf("%v", document)
	}
	if array["degraded"] != float64(1) || array["level"] == nil {
		t.Fatalf("%v", array)
	}
	members, ok := array["members"].(map[string]any)
	if !ok || len(members) == 0 {
		t.Fatalf("the member map: %v", array["members"])
	}
}

func TestPoolEvidenceCarriesStatusAndList(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence pools host-5797a2")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	status, ok := document["status"].(map[string]any)
	if !ok || status["pools"] == nil {
		t.Fatalf("status half missing: %v", document["status"])
	}
	if document["list"] == nil {
		t.Fatalf("list half missing (this capture stages it): %v", document)
	}
}

func TestAVerbDeclineIsDataNotACrash(t *testing.T) {
	code, stdout, _ := runVerb(t, "object watchlists tank")
	if code != exitOK {
		t.Fatalf("%d", code)
	}
	records := parseRecords(t, stdout)
	if decline := ofKind(records, "decline")[0]; decline["reason"] != "unsupported" {
		t.Fatalf("%+v", decline)
	}
	code, stdout, _ = runVerb(t, "evidence arrays md99")
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
	for _, request := range []string{"object arrays", "object arrays a b", "evidence pools"} {
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
