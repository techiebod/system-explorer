// The two verbs, replayed against the committed corpus capture
// (corpus/traefik/healthy): the row behind an object answer, the API's own
// documents behind evidence, the checkable digest, the service-URL
// redaction, and the declines — because a decline is data under every verb.
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
	source := filepath.Join("..", "..", "..", "corpus", "traefik", "healthy", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the traefik healthy payloads are not here: %v", err)
	}
	return map[string]string{"SE_REPLAY_DIR": source}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusHealthy(t))
}

func TestObjectServesTheRowTheCollectionPublishes(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object routers api@internal")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != "traefik-router" || object["name"] != "api@internal" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["Status"] != "enabled" || facts["Provider"] != "internal" {
		t.Fatalf("%+v", facts)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestOverviewEvidenceServesItsThreeDocuments(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence overview traefik")
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
	overview, ok := document["overview"].(map[string]any)
	if !ok || overview["http"] == nil {
		t.Fatalf("overview document missing: %v", document["overview"])
	}
	if document["version"] == nil || document["entrypoints"] == nil {
		t.Fatalf("three documents: %v", document)
	}
}

func TestRouterEvidenceIsTheListEntryVerbatim(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence routers api@internal")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	// The raw entry as the API listed it — members the row never lifts
	// (ruleSyntax, using) included, and the priority literal preserved.
	if document["name"] != "api@internal" || document["ruleSyntax"] != "v3" {
		t.Fatalf("%v", document)
	}
	if !strings.Contains(lines[1], "9223372036854775806") {
		t.Fatal("the document's own number literal must survive")
	}
}

// The reference's _redact_service_evidence, driven directly because the
// healthy capture's services carry no backend URLs — a test that only
// replayed it would pass with the redaction deleted, which is the
// guard-that-checks-a-subset defect.
func TestServiceEvidenceStripsBackendUserinfo(t *testing.T) {
	document, err := decodeDocument([]byte(`{
	  "name": "files@file",
	  "loadBalancer": {"servers": [
	    {"url": "http://user:hunter2@backend.internal:8080/health"},
	    {"address": "plain.internal:9000"}
	  ]},
	  "serverStatus": {"http://user:hunter2@backend.internal:8080/health": "UP"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	redactServiceEvidence(document)
	served := string(document.encode())
	if strings.Contains(served, "hunter2") {
		t.Fatalf("userinfo survived: %s", served)
	}
	if !strings.Contains(served, "«redacted»@backend.internal:8080") {
		t.Fatalf("the marker must keep the withholding visible: %s", served)
	}
	if !strings.Contains(served, "plain.internal:9000") {
		t.Fatalf("a URL with no userinfo keeps its exact bytes: %s", served)
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
	code, stdout, _ = runVerb(t, "evidence services nothere@docker")
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
	for _, request := range []string{"object routers", "object routers a b", "evidence services"} {
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
