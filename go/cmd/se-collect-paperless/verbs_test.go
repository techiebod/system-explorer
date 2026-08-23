// The two verbs, replayed against the committed corpus capture
// (corpus/paperless/healthy): the one row behind an object answer, the two
// API documents behind evidence, the checkable digest, the credential-URL
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
	source := filepath.Join("..", "..", "..", "corpus", "paperless", "healthy", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the paperless healthy payloads are not here: %v", err)
	}
	return map[string]string{"SE_REPLAY_DIR": source}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusHealthy(t))
}

func TestObjectServesTheRowTheCollectionPublishes(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object instance paperless")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != "paperless-instance" || object["name"] != "paperless" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["DocumentCount"] == nil || facts["PngxVersion"] == nil {
		t.Fatalf("%+v", facts)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestEvidenceServesBothDocumentsAndTheDigestChecks(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence instance paperless")
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
	statistics, ok := document["statistics"].(map[string]any)
	if !ok || statistics["documents_total"] == nil {
		t.Fatalf("statistics half missing: %v", document["statistics"])
	}
	status, ok := document["status"].(map[string]any)
	if !ok || status["pngx_version"] == nil {
		t.Fatalf("status half missing: %v", document["status"])
	}
	if _, present := document["status_error"]; present {
		t.Fatal("a healthy capture read its status; status_error must be absent")
	}
}

// The reference's _redact_url_credentials, ported: userinfo and query
// stripped from the two declared connection-URL paths, everything else kept
// byte-identical. Driven directly because the healthy capture's URLs carry
// no credentials — a test that only replayed it would pass with the
// redaction deleted, which is the guard-that-checks-a-subset defect.
func TestEvidenceStripsCredentialURLs(t *testing.T) {
	document, err := decodeDocument(strings.NewReader(`{
	  "database": {"url": "postgresql://paperless:hunter2@db.internal:5432/paperless?sslmode=require"},
	  "tasks": {"redis_url": "redis://cache.internal:6379"},
	  "other": {"url": "postgresql://user:pw@kept.example/x"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	redacted := redactCredentialURLs(document)
	database := redacted.get("database").get("url").text
	if strings.Contains(database, "hunter2") || !strings.Contains(database, "«redacted»@db.internal:5432") {
		t.Fatalf("userinfo survived: %q", database)
	}
	if strings.Contains(database, "sslmode") || !strings.Contains(database, "query-stripped") {
		t.Fatalf("query survived: %q", database)
	}
	// A URL with nothing to strip keeps its exact bytes.
	if redis := redacted.get("tasks").get("redis_url").text; redis != "redis://cache.internal:6379" {
		t.Fatalf("an unchanged URL must keep its original spelling: %q", redis)
	}
	// Only the two DECLARED positions are transformed: the rule is the
	// declaration's redactions list, not a sweep over anything URL-shaped.
	if other := redacted.get("other").get("url").text; !strings.Contains(other, "user:pw@") {
		t.Fatalf("an undeclared path must not be rewritten: %q", other)
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
	code, stdout, _ = runVerb(t, "evidence instance ngx")
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
	for _, request := range []string{"object instance", "object instance a b", "evidence instance"} {
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
