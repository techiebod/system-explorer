// The two verbs, driven over the same staged fleet the replay tests use —
// radarr and prowlarr, a queue record, a two-event history page — plus the
// committed corpus capture where it reaches further. The URL redaction is
// ALSO driven directly, because the staged history carries no credentialled
// URL and a test that only replayed it would pass with the redaction
// deleted — the guard-that-checks-a-subset defect.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", stagedAll(t))
}

func TestObjectServesTheRowTheCollectionPublishes(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object apps radarr")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != "servarr-app" || object["name"] != "radarr" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["App"] != "radarr" || facts["AppName"] != "Radarr" {
		t.Fatalf("%+v", facts)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestObjectAnswersTheFanoutCollections(t *testing.T) {
	for request, kind := range map[string]string{
		"object queue radarr/91":     "servarr-queue-item",
		"object history radarr/4711": "servarr-history-event",
	} {
		code, stdout, stderr := runVerb(t, request)
		if code != exitOK {
			t.Fatalf("%q: exit %d: %s", request, code, stderr)
		}
		objects := ofKind(parseRecords(t, stdout), "object")
		if len(objects) != 1 || objects[0]["type"] != kind {
			t.Fatalf("%q: %v", request, objects)
		}
	}
}

func TestAppsEvidenceServesBothDocumentsAndTheDigestChecks(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence apps radarr")
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
	status, ok := document["system_status"].(map[string]any)
	if !ok || status["appName"] != "Radarr" {
		t.Fatalf("system_status half missing: %v", document["system_status"])
	}
	if _, ok := document["health"].([]any); !ok {
		t.Fatalf("health half missing: %v", document["health"])
	}
}

func TestHealthEvidenceServesTheMatchingEntry(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence health radarr/DownloadClientCheck")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	if document["source"] != "DownloadClientCheck" {
		t.Fatalf("%v", document)
	}
}

func TestQueueEvidenceServesTheRawRecord(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence queue radarr/91")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	// The raw record — members the row never lifts (downloadId, the
	// statusMessages tree) ride verbatim.
	if document["id"] != float64(91) || document["downloadId"] == nil ||
		document["statusMessages"] == nil {
		t.Fatalf("%v", document)
	}
}

func TestHistoryEvidenceServesThePageAndMintsMembershipTheSameWay(t *testing.T) {
	// index-1: the second record states no id, so its name IS its position —
	// and its evidence is the page that contains it.
	code, stdout, stderr := runVerb(t, "evidence history radarr/index-1")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	records, ok := document["records"].([]any)
	if !ok || len(records) != 2 {
		t.Fatalf("the page whole: %v", document)
	}
}

// The reference's _redact_history_urls and _keep_scheme_host, driven
// directly: the credential half of every embedded URL withheld, the
// diagnostic half kept.
func TestHistoryRedactionWithholdsTheCredentialHalf(t *testing.T) {
	page, err := decodeDocument([]byte(`{"records": [
	  {"id": 1, "eventType": "grabbed", "data": {
	    "downloadUrl": "https://Indexer.example:8443/api?apikey=hunter2&t=get",
	    "note": "grabbed via https://tracker.example/passkey/deadbeef/announce ok",
	    "bare": "https://indexer.example",
	    "plain": "no url here"}}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	redactHistoryPage(page)
	served := string(page.encode())
	for _, credential := range []string{"hunter2", "deadbeef"} {
		if strings.Contains(served, credential) {
			t.Fatalf("%s survived: %s", credential, served)
		}
	}
	if !strings.Contains(served, `https://indexer.example:8443/«redacted»`) {
		t.Fatalf("the scheme and host must survive, lowercased as the reference spells them: %s", served)
	}
	// A URL inside prose is matched on shape, and the prose around it rides.
	if !strings.Contains(served, `grabbed via https://tracker.example/«redacted» ok`) {
		t.Fatalf("embedded URL handling: %s", served)
	}
	// A bare scheme+host has nothing to withhold and rides unchanged.
	if !strings.Contains(served, `"bare":"https://indexer.example"`) {
		t.Fatalf("bare host must ride unchanged: %s", served)
	}
	if !strings.Contains(served, `"plain":"no url here"`) {
		t.Fatalf("a plain value must ride unchanged: %s", served)
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
		"evidence queue radarr/9999",   // an id no page carries
		"evidence apps lidarr",         // an instance nobody configured
		"evidence history radarr/4712", // an id the page does not contain
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

// prowlarr's history is indexer grabs, not media events: the row walk
// publishes nothing for it, and its evidence invents nothing either.
func TestProwlarrHistoryStaysUnserved(t *testing.T) {
	code, stdout, _ := runVerb(t, "evidence history prowlarr/1")
	if code != exitOK {
		t.Fatalf("%d", code)
	}
	records := parseRecords(t, stdout)
	if decline := ofKind(records, "decline")[0]; decline["reason"] != "unavailable" {
		t.Fatalf("%+v", decline)
	}
}

func TestTheVerbRequestShapeIsExactlyThreeTokens(t *testing.T) {
	for _, request := range []string{"object apps", "object apps a b", "evidence queue"} {
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
