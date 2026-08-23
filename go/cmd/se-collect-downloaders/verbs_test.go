// The two verbs, replayed against the committed corpus capture
// (corpus/downloaders/healthy): the rows behind object answers, the
// daemons' own documents behind evidence, the checkable digest, and the
// declines — because a decline is data under every verb.
//
// The sabnzbd client's evidence document (fullstatus) is the one call the
// capture predates — its daemons are gone and a re-stage moves every anchor
// — so that test stages the capture plus a marked-synthetic fullstatus in a
// temp directory, and asserts mechanism, not machine truth.
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

const corpusTorrent = "d92d27bd899a09537a6ad1b7030a7221ac143175"
const corpusSlot = "5cb01b2b-aab4-d0c2-ada1-f4818b15edcf"

func corpusPayloads(t *testing.T) string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "downloaders", "healthy", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the downloaders healthy payloads are not here: %v", err)
	}
	return source
}

func corpusHealthy(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{"SE_REPLAY_DIR": corpusPayloads(t)}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusHealthy(t))
}

func TestObjectServesTheRowTheCollectionPublishes(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object clients transmission")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != "download-client" || object["name"] != "transmission" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["TorrentCount"] != float64(3) {
		t.Fatalf("%+v", facts)
	}
	code, stdout, stderr = runVerb(t, "object transfers "+corpusTorrent)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	transfer := ofKind(parseRecords(t, stdout), "object")[0]
	if transfer["type"] != "transfer" || transfer["name"] != corpusTorrent {
		t.Fatalf("%+v", transfer)
	}
}

func TestTransmissionClientEvidenceServesBothDocuments(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence clients transmission")
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
	session, ok := document["session"].(map[string]any)
	if !ok || session["version"] == nil {
		t.Fatalf("session half missing: %v", document["session"])
	}
	if document["stats"] == nil {
		t.Fatalf("stats half missing: %v", document)
	}
}

func TestTransferEvidenceServesTheRawEntry(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence transfers "+corpusSlot)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	if document["nzo_id"] != corpusSlot {
		t.Fatalf("%v", document)
	}
}

func TestSabnzbdClientEvidenceIsItsFullStatus(t *testing.T) {
	// The capture, plus a marked-synthetic fullstatus: the mechanism under
	// test is membership, digest and bounds — the document's truth belongs
	// to a future capture whose meta will say so.
	dir := t.TempDir()
	entries, err := os.ReadDir(corpusPayloads(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(corpusPayloads(t), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	synthetic := `{"status":{"version":"5.1.1","uptime":"1d","synthetic_fixture":true}}`
	if err := os.WriteFile(filepath.Join(dir, callFullStatus+".json"), []byte(synthetic), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runWith(t, "evidence clients sabnzbd\n",
		map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	// The value model re-renders spacing; member order and literals ride.
	if lines[1] != synthetic {
		t.Fatalf("fullstatus must ride as the daemon spelled it: %q", lines[1])
	}
	// Against the capture as committed, the same request is a broken
	// replay, never a statement about a machine.
	code, _, _ = runWith(t, "evidence clients sabnzbd\n", corpusHealthy(t))
	if code != exitRuntime {
		t.Fatalf("an unstaged fullstatus must refuse the run: %d", code)
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
		"object clients deluge",
		"evidence transfers 0000000000000000000000000000000000000000",
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
	for _, request := range []string{"object clients", "object clients a b", "evidence transfers"} {
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
