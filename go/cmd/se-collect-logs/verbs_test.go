// The two verbs, replayed against the committed corpus capture
// (corpus/logs/healthy): the opened entry behind an object answer — with the
// member-of edge the collection deliberately never publishes — the record
// verbatim behind evidence, the checkable digest, and the declines.
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

// The first entry that carries a unit in the committed page, transcribed
// from the capture rather than invented.
const corpusCursor = "s=5cb074131dc832dca9342fde944c7ceb;i=5cf;b=5cb03c15a640717079cbb1f88f26353d;m=1824f868;t=6596794cda154;x=38e6295da9210261"

func corpusHealthy(t *testing.T) map[string]string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "logs", "healthy", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the logs healthy payloads are not here: %v", err)
	}
	return map[string]string{"SE_REPLAY_DIR": source}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusHealthy(t))
}

func cursorWithUnit(t *testing.T) (string, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "corpus", "logs",
		"healthy", "payloads", "r---n--100.json"))
	if err != nil {
		t.Skip(err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		unit, _ := entry["_SYSTEMD_UNIT"].(string)
		cursor, _ := entry["__CURSOR"].(string)
		if unit != "" && cursor != "" {
			return cursor, unit
		}
	}
	t.Skip("no entry in the capture carries a unit")
	return "", ""
}

func TestObjectOpensTheEntryAndMintsItsEdge(t *testing.T) {
	cursor, unit := cursorWithUnit(t)
	code, stdout, stderr := runVerb(t, "object journal "+cursor)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != "entry" || object["name"] != cursor {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["SystemdUnit"] != unit || facts["Message"] == nil {
		t.Fatalf("%+v", facts)
	}
	// RepeatCount and RepeatWindow are page-derived; a single-record read
	// has no page, and the opened object honestly lacks them.
	for _, absent := range []string{"RepeatCount", "RepeatWindow"} {
		if _, present := facts[absent]; present {
			t.Errorf("%s is page-derived and must not ride a single-record answer", absent)
		}
	}
	// The member-of edge, minted exactly where the reference mints it: on
	// the opened object, never on the collection.
	edges := ofKind(records, "relation_assertion")
	if len(edges) != 1 {
		t.Fatalf("one edge, got %d", len(edges))
	}
	target := edges[0]["target"].(map[string]any)
	if edges[0]["type"] != "member-of" || target["kind"] != "unit" || target["name"] != unit {
		t.Fatalf("%+v", edges[0])
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestEvidenceServesTheRecordAndTheDigestChecks(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence journal "+corpusCursor)
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
	// The record as journald wrote it: fields the row never lifts ride too.
	var document map[string]any
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatal(err)
	}
	if document["__CURSOR"] != corpusCursor || document["__REALTIME_TIMESTAMP"] == nil {
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
	// A cursor outside the staged page: under replay the page is a WINDOW,
	// so the honest answer is a refused run — never "the machine did not
	// have it", which nobody observed.
	code, _, _ = runVerb(t, "evidence journal s=00;i=1;b=00;m=1;t=1;x=1")
	if code != exitRuntime {
		t.Fatalf("an uncaptured cursor must refuse the run: %d", code)
	}
}

// The unavailable decline needs a source that ANSWERS "not there" — which
// only a live journal can, so it is staged through a stub: found=false is
// the machine's own no, and the verb turns it into data.
func TestACursorTheJournalDoesNotHoldDeclinesUnavailable(t *testing.T) {
	var stdout, stderr strings.Builder
	code := serveObject(&stdout, &stderr, absentEntrySource{}, "journal", "s=gone;i=0")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	records := parseRecords(t, stdout.String())
	if decline := ofKind(records, "decline")[0]; decline["reason"] != "unavailable" {
		t.Fatalf("%+v", decline)
	}
	if len(ofKind(records, "verb_end")) != 1 {
		t.Fatal("every verb response ends with its terminator")
	}
}

type absentEntrySource struct{}

func (absentEntrySource) bootID() (string, error)    { return "stub", nil }
func (absentEntrySource) timens() int64              { return 0 }
func (absentEntrySource) batch() (string, error)     { return "stub", nil }
func (absentEntrySource) declaration() string        { return "sha256:0" }
func (absentEntrySource) journal() ([]*value, error) { return nil, nil }
func (absentEntrySource) entry(string) (*value, bool, error) {
	return nil, false, nil
}
func (absentEntrySource) stamp(int) float64         { return 1.0 }
func (absentEntrySource) costs() (float64, float64) { return 0, 0 }

func TestTheVerbRequestShapeIsExactlyThreeTokens(t *testing.T) {
	for _, request := range []string{"object journal", "object journal a b", "evidence journal"} {
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
