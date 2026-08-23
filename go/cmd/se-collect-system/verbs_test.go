// The two verbs, replayed against the committed corpus captures — the
// time-synced variant, whose staged interface set covers all four
// collections: the collection's own records re-served byte-for-byte behind
// an object answer, the native documents behind evidence, the Environment
// redaction, the checkable digest, and the declines.
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

// The captured machine's identifiers, transcribed from the variant. The
// four singletons use three naming schemes: identity and time answer to the
// hostname, overview to the literal "host", and boot to its boot id.
const capturedHost = "host-9330c2"
const capturedBootID = "5cb0781a58ccba61e64e3c90732537cb"

func singletonName(collection string) string {
	switch collection {
	case "overview":
		return "host"
	case "boot":
		return capturedBootID
	}
	return capturedHost
}

func corpusSynced(t *testing.T) map[string]string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "system", "time-synced", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the system time-synced payloads are not here: %v", err)
	}
	return map[string]string{"SE_REPLAY_DIR": source,
		"SE_REPLAY_NOW": "2026-08-19T10:00:00Z"}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusSynced(t))
}

func TestObjectReservesTheCollectionsOwnRecords(t *testing.T) {
	for _, collection := range []string{"identity", "time", "overview", "boot"} {
		code, stdout, stderr := runVerb(t, "object "+collection+" "+singletonName(collection))
		if code != exitOK {
			t.Fatalf("%s: exit %d: %s", collection, code, stderr)
		}
		records := parseRecords(t, stdout)
		objects := ofKind(records, "object")
		if len(objects) != 1 {
			t.Fatalf("%s: one object, got %d", collection, len(objects))
		}
		if objects[0]["name"] != singletonName(collection) || objects[0]["collection"] != collection {
			t.Fatalf("%s: %+v", collection, objects[0])
		}
		if commits := ofKind(records, "commit"); len(commits) != 0 {
			t.Fatalf("%s: a commit is a collection-stream statement, not a verb's", collection)
		}
		if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" {
			t.Fatalf("%s: %+v", collection, terminator)
		}
	}
}

func TestTimeEvidenceCarriesBothBusAnswers(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence time "+capturedHost)
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
	if document["org.freedesktop.timedate1"] == nil ||
		document["org.freedesktop.timesync1.Manager"] == nil {
		t.Fatalf("both bus answers on a synced host: %v", document)
	}
}

func TestOverviewEvidenceServesTheProcFilesByPath(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence overview host")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]string
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(document["/proc/uptime"], "") || document["/proc/loadavg"] == "" {
		t.Fatalf("%v", document)
	}
	// This capture stages no arcstats: absent files are absent from the
	// payload too, never empty members.
	if _, present := document["/proc/spl/kstat/zfs/arcstats"]; present {
		t.Fatal("an absent file must be absent from the payload")
	}
}

func TestIdentityEvidenceIsThePortsOwnDocuments(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence identity "+capturedHost)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]string
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(document["/etc/os-release"], "ID=") ||
		document["hostname"] != capturedHost {
		t.Fatalf("%v", document)
	}
}

func TestBootEvidenceWithholdsTheManagerEnvironmentValues(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence boot "+capturedBootID)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	manager := string(document["org.freedesktop.systemd1.Manager"])
	if manager == "" {
		t.Fatalf("%v", document)
	}
	// The manager-wide Environment block: names kept, values withheld.
	if strings.Contains(manager, "Environment") {
		for _, line := range strings.Split(manager, ",") {
			if strings.Contains(line, "PATH=") && !strings.Contains(line, "«redacted»") {
				t.Fatalf("an Environment value survived: %s", line)
			}
		}
	}
}

// The redaction, driven directly on a crafted GetAll document — the staged
// capture's manager may carry a bare Environment, and a test that only
// replayed it would pass with the redaction deleted.
func TestRedactEnvironmentWithholdsValuesAndKeepsNames(t *testing.T) {
	raw := []byte(`{"type":"a{sv}","data":[{"Environment":{"type":"as","data":["PATH=/usr/bin:/bin","LANG=C.UTF-8","BARE"]},"Version":{"type":"s","data":"257"}}]}`)
	redacted, err := redactEnvironment(raw)
	if err != nil {
		t.Fatal(err)
	}
	served := string(redacted)
	if strings.Contains(served, "/usr/bin") || strings.Contains(served, "C.UTF-8") {
		t.Fatalf("a value survived: %s", served)
	}
	for _, kept := range []string{`PATH=«redacted»`, `LANG=«redacted»`, `"BARE"`, `"Version"`} {
		if !strings.Contains(served, kept) {
			t.Fatalf("%s missing: %s", kept, served)
		}
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
	// A name this host does not answer to.
	code, stdout, _ = runVerb(t, "evidence identity some-other-host")
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
	for _, request := range []string{"object identity", "object identity a b", "evidence boot"} {
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
