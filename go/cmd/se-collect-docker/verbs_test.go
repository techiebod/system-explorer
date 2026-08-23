// The two verbs, replayed against the committed corpus capture
// (corpus/docker/healthy) — plus a marked-synthetic inspect document for the
// evidence arm, because the capture predates the per-object paths and its
// containers are gone. The env redaction is asserted on that document, so
// the mechanism and the withholding are proven together.
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

func corpusPayloads(t *testing.T) string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "docker", "healthy", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the docker healthy payloads are not here: %v", err)
	}
	return source
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n",
		map[string]string{"SE_REPLAY_DIR": corpusPayloads(t)})
}

func TestObjectServesTheRowTheCollectionPublishes(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object containers lab-oneshot")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != "container" || object["name"] != "lab-oneshot" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["State"] == nil || facts["Image"] == nil {
		t.Fatalf("%+v", facts)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

// The synthetic inspect: shaped like the Engine API's answer, carrying the
// three assignment lists the redaction watches plus one nested inside a
// list, which is exactly the walk the reference's docstring once promised
// and did not do.
const syntheticInspect = `{"Id":"c0ffee","Name":"/lab-oneshot",` +
	`"Config":{"Env":["DB_URL=postgres://u:hunter2@db/x","TERM=xterm","BARE"],` +
	`"Cmd":["serve","--listen=0.0.0.0:80"],"Entrypoint":null},` +
	`"Mounts":[{"Env":["NESTED_KEY=nested-secret"]}],` +
	`"State":{"Status":"exited"}}`

func stageWithInspect(t *testing.T) map[string]string {
	t.Helper()
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
	stem := payloadStem(inspectPath("containers", "lab-oneshot"))
	if err := os.WriteFile(filepath.Join(dir, stem+".json"), []byte(syntheticInspect), 0o644); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"SE_REPLAY_DIR": dir}
}

func TestEvidenceServesTheInspectWithAssignmentValuesWithheld(t *testing.T) {
	code, stdout, stderr := runWith(t, "evidence containers lab-oneshot\n", stageWithInspect(t))
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
	for _, credential := range []string{"hunter2", "nested-secret", "--listen=0.0.0.0:80"} {
		if strings.Contains(payload, credential) {
			t.Fatalf("%s survived: %s", credential, payload)
		}
	}
	// The names stay: "is DB_URL even set?" is a real question.
	for _, kept := range []string{`"DB_URL=«redacted»"`, `"NESTED_KEY=«redacted»"`,
		`"--listen=«redacted»"`, `"BARE"`, `"TERM=«redacted»"`} {
		if !strings.Contains(payload, kept) {
			t.Fatalf("%s missing: %s", kept, payload)
		}
	}
	// Entrypoint is null, not a list: untouched.
	if !strings.Contains(payload, `"Entrypoint":null`) {
		t.Fatalf("a null Entrypoint rides as the daemon wrote it: %s", payload)
	}
}

func TestAnUnstagedInspectRefusesTheRun(t *testing.T) {
	// The committed capture stages the listings and no per-object inspect:
	// a broken capture for this request, never a statement about a machine.
	code, _, _ := runVerb(t, "evidence containers lab-oneshot")
	if code != exitRuntime {
		t.Fatalf("an unstaged inspect must refuse the run: %d", code)
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
	// A name the listing does not publish declines BEFORE any per-object
	// path is built — the listing is the authority, and a token is data.
	code, stdout, _ = runVerb(t, "evidence containers ../../../etc/passwd")
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
	for _, request := range []string{"object containers", "object containers a b", "evidence volumes"} {
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
