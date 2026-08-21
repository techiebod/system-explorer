// The two verbs, replayed against the committed capture that has real
// devices in it (corpus/hardware/staged-disks): the density the row does not
// carry, the raw documents behind it, the checkable digest, and the declines
// — because a decline is data under every verb.
//
// Replayed rather than staged by hand, deliberately: an evidence document is
// what the machine said, so a fixture written here would be a fixture of what
// this file's author believed sysfs looks like.
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

func stagedDisks(t *testing.T) string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "hardware",
		"staged-disks", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the staged-disks payloads are not here: %v", err)
	}
	return source
}

// ofKind is the record-shaped sibling of replay_test.go's objectsIn: the
// verb responses carry records that collection streams do not.
func ofKind(records []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, record := range records {
		if record["record"] == kind {
			out = append(out, record)
		}
	}
	return out
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n",
		map[string]string{"SE_REPLAY_DIR": stagedDisks(t)})
}

func TestObjectServesTheWholeDeviceDirectory(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object scsi 0:0:0:0")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != "disk" || object["name"] != "0:0:0:0" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	// The row's own facts, unchanged: an object response overlays density on
	// a row, and a row here disagreeing with the listing would be two answers
	// about one device.
	if facts["DeviceType"] != "disk" || facts["State"] != "running" {
		t.Fatalf("%+v", facts)
	}
	// The density: attributes the row does not publish, under sysfs's own
	// names. `queue_depth` is one no fact declares and no page shows, which
	// is exactly the kind of question this verb exists to answer.
	if _, present := facts["sysfs:queue_depth"]; !present {
		t.Fatalf("the device directory did not reach the response: %+v", facts)
	}
	// A declared fact is never respelled beside itself: the row's reading of
	// an attribute is the declared one, and a raw second spelling would be
	// two answers to one question.
	for name := range facts {
		if strings.HasPrefix(name, "sysfs:") {
			if _, clash := facts[strings.TrimPrefix(name, "sysfs:")]; clash {
				t.Errorf("%s duplicates a declared fact", name)
			}
		}
	}
	// The names families and the edges ride the same response, so one request
	// answers "what is this disk and what is it attached to".
	if object["names"] == nil {
		t.Error("the object response carries no name families")
	}
	var edges []string
	for _, assertion := range ofKind(records, "relation_assertion") {
		target := assertion["target"].(map[string]any)
		edges = append(edges, assertion["type"].(string)+"→"+target["name"].(string))
	}
	if len(edges) != 2 || edges[0] != "attached-to→host0" || edges[1] != "backs→sda" {
		t.Fatalf("edges %v", edges)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestEvidenceServesTheDocumentAndTheDigestChecks(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence nvme nvme0")
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
	// The digest is over the bytes AS SERVED — recompute and compare.
	sum := sha256.Sum256([]byte(payload))
	if header.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("the served digest must match the served bytes")
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatal(err)
	}
	// The raw attributes as the kernel wrote them, not the row's reading of
	// them: serial and wwid are strings here, where the row publishes Serial
	// and WWN.
	attributes, ok := document["attributes"].(map[string]any)
	if !ok || attributes["serial"] == nil || attributes["state"] != "live" {
		t.Fatalf("%v", document["attributes"])
	}
	if document["syspath"] == nil {
		t.Error("evidence names no syspath, so nothing says where it was read")
	}
	// udisks2 is an explicit null rather than a missing key: asked, and the
	// daemon is not on this bus. A reader can tell that from never asked.
	value, present := document["udisks2"]
	if !present || value != nil {
		t.Errorf("udisks2 = %v (present %v); absence is a reading and says so",
			value, present)
	}
}

func TestAVerbDeclineIsDataNotACrash(t *testing.T) {
	// A collection this collector never served.
	code, stdout, _ := runVerb(t, "object pools tank")
	if code != exitOK {
		t.Fatalf("%d", code)
	}
	records := parseRecords(t, stdout)
	if decline := ofKind(records, "decline")[0]; decline["reason"] != "unsupported" {
		t.Fatalf("%+v", decline)
	}
	if len(ofKind(records, "verb_end")) != 1 {
		t.Fatal("every verb response ends with its terminator")
	}
	// A name the capture never probed. Under REPLAY that is a broken request
	// — "I could not run" — and never a statement about a machine: the seam
	// refuses rather than reading the tree of whichever host is replaying, so
	// the honest answer is an exit code and not a decline that would read as
	// "this device is not there". Live, the same name declines unavailable,
	// which the probe below is arranged to show without a machine.
	code, _, _ = runVerb(t, "evidence scsi 9:9:9:9")
	if code != exitRuntime {
		t.Fatalf("an unprobed name under replay must refuse the run: %d", code)
	}
}

// The unavailable decline, on a source that ANSWERS the probe rather than
// refusing it: a name no collection publishes is a statement about the
// machine, where unsupported is one about the request. Staged here because
// replay cannot express "I looked and it is not there" — an uncaptured path
// is a refusal by design — so the case would otherwise be reachable only on
// a live host.
func TestANameNothingPublishesDeclinesUnavailable(t *testing.T) {
	source := &fakeTree{
		reads: map[string]string{"/sys/class/dmi/id/sys_vendor": "QEMU"},
		lists: map[string][]string{},
	}
	var stdout, stderr strings.Builder
	if code := serveEvidence(&stdout, &stderr, source, "scsi", "9:9:9:9"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	records := parseRecords(t, stdout.String())
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
	for _, request := range []string{"object scsi", "object scsi a b", "evidence nvme"} {
		code, _, _ := runVerb(t, request)
		if code != exitRequest {
			t.Fatalf("%q must be refused whole: %d", request, code)
		}
	}
}

// The bounds the verbs enforce are the bounds the declaration promises: a
// bound only in the declaration is a promise, one only in verbs.go is
// undeclared authority. verbs.go names this test beside its const block.
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
