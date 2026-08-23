// The two verbs, replayed against the committed corpus capture that has a
// full document set in it (corpus/kea/leases): the row behind an object
// answer, the raw documents behind evidence, the checkable digest, and the
// declines — because a decline is data under every verb.
//
// Replayed rather than staged by hand, deliberately: an evidence document is
// what the daemon said, so a fixture written here would be a fixture of what
// this file's author believed a Kea answer looks like.
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

func corpusLeases(t *testing.T) map[string]string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "kea", "leases", "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the kea leases payloads are not here: %v", err)
	}
	return map[string]string{"SE_REPLAY_DIR": source}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusLeases(t))
}

func TestObjectServesTheRowTheCollectionPublishes(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object subnets 192.0.2.0/24")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["type"] != "dhcp-subnet" || object["name"] != "192.0.2.0/24" ||
		object["collection"] != "subnets" {
		t.Fatalf("%+v", object)
	}
	// The row's own facts, unchanged: kea has no density behind its rows, so
	// an object response here disagreeing with the listing would be two
	// answers about one subnet.
	facts := object["facts"].(map[string]any)
	if facts["SubnetId"] != float64(1) || facts["Subnet"] != "192.0.2.0/24" {
		t.Fatalf("%+v", facts)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" ||
		terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestObjectAnswersEveryCollection(t *testing.T) {
	for request, kind := range map[string]string{
		"object daemon kea-dhcp4":        "kea-daemon",
		"object reservations 192.0.2.38": "dhcp-reservation",
		"object leases 192.0.2.84":       "dhcp-lease",
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

func TestEvidenceServesTheDocumentsAndTheDigestChecks(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence subnets 192.0.2.0/24")
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
	// Both halves the row is joined from, in the reference's shape: the
	// counters and the config document that gives the row its CIDR.
	var document map[string]any
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatal(err)
	}
	statistics, ok := document["statistics"].(map[string]any)
	if !ok || statistics["subnet[1].total-addresses"] == nil {
		t.Fatalf("statistics half missing: %v", document["statistics"])
	}
	config, ok := document["config"].(map[string]any)
	if !ok || config["Dhcp4"] == nil {
		t.Fatalf("config half missing: %v", document["config"])
	}
}

func TestLeaseEvidenceIsTheLeaseAnswerWhole(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence leases 192.0.2.84")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	answer, ok := document["leases"].(map[string]any)
	if !ok || answer["result"] != float64(0) {
		t.Fatalf("the whole lease4-get-all answer, result included: %v", document)
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
	// A name no collection publishes is a statement about the machine.
	code, stdout, _ = runVerb(t, "evidence subnets 198.51.100.0/24")
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
}

// The lease-hook gate reaches the verbs exactly as it reaches collect: a Kea
// with no hook loaded has no lease table, and that is a decline carrying the
// actionable constant, not a crash and not an empty answer.
func TestTheLeaseHookGateReachesTheVerbs(t *testing.T) {
	code, stdout, stderr := runWith(t, "evidence leases 192.0.2.84\n",
		map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	decline := ofKind(records, "decline")[0]
	if decline["reason"] != "unsupported" || decline["detail"] != declineLeaseCommands.detail {
		t.Fatalf("%+v", decline)
	}
}

func TestTheVerbRequestShapeIsExactlyThreeTokens(t *testing.T) {
	for _, request := range []string{"object subnets", "object subnets a b", "evidence leases"} {
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
