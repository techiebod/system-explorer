// The two verbs, replayed against the committed corpus captures — the
// exposure variant, whose staged interface set covers the nft collections,
// the socket join and the plumbing; and the tailnet variant for the
// snapshot. Names in this collector carry SPACES ("inet selab",
// "tcp 0.0.0.0:22"), so these tests are also where the request line's
// declared whitespace encoding (%20, %25 — DESIGN 18) is proven to bite.
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

func corpusNetwork(t *testing.T, variant string) map[string]string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "corpus", "network", variant, "payloads")
	if _, err := os.Stat(source); err != nil {
		t.Skipf("the network %s payloads are not here: %v", variant, err)
	}
	return map[string]string{"SE_REPLAY_DIR": source,
		"SE_REPLAY_NOW": "2026-08-23T12:00:00Z"}
}

func runVerb(t *testing.T, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", corpusNetwork(t, "exposure"))
}

func TestObjectAddressesASpacedNameThroughTheEncoding(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object nft-tables inet%20selab")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	object := objects[0]
	if object["name"] != "inet selab" || object["collection"] != "nft-tables" {
		t.Fatalf("%+v", object)
	}
	if commits := ofKind(records, "commit"); len(commits) != 0 {
		t.Fatal("a commit is a collection-stream statement, not a verb's")
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "object" {
		t.Fatalf("%+v", terminator)
	}
	// The undecoded spelling is a name nothing published.
	code, stdout, _ = runVerb(t, "object nft-tables inet")
	if code != exitOK {
		t.Fatalf("%d", code)
	}
	if decline := ofKind(parseRecords(t, stdout), "decline")[0]; decline["reason"] != "unavailable" {
		t.Fatalf("%+v", decline)
	}
}

func TestObjectReservesAnExposureRowAndItsRecords(t *testing.T) {
	code, stdout, stderr := runVerb(t, "object port-exposure tcp%200.0.0.0:22")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 || objects[0]["name"] != "tcp 0.0.0.0:22" {
		t.Fatalf("%v", objects)
	}
}

func TestNftEvidenceIsTheRulesetWholeAndTheDigestChecks(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence nft-tables inet%20selab")
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
	if document["nftables"] == nil {
		t.Fatalf("the ruleset whole: %v", document)
	}
}

func TestExposureEvidenceCarriesBothHalves(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence port-exposure tcp%200.0.0.0:22")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	sockets, ok := document["sockets"].(map[string]any)
	if !ok || sockets["/proc/net/tcp"] == nil {
		t.Fatalf("sockets half: %v", document["sockets"])
	}
	if document["ruleset"] == nil {
		t.Fatalf("ruleset half: %v", document)
	}
}

func TestListeningEvidenceShowsAnUnreadableTableAsItsReason(t *testing.T) {
	code, stdout, stderr := runVerb(t, "evidence listening tcp%200.0.0.0:22")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]string
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	if len(document) != 4 {
		t.Fatalf("the four tables: %v", document)
	}
	if !strings.Contains(document["/proc/net/tcp"], "local_address") {
		t.Fatalf("%q", document["/proc/net/tcp"])
	}
}

func TestTailscaleEvidenceIsTheSnapshotVerbatim(t *testing.T) {
	code, stdout, stderr := runWith(t, "evidence tailscale lab-node\n",
		corpusNetwork(t, "tailnet"))
	if code != exitOK {
		// The tailnet variant's node name is transcribed from its capture;
		// if it moved, read the decline rather than guessing.
		t.Fatalf("exit %d: %s\n%s", code, stderr, stdout)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var document map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &document); err != nil {
		t.Fatal(err)
	}
	if document["Self"] == nil || document["Peer"] == nil {
		t.Fatalf("the raw snapshot: %v", document)
	}
}

func TestAVerbDeclineIsDataNotACrash(t *testing.T) {
	// A collection this collector never served: the walk's own unsupported
	// decline is the verb's answer.
	code, stdout, _ := runVerb(t, "object watchlists tank")
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
	code, stdout, _ = runVerb(t, "evidence nft-chains nothere")
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

func TestTheVerbRequestShapeIsExactlyThreeTokens(t *testing.T) {
	// A spaced name that did NOT travel encoded arrives as extra tokens and
	// is refused whole — which is the rule the encoding exists to satisfy.
	for _, request := range []string{"object nft-tables", "object nft-tables inet selab", "evidence listening"} {
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
