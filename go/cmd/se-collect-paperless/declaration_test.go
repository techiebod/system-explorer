package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestDeclareEmitsTheEmbeddedBytesExactlyAndStably(t *testing.T) {
	code, first, stderr := runWith(t, "declare\n", nil)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if first != string(declarationBytes) {
		t.Fatal("declare must emit the embedded declaration verbatim — any re-serialisation un-anchors the hash begin carries")
	}
	_, second, _ := runWith(t, "declare\n", nil)
	if first != second {
		t.Fatal("declare is static and must be byte-stable across runs")
	}

	sum := sha256.Sum256([]byte(first))
	if want := "sha256:" + hex.EncodeToString(sum[:]); declarationDigest != want {
		t.Fatalf("begin's declaration digest %q does not cover the declare bytes (%q)", declarationDigest, want)
	}
}

type declaredFact struct {
	Type        string `json:"type"`
	Unit        string `json:"unit"`
	Temperament string `json:"temperament"`
	Kind        string `json:"kind"`
	Discloses   string `json:"discloses"`
	From        string `json:"from"`
	Sentence    string `json:"sentence"`
}

type declaredCollection struct {
	Name       string                  `json:"name"`
	Prefix     string                  `json:"prefix"`
	Freshness  string                  `json:"freshness"`
	Answer     []string                `json:"answer"`
	Facts      map[string]declaredFact `json:"facts"`
	Redactions []struct {
		Path      string `json:"path"`
		Discloses string `json:"discloses"`
	} `json:"redactions"`
	Exemption string `json:"redaction_exemption"`
	Commands  []struct {
		Purpose string   `json:"purpose"`
		Argv    []string `json:"argv"`
	} `json:"reference_commands"`
}

func decodeDeclaration(t *testing.T) declaredCollection {
	t.Helper()
	var declaration struct {
		Schema      string               `json:"schema"`
		Collector   string               `json:"collector"`
		Collections []declaredCollection `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "paperless" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 1 {
		t.Fatalf("one collection, instance; got %d", len(declaration.Collections))
	}
	return declaration.Collections[0]
}

// The pinned members, asserted from the wire side: the schema-validation half
// (se.declaration.1.json is closed) runs in the Python harness, which owns the
// contract registry.
func TestTheDeclarationCarriesThePinnedContract(t *testing.T) {
	collection := decodeDeclaration(t)
	if collection.Name != collectionInstance || collection.Freshness != "60s" {
		t.Fatalf("collection %q at freshness %q", collection.Name, collection.Freshness)
	}
	// The prefix and the row's name are what the collator mints the id from,
	// and `instance:paperless` is the id the shipping adapter mints — so a port
	// that moved either would publish a second object for one archive.
	if collection.Prefix != "instance" {
		t.Fatalf("prefix %q: the id is <prefix>:<name>, and the adapter's is instance:%s", collection.Prefix, instanceName)
	}

	// Temperament decides whether a fact churns the snapshot diff (DESIGN 12),
	// which is why it is pinned rather than left to reading. Every count is a
	// `gauge` — documents are deleted as well as added, so none of them is a
	// counter — the release is `configuration`, and every component word and
	// error sentence is `state`, because those are exactly what changes
	// underneath a still archive.
	temperament := map[string]string{
		factDocumentCount:         "gauge",
		factInboxCount:            "gauge",
		factTagCount:              "gauge",
		factCorrespondentCount:    "gauge",
		factDocumentTypeCount:     "gauge",
		factPngxVersion:           "configuration",
		factStorageTotalBytes:     "gauge",
		factStorageAvailableBytes: "gauge",
		factDatabaseStatus:        "state",
		factDatabaseError:         "state",
		factRedisStatus:           "state",
		factRedisError:            "state",
		factCeleryStatus:          "state",
		factCeleryError:           "state",
		factIndexStatus:           "state",
		factIndexError:            "state",
		factClassifierStatus:      "state",
		factClassifierError:       "state",
		factStatusUnobservable:    "state",
	}
	if len(collection.Facts) != len(temperament) {
		t.Fatalf("declared facts %v", collection.Facts)
	}
	// The declared set and the set this code can emit are one set: a fact
	// declared and never emitted is a promise nothing tests, and one emitted
	// and never declared has no sentence, no type and no disclosure class.
	emitted := map[string]bool{}
	for _, name := range emittableFacts() {
		emitted[name] = true
	}
	for fact, want := range temperament {
		declared, ok := collection.Facts[fact]
		if !ok {
			t.Errorf("fact %s is not declared", fact)
			continue
		}
		if !emitted[fact] {
			t.Errorf("%s is declared and this collector cannot emit it", fact)
		}
		if declared.Temperament != want {
			t.Errorf("%s is declared %q, pinned %q", fact, declared.Temperament, want)
		}
		if declared.Kind != "observed" {
			t.Errorf("%s is %q: every value here is read off the archive's own API", fact, declared.Kind)
		}
		if declared.Sentence == "" {
			t.Errorf("%s has no sentence, and a sentence is what a consumer renders", fact)
		}
	}
	for fact := range emitted {
		if _, ok := collection.Facts[fact]; !ok {
			t.Errorf("%s is emitted and not declared", fact)
		}
	}

	// The four facts that are not `nothing`, and they are the whole disclosure
	// judgement this collector makes. A component's error sentence is
	// paperless's own text and it interpolates whatever the check was reaching
	// for — a hostname, a DSN — so it is third-party content, marked as such for
	// a model (DESIGN 21/29) and substituted for a public corpus.
	content := map[string]bool{
		factDatabaseError: true, factRedisError: true,
		factCeleryError: true, factIndexError: true, factClassifierError: true,
	}
	for fact, declared := range collection.Facts {
		want := "nothing"
		if content[fact] {
			want = "content"
		}
		if declared.Discloses != want {
			t.Errorf("%s discloses %q, pinned %q", fact, declared.Discloses, want)
		}
	}

	// Both byte counts carry their unit, because a bare 63195054080 beside a
	// bare 3 is two numbers a renderer cannot tell apart.
	for _, pair := range storageMembers {
		if collection.Facts[pair.fact].Unit != "bytes" {
			t.Errorf("%s declares unit %q, and it is a byte count", pair.fact, collection.Facts[pair.fact].Unit)
		}
	}
	for _, pair := range inventoryMembers {
		if collection.Facts[pair.fact].Unit != "count" {
			t.Errorf("%s declares unit %q, and it is a count", pair.fact, collection.Facts[pair.fact].Unit)
		}
	}

	// Every count is an integer on the wire, and every word and sentence a
	// string. Declared rather than inferred, because the harness's typed
	// equality treats 3 and 3.0 as two different readings.
	for fact, declared := range collection.Facts {
		want := "string"
		if strings.HasSuffix(fact, "Count") || strings.HasSuffix(fact, "Bytes") {
			want = "integer"
		}
		if declared.Type != want {
			t.Errorf("%s is declared %q, want %q", fact, declared.Type, want)
		}
	}
}

// The answer is what a row is FOR (DESIGN 26), and every name in it must be a
// fact this collection declares — an answer naming something undeclared is a
// row a renderer would go looking for and never find.
func TestTheDeclaredAnswerNamesDeclaredFacts(t *testing.T) {
	collection := decodeDeclaration(t)
	if len(collection.Answer) == 0 {
		t.Fatal("a collection with no declared answer states no reason to exist")
	}
	for _, name := range collection.Answer {
		if _, ok := collection.Facts[name]; !ok {
			t.Errorf("the answer names %s, which this collection does not declare", name)
		}
	}
	// The count both incidents needed surfaced, stated as part of the answer
	// rather than left to be inferred from the row.
	answers := map[string]bool{}
	for _, name := range collection.Answer {
		answers[name] = true
	}
	if !answers[factDocumentCount] {
		t.Errorf("%s is what this subsystem exists to publish and the answer does not name it", factDocumentCount)
	}
}

// A fact lifted straight out of a document declares WHERE in it, so a reader
// with the payload can check the collector's reading rather than trust it
// (DESIGN 19, `from`). The path is into the EVIDENCE payload, whose two members
// are the two requests — which is what makes `/statistics/documents_total` and
// `/status/tasks/redis_status` re-checkable with one curl each.
func TestEveryDocumentBorneFactDeclaresWhereItCameFrom(t *testing.T) {
	collection := decodeDeclaration(t)
	want := map[string]string{}
	for _, pair := range inventoryMembers {
		want[pair.fact] = "/statistics/" + pair.member
	}
	want[factPngxVersion] = "/status/pngx_version"
	for _, pair := range storageMembers {
		want[pair.fact] = "/status/storage/" + pair.member
	}
	want[factDatabaseStatus] = "/status/database/status"
	want[factDatabaseError] = "/status/database/error"
	for _, component := range taskComponents {
		want[component.statusFact] = "/status/tasks/" + component.member
		want[component.errorFact] = "/status/tasks/" + errorMember(component.member)
	}
	for fact, path := range want {
		if got := collection.Facts[fact].From; got != path {
			t.Errorf("%s declares from %q, want %q", fact, got, path)
		}
	}
	// The one fact no payload carries: a could-not-read exists precisely
	// because there was no document to point into.
	if collection.Facts[factStatusUnobservable].From != "" {
		t.Errorf("%s declares a payload path, and no payload carries it", factStatusUnobservable)
	}
}

// The two connection-URL positions are declared and the exemption is not, in
// both directions. An exemption asserting "no credential surface" would be
// FALSE on any paperless running Postgres or a remote broker, where
// `database.url` and `tasks.redis_url` hold the credential itself — which is
// the bound harness/scrub/paperless.json states loudly and the reason no fact
// here is derived from either.
func TestTheTwoConnectionURLsAreDeclaredSecretAndReachNoFact(t *testing.T) {
	collection := decodeDeclaration(t)
	if collection.Exemption != "" {
		t.Fatal("an exemption beside a redaction list is two rulings contradicting each other in one document")
	}
	paths := map[string]string{}
	for _, redaction := range collection.Redactions {
		paths[redaction.Path] = redaction.Discloses
	}
	for _, path := range []string{"/status/database/url", "/status/tasks/redis_url"} {
		if paths[path] != "secret" {
			t.Errorf("%s is declared %q; on a Postgres or remote-broker deployment it holds the credential", path, paths[path])
		}
	}
	if len(paths) != 2 {
		t.Errorf("declared redactions %v: the two connection URLs are the whole of this document's credential surface", paths)
	}
	// And neither is a source of anything: no declared fact points into them.
	for fact, declared := range collection.Facts {
		for path := range paths {
			if declared.From == path {
				t.Errorf("%s is derived from %s, which is declared secret", fact, path)
			}
		}
	}
}

// The credential is DECLARED and never written down. The declaration names the
// variable systemd will hold, and no reference command, no probe sentence and
// no read path may carry a token — a reference command an administrator can
// paste has a placeholder where the secret goes, which is also how the shipping
// adapter writes it.
func TestTheDeclarationNamesTheCredentialAndCarriesNoToken(t *testing.T) {
	var declaration struct {
		Authority struct {
			ReadPaths   []string `json:"read_paths"`
			Credentials []string `json:"credentials"`
		} `json:"authority"`
		Probe string `json:"probe"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	for _, path := range declaration.Authority.ReadPaths {
		if !strings.HasPrefix(path, "/proc/") {
			t.Errorf("read path %q: the only paths this collector opens are the two /proc files the envelope needs", path)
		}
	}
	if len(declaration.Authority.Credentials) != 1 || declaration.Authority.Credentials[0] != tokenVariable {
		t.Errorf("the declared credential is %v, and the collector reads %s", declaration.Authority.Credentials, tokenVariable)
	}
	// The probe prose must name BOTH variables: where the archive is and what
	// opens it are deployment configuration, and a declaration that named
	// neither would leave the deployment guessing which absence it is looking
	// at when the row does not appear.
	for _, variable := range []string{urlVariable, tokenVariable} {
		if !strings.Contains(declaration.Probe, variable) {
			t.Errorf("the probe prose must name %s", variable)
		}
	}

	collection := decodeDeclaration(t)
	found := map[string]bool{}
	for _, command := range collection.Commands {
		if command.Purpose == "" {
			t.Errorf("reference command %v states no purpose", command.Argv)
		}
		for _, token := range command.Argv {
			if strings.Contains(token, statisticsPath) {
				found[statisticsPath] = true
			}
			if strings.Contains(token, statusPath) {
				found[statusPath] = true
			}
			// The placeholder, not a value: a declaration is the same file on
			// every host, so a token written into one would be published to all
			// of them.
			if strings.Contains(token, tokenHeader+": "+strings.TrimSpace(tokenScheme)) &&
				!strings.Contains(token, "<token>") {
				t.Errorf("reference command %v spells the header without a placeholder", command.Argv)
			}
		}
	}
	if !found[statisticsPath] || !found[statusPath] {
		t.Fatalf("the declared reference commands have drifted from the paths in source.go: %v", found)
	}
}
