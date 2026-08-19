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
	Redactions []any                   `json:"redactions"`
	Exemption  string                  `json:"redaction_exemption"`
	Commands   []struct {
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
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "bazarr" {
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
	// and `instance:bazarr` is the id the shipping adapter mints — so a port
	// that moved either would publish a second object for one instance.
	if collection.Prefix != "instance" {
		t.Fatalf("prefix %q: the id is <prefix>:<name>, and the adapter's is instance:%s", collection.Prefix, instanceName)
	}

	// Temperament decides whether a fact churns the snapshot diff (DESIGN 12),
	// which is why it is pinned rather than left to reading. The three version
	// strings are `configuration` — they move on a deployment and never on a
	// sample — while the health list and the could-not-read text are `state`,
	// because those are exactly what changes underneath a still instance.
	temperament := map[string]string{
		factVersion:            "configuration",
		factSonarrVersion:      "configuration",
		factRadarrVersion:      "configuration",
		factHealthIssues:       "state",
		factConfigMissing:      "existence",
		factStatusUnobservable: "state",
	}
	if len(collection.Facts) != len(temperament) {
		t.Fatalf("declared facts %v", collection.Facts)
	}
	// The declared set and the set this code can emit are one set: a fact
	// declared and never emitted is a promise nothing tests, and one emitted
	// and never declared has no sentence, no type and no disclosure class.
	emitted := map[string]bool{
		factHealthIssues: true, factConfigMissing: true, factStatusUnobservable: true,
	}
	for _, pair := range statusMembers {
		emitted[pair.fact] = true
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
			t.Errorf("%s is %q: every value here is read off the instance or off this deployment's own configuration", fact, declared.Kind)
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

	// The one fact that is not `nothing`, and it is the whole disclosure
	// judgement this collector makes. A health sentence is bazarr's own text
	// and it interpolates whatever the instance is complaining about — a media
	// path, a provider's name — so it is third-party content, marked as such
	// for a model (DESIGN 21/29) and substituted for a public corpus. Declaring
	// it `nothing` would be the shape harness/scrub/docker.json's own
	// #argv-and-labels audit found twice.
	for fact, declared := range collection.Facts {
		want := "nothing"
		if fact == factHealthIssues {
			want = "content"
		}
		if declared.Discloses != want {
			t.Errorf("%s discloses %q, pinned %q", fact, declared.Discloses, want)
		}
	}

	if len(collection.Redactions) != 0 || collection.Exemption == "" {
		t.Fatal("an exemption beside a redaction list is two rulings contradicting each other in one document")
	}
}

// A fact lifted straight out of a document declares WHERE in it, so a reader
// with the payload can check the collector's reading rather than trust it
// (DESIGN 19, `from`). The two facts with no `from` are the ones no document
// carries — a missing receipt is read off this deployment, and a could-not-read
// exists precisely because there was no document.
func TestEveryDocumentBorneFactDeclaresWhereItCameFrom(t *testing.T) {
	collection := decodeDeclaration(t)
	for _, pair := range statusMembers {
		want := "/data/" + pair.member
		if got := collection.Facts[pair.fact].From; got != want {
			t.Errorf("%s declares from %q, want %q", pair.fact, got, want)
		}
	}
	if collection.Facts[factHealthIssues].From == "" {
		t.Error("HealthIssues is folded from a document and must say from where")
	}
	for _, fact := range []string{factConfigMissing, factStatusUnobservable} {
		if collection.Facts[fact].From != "" {
			t.Errorf("%s declares a payload path, and no payload carries it", fact)
		}
	}
}

// The credential is DECLARED and never written down. The declaration names the
// variable systemd will hold, and no reference command, no probe sentence and
// no read path may carry a key — a reference command an administrator can
// paste has a placeholder where the secret goes, which is also how the shipping
// adapter writes it.
func TestTheDeclarationNamesTheCredentialAndCarriesNoKey(t *testing.T) {
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
	if len(declaration.Authority.Credentials) != 1 || declaration.Authority.Credentials[0] != keyVariable {
		t.Errorf("the declared credential is %v, and the collector reads %s", declaration.Authority.Credentials, keyVariable)
	}
	// The probe prose must name BOTH variables: where the instance is and what
	// opens it are deployment configuration, and a declaration that named
	// neither would leave the deployment guessing which absence it is looking
	// at when the row does not appear.
	for _, variable := range []string{urlVariable, keyVariable} {
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
			if strings.Contains(token, pathStatus) {
				found[pathStatus] = true
			}
			if strings.Contains(token, pathHealth) {
				found[pathHealth] = true
			}
			// The placeholder, not a value: a declaration is the same file on
			// every host, so a key written into one would be published to all
			// of them.
			if strings.Contains(token, "X-API-KEY") && !strings.Contains(token, "<key>") {
				t.Errorf("reference command %v spells the header without a placeholder", command.Argv)
			}
		}
	}
	if !found[pathStatus] || !found[pathHealth] {
		t.Fatalf("the declared reference commands have drifted from the paths in source.go: %v", found)
	}
}
