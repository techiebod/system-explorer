package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// The pinned members of the system-identity declaration, asserted from the
// wire side: the schema-validation half (se.declaration.1.json is closed)
// runs in the Python harness, which owns the contract registry.
func TestTheDeclarationCarriesThePinnedContract(t *testing.T) {
	var declaration struct {
		Schema      string `json:"schema"`
		Collector   string `json:"collector"`
		Collections []struct {
			Name      string `json:"name"`
			Freshness string `json:"freshness"`
			Facts     map[string]struct {
				Type        string `json:"type"`
				Temperament string `json:"temperament"`
				Kind        string `json:"kind"`
				Discloses   string `json:"discloses"`
				Sentence    string `json:"sentence"`
			} `json:"facts"`
			Redactions []any  `json:"redactions"`
			Exemption  string `json:"redaction_exemption"`
		} `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "system" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 1 {
		t.Fatalf("one collection, identity; got %d", len(declaration.Collections))
	}
	collection := declaration.Collections[0]
	if collection.Name != "identity" || collection.Freshness != "1h" {
		t.Fatalf("collection %q at freshness %q", collection.Name, collection.Freshness)
	}

	discloses := map[string]string{
		"OsId":         "nothing",
		"OsVersionId":  "nothing",
		"OsPrettyName": "nothing",
		"Hostname":     "location",
	}
	if len(collection.Facts) != len(discloses) {
		t.Fatalf("declared facts %v", collection.Facts)
	}
	for fact, want := range discloses {
		declared, ok := collection.Facts[fact]
		if !ok {
			t.Errorf("fact %s is not declared", fact)
			continue
		}
		if declared.Discloses != want {
			t.Errorf("%s discloses %q, pinned %q", fact, declared.Discloses, want)
		}
		if declared.Type != "string" || declared.Temperament != "configuration" || declared.Kind != "observed" {
			t.Errorf("%s: %s/%s/%s — pinned string/configuration/observed", fact, declared.Type, declared.Temperament, declared.Kind)
		}
		if declared.Sentence == "" {
			t.Errorf("%s has no sentence, and a sentence is what a consumer renders", fact)
		}
	}

	// The redaction exemption's prose is load-bearing and carried verbatim
	// (DESIGN 19): it is the reviewed statement that this source has no
	// credential surface, so a paraphrase is a different review.
	const pinned = "every served fact is a single declared scalar; the evidence document is os-release verbatim, whose remaining members are distribution constants that disclose nothing"
	if collection.Exemption != pinned {
		t.Fatalf("redaction_exemption drifted from the pinned prose:\n%q", collection.Exemption)
	}
	if len(collection.Redactions) != 0 {
		t.Fatal("an exemption beside a redaction list is two rulings contradicting each other in one document")
	}
}
