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
			Rules      []struct {
				Key     string `json:"key"`
				Level   string `json:"level"`
				Grounds string `json:"grounds"`
			} `json:"rules"`
		} `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "system" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 4 {
		t.Fatalf("four collections — identity, time, overview, boot; got %d",
			len(declaration.Collections))
	}
	collection := declaration.Collections[0]
	if collection.Name != "identity" || collection.Freshness != "1h" {
		t.Fatalf("collection %q at freshness %q", collection.Name, collection.Freshness)
	}

	// The whole identity contract, pinned. It was four facts until
	// 2026-08-23, when the first live comparison this collection has ever
	// had found it sharing NO fact names with the reference's — the
	// machine's own account of itself was simply missing, and no probe
	// could see it because the row claiming the comparison read the work
	// list. MachineID discloses `identity` because it is exactly that: it
	// survives a rename and changes on reinstall.
	discloses := map[string]string{
		"OsId":                      "nothing",
		"OsVersionId":               "nothing",
		"OsPrettyName":              "nothing",
		"Hostname":                  "location",
		"StaticHostname":            "identity",
		"Chassis":                   "identity",
		"OperatingSystemPrettyName": "identity",
		"KernelName":                "nothing",
		"KernelRelease":             "nothing",
		"HardwareVendor":            "identity",
		"HardwareModel":             "identity",
		"Architecture":              "nothing",
		"Virtualization":            "identity",
		"MachineID":                 "identity",
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

// The time collection's own pins: the discloses classes (three location
// facts — the timezone and the server names — must never quietly become
// "nothing"), the moving reading declared as the gauge it is, and the
// fleet's first rule table with its grounds stated as OURS.
func TestTheTimeDeclarationPinsItsClasses(t *testing.T) {
	var declaration struct {
		Collections []struct {
			Name  string `json:"name"`
			Facts map[string]struct {
				Temperament string `json:"temperament"`
				Discloses   string `json:"discloses"`
			} `json:"facts"`
			Rules []struct {
				Key     string   `json:"key"`
				Level   string   `json:"level"`
				Grounds string   `json:"grounds"`
				Cites   []string `json:"cites"`
			} `json:"rules"`
		} `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range declaration.Collections {
		if c.Name != "time" {
			continue
		}
		found = true
		for fact, want := range map[string]string{
			"Timezone": "location", "CurrentNTPServer": "location",
			"SystemNTPServers": "location", "FallbackNTPServers": "location",
			"NTP": "nothing", "NTPSynchronized": "nothing",
		} {
			if got := c.Facts[fact].Discloses; got != want {
				t.Errorf("%s discloses %q, pinned %q", fact, got, want)
			}
		}
		if c.Facts["CurrentTime"].Temperament != "gauge" {
			t.Error("CurrentTime moves between any two correct runs; anything " +
				"but gauge would make the comparator read time passing as a defect")
		}
		if len(c.Rules) != 1 || c.Rules[0].Key != "time-sync" ||
			c.Rules[0].Level != "warn" || c.Rules[0].Grounds != "threshold" {
			t.Fatalf("the time-sync rule is pinned warn/threshold: %+v", c.Rules)
		}
	}
	if !found {
		t.Fatal("no time collection declared")
	}
}
