package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
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

type declaredCollection struct {
	Name   string   `json:"name"`
	Prefix string   `json:"prefix"`
	Answer []string `json:"answer"`
	Facts  map[string]struct {
		Type      string   `json:"type"`
		Values    []string `json:"values"`
		Sentence  string   `json:"sentence"`
		Discloses string   `json:"discloses"`
	} `json:"facts"`
	Names      map[string]any `json:"names"`
	Relations  []any          `json:"relations"`
	Redactions []struct {
		Path      string `json:"path"`
		Discloses string `json:"discloses"`
	} `json:"redactions"`
	Exemption string `json:"redaction_exemption"`
}

func decodeDeclaration(t *testing.T) (map[string]declaredCollection, []string) {
	t.Helper()
	var declaration struct {
		Schema    string `json:"schema"`
		Collector string `json:"collector"`
		Probe     string `json:"probe"`
		Authority struct {
			ReadPaths   []string `json:"read_paths"`
			Credentials []string `json:"credentials"`
		} `json:"authority"`
		Collections []declaredCollection `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "servarr" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	byName := map[string]declaredCollection{}
	for _, collection := range declaration.Collections {
		byName[collection.Name] = collection
	}
	return byName, declaration.Authority.Credentials
}

// The declaration must name every fact this collector can put on the wire and
// nothing it cannot: the fact dictionary, the renderer's semantics and the MCP
// tool descriptions are all generated from it, so a fact emitted and not
// declared arrives at a consumer with no sentence, and a fact declared and
// never emitted is a promise the collector does not keep.
//
// The emitted sets below are held beside the declaration BY HAND rather than
// derived from it, which is the whole point: a list generated from the file it
// checks would go green forever.
func TestTheDeclarationNamesExactlyTheFactsThisCollectorEmits(t *testing.T) {
	collections, _ := decodeDeclaration(t)
	emitted := map[string][]string{
		"apps": {"App", "ApiFamily", "AppName", "Version", "HealthErrors",
			"HealthWarnings", "QueueTotal", "QueueUnobservable",
			"StatusUnobservable", "ConfigMissing", "ConfigDuplicate"},
		"health": {"App", "Source", "Type", "Message", "WikiUrl"},
		"queue": {"App", "Title", "Status", "TrackedDownloadStatus",
			"TrackedDownloadState", "DownloadClient", "Indexer", "Protocol",
			"DownloadId", "SizeLeftBytes", "ErrorMessage", "StatusMessages"},
		"history": {"App", "EventType", "Title", "Indexer", "DownloadClient",
			"DownloadId", "Quality", "Date"},
	}
	if len(collections) != len(emitted) {
		t.Fatalf("declared %d collections, this collector serves %d", len(collections), len(emitted))
	}
	// The served table is what the batch loop dispatches on, so the two must
	// carry the same names or a request the declaration promises is declined
	// unsupported by the binary that made the promise.
	for name := range served {
		if _, declared := collections[name]; !declared {
			t.Errorf("the binary serves %q and the declaration does not carry it", name)
		}
	}
	for name, facts := range emitted {
		collection, declared := collections[name]
		if !declared {
			t.Errorf("%s is served and not declared", name)
			continue
		}
		if len(collection.Facts) != len(facts) {
			declaredNames := make([]string, 0, len(collection.Facts))
			for fact := range collection.Facts {
				declaredNames = append(declaredNames, fact)
			}
			sort.Strings(declaredNames)
			t.Errorf("%s declares %v; this collector emits %v", name, declaredNames, facts)
		}
		for _, fact := range facts {
			spec, ok := collection.Facts[fact]
			if !ok {
				t.Errorf("%s/%s reaches the wire and is not declared", name, fact)
				continue
			}
			if spec.Sentence == "" {
				t.Errorf("%s/%s has no sentence, and a sentence is what a consumer renders", name, fact)
			}
			if spec.Discloses == "" {
				t.Errorf("%s/%s declares no disclosure class, and there is no safe default", name, fact)
			}
		}
		for _, fact := range collection.Answer {
			if _, ok := collection.Facts[fact]; !ok {
				t.Errorf("%s answers with %s, which it does not declare", name, fact)
			}
		}
	}
}

// The health grade is NOT declared as a closed set, and that is a decision
// rather than an omission. The apps' ladder is ok/notice/warning/error today,
// and this collector mirrors a grade it has never met as a warning rather than
// dropping it — because an unrecognised grade is still the app raising its
// hand. An enum here would put a value outside its own declaration on the wire
// the first release a new grade shipped.
func TestTheHealthGradeIsNotDeclaredAClosedSet(t *testing.T) {
	collections, _ := decodeDeclaration(t)
	grade := collections["health"].Facts["Type"]
	if grade.Type != "string" || len(grade.Values) != 0 {
		t.Errorf("Type is declared %q with values %v; the apps own this vocabulary "+
			"and this collector mirrors what they say", grade.Type, grade.Values)
	}
	if !strings.Contains(grade.Sentence, "never") {
		t.Error("the sentence must say the grade is mirrored and never re-judged, " +
			"because that is the whole of what this fact promises")
	}
}

// Absences and presences that are decisions rather than omissions, each pinned
// so nobody adds one without meeting the reason it is not there.
func TestTheDeclarationsShapeIsTheOneTheStreamCarries(t *testing.T) {
	collections, credentials := decodeDeclaration(t)
	for name, collection := range collections {
		// No `names`: the reference's rows publish no name family at all, so
		// the collator keys a row on the name this collector publishes —
		// <instance>/<native>, which already carries the namespace.
		if len(collection.Names) != 0 {
			t.Errorf("%s declares a names family and the stream carries none", name)
		}
		// No `relations`: the queue's `tracks` edge and the app's
		// `dispatches-to` edges both belong to the opened object, and this
		// collector does not serve that verb yet.
		if len(collection.Relations) != 0 {
			t.Errorf("%s declares a relation type and asserts none", name)
		}
	}
	// Three collections carry a reviewed exemption and one carries a redaction
	// list, and the split is the reference's own: a grab's downloadUrl is where
	// an indexer's api key and a private tracker's passkey live, and it sits in
	// the history's records alone. Getting this backwards is the failure the
	// exemption exists to prevent — a document family declared credential-free
	// while it carries the one credential this subsystem touches.
	for _, name := range []string{"apps", "health", "queue"} {
		if collections[name].Exemption == "" {
			t.Errorf("%s must carry a reviewed statement that its documents have "+
				"no credential surface, or a redaction list", name)
		}
		if len(collections[name].Redactions) != 0 {
			t.Errorf("%s claims an exemption AND a redaction list — two rulings "+
				"contradicting each other in one document", name)
		}
	}
	if collections["history"].Exemption != "" {
		t.Error("the acquisition trail carries the one credential-bearing member " +
			"in this subsystem and must not claim to have none")
	}
	if len(collections["history"].Redactions) == 0 {
		t.Error("a grab's data members carry the URL an indexer credential rides in")
	}
	for _, redaction := range collections["history"].Redactions {
		if redaction.Discloses != "secret" {
			t.Errorf("%s discloses %q: a URL carrying an api key or a passkey is "+
				"withheld at the source, never substituted", redaction.Path,
				redaction.Discloses)
		}
	}
	for name, want := range map[string]string{
		"apps": "app", "health": "health", "queue": "queue", "history": "history",
	} {
		if got := collections[name].Prefix; got != want {
			t.Errorf("%s prefix %q: a target's kind names a declared prefix, and the "+
				"reference publishes these objects as %s:<name>", name, got, want)
		}
	}
	// The receipt names are the authority this collector needs, and the KEY is
	// the one thing a deployment must grant it. Declaring it is what puts the
	// credential in the generated unit configuration instead of in a comment.
	granted := strings.Join(credentials, " ")
	for _, want := range []string{"SE_SERVARR_INSTANCES", "SE_<NAME>_API_KEY"} {
		if !strings.Contains(granted, want) {
			t.Errorf("authority.credentials omits %s, which this process reads", want)
		}
	}
}
