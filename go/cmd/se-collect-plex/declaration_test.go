package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// stubSource drives the row builders past shapes no staged DOCUMENT can reach.
//
// Three of this collector's facts are not statements about a document at all:
// ConfigMissing is decided by the process's own receipts before any request,
// and StatusUnobservable and ItemCountUnobservable are decided by whether the
// request came back. A replay directory cannot stage any of the three — an
// uncaptured payload is a broken capture and fails the run, deliberately, rather
// than becoming a reading about a machine nobody observed — so they are reached
// here, through the real derivations, with the seam answering the way a dark
// server makes it answer.
type stubSource struct {
	replaySource
	deploy deployment
	dark   map[string]string // request path -> the could-not-read text it answers with
}

func (s stubSource) deployment() deployment { return s.deploy }

func (s stubSource) document(path string) (fetched, error) {
	if detail, silent := s.dark[path]; silent {
		return fetched{detail: detail}, nil
	}
	return s.replaySource.document(path)
}

func (s stubSource) window(path string) (fetched, error) {
	if detail, silent := s.dark[path]; silent {
		return fetched{detail: detail}, nil
	}
	return s.replaySource.window(path)
}

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
	Type        string   `json:"type"`
	Unit        string   `json:"unit"`
	Values      []string `json:"values"`
	Labels      []string `json:"labels"`
	Temperament string   `json:"temperament"`
	Kind        string   `json:"kind"`
	Discloses   string   `json:"discloses"`
	Sentence    string   `json:"sentence"`
	From        string   `json:"from"`
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

func decodeDeclaration(t *testing.T) map[string]declaredCollection {
	t.Helper()
	var declaration struct {
		Schema      string               `json:"schema"`
		Collector   string               `json:"collector"`
		Probe       string               `json:"probe"`
		Collections []declaredCollection `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "plex" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	out := map[string]declaredCollection{}
	for _, collection := range declaration.Collections {
		out[collection.Name] = collection
	}
	if len(out) != len(served) {
		t.Fatalf("the declaration carries %d collections and this collector serves %d", len(out), len(served))
	}
	for name := range served {
		if _, ok := out[name]; !ok {
			t.Fatalf("%s is served and not declared", name)
		}
	}
	// seerr's collection is neither served nor declared, and that is a ruling
	// rather than an omission: it is a second application reached with a second
	// credential, no corpus variant can stage one, and a declaration carrying it
	// would promise facts this binary has never been able to read.
	if _, declared := out["requests"]; declared {
		t.Fatal("requests is seerr's collection; this collector must neither serve nor declare it")
	}
	return out
}

// emittedFacts runs the collector over both staged shapes and both dark ones,
// and returns every fact name it published, per collection. Derived from the RUN
// rather than listed here, because a list retyped in a test drifts into agreement
// with whatever the code happens to do — which is the defect this guard exists to
// catch, one level up.
func emittedFacts(t *testing.T) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	record := func(collection string, facts map[string]any) {
		if out[collection] == nil {
			out[collection] = map[string]bool{}
		}
		for name := range facts {
			out[collection][name] = true
		}
	}

	for _, dir := range []string{stageHealthy(t), stageBusy(t)} {
		code, stdout, stderr := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": dir})
		if code != exitOK {
			t.Fatalf("exit %d, stderr: %s", code, stderr)
		}
		for _, object := range ofKind(parseRecords(t, stdout), "object") {
			facts, _ := object["facts"].(map[string]any)
			record(object["collection"].(string), facts)
		}
	}

	// The three that no document can carry, taken through the real builders.
	staged := replaySource{dir: stageHealthy(t)}
	cases := []struct {
		collection string
		src        source
	}{
		{"server", stubSource{replaySource: staged,
			deploy: deployment{missing: []string{tokenVariable}}}},
		{"server", stubSource{replaySource: staged,
			dark: map[string]string{pathRoot: detailNoAnswer(pathRoot)}}},
		{"libraries", stubSource{replaySource: staged,
			dark: map[string]string{sectionWindowPath("1"): detailStatusCode(sectionWindowPath("1"), 503)}}},
	}
	for _, one := range cases {
		rows, err := served[one.collection](one.src)
		if err != nil {
			t.Fatalf("%s: %v", one.collection, err)
		}
		for _, row := range rows {
			var facts map[string]any
			if err := json.Unmarshal(row.facts.encode(), &facts); err != nil {
				t.Fatal(err)
			}
			record(one.collection, facts)
		}
	}
	return out
}

// The declared set and the set this code can emit are one set. A fact declared
// and never emitted is a promise nothing tests; one emitted and never declared
// has no sentence, no type and no disclosure class, so nothing downstream can
// render it or redact it.
func TestTheDeclaredFactsAreExactlyTheFactsThisCollectorEmits(t *testing.T) {
	declared := decodeDeclaration(t)
	emitted := emittedFacts(t)

	var orphans []string
	for name, collection := range declared {
		for fact := range collection.Facts {
			if !emitted[name][fact] {
				orphans = append(orphans, name+"/"+fact)
			}
		}
	}
	for name, facts := range emitted {
		for fact := range facts {
			if _, ok := declared[name].Facts[fact]; !ok {
				orphans = append(orphans, "undeclared "+name+"/"+fact)
			}
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Fatalf("the declaration and the code disagree about what this collector says: %v", orphans)
	}
}

// The pinned members, asserted from the wire side: the schema-validation half
// (se.declaration.1.json is closed) runs in the Python harness, which owns the
// contract registry.
func TestTheDeclarationCarriesThePinnedContract(t *testing.T) {
	declared := decodeDeclaration(t)

	// The prefix and the row's name are what the collator mints the id from, and
	// `server:plex`, `library:<key>` and `session:<key>` are the ids the shipping
	// adapter mints — so a port that moved either would publish a second object
	// for one library.
	prefixes := map[string]string{"server": "server", "libraries": "library", "sessions": "session"}
	for name, prefix := range prefixes {
		if declared[name].Prefix != prefix {
			t.Errorf("%s declares prefix %q, and the adapter's id is %s:<name>", name, declared[name].Prefix, prefix)
		}
		if declared[name].Freshness == "" || len(declared[name].Answer) == 0 {
			t.Errorf("%s declares no freshness or no answer set", name)
		}
	}

	// The three facts that state a FAILURE rather than a reading, and therefore
	// have no path into any payload. Every other fact declares one, because a
	// reader holding the document must be able to check the reading against it.
	statements := map[string]bool{
		"server/ConfigMissing":            true,
		"server/StatusUnobservable":       true,
		"libraries/ItemCountUnobservable": true,
	}

	// Disclosure is required with no default, and these are the values that
	// decide whether a corpus can be published at all: the server's own name is
	// its identity, a library title is a word the operator chose, and a session
	// names a person and what they were watching.
	pinned := map[string]string{
		"server/FriendlyName": "identity",
		"server/Version":      "nothing",
		"server/SessionCount": "nothing",
		"libraries/Title":     "content",
		"libraries/ItemCount": "nothing",
		"sessions/Title":      "content",
		"sessions/User":       "identity",
	}
	classes := map[string]bool{"nothing": true, "identity": true, "location": true,
		"content": true, "secret": true}
	for name, collection := range declared {
		for fact, spec := range collection.Facts {
			reference := name + "/" + fact
			if spec.Sentence == "" {
				t.Errorf("%s has no sentence, and a sentence is what a consumer renders", reference)
			}
			if !classes[spec.Discloses] {
				t.Errorf("%s discloses %q, which is not one of the five classes", reference, spec.Discloses)
			}
			if spec.Kind != "observed" {
				// Every figure here is read off the API — the two timestamps are
				// a unit conversion of a member the server stated, not a
				// derivation from another FACT, which is what `derived` means.
				t.Errorf("%s is kind %q; every fact here is read off the interface", reference, spec.Kind)
			}
			if (spec.From == "") != statements[reference] {
				t.Errorf("%s declares from %q; a reading names its payload path and a failure statement has none", reference, spec.From)
			}
			if want, ok := pinned[reference]; ok && spec.Discloses != want {
				t.Errorf("%s discloses %q, pinned %q", reference, spec.Discloses, want)
			}
		}
	}

	// The two counts are INTEGERS, and that is the type the wire carries: a
	// float64 round trip would spell 2 as 2.0, which the harness's typed equality
	// sees and a typed consumer reads as a different value.
	for _, reference := range []string{"server/SessionCount", "libraries/ItemCount"} {
		collection, fact, _ := strings.Cut(reference, "/")
		if spec := declared[collection].Facts[fact]; spec.Type != "integer" || spec.Unit != "count" {
			t.Errorf("%s is %q/%q; a count of things is an integer count", reference, spec.Type, spec.Unit)
		}
	}
	// Refreshing is a boolean with its two display words, because `false` is a
	// reading this row publishes rather than an absence a renderer may skip.
	if spec := declared["libraries"].Facts["Refreshing"]; spec.Type != "boolean" || len(spec.Labels) != 2 {
		t.Errorf("libraries/Refreshing is %q with labels %v", spec.Type, spec.Labels)
	}
	for _, fact := range []string{"ScannedAt", "UpdatedAt"} {
		if spec := declared["libraries"].Facts[fact]; spec.Type != "timestamp" {
			t.Errorf("libraries/%s is %q; the epoch seconds are converted to a UTC timestamp", fact, spec.Type)
		}
	}
}

// Exactly one of the two, per collection: declaring neither is a build failure,
// and an exemption asserting no credential surface beside a declared redaction
// list is two rulings contradicting each other in one document.
func TestEachCollectionEitherDeclaresItsRedactionsOrWhyItNeedsNone(t *testing.T) {
	declared := decodeDeclaration(t)
	for name, collection := range declared {
		if (len(collection.Redactions) == 0) == (collection.Exemption == "") {
			t.Errorf("%s declares %d redactions and an exemption of %d characters", name, len(collection.Redactions), len(collection.Exemption))
		}
	}
	// The token is the one credential in play and it rides a HEADER, so no
	// document this collector reads can carry it — which is what every exemption
	// here rests on, and it must say so rather than merely being true.
	for name, collection := range declared {
		prose := strings.ToLower(collection.Exemption)
		if !strings.Contains(prose, "header") && !strings.Contains(prose, "credential") {
			t.Errorf("%s's exemption does not state why there is no credential surface: %q", name, collection.Exemption)
		}
	}
	// The sessions exemption is the one that must bound PUBLICATION rather than
	// service: the document names a person, which is declared and served, and is
	// precisely what a public corpus may not hold.
	if !strings.Contains(declared["sessions"].Exemption, "corpus") {
		t.Error("the sessions exemption must state the publication bound, not only the credential one")
	}
}

// The declared commands must be the requests this collector actually makes: a
// reference command is what an administrator re-runs by hand to check the
// reading, and one naming a path the code never fetches documents a collector
// that does not exist.
func TestTheReferenceCommandsNameEveryRequestThisCollectorMakes(t *testing.T) {
	declared := decodeDeclaration(t)
	joined := ""
	for _, collection := range declared {
		for _, command := range collection.Commands {
			if command.Purpose == "" {
				t.Errorf("reference command %v states no purpose", command.Argv)
			}
			joined += strings.Join(command.Argv, " ") + "\n"
		}
	}
	// Four requests, and the last is a FAMILY: one per section, keyed by the
	// section's own key, asked with the zero-size container window that makes the
	// count possible without pulling the library.
	for _, fragment := range []string{
		pathSessions,
		pathSections,
		sectionWindowPath("<key>"),
		countWindow,
		tokenHeader,
		acceptHeader,
	} {
		if !strings.Contains(joined, fragment) {
			t.Errorf("no reference command names %q, which this collector sends", fragment)
		}
	}
	// The endpoint and the token are deployment configuration, so the commands
	// name the variables rather than an address and a secret this file invented.
	for _, variable := range []string{urlVariable, tokenVariable} {
		if !strings.Contains(joined, variable) {
			t.Errorf("the reference commands do not name %s, which is not a constant", variable)
		}
	}
}

// The probe prose has to name where the endpoint and the token come from: a probe
// an operator cannot act on is a probe they will ignore, and "no plex here",
// "SE_PLEX_URL is unset" and "SE_PLEX_TOKEN is unset" are three readings with
// three different fixes.
func TestTheProbeProseNamesTheDeploymentVariables(t *testing.T) {
	var declaration struct {
		Probe     string `json:"probe"`
		Authority struct {
			ReadPaths   []string `json:"read_paths"`
			Credentials []string `json:"credentials"`
		} `json:"authority"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	for _, variable := range []string{urlVariable, tokenVariable} {
		if !strings.Contains(declaration.Probe, variable) {
			t.Errorf("the probe prose must name %s", variable)
		}
	}
	for _, path := range declaration.Authority.ReadPaths {
		if !strings.HasPrefix(path, "/proc/") {
			t.Errorf("read path %q: the only paths this collector opens are the two /proc files the envelope needs — the API is reached over HTTP", path)
		}
	}
	if len(declaration.Authority.Credentials) != 1 || declaration.Authority.Credentials[0] != tokenVariable {
		t.Errorf("the declared credentials are %v, and this collector carries exactly %s", declaration.Authority.Credentials, tokenVariable)
	}
}
