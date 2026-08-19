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

type declaredFact struct {
	Type        string   `json:"type"`
	Unit        string   `json:"unit"`
	Temperament string   `json:"temperament"`
	Kind        string   `json:"kind"`
	Discloses   string   `json:"discloses"`
	Sentence    string   `json:"sentence"`
	Values      []string `json:"values"`
	DerivedFrom []string `json:"derived_from"`
	From        string   `json:"from"`
}

type declaredCollection struct {
	Name          string                  `json:"name"`
	Question      string                  `json:"question"`
	Prefix        string                  `json:"prefix"`
	Perishability string                  `json:"perishability"`
	Answer        []string                `json:"answer"`
	Facts         map[string]declaredFact `json:"facts"`
	Redactions    []any                   `json:"redactions"`
	Exemption     string                  `json:"redaction_exemption"`
	Commands      []struct {
		Purpose string   `json:"purpose"`
		Argv    []string `json:"argv"`
	} `json:"reference_commands"`
}

func decodeDeclaration(t *testing.T) map[string]declaredCollection {
	t.Helper()
	var declaration struct {
		Schema      string               `json:"schema"`
		Collector   string               `json:"collector"`
		Collections []declaredCollection `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "protection" {
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
		if _, declared := out[name]; !declared {
			t.Fatalf("%s is served and not declared", name)
		}
	}
	return out
}

// Every fact this collector's derivation can write, read off the derivation
// rather than retyped: the tests below bind to THIS set, so a fact added to a
// row without a sentence fails here instead of at the contract harness.
//
// It is a literal list because the derivation writes each name at a call site
// rather than through a table, and a list assembled from the call sites by
// hand is the thing under test — so the next test proves the list is neither
// short nor long by driving the real payloads through the real binary.
var emittable = map[string][]string{
	"targets": {
		"Class", "Kind", "OwnerHost", "Source", "Retention", "Cadence",
		"Destinations", "IndependentDestinations", "ImplementedHops",
		"HopImplementedBy", "UnimplementedHops", "ProvenRungs", "UnprovenRungs",
		"LastProvenAt", "FailedProofRungs", "LastFailedProofAt",
		"ProofScope", "ProofComparedAgainst", "ProofRecord",
	},
	"jobs": {
		"Job", "Unit", "State", "Basis", "AgeSeconds", "MaxAgeSeconds",
		"CheckedAt", "CheckedAgeSeconds", "LastResult", "LastFinishedAt",
		"LastSuccessAt", "ExitStatus", "ReceiptsUnobservable",
		"Target", "TargetClass", "TargetNotScoped", "TargetClassUnjoined",
		"ImplementsHops",
	},
	"destinations": {"Kind", "Independent", "PruneAuthority", "Immutability"},
}

// The one fact this collector can emit and does not declare, named here with
// the reason and the venue rather than left as a silent gap.
//
// TargetClassUnjoined fires only where the verdict's job row has NO `target`
// member at all — a checker that predates the field — and where no declared
// target names the job by name or in an implementedBy hop this host runs. The
// committed variant cannot stage it: every row in it carries `target`, because
// every checker the estate has run since the member landed writes one. So
// declaring it would fail the contract's other arm — declared implies observed
// somewhere, and no capture and no mutation operator reaches it — and the
// escape that arm offers is a residual in harness/se_harness/corpus.py, which
// is not this collector's file to write.
//
// Venue: a second protection variant staging a pre-`target` verdict, or a
// residual naming this fact. Until one lands, a host running an older checker
// would put a fact on the wire that this declaration cannot describe, and that
// is a defect stated here rather than a gap nobody can see.
var undeclaredButEmittable = map[string]string{
	"jobs/TargetClassUnjoined": "reachable only on a checker that predates the verdict's `target` member; no committed variant and no mutation operator stages one",
}

// The declared set and the set this code can emit are one set, deny-by-default
// in both directions with a single audited exception: a fact declared and never
// emitted is a promise nothing tests, and one emitted and never declared has no
// sentence, no type and no disclosure class.
func TestTheDeclaredFactsAreTheFactsThisCollectorCanEmit(t *testing.T) {
	declaration := decodeDeclaration(t)
	for collection, facts := range emittable {
		declared := declaration[collection].Facts
		for _, fact := range facts {
			if _, excused := undeclaredButEmittable[collection+"/"+fact]; excused {
				if _, present := declared[fact]; present {
					t.Errorf("%s/%s is declared AND excused from being declared — an excuse that has come true is one nobody withdrew", collection, fact)
				}
				continue
			}
			spec, ok := declared[fact]
			if !ok {
				t.Errorf("%s/%s is emitted and not declared", collection, fact)
				continue
			}
			if spec.Sentence == "" {
				t.Errorf("%s/%s has no sentence, and a sentence is what a consumer renders", collection, fact)
			}
		}
		known := map[string]bool{}
		for _, fact := range facts {
			known[fact] = true
		}
		for fact := range declared {
			if !known[fact] {
				t.Errorf("%s/%s is declared and this collector cannot emit it", collection, fact)
			}
		}
	}
	for key, reason := range undeclaredButEmittable {
		collection, fact, _ := strings.Cut(key, "/")
		found := false
		for _, name := range emittable[collection] {
			found = found || name == fact
		}
		if !found {
			t.Errorf("%s is excused from the declaration and this collector cannot emit it — an entry about nothing reads as coverage", key)
		}
		if !strings.Contains(reason, "no committed variant") {
			t.Errorf("%s: an excuse must say why the fact cannot be reached, not merely that it is not", key)
		}
	}
}

// The list above is the thing under test in every other case here, so it is
// proven against the binary rather than trusted: every fact the healthy
// staging actually puts on the wire must be in it. That closes the direction a
// hand-written list fails in — a fact the derivation writes and nobody
// remembered to list would be excused by both tests at once.
func TestTheEmittableListCoversWhatTheBinaryActuallyEmits(t *testing.T) {
	known := map[string]bool{}
	for collection, facts := range emittable {
		for _, fact := range facts {
			known[collection+"/"+fact] = true
		}
	}
	seen := map[string]bool{}
	for _, record := range ofKind(replayHealthy(t), "object") {
		collection, _ := record["collection"].(string)
		for fact := range record["facts"].(map[string]any) {
			key := collection + "/" + fact
			seen[key] = true
			if !known[key] {
				t.Errorf("%s reached the wire and is in neither the declaration nor the emittable list", key)
			}
		}
	}
	// Non-vacuity: a staging that reached nothing would pass the loop above in
	// silence, which is the shape this repository refuses.
	if len(seen) < 25 {
		t.Fatalf("the healthy staging reached only %d facts; it exists to exercise the derivation, not to be green", len(seen))
	}
}

// Law 4: a derived fact names the facts it consumed, because a derivation with
// no stated inputs cannot be re-checked. The schema requires the member; this
// requires the members it names to be real facts — of this collection, or of
// another collection of this collector, which is how a job's class says it came
// from the target's.
func TestEveryDerivedFactNamesInputsThatExist(t *testing.T) {
	declaration := decodeDeclaration(t)
	for name, collection := range declaration {
		for fact, spec := range collection.Facts {
			if spec.Kind != "derived" {
				if len(spec.DerivedFrom) != 0 {
					t.Errorf("%s/%s is %q and names derived_from — inputs on a reading are a derivation nobody performs", name, fact, spec.Kind)
				}
				continue
			}
			if len(spec.DerivedFrom) == 0 {
				t.Errorf("%s/%s is derived from nothing stated", name, fact)
			}
			for _, input := range spec.DerivedFrom {
				source, member, crossed := strings.Cut(input, "/")
				if !crossed {
					source, member = name, input
				}
				if _, ok := declaration[source]; !ok {
					t.Errorf("%s/%s names input %q, and %q is not a collection of this collector", name, fact, input, source)
					continue
				}
				if _, ok := declaration[source].Facts[member]; !ok {
					t.Errorf("%s/%s names input %q, which is not a declared fact", name, fact, input)
				}
			}
		}
	}
}

// The row is what an operator ranks by, so `answer` may only name facts this
// collection carries — and each collection's answer must reach the question it
// declares. The three questions are the adapter's own, one per collection, and
// a collection whose answer omits the fact its question turns on is a row an
// operator cannot act on.
func TestEachCollectionsAnswerNamesItsOwnFactsAndReachesItsQuestion(t *testing.T) {
	declaration := decodeDeclaration(t)
	required := map[string][]string{
		// is each promise built, and has anything been restored from it
		"targets": {"Class", "UnimplementedHops", "UnprovenRungs", "FailedProofRungs"},
		// did it run, and when did it last SUCCEED
		"jobs": {"State", "LastResult", "LastSuccessAt", "CheckedAgeSeconds"},
		// who may delete, and what protects history
		"destinations": {"Independent", "PruneAuthority", "Immutability"},
	}
	for name, collection := range declaration {
		if collection.Question == "" || !strings.HasSuffix(collection.Question, "?") {
			t.Errorf("%s states its question as %q — a collection answers a question somebody would ask", name, collection.Question)
		}
		answered := map[string]bool{}
		for _, fact := range collection.Answer {
			if _, ok := collection.Facts[fact]; !ok {
				t.Errorf("%s: answer names %q, which is not a declared fact", name, fact)
			}
			answered[fact] = true
		}
		for _, fact := range required[name] {
			if !answered[fact] {
				t.Errorf("%s: the row omits %q, which its own question turns on", name, fact)
			}
		}
	}
}

// The ids this collector's rows key under, held to the reference's own
// prefixes: a port that published `protection-target:` would mint a second
// object for every target the shipping adapter already publishes.
func TestTheObjectPrefixesAreTheOnesTheReferencePublishes(t *testing.T) {
	declaration := decodeDeclaration(t)
	for collection, prefix := range map[string]string{
		"targets": "target", "jobs": "job", "destinations": "destination",
	} {
		if got := declaration[collection].Prefix; got != prefix {
			t.Errorf("%s publishes under %q, and the reference's id is %s:<name>", collection, got, prefix)
		}
	}
}

// What a value tells a reader (DESIGN 21), held to harness/scrub/protection.json
// — the manifest that classifies the same leaves for a capture. A name an
// operator chose for what is worth protecting is `content` there and must be
// `content` here; a closed vocabulary the estate's own tooling writes is
// `nothing` in both. The two files are the only places this subsystem's
// disclosure is stated, and a disagreement between them is a scrub that
// protects something the declaration says is public, or the reverse.
func TestDisclosureAgreesWithTheScrubManifest(t *testing.T) {
	declaration := decodeDeclaration(t)
	expected := map[string]string{
		// Operator-chosen words for what is protected and where it lands.
		"targets/Source": "content", "targets/Destinations": "content",
		"targets/IndependentDestinations": "content", "targets/ImplementedHops": "content",
		"targets/HopImplementedBy": "content", "targets/UnimplementedHops": "content",
		"targets/ProvenRungs": "content", "targets/UnprovenRungs": "content",
		"targets/LastProvenAt": "content", "targets/FailedProofRungs": "content",
		"targets/ProofScope": "content", "targets/ProofComparedAgainst": "content",
		"targets/ProofRecord": "content",
		"jobs/Job":            "content", "jobs/Unit": "content", "jobs/Target": "content",
		"jobs/ImplementsHops": "content", "jobs/ReceiptsUnobservable": "content",
		"destinations/Immutability": "content", "destinations/PruneAuthority": "content",
		// A machine, located.
		"targets/OwnerHost": "location",
		// Closed vocabularies, durations and dates: the same on every estate
		// that has one, and substituting any of them would destroy the
		// distinction every rule in this subsystem turns on.
		"targets/Class": "nothing", "targets/Kind": "nothing",
		"targets/Retention": "nothing", "targets/Cadence": "nothing",
		"targets/LastFailedProofAt": "nothing",
		"jobs/State":                "nothing", "jobs/Basis": "nothing",
		"jobs/AgeSeconds": "nothing", "jobs/MaxAgeSeconds": "nothing",
		"jobs/CheckedAt": "nothing", "jobs/CheckedAgeSeconds": "nothing",
		"jobs/LastResult": "nothing", "jobs/LastFinishedAt": "nothing",
		"jobs/LastSuccessAt": "nothing", "jobs/ExitStatus": "nothing",
		"jobs/TargetClass": "nothing", "jobs/TargetNotScoped": "nothing",
		"destinations/Kind": "nothing", "destinations/Independent": "nothing",
	}
	declared := 0
	for name, collection := range declaration {
		for fact, spec := range collection.Facts {
			declared++
			want, stated := expected[name+"/"+fact]
			if !stated {
				t.Errorf("%s/%s is declared and this check does not say what it discloses", name, fact)
				continue
			}
			if spec.Discloses != want {
				t.Errorf("%s/%s discloses %q; the scrub manifest classifies the leaf it comes from as %q", name, fact, spec.Discloses, want)
			}
		}
	}
	if declared != len(expected) {
		t.Fatalf("%d facts declared and %d classified here — the table must be exhaustive or it is checking a subset", declared, len(expected))
	}
	// Nothing here is `secret`, and that is the subsystem's design rather than
	// an omission: no repository is opened, so no credential is ever in hand.
	for name, collection := range declaration {
		if len(collection.Redactions) != 0 || collection.Exemption == "" {
			t.Errorf("%s: an exemption beside a redaction list is two rulings contradicting each other in one document", name)
		}
		// The exemption is a statement about CREDENTIALS and must not be read
		// as one about publishability — the estate's names are content and a
		// real capture is refused on judgement.
		if !strings.Contains(collection.Exemption, "credential") {
			t.Errorf("%s: the exemption must say what it is exempting — a source with no credential surface", name)
		}
	}
}

// A reference command is what lets a reader check the reading by hand, so
// every file this collector opens by name must be reachable from one — and the
// two receipts in particular, because the pair IS the distinction between a run
// that failed and a job that has never run.
func TestEveryDocumentTheDerivationOpensIsNamedByAReferenceCommand(t *testing.T) {
	declaration := decodeDeclaration(t)
	joined := map[string]string{}
	for name, collection := range declaration {
		text := ""
		for _, command := range collection.Commands {
			if command.Purpose == "" {
				t.Errorf("%s: reference command %v states no purpose", name, command.Argv)
			}
			text += " " + strings.Join(command.Argv, " ")
		}
		joined[name] = text
	}
	for name, wanted := range map[string][]string{
		"targets":      {manifestPath},
		"destinations": {manifestPath},
		"jobs":         {statusPath, receiptsDir, ".last.json", ".last-success.json"},
	} {
		for _, path := range wanted {
			if !strings.Contains(joined[name], path) {
				t.Errorf("%s: no reference command names %s, which the derivation reads", name, path)
			}
		}
	}
}

// The authority is the paths this binary actually opens, and nothing wider: a
// declaration asking for more than it reads is a sandbox granted on a promise
// nobody checked. No credential and no command, and both absences are the
// point — the repositories are never reached, so the delete-capable identity is
// never held.
func TestTheAuthorityNamesTheThreeSurfacesAndAsksForNoCredential(t *testing.T) {
	var declaration struct {
		Authority struct {
			ReadPaths    []string `json:"read_paths"`
			Commands     []string `json:"commands"`
			Credentials  []string `json:"credentials"`
			Groups       []string `json:"groups"`
			Capabilities []string `json:"capabilities"`
		} `json:"authority"`
		Probe string `json:"probe"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if len(declaration.Authority.Commands) != 0 || len(declaration.Authority.Credentials) != 0 ||
		len(declaration.Authority.Groups) != 0 || len(declaration.Authority.Capabilities) != 0 {
		t.Errorf("this collector opens files and holds nothing: %+v", declaration.Authority)
	}
	granted := map[string]bool{}
	for _, path := range declaration.Authority.ReadPaths {
		granted[path] = true
	}
	for _, path := range []string{manifestPath, statusPath, receiptsDir} {
		if !granted[path] {
			t.Errorf("the authority does not ask for %s, which the derivation reads", path)
		}
	}
	sorted := append([]string(nil), declaration.Authority.ReadPaths...)
	sort.Strings(sorted)
	for _, path := range sorted {
		if !strings.HasPrefix(path, "/proc/") && path != manifestPath && path != statusPath && path != receiptsDir {
			t.Errorf("the authority asks for %s, which this collector never opens", path)
		}
	}
	if !strings.Contains(declaration.Probe, manifestPath) {
		t.Error("the probe prose must name the file the capability question is asked of")
	}
	// The probe's own answer, taken through the binary rather than described:
	// a machine with no /etc/homelab is a NO with a reason somebody can act on.
	code, stdout, _ := runWith(t, "probe\n", nil)
	if code != exitOK {
		t.Fatalf("probe exited %d; a probe reports its verdict in the document", code)
	}
	var verdict probeVerdict
	if err := json.Unmarshal([]byte(stdout), &verdict); err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "no" || verdict.Reason != declineNoManifest.detail {
		t.Errorf("probe on a host with no manifest said %+v", verdict)
	}
	// And YES against a staged capture, so the negative above is a reading
	// rather than a collector that can never say yes.
	_, staged, _ := runWith(t, "probe\n", replayEnv(stageHealthy(t)))
	if err := json.Unmarshal([]byte(staged), &verdict); err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "yes" || verdict.Reason == "" {
		t.Errorf("probe against a staged manifest said %+v", verdict)
	}
}
