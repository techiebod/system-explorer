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
	Type        string   `json:"type"`
	Values      []string `json:"values"`
	Temperament string   `json:"temperament"`
	Kind        string   `json:"kind"`
	Discloses   string   `json:"discloses"`
	Sentence    string   `json:"sentence"`
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
	Rules     []struct {
		Key     string `json:"key"`
		Level   string `json:"level"`
		Grounds string `json:"grounds"`
	} `json:"rules"`
	Verbs map[string]struct {
		Bytes int `json:"bytes"`
		Ms    int `json:"ms"`
	} `json:"verbs"`
	Commands []struct {
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
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "units" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	if len(declaration.Collections) != 1 {
		t.Fatalf("one collection, units; got %d", len(declaration.Collections))
	}
	return declaration.Collections[0]
}

// The declared set and the set this code can emit are ONE set, in both
// directions: a fact declared and never emitted is a promise nothing tests, and
// one emitted and never declared has no sentence, no type and no disclosure
// class. The emittable side is derived from the source's own tables where there
// is one, so a directive added to the walk without a declaration fails here.
func TestTheDeclaredFactsAreExactlyTheEmittableOnes(t *testing.T) {
	collection := decodeDeclaration(t)
	emittable := map[string]bool{
		"LoadState": true, "ActiveState": true, "SubState": true,
		"Description": true, "RuntimeSynthesised": true, "ContainerID": true,
		"MachineName": true, "Slice": true, "ReferencedBy": true,
		"MissingReferenceUnobservable": true,
	}
	// The object verb's density (R3c): one unit's properties, served where
	// they are already in hand — the row deliberately cannot afford them.
	for _, fact := range [...]string{"LoadError", "UnitFileState",
		"FragmentPath", "ActiveEnterTimestamp", "MainPID", "NRestarts",
		"Result", "TasksCurrent", "ExecMainStartTimestamp", "NextElapse",
		"LastTrigger"} {
		emittable[fact] = true
	}
	for _, fact := range absentReferenceFacts {
		emittable[fact] = true
	}
	for name := range emittable {
		if _, declared := collection.Facts[name]; !declared {
			t.Errorf("%s is emitted and not declared", name)
		}
	}
	for name := range collection.Facts {
		if !emittable[name] {
			t.Errorf("%s is declared and this collector cannot emit it", name)
		}
	}
}

// The pinned members, asserted from the wire side: the schema-validation half
// (se.declaration.1.json is closed) runs in the Python harness, which owns the
// contract registry.
func TestTheDeclarationCarriesThePinnedContract(t *testing.T) {
	collection := decodeDeclaration(t)
	if collection.Name != collectionUnits || collection.Freshness != "60s" {
		t.Fatalf("collection %q at freshness %q", collection.Name, collection.Freshness)
	}
	// The prefix and the row's name are what the collator mints the id from,
	// and `unit:<name>` is the id the shipping adapter mints — so a port that
	// moved either would publish a second object for one unit.
	if collection.Prefix != "unit" {
		t.Fatalf("prefix %q: the id is <prefix>:<name>, and the adapter's is unit:<name>", collection.Prefix)
	}

	// Temperament decides whether a fact churns the snapshot diff (DESIGN 12),
	// which is why it is pinned rather than left to reading. No ROW fact is a
	// counter or a gauge: the two measurements below (NRestarts, TasksCurrent)
	// ride the object verb only, which is not snapshot material — so the
	// boundary that keeps /v1/changes from reporting every cgroup-bearing unit
	// as changed on every poll still holds, one layer down from where it did.
	temperament := map[string]string{
		"LoadState": "state", "ActiveState": "state", "SubState": "state",
		"Description": "configuration", "RuntimeSynthesised": "configuration",
		"ContainerID": "existence", "MachineName": "existence",
		"Slice": "configuration", "MissingRequirements": "configuration",
		"MissingWants": "configuration", "MissingOrdering": "configuration",
		"ReferencedBy": "configuration", "MissingReferenceUnobservable": "state",
		// The object verb's density (R3c): one unit, properties in hand.
		"LoadError": "state", "UnitFileState": "configuration",
		"FragmentPath": "configuration", "ActiveEnterTimestamp": "state",
		"MainPID": "state", "NRestarts": "counter", "Result": "state",
		"TasksCurrent": "gauge", "ExecMainStartTimestamp": "state",
		"NextElapse": "state", "LastTrigger": "state",
	}
	if len(collection.Facts) != len(temperament) {
		t.Fatalf("declared facts %v", collection.Facts)
	}
	for fact, want := range temperament {
		declared, ok := collection.Facts[fact]
		if !ok {
			t.Errorf("fact %s is not declared", fact)
			continue
		}
		if declared.Temperament != want {
			t.Errorf("%s is declared %q, pinned %q", fact, declared.Temperament, want)
		}
		if declared.Sentence == "" {
			t.Errorf("%s has no sentence, and a sentence is what a consumer renders", fact)
		}
	}

	// The four facts that carry words somebody chose — a unit's description, a
	// slice's name, a domain name, and the referrer lists that are made of unit
	// names — are `content` and the rest disclose nothing. Pinned because the
	// class is what a policy acts on (DESIGN 21) and it is one word per fact in
	// a file being written anyway, which is exactly how a forgotten one gets
	// published.
	content := map[string]bool{
		"Description": true, "MachineName": true, "Slice": true,
		"MissingRequirements": true, "MissingWants": true,
		"MissingOrdering": true, "ReferencedBy": true,
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

	// R2's exemption said "serves no evidence verb", and R3c made that false:
	// the evidence document is the service's full property set, so the three
	// members that carry a process environment are withheld — an Environment=
	// line is where a credential lives. Pinned path-by-path because a
	// forgotten redaction publishes, and an exemption beside a redaction list
	// would be two rulings contradicting each other in one document.
	if collection.Exemption != "" {
		t.Fatalf("exemption %q beside a redaction list", collection.Exemption)
	}
	withheld := map[string]bool{}
	for _, redaction := range collection.Redactions {
		if redaction.Discloses != "secret" {
			t.Errorf("%s is withheld as %q; an environment member is withheld because it is a secret",
				redaction.Path, redaction.Discloses)
		}
		withheld[redaction.Path] = true
	}
	for _, member := range []string{"Environment", "UnsetEnvironment", "PassEnvironment"} {
		if !withheld["/org.freedesktop.systemd1.Service/data/0/"+member] {
			t.Errorf("the %s member is not withheld from evidence", member)
		}
	}
	if len(collection.Redactions) != 3 {
		t.Errorf("%d redactions declared; a fourth means the ruling moved and this pin must move with it",
			len(collection.Redactions))
	}
}

// LoadState and ActiveState are the two closed sets, and a value outside a
// declared enum fails contract verification — so the members are pinned here
// against what this collector actually reads off the wire, not against a
// vocabulary somebody remembered.
func TestTheTwoEnumsCarryTheStatesSystemdReports(t *testing.T) {
	facts := decodeDeclaration(t).Facts
	for name, required := range map[string][]string{
		"LoadState":   {"loaded", "not-found", "masked", "error"},
		"ActiveState": {"active", "inactive", "failed", "activating", "deactivating"},
	} {
		declared := map[string]bool{}
		for _, value := range facts[name].Values {
			declared[value] = true
		}
		if facts[name].Type != "enum" {
			t.Errorf("%s is declared %q; a closed set is an enum or a renderer has to guess", name, facts[name].Type)
		}
		for _, value := range required {
			if !declared[value] {
				t.Errorf("%s does not declare %q, which systemd reports", name, value)
			}
		}
	}
	// SubState is deliberately NOT an enum: its vocabulary is decided by the
	// unit's TYPE — mounted, plugged, exited, listening, waiting — so a closed
	// set here would refuse a legal reading the first time a unit type nobody
	// had met turned up.
	if facts["SubState"].Type != "string" || facts["SubState"].Values != nil {
		t.Error("SubState's vocabulary belongs to the unit type, not to systemd as a whole")
	}
}

// The declared reference commands must be the ones this collector actually
// makes, or an operator checking a surprising claim runs something else and
// gets a different answer. busctl is named because it IS the native document
// (DESIGN's 2026-08-19 ruling) — the bytes an operator gets by hand are the
// bytes this binary parses.
func TestTheReferenceCommandsAreTheCallsThisCollectorMakes(t *testing.T) {
	collection := decodeDeclaration(t)
	found := map[string]bool{}
	for _, command := range collection.Commands {
		if command.Purpose == "" {
			t.Errorf("reference command %v states no purpose", command.Argv)
		}
		for _, token := range command.Argv {
			switch token {
			case "ListUnits", "ListUnitFiles", "GetAll", "Get":
				found[token] = true
			}
		}
	}
	for _, member := range []string{"ListUnits", "ListUnitFiles", "GetAll", "Get"} {
		if !found[member] {
			t.Errorf("no reference command names %s, which the acquisition path calls", member)
		}
	}
	// Every busctl command must ask for the JSON rendering, because that IS
	// the document: a reference command that printed busctl's default output
	// would hand an operator a shape no `from` path addresses.
	for _, command := range collection.Commands {
		if command.Argv[0] != busctl {
			continue
		}
		if !strings.Contains(strings.Join(command.Argv, " "), "--json=short") {
			t.Errorf("reference command %v does not ask for the native rendering", command.Argv)
		}
	}
}

// The bounds the verbs enforce are the bounds the declaration promises: a
// bound only in the declaration is a promise, one only in verbs.go is
// undeclared authority. verbs.go names this test beside its const block.
func TestTheVerbBoundsAreTheDeclaredOnes(t *testing.T) {
	verbs := decodeDeclaration(t).Verbs
	if len(verbs) != 2 {
		t.Fatalf("verbs %v: this collector serves object and evidence", verbs)
	}
	if verbs["object"].Bytes != objectVerbBytes {
		t.Errorf("object declares %d bytes, the verb enforces %d",
			verbs["object"].Bytes, objectVerbBytes)
	}
	if verbs["evidence"].Bytes != evidenceVerbBytes {
		t.Errorf("evidence declares %d bytes, the verb enforces %d",
			verbs["evidence"].Bytes, evidenceVerbBytes)
	}
	for verb, bounds := range verbs {
		if bounds.Ms <= 0 {
			t.Errorf("%s declares no time bound, and an unbounded verb is a hung collator", verb)
		}
	}
}

// The rule table, pinned key by key. unit-health is `interface` — systemd
// itself declares the fault — where restart-churn is `threshold`, our own
// judgement about how much churn is too much; the grounds axis is what tells
// a consumer which kind of claim it is relaying (DESIGN's grounds ruling).
// restart-churn reads NRestarts, which only the object verb carries, so it
// fires where the density is in hand — the old detail-only rule, kept.
func TestTheRuleTableCarriesTheJudgedConditions(t *testing.T) {
	rules := decodeDeclaration(t).Rules
	pinned := map[string][2]string{
		"unit-health":                         {"critical", "interface"},
		"restart-churn":                       {"warn", "threshold"},
		"unit-requires-absent-unit":           {"warn", "interface"},
		"unit-wants-absent-unit":              {"info", "interface"},
		"unit-absent-references-unobservable": {"info", "interface"},
	}
	if len(rules) != len(pinned) {
		t.Fatalf("%d rules declared, %d pinned", len(rules), len(pinned))
	}
	for _, rule := range rules {
		want, ok := pinned[rule.Key]
		if !ok {
			t.Errorf("rule %s is not pinned here", rule.Key)
			continue
		}
		if rule.Level != want[0] || rule.Grounds != want[1] {
			t.Errorf("%s is %s/%s, pinned %s/%s",
				rule.Key, rule.Level, rule.Grounds, want[0], want[1])
		}
	}
}
