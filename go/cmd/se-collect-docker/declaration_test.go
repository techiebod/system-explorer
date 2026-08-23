package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
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
	Names     map[string]any `json:"names"`
	Relations []struct {
		Type string `json:"type"`
	} `json:"relations"`
	Redactions []any  `json:"redactions"`
	Exemption  string `json:"redaction_exemption"`
}

func decodeDeclaration(t *testing.T) (string, map[string]declaredCollection, []string) {
	t.Helper()
	var declaration struct {
		Schema    string `json:"schema"`
		Collector string `json:"collector"`
		Authority struct {
			ReadPaths []string `json:"read_paths"`
			Groups    []string `json:"groups"`
		} `json:"authority"`
		Collections []declaredCollection `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "docker" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	byName := map[string]declaredCollection{}
	for _, collection := range declaration.Collections {
		byName[collection.Name] = collection
	}
	return declaration.Collector, byName, declaration.Authority.ReadPaths
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
	_, collections, _ := decodeDeclaration(t)
	emitted := map[string][]string{
		"containers": {"State", "Status", "Image", "Created", "ComposeProject",
			"NetworkMode", "ContainerID", "ScopeUnit", "Ports"},
		"volumes":  {"Driver", "Mountpoint", "ComposeProject"},
		"networks": {"Driver", "Scope", "Internal", "BridgeInterface", "ComposeProject"},
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

// State is the one closed vocabulary here, and the members are docker's rather
// than this port's. A shorter list would publish a value outside its own
// declaration the first time a container was paused, and a renderer switching
// on it would meet a state it cannot name.
func TestTheStateEnumIsDockersOwnSevenAndNotASubset(t *testing.T) {
	_, collections, _ := decodeDeclaration(t)
	declared := map[string]bool{}
	for _, value := range collections["containers"].Facts["State"].Values {
		declared[value] = true
	}
	for _, state := range []string{"created", "running", "paused", "restarting",
		"removing", "exited", "dead"} {
		if !declared[state] {
			t.Errorf("the State enum omits %q, which dockerd can put on a row", state)
		}
	}
	if len(declared) != 7 {
		t.Errorf("the State enum carries %d values; docker defines seven", len(declared))
	}
	// And the three that keep a scope must all be inside it, or the scope rule
	// is guarding against a state the declaration says cannot happen.
	for _, scoped := range scopedStates {
		if !declared[scoped] {
			t.Errorf("%q keeps a scope cgroup and is not a declared state", scoped)
		}
	}
}

// Absences and presences that are decisions rather than omissions, each pinned
// so nobody adds one without meeting the reason it is not there.
func TestTheDeclarationsShapeIsTheOneTheStreamCarries(t *testing.T) {
	_, collections, readPaths := decodeDeclaration(t)
	for name, collection := range collections {
		// No `names`: the reference's rows publish no name family, so the
		// collator keys a container on its NAME alone. The container id is the
		// identifier that would survive a rename — except that it does not
		// survive a recreation, which the name does, so there is nothing to
		// declare here that would be a better key.
		if len(collection.Names) != 0 {
			t.Errorf("%s declares a names family and the stream carries none", name)
		}
		// The opened-object edges landed with the verb rollout, so the pin
		// inverts: the palettes must now cover exactly what serveObject
		// asserts (the collator REJECTS an undeclared type), and volumes
		// still asserts none. The reference's runs edge travels as
		// member-of — the assertion model asserts outward and carries no
		// direction member — and its inward network attached-to edges are
		// not asserted at all, because each container already asserts them
		// outward and one collector asserting both ends counts one
		// observation twice.
		declared := map[string]bool{}
		for _, relation := range collection.Relations {
			declared[relation.Type] = true
		}
		want := map[string][]string{
			"containers": {"member-of", "mounts", "attached-to"},
			"volumes":    {},
			"networks":   {"plumbed-onto"},
		}[name]
		if len(declared) != len(want) {
			t.Errorf("%s declares %d relation types, the opened object asserts %d",
				name, len(declared), len(want))
		}
		for _, relType := range want {
			if !declared[relType] {
				t.Errorf("%s asserts %s and the declaration does not carry it",
					name, relType)
			}
		}
		// The exemption is the false half everywhere here. A listing document
		// carries no credential member — docker keeps Config.Env in the INSPECT
		// document, which this collector never fetches — but it does carry
		// addresses, MACs and host paths, and "no credential surface" is not the
		// statement those need. What the list can say is what the scrub manifest
		// already performs on the same paths.
		if collection.Exemption != "" {
			t.Errorf("%s claims a reviewed no-credential-surface exemption, which "+
				"says nothing about the addresses and host paths it does carry", name)
		}
		if len(collection.Redactions) == 0 {
			t.Errorf("%s serves a payload whose values are not all publishable verbatim", name)
		}
	}
	for name, want := range map[string]string{
		"containers": "container", "volumes": "volume", "networks": "docker-network",
	} {
		if got := collections[name].Prefix; got != want {
			t.Errorf("%s prefix %q: a target's kind names a declared prefix, and the "+
				"reference publishes these objects as %s:<name>", name, got, want)
		}
	}
	// The socket is the whole of what this process opens, and a sandbox that
	// omits it does not fail loudly — it makes every host's containers absent,
	// which is the one decline that retires them.
	granted := map[string]bool{}
	for _, path := range readPaths {
		granted[path] = true
	}
	if !granted[socketPath] {
		t.Errorf("read_paths omits %s, which this process opens directly", socketPath)
	}
}
