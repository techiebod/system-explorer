// The declaration-derived routes (register rows 13 and 14): the prefix
// map that opens ids, and the fact dictionary that explains them — each
// derived from the store's declarations, with the failure modes that
// matter shown to discriminate: an undescribed collection stays visible,
// and a contended prefix resolves to nobody rather than to a coin toss.
package collate

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
)

func declareAndIssue(t *testing.T, st *store.Store, digest, document string, names []string) {
	t.Helper()
	if err := st.RecordDeclaration(digest, document); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IssueGenerations(names, digest); err != nil {
		t.Fatal(err)
	}
}

func viewOf(t *testing.T, st *store.Store, path string) map[string]any {
	t.Helper()
	rr := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID), path)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
	}
	var view map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func TestCapabilitiesServeThePrefixMapWithRoutes(t *testing.T) {
	st := openStore(t)
	declareAndIssue(t, st, "sha256:pools", declWithRules("[]"), []string{"pools"})
	view := viewOf(t, st, "/v1/capabilities")

	entry := view["collections"].(map[string]any)["pools"].(map[string]any)
	if entry["prefix"] != "pool" || entry["question"] != "q" {
		t.Fatalf("%+v", entry)
	}
	home := view["object_prefixes"].(map[string]any)["pool"].(map[string]any)
	if home["collection"] != "pools" || home["route"] != "/v1/collections/pools/objects" {
		t.Fatalf("an id wearing 'pool' must resolve to the route that serves "+
			"it: %+v", home)
	}
}

func TestAnUndescribedCollectionStaysVisibleAndMintsNoPrefix(t *testing.T) {
	// A collection whose declaration the store does not hold exists and a
	// reader must see it — but it must not invent a prefix, because a chip
	// built from an invented mapping dead-ends.
	view := viewOf(t, seeded(t), "/v1/capabilities")
	entry, present := view["collections"].(map[string]any)["identity"]
	if !present {
		t.Fatalf("known collection missing: %+v", view)
	}
	if len(entry.(map[string]any)) != 0 {
		t.Fatalf("no declaration, no described members: %+v", entry)
	}
	if len(view["object_prefixes"].(map[string]any)) != 0 {
		t.Fatalf("%+v", view)
	}
}

func TestAContendedPrefixResolvesToNobodyAndSaysSo(t *testing.T) {
	// Two collections declaring one prefix: serving either home would be a
	// silent coin toss. The wire path refuses such a declaration, but the
	// store can hold the state transiently — so the read route states the
	// contention instead of picking a winner nobody chose.
	document := `{"schema":"se.declaration/1","collector":"x","version":"1.0.0",
	 "collections":[
	  {"name":"aaa","question":"q","prefix":"thing","freshness":"60s",
	   "perishability":"perishable","answer":["F"],
	   "facts":{"F":{"type":"string","temperament":"state","kind":"observed","discloses":"nothing","sentence":"."}}},
	  {"name":"bbb","question":"q","prefix":"thing","freshness":"60s",
	   "perishability":"perishable","answer":["F"],
	   "facts":{"F":{"type":"string","temperament":"state","kind":"observed","discloses":"nothing","sentence":"."}}}]}`
	st := openStore(t)
	declareAndIssue(t, st, "sha256:x", document, []string{"aaa", "bbb"})
	view := viewOf(t, st, "/v1/capabilities")
	if len(view["object_prefixes"].(map[string]any)) != 0 {
		t.Fatalf("a contended prefix must resolve to nobody: %+v", view)
	}
	contended := view["ambiguous_prefixes"].(map[string]any)["thing"].([]any)
	if len(contended) != 2 || contended[0] != "aaa" || contended[1] != "bbb" {
		t.Fatalf("%+v", view)
	}
}

func TestTheFactDictionaryServesTheDeclarationVerbatim(t *testing.T) {
	st := openStore(t)
	declareAndIssue(t, st, "sha256:pools", declWithRules("[]"), []string{"pools"})
	view := viewOf(t, st, "/v1/facts")
	facts := view["collections"].(map[string]any)["pools"].(map[string]any)
	state := facts["State"].(map[string]any)
	if state["type"] != "string" || state["temperament"] != "state" ||
		state["kind"] != "observed" || state["sentence"] != "." {
		t.Fatalf("the axes and sentence travel verbatim: %+v", state)
	}
}

func TestASecretFactsMeaningIsPublicEvenThoughItsValueIsNot(t *testing.T) {
	// The dictionary explains; the objects route withholds. A reader must
	// be able to learn what a withheld fact MEANS — the name and axes are
	// the public contract — while its value never leaves the host.
	document := `{"schema":"se.declaration/1","collector":"vault","version":"1.0.0",
	 "collections":[{"name":"tokens","question":"q","prefix":"token","freshness":"60s",
	 "perishability":"perishable","answer":["Label"],
	 "facts":{"Held":{"type":"string","temperament":"state","kind":"observed","discloses":"secret","sentence":"the credential this service holds"}}}]}`
	st := openStore(t)
	declareAndIssue(t, st, "sha256:vault", document, []string{"tokens"})
	view := viewOf(t, st, "/v1/facts")
	held := view["collections"].(map[string]any)["tokens"].(map[string]any)["Held"].(map[string]any)
	if held["discloses"] != "secret" || held["sentence"] == "" {
		t.Fatalf("%+v", held)
	}
}
