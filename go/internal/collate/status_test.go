// The status route's promises, each shown to discriminate: a fired rule
// reaches the roll-up at its level; judged-clean and unjudged are two
// different states; and a secret fact can never decide an opinion here.
package collate

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
)

func statusOf(t *testing.T, st *store.Store) map[string]any {
	t.Helper()
	rr := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID), "/v1/status")
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var view map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func entryOf(t *testing.T, view map[string]any, name string) map[string]any {
	t.Helper()
	entry, ok := view["collections"].(map[string]any)[name].(map[string]any)
	if !ok {
		t.Fatalf("no %s entry: %+v", name, view)
	}
	return entry
}

// applyPools seeds one pools collection under the declWithRules fixture
// with the given rows, so each test states only what it is about.
func applyPools(t *testing.T, rules string, objects []store.Object) *store.Store {
	t.Helper()
	st := openStore(t)
	document := declWithRules(rules)
	if err := st.RecordDeclaration("sha256:pools", document); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IssueGenerations([]string{"pools"}, "sha256:pools"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyCommit("pools", store.HostNative, 1, "b1", fakeBootID, objects); err != nil {
		t.Fatal(err)
	}
	return st
}

const degradedRule = `[{"key":"pool-degraded","level":"critical",
 "grounds":"interface","when":{"fact":"State","equals":"degraded"},
 "sentence":"ZFS reports this pool degraded.","cites":["State"]}]`

func TestStatusRollsAFiredRuleUpAtItsLevel(t *testing.T) {
	st := applyPools(t, degradedRule, []store.Object{
		{ID: "pools:tank", Name: "tank", Facts: json.RawMessage(`{"State":"degraded"}`), At: 10},
		{ID: "pools:scratch", Name: "scratch", Facts: json.RawMessage(`{"State":"online"}`), At: 10},
	})
	view := statusOf(t, st)
	if view["worst"] != "critical" || view["attention"] != float64(1) {
		t.Fatalf("%+v", view)
	}
	entry := entryOf(t, view, "pools")
	if entry["judged"] != true || entry["worst"] != "critical" ||
		entry["attention"] != float64(1) || entry["total"] != float64(2) {
		t.Fatalf("%+v", entry)
	}
	if counts := entry["counts"].(map[string]any); counts["critical"] != float64(1) {
		t.Fatalf("%+v", counts)
	}
}

func TestJudgedCleanServesAnExplicitNullNeverASilence(t *testing.T) {
	// The control for every test here: rules ran, nothing fired. worst is
	// an explicit null with judged=true — the absent-severity mark
	// (DESIGN 27), not the old vocabulary's "ok" and not an omission.
	st := applyPools(t, degradedRule, []store.Object{
		{ID: "pools:tank", Name: "tank", Facts: json.RawMessage(`{"State":"online"}`), At: 10},
	})
	view := statusOf(t, st)
	entry := entryOf(t, view, "pools")
	if entry["judged"] != true || entry["attention"] != float64(0) {
		t.Fatalf("%+v", entry)
	}
	if worst, present := entry["worst"]; !present || worst != nil {
		t.Fatalf("judged-clean must serve worst: null explicitly, got %+v", entry)
	}
	if view["worst"] != nil || len(view["unjudged"].([]any)) != 0 {
		t.Fatalf("%+v", view)
	}
}

func TestUnjudgedIsItsOwnStateAndNamedAtTheTop(t *testing.T) {
	// No rule table: the identity fixture. Absence of judgement must not
	// render like judged-clean — that would be absence reported as health,
	// through the one route a person polls to know what needs attention.
	view := statusOf(t, seeded(t))
	entry := entryOf(t, view, "identity")
	if entry["judged"] != false {
		t.Fatalf("%+v", entry)
	}
	if _, present := entry["worst"]; present {
		t.Fatalf("an unjudged collection makes no worst claim at all: %+v", entry)
	}
	if entry["unjudged_reason"] == "" || entry["unjudged_reason"] == nil {
		t.Fatalf("%+v", entry)
	}
	unjudged := view["unjudged"].([]any)
	if len(unjudged) != 1 || unjudged[0] != "identity" {
		t.Fatalf("the top level must repeat the unjudged names: %+v", view)
	}
}

func TestDeclaredButNeverAppliedSaysSo(t *testing.T) {
	st := openStore(t)
	// A generation issued and never committed: the store knows the
	// collection, nothing has ever applied.
	if _, err := st.IssueGenerations([]string{"pools"}, "sha256:pools"); err != nil {
		t.Fatal(err)
	}
	view := statusOf(t, st)
	entry := entryOf(t, view, "pools")
	if entry["judged"] != false || entry["generation"] != float64(0) {
		t.Fatalf("%+v", entry)
	}
}

func TestASecretFactCannotDecideAnOpinionHere(t *testing.T) {
	// A rule over a fact declared `discloses: secret` must not fire: the
	// fact is deleted before judgement exactly as on the host page, because
	// an opinion's sentence travels to every consumer of this route.
	document := `{"schema":"se.declaration/1","collector":"vault","version":"1.0.0",
	 "collections":[{"name":"tokens","question":"q","prefix":"token","freshness":"60s",
	 "perishability":"perishable","answer":["Held"],
	 "facts":{"Held":{"type":"string","temperament":"state","kind":"observed","discloses":"secret","sentence":"."}},
	 "rules":[{"key":"held-set","level":"warn","grounds":"threshold",
	  "when":{"fact":"Held","present":true},
	  "sentence":"a token is held","cites":["Held"]}]}]}`
	st := openStore(t)
	if err := st.RecordDeclaration("sha256:vault", document); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IssueGenerations([]string{"tokens"}, "sha256:vault"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyCommit("tokens", store.HostNative, 1, "b1", fakeBootID,
		[]store.Object{{ID: "tokens:t1", Name: "t1",
			Facts: json.RawMessage(`{"Held":"hunter2"}`), At: 10}}); err != nil {
		t.Fatal(err)
	}
	view := statusOf(t, st)
	entry := entryOf(t, view, "tokens")
	if entry["judged"] != true || entry["attention"] != float64(0) {
		t.Fatalf("a rule over a secret fact fired: %+v", entry)
	}
}

func TestWorstIsTheWorstAcrossCollectionsAndObjectsCountOnce(t *testing.T) {
	rules := `[{"key":"pool-degraded","level":"warn",
	 "grounds":"interface","when":{"fact":"State","equals":"degraded"},
	 "sentence":"degraded","cites":["State"]},
	 {"key":"pool-full","level":"critical","grounds":"threshold",
	 "when":{"fact":"CapacityPercent","at_least":90},
	 "sentence":"nearly full","cites":["CapacityPercent"]}]`
	st := applyPools(t, rules, []store.Object{
		// Fires BOTH rules: must count once, at critical.
		{ID: "pools:tank", Name: "tank",
			Facts: json.RawMessage(`{"State":"degraded","CapacityPercent":95}`), At: 10},
	})
	view := statusOf(t, st)
	entry := entryOf(t, view, "pools")
	if entry["attention"] != float64(1) || entry["worst"] != "critical" {
		t.Fatalf("an object fires two rules and counts once, at its worst: %+v", entry)
	}
	counts := entry["counts"].(map[string]any)
	if counts["critical"] != float64(1) || counts["warn"] != nil {
		t.Fatalf("%+v", counts)
	}
}
