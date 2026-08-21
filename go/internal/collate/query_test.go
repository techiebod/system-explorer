// Fact filters and pagination on the objects route (register rows 11 and
// 12): the near-miss refusal, the open-vocabulary empty page, the value
// operators, and the declared ceiling governing what a read may serve.
// Each carried semantic here was argued once in the shipping agent
// (envelope.apply_fact_filters, three review passes) — the tests pin the
// port, not the argument.
package collate

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// unitsFixture applies three unit rows with types, under a declaration
// with a records ceiling of 2 — small enough that the ceiling, not the
// default, governs the page.
func unitsFixture(t *testing.T, ceiling string) *store.Store {
	t.Helper()
	st := openStore(t)
	document := `{"schema":"se.declaration/1","collector":"units","version":"1.0.0",
	 "collections":[{"name":"units","question":"q","prefix":"unit","freshness":"60s",
	 "perishability":"perishable","answer":["ActiveState"],` + ceiling + `
	 "facts":{"ActiveState":{"type":"string","temperament":"state","kind":"observed","discloses":"nothing","sentence":"."},
	          "Description":{"type":"string","temperament":"state","kind":"observed","discloses":"nothing","sentence":"."}}}]}`
	if err := st.RecordDeclaration("sha256:units", document); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IssueGenerations([]string{"units"}, "sha256:units"); err != nil {
		t.Fatal(err)
	}
	objects := []store.Object{
		{ID: "units:a.service", Name: "a.service", Type: "service",
			Facts: json.RawMessage(`{"ActiveState":"active","Description":"first"}`), At: 10},
		{ID: "units:b.service", Name: "b.service", Type: "service",
			Facts: json.RawMessage(`{"ActiveState":"failed","Description":"second"}`), At: 10},
		{ID: "units:c.slice", Name: "c.slice", Type: "slice",
			Facts: json.RawMessage(`{"ActiveState":"active"}`), At: 10},
	}
	if _, err := st.ApplyCommit("units", store.HostNative, 1, "b1", fakeBootID, objects); err != nil {
		t.Fatal(err)
	}
	return st
}

func pageOf(t *testing.T, st *store.Store, path string) (map[string]any, *string) {
	t.Helper()
	rr := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID), path)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
	}
	var page map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	var next *string
	if page["next_cursor"] != nil {
		text := page["next_cursor"].(string)
		next = &text
	}
	return page, next
}

func ids(page map[string]any) []string {
	out := []string{}
	for _, row := range page["objects"].([]any) {
		out = append(out, row.(map[string]any)["id"].(string))
	}
	return out
}

func TestAFactFilterKeepsMatchingRowsAndTotalCountsThem(t *testing.T) {
	st := unitsFixture(t, "")
	page, _ := pageOf(t, st, "/v1/collections/units/objects?ActiveState=active")
	if page["total"] != float64(2) || len(ids(page)) != 2 {
		t.Fatalf("%+v", page)
	}
	page, _ = pageOf(t, st, "/v1/collections/units/objects?type=slice")
	if got := ids(page); len(got) != 1 || got[0] != "units:c.slice" {
		t.Fatalf("%+v", page)
	}
	// Filters compose: every key must match.
	page, _ = pageOf(t, st, "/v1/collections/units/objects?ActiveState=active&type=service")
	if got := ids(page); len(got) != 1 || got[0] != "units:a.service" {
		t.Fatalf("%+v", page)
	}
}

func TestANearMissFilterKeyIsRefusedWithTheRealName(t *testing.T) {
	// ?activestate=failed and ?ActiveState=failed used to be byte-identical
	// empty-ok envelopes in the shipping agent before its 422 — a mistyped
	// question indistinguishable from a healthy empty answer. The refusal
	// names the twin, and it survives a misplaced operator on the key.
	st := unitsFixture(t, "")
	for _, path := range []string{
		"/v1/collections/units/objects?activestate=failed",
		"/v1/collections/units/objects?active_state=failed",
		"/v1/collections/units/objects?ACTIVESTATE=failed",
		"/v1/collections/units/objects?!activestate=failed",
	} {
		rr := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID), path)
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"ActiveState"`) {
			t.Fatalf("the refusal must name the carried twin: %s", rr.Body.String())
		}
	}
}

func TestATypoWithNoNearMissGetsTheEmptyPageNotAnError(t *testing.T) {
	// The vocabulary is open: "no row carries this key right now" is a
	// statement about the moment. Refusing it would flip one correct query
	// between ok and error as host state drifts.
	st := unitsFixture(t, "")
	page, _ := pageOf(t, st, "/v1/collections/units/objects?NoSuchFact=x")
	if page["total"] != float64(0) || len(ids(page)) != 0 {
		t.Fatalf("%+v", page)
	}
}

func TestValueOperatorsNegatePrefixAndCompose(t *testing.T) {
	st := unitsFixture(t, "")
	page, _ := pageOf(t, st, "/v1/collections/units/objects?ActiveState=!failed")
	if page["total"] != float64(2) {
		t.Fatalf("negation: %+v", page)
	}
	page, _ = pageOf(t, st, "/v1/collections/units/objects?Description=fir*")
	if got := ids(page); len(got) != 1 || got[0] != "units:a.service" {
		t.Fatalf("prefix: %+v", page)
	}
	page, _ = pageOf(t, st, "/v1/collections/units/objects?Description=!fir*")
	if got := ids(page); len(got) != 2 {
		t.Fatalf("composed: %+v", page)
	}
	// An absent fact matches only negated filters: c.slice carries no
	// Description — absence equals nothing, but is honestly not-equal to
	// everything.
	page, _ = pageOf(t, st, "/v1/collections/units/objects?Description=!second")
	got := ids(page)
	if len(got) != 2 || got[0] != "units:a.service" || got[1] != "units:c.slice" {
		t.Fatalf("absent-under-negation: %+v", page)
	}
}

func TestABadLimitIsRefusedAsAMalformedQuestion(t *testing.T) {
	st := unitsFixture(t, "")
	h := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)
	for path, want := range map[string]string{
		"/v1/collections/units/objects?limit=abc": "integer",
		"/v1/collections/units/objects?limit=0":   ">= 1",
		"/v1/collections/units/objects?limit=-5":  ">= 1",
	} {
		rr := get(t, h, path)
		if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
	}
}

func TestTheDeclaredCeilingGovernsTheReadAndTheCursorWalksIt(t *testing.T) {
	// records ceiling 2 over three rows: an unlimited request serves two,
	// says so, and hands over an explicit cursor; a requested limit above
	// the ceiling is clamped to it — a read must not serve more than the
	// collection is allowed to hold (DESIGN 19).
	st := unitsFixture(t, `"ceiling":{"records":2},`)
	page, next := pageOf(t, st, "/v1/collections/units/objects")
	if page["applied_limit"] != float64(2) || page["total"] != float64(3) {
		t.Fatalf("%+v", page)
	}
	if got := ids(page); len(got) != 2 || got[0] != "units:a.service" {
		t.Fatalf("first page, applied order: %+v", got)
	}
	if next == nil {
		t.Fatal("a truncated page must say so with a cursor")
	}
	page, next = pageOf(t, st, "/v1/collections/units/objects?limit=999&cursor="+*next)
	if page["applied_limit"] != float64(2) {
		t.Fatalf("a requested limit above the ceiling must clamp: %+v", page)
	}
	if got := ids(page); len(got) != 1 || got[0] != "units:c.slice" {
		t.Fatalf("second page: %+v", got)
	}
	if next != nil {
		t.Fatalf("the final page must serve next_cursor null, got %v", *next)
	}
}

func TestPaginationSlicesTheFilteredSetInAppliedOrder(t *testing.T) {
	st := unitsFixture(t, "")
	page, next := pageOf(t, st, "/v1/collections/units/objects?ActiveState=active&limit=1")
	if page["total"] != float64(2) || len(ids(page)) != 1 || ids(page)[0] != "units:a.service" {
		t.Fatalf("%+v", page)
	}
	if next == nil {
		t.Fatal("one of two filtered rows served; the cursor must exist")
	}
	page, _ = pageOf(t, st, "/v1/collections/units/objects?ActiveState=active&limit=1&cursor="+*next)
	if got := ids(page); len(got) != 1 || got[0] != "units:c.slice" {
		t.Fatalf("%+v", page)
	}
}

func TestASecretFactIsNeitherFilterableNorATwin(t *testing.T) {
	// The value never prints on this route, so the filter must not become
	// an oracle for it: any value — right or wrong — matches nothing, and
	// the near-miss rule never names it because carried is computed from
	// the rows as served.
	document := `{"schema":"se.declaration/1","collector":"vault","version":"1.0.0",
	 "collections":[{"name":"tokens","question":"q","prefix":"token","freshness":"60s",
	 "perishability":"perishable","answer":["Label"],
	 "facts":{"Label":{"type":"string","temperament":"state","kind":"observed","discloses":"nothing","sentence":"."},
	          "Held":{"type":"string","temperament":"state","kind":"observed","discloses":"secret","sentence":"."}}}]}`
	st := openStore(t)
	if err := st.RecordDeclaration("sha256:vault", document); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IssueGenerations([]string{"tokens"}, "sha256:vault"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyCommit("tokens", store.HostNative, 1, "b1", fakeBootID,
		[]store.Object{{ID: "tokens:t1", Name: "t1",
			Facts: json.RawMessage(`{"Label":"ci","Held":"hunter2"}`), At: 10}}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)
	right := get(t, h, "/v1/collections/tokens/objects?Held=hunter2")
	wrong := get(t, h, "/v1/collections/tokens/objects?Held=nope")
	if right.Code != http.StatusOK || wrong.Code != http.StatusOK {
		t.Fatalf("%d %d", right.Code, wrong.Code)
	}
	if right.Body.String() != wrong.Body.String() {
		t.Fatal("the right and wrong guess must be indistinguishable, or the " +
			"filter is a value oracle for a fact this route refuses to print")
	}
	var page map[string]any
	if err := json.Unmarshal(right.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page["total"] != float64(0) {
		t.Fatalf("a filter over a withheld fact matches nothing: %+v", page)
	}
	// And the near-miss path stays silent about it too.
	miss := get(t, h, "/v1/collections/tokens/objects?held=x")
	if miss.Code != http.StatusOK {
		t.Fatalf("a withheld fact must not be confirmed as a twin: %d %s",
			miss.Code, miss.Body.String())
	}
}
