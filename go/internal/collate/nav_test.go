package collate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// The rail: every collection this host has ever been asked for, grouped,
// on every page. There was none — a breadcrumb and a 52-row index you
// had to go back to.

const netDecl = `{"schema":"se.declaration/1","collector":"network","collections":[
  {"name":"tailscale","freshness":"1h","prefix":"ts","answer":[],"facts":{}},
  {"name":"links","freshness":"1h","prefix":"link","answer":[],"facts":{}}]}`

const stoDecl = `{"schema":"se.declaration/1","collector":"storage","collections":[
  {"name":"pools","freshness":"1h","prefix":"pool","answer":[],"facts":{}},
  {"name":"arrays","freshness":"1h","prefix":"array","answer":[],"facts":{}}]}`

func railStore(t *testing.T) (*store.Store, []store.CollectionState) {
	t.Helper()
	st := openStore(t)
	// network's collections are issued together, so both carry the same
	// declaration — which is how the store's join works in production.
	if _, err := st.IssueGenerations([]string{"tailscale", "links"}, "sha256:n"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:n", netDecl); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IssueGenerations([]string{"pools", "arrays"}, "sha256:s"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:s", stoDecl); err != nil {
		t.Fatal(err)
	}
	// links applies; the rest never do.
	if _, err := st.ApplyCommit("links", store.HostNative, 1, "b1", fakeBootID,
		[]store.Object{{ID: "link:lo", Name: "lo", Facts: json.RawMessage(`{}`), At: 10}}); err != nil {
		t.Fatal(err)
	}
	states, err := st.Collections()
	if err != nil {
		t.Fatal(err)
	}
	return st, states
}

func TestTheRailGroupsByTheCollectorEachCollectionWasLearnedUnder(t *testing.T) {
	st, states := railStore(t)
	groups := navGroups(st, states)
	got := map[string][]string{}
	for _, g := range groups {
		got[g.Collector] = g.Collections
	}
	if len(got["network"]) != 2 || len(got["storage"]) != 2 {
		t.Fatalf("%+v", got)
	}
	// Within a group, the PRODUCER's declared order — network lists
	// tailscale before links, which is argued, not alphabetical.
	if got["network"][0] != "tailscale" || got["network"][1] != "links" {
		t.Fatalf("the declaration's own order must be preserved: %v",
			got["network"])
	}
	// Across groups, alphabetical: this file must not decide that
	// storage matters more than network.
	if groups[0].Collector != "network" || groups[1].Collector != "storage" {
		t.Fatalf("%+v", groups)
	}
}

func TestACollectionNothingEverReadStillAppearsInTheRail(t *testing.T) {
	// 18 of 52 on a lab host have never applied. The declaration digest
	// is stamped when the generation is ISSUED, not when a batch
	// applies, so the collector is known for them too — and a nav that
	// dropped them would be absence rendering as non-existence in the
	// navigation itself.
	st, states := railStore(t)
	rail := markup(navRail(st, states, "", freshnessMap(st, states, 26.0, fakeBootID)))
	for _, name := range []string{"tailscale", "pools", "arrays"} {
		if !strings.Contains(rail, ">"+name+"<") {
			t.Fatalf("%s never applied and is missing from the rail: %s",
				name, visible(rail))
		}
	}
	// And it says so, rather than looking like a collection holding zero.
	if !strings.Contains(rail, "never read") {
		t.Fatalf("a never-read entry wears its state: %s", visible(rail))
	}
}

func TestTheRailNeverHidesACollection(t *testing.T) {
	// The old nav hid collections the roll-up called honestly empty, and
	// the same file records what that produced: "a nav that shrank under
	// the pointer".
	st, states := railStore(t)
	rail := markup(navRail(st, states, "", freshnessMap(st, states, 26.0, fakeBootID)))
	for _, cs := range states {
		if !strings.Contains(rail, collectionHref(cs.Name)) {
			t.Fatalf("%s is missing from the rail", cs.Name)
		}
	}
}

func TestTheRailMarksWhereYouAre(t *testing.T) {
	st, states := railStore(t)
	rail := navRail(st, states, "links", freshnessMap(st, states, 26.0, fakeBootID))
	if strings.Count(rail, `aria-current="page"`) != 1 {
		t.Fatalf("exactly one current entry: %s", rail)
	}
	i := strings.Index(rail, `aria-current="page"`)
	if !strings.Contains(rail[max(0, i-200):i+200], "links") {
		t.Fatalf("the current mark is on the wrong entry: %s", rail)
	}
}

func TestACollectionWhoseDeclarationCannotBeReadGetsItsOwnGroup(t *testing.T) {
	// Never dropped, never filed under a guess — the direction the
	// prefix index already takes when a prefix is contested.
	st := openStore(t)
	if _, err := st.IssueGenerations([]string{"mystery"}, "sha256:gone"); err != nil {
		t.Fatal(err)
	}
	states, err := st.Collections()
	if err != nil {
		t.Fatal(err)
	}
	rail := markup(navRail(st, states, "", freshnessMap(st, states, 26.0, fakeBootID)))
	if !strings.Contains(rail, "collector not recorded") {
		t.Fatalf("%s", visible(rail))
	}
	if !strings.Contains(rail, ">mystery<") {
		t.Fatalf("and the collection is still there: %s", visible(rail))
	}
}

func TestTheRailIsOnEveryPage(t *testing.T) {
	st, _ := railStore(t)
	h := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)
	for _, path := range []string{"/", "/collections/links",
		"/collections/links/object?name=lo"} {
		rr := get(t, h, path)
		if rr.Code != 200 {
			t.Fatalf("%s: %d", path, rr.Code)
		}
		body := markup(rr.Body.String())
		if !strings.Contains(body, `class="rail"`) {
			t.Fatalf("%s carries no rail", path)
		}
		// The rail is first, behind a skip link: correct keyboard order.
		if strings.Index(body, `class="skip"`) > strings.Index(body, `id="main"`) {
			t.Fatalf("%s: the skip link must precede the content", path)
		}
	}
}
