package collate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// declaredNames decides which collections can answer `evidence`, `object`
// and `lookup` at all — the reverse map is built from it ONCE at
// start-up, so a name missing here is a name that is unroutable for the
// process's whole life.
//
// It parsed `lookups` as an ARRAY and the declared shape is a MAP.
// json.Unmarshal fails on the whole document when one member has the
// wrong shape, and the error branch returned nil, so a collector that
// declares any lookup contributed NO names — and all FOURTEEN
// collections of storage and network answered "no collector on this host
// publishes it" while publishing objects every sweep.
//
// These drive the REAL declarations rather than a synthetic one. A
// synthetic fixture is exactly what let this ship: every test in the
// package writes its own declaration, and none of them declares a
// lookup, so the shape the product actually ships was never parsed here.

func realDeclarations(t *testing.T) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob("../../cmd/se-collect-*/declaration.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no declarations found: %v", err)
	}
	out := map[string][]byte{}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(filepath.Dir(path))] = raw
	}
	return out
}

func TestEveryShippedCollectionIsRoutable(t *testing.T) {
	// The whole product, name by name. If a collector declares
	// collections, every one of them must appear — a collector that
	// contributes nothing has taken its collections' verbs with it.
	for collector, raw := range realDeclarations(t) {
		var document struct {
			Collections []struct {
				Name string `json:"name"`
			} `json:"collections"`
		}
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("%s: %v", collector, err)
		}
		names := declaredNames(raw)
		for _, c := range document.Collections {
			if !slices.Contains(names, c.Name) {
				t.Errorf("%s: %s is not routable, so its evidence, object "+
					"and lookup verbs all answer \"no collector on this host "+
					"publishes it\" — while the collection publishes objects "+
					"on every sweep", collector, c.Name)
			}
		}
	}
}

func TestALookupPaletteIsReadAsTheMapItIs(t *testing.T) {
	// storage declares `snapshots-of`; network declares `route-get` and
	// `resolve`. The palette is a root member mapping each name to its
	// question (PLAN, R3d), and reading it as an array cost the
	// collections beside it.
	all := realDeclarations(t)
	for collector, want := range map[string][]string{
		"se-collect-storage": {"snapshots-of"},
		"se-collect-network": {"route-get", "resolve"},
	} {
		raw, ok := all[collector]
		if !ok {
			t.Fatalf("%s is missing", collector)
		}
		names := declaredNames(raw)
		for _, lookup := range want {
			if !slices.Contains(names, lookup) {
				t.Errorf("%s: lookup %q is not routable: %v", collector, lookup, names)
			}
		}
	}
}

func TestOneMalformedMemberDoesNotCostTheOthers(t *testing.T) {
	// The structural rule the defect taught: the members are parsed
	// SEPARATELY, so one member's shape cannot decide another's fate. A
	// lookups member of an unexpected shape costs the lookups and not the
	// collections.
	raw := []byte(`{"schema":"se.declaration/1","collector":"x",
	  "collections":[{"name":"pools"},{"name":"mounts"}],
	  "lookups":["this","is","the wrong shape"]}`)
	names := declaredNames(raw)
	for _, want := range []string{"pools", "mounts"} {
		if !slices.Contains(names, want) {
			t.Fatalf("a malformed lookups member cost the collections: %v", names)
		}
	}
}

func TestAnUnroutableVerbIsNotServedAsSuccess(t *testing.T) {
	// A refusal at HTTP 200 reads to every caller — curl, MCP, a browser,
	// a monitor — as a considered answer. That is how a parse bug made
	// fourteen collections answer "no collector on this host publishes
	// it" for their evidence, object and lookup verbs, while publishing
	// objects on every sweep, with nothing anywhere going red.
	handler := NewHandlerWithReverse(seeded(t), func() float64 { return 26.0 },
		fakeBootID, map[string]Reverse{"something-else": stubReverse{}})
	for _, path := range []string{
		"/v1/collections/identity/objects/host1/evidence",
		"/v1/collections/identity/objects/host1",
		"/v1/lookups/nosuch?input=x",
	} {
		rr := get(t, handler, path)
		if rr.Code == http.StatusOK {
			t.Errorf("%s: served an unroutable verb as success (200); a "+
				"well-worded refusal at 200 is indistinguishable from a "+
				"result: %s", path, rr.Body.String())
		}
		if rr.Code != http.StatusBadGateway {
			t.Errorf("%s: want 502 — the object may exist and the fault is "+
				"between this collator and the collector that would know, "+
				"which is what 502 says and 404 denies; got %d",
				path, rr.Code)
		}
	}
}

// stubReverse serves a collection this test never asks for: the subject
// is what happens when the requested name is NOT in the map.
type stubReverse struct{}

func (stubReverse) Object(context.Context, string, string, map[string]bool) ([]byte, error) {
	return nil, nil
}

func (stubReverse) Evidence(context.Context, string, string, map[string]bool) ([]byte, error) {
	return nil, nil
}

func (stubReverse) Lookup(context.Context, string, string, map[string]bool) ([]byte, error) {
	return nil, nil
}

func TestAFailedVerbIsRecordedEvenThoughItsTextIsNotServed(t *testing.T) {
	// Suppressing an error's text on an unauthenticated channel is right:
	// it is where a path or a token leaks. Suppressing it from the STORE
	// as well is how a fault becomes unfindable — an operator got "lookup
	// failed", four words, and nothing to read next.
	//
	// The refusal branch beside this one records for exactly this reason:
	// "a refusal nobody can see is one nobody can act on."
	st := seeded(t)
	handler := NewHandlerWithReverse(st, func() float64 { return 26.0 },
		fakeBootID, map[string]Reverse{"identity": failingReverse{}})
	rr := get(t, handler, "/v1/collections/identity/objects/host1/evidence")
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("a failed verb is not a success: %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "/etc/secret-path") {
		t.Fatalf("the error's text must not reach the wire: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "recorded on this host") {
		t.Fatalf("and the caller is told where the reason went: %s",
			rr.Body.String())
	}
	rejections, err := st.Rejections()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range rejections {
		if strings.Contains(r.Detail, "/etc/secret-path") {
			found = true
		}
	}
	if !found {
		t.Fatal("the reason must be recorded, or a transport failure leaves " +
			"no trace anywhere and the fault cannot be found")
	}
}

type failingReverse struct{ stubReverse }

func (failingReverse) Evidence(context.Context, string, string, map[string]bool) ([]byte, error) {
	return nil, errors.New("dial unix /etc/secret-path: connection refused")
}

func TestAUnitWhoseFileDoesNotExistIsDistinguishableOnItsRow(t *testing.T) {
	// systemd lists a unit whose file is NOT INSTALLED, because something
	// references it, and reports it inactive/dead. With LoadState off the
	// row, 19 such units on a live host rendered exactly like ordinary
	// stopped services — same two state columns, same `ok` verdict, no
	// way to tell "this is switched off" from "this does not exist".
	// That is the founding failure on the busiest page in the product.
	//
	// Driven from the REAL declaration so it cannot drift: this is a
	// statement about what `units` ships, not about a fixture.
	raw, err := os.ReadFile("../../cmd/se-collect-units/declaration.json")
	if err != nil {
		t.Fatal(err)
	}
	render, err := RenderFor(string(raw), "units")
	if err != nil || render == nil {
		t.Fatalf("units must describe itself: %v", err)
	}
	if !slices.Contains(render.Answer, "LoadState") {
		t.Fatal("LoadState is not on the row, so a unit whose file does not " +
			"exist is indistinguishable from one that is merely stopped")
	}
	// It arrives in the same reply that already carries ActiveState, so
	// this costs the collector nothing.
	if _, declared := render.Facts["LoadState"]; !declared {
		t.Fatal("and it must be declared, or the renderer cannot draw it")
	}
	// The reference's three columns survive, in their order — the
	// comparator ruling for units/units is `additive`.
	var at = -1
	for _, name := range []string{"ActiveState", "SubState", "Description"} {
		i := slices.Index(render.Answer, name)
		if i < 0 {
			t.Fatalf("%s left the answer list: %v", name, render.Answer)
		}
		if i < at {
			t.Fatalf("the reference's columns must keep their order: %v",
				render.Answer)
		}
		at = i
	}
}

func TestTheInactiveGroupNeverSwallowsAUnitThatDoesNotExist(t *testing.T) {
	// systemd reports a unit whose file is not installed as INACTIVE, so
	// an unnarrowed inactive group hides it. app.js accepted that and
	// said so — "in practice the inactive group claims it and one chip
	// brings it back". Here it would take back, in the same breath, the
	// fix that put LoadState on the row to make those 18 rows visible.
	//
	// Driven from the REAL declaration: a statement about what units ships.
	raw, err := os.ReadFile("../../cmd/se-collect-units/declaration.json")
	if err != nil {
		t.Fatal(err)
	}
	groups, err := HideGroupsFor(string(raw), "units")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) == 0 {
		t.Fatal("units declares no hide group, so its 300 rows all show")
	}
	stopped := map[string]any{"ActiveState": "inactive", "LoadState": "loaded"}
	ghost := map[string]any{"ActiveState": "inactive", "LoadState": "not-found"}
	failed := map[string]any{"ActiveState": "failed", "LoadState": "loaded"}

	if assign(groups, stopped, "") == "" {
		t.Fatal("a genuinely stopped unit is what the group is for")
	}
	if got := assign(groups, ghost, ""); got != "" {
		t.Fatalf("a unit whose file does not exist was hidden by %q — the "+
			"rows LoadState was added to surface", got)
	}
	// The standing invariant: critical is never suppressed, whatever a
	// group matches on.
	if got := assign(groups, failed, "critical"); got != "" {
		t.Fatalf("a critical row was hidden by %q", got)
	}
}
