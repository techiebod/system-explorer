package collate

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
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
