// The read API's promises: the declared shapes, the freshness-from-oldest
// rule visible at the surface, and read-only as a structural property.
package collate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// seeded applies two objects under fakeBootID and returns the store, so
// each test can pair it with the clock and own-boot-id of its branch.
func seeded(t *testing.T) *store.Store {
	t.Helper()
	st := openStore(t)
	if _, err := st.IssueGenerations([]string{"identity"}); err != nil {
		t.Fatal(err)
	}
	objects := []store.Object{
		{ID: "identity:host1", Name: "host1", Facts: json.RawMessage(`{"OsId":"nixos"}`), At: 10.0},
		{ID: "identity:host2", Name: "host2", Facts: json.RawMessage(`{"OsId":"nixos"}`), At: 16.0},
	}
	if _, err := st.ApplyCommit("identity", store.HostNative, 1, "b1", fakeBootID, objects); err != nil {
		t.Fatal(err)
	}
	return st
}

func seededHandler(t *testing.T) http.Handler {
	t.Helper()
	// A fixed clock and the stored batch's own boot id: ages must be
	// assertable, not merely plausible.
	return NewHandler(seeded(t), func() float64 { return 26.0 }, fakeBootID)
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestHealth(t *testing.T) {
	rr := get(t, seededHandler(t), "/v1/health")
	if rr.Code != http.StatusOK || rr.Body.String() != "{\"ok\":true}\n" {
		t.Fatalf("%d %q", rr.Code, rr.Body.String())
	}
}

func TestCollectionsRow(t *testing.T) {
	rr := get(t, seededHandler(t), "/v1/collections")
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%+v", rows)
	}
	row := rows[0]
	if row["name"] != "identity" || row["generation"] != float64(1) ||
		row["object_count"] != float64(2) || row["stale"] != false {
		t.Fatalf("%+v", row)
	}
	// Item 5 at the surface: oldest_at is the oldest contributing read
	// and age_s is measured from it — 26.0 − 10.0, never 26.0 − 16.0.
	if row["oldest_at"] != 10.0 || row["age_s"] != 16.0 {
		t.Fatalf("freshness must derive from the oldest read: %+v", row)
	}
	if row["stale_reason"] != nil || row["applied_at"] == nil {
		t.Fatalf("%+v", row)
	}
}

func TestObjectsRoute(t *testing.T) {
	rr := get(t, seededHandler(t), "/v1/collections/identity/objects")
	var rows []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["id"] != "identity:host1" || rows[0]["at"] != 10.0 {
		t.Fatalf("%+v", rows)
	}
	facts := rows[0]["facts"].(map[string]any)
	if facts["OsId"] != "nixos" {
		t.Fatalf("%+v", facts)
	}
}

func TestUnknownCollectionIs404(t *testing.T) {
	rr := get(t, seededHandler(t), "/v1/collections/pools/objects")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("an unknown name is a 404, not an empty 200: %d", rr.Code)
	}
}

func TestEmptyStoreServesEmptyListNotNull(t *testing.T) {
	st := openStore(t)
	rr := get(t, NewHandler(st, BootNow, fakeBootID), "/v1/collections")
	if rr.Body.String() != "[]\n" {
		t.Fatalf("%q", rr.Body.String())
	}
}

// The three age branches (DESIGN §09): the same clock domain serves the
// arithmetic; any other domain is a STATED mismatch, never a subtraction
// across boots; and same-domain arithmetic that still goes negative is
// stated too. Under either marker age_s is omitted — no branch serves a
// negative number.

func TestCrossBootIsStatedAndAgeIsOmitted(t *testing.T) {
	// The collator rebooted since the apply: its own boot id no longer
	// matches the stored one.
	h := NewHandler(seeded(t), func() float64 { return 26.0 },
		"5e000000-0000-4000-8000-0000000000d2")
	rr := get(t, h, "/v1/collections")
	var rows []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	row := rows[0]
	if _, present := row["age_s"]; present {
		t.Fatalf("an age across boot domains is garbage and must be omitted: %+v", row)
	}
	if row["cross_boot"] != true {
		t.Fatalf("the mismatch is stated, not hidden: %+v", row)
	}
	// A different clock domain is not staleness — staleness is decline
	// semantics — and the stamp itself still serves verbatim.
	if row["stale"] != false || row["oldest_at"] != 10.0 {
		t.Fatalf("%+v", row)
	}
}

func TestSameBootNegativeArithmeticIsStated(t *testing.T) {
	// Same boot id, clock behind the stamp — a time namespace is the
	// ordinary cause. Stated, never served as a negative age.
	h := NewHandler(seeded(t), func() float64 { return 5.0 }, fakeBootID)
	rr := get(t, h, "/v1/collections")
	var rows []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	row := rows[0]
	if _, present := row["age_s"]; present {
		t.Fatalf("negative arithmetic must not serve a number: %+v", row)
	}
	if row["clock_domain_mismatch"] != true {
		t.Fatalf("the impossibility is stated: %+v", row)
	}
	if _, present := row["cross_boot"]; present {
		t.Fatalf("same boot is not cross boot: %+v", row)
	}
}

func TestSameBootServesTheAgeWithoutMarkers(t *testing.T) {
	rr := get(t, seededHandler(t), "/v1/collections")
	var rows []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	row := rows[0]
	if row["age_s"] != 16.0 {
		t.Fatalf("same domain serves the arithmetic: %+v", row)
	}
	for _, marker := range []string{"cross_boot", "clock_domain_mismatch"} {
		if _, present := row[marker]; present {
			t.Fatalf("no mismatch to state: %+v", row)
		}
	}
}

func TestBootIDCaseNeverSplitsADomain(t *testing.T) {
	// linux lowercases the id, darwin's sysctl does not; UUID-shaped is
	// the ruling, not a platform's spelling, so case must not read as a
	// reboot.
	h := NewHandler(seeded(t), func() float64 { return 26.0 },
		"5E000000-0000-4000-8000-000000000001")
	rr := get(t, h, "/v1/collections")
	var rows []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if rows[0]["age_s"] != 16.0 {
		t.Fatalf("an upper-cased spelling of the same boot must serve the age: %+v", rows[0])
	}
}

func TestNoMutatingRouteExists(t *testing.T) {
	h := seededHandler(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		for _, path := range []string{"/v1/health", "/v1/collections", "/v1/collections/identity/objects"} {
			req := httptest.NewRequest(method, path, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: %d — read-only means no route mutates", method, path, rr.Code)
			}
		}
	}
}
