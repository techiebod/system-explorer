// The read API's promises: the declared shapes, the freshness-from-oldest
// rule visible at the surface, and read-only as a structural property.
package collate

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// seeded applies two objects under fakeBootID and returns the store, so
// each test can pair it with the clock and own-boot-id of its branch.
func seeded(t *testing.T) *store.Store {
	t.Helper()
	st := openStore(t)
	if _, err := st.IssueGenerations([]string{"identity"}, "sha256:test"); err != nil {
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
	var page struct {
		Objects []map[string]any `json:"objects"`
		Total   int              `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	rows := page.Objects
	if page.Total != 2 || len(rows) != 2 ||
		rows[0]["id"] != "identity:host1" || rows[0]["at"] != 10.0 {
		t.Fatalf("%+v", page)
	}
	facts := rows[0]["facts"].(map[string]any)
	if facts["OsId"] != "nixos" {
		t.Fatalf("%+v", facts)
	}
	// The envelope's paging members are explicit, present even when the
	// whole collection fits one page: a client never infers truncation.
	var envelope map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if next, ok := envelope["next_cursor"]; !ok || next != nil {
		t.Fatalf("next_cursor must be an explicit null: %+v", envelope)
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

// The relations route, and the one property it exists to preserve: a reader
// must be able to tell an edge into open space from an edge to a known object
// WITHOUT reading prose, and must never see `asserted` wearing `confirmed`'s
// shape. So `observability` and `target.resolved` are required members and
// `target.id` appears only when there is one — an omitted state would let a
// consumer default it, and the default a consumer picks is `confirmed`.
func TestRelationsRouteRendersResolutionAndObservability(t *testing.T) {
	st := seeded(t)
	_, err := st.ApplyAssertions("identity", store.HostNative,
		[]store.Assertion{
			{Collection: "identity", SourceName: "host1", Type: "peers-with",
				Vantage: "identity", TargetKind: "host", TargetName: "host2"},
			{Collection: "identity", SourceName: "host1", Type: "peers-with",
				Vantage: "identity", TargetKind: "host", TargetName: "elsewhere"},
		},
		map[string]store.RelationType{"peers-with": {}},
		st.ResolverFor(map[string]string{"host": "identity"}, store.HostNative),
		nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID),
		"/v1/collections/identity/relations")
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("both edges are served, the unresolved one included: %+v", rows)
	}
	byName := map[string]map[string]any{}
	for _, row := range rows {
		target := row["target"].(map[string]any)
		byName[target["name"].(string)] = row
	}

	known := byName["host2"]["target"].(map[string]any)
	if known["resolved"] != true || known["id"] != "identity:host2" {
		t.Fatalf("a name this host published resolves and carries its id: %+v", known)
	}
	open := byName["elsewhere"]["target"].(map[string]any)
	if open["resolved"] != false {
		t.Fatalf("resolved is present and false, never absent: %+v", open)
	}
	if _, hasID := open["id"]; hasID {
		t.Fatalf("an unresolved target has no id to carry: %+v", open)
	}
	if open["name"] != "elsewhere" {
		t.Fatalf("it carries the bare name instead: %+v", open)
	}
	for name, row := range byName {
		if row["observability"] != "asserted" {
			t.Fatalf("%s: observability is required and stated, not inferred: %+v", name, row)
		}
	}
}

// Acceptance item 1, at the SERVING path rather than in the store. The
// store keeps two instances apart by scope and its own test proves it —
// but Objects() dropped the scope column, so both rows reached this API
// carrying the identical minted id and nothing to tell them apart. A
// consumer reading two rows called `identity:indexer:3` cannot say which
// instance either belongs to, which is the merge item 1 forbids arriving
// one layer later than the layer that was tested.
//
// Found 2026-08-20 while building the checkpoint, which would have
// inherited it and made item 1's hub half unreachable.
func TestTwoInstancesAreDistinguishableOnTheWire(t *testing.T) {
	st := openStore(t)
	for range 2 {
		if _, err := st.IssueGenerations([]string{"identity"}, "sha256:test"); err != nil {
			t.Fatal(err)
		}
	}
	apply := func(instance string, gen uint64, batch, facts string) {
		t.Helper()
		outcome, err := st.ApplyCommit("identity", instance, gen, batch, fakeBootID,
			[]store.Object{{ID: "identity:indexer:3", Name: "indexer:3",
				Facts: json.RawMessage(facts), At: 10}})
		if err != nil || outcome != store.OutcomeApplied {
			t.Fatalf("apply %q: %v %s", instance, err, outcome)
		}
	}
	apply(store.HostNative, 1, "b1", `{"Port":1}`)
	apply("radarr", 2, "b2", `{"Port":2}`)

	h := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)
	rr := get(t, h, "/v1/collections/identity/objects")
	var page struct {
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	rows := page.Objects
	if len(rows) != 2 {
		t.Fatalf("two instances, two rows: %s", rr.Body.String())
	}
	// Present on BOTH rows, never omitted: "absent means host-native"
	// would be the magic value the identity design refuses, and a reader
	// would have to know the convention to interpret the row at all.
	for i, row := range rows {
		if _, ok := row["instance"]; !ok {
			t.Fatalf("row %d carries no instance member: %v", i, row)
		}
	}
	if rows[0]["instance"] != nil {
		t.Fatalf("host-native instance must serialise as null, got %v", rows[0]["instance"])
	}
	if rows[1]["instance"] != "radarr" {
		t.Fatalf("named instance must serialise as its name, got %v", rows[1]["instance"])
	}
}

// The host page: the collator's own scale of the UI. It must answer
// whether or not a hub is reachable, which is the founding invariant.
func TestHostPageRendersWithoutAHub(t *testing.T) {
	st := seeded(t)
	rr := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID), "/")
	if rr.Code != http.StatusOK {
		t.Fatalf("%d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"<!doctype html>", "This host", "identity", "--ok:"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
	if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("the page carries no script and the header must say so")
	}
	if strings.Contains(body, "<script") {
		t.Fatal("server-rendered means no script, structurally")
	}
}

func TestHostPageEscapesWhatItDidNotWrite(t *testing.T) {
	st := openStore(t)
	if _, err := st.IssueGenerations([]string{"identity"}, "sha256:test"); err != nil {
		t.Fatal(err)
	}
	hostile := `<script>alert("x")</script>`
	if _, err := st.ApplyCommit("identity", store.HostNative, 1, "b1", fakeBootID,
		[]store.Object{{ID: "identity:h", Name: hostile,
			Facts: json.RawMessage(`{"OsId":"` + `nixos` + `"}`), At: 10}}); err != nil {
		t.Fatal(err)
	}
	body := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID), "/").Body.String()
	if strings.Contains(body, "<script>alert") {
		t.Fatal("facts carry text this product did not write; a page that trusted " +
			"it would turn a read-only observer into a delivery mechanism")
	}
}

func TestHostPageSaysWhenNothingCouldJudge(t *testing.T) {
	// A collection whose declaration the store cannot produce is UNJUDGED,
	// and unjudged must not render the same as clean.
	st := seeded(t)
	body := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID), "/").Body.String()
	if !strings.Contains(body, "no rule table could be read") {
		t.Fatalf("unobservable and healthy must not render the same:\n%s", body[:400])
	}
}

func TestHostPageShowsOpinionsWithTheirGrounds(t *testing.T) {
	st := openStore(t)
	document := declWithRules(`[{"key":"pool-degraded","level":"critical",
	 "grounds":"interface","when":{"fact":"State","equals":"degraded"},
	 "sentence":"ZFS reports this pool degraded.","cites":["State"]}]`)
	digest := "sha256:pools"
	if err := st.RecordDeclaration(digest, document); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IssueGenerations([]string{"pools"}, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyCommit("pools", store.HostNative, 1, "b1", fakeBootID,
		[]store.Object{{ID: "pools:tank", Name: "tank",
			Facts: json.RawMessage(`{"State":"degraded"}`), At: 10}}); err != nil {
		t.Fatal(err)
	}
	body := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID), "/").Body.String()
	if !strings.Contains(body, "ZFS reports this pool degraded.") {
		t.Fatal("the sentence comes from the declaration, and must reach the page")
	}
	if !strings.Contains(body, `class="grounds interface"`) {
		t.Fatal("grounds is its own axis: our threshold must never look like the " +
			"machine declaring its own fault")
	}
	if !strings.Contains(body, `class="chip critical"`) {
		t.Fatal("the level comes from the rule table")
	}
}

// Both scales publish their own route table, so one MCP surface can
// become either without knowing at build time what routes a tier has.
func TestTheTierPublishesItsRoutes(t *testing.T) {
	rr := get(t, NewHandler(seeded(t), func() float64 { return 26.0 }, fakeBootID),
		"/v1/routes")
	if rr.Code != http.StatusOK {
		t.Fatalf("%d", rr.Code)
	}
	var payload struct {
		Routes []struct {
			Path, Tool, Summary string
			Params              []string
		} `json:"routes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Routes) < 4 {
		t.Fatalf("a tier that publishes no routes has no surface: %+v", payload.Routes)
	}
	seen := map[string]bool{}
	for _, route := range payload.Routes {
		if route.Path == "" || route.Tool == "" || route.Summary == "" {
			t.Fatalf("a route with no tool or no summary cannot become one: %+v", route)
		}
		if seen[route.Tool] {
			t.Fatalf("two routes claim the tool %q", route.Tool)
		}
		seen[route.Tool] = true
		// Every published route must actually answer, or the table is a
		// promise the tier does not keep.
		path := strings.ReplaceAll(route.Path, "{name}", "identity")
		if got := get(t, NewHandler(seeded(t), func() float64 { return 26.0 },
			fakeBootID), path); got.Code != http.StatusOK {
			t.Fatalf("%s published and answered %d", path, got.Code)
		}
	}
}

// Acceptance item 11 at the collator's own channels. The hub sweeps its
// four; these are the two this tier owns, swept next to the store that
// holds the facts.
func TestNoCanaryReachesTheCollatorsChannels(t *testing.T) {
	const canary = "se-canary-9d41f2b7c0e5-do-not-publish"
	st := openStore(t)
	document := `{"schema":"se.declaration/1","collector":"vault","version":"1.0.0",
	 "collections":[{"name":"creds","question":"q","prefix":"cred","freshness":"60s",
	 "perishability":"perishable","answer":["Endpoint"],
	 "facts":{"Endpoint":{"type":"string","temperament":"configuration","kind":"observed","discloses":"location","sentence":"."},
	          "ApiToken":{"type":"string","temperament":"configuration","kind":"observed","discloses":"secret","sentence":"."}},
	 "rules":[{"key":"vault-reachable","level":"info","grounds":"interface",
	           "when":{"fact":"Endpoint","present":true},
	           "sentence":"The vault endpoint is configured.","cites":["Endpoint"]}]}]}`
	if err := st.RecordDeclaration("sha256:vault", document); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IssueGenerations([]string{"creds"}, "sha256:vault"); err != nil {
		t.Fatal(err)
	}
	facts := `{"Endpoint":"https://vault.example","ApiToken":"` + canary + `"}`
	if _, err := st.ApplyCommit("creds", store.HostNative, 1, "b1", fakeBootID,
		[]store.Object{{ID: "creds:vault", Name: "vault",
			Facts: json.RawMessage(facts), At: 10}}); err != nil {
		t.Fatal(err)
	}
	// Anti-vacuity: the canary really is in the state being swept.
	rows, err := st.Objects("creds")
	if err != nil || !strings.Contains(string(rows[0].Facts), canary) {
		t.Fatalf("the canary must be planted for the sweep to mean anything: %v", err)
	}

	handler := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)
	// Every route the tier publishes, walked from the table it publishes —
	// not the ones this test's author remembered.
	published := get(t, handler, "/v1/routes")
	var table struct {
		Routes []struct {
			Path string `json:"path"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(published.Body.Bytes(), &table); err != nil {
		t.Fatal(err)
	}
	paths := []string{"/", "/v1/routes"}
	for _, route := range table.Routes {
		paths = append(paths, strings.ReplaceAll(route.Path, "{name}", "creds"))
	}
	for _, path := range paths {
		body := get(t, handler, path).Body.String()
		if strings.Contains(body, canary) {
			t.Fatalf("%s published a declared credential", path)
		}
	}

	// And the checkpoint, which is the channel that leaves the host.
	var buf bytes.Buffer
	if err := WriteCheckpoint(&buf, st, "cp-1", "storage-1", fakeBootID, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), canary) {
		t.Fatal("a declared credential reached the hub")
	}
	if !strings.Contains(buf.String(), "vault.example") {
		t.Fatal("only the credential is withheld; the rest of the row must survive")
	}
}

// Gate R1's clause, at the surface a consumer reads: rows come back in
// the batch's own emission order, each carrying its type. The store test
// proves the columns; this proves nothing between store and wire quietly
// re-sorts or drops them.
func TestRowsServeTypedInAppliedOrder(t *testing.T) {
	st := openStore(t)
	if _, err := st.IssueGenerations([]string{"units"}, "sha256:units"); err != nil {
		t.Fatal(err)
	}
	emitted := []store.Object{
		{ID: "units:-.slice", Name: "-.slice", Type: "slice",
			Facts: json.RawMessage(`{}`), At: 10},
		{ID: "units:zfs.target", Name: "zfs.target", Type: "target",
			Facts: json.RawMessage(`{}`), At: 10},
		{ID: "units:apparmor.service", Name: "apparmor.service", Type: "service",
			Facts: json.RawMessage(`{}`), At: 10},
	}
	if _, err := st.ApplyCommit("units", store.HostNative, 1, "b1", fakeBootID,
		emitted); err != nil {
		t.Fatal(err)
	}
	rr := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID),
		"/v1/collections/units/objects")
	var page struct {
		Objects []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	rows := page.Objects
	if len(rows) != 3 {
		t.Fatalf("%d rows", len(rows))
	}
	for i, want := range emitted {
		if rows[i].ID != want.ID || rows[i].Type != want.Type {
			t.Fatalf("row %d: got (%s, %s), applied (%s, %s) — the wire must "+
				"serve the producer's order and kind, not its own",
				i, rows[i].ID, rows[i].Type, want.ID, want.Type)
		}
	}
}
