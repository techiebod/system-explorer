package collate

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// The pages, asserted on WHAT A PERSON SEES. A class name is a promise
// about a stylesheet; the words are the page.

const pagesDecl = `{"schema":"se.declaration/1","collector":"t","collections":[{
  "name":"pools","freshness":"1h","question":"Are the pools healthy?",
  "prefix":"pool","answer":["Health","SizeBytes","CapacityPercent"],
  "facts":{
    "Health":{"type":"enum","values":["ONLINE","DEGRADED"],"temperament":"state",
              "sentence":"ZFS's own verdict on the pool."},
    "SizeBytes":{"type":"integer","unit":"bytes","temperament":"gauge"},
    "CapacityPercent":{"type":"number","unit":"percent","temperament":"gauge",
                       "denominator":"SizeBytes"},
    "SpareCount":{"type":"integer","unit":"count","temperament":"configuration"}
  }}]}`

func pagesStore(t *testing.T) *store.Store {
	t.Helper()
	st := openStore(t)
	if _, err := st.IssueGenerations([]string{"pools"}, "sha256:p"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:p", pagesDecl); err != nil {
		t.Fatal(err)
	}
	objects := []store.Object{{
		ID: "pool:tank", Name: "tank", Type: "pool",
		Facts: json.RawMessage(
			`{"Health":"ONLINE","SizeBytes":1073741824,"CapacityPercent":25}`),
		Absent: []string{"SpareCount"},
		At:     10.0,
	}}
	if _, err := st.ApplyCommit("pools", store.HostNative, 1, "b1",
		fakeBootID, objects); err != nil {
		t.Fatal(err)
	}
	return st
}

func htmlOf(t *testing.T, st *store.Store, path string) string {
	t.Helper()
	h := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)
	rr := get(t, h, path)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: %d", path, rr.Code)
	}
	return rr.Body.String()
}

func TestColumnsComeFromTheProducersAnswerInItsOrder(t *testing.T) {
	// §27: a table is scanned, not read, and a row that carries
	// everything carries nothing. The ORDER is the producer's — a
	// renderer sorting these would be deciding which fact matters most.
	out := htmlOf(t, pagesStore(t), "/collections/pools")
	head := out[strings.Index(out, "<thead>"):strings.Index(out, "</thead>")]
	want := []string{"Health", "SizeBytes", "CapacityPercent"}
	at := -1
	for _, name := range want {
		i := strings.Index(head, ">"+name+"<")
		if i < 0 {
			t.Fatalf("%s missing from the header: %s", name, head)
		}
		if i < at {
			t.Fatalf("%s is out of the producer's declared order: %s", name, head)
		}
		at = i
	}
	// SpareCount is declared but NOT in `answer`, so it belongs to the
	// object density and must not widen the table.
	if strings.Contains(head, "SpareCount") {
		t.Fatalf("a fact outside `answer` reached the row density: %s", head)
	}
}

func TestARowRendersAbsentAsAbsentAndNotAsBlank(t *testing.T) {
	// SpareCount is absent on this object. On the OBJECT page — where
	// every fact appears — it must render as an em dash, muted, never as
	// an empty cell and never as zero.
	out := htmlOf(t, pagesStore(t), "/collections/pools/objects/tank")
	i := strings.Index(out, "SpareCount")
	if i < 0 {
		t.Fatal("an absent fact must still appear: it is a measured negative")
	}
	window := out[i:min(i+400, len(out))]
	if !strings.Contains(window, "—") {
		t.Fatalf("absent renders as an em dash: %s", window)
	}
	if strings.Contains(window, ">0<") {
		t.Fatalf("never zero — a zero reads as measured: %s", window)
	}
}

func TestTheFourEmptyStatesDoNotRenderAlikeOnAPage(t *testing.T) {
	// declined-absent, declined-unauthorised, read-and-empty, never-read.
	// Below the collector these were collapsed twice; this is where the
	// difference finally reaches a person.
	pages := map[string]string{}

	// 1. absent: declines AND commits.
	st := openStore(t)
	mustIssue(t, st, "pools", "sha256:p", pagesDecl)
	if _, err := st.ApplyCommit("pools", store.HostNative, 1, "b1", fakeBootID,
		nil); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAbsent("pools", "no zpool on this host"); err != nil {
		t.Fatal(err)
	}
	pages["absent"] = htmlOf(t, st, "/collections/pools")

	// 2. unauthorised: declines and does NOT commit.
	st2 := openStore(t)
	mustIssue(t, st2, "pools", "sha256:p", pagesDecl)
	if _, err := st2.ApplyCommit("pools", store.HostNative, 1, "b1", fakeBootID,
		nil); err != nil {
		t.Fatal(err)
	}
	if err := st2.MarkStaleWith("pools", "unauthorised", "root only"); err != nil {
		t.Fatal(err)
	}
	pages["unauthorised"] = htmlOf(t, st2, "/collections/pools")

	// 3. read, and holds nothing.
	st3 := openStore(t)
	mustIssue(t, st3, "pools", "sha256:p", pagesDecl)
	if _, err := st3.ApplyCommit("pools", store.HostNative, 1, "b1", fakeBootID,
		nil); err != nil {
		t.Fatal(err)
	}
	pages["empty"] = htmlOf(t, st3, "/collections/pools")

	// 4. never read: a generation issued and nothing ever applied.
	st4 := openStore(t)
	mustIssue(t, st4, "pools", "sha256:p", pagesDecl)
	pages["never"] = htmlOf(t, st4, "/collections/pools")

	seen := map[string]string{}
	for name, page := range pages {
		text := visible(page)
		for other, against := range seen {
			if text == against {
				t.Fatalf("%s and %s render identically — the four empty "+
					"states collapsed at the surface", name, other)
			}
		}
		seen[name] = text
	}
	if !strings.Contains(pages["absent"], "not on this host") {
		t.Fatalf("absent says the question does not apply: %s", visible(pages["absent"]))
	}
	if !strings.Contains(pages["unauthorised"], "refused permission") {
		t.Fatalf("unauthorised says who could not look: %s",
			visible(pages["unauthorised"]))
	}
	if !strings.Contains(pages["empty"], "answered") {
		t.Fatalf("read-and-empty says the interface answered: %s",
			visible(pages["empty"]))
	}
	if !strings.Contains(pages["never"], "Never read") {
		t.Fatalf("never-read says no baseline exists: %s", visible(pages["never"]))
	}
}

func TestADeclineStatesItsReasonInsteadOfShowingAnEmptyTable(t *testing.T) {
	// §28: "the collection states its reason instead of showing an empty
	// table". An empty table is an answer; a decline is not.
	st := openStore(t)
	mustIssue(t, st, "pools", "sha256:p", pagesDecl)
	if _, err := st.ApplyCommit("pools", store.HostNative, 1, "b1", fakeBootID,
		nil); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkStaleWith("pools", "unavailable",
		"the zfs module is not loaded"); err != nil {
		t.Fatal(err)
	}
	out := htmlOf(t, st, "/collections/pools")
	if !strings.Contains(out, "the zfs module is not loaded") {
		t.Fatal("the detail is the half a person acts on and must reach the page")
	}
	if !strings.Contains(out, "incident") {
		t.Fatalf("unavailable is an incident, not a configuration: %s", visible(out))
	}
}

func TestStalenessIsStatedOverTheTableNotIntoEveryCell(t *testing.T) {
	// Repeating "stale" into every cell says each fact independently went
	// stale, which is not what happened, and buries the one statement
	// that matters.
	st := pagesStore(t)
	if err := st.MarkStaleWith("pools", "unavailable", "zfs stopped answering"); err != nil {
		t.Fatal(err)
	}
	out := htmlOf(t, st, "/collections/pools")
	// `class="..."`, not the bare word: the stylesheet is embedded in the
	// page, so counting the class NAME counts its own CSS rule too. Same
	// trap as reading a title attribute for prose.
	if !strings.Contains(out, `class="stale-banner"`) {
		t.Fatalf("a stale collection says so, prominently: %s", visible(out))
	}
	// The values still stand — the last thing known beats a blank page.
	if !strings.Contains(out, "ONLINE") {
		t.Fatal("a non-absent decline leaves prior objects standing")
	}
	if n := strings.Count(out, `class="stale-banner"`); n != 1 {
		t.Fatalf("stated once, over the table, never repeated into every "+
			"cell as though each fact independently went stale: %d times", n)
	}
}

func TestTheDrillIsAnchorsAllTheWayDown(t *testing.T) {
	// §28's interaction table gives every step of row → object →
	// evidence to <a href>, with no script. A page that needs script to
	// be navigable is not a complete answer.
	st := pagesStore(t)
	host := htmlOf(t, st, "/")
	if !strings.Contains(host, `href="/collections/pools"`) {
		t.Fatalf("the host page drills into a collection: %s", host)
	}
	collection := htmlOf(t, st, "/collections/pools")
	if !strings.Contains(collection, `href="/collections/pools/objects/tank"`) {
		t.Fatalf("a row drills into its object: %s", collection)
	}
	object := htmlOf(t, st, "/collections/pools/objects/tank")
	if !strings.Contains(object,
		`href="/v1/collections/pools/objects/tank/evidence"`) {
		t.Fatalf("evidence is one step from any fact: %s", object)
	}
	for _, page := range []string{host, collection, object} {
		if strings.Contains(page, "<script") || strings.Contains(page, "onclick") {
			t.Fatal("this tier cannot run script at all — that is the ruling, " +
				"and it is a header as well as a habit")
		}
	}
}

func TestEveryPageCarriesTheNoScriptPolicy(t *testing.T) {
	st := pagesStore(t)
	h := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)
	for _, path := range []string{"/", "/collections/pools",
		"/collections/pools/objects/tank"} {
		rr := get(t, h, path)
		policy := rr.Header().Get("Content-Security-Policy")
		if !strings.Contains(policy, "default-src 'none'") {
			t.Fatalf("%s: the collator's pages must answer when everything "+
				"else is down, and not being able to execute anything is "+
				"worth more there than any narrowing: %q", path, policy)
		}
		if strings.Contains(policy, "script-src") {
			t.Fatalf("%s: the one script exception is the HUB's to spend, "+
				"never this tier's: %q", path, policy)
		}
	}
}

func TestAPercentageOnARowCarriesItsDenominator(t *testing.T) {
	out := htmlOf(t, pagesStore(t), "/collections/pools")
	if !strings.Contains(out, "25%") {
		t.Fatalf("%s", visible(out))
	}
	if !strings.Contains(out, "of 1 GiB") {
		t.Fatalf("a percentage with no denominator is a number pretending "+
			"to be an answer: %s", visible(out))
	}
}

func TestAFactsSentenceComesFromTheDeclaration(t *testing.T) {
	// A glossary in the renderer would be a fourth copy of what the
	// producer already said — the failure §27 records three times.
	out := htmlOf(t, pagesStore(t), "/collections/pools/objects/tank")
	if !strings.Contains(out, "ZFS&#39;s own verdict on the pool.") &&
		!strings.Contains(out, "ZFS's own verdict on the pool.") {
		t.Fatalf("the declaration's sentence must reach the page: %s", visible(out))
	}
}

func TestACollectionStatesTheQuestionItAnswers(t *testing.T) {
	out := htmlOf(t, pagesStore(t), "/collections/pools")
	if !strings.Contains(out, "Are the pools healthy?") {
		t.Fatalf("a table whose purpose is only in the producer's head is "+
			"one a reader has to reverse-engineer: %s", visible(out))
	}
}

func mustIssue(t *testing.T, st *store.Store, collection, digest, document string) {
	t.Helper()
	if _, err := st.IssueGenerations([]string{collection}, digest); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration(digest, document); err != nil {
		t.Fatal(err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── hide groups, and the four invariants carried from app.js ──────────

const hidingDecl = `{"schema":"se.declaration/1","collector":"t","collections":[{
  "name":"units","freshness":"1h","question":"What is running?",
  "prefix":"unit","answer":["ActiveState"],
  "facts":{"ActiveState":{"type":"enum","values":["active","inactive","failed"],
                          "temperament":"state"}},
  "hide_groups":[{"key":"inactive","label":"inactive",
                  "when":{"fact":"ActiveState","equals":"inactive"}}],
  "rules":[{"key":"unit-health","level":"critical","grounds":"interface",
            "when":{"fact":"ActiveState","equals":"failed"},
            "sentence":"systemd reports this unit failed.","cites":["ActiveState"]}]
  }]}`

func hidingStore(t *testing.T) *store.Store {
	t.Helper()
	st := openStore(t)
	mustIssue(t, st, "units", "sha256:u", hidingDecl)
	objects := []store.Object{
		{ID: "unit:a", Name: "a", Facts: json.RawMessage(`{"ActiveState":"active"}`), At: 10},
		{ID: "unit:b", Name: "b", Facts: json.RawMessage(`{"ActiveState":"inactive"}`), At: 10},
		{ID: "unit:c", Name: "c", Facts: json.RawMessage(`{"ActiveState":"inactive"}`), At: 10},
		{ID: "unit:d", Name: "d", Facts: json.RawMessage(`{"ActiveState":"failed"}`), At: 10},
	}
	if _, err := st.ApplyCommit("units", store.HostNative, 1, "b1", fakeBootID,
		objects); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestAHideGroupComesFromTheDeclarationNotFromTheRenderer(t *testing.T) {
	// app.js holds these as hard-coded predicates, which is a fifth copy
	// of producer knowledge in a renderer — the shape §27 records rotting
	// three times. A collection declaring no groups hides nothing.
	st := pagesStore(t) // pools: declares no hide_groups
	out := markup(htmlOf(t, st, "/collections/pools"))
	if strings.Contains(out, "hide-chip") {
		t.Fatalf("a collection that declares no group must get no chips, "+
			"or the renderer is deciding which rows are uninteresting: %s",
			visible(out))
	}
}

func TestACriticalRowIsNeverSuppressedWhateverTheGroupMatches(t *testing.T) {
	// Invariant 2, and the promise the whole toggle rests on: the default
	// view never swallows a failure. Enforced once, structurally, rather
	// than re-derived in every predicate anyone adds later.
	out := htmlOf(t, hidingStore(t), "/collections/units")
	i := strings.Index(out, `>d<`)
	if i < 0 {
		t.Fatalf("the failed unit is missing entirely: %s", visible(out))
	}
	// It must not carry a group, which is what a selector would hide it by.
	row := out[max(0, strings.LastIndex(out[:i], "<tr")):i]
	if strings.Contains(row, "data-group") {
		t.Fatalf("a critical row was assigned to a hide group: %s", row)
	}
}

func TestTheExemptionIsCriticalOnlyAndNotWarn(t *testing.T) {
	// Invariant 3. The inactive group hides a unit carrying a
	// restart-churn warning today, and widening the exemption to warn
	// would quietly change what that group has always meant.
	groups := []HideGroup{{Key: "inactive", Label: "inactive",
		When: json.RawMessage(`{"fact":"ActiveState","equals":"inactive"}`)}}
	facts := map[string]any{"ActiveState": "inactive"}
	if got := assign(groups, facts, "warn"); got != "inactive" {
		t.Fatalf("a warn row is still hidden by its group: %q", got)
	}
	if got := assign(groups, facts, "critical"); got != "" {
		t.Fatalf("a critical row is exempt: %q", got)
	}
}

func TestAChipCountsWhatItsGroupHoldsAndNothingRecomputesIt(t *testing.T) {
	// Invariant 1: the number answers WHAT THIS GROUP HOLDS, not what is
	// hidden right now. Two inactive rows; the failed one is exempt and
	// must not be counted, because the count promises exactly the set
	// that pressing the chip reveals.
	out := htmlOf(t, hidingStore(t), "/collections/units")
	if !strings.Contains(out, `class="chip hide-chip"`) {
		t.Fatalf("a declared group renders its chip: %s", visible(out))
	}
	if !strings.Contains(out, `<span class="count">2</span>`) {
		t.Fatalf("the count is what assign() ASSIGNS — two inactive rows, "+
			"the failed one exempt: %s", visible(out))
	}
	// Nothing on the page can change it: no script at all.
	if strings.Contains(out, "<script") {
		t.Fatal("a recomputed count is a count that can disagree with its group")
	}
}

func TestAHiddenRowIsInTheMarkupAndOnlyHiddenBySelector(t *testing.T) {
	// §28 rule 4: every page is a complete answer with script disabled —
	// and, here, with CSS disabled too. A row the server left out is a
	// row curl and the consumer without eyes never receive.
	out := htmlOf(t, hidingStore(t), "/collections/units")
	for _, name := range []string{">a<", ">b<", ">c<", ">d<"} {
		if !strings.Contains(out, name) {
			t.Fatalf("%s was omitted rather than hidden: %s", name, visible(out))
		}
	}
	if !strings.Contains(out, `data-group="inactive"`) {
		t.Fatalf("a hidden row carries its group: %s", visible(out))
	}
	if !strings.Contains(out, `tr[data-group]{display:none}`) {
		t.Fatalf("hiding is a selector, not an omission: %s", out)
	}
}

func TestTheChipIsTheControlSoThereIsNoStateToGetOutOfStep(t *testing.T) {
	// Invariant 4: the way back is legible because the chip IS the
	// checkbox's label — one thing, not a control and a separate count
	// that can disagree.
	out := htmlOf(t, hidingStore(t), "/collections/units")
	if !strings.Contains(out, `<input type="checkbox" id="reveal-inactive"`) {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(out, `<label for="reveal-inactive"`) {
		t.Fatalf("the chip is the label of the checkbox that reveals it: %s", out)
	}
	if !strings.Contains(out, `#reveal-inactive:checked ~ .scroll tr[data-group="inactive"]`) {
		t.Fatalf("a checkbox and a :checked ~ sibling selector, per §28: %s", out)
	}
}

func TestAGroupKeyCannotEscapeIntoTheStylesheet(t *testing.T) {
	// A group key is producer text, and a selector assembled from
	// unescaped producer text is an injection into the one place this
	// page's CSP cannot help — the stylesheet it already permits.
	if got := cssIdent(`x"]{}*{display:block}[a="`); strings.ContainsAny(got, `"{}[]*:`) {
		t.Fatalf("a key reached the selector intact: %q", got)
	}
}

func TestAGroupWhoseConditionCannotBeEvaluatedLeavesRowsVisible(t *testing.T) {
	// The safe direction: the failure mode of a missing group is a longer
	// page, and the failure mode of a broken one hiding rows anyway is a
	// suppressed fault.
	groups := []HideGroup{{Key: "broken", Label: "broken",
		When: json.RawMessage(`{"nonsense":true}`)}}
	if got := assign(groups, map[string]any{"ActiveState": "inactive"}, ""); got != "" {
		t.Fatalf("an unevaluable group hid a row: %q", got)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── the three acceptance items, which the gate judges ─────────────────

const treeDecl = `{"schema":"se.declaration/1","collector":"t","collections":[{
  "name":"units","freshness":"1h","question":"What is running?","prefix":"unit",
  "answer":["ActiveState"],
  "facts":{"ActiveState":{"type":"enum","values":["active"],"temperament":"state"}},
  "relations":[{"type":"member-of","kind":"unit"}]}]}`

func treeStore(t *testing.T) *store.Store {
	t.Helper()
	st := openStore(t)
	mustIssue(t, st, "units", "sha256:t", treeDecl)
	objects := []store.Object{
		{ID: "unit:a.slice", Name: "a.slice",
			Facts: json.RawMessage(`{"ActiveState":"active"}`), At: 10},
		{ID: "unit:child.service", Name: "child.service",
			Facts: json.RawMessage(`{"ActiveState":"active"}`), At: 10},
		{ID: "unit:other.slice", Name: "other.slice",
			Facts: json.RawMessage(`{"ActiveState":"active"}`), At: 10},
	}
	if _, err := st.ApplyCommit("units", store.HostNative, 1, "b1", fakeBootID,
		objects); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestATreeIsDerivedFromTheProducersOwnEdges(t *testing.T) {
	// Acceptance item: the units page renders its slice tree, derived
	// from `member-of`. The nesting is the producer's assertion; this
	// file only draws it.
	rows := []store.ObjectRow{
		{Name: "a.slice"}, {Name: "child.service"}, {Name: "other.slice"},
	}
	order, depth, cyclic := nest(rows, map[string]string{"child.service": "a.slice"})
	if cyclic {
		t.Fatal("no cycle here")
	}
	if len(order) != 3 {
		t.Fatalf("every row is drawn: %v", order)
	}
	// The child follows its parent, one level in.
	var at = map[string]int{}
	for pos, i := range order {
		at[rows[i].Name] = pos
	}
	if at["child.service"] != at["a.slice"]+1 {
		t.Fatalf("a child follows its parent: %v", at)
	}
	if depth[order[at["child.service"]]] != 1 {
		t.Fatalf("a child is drawn one level in: %v", depth)
	}
}

func TestARowWhoseParentIsNotOnThePageIsARoot(t *testing.T) {
	// Nesting it under an absent parent would draw an edge to something
	// the reader cannot see.
	rows := []store.ObjectRow{{Name: "orphan.service"}}
	order, depth, _ := nest(rows, map[string]string{"orphan.service": "gone.slice"})
	if len(order) != 1 || depth[0] != 0 {
		t.Fatalf("order %v depth %v", order, depth)
	}
}

func TestACycleIsShownAtTopLevelAndSaidRatherThanDropped(t *testing.T) {
	// Silently dropping loses a row; silently recursing hangs the
	// request. Neither is acceptable, so the row is shown and the page
	// says a cycle was found.
	rows := []store.ObjectRow{{Name: "x"}, {Name: "y"}}
	order, _, cyclic := nest(rows, map[string]string{"x": "y", "y": "x"})
	if !cyclic {
		t.Fatal("the cycle must be reported")
	}
	if len(order) != 2 {
		t.Fatalf("no row is dropped: %v", order)
	}
}

func TestIndentationIsDisabledUnderSort(t *testing.T) {
	// The acceptance item says so explicitly. Indentation claims a parent
	// sits directly above its child; once rows are reordered that claim
	// is false, and a tree drawn over a reordered list tells the reader
	// something the data does not say.
	//
	// Driven through nest() and sortedOrder() rather than through a
	// seeded relation store: the rule under test is which ORDERING the
	// page uses, and routing a relation through the applier would test
	// the applier.
	rows := []store.ObjectRow{
		{Name: "a.slice", Facts: json.RawMessage(`{"ActiveState":"active"}`)},
		{Name: "child.service", Facts: json.RawMessage(`{"ActiveState":"active"}`)},
	}
	_, depth, _ := nest(rows, map[string]string{"child.service": "a.slice"})
	if depth[1] != 1 {
		t.Fatalf("unsorted, the tree is drawn: %v", depth)
	}
	// Sorted, the page uses sortedOrder and never calls nest, so no row
	// carries a depth at all.
	order := sortedOrder(rows, nil, "ActiveState")
	if len(order) != 2 {
		t.Fatalf("%v", order)
	}
	// And on a real page carrying real edges, because a page-level
	// assertion against a collection that asserts NO relations can never
	// have a depth to lose — it passes whatever the ordering code does,
	// which is exactly how the first spelling of this test let a plant
	// through.
	st := treeStore(t)
	if _, err := st.ApplyAssertions("units", store.HostNative,
		[]store.Assertion{{
			Collection: "units", SourceName: "child.service", Type: "member-of",
			Vantage: "units", TargetKind: "unit", TargetName: "a.slice",
		}},
		map[string]store.RelationType{"member-of": {}},
		func(kind, name string) (string, bool) { return "unit:" + name, true },
		func(string, string, string) (json.RawMessage, bool) { return nil, false },
	); err != nil {
		t.Fatal(err)
	}
	nested := markup(htmlOf(t, st, "/collections/units"))
	if !strings.Contains(nested, "--depth:") {
		t.Fatalf("the unsorted page draws the tree it was given: %s",
			visible(nested))
	}
	if !strings.Contains(nested, "Nested by") {
		t.Fatalf("and says which relation nests it: %s", visible(nested))
	}
	sorted := markup(htmlOf(t, st, "/collections/units?sort=ActiveState"))
	if strings.Contains(sorted, "--depth:") {
		t.Fatalf("a sorted table is flat: %s", visible(sorted))
	}
	if !strings.Contains(sorted, "is not drawn") {
		t.Fatalf("and the page says why rather than silently dropping the "+
			"shape: %s", visible(sorted))
	}
}

func TestSortingIsALinkThatReAsks(t *testing.T) {
	// §28 pattern 2: if the control needs something the page does not
	// hold, it re-asks. The server's answer is the answer.
	out := markup(htmlOf(t, pagesStore(t), "/collections/pools"))
	if !strings.Contains(out, `href="/collections/pools?sort=Health"`) {
		t.Fatalf("%s", out)
	}
	if strings.Contains(out, "<script") {
		t.Fatal("a browser-side reordering is the browser reconstructing the " +
			"server's answer")
	}
}

func TestACrossSubsystemTargetResolvesThroughTheProducersPrefixes(t *testing.T) {
	// Acceptance item: a zpool status device links through to its
	// hardware disk. The target lives in ANOTHER collection, and where it
	// lives is read from the declarations this host holds — never from a
	// routing table here, which is §27's first rotted copy.
	owner := map[string]string{"block-device": "block-devices"}
	linked := targetLink(owner, store.Relation{
		Resolved: true, TargetID: "block-device:sda", TargetKind: "block-device",
		TargetName: "sda"})
	if !strings.Contains(linked, `href="/collections/block-devices/objects/sda"`) {
		t.Fatalf("the link crosses into the target's own collection: %s", linked)
	}
}

func TestAnUnresolvedTargetIsNotALink(t *testing.T) {
	// §13: an asserted relation carries a positive claim about what was
	// NOT looked at, and a link implies there is something to open —
	// which is the claim the state exists to deny.
	out := targetLink(map[string]string{"repository": "repos"}, store.Relation{
		Resolved: false, TargetKind: "repository", TargetName: "offsite-vault"})
	if strings.Contains(out, "<a ") {
		t.Fatalf("an unread far end is not a link: %s", out)
	}
	if !strings.Contains(out, "offsite-vault") {
		t.Fatalf("but the name is still shown: %s", out)
	}
}

func TestATargetWhoseKindNoDeclarationClaimsIsStatedNotGuessed(t *testing.T) {
	// A dead link is what the browser's routing table produced for the
	// whole application tier, and nobody noticed for as long as it existed.
	out := targetLink(map[string]string{}, store.Relation{
		Resolved: true, TargetID: "x:1", TargetKind: "mystery", TargetName: "x"})
	if strings.Contains(out, "<a ") {
		t.Fatalf("a guess is worse than a statement: %s", out)
	}
	if !strings.Contains(out, "mystery") {
		t.Fatalf("the unclaimed prefix is named: %s", out)
	}
}

func TestAPrefixTwoCollectionsClaimResolvesToNeither(t *testing.T) {
	// The collator refuses that at apply time rather than picking
	// whichever was read last, and a renderer quietly picking one would
	// re-decide what the collator declined to decide.
	st := openStore(t)
	mustIssue(t, st, "a", "sha256:a",
		`{"schema":"se.declaration/1","collector":"a","collections":[{"name":"a",
		  "freshness":"1h","prefix":"shared","facts":{}}]}`)
	mustIssue(t, st, "b", "sha256:b",
		`{"schema":"se.declaration/1","collector":"b","collections":[{"name":"b",
		  "freshness":"1h","prefix":"shared","facts":{}}]}`)
	owner, err := collectionOfPrefix(st)
	if err == nil {
		t.Fatalf("a contested prefix must be refused, not resolved: %v", owner)
	}
	if !strings.Contains(err.Error(), "whichever was read last") {
		t.Fatalf("and refused for the stated reason: %v", err)
	}
	// The page then renders every target as a stated non-link, which is
	// the honest degradation: no link is better than a link to a guess.
	if _, claimed := owner["shared"]; claimed {
		t.Fatalf("no index is returned at all: %v", owner)
	}
}

func TestTheIdentityChainPutsEveryNameOnOnePage(t *testing.T) {
	// Acceptance item: one disk reachable from its /dev/disk/by-id path,
	// its kernel name and its WWN — one object, one page, every name on
	// it. An operator holding any one of them must be able to tell they
	// have the right disk.
	st := openStore(t)
	mustIssue(t, st, "disks", "sha256:d",
		`{"schema":"se.declaration/1","collector":"h","collections":[{
		  "name":"disks","freshness":"1h","prefix":"block-device","answer":[],
		  "facts":{}}]}`)
	objects := []store.Object{{
		ID: "block-device:sda", Name: "sda",
		Facts: json.RawMessage(`{}`),
		Names: json.RawMessage(`{"kernel":["sda"],` +
			`"by-id":["/dev/disk/by-id/ata-Samsung_SSD_870_S5"],` +
			`"wwn":["0x5002538f31a1b2c3"]}`),
		At: 10,
	}}
	if _, err := st.ApplyCommit("disks", store.HostNative, 1, "b1", fakeBootID,
		objects); err != nil {
		t.Fatal(err)
	}
	out := htmlOf(t, st, "/collections/disks/objects/sda")
	for _, name := range []string{
		"sda", "/dev/disk/by-id/ata-Samsung_SSD_870_S5", "0x5002538f31a1b2c3",
	} {
		if !strings.Contains(out, name) {
			t.Fatalf("%s is missing: a page showing only the name it was "+
				"reached by leaves an operator unable to tell whether they "+
				"have the right disk: %s", name, visible(out))
		}
	}
}
