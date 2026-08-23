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
