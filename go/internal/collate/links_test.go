package collate

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// EVERY LINK ON EVERY PAGE MUST RESOLVE.
//
// A mount named `boot/efi` — and every ZFS dataset, `tank/photos` —
// minted `/collections/mounts/objects/boot/efi`, which Go's mux reads as
// two segments and answers 404. Every mount below the root and every
// nested dataset on the estate was unreachable from its own table, and
// the row linked confidently to nothing. `esc()` is HTML escaping and
// does nothing to a slash; the names needed URL escaping.
//
// Found by the owner clicking a mount. Nothing here had ever followed a
// link — every test asserted that an href was PRESENT, and none that it
// went anywhere.

var hrefRE = regexp.MustCompile(`href="([^"]+)"`)

func slashyStore(t *testing.T) *store.Store {
	t.Helper()
	st := openStore(t)
	mustIssue(t, st, "mounts", "sha256:m",
		`{"schema":"se.declaration/1","collector":"storage","collections":[{
		  "name":"mounts","freshness":"1h","prefix":"mount",
		  "answer":["Source"],
		  "facts":{"Source":{"type":"string","temperament":"configuration"}}}]}`)
	// Real shapes: a nested mount, a dataset path, a name with a space,
	// and one with a percent — each of which breaks a different naive
	// escaping.
	objects := []store.Object{
		{ID: "mount:boot/efi", Name: "boot/efi", Type: "mount",
			Facts: json.RawMessage(`{"Source":"/dev/sda1"}`), At: 10},
		{ID: "mount:tank/photos", Name: "tank/photos", Type: "mount",
			Facts: json.RawMessage(`{"Source":"tank/photos"}`), At: 10},
		{ID: "mount:odd name", Name: "odd name", Type: "mount",
			Facts: json.RawMessage(`{"Source":"none"}`), At: 10},
		{ID: "mount:100%", Name: "100%", Type: "mount",
			Facts: json.RawMessage(`{"Source":"none"}`), At: 10},
	}
	if _, err := st.ApplyCommit("mounts", store.HostNative, 1, "b1", fakeBootID,
		objects); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestEveryLinkOnEveryPageResolves(t *testing.T) {
	st := slashyStore(t)
	handler := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)

	// Crawl from the root, following every internal link, exactly as a
	// person clicking would.
	seen := map[string]bool{}
	queue := []string{"/"}
	var broken []string
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		if seen[path] {
			continue
		}
		seen[path] = true
		rr := get(t, handler, path)
		if rr.Code != http.StatusOK {
			broken = append(broken, path+" -> "+http.StatusText(rr.Code))
			continue
		}
		for _, m := range hrefRE.FindAllStringSubmatch(markup(rr.Body.String()), -1) {
			href := m[1]
			// Only this surface's own pages; /v1 is the JSON API and is
			// crawled separately, and an external link is not ours.
			if !strings.HasPrefix(href, "/") || strings.HasPrefix(href, "/v1") {
				continue
			}
			queue = append(queue, href)
		}
	}
	if len(broken) > 0 {
		t.Fatalf("links that go nowhere: %v", broken)
	}
	// Anti-vacuity: the crawl must actually have reached the objects.
	// A crawler that found no links would pass this test trivially,
	// which is how the defect it exists to catch got shipped.
	if len(seen) < 6 {
		t.Fatalf("the crawl reached only %d pages, so it proves nothing: %v",
			len(seen), seen)
	}
	for _, want := range []string{
		"/collections/mounts", "/collections/mounts/object?name=boot%2Fefi",
	} {
		if !seen[want] {
			t.Fatalf("%s was never reached: %v", want, seen)
		}
	}
}

func TestAnObjectNameWithAnyShapeIsReachable(t *testing.T) {
	// Each of these breaks a different naive escaping: a slash is read as
	// a path separator, a space is invalid in a URL, and a percent starts
	// an escape sequence.
	st := slashyStore(t)
	handler := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)
	for _, name := range []string{"boot/efi", "tank/photos", "odd name", "100%"} {
		href := objectHref("mounts", name)
		rr := get(t, handler, href)
		if rr.Code != http.StatusOK {
			t.Errorf("%q -> %s -> %d", name, href, rr.Code)
			continue
		}
		if !strings.Contains(markup(rr.Body.String()), esc(name)) {
			t.Errorf("%q resolved to a page that is not it", name)
		}
	}
}

func TestTheRootMountIsReachable(t *testing.T) {
	// The most important mount on every host is named "/". Go's ServeMux
	// refuses a path segment that decodes to exactly "/", so
	// percent-escaping got `/boot/efi` through and could not get `/`
	// through at all — its neighbours worked and it 404'd. A special
	// case for that one name would fix the instance and leave the class,
	// so the name moved out of the path entirely.
	st := openStore(t)
	mustIssue(t, st, "mounts", "sha256:m",
		`{"schema":"se.declaration/1","collector":"storage","collections":[{
		  "name":"mounts","freshness":"1h","prefix":"mount","answer":["Source"],
		  "facts":{"Source":{"type":"string","temperament":"configuration"}}}]}`)
	// The real shapes from a live host, root first.
	objects := []store.Object{
		{ID: "mount:/", Name: "/", Type: "mount",
			Facts: json.RawMessage(`{"Source":"/dev/vda1"}`), At: 10},
		{ID: "mount://boot/efi", Name: "/boot/efi", Type: "mount",
			Facts: json.RawMessage(`{"Source":"/dev/vda15"}`), At: 10},
	}
	if _, err := st.ApplyCommit("mounts", store.HostNative, 1, "b1", fakeBootID,
		objects); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)
	for _, name := range []string{"/", "/boot/efi"} {
		rr := get(t, handler, objectHref("mounts", name))
		if rr.Code != http.StatusOK {
			t.Fatalf("mount %q -> %s -> %d", name, objectHref("mounts", name), rr.Code)
		}
	}
	// And the crawl reaches them from the table, which is the only route
	// a person has.
	page := markup(get(t, handler, "/collections/mounts").Body.String())
	for _, m := range hrefRE.FindAllStringSubmatch(page, -1) {
		if !strings.HasPrefix(m[1], "/collections/mounts/object") {
			continue
		}
		if rr := get(t, handler, m[1]); rr.Code != http.StatusOK {
			t.Fatalf("a row links to %s which answers %d", m[1], rr.Code)
		}
	}
}

func TestAnObjectShowsEdgesPointingAtItAsWellAsFromIt(t *testing.T) {
	// The owner's words: "most relationships don't appear to be shown."
	// They were all there. relationsSection read Relations(collection)
	// and matched only the SOURCE, so an edge was visible from one end
	// and one collection only — an md array's page read "This object
	// asserts no relations" while every member device asserted
	// `member-of` pointing straight at it.
	st := openStore(t)
	mustIssue(t, st, "arrays", "sha256:a",
		`{"schema":"se.declaration/1","collector":"storage","collections":[{
		  "name":"arrays","freshness":"1h","prefix":"array","answer":[],
		  "facts":{}}]}`)
	if _, err := st.ApplyCommit("arrays", store.HostNative, 1, "b1", fakeBootID,
		[]store.Object{{ID: "array:md126", Name: "md126", Type: "raid1",
			Facts: json.RawMessage(`{}`), At: 10}}); err != nil {
		t.Fatal(err)
	}
	// The edge is asserted BY block-devices, ABOUT the array — a
	// different collection at each end, which is the ordinary shape.
	mustIssue(t, st, "block-devices", "sha256:b",
		`{"schema":"se.declaration/1","collector":"storage","collections":[{
		  "name":"block-devices","freshness":"1h","prefix":"block-device",
		  "answer":[],"facts":{},
		  "relations":[{"type":"member-of","kind":"array"}]}]}`)
	if _, err := st.ApplyCommit("block-devices", store.HostNative, 1, "b2",
		fakeBootID, []store.Object{{ID: "block-device:loop2", Name: "loop2",
			Type: "disk", Facts: json.RawMessage(`{}`), At: 10}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyAssertions("block-devices", store.HostNative,
		[]store.Assertion{{
			Collection: "block-devices", SourceName: "loop2", Type: "member-of",
			Vantage: "block-devices", TargetKind: "array", TargetName: "md126",
		}},
		map[string]store.RelationType{"member-of": {}},
		func(kind, name string) (string, bool) { return "array:" + name, true },
		func(string, string, string) (json.RawMessage, bool) { return nil, false },
	); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(st, func() float64 { return 26.0 }, fakeBootID)
	// The ARRAY's page — the end that asserts nothing — must show it.
	page := markup(get(t, handler, objectHref("arrays", "md126")).Body.String())
	if strings.Contains(page, "Nothing asserts an edge") {
		t.Fatalf("the array's page denies an edge that points straight at "+
			"it: %s", visible(page))
	}
	if !strings.Contains(page, "loop2") {
		t.Fatalf("the member device must be named on the array's page: %s",
			visible(page))
	}
	// And it must be FOLLOWABLE, to the collection that holds the source
	// rather than to this object's own.
	if !strings.Contains(page, objectHref("block-devices", "loop2")) {
		t.Fatalf("an inbound edge must link to its source, in the source's "+
			"own collection: %s", page)
	}
	// The disk's page still shows the outbound edge.
	disk := markup(get(t, handler, objectHref("block-devices", "loop2")).Body.String())
	if !strings.Contains(disk, "md126") {
		t.Fatalf("the outbound direction must not be lost: %s", visible(disk))
	}
	// The two directions are DISTINGUISHED — "what is this made of" and
	// "what depends on this" are different questions.
	if !strings.Contains(page, "from elsewhere") {
		t.Fatalf("an inbound edge is labelled as such: %s", visible(page))
	}
}

func TestOneContestedPrefixDoesNotBlankEveryLink(t *testing.T) {
	// The estate's own declarations contain a clash: `units` and
	// `workloads` both declare the prefix `unit`. collectionOfPrefix used
	// store.PrefixIndex, which refuses the WHOLE index when any prefix is
	// contested — so on every host running both collectors, every
	// relation target on every object page rendered as dead text, and the
	// page blamed a prefix that was very often not the one in question.
	//
	// It is the same defect the apply path had and the same fix: one bad
	// thing must not cost the host its other facts.
	// Driven through collectionOfPrefix with a REAL store carrying the
	// clash. The first version of this test called prefixIndexTolerant
	// directly — the helper, not the caller — so planting the strict
	// index back into collectionOfPrefix changed nothing and the test
	// stayed green. A guard must test its subject, not a copy of it.
	st := openStore(t)
	mustIssue(t, st, "units", "sha256:u",
		`{"schema":"se.declaration/1","collector":"units","collections":[{
		  "name":"units","freshness":"1h","prefix":"unit","facts":{}}]}`)
	mustIssue(t, st, "workloads", "sha256:w",
		`{"schema":"se.declaration/1","collector":"resources","collections":[{
		  "name":"workloads","freshness":"1h","prefix":"unit","facts":{}}]}`)
	mustIssue(t, st, "block-devices", "sha256:b",
		`{"schema":"se.declaration/1","collector":"storage","collections":[{
		  "name":"block-devices","freshness":"1h","prefix":"block-device",
		  "facts":{}}]}`)
	owner, contested, err := collectionOfPrefix(st)
	if err != nil {
		t.Fatal(err)
	}
	// The uncontested prefixes still resolve, which is the whole point.
	linked := targetLink(owner, contested, store.Relation{
		Resolved: true, TargetID: "block-device:sda",
		TargetKind: "block-device", TargetName: "sda"})
	if !strings.Contains(linked, "<a ") {
		t.Fatalf("one clash must not cost every other prefix its links: %s",
			linked)
	}
	// A contested prefix OFFERS EVERY CLAIMANT. `units` and `workloads`
	// both declare `unit` and both are right — one describes what a unit
	// is doing, the other what it is consuming, about the same objects.
	// Saying "resolves to neither" and stopping withholds two
	// destinations the page is holding.
	blocked := targetLink(owner, contested, store.Relation{
		Resolved: false, TargetID: "", TargetKind: "unit",
		TargetName: "cron.service"})
	for _, want := range []string{
		objectHref("units", "cron.service"),
		objectHref("workloads", "cron.service"),
	} {
		if !strings.Contains(blocked, want) {
			t.Fatalf("every claimant must be offered: %s missing from %s",
				want, blocked)
		}
	}
	// It offers them; it does not CHOOSE. Neither claimant is presented
	// as the answer.
	if strings.Contains(blocked, ">cron.service</a>") {
		t.Fatalf("the target must not be linked as though one claimant "+
			"were the answer: %s", blocked)
	}
	// And a genuinely unclaimed prefix keeps its own, different message.
	unknown := targetLink(owner, contested, store.Relation{
		Resolved: true, TargetID: "mystery:x", TargetKind: "mystery",
		TargetName: "x"})
	if !strings.Contains(unknown, "no collection on this host declares") {
		t.Fatalf("%s", unknown)
	}
}
