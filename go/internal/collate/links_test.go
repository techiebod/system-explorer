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
