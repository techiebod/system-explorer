package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A live source pointed at a test server. `stamped` is pre-set because the
// clock is the one part of the live path that is Linux-only — CLOCK_BOOTTIME
// exists nowhere else — and the reading under test here is the HTTP half. The
// clock's own rule (taken once per collection, before the first read) is
// asserted by the seam test that reaches it through the source interface.
func liveAgainst(t *testing.T, handler http.Handler) (*liveSource, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &liveSource{url: server.URL, client: server.Client(), stamped: true}, server
}

// The pagination loop the reference documents and no capture can exercise: the
// API slices a listing at 100 and signals continuation ONLY through
// X-Next-Page, so a single-page fetch past 100 routers would render absence as
// a complete healthy listing — an operator reading a route map that silently
// stops, with evidence 404ing on routes Traefik is serving.
func TestAListEndpointIsFollowedToItsLastPage(t *testing.T) {
	var asked []string
	src, _ := liveAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.RequestURI())
		switch r.URL.Query().Get("page") {
		case "1":
			w.Header().Set(nextPageHeader, "2")
			fmt.Fprint(w, `[{"name":"a@file"},{"name":"b@file"}]`)
		case "2":
			// 1 is what Traefik answers on the last page, not an absent header.
			w.Header().Set(nextPageHeader, "1")
			fmt.Fprint(w, `[{"name":"c@file"}]`)
		default:
			t.Errorf("asked for page %q, which the walk should never reach", r.URL.Query().Get("page"))
		}
	}))

	document, err := src.list(pathRouters)
	if err != nil {
		t.Fatal(err)
	}
	if document.kind != jsonArray || len(document.items) != 3 {
		t.Fatalf("every page's items, concatenated in order; got %d", len(document.items))
	}
	if document.items[2].get("name").text != "c@file" {
		t.Fatalf("the second page's rows are missing: %v", document.items)
	}
	want := []string{
		pathRouters + "?page=1&per_page=100",
		pathRouters + "?page=2&per_page=100",
	}
	if len(asked) != 2 || asked[0] != want[0] || asked[1] != want[1] {
		t.Fatalf("the walk asked %v, want %v", asked, want)
	}
}

// The two exits the reference takes, and neither is "the header is missing".
func TestThePageWalkStopsWhereTheReferenceStops(t *testing.T) {
	cases := map[string]string{
		"the last page answers 1":       "1",
		"a header that does not advance": "0",
		"a header this side cannot read": "soon",
		"no header at all":               "",
	}
	for label, header := range cases {
		pages := 0
		src, _ := liveAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pages++
			if header != "" {
				w.Header().Set(nextPageHeader, header)
			}
			fmt.Fprint(w, `[{"name":"a@file"}]`)
		}))
		if _, err := src.list(pathServices); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if pages != 1 {
			t.Errorf("%s: the walk asked for %d pages", label, pages)
		}
	}
}

// An endpoint that keeps promising another page holds the sweep forever in the
// reference, whose loop advances while the header advances. The port bounds it
// and says "I could not run" — a listing cut in half reads as a complete one,
// which is the outcome the walk exists to prevent.
func TestAnEndlessListingIsRefusedRatherThanFollowedForever(t *testing.T) {
	pages := 0
	src, _ := liveAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages++
		w.Header().Set(nextPageHeader, fmt.Sprint(pages+1))
		fmt.Fprint(w, `[{"name":"a@file"}]`)
	}))
	document, err := src.list(pathRouters)
	if err == nil {
		t.Fatalf("the walk followed %d pages and returned %d rows", pages, len(document.items))
	}
	// The bound is checked before the request, so the last page fetched is the
	// bound itself — the refusal costs no extra round trip.
	if pages != pageBound {
		t.Errorf("the walk fetched %d pages, and the bound is %d", pages, pageBound)
	}
	var refused *declined
	if errors.As(err, &refused) {
		t.Errorf("running past the bound is not a statement about a machine: %v", refused)
	}
}

// `_get` sends no page parameters: the overview, the version and the
// entrypoints are single documents, and a query string this side invented would
// be a request the reference never makes.
func TestASingleDocumentIsFetchedWithoutPageParameters(t *testing.T) {
	var asked string
	src, _ := liveAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.RequestURI()
		fmt.Fprint(w, `{"Version":"3.1.7"}`)
	}))
	if _, err := src.document(pathVersion); err != nil {
		t.Fatal(err)
	}
	if asked != pathVersion {
		t.Fatalf("asked %q, want %q", asked, pathVersion)
	}
}

// The three non-absent readings, each mapped where it is distinguishable. Only
// absence commits, so getting this wrong in the other direction retires a live
// ingress map over a proxy restart.
func TestTheLiveDeclinesAreMappedToWhatActuallyHappened(t *testing.T) {
	cases := []struct {
		label  string
		status int
		want   declined
	}{
		{"a refusal in front of the dashboard", http.StatusUnauthorized, declineAPIRefused},
		{"a proxy that forbids the API", http.StatusForbidden, declineAPIRefused},
		{"a gateway with nothing behind it", http.StatusBadGateway, declineAPISilent},
		{"a status this collector cannot read", http.StatusNotFound, declineAPISilent},
	}
	for _, one := range cases {
		src, _ := liveAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(one.status)
		}))
		err := src.reachable()
		var refused *declined
		if !errors.As(err, &refused) {
			t.Errorf("%s: %v is not a decline at all", one.label, err)
			continue
		}
		if *refused != one.want {
			t.Errorf("%s: reached %v, want %v", one.label, *refused, one.want)
		}
		if refused.reason == "absent" {
			t.Errorf("%s: absent is the one decline that RETIRES, and something answered here", one.label)
		}
	}
}

// A configured endpoint nothing answers is `unavailable`, never absent: the
// deployment says there is a proxy here, and "I could not reach it" must not
// delete the routes it published last time.
func TestAnEndpointNothingAnswersIsUnavailableAndNeverAbsent(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	address := server.URL
	server.Close() // nothing is listening there now
	src := &liveSource{url: address, client: &http.Client{Timeout: requestTimeout}, stamped: true}

	err := src.reachable()
	var refused *declined
	if !errors.As(err, &refused) {
		t.Fatalf("%v is not a decline at all", err)
	}
	if *refused != declineAPISilent {
		t.Fatalf("reached %v, want %v", *refused, declineAPISilent)
	}
}

// Decline detail travels to a hub and out over MCP, and SE_TRAEFIK_URL is a URL
// — the one shape DESIGN 21 calls a credential channel when it carries
// userinfo. So the endpoint appears in no decline this collector emits, whatever
// the reason.
func TestNoDeclineDetailCarriesTheConfiguredEndpoint(t *testing.T) {
	const secret = "http://someone:hunter2@ingress.invalid:8080"
	for _, reason := range []declined{declineNoAPI, declineAPIRefused, declineAPISilent} {
		for _, leak := range []string{"hunter2", "ingress.invalid", secret} {
			if strings.Contains(reason.detail, leak) {
				t.Errorf("%q carries %q", reason.detail, leak)
			}
		}
	}
	// And the constants are literally constant: an interpolated detail is a
	// redaction path nobody reviewed, so nothing here is built from the URL.
	src := &liveSource{url: secret, client: &http.Client{Timeout: requestTimeout}, stamped: true}
	var refused *declined
	if err := src.reachable(); errors.As(err, &refused) && strings.Contains(refused.detail, "hunter2") {
		t.Errorf("a live decline carried the credential: %q", refused.detail)
	}
}
