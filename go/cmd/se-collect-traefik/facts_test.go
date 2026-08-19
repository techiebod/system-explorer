package main

import (
	"strings"
	"testing"
)

func decode(t *testing.T, text string) *value {
	t.Helper()
	document, err := decodeDocument([]byte(text))
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	return document
}

func factsOf(t *testing.T, v *value) string {
	t.Helper()
	return string(v.encode())
}

// A file-provider server URL can carry basic-auth, and Servers, DownServers and
// the evidence payload all reach unauthenticated pollers. The marker is kept so
// the withholding is visible — redaction that hid its own existence would
// invert the provenance contract.
func TestBackendUserinfoIsStrippedAndTheWithholdingIsVisible(t *testing.T) {
	cases := map[string]string{
		"http://user:pass@backend.invalid:8080/health": "http://" + redactedMarker + "@backend.invalid:8080/health",
		"http://token@backend.invalid":                 "http://" + redactedMarker + "@backend.invalid",
		"https://u:p@backend.invalid:443/?a=1#f":       "https://" + redactedMarker + "@backend.invalid:443/?a=1#f",
		// An at-sign in the PATH is not userinfo: urlsplit's netloc ends at the
		// first slash, and rewriting past it would corrupt a legitimate URL.
		"http://backend.invalid/mail@host": "http://backend.invalid/mail@host",
		// Nothing to strip, byte for byte.
		"http://172.19.0.4:8080": "http://172.19.0.4:8080",
		// No authority at all: urlsplit's netloc is empty, so there is no
		// userinfo to find however many at-signs the string carries.
		"unix:///var/run/app.sock@2": "unix:///var/run/app.sock@2",
		// A scheme-relative URL still has an authority, and a walk that only
		// looked for "://" would leak the credential in it.
		"//user:pass@backend.invalid/x": "//" + redactedMarker + "@backend.invalid/x",
	}
	for original, want := range cases {
		if got := redactURLUserinfo(stringValue(original)).text; got != want {
			t.Errorf("%q redacted to %q, want %q", original, got, want)
		}
	}
}

// The fold that turns Traefik's health map into a row. A green router over
// ServersUp 0 is a front door onto nothing, and this is the only place in the
// product where that shows — so the counts, the sorted down list and the
// redaction all have to hold together.
func TestTheHealthMapFoldsToCountsAndTheDownBackendsByName(t *testing.T) {
	facts, err := serviceFacts(decode(t, `{
		"name": "app@file", "provider": "file", "status": "enabled",
		"type": "loadbalancer",
		"usedBy": ["app@file"],
		"loadBalancer": {"servers": [
			{"url": "http://172.19.0.5:8080"},
			{"url": "http://user:pass@172.19.0.4:8080"},
			{"url": "http://172.19.0.6:8080"}
		]},
		"serverStatus": {
			"http://172.19.0.5:8080": "DOWN",
			"http://user:pass@172.19.0.4:8080": "UP",
			"http://172.19.0.6:8080": "MAINTENANCE"
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got := factsOf(t, facts)
	for _, want := range []string{
		`"ServersUp":1`,
		`"ServersDown":2`,
		// Sorted, so two runs of one document read the same, and redacted, so
		// the credential does not travel on the fact either.
		`"DownServers":["http://172.19.0.5:8080","http://172.19.0.6:8080"]`,
		`"Servers":["http://172.19.0.5:8080","http://` + redactedMarker + `@172.19.0.4:8080","http://172.19.0.6:8080"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("row does not carry %s:\n%s", want, got)
		}
	}
	// Anything that is not UP is down. Traefik reports UP and DOWN today, and a
	// third word this collector has never met must not be counted as healthy by
	// default — which is the direction that reports a broken backend as fine.
	if strings.Contains(got, "MAINTENANCE") && !strings.Contains(got, `"ServersDown":2`) {
		t.Errorf("a state that is not UP was counted as up:\n%s", got)
	}
}

// A service with no health map says nothing about backend health rather than
// claiming zero of them: the three counts are absent, not zeroed, because "no
// map" and "a map with nothing up" are different statements.
func TestAServiceWithNoHealthMapCarriesNoCounts(t *testing.T) {
	facts, err := serviceFacts(decode(t, `{"name":"noop@internal","provider":"internal","status":"enabled"}`))
	if err != nil {
		t.Fatal(err)
	}
	got := factsOf(t, facts)
	for _, absent := range []string{"ServersUp", "ServersDown", "DownServers", "Servers", "Type", "UsedBy"} {
		if strings.Contains(got, absent) {
			t.Errorf("row carries %s, and the document states none of it: %s", absent, got)
		}
	}
	if got != `{"Provider":"internal","Status":"enabled"}` {
		t.Errorf("an internal service's whole row is its provider and its status; got %s", got)
	}
}

// A server carrying neither member would put a null INSIDE the Servers list,
// one level below where a top-level sweep looks — which is exactly where a
// marshalled struct with a nil field puts one, and the judge refuses a null
// fact at any depth. No provider writes one, so this is "I could not run"
// rather than a row with a hole in it.
func TestAServerWithNoAddressRefusesToRunRatherThanNullingTheList(t *testing.T) {
	_, err := serviceFacts(decode(t, `{"name":"app@file","loadBalancer":{"servers":[{"weight":1}]}}`))
	if err == nil {
		t.Fatal("a server with neither a url nor an address produced a row")
	}
	if !strings.Contains(err.Error(), "url") {
		t.Errorf("the refusal must say what was missing: %v", err)
	}
}

// Traefik's error member is a list of strings and that is what every version of
// the API emits. A bare string is accepted because the reference's `str()` arm
// exists for it; anything else would take Python's own repr, which is not a
// rendering this side can reproduce, so it is refused rather than guessed at.
func TestTheErrorListIsCarriedWholeAndAStringIsWrapped(t *testing.T) {
	facts, err := routerFacts(decode(t, `{"name":"broken@file","rule":"x","service":"s","provider":"file","status":"disabled","error":["one","two"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(factsOf(t, facts), `"Error":["one","two"]`) {
		t.Errorf("the list is carried whole: %s", factsOf(t, facts))
	}

	facts, err = routerFacts(decode(t, `{"name":"broken@file","rule":"x","service":"s","provider":"file","status":"disabled","error":"one"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(factsOf(t, facts), `"Error":["one"]`) {
		t.Errorf("a bare string is wrapped: %s", factsOf(t, facts))
	}

	if _, err := routerFacts(decode(t, `{"name":"x","error":{"why":"no"}}`)); err == nil {
		t.Error("an error member that is neither a list nor a string was rendered anyway")
	}
}

// The TLS block's PRESENCE is the fact: Traefik writes an empty one for a
// router that terminates with every option defaulted, so a row saying true with
// no CertResolver beside it is using a certificate the deployment supplied.
func TestTheTlsBlocksPresenceIsTheFactAndTheResolverIsSeparate(t *testing.T) {
	cases := map[string]string{
		`{"name":"a","tls":{}}`:                              `{"EntryPoints":[],"Tls":true}`,
		`{"name":"a","tls":{"certResolver":"lab"}}`:          `{"EntryPoints":[],"Tls":true,"CertResolver":"lab"}`,
		`{"name":"a","tls":{"options":"default"}}`:           `{"EntryPoints":[],"Tls":true}`,
		`{"name":"a"}`:                                       `{"EntryPoints":[]}`,
		// Null is not a block, and it is not a false either: the reference's
		// isinstance test refuses it, so the row says nothing about TLS.
		`{"name":"a","tls":null}`: `{"EntryPoints":[]}`,
	}
	for document, want := range cases {
		facts, err := routerFacts(decode(t, document))
		if err != nil {
			t.Fatal(err)
		}
		if got := factsOf(t, facts); got != want {
			t.Errorf("%s -> %s, want %s", document, got, want)
		}
	}
}

// A priority of 0 is the bottom of the evaluation order, not an absence of one
// — the reference's test is `is not None` rather than truthiness, and a port
// that used the same `if x:` it uses everywhere else would drop it.
func TestAZeroPriorityIsPublishedAndAMissingOneIsNot(t *testing.T) {
	facts, err := routerFacts(decode(t, `{"name":"a","priority":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(factsOf(t, facts), `"Priority":0`) {
		t.Errorf("a zero priority was dropped: %s", factsOf(t, facts))
	}
	facts, _ = routerFacts(decode(t, `{"name":"a"}`))
	if strings.Contains(factsOf(t, facts), "Priority") {
		t.Errorf("a priority the document does not state was invented: %s", factsOf(t, facts))
	}
}

// A router mounted on nothing publishes the empty list, which is the
// reference's `or []` — distinct from a member it never carried, and distinct
// from a null. An empty list here is a route that exists and can never be
// reached, which is a statement worth making.
func TestARouterWithNoEntrypointsPublishesTheEmptyList(t *testing.T) {
	for _, document := range []string{`{"name":"a"}`, `{"name":"a","entryPoints":[]}`, `{"name":"a","entryPoints":null}`} {
		facts, err := routerFacts(decode(t, document))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(factsOf(t, facts), `"EntryPoints":[]`) {
			t.Errorf("%s -> %s", document, factsOf(t, facts))
		}
	}
}

// A count the document states as zero is a reading and must be published; the
// reference's test is membership, not truthiness, and RoutersErrors 0 is the
// figure an operator watches.
func TestZeroCountsArePublishedAndAbsentFamiliesAreNot(t *testing.T) {
	facts, err := overviewFacts(
		decode(t, `{"http":{"routers":{"total":0,"warnings":0,"errors":0}}}`),
		decode(t, `{"Version":"3.1.7"}`),
		decode(t, `[]`),
	)
	if err != nil {
		t.Fatal(err)
	}
	got := factsOf(t, facts)
	if got != `{"Version":"3.1.7","RoutersTotal":0,"RoutersErrors":0,"RoutersWarnings":0}` {
		t.Fatalf("zero counts are readings and an absent family says nothing; got %s", got)
	}
}

// The name is what the collator keys the object on, so a row cannot be
// published under one this side invented — and Traefik's own fallback for a
// nameless entry is the reference's, spelled once.
func TestANamelessEntryTakesTheReferencesFallback(t *testing.T) {
	name, err := routeName(decode(t, `{}`))
	if err != nil || name != unnamed {
		t.Fatalf("name %q, err %v", name, err)
	}
	if _, err := routeName(decode(t, `{"name": 7}`)); err == nil {
		t.Error("a row was named with something that is not a string")
	}
}
