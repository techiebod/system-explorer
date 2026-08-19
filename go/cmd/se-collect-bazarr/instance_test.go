package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// row decodes one document pair through the whole derivation, which is what
// every case below is about: the facts a reader would see on the wire.
func row(t *testing.T, status, health string) map[string]any {
	t.Helper()
	got := reading{}
	if status != "" {
		doc, err := decodeDocument(strings.NewReader(status))
		if err != nil {
			t.Fatalf("status fixture is not a document: %v", err)
		}
		got.statusRead, got.status = true, doc
	}
	if health != "" {
		doc, err := decodeDocument(strings.NewReader(health))
		if err != nil {
			t.Fatalf("health fixture is not a document: %v", err)
		}
		got.healthRead, got.health = true, doc
	}
	var facts map[string]any
	if err := json.Unmarshal(instanceRow(got).encode(), &facts); err != nil {
		t.Fatalf("the row is not a document: %v", err)
	}
	return facts
}

// The gate the whole differential case turns on. bazarr reports "wired to
// nothing" as an EMPTY STRING, so a derivation that published a fact whenever
// the member existed would put "" on the row — which says the manager answered
// and reported no version, the opposite of what the document means.
func TestAnEmptyManagerVersionIsOmittedAndAPopulatedOneIsCarried(t *testing.T) {
	unwired := row(t, healthyStatus, healthyHealth)
	if _, present := unwired[factSonarrVersion]; present {
		t.Errorf("an empty sonarr_version must be omitted, not published: %v", unwired)
	}
	if _, present := unwired[factRadarrVersion]; present {
		t.Errorf("an empty radarr_version must be omitted, not published: %v", unwired)
	}

	wired := row(t, `{"data": {"bazarr_version": "1.6.0",
	                           "sonarr_version": "4.0.15.2941",
	                           "radarr_version": "5.27.5.10198"}}`, healthyHealth)
	if wired[factSonarrVersion] != "4.0.15.2941" || wired[factRadarrVersion] != "5.27.5.10198" {
		t.Fatalf("a populated manager version is carried verbatim: %v", wired)
	}
}

// The row's order is the derivation's, which is the reference's: the status
// members in the order status_facts walks them, then the health list. It is not
// what the judge compares — records are compared as parsed values — but the two
// streams read beside each other in a failure report, and a row that came out
// backwards would read as a different answer.
func TestTheRowKeepsTheDerivationsOrder(t *testing.T) {
	got := reading{}
	doc, err := decodeDocument(strings.NewReader(`{"data": {"bazarr_version": "1.6.0",
	                                                        "sonarr_version": "4.0.15.2941",
	                                                        "radarr_version": "5.27.5.10198"}}`))
	if err != nil {
		t.Fatal(err)
	}
	got.statusRead, got.status = true, doc
	if doc, err = decodeDocument(strings.NewReader(healthyHealth)); err != nil {
		t.Fatal(err)
	}
	got.healthRead, got.health = true, doc

	encoded := string(instanceRow(got).encode())
	want := []string{factVersion, factSonarrVersion, factRadarrVersion, factHealthIssues}
	at := 0
	for _, name := range want {
		found := strings.Index(encoded[at:], `"`+name+`"`)
		if found < 0 {
			t.Fatalf("%s is missing or out of order in %s", name, encoded)
		}
		at += found
	}
}

// The fold, and the three shapes it has to get right. bazarr does not grade its
// issues, so the mirror is whole: each entry becomes one sentence and nothing
// here decides that one of them matters more.
func TestTheHealthFoldJoinsBothHalvesAndFallsBackToWhicheverItHas(t *testing.T) {
	facts := row(t, healthyStatus, `{"data": [
	  {"object": "Missing languages profile", "issue": "You must create one."},
	  {"object": "Sonarr", "issue": null},
	  {"object": null, "issue": "Bad API key"},
	  {"object": null, "issue": null},
	  "not an entry at all"
	]}`)
	issues, _ := facts[factHealthIssues].([]any)
	want := []string{
		"Missing languages profile: You must create one.",
		"Sonarr",
		"Bad API key",
	}
	if len(issues) != len(want) {
		t.Fatalf("expected %d issues, got %v", len(want), issues)
	}
	for i, sentence := range want {
		if issues[i] != sentence {
			t.Errorf("issue %d is %q, want %q", i, issues[i], sentence)
		}
	}
}

// An empty list is a VALUE and not an absence: it is the instance raising
// nothing, which the glossary states and which is the answer an operator is
// looking for. A port that dropped it for looking empty would leave a healthy
// instance indistinguishable from one whose health endpoint was never read.
func TestAnInstanceRaisingNothingCarriesAnEmptyHealthList(t *testing.T) {
	facts := row(t, healthyStatus, `{"data": []}`)
	issues, ok := facts[factHealthIssues].([]any)
	if !ok || len(issues) != 0 {
		t.Fatalf("HealthIssues must be present and empty, got %#v", facts[factHealthIssues])
	}
}

// One issue sentence, bounded and scrubbed exactly as envelope.reason bounds
// and scrubs it: whole words, a marker where anything was dropped, and a query
// string removed wholesale — because an app that writes a URL into a health
// message writes whatever was in it.
func TestAnIssueSentenceIsBoundedAndItsQueryStringStripped(t *testing.T) {
	long := strings.Repeat("subtitle ", 80)
	facts := row(t, healthyStatus,
		`{"data": [{"object": "Provider", "issue": "`+long+`"},
		           {"object": "Provider", "issue": "GET https://example.invalid/api?apikey=deadbeefcafe failed"}]}`)
	issues, _ := facts[factHealthIssues].([]any)
	if len(issues) != 2 {
		t.Fatalf("expected two issues, got %v", issues)
	}
	first, _ := issues[0].(string)
	if len([]rune(first)) > maxReasonLength+len(" … (truncated)") {
		t.Errorf("an unbounded sentence reached the row: %d characters", len([]rune(first)))
	}
	if !strings.HasSuffix(first, "… (truncated)") {
		t.Errorf("a bounded sentence says it was bounded: %q", first)
	}
	second, _ := issues[1].(string)
	if strings.Contains(second, "deadbeefcafe") || !strings.Contains(second, "?[query-stripped]") {
		t.Errorf("a query string in a health message must be stripped wholesale: %q", second)
	}
}

// Both AttributeError arms of the reference, which are the only shapes that
// turn a reading into a could-not-read without any request failing. Neither is
// a document bazarr produces; they are here because the reference's arms are,
// and because a port that let one through would publish a row of whatever
// survived the parse.
func TestADocumentTheReferenceCouldNotFoldBecomesStatusUnobservable(t *testing.T) {
	cases := map[string]struct{ status, health, want string }{
		"a status document that is a list": {
			`[{"data": {}}]`, healthyHealth, detailUnreadable(pathStatus)},
		"a status `data` that is not a mapping": {
			`{"data": ["bazarr_version"]}`, healthyHealth, detailUnreadable(pathStatus)},
		"a health `data` that cannot be iterated": {
			healthyStatus, `{"data": 3}`, detailUnreadable(pathHealth)},
	}
	for label, want := range cases {
		facts := row(t, want.status, want.health)
		if facts[factStatusUnobservable] != want.want {
			t.Errorf("%s: StatusUnobservable is %#v, want %q", label, facts[factStatusUnobservable], want.want)
		}
	}

	// An empty or missing `data` is a READING and not a failure — the
	// reference's `raw.get("data") or {}` — so the row is published with no
	// version facts and an empty issue list.
	facts := row(t, `{"data": {}}`, `{}`)
	if facts[factStatusUnobservable] != nil {
		t.Fatalf("an empty document is a reading, not a could-not-read: %v", facts)
	}
	if issues, ok := facts[factHealthIssues].([]any); !ok || len(issues) != 0 {
		t.Fatalf("a health document with no data raises nothing: %v", facts)
	}
}

// The reference folds the status document onto the row BEFORE it asks for
// health, so an instance whose health endpoint alone went dark keeps its
// version facts and loses only its issue list. The row says both things at
// once, which is what the estate needs to see.
func TestAHealthEndpointThatWentDarkKeepsTheVersionFacts(t *testing.T) {
	doc, err := decodeDocument(strings.NewReader(healthyStatus))
	if err != nil {
		t.Fatal(err)
	}
	var facts map[string]any
	encoded := instanceRow(reading{
		statusRead:   true,
		status:       doc,
		unobservable: detailNoAnswer(pathHealth),
	}).encode()
	if err := json.Unmarshal(encoded, &facts); err != nil {
		t.Fatal(err)
	}
	if facts[factVersion] != "1.6.0" {
		t.Errorf("the version read before the failure must survive it: %v", facts)
	}
	if _, present := facts[factHealthIssues]; present {
		t.Errorf("the issue list was never read and must not be invented: %v", facts)
	}
	if facts[factStatusUnobservable] != detailNoAnswer(pathHealth) {
		t.Errorf("StatusUnobservable is %#v", facts[factStatusUnobservable])
	}
}

// A missing receipt is a row saying so, never a decline: the estate configured
// this instance, and a gap in THIS deployment is a different statement from an
// absence of the thing. Nothing is fetched, so no other fact can appear beside
// it.
func TestAMissingReceiptIsTheOnlyThingTheRowSays(t *testing.T) {
	for label, missing := range map[string][]string{
		"no key at all": {keyVariable},
		"an unfit key":  {keyProblemDetail},
	} {
		var facts map[string]any
		if err := json.Unmarshal(instanceRow(reading{configMissing: missing}).encode(), &facts); err != nil {
			t.Fatal(err)
		}
		if len(facts) != 1 {
			t.Fatalf("%s: a receipts row says one thing: %v", label, facts)
		}
		got, _ := facts[factConfigMissing].([]any)
		if len(got) != 1 || got[0] != missing[0] {
			t.Fatalf("%s: ConfigMissing is %v", label, facts[factConfigMissing])
		}
	}
}

// The receipt gate, and it is the shipping adapter's own test: a key with a
// control character or a non-ASCII rune is refused rather than sent, because a
// header value carrying one is a request-smuggling shape. The refusal names the
// VARIABLE and never the value.
func TestAKeyThatCannotTravelInAHeaderIsRefusedByName(t *testing.T) {
	cases := map[string]struct {
		key        string
		configured bool
		problem    bool
	}{
		"an ordinary hex key":    {"5cb0d1e2f3a4b5c6d7e8f90a1b2c3d4e", true, false},
		"punctuation and spaces": {"a key-with_punctuation.1", true, false},
		"a newline in the value": {"abc\ndef", false, true},
		"a NUL":                  {"abc\x00def", false, true},
		"a non-ASCII rune":       {"kéy-material", false, true},
		"a DEL":                  {"abc\x7f", false, true},
	}
	for label, want := range cases {
		src := newSource(func(key string) string {
			switch key {
			case urlVariable:
				return "http://127.0.0.1:6767"
			case keyVariable:
				return want.key
			}
			return ""
		}).(*liveSource)
		if (src.key != "") != want.configured {
			t.Errorf("%s: key configured = %v, want %v", label, src.key != "", want.configured)
		}
		if (src.keyProblem != "") != want.problem {
			t.Errorf("%s: key problem = %q, want problem = %v", label, src.keyProblem, want.problem)
		}
		if src.keyProblem != "" && strings.Contains(src.keyProblem, want.key) {
			t.Errorf("%s: the refusal repeated the key it refused to send", label)
		}
	}
}

// rstrip("/"), the reference's own: an operator who wrote a trailing slash
// addresses the same instance, and `<url>//api/system/status` is a path bazarr
// does not serve.
func TestTrailingSlashesAreStrippedFromTheConfiguredURL(t *testing.T) {
	src := newSource(func(key string) string {
		if key == urlVariable {
			return "http://127.0.0.1:6767///"
		}
		return ""
	}).(*liveSource)
	if src.url != "http://127.0.0.1:6767" {
		t.Fatalf("url is %q", src.url)
	}
}

// ── the live request, without the clock ─────────────────────────────────
//
// fetch is exercised directly rather than through instance(), because
// instance() reads CLOCK_BOOTTIME first and that is a Linux clock: driving the
// whole reading here would skip this coverage on the machine most of it is
// written on. What fetch owes is the header, the three could-not-read readings,
// and the promise that none of them carries the key or the URL.

func TestTheKeyTravelsAsAHeaderAndNowhereElse(t *testing.T) {
	const key = "se-canary-bazarr-key-do-not-log"
	var seen *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(healthyStatus))
	}))
	defer server.Close()

	src := newSource(func(name string) string {
		switch name {
		case urlVariable:
			return server.URL
		case keyVariable:
			return key
		}
		return ""
	}).(*liveSource)

	document, detail := src.fetch(pathStatus)
	if detail != "" {
		t.Fatalf("the server answered and the fetch reported %q", detail)
	}
	if seen == nil {
		t.Fatal("no request reached the server")
	}
	if seen.Header.Get(keyHeader) != key {
		t.Errorf("the key must travel as %s; headers were %v", keyHeader, seen.Header)
	}
	if seen.URL.RawQuery != "" {
		t.Errorf("the key must never reach a query string: %q", seen.URL.RawQuery)
	}
	if seen.URL.Path != pathStatus {
		t.Errorf("path %q, want %q", seen.URL.Path, pathStatus)
	}
	if got := document.get("data").get("bazarr_version"); got.text != "1.6.0" {
		t.Errorf("the answered document did not reach the caller: %#v", got)
	}
}

func TestTheThreeCouldNotReadReadingsNameTheRequestAndNothingElse(t *testing.T) {
	const key = "se-canary-bazarr-key-do-not-log"

	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer refusing.Close()
	prose := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>bazarr is starting</html>"))
	}))
	defer prose.Close()
	// A server that is closed before it is asked: a connection nobody accepts
	// is the ordinary shape of a stopped container.
	silent := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	silentURL := silent.URL
	silent.Close()

	cases := map[string]struct{ url, want string }{
		"a refusal":       {refusing.URL, detailStatusCode(pathStatus, http.StatusUnauthorized)},
		"prose, not JSON": {prose.URL, detailUnreadable(pathStatus)},
		"nothing dialled": {silentURL, detailNoAnswer(pathStatus)},
	}
	for label, want := range cases {
		src := newSource(func(name string) string {
			switch name {
			case urlVariable:
				return want.url
			case keyVariable:
				return key
			}
			return ""
		}).(*liveSource)
		_, detail := src.fetch(pathStatus)
		if detail != want.want {
			t.Errorf("%s: reading %q, want %q", label, detail, want.want)
		}
		// The reading travels to a hub and out over MCP, so it carries neither
		// the credential nor the instance's address — the URL may itself hold
		// basic-auth userinfo.
		if strings.Contains(detail, key) || strings.Contains(detail, want.url) {
			t.Errorf("%s: the could-not-read text carries a credential or an address: %q", label, detail)
		}
	}
}

// A redirect is NOT followed, and the reason is stronger than parity with
// httpx's default: Go's own policy would re-send the X-API-KEY header to
// whatever host the 302 named.
func TestARedirectIsNotFollowedWithTheKeyAttached(t *testing.T) {
	const key = "se-canary-bazarr-key-do-not-log"
	var elsewhere []*http.Request
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		elsewhere = append(elsewhere, r.Clone(r.Context()))
	}))
	defer other.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+pathStatus, http.StatusFound)
	}))
	defer redirecting.Close()

	src := newSource(func(name string) string {
		switch name {
		case urlVariable:
			return redirecting.URL
		case keyVariable:
			return key
		}
		return ""
	}).(*liveSource)
	_, detail := src.fetch(pathStatus)
	if len(elsewhere) != 0 {
		t.Fatalf("the key was re-sent to the redirect target: %v", elsewhere[0].Header)
	}
	if detail != detailStatusCode(pathStatus, http.StatusFound) {
		t.Fatalf("a redirect is a could-not-read naming its status: %q", detail)
	}
}

// A response past the bound is refused rather than parsed: a document cut in
// half parses into a row of plausible half-facts, which is the one outcome
// worse than an error.
func TestAResponsePastTheBoundIsRefusedRatherThanTrimmed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data": {"bazarr_version": "`))
		_, _ = w.Write(bytes.Repeat([]byte("1"), responseBound))
		_, _ = w.Write([]byte(`"}}`))
	}))
	defer server.Close()

	src := newSource(func(name string) string {
		switch name {
		case urlVariable:
			return server.URL
		case keyVariable:
			return "5cb0d1e2f3a4b5c6d7e8f90a1b2c3d4e"
		}
		return ""
	}).(*liveSource)
	if _, detail := src.fetch(pathStatus); detail != detailUnreadable(pathStatus) {
		t.Fatalf("reading %q", detail)
	}
}

// Acceptance item 11, at this collector's own boundary: a planted credential
// appears in no output channel. Under replay the key is never read at all — the
// seam refuses to consult the replaying machine's environment — and that is the
// case a corpus run actually takes, so it is the case pinned here.
func TestAPlantedKeyReachesNeitherStdoutNorStderr(t *testing.T) {
	const canary = "se-canary-bazarr-key-do-not-log"
	env := map[string]string{
		"SE_REPLAY_DIR": stageInstance(t, healthyStatus, healthyHealth),
		urlVariable:     "http://127.0.0.1:6767",
		keyVariable:     canary,
	}
	for _, request := range []string{"collect instance:4\n", "probe\n", "declare\n"} {
		_, stdout, stderr := runWith(t, request, env)
		if strings.Contains(stdout, canary) || strings.Contains(stderr, canary) {
			t.Fatalf("%q leaked the key: stdout %q stderr %q", request, stdout, stderr)
		}
	}
}
