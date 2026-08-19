package main

import (
	"strings"
	"testing"
)

// decode is the staged document as this collector reads it, so a test can state
// the shape it is about rather than the whole payload set.
func decode(t *testing.T, text string) *value {
	t.Helper()
	document, err := decodeDocument([]byte(text))
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	return document
}

func encodeFacts(t *testing.T, build func(*value, *value), raw string) string {
	t.Helper()
	facts := newObject()
	build(decode(t, raw), facts)
	return string(facts.encode())
}

// The falsy-but-STATED shapes, which are where a port and the reference most
// easily part company: Python's truth test and Python's `is not None` are
// different questions, and the reference asks each of them in a different place.
func TestFalsyMembersAreReadTheWayTheReferenceReadsThem(t *testing.T) {
	cases := []struct {
		what string
		raw  string
		want string
	}{
		{
			// `if raw.get("refreshing") is not None` — presence, not truth. A
			// section stating 0 is a section that is not scanning.
			what: "refreshing 0 is the boolean false, published",
			raw:  `{"key":"1","title":"Movies","type":"movie","refreshing":0}`,
			want: `{"Title":"Movies","Type":"movie","Refreshing":false}`,
		},
		{
			what: "refreshing null is not stated at all, so no fact",
			raw:  `{"key":"1","title":"Movies","type":"movie","refreshing":null}`,
			want: `{"Title":"Movies","Type":"movie"}`,
		},
		{
			// `isinstance(value, int) and value > 0` — a zero stamp is Plex saying
			// the section has never been scanned, which is an absence and not the
			// epoch.
			what: "a zero scan stamp is an absence rather than 1970",
			raw:  `{"key":"1","title":"Movies","type":"movie","scannedAt":0,"updatedAt":1787141574}`,
			want: `{"Title":"Movies","Type":"movie","UpdatedAt":"2026-08-19T12:12:54Z"}`,
		},
		{
			what: "a fractional stamp is not an int and is not published",
			raw:  `{"key":"1","title":"Movies","type":"movie","scannedAt":1787141586.0}`,
			want: `{"Title":"Movies","Type":"movie"}`,
		},
	}
	for _, one := range cases {
		if got := encodeFacts(t, libraryFacts, one.raw); got != one.want {
			t.Errorf("%s:\n got %s\nwant %s", one.what, got, one.want)
		}
	}
}

// `if container.get(member):` — a member the server stated as the empty string
// says it has no name, and publishing "" would put a blank where every client
// shows a word.
func TestABlankServerMemberIsNoFactRatherThanAnEmptyOne(t *testing.T) {
	got := encodeFacts(t, serverFacts,
		`{"MediaContainer":{"friendlyName":"","version":"1.43.3","platform":""}}`)
	if got != `{"Version":"1.43.3"}` {
		t.Fatalf("got %s", got)
	}
	// A document with no container at all yields nothing, which is a reading of a
	// server answering something this collector does not recognise.
	if got := encodeFacts(t, serverFacts, `{"other":1}`); got != `{}` {
		t.Fatalf("got %s", got)
	}
}

// The count gate is `isinstance(size, int)`, so a container that stated no size,
// or stated it as a float, publishes no count — which is different from a count
// of zero, and the difference is the whole reason SessionCount exists.
func TestTheStreamCountIsPublishedOnlyWhereTheDocumentStatesAnInteger(t *testing.T) {
	if got := encodeFacts(t, sessionCount, `{"MediaContainer":{"size":0}}`); got != `{"SessionCount":0}` {
		t.Errorf("zero is a reading: %s", got)
	}
	if got := encodeFacts(t, sessionCount, `{"MediaContainer":{}}`); got != `{}` {
		t.Errorf("no size stated, no count: %s", got)
	}
	if got := encodeFacts(t, sessionCount, `{"MediaContainer":{"size":2.0}}`); got != `{}` {
		t.Errorf("a float is not an int to the reference: %s", got)
	}
	// The token survives: a big count is the integer the document spelled.
	if got := encodeFacts(t, sessionCount, `{"MediaContainer":{"size":9007199254740993}}`); got != `{"SessionCount":9007199254740993}` {
		t.Errorf("a number was re-rendered through a float64: %s", got)
	}
}

// `totalSize`, never `size`. Under the zero-size container window `size` is 0 by
// construction, so a port that read it publishes 0 for every section — the
// emptied-library shape, manufactured.
func TestTheItemCountReadsTotalSizeAndNotSize(t *testing.T) {
	if got := encodeFacts(t, itemCount, `{"MediaContainer":{"size":0,"totalSize":2}}`); got != `{"ItemCount":2}` {
		t.Fatalf("got %s", got)
	}
	// A genuinely empty section states totalSize 0, and that is a reading worth
	// publishing: it is the emptied-library shape itself.
	if got := encodeFacts(t, itemCount, `{"MediaContainer":{"size":0,"totalSize":0}}`); got != `{"ItemCount":0}` {
		t.Fatalf("got %s", got)
	}
	if got := encodeFacts(t, itemCount, `{"MediaContainer":{"size":0}}`); got != `{}` {
		t.Fatalf("a container that stated no total states no count: %s", got)
	}
}

// The session key is `sessionKey or ratingKey`, and Python's `or` falls through
// on a FALSY left-hand side rather than a missing one — so a session stating 0
// takes the rating key, and one stating neither is a row this collector cannot
// name and does not publish.
func TestASessionIsNamedByItsKeyWithTheReferencesFallThrough(t *testing.T) {
	cases := []struct {
		raw   string
		name  string
		named bool
	}{
		{`{"sessionKey":"41","ratingKey":"9001"}`, "41", true},
		{`{"ratingKey":"9002"}`, "9002", true},
		{`{"sessionKey":0,"ratingKey":77}`, "77", true},
		{`{"sessionKey":0}`, "", false},
		{`{"sessionKey":null,"ratingKey":null}`, "", false},
		{`{}`, "", false},
		// Stated and falsy with no fall-back is still stated: `"" or None` is
		// None, but `""` with no ratingKey member at all is what the reference
		// keeps, because `.get` answers None and `is None` is the test.
		{`{"sessionKey":"","ratingKey":"5"}`, "5", true},
	}
	for _, one := range cases {
		name, named := sessionName(decode(t, one.raw))
		if named != one.named || name != one.name {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", one.raw, name, named, one.name, one.named)
		}
	}
}

// An episode titles itself with its series and a film keeps its own name; every
// other member is lifted only where the document states it truthily, so a
// stream the server is not transcoding says nothing about a decision rather than
// claiming a direct play it did not report.
func TestASessionRowIsWhatIsPlayingAndWhoIsWatching(t *testing.T) {
	episode := encodeFacts(t, sessionFacts,
		`{"title":"Pilot","grandparentTitle":"Example Series","type":"episode",`+
			`"User":{"title":"example-viewer"},"Player":{"product":"Plex Web","state":"buffering"},`+
			`"TranscodeSession":{"videoDecision":"transcode"}}`)
	want := `{"Title":"Example Series — Pilot","Type":"episode","User":"example-viewer",` +
		`"Player":"Plex Web","State":"buffering","VideoDecision":"transcode"}`
	if episode != want {
		t.Errorf("\n got %s\nwant %s", episode, want)
	}

	film := encodeFacts(t, sessionFacts, `{"title":"Example Film","type":"movie"}`)
	if film != `{"Title":"Example Film","Type":"movie"}` {
		t.Errorf("a film with no grandparent keeps its own name: %s", film)
	}
	// An empty grandparent is no grandparent — the reference's test is
	// truthiness — so the title is not prefixed with a dash and a blank.
	blank := encodeFacts(t, sessionFacts, `{"title":"Example Film","grandparentTitle":"","type":"movie"}`)
	if strings.Contains(blank, "—") {
		t.Errorf("an empty grandparent produced a dangling separator: %s", blank)
	}
	// A row the document said nothing about carries nothing, and never a null.
	if bare := encodeFacts(t, sessionFacts, `{}`); bare != `{}` {
		t.Errorf("got %s", bare)
	}
}

// The stem is the replay shim's slug(), and the four requests this collector
// makes are what the corpus commits under.
func TestThePayloadStemIsTheShimsSlug(t *testing.T) {
	cases := map[string]string{
		pathRoot:                   "root",
		pathSessions:               "status-sessions",
		pathSections:               "library-sections",
		sectionWindowPath("1"):     "library-sections-1-all",
		sectionWindowPath("3"):     "library-sections-3-all",
		sectionWindowPath("cover"): "library-sections-cover-all",
	}
	for path, want := range cases {
		if got := payloadStem(path); got != want {
			t.Errorf("%q slugs to %q, want %q", path, got, want)
		}
	}
}
