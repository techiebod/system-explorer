package main

import (
	"bytes"
	"strings"
	"testing"
)

func runWith(t *testing.T, stdin string, env map[string]string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(strings.NewReader(stdin), &stdout, &stderr, func(key string) string { return env[key] })
	return code, stdout.String(), stderr.String()
}

// Exit 2 is "I could not run", with a stderr line saying why — never a silent
// exit and never a decline, because a request this side cannot parse genuinely
// was not run (DESIGN 18).
func TestMalformedRequestsExitTwoWithAStderrLine(t *testing.T) {
	cases := map[string]string{
		"empty request":                 "",
		"blank line":                    "\n",
		"whitespace only":               "   \n",
		"unknown verb":                  "frobnicate\n",
		"collect with no collections":   "collect\n",
		"token without a generation":    "collect libraries\n",
		"token with an empty gen":       "collect libraries:\n",
		"token with a non-integer gen":  "collect libraries:abc\n",
		"token with a signed gen":       "collect libraries:-1\n",
		"token with a plus-signed gen":  "collect libraries:+5\n",
		"token with only a generation":  "collect :5\n",
		"an unecho-able uppercase name": "collect Libraries:5\n",
		"a colon-bearing name":          "collect a:b:5\n",
		"one collection, two gens":      "collect server:1 server:2\n",
		"declare with arguments":        "declare now\n",
		"probe with arguments":          "probe hard\n",
		// The three verbs this collector does not serve yet. They are refused as
		// unknown rather than answered emptily: phase 3 owes object, evidence and
		// lookup, and a collector that answered them with nothing would be
		// serving a contract it does not implement (appendix C).
		"the object verb":   "object libraries 1\n",
		"the evidence verb": "evidence libraries 1\n",
		"the lookup verb":   "lookup library Movies\n",
	}
	for label, request := range cases {
		code, stdout, stderr := runWith(t, request, nil)
		if code != exitRequest {
			t.Errorf("%s (%q): exit %d, want %d", label, request, code, exitRequest)
		}
		if stderr == "" {
			t.Errorf("%s (%q): exit 2 with no stderr line tells nobody anything", label, request)
		}
		if stdout != "" {
			t.Errorf("%s (%q): a refused request must emit no stream: %q", label, request, stdout)
		}
	}
}

func TestARequestLineBeyondTheBoundIsRefused(t *testing.T) {
	long := "collect " + strings.Repeat("a", requestBound) + ":1\n"
	code, _, stderr := runWith(t, long, nil)
	if code != exitRequest || stderr == "" {
		t.Fatalf("an unbounded request line must be refused before parsing: exit %d, stderr %q", code, stderr)
	}
}

func TestOnlyTheFirstLineIsARequest(t *testing.T) {
	// Run-and-exit has no second question: everything after the first newline is
	// ignored, so a stray extra line cannot become a request.
	env := map[string]string{"SE_REPLAY_DIR": stageHealthy(t)}
	code, stdout, stderr := runWith(t, "collect server:3\ncollect server:4\n", env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if got := len(ofKind(parseRecords(t, stdout), "begin")); got != 1 {
		t.Fatalf("two requests were answered: %d begin records", got)
	}
}

// A collection this collector never published is declined, never guessed at and
// never crashed on — and unsupported does not commit, so whatever a previous
// batch published for that name stands (DESIGN 18, 19).
//
// `requests` is the name that matters here. It is seerr's collection, reached
// with a second application's credential, and this binary has never read it: a
// port that answered it — emptily or otherwise — would be answering for an
// interface nothing in this repository has ever opened.
func TestAnUnpublishedCollectionIsDeclinedUnsupportedAndNotCommitted(t *testing.T) {
	// requests held this drill's seat while it was seerr's unserved
	// collection; it is served since R3d, so the seat passes to a name this
	// collector has never published and never will.
	env := map[string]string{"SE_REPLAY_DIR": stageHealthy(t)}
	code, stdout, stderr := runWith(t, "collect watchlists:11 server:12\n", env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["collection"] != "watchlists" || declines[0]["reason"] != "unsupported" {
		t.Fatalf("expected one unsupported decline for watchlists, got %v", declines)
	}
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] == "watchlists" {
			t.Fatal("an unsupported decline established nothing and must not commit")
		}
	}
	// On a variant staging no seerr documents, the served requests
	// collection reads the capture's own receipts: unavailable, the second
	// application's absence, prior state standing.
	code, stdout, stderr = runWith(t, "collect requests:13\n", env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records = parseRecords(t, stdout)
	decline := ofKind(records, "decline")[0]
	if decline["reason"] != "unavailable" {
		t.Fatalf("%+v", decline)
	}
	if len(ofKind(records, "commit")) != 0 {
		t.Fatal("unavailable establishes nothing and must not commit")
	}
}

// The collections are served in the order the request line names them, because
// `at` advances in emission order and the collator reads the stream as it
// arrives. A map iteration here would reorder the batch between two runs of one
// payload.
func TestTheCollectionOrderIsTheRequestLines(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageHealthy(t)}
	_, stdout, _ := runWith(t, "collect sessions:1 server:2 libraries:3\n", env)
	var order []string
	for _, commit := range ofKind(parseRecords(t, stdout), "commit") {
		order = append(order, commit["collection"].(string))
	}
	want := []string{"sessions", "server", "libraries"}
	for i := range want {
		if i >= len(order) || order[i] != want[i] {
			t.Fatalf("commit order %v, want %v", order, want)
		}
	}
}
