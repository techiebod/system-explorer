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
		"token without a generation":    "collect daemon\n",
		"token with an empty gen":       "collect daemon:\n",
		"token with a non-integer gen":  "collect daemon:abc\n",
		"token with a signed gen":       "collect daemon:-1\n",
		"token with a plus-signed gen":  "collect daemon:+5\n",
		"token with only a generation":  "collect :5\n",
		"an unecho-able uppercase name": "collect Daemon:5\n",
		"a colon-bearing name":          "collect a:b:5\n",
		"one collection, two gens":      "collect daemon:1 daemon:2\n",
		"declare with arguments":        "declare now\n",
		"probe with arguments":          "probe hard\n",
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
	// Run-and-exit has no second question: everything after the first newline
	// is ignored, so a stray extra line cannot become a request.
	env := map[string]string{"SE_REPLAY_DIR": stageDaemon(t, healthyStatus, healthyStats)}
	code, stdout, stderr := runWith(t, "collect daemon:3\ncollect daemon:4\n", env)
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
func TestAnUnservedCollectionIsDeclinedUnsupportedAndNotCommitted(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageDaemon(t, healthyStatus, healthyStats)}
	code, stdout, stderr := runWith(t, "collect zones:11 daemon:12\n", env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["collection"] != "zones" || declines[0]["reason"] != "unsupported" {
		t.Fatalf("expected one unsupported decline for zones, got %v", declines)
	}
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] == "zones" {
			t.Fatal("an unsupported decline established nothing and must not commit")
		}
	}
}
