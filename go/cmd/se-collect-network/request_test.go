package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func runWith(t *testing.T, stdin string, env map[string]string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(strings.NewReader(stdin), &stdout, &stderr, func(key string) string { return env[key] })
	return code, stdout.String(), stderr.String()
}

func parseRecords(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stream), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("stream line is not JSON: %v\n%s", err, line)
		}
		records = append(records, record)
	}
	return records
}

func ofKind(records []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, r := range records {
		if r["record"] == kind {
			out = append(out, r)
		}
	}
	return out
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
		"token without a generation":    "collect nft-chains\n",
		"token with an empty gen":       "collect nft-chains:\n",
		"token with a non-integer gen":  "collect nft-chains:abc\n",
		"token with a signed gen":       "collect nft-chains:-1\n",
		"token with a plus-signed gen":  "collect nft-chains:+5\n",
		"token with only a generation":  "collect :5\n",
		"an unecho-able uppercase name": "collect Nft-Chains:5\n",
		"a name starting with a digit":  "collect 9chains:5\n",
		"a colon-bearing name":          "collect a:b:5\n",
		"one collection, two gens":      "collect nft-chains:1 nft-chains:2\n",
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
	dir := stageRuleset(t, `{"nftables":[]}`)
	code, stdout, stderr := runWith(t, "collect nft-chains:3\ncollect nft-chains:4\n",
		map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if got := len(ofKind(parseRecords(t, stdout), "begin")); got != 1 {
		t.Fatalf("two requests were answered: %d begin records", got)
	}
}

func TestTheRequestLineIsTheOnlySourceOfAGeneration(t *testing.T) {
	// The sealed payload directory encodes no variant name and holds no
	// expected stream, so a generation can only come from stdin — which is
	// what makes a baked-in constant fail on the second variant.
	dir := stageRuleset(t, `{"nftables":[]}`)
	for _, generation := range []string{"1", "103", "998", "18446744073709551615"} {
		code, stdout, stderr := runWith(t, "collect nft-chains:"+generation+"\n",
			map[string]string{"SE_REPLAY_DIR": dir})
		if code != exitOK {
			t.Fatalf("exit %d, stderr: %s", code, stderr)
		}
		// Compared as raw bytes, not through a JSON decode: a generation
		// above 2^53 loses digits the moment it passes through a float.
		if !strings.Contains(stdout, `"nft-chains":`+generation) {
			t.Fatalf("generation %s was not echoed in begin: %s", generation, stdout)
		}
		if !strings.Contains(stdout, `"generation":`+generation+`,`) {
			t.Fatalf("the commit did not echo generation %s: %s", generation, stdout)
		}
	}
}

func TestCollectionOrderIsTheRequestLines(t *testing.T) {
	dir := stageRuleset(t, `{"nftables":[]}`)
	code, stdout, stderr := runWith(t, "collect nft-rules:2 nft-chains:1\n",
		map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	commits := ofKind(parseRecords(t, stdout), "commit")
	if len(commits) != 2 || commits[0]["collection"] != "nft-rules" || commits[1]["collection"] != "nft-chains" {
		t.Fatalf("the request line's order is the batch's order; got %v", commits)
	}
}
