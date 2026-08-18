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

// Exit 2 is "I could not run", with a stderr line saying why — never a
// silent exit and never a decline, because a request this side cannot parse
// genuinely was not run (DESIGN 18).
func TestMalformedRequestsExitTwoWithAStderrLine(t *testing.T) {
	cases := map[string]string{
		"empty request":                 "",
		"blank line":                    "\n",
		"whitespace only":               "   \n",
		"unknown verb":                  "frobnicate\n",
		"collect with no collections":   "collect\n",
		"token without a generation":    "collect pools\n",
		"token with an empty gen":       "collect pools:\n",
		"token with a non-integer gen":  "collect pools:abc\n",
		"token with a signed gen":       "collect pools:-1\n",
		"token with a plus-signed gen":  "collect pools:+5\n",
		"token with only a generation":  "collect :5\n",
		"an unecho-able uppercase name": "collect Pools:5\n",
		"a colon-bearing name":          "collect a:b:5\n",
		"one collection, two gens":      "collect pools:1 pools:2\n",
		"declare with arguments":        "declare now\n",
		"probe with arguments":          "probe hard\n",
	}
	for label, request := range cases {
		code, stdout, stderr := runWith(t, request, nil)
		if code != exitRequest {
			t.Errorf("%s: exit %d, want %d", label, code, exitRequest)
		}
		if stdout != "" {
			t.Errorf("%s: a request that was never run emits no stream; got %q", label, stdout)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Errorf("%s: exit 2 with no stderr line is indistinguishable from a crash", label)
		}
	}
}

// The generation is everything after the LAST colon: names in this product
// legitimately contain them, and the collection is what begin must echo.
func TestParseCollectSplitsOnTheLastColon(t *testing.T) {
	order, generations, err := parseCollect([]string{"pools:458"})
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 1 || order[0] != "pools" || generations["pools"] != 458 {
		t.Fatalf("got %v / %v", order, generations)
	}
}

// A request line larger than the bound is refused before any token is
// interpreted, so an unbounded line cannot become an unbounded parse.
func TestAnOversizedRequestLineIsRefusedWhole(t *testing.T) {
	code, _, stderr := runWith(t, "collect "+strings.Repeat("a", requestBound)+":1\n", nil)
	if code != exitRequest || !strings.Contains(stderr, "bound") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}
