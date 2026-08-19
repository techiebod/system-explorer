package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
		"empty request":                "",
		"blank line":                   "\n",
		"whitespace only":              "   \n",
		"unknown verb":                 "frobnicate\n",
		"collect with no collections":  "collect\n",
		"token without a generation":   "collect apps\n",
		"token with an empty gen":      "collect apps:\n",
		"token with a non-integer gen": "collect apps:abc\n",
		"token with a signed gen":      "collect apps:-1\n",
		"token with a plus-signed gen": "collect apps:+5\n",
		"token with only a generation": "collect :5\n",
		"an unecho-able uppercase":     "collect Apps:5\n",
		"a colon-bearing name":         "collect a:b:5\n",
		"one collection, two gens":     "collect apps:1 apps:2\n",
		"declare with arguments":       "declare now\n",
		"probe with arguments":         "probe hard\n",
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
	order, generations, err := parseCollect([]string{"apps:234", "health:251"})
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "apps" || order[1] != "health" {
		t.Fatalf("the request line's order is the emission order; got %v", order)
	}
	if generations["apps"] != 234 || generations["health"] != 251 {
		t.Fatalf("got %v", generations)
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

// One condition, one answer, both paths. The storage collector answered "the
// interface is not on this host" two opposite ways for as long as it existed —
// the live path declined `unsupported`, which never commits and leaves prior
// objects standing stale forever, and the replay path declined `absent`, which
// commits zero and retires them — with a confident comment on each side arguing
// against the other, in one file. Nothing caught it, because replay exercises
// only the replay half.
//
// So this collector spells the reading once, in a shared constant, and this
// test is what holds every path to it: the two sources, the probe, and the
// stream a collect emits.
func TestEverySourceGivesTheFleetMissingOneAnswer(t *testing.T) {
	// An empty replay directory is a staged host that fronted no fleet.
	_, replayErr := replaySource{dir: t.TempDir()}.fleet()
	var fromReplay *declined
	if !errors.As(replayErr, &fromReplay) {
		t.Fatalf("an empty replay directory is a host with no servarr: %v", replayErr)
	}
	if fromReplay.reason != declineNoInstances.reason || fromReplay.detail != declineNoInstances.detail {
		t.Fatalf("the replay path must take the shared reading, got %+v", fromReplay)
	}
	// `unavailable`, and it must NOT be the reason that commits — RULED
	// 2026-08-19, reversing what this test used to assert. An empty
	// SE_SERVARR_INSTANCES establishes that this process was not told which
	// apps to ask, not that the host fronts none; the apps may be running and
	// answering. `absent` commits zero and retires, and a configuration gap may
	// never retire an object, so prior state stands and the collator marks it
	// stale instead.
	if declineNoInstances.reason != "unavailable" {
		t.Fatalf("an unnamed fleet is a reading this process could not take, not "+
			"an establishment that the host runs no media managers, so it must "+
			"not be the reason that commits and retires; got %q",
			declineNoInstances.reason)
	}
	// The live path, with an environment that names nobody — which is every
	// machine that has not been configured for this collector.
	live := &liveSource{getenv: func(string) string { return "" }}
	apps, err := live.fleet()
	if err != nil || len(apps) != 0 {
		t.Fatalf("an unconfigured host fronts no instances; got %v, %v", apps, err)
	}
	// And the stream: the decision that turns an empty fleet into the shared
	// reading lives in one place, so both sources reach it. A decline spelled
	// here and not there is the defect this test exists for.
	code, stdout, _ := runWith(t, "collect apps:11 health:12\n",
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d", code)
	}
	for _, decline := range ofKind(parseRecords(t, stdout), "decline") {
		if decline["reason"] != declineNoInstances.reason ||
			decline["detail"] != declineNoInstances.detail {
			t.Fatalf("the stream spells the reading differently from the constant: %v", decline)
		}
	}
	// The probe answers the same question with the same words, so a probe and
	// a collect on one host cannot say different things about it.
	var verdict probeVerdict
	var out, errOut bytes.Buffer
	if probe(&out, &errOut, live) != exitOK {
		t.Fatal("a probe reports its verdict in the document, never in the exit code")
	}
	if err := json.Unmarshal(out.Bytes(), &verdict); err != nil {
		t.Fatal(err)
	}
	if verdict.Verdict != "no" || verdict.Reason != declineNoInstances.detail {
		t.Fatalf("the probe path must take the shared reading too, got %+v", verdict)
	}
}

func TestDeclareAndProbeTakeNoArgumentsAndAnswerInDocuments(t *testing.T) {
	code, stdout, stderr := runWith(t, "declare\n", nil)
	if code != exitOK || stdout != string(declarationBytes) {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	code, stdout, _ = runWith(t, "probe\n", map[string]string{
		"SE_SERVARR_INSTANCES": "radarr",
		"SE_RADARR_URL":        "http://radarr.invalid",
		"SE_RADARR_API_KEY":    "k",
	})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	// The verdict names what it established — that a fleet is configured —
	// rather than claiming a reachability it did not test.
	if !strings.Contains(stdout, "radarr") {
		t.Errorf("a verdict a person cannot act on is one they will ignore: %q", stdout)
	}
}
