package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
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
		"token without a generation":    "collect containers\n",
		"token with an empty gen":       "collect containers:\n",
		"token with a non-integer gen":  "collect containers:abc\n",
		"token with a signed gen":       "collect containers:-1\n",
		"token with a plus-signed gen":  "collect containers:+5\n",
		"token with only a generation":  "collect :5\n",
		"an unecho-able uppercase name": "collect Containers:5\n",
		"a colon-bearing name":          "collect a:b:5\n",
		"one collection, two gens":      "collect containers:1 containers:2\n",
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
	order, generations, err := parseCollect([]string{"containers:412", "volumes:429"})
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "containers" || order[1] != "volumes" {
		t.Fatalf("the request line's order is the emission order; got %v", order)
	}
	if generations["containers"] != 412 || generations["volumes"] != 429 {
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
// test is what holds the two paths to it.
func TestBothSourcesGiveTheInterfaceMissingOneAnswer(t *testing.T) {
	// An empty replay directory is a staged host with no docker.
	_, err := replaySource{dir: t.TempDir()}.document(pathContainers)
	var fromReplay *declined
	if !errors.As(err, &fromReplay) {
		t.Fatalf("an empty replay directory is a host with no docker: %v", err)
	}
	if fromReplay.reason != declineNoSocket.reason || fromReplay.detail != declineNoSocket.detail {
		t.Fatalf("the replay path must take the shared reading, got %+v", fromReplay)
	}
	// absent is the only decline that commits, and that is the whole point: it
	// must be able to retire the containers a previous batch published.
	if declineNoSocket.reason != "absent" {
		t.Fatalf("no docker socket on the host is a successful reading that "+
			"establishes there are no containers, so it must be the reason that "+
			"commits and retires; got %q", declineNoSocket.reason)
	}
	// And the live path, on any machine without the socket — which every CI
	// runner is. Skipped rather than faked where the socket exists, because a
	// faked stat would be testing the fake.
	if _, err := os.Stat(socketPath); err != nil {
		live := &liveSource{client: unixClient()}
		_, err := live.document(pathContainers)
		var fromLive *declined
		if !errors.As(err, &fromLive) {
			t.Fatalf("a live host with no docker socket declines: %v", err)
		}
		if fromLive.reason != fromReplay.reason || fromLive.detail != fromReplay.detail {
			t.Fatalf("the two paths disagree about one condition: live %+v, "+
				"replay %+v — which is the defect this test exists for",
				fromLive, fromReplay)
		}
		// The capability question takes the same shared reading, so a probe and
		// a collect on one host cannot say different things about it.
		var fromProbe *declined
		if !errors.As(live.reachable(), &fromProbe) || fromProbe.detail != declineNoSocket.detail {
			t.Fatalf("the probe path must take the shared reading too, got %v", live.reachable())
		}
	}
}

// The two non-absent readings, and the property that matters about both: they
// must NOT commit. A host whose socket is there may be running containers right
// now, so a collector that could not read them says so and leaves them
// standing — committing zero would retire a host's whole docker estate because
// a group membership was missing or a daemon was restarting.
func TestTheTwoReadableFailuresDoNotRetireAnything(t *testing.T) {
	for _, refusal := range []declined{declineSocketRefused, declineDaemonSilent} {
		if refusal.reason == "absent" {
			t.Errorf("%q establishes nothing about what this host runs, so it must "+
				"not be the reason that commits", refusal.detail)
		}
		if refusal.detail == "" {
			t.Error("a decline a person cannot act on is one they will ignore")
		}
	}
	if declineSocketRefused.reason != "unauthorised" {
		t.Errorf("reason %q: a socket this process may not open is a deployment "+
			"error — the unit was not given the group — and unauthorised is the "+
			"word that sends somebody to the unit rather than to the daemon",
			declineSocketRefused.reason)
	}
	if declineDaemonSilent.reason != "unavailable" {
		t.Errorf("reason %q: a daemon that did not answer may answer on the next "+
			"batch, and unsupported would tell an operator to stop asking",
			declineDaemonSilent.reason)
	}
}

// The stem the replay seam addresses a captured response by, which is the
// reference shim's slug() and therefore the name the committed corpus carries.
// A port that spelled it differently would replay against nothing and decline
// absent on a variant that staged a whole docker.
func TestThePayloadStemIsTheOneTheCorpusCarries(t *testing.T) {
	for path, want := range map[string]string{
		pathContainers: "containers-json-all-1",
		pathVolumes:    "volumes",
		pathNetworks:   "networks",
		"/":            "root",
	} {
		if got := payloadStem(path); got != want {
			t.Errorf("payloadStem(%q) = %q, want %q", path, got, want)
		}
	}
}
