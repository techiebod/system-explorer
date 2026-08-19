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
// exit and never a decline, because a request this side cannot parse
// genuinely was not run (DESIGN 18).
func TestMalformedRequestsExitTwoWithAStderrLine(t *testing.T) {
	cases := map[string]string{
		"empty request":                 "",
		"blank line":                    "\n",
		"whitespace only":               "   \n",
		"unknown verb":                  "frobnicate\n",
		"collect with no collections":   "collect\n",
		"token without a generation":    "collect domains\n",
		"token with an empty gen":       "collect domains:\n",
		"token with a non-integer gen":  "collect domains:abc\n",
		"token with a signed gen":       "collect domains:-1\n",
		"token with a plus-signed gen":  "collect domains:+5\n",
		"token with only a generation":  "collect :5\n",
		"an unecho-able uppercase name": "collect Domains:5\n",
		"a colon-bearing name":          "collect a:b:5\n",
		"one collection, two gens":      "collect domains:1 domains:2\n",
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
	order, generations, err := parseCollect([]string{"domains:412"})
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 1 || order[0] != "domains" || generations["domains"] != 412 {
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

// One condition, one answer, both paths. The storage collector answered "the
// interface is not on this host" two opposite ways for as long as it existed
// — the live path declined `unsupported`, which never commits and leaves
// prior objects standing stale forever, and the replay path declined
// `absent`, which commits zero and retires them — with a confident comment on
// each side arguing against the other, in one file. Nothing caught it, because
// replay exercises only the replay half.
//
// So this collector spells the reading once, in a shared constant, and this
// test is what holds the two paths to it.
func TestBothSourcesGiveTheInterfaceMissingOneAnswer(t *testing.T) {
	// An empty replay directory is a staged host with no libvirt.
	_, err := replaySource{dir: t.TempDir()}.domains()
	var fromReplay *declined
	if !errors.As(err, &fromReplay) {
		t.Fatalf("an empty replay directory is a host with no libvirt: %v", err)
	}
	if fromReplay.reason != declineNoLibvirt.reason || fromReplay.detail != declineNoLibvirt.detail {
		t.Fatalf("the replay path must take the shared reading, got %+v", fromReplay)
	}
	// absent is the only decline that commits, and that is the whole point: it
	// must be able to retire the domains a previous batch published.
	if declineNoLibvirt.reason != "absent" {
		t.Fatalf("no libvirt on the host is a successful reading that establishes "+
			"there are no domains, so it must be the reason that commits and "+
			"retires; got %q", declineNoLibvirt.reason)
	}
	// And the live path, on any machine without the read-only socket — which
	// every CI runner is. Skipped rather than faked where the socket exists,
	// because a faked stat would be testing the fake.
	if _, err := os.Stat(socketReadOnly); err != nil {
		_, err := (&liveSource{}).domains()
		var fromLive *declined
		if !errors.As(err, &fromLive) {
			t.Fatalf("a live host with no libvirt socket declines: %v", err)
		}
		if fromLive.reason != fromReplay.reason || fromLive.detail != fromReplay.detail {
			t.Fatalf("the two paths disagree about one condition: live %+v, "+
				"replay %+v — which is the defect this test exists for",
				fromLive, fromReplay)
		}
	}
}

// The other live reading, and the one that must NOT commit. A host whose
// socket is there is a host that may hold running guests right now, so a
// build that cannot read them says so and leaves them standing — committing
// zero would retire a fleet nobody looked at.
func TestALibvirtThisBuildCannotReadDoesNotRetireAnything(t *testing.T) {
	if declineNoLibvirtReader.reason == "absent" {
		t.Fatal("a reading this build could not take establishes nothing, so it " +
			"must not be the reason that commits — absent would retire every " +
			"domain on a host that has them")
	}
	if declineNoLibvirtReader.reason != "unsupported" {
		t.Errorf("reason %q: this is permanent for this build, not transient, "+
			"and unavailable would send somebody hunting a failure that is not "+
			"there", declineNoLibvirtReader.reason)
	}
}
