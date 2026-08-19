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
		"token without a generation":   "collect pci\n",
		"token with an empty gen":      "collect pci:\n",
		"token with a non-integer gen": "collect pci:abc\n",
		"token with a signed gen":      "collect pci:-1\n",
		"token with a float gen":       "collect pci:1.5\n",
		"a collection named twice":     "collect pci:1 pci:2\n",
		"an illegal collection name":   "collect PCI:1\n",
		"declare with an argument":     "declare now\n",
		"probe with an argument":       "probe now\n",
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runWith(t, request, nil)
			if code != exitRequest {
				t.Fatalf("exit %d, want %d", code, exitRequest)
			}
			if stdout != "" {
				t.Fatalf("a request that was not run emitted a stream: %q", stdout)
			}
			if strings.TrimSpace(stderr) == "" {
				t.Fatal("no stderr line: a refusal a person cannot read is a refusal they will retry forever")
			}
		})
	}
}

// The bound refuses an over-long request before any token is interpreted, so
// an unbounded line cannot become an unbounded parse (DESIGN 18).
func TestAnOverlongRequestLineIsRefusedUnparsed(t *testing.T) {
	code, _, stderr := runWith(t, "collect "+strings.Repeat("a", requestBound)+":1\n", nil)
	if code != exitRequest {
		t.Fatalf("exit %d, want %d", code, exitRequest)
	}
	if !strings.Contains(stderr, "bound") {
		t.Fatalf("stderr does not name the bound: %q", stderr)
	}
}

// A collection this collector never published is DECLINED and not crashed on,
// and it does NOT commit: prior state stands rather than being retired by a
// batch that never looked (DESIGN 18, the ruling in appendix C).
func TestAnUnservedCollectionDeclinesUnsupportedAndCommitsNothing(t *testing.T) {
	dir := stageEmpty(t)
	code, stdout, stderr := runWith(t, "collect blockdevices:7\n",
		map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	var declines, commits int
	for _, record := range records {
		switch record["record"] {
		case "decline":
			declines++
			if record["reason"] != "unsupported" {
				t.Fatalf("reason %v, want unsupported", record["reason"])
			}
		case "commit":
			commits++
		}
	}
	if declines != 1 || commits != 0 {
		t.Fatalf("declines=%d commits=%d; an unserved collection declines once and commits never", declines, commits)
	}
}

// probe answers with a verdict and exit zero, never with an exit code — a
// collector that said "I cannot run here" by exiting non-zero would be
// indistinguishable from one that crashed (DESIGN 18).
func TestProbeAnswersWithAVerdict(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"a staged capture": {"SE_REPLAY_DIR": stageCorpus(t)},
		"nothing staged":   {"SE_REPLAY_DIR": stageEmpty(t)},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, _ := runWith(t, "probe\n", env)
			if code != exitOK {
				t.Fatalf("exit %d: a probe reports its verdict in the document", code)
			}
			var verdict struct{ Verdict, Reason string }
			if err := json.Unmarshal([]byte(stdout), &verdict); err != nil {
				t.Fatalf("probe emitted no verdict document: %v", err)
			}
			if verdict.Verdict != "yes" && verdict.Verdict != "no" {
				t.Fatalf("verdict %q is neither yes nor no", verdict.Verdict)
			}
			if verdict.Reason == "" {
				t.Fatal("a verdict a person cannot act on is a verdict they will ignore")
			}
		})
	}
}
