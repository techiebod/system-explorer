package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// stageRuleset lays out the one document the replay seam reads. An empty
// string stages nothing, which is how the absent path is reached: absence of
// nft.json IS the absence of the interface.
func stageRuleset(t *testing.T, document string) string {
	t.Helper()
	dir := t.TempDir()
	if document != "" {
		if err := os.WriteFile(filepath.Join(dir, "nft.json"), []byte(document), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const oneChain = `{"nftables":[
  {"chain":{"family":"ip","table":"filter","name":"INPUT","handle":20,"type":"filter","hook":"input","prio":0,"policy":"accept"}},
  {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":58,"expr":[{"counter":{"packets":3,"bytes":9}},{"accept":null}]}}
]}`

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	dir := stageRuleset(t, oneChain)
	env := map[string]string{"SE_REPLAY_DIR": dir}
	code1, first, stderr := runWith(t, "collect nft-chains:658 nft-rules:675\n", env)
	code2, second, _ := runWith(t, "collect nft-chains:658 nft-rules:675\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	dir := stageRuleset(t, oneChain)
	code, stdout, stderr := runWith(t, "collect nft-chains:658\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)

	begin := ofKind(records, "begin")[0]
	if begin["request"] != "replay" || begin["batch"] != "replay" {
		t.Errorf("replay pins batch and request to the constant \"replay\"; got %v/%v", begin["request"], begin["batch"])
	}
	if begin["boot_id"] != replayBootID {
		t.Errorf("a variant staging no boot_id gets the fixed v4-shaped id; got %v", begin["boot_id"])
	}
	if begin["timens"] != 0.0 {
		t.Errorf("no time namespace was observed at capture, so timens is 0; got %v", begin["timens"])
	}
	if begin["instance"] != nil {
		t.Errorf("host-native means instance null, and only null; got %v", begin["instance"])
	}
	// The real digest under replay as much as live: a replay does not change
	// which contract this binary holds. begin.declaration is rule-governed
	// rather than byte-compared (DESIGN 19), so this collector publishes its
	// own identity instead of copying the one the committed half carries.
	if begin["declaration"] != declarationDigest {
		t.Errorf("begin.declaration under replay is %q; got %v", declarationDigest, begin["declaration"])
	}
	if at := ofKind(records, "object")[0]["at"]; at != 1.0 {
		t.Errorf("the first replayed object carries at = 1.0 + 0.001*0; got %v", at)
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

func TestAtIsOneCounterAcrossTheWholeBatch(t *testing.T) {
	// Both collections come from one document, and `at` advances per emitted
	// object across the batch rather than restarting per collection — which
	// is what the two-collection committed pair pins.
	dir := stageRuleset(t, oneChain)
	code, stdout, stderr := runWith(t, "collect nft-chains:1 nft-rules:2\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	objects := ofKind(parseRecords(t, stdout), "object")
	if len(objects) != 2 {
		t.Fatalf("one chain and one rule; got %d objects", len(objects))
	}
	if objects[0]["at"] != 1.0 || objects[1]["at"] != 1.001 {
		t.Fatalf("at must advance 1.0, 1.001 across the batch; got %v, %v", objects[0]["at"], objects[1]["at"])
	}
}

func TestReplayNowIsIgnoredButNeverACrash(t *testing.T) {
	// This collector derives nothing from wall time, so SE_REPLAY_NOW has
	// nothing to pin — the contract is only that setting it changes nothing
	// and breaks nothing.
	dir := stageRuleset(t, oneChain)
	bare := map[string]string{"SE_REPLAY_DIR": dir}
	pinned := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-14T12:00:00Z"}
	code1, first, _ := runWith(t, "collect nft-chains:2\n", bare)
	code2, second, _ := runWith(t, "collect nft-chains:2\n", pinned)
	if code1 != exitOK || code2 != exitOK || first != second {
		t.Fatalf("SE_REPLAY_NOW changed the outcome: exits %d/%d", code1, code2)
	}
}

func TestAnAbsentRulesetDeclinesAbsentAndCommitsZeroForEveryCollection(t *testing.T) {
	dir := stageRuleset(t, "")
	code, stdout, stderr := runWith(t, "collect nft-chains:77 nft-rules:94\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 2 {
		t.Fatalf("both requested collections must resolve; got %v", declines)
	}
	for _, decline := range declines {
		if decline["reason"] != "absent" {
			t.Errorf("reason %v, want absent", decline["reason"])
		}
		// The detail is the reference's, byte for byte: it travels to a hub
		// and out over MCP, so it is a pinned constant rather than prose.
		if decline["detail"] != "no nft on this host" {
			t.Errorf("detail %q is not the pinned string", decline["detail"])
		}
	}
	commits := ofKind(records, "commit")
	if len(commits) != 2 {
		t.Fatalf("absent is authoritative-empty and MUST commit zero, so it can retire what a previous batch published; got %v", commits)
	}
	for _, commit := range commits {
		if commit["objects"] != 0.0 || commit["assertions"] != 0.0 || commit["unobservable"] != 0.0 {
			t.Errorf("all three counts, zero when zero; got %v", commit)
		}
	}
	if len(ofKind(records, "object")) != 0 {
		t.Fatal("a declined collection carries no records")
	}
}

func TestAnEmptyRulesetCommitsZeroWithNoDecline(t *testing.T) {
	// The middle case, and the one a port gets wrong by keying on "did it
	// produce objects" rather than "did the acquisition happen": nft answered,
	// the ruleset is empty, so the answer is an authoritative-empty commit
	// that retires chains a previous batch published. A decline here would
	// mark that prior state stale instead.
	dir := stageRuleset(t, `{"nftables":[{"metainfo":{"version":"1.0.9"}}]}`)
	code, stdout, stderr := runWith(t, "collect nft-chains:5 nft-rules:6\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	if got := ofKind(records, "decline"); len(got) != 0 {
		t.Fatalf("a readable empty ruleset is not a decline; got %v", got)
	}
	commits := ofKind(records, "commit")
	if len(commits) != 2 || commits[0]["objects"] != 0.0 || commits[1]["objects"] != 0.0 {
		t.Fatalf("both collections commit zero; got %v", commits)
	}
}

func TestADocumentWithoutTheNftablesKeyIsStillAnAnswer(t *testing.T) {
	dir := stageRuleset(t, `{}`)
	code, stdout, _ := runWith(t, "collect nft-chains:5\n", map[string]string{"SE_REPLAY_DIR": dir})
	records := parseRecords(t, stdout)
	if code != exitOK || len(ofKind(records, "decline")) != 0 {
		t.Fatalf("data.get(\"nftables\", []) yields zero objects, never a decline; exit %d, %s", code, stdout)
	}
	if ofKind(records, "commit")[0]["objects"] != 0.0 {
		t.Fatal("zero objects, committed")
	}
}

func TestAnUnservedCollectionIsDeclinedUnsupportedWithNoCommit(t *testing.T) {
	// lookups is the PERMANENT seat: it is dropped by ruling — lookup is a
	// VERB in the new contract, not a collection — so unlike the owed names
	// that held this seat before (nft-tables, port-exposure, tailscale), it
	// will never be served and the drill never moves again.
	dir := stageRuleset(t, oneChain)
	code, stdout, stderr := runWith(t, "collect nft-chains:1 lookups:2\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("a name this collector never published is declined, not crashed on; exit %d, stderr %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["collection"] != "lookups" || declines[0]["reason"] != "unsupported" {
		t.Fatalf("expected one unsupported decline for lookups; got %v", declines)
	}
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] == "lookups" {
			t.Fatal("unsupported established nothing about that collection and must not commit, or prior state is retired by a batch that never looked")
		}
	}
}

func TestAStagedRulesetThatIsNotADocumentRefusesToRun(t *testing.T) {
	// A payload the variant staged but this side cannot read is a broken
	// capture, not a statement about any machine — and it must never fall
	// back to the live nft of the workstation replaying the corpus.
	dir := stageRuleset(t, "{not json")
	code, stdout, stderr := runWith(t, "collect nft-chains:1\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d", code, exitRuntime)
	}
	if !strings.Contains(stderr, "nft") {
		t.Fatalf("stderr must name what could not be read: %q", stderr)
	}
	if strings.Contains(stdout, `"decline"`) {
		t.Fatal("a broken capture is not a decline")
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	ready := stageRuleset(t, oneChain)
	code, stdout, _ := runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": ready})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}

	// An EMPTY ruleset is a successful read, never a probe failure: the
	// collection's honest answer there is a zero commit.
	empty := stageRuleset(t, `{"nftables":[]}`)
	code, stdout, _ = runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": empty})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("an empty ruleset is a yes: exit %d, stdout %q", code, stdout)
	}

	// A no is still exit zero: the verdict is the answer, and a non-zero exit
	// would read as a crash (DESIGN 18).
	bare := stageRuleset(t, "")
	code, stdout, _ = runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": bare})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"no"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	record := parseRecords(t, stdout)[0]
	if record["reason"] == "" || record["reason"] == nil {
		t.Fatal("a verdict without its why is not actionable")
	}
}

func TestNoFactIsEverNullAtAnyDepth(t *testing.T) {
	// The rule a Go port breaks first: marshalling a struct with nil members.
	// The document below omits or nulls every optional member there is.
	dir := stageRuleset(t, `{"nftables":[
      {"chain":{"family":"ip","table":"t","name":"c","handle":null,"hook":null,"type":null,"policy":null,"prio":null}},
      {"rule":{"family":"ip","table":"t","chain":"c","handle":1,"expr":[{"jump":null},{"counter":{"packets":null,"bytes":null}}]}}
    ]}`)
	code, stdout, stderr := runWith(t, "collect nft-chains:1 nft-rules:2\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var walk func(path string, value any)
	walk = func(path string, value any) {
		switch v := value.(type) {
		case nil:
			t.Errorf("fact value at %s is null; the contract forbids it at any depth", path)
		case map[string]any:
			for key, member := range v {
				walk(path+"/"+key, member)
			}
		case []any:
			for i, element := range v {
				walk(path+"/"+strconv.Itoa(i), element)
			}
		}
	}
	for _, object := range ofKind(parseRecords(t, stdout), "object") {
		walk(object["name"].(string), object["facts"])
	}
}
