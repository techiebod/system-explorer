package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// chainRows derives the chain rows for one inline document, as JSON keyed by
// the stream name — the shape a reader can compare against expected.jsonl by
// eye. Every expectation below was measured against the Python reference over
// the same document before it was written down.
func chainRows(t *testing.T, document string) map[string]string {
	t.Helper()
	doc, err := decodeDocument(strings.NewReader(document))
	if err != nil {
		t.Fatalf("staging a document the collector cannot read: %v", err)
	}
	out := map[string]string{}
	for _, row := range nftChains(doc) {
		encoded, err := json.Marshal(row.facts)
		if err != nil {
			t.Fatal(err)
		}
		out[row.key.streamName()] = string(encoded)
	}
	return out
}

func wantRow(t *testing.T, rows map[string]string, name, facts string) {
	t.Helper()
	got, ok := rows[name]
	if !ok {
		t.Fatalf("no object named %q; got %v", name, rows)
	}
	var a, b any
	if err := json.Unmarshal([]byte(got), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(facts), &b); err != nil {
		t.Fatal(err)
	}
	if string(mustCanonical(t, a)) != string(mustCanonical(t, b)) {
		t.Errorf("%s\n  got  %s\n  want %s", name, mustCanonical(t, a), mustCanonical(t, b))
	}
}

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The name carries family and table because the same chain name in ip and ip6
// is two chains; identity is never keyed on the handle, which one committed
// capture deliberately makes identical across both.
func TestAChainIsIdentifiedByFamilyTableAndName(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"ip","table":"asym","name":"shared","handle":1}},
      {"chain":{"family":"ip6","table":"asym","name":"shared","handle":1}},
      {"rule":{"family":"ip","table":"asym","chain":"input","handle":3,"expr":[{"jump":{"target":"shared"}}]}}
    ]}`)
	wantRow(t, rows, "ip asym shared", `{"Family":"ip","Table":"asym","Name":"shared","BaseChain":false,"Handle":1,"RuleCount":0,"JumpedFrom":["input"]}`)
	wantRow(t, rows, "ip6 asym shared", `{"Family":"ip6","Table":"asym","Name":"shared","BaseChain":false,"Handle":1,"RuleCount":0,"Unreferenced":true}`)
}

// Last entry wins for the content, first sighting fixes the position: a
// slice-append implementation emits the chain twice, and multiplicity is a
// difference even when both copies are otherwise right.
func TestDuplicateChainEntriesCollapseToOneRowCarryingTheLastContent(t *testing.T) {
	document := `{"nftables":[
      {"chain":{"family":"inet","table":"t","name":"dup","handle":10}},
      {"chain":{"family":"inet","table":"t","name":"later","handle":11}},
      {"chain":{"family":"inet","table":"t","name":"dup","handle":12,"hook":"input"}}
    ]}`
	doc, err := decodeDocument(strings.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	rows := nftChains(doc)
	if len(rows) != 2 {
		t.Fatalf("one row per distinct (family, table, name); got %d", len(rows))
	}
	if rows[0].key.name != "dup" || rows[1].key.name != "later" {
		t.Fatalf("the first sighting fixes the position; got %v then %v", rows[0].key, rows[1].key)
	}
	if handle, _ := json.Marshal(rows[0].facts["Handle"]); string(handle) != "12" {
		t.Fatalf("the last entry's content wins; Handle is %s", handle)
	}
}

// Whatever family token the document carries, carry it. Three differential
// operators exist solely to kill a walk whose families are an enum over the
// ones its author had met.
func TestAddressFamiliesAreNeverAnEnum(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"netdev","table":"filter","name":"ingress","handle":1,"type":"filter","hook":"ingress","dev":"lab0","prio":-500,"policy":"accept"}},
      {"chain":{"family":"bridge","table":"filter","name":"island","handle":2}},
      {"chain":{"family":"arp","table":"filter","name":"input","handle":3,"type":"filter","hook":"input","prio":-150,"policy":"accept"}},
      {"chain":{"family":"fictional","table":"t","name":"c","handle":4}}
    ]}`)
	for _, name := range []string{"netdev filter ingress", "bridge filter island", "arp filter input", "fictional t c"} {
		if _, ok := rows[name]; !ok {
			t.Errorf("%s went missing; got %v", name, rows)
		}
	}
	// The netdev-only `dev` member is not a fact and is not smuggled onto the
	// row by a struct that happened to have a field for it.
	if strings.Contains(rows["netdev filter ingress"], "lab0") {
		t.Error("only declared facts travel; `dev` is not one of them")
	}
}

func TestBaseChainIsTheTruthinessOfHookAndHookIsItsPresence(t *testing.T) {
	// Two different tests on one member, kept apart deliberately: "" and 0
	// are not base chains, but Hook is still emitted for both, while a null
	// hook omits the fact entirely.
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"ip","table":"t","name":"empty","handle":1,"hook":""}},
      {"chain":{"family":"ip","table":"t","name":"zero","handle":2,"hook":0}},
      {"chain":{"family":"ip","table":"t","name":"nulled","handle":3,"hook":null}}
    ]}`)
	wantRow(t, rows, "ip t empty", `{"Family":"ip","Table":"t","Name":"empty","BaseChain":false,"Handle":1,"Hook":"","RuleCount":0,"Unreferenced":true}`)
	wantRow(t, rows, "ip t zero", `{"Family":"ip","Table":"t","Name":"zero","BaseChain":false,"Handle":2,"Hook":0,"RuleCount":0,"Unreferenced":true}`)
	wantRow(t, rows, "ip t nulled", `{"Family":"ip","Table":"t","Name":"nulled","BaseChain":false,"Handle":3,"RuleCount":0,"Unreferenced":true}`)
}

// Zero is emitted for a priority and for a rule count. A falsy check on prio
// would drop the priority of every filter/input chain and leave two chains on
// one hook with nothing saying which sees the packet first; a falsy check on
// RuleCount would hide an empty base chain, which runs its policy on
// everything.
func TestZeroIsAValueNotAnAbsence(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"ip","table":"t","name":"c","handle":0,"hook":"input","prio":0,"type":"filter","policy":"accept"}}
    ]}`)
	wantRow(t, rows, "ip t c", `{"Family":"ip","Table":"t","Name":"c","BaseChain":true,"Handle":0,"Hook":"input","Type":"filter","Priority":0,"Policy":"accept","RuleCount":0}`)
}

// Handle and Priority are copied with their JSON type intact, because the
// harness treats 12 and 12.0 as different answers.
func TestPassThroughMembersKeepTheDocumentsOwnType(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"ip","table":"t","name":"c","handle":12.0,"prio":-150.5}},
      {"chain":{"family":"ip","table":"t","name":"d","handle":1,"prio":"filter"}},
      {"chain":{"family":"ip","table":"t","name":"big","handle":18446744073709551615}}
    ]}`)
	if !strings.Contains(rows["ip t c"], `"Handle":12.0`) || !strings.Contains(rows["ip t c"], `"Priority":-150.5`) {
		t.Errorf("floats must survive as floats: %s", rows["ip t c"])
	}
	if !strings.Contains(rows["ip t d"], `"Priority":"filter"`) {
		t.Errorf("a symbolic priority travels as the string it is: %s", rows["ip t d"])
	}
	// Above 2^53: round-tripping through float64 would emit 18446744073709552000.
	if !strings.Contains(rows["ip t big"], `"Handle":18446744073709551615`) {
		t.Errorf("a u64 handle lost its digits: %s", rows["ip t big"])
	}
}

func TestReachabilityReadsJumpAndGotoIdentically(t *testing.T) {
	// goto differs from jump in where control RETURNS, never in whether it
	// ARRIVES, so the two produce the same row — which is exactly what the
	// nft-jump-to-goto operator checks by rewriting one into the other.
	jump := chainRows(t, `{"nftables":[
      {"chain":{"family":"inet","table":"t","name":"dispatch","handle":1}},
      {"rule":{"family":"inet","table":"t","chain":"input","handle":2,"expr":[{"jump":{"target":"dispatch"}}]}}
    ]}`)
	goTo := chainRows(t, `{"nftables":[
      {"chain":{"family":"inet","table":"t","name":"dispatch","handle":1}},
      {"rule":{"family":"inet","table":"t","chain":"input","handle":2,"expr":[{"goto":{"target":"dispatch"}}]}}
    ]}`)
	if jump["inet t dispatch"] != goTo["inet t dispatch"] {
		t.Fatalf("jump and goto must produce the same row:\n  %s\n  %s", jump["inet t dispatch"], goTo["inet t dispatch"])
	}
	if !strings.Contains(jump["inet t dispatch"], `"JumpedFrom":["input"]`) {
		t.Fatalf("got %s", jump["inet t dispatch"])
	}
}

func TestAVerdictNestedDeepInsideAnExpressionStillReaches(t *testing.T) {
	// The defect this walk exists for: a ct-state verdict map carries its
	// jumps two levels down, in the map's data, and a surface-only walk
	// published the chain holding every inbound accept as Unreferenced.
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"inet","table":"t","name":"input-allow","handle":1}},
      {"rule":{"family":"inet","table":"t","chain":"input","handle":2,"expr":[
        {"vmap":{"key":{"ct":{"key":"state"}},"data":{"set":[
          ["invalid",{"drop":null}],
          ["new",{"jump":{"target":"input-allow"}}],
          ["untracked",{"jump":{"target":"input-allow"}}]]}}}]}}
    ]}`)
	wantRow(t, rows, "inet t input-allow", `{"Family":"inet","Table":"t","Name":"input-allow","BaseChain":false,"Handle":1,"RuleCount":0,"JumpedFrom":["input"]}`)
}

func TestANamedVerdictMapCountsOnlyWhereSomeRuleConsultsIt(t *testing.T) {
	// The jumps live in the map OBJECT's elem list and in no rule expression
	// at all — the dispatching rule carries only "@dispatch". And a map no
	// rule consults is latent: the kernel never traverses it, so counting it
	// would retire Unreferenced from exactly the chains telling the truth.
	used := chainRows(t, `{"nftables":[
      {"chain":{"family":"inet","table":"maplab","name":"input","handle":1,"hook":"input","prio":0,"policy":"drop"}},
      {"chain":{"family":"inet","table":"maplab","name":"landing","handle":2}},
      {"map":{"family":"inet","table":"maplab","name":"dispatch","handle":3,"type":"inet_proto","map":"verdict",
              "elem":[["tcp",{"jump":{"target":"landing"}}],["udp",{"drop":null}]]}},
      {"rule":{"family":"inet","table":"maplab","chain":"input","handle":6,
               "expr":[{"vmap":{"key":{"meta":{"key":"l4proto"}},"data":"@dispatch"}}]}}
    ]}`)
	wantRow(t, used, "inet maplab landing", `{"Family":"inet","Table":"maplab","Name":"landing","BaseChain":false,"Handle":2,"RuleCount":0,"JumpedFrom":["input"]}`)

	unused := chainRows(t, `{"nftables":[
      {"chain":{"family":"inet","table":"maplab","name":"landing","handle":2}},
      {"map":{"family":"inet","table":"maplab","name":"dispatch","handle":3,
              "elem":[["tcp",{"jump":{"target":"landing"}}]]}}
    ]}`)
	wantRow(t, unused, "inet maplab landing", `{"Family":"inet","Table":"maplab","Name":"landing","BaseChain":false,"Handle":2,"RuleCount":0,"Unreferenced":true}`)
}

// The reference never tests the map object's own "map" member, and gating on
// "verdict" here would disagree with it on a document whose elem happens to
// hold a jump under some other data type.
func TestAMapIsWalkedWhateverItsDeclaredDataType(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"inet","table":"t","name":"land","handle":1}},
      {"map":{"family":"inet","table":"t","name":"m","map":"ipv4_addr",
              "elem":[["a",{"jump":{"target":"land"}}]]}},
      {"rule":{"family":"inet","table":"t","chain":"c","handle":2,"expr":[{"match":{"right":"@m"}}]}}
    ]}`)
	if !strings.Contains(rows["inet t land"], `"JumpedFrom":["c"]`) {
		t.Fatalf("got %s", rows["inet t land"])
	}
}

// A set's elem holds bare keys and verdict is not a key type, so a set has
// nowhere for a jump to sit — walking one would invent reachability.
func TestASetIsNotWalked(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"inet","table":"t","name":"land","handle":1}},
      {"set":{"family":"inet","table":"t","name":"s","elem":[["tcp",{"jump":{"target":"land"}}]]}},
      {"rule":{"family":"inet","table":"t","chain":"c","handle":2,"expr":[{"match":{"right":"@s"}}]}}
    ]}`)
	if !strings.Contains(rows["inet t land"], `"Unreferenced":true`) {
		t.Fatalf("got %s", rows["inet t land"])
	}
}

func TestScopingIsFamilyAndTableNeverNameAlone(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"inet","table":"y","name":"land","handle":1}},
      {"map":{"family":"inet","table":"y","name":"m","elem":[["a",{"jump":{"target":"land"}}]]}},
      {"rule":{"family":"inet","table":"x","chain":"c","handle":2,"expr":[{"vmap":{"data":"@m"}}]}},
      {"chain":{"family":"ip","table":"t","name":"tgt","handle":3}},
      {"rule":{"family":"ip6","table":"t","chain":"c","handle":4,"expr":[{"jump":{"target":"tgt"}}]}}
    ]}`)
	if !strings.Contains(rows["inet y land"], `"Unreferenced":true`) {
		t.Errorf("a map consulted from another table credits nothing: %s", rows["inet y land"])
	}
	if !strings.Contains(rows["ip t tgt"], `"Unreferenced":true`) {
		t.Errorf("a jump cannot cross families: %s", rows["ip t tgt"])
	}
}

func TestJumpedFromIsASortedDeduplicatedSetOfCallerChains(t *testing.T) {
	// A chain that jumps to the same target twice is ONE caller — a
	// single-valued map here is the defect nft-second-caller exposes — and
	// the order is by code point, not by document.
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"ip","table":"t","name":"tgt","handle":1}},
      {"rule":{"family":"ip","table":"t","chain":"Zulu","handle":2,"expr":[{"jump":{"target":"tgt"}}]}},
      {"rule":{"family":"ip","table":"t","chain":"alpha","handle":3,"expr":[{"jump":{"target":"tgt"}}]}},
      {"rule":{"family":"ip","table":"t","chain":"alpha","handle":4,"expr":[{"goto":{"target":"tgt"}}]}},
      {"rule":{"family":"ip","table":"t","chain":"_under","handle":5,"expr":[{"jump":{"target":"tgt"}}]}}
    ]}`)
	if !strings.Contains(rows["ip t tgt"], `"JumpedFrom":["Zulu","_under","alpha"]`) {
		t.Fatalf("got %s", rows["ip t tgt"])
	}
}

// The reference credits a caller even when the caller is itself unreachable,
// deliberately: "some rule" means any rule in the (family, table), not a rule
// proven base-reachable. A walk that improved on this would disagree with the
// reference on a committed pair.
func TestBaseChainReachabilityIsNotModelled(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"ip","table":"t","name":"tgt","handle":1}},
      {"chain":{"family":"ip","table":"t","name":"orphan","handle":2}},
      {"rule":{"family":"ip","table":"t","chain":"orphan","handle":3,"expr":[{"jump":{"target":"tgt"}}]}}
    ]}`)
	if !strings.Contains(rows["ip t tgt"], `"JumpedFrom":["orphan"]`) {
		t.Fatalf("an unreachable caller still counts: %s", rows["ip t tgt"])
	}
	if !strings.Contains(rows["ip t orphan"], `"Unreferenced":true`) {
		t.Fatalf("got %s", rows["ip t orphan"])
	}
}

func TestABaseChainIsNeverUnreferencedButCanCarryJumpedFrom(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"ip","table":"t","name":"INPUT","handle":1,"hook":"input","prio":0,"policy":"accept"}},
      {"chain":{"family":"ip","table":"t","name":"lonely","handle":2,"hook":"forward","prio":0,"policy":"drop"}},
      {"rule":{"family":"ip","table":"t","chain":"other","handle":3,"expr":[{"jump":{"target":"INPUT"}}]}}
    ]}`)
	if !strings.Contains(rows["ip t INPUT"], `"JumpedFrom":["other"]`) {
		t.Errorf("the caller branch is tested first and does not consult BaseChain: %s", rows["ip t INPUT"])
	}
	if strings.Contains(rows["ip t lonely"], "Unreferenced") {
		t.Errorf("nothing jumps to a forward hook and nothing needs to: %s", rows["ip t lonely"])
	}
}

func TestRuleCountIsKeyedOnTheContainingChainNotTheTarget(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"ip","table":"t","name":"src","handle":1}},
      {"chain":{"family":"ip","table":"t","name":"dst","handle":2}},
      {"rule":{"family":"ip","table":"t","chain":"src","handle":3,"expr":[{"jump":{"target":"dst"}}]}},
      {"rule":{"family":"ip","table":"t","chain":"src","handle":4,"comment":"no expr at all"}},
      {"rule":{"family":"ip","table":"t","chain":"ghost","handle":5,"expr":[]}}
    ]}`)
	if !strings.Contains(rows["ip t src"], `"RuleCount":2`) {
		t.Errorf("every rule entry counts, expr or not: %s", rows["ip t src"])
	}
	if !strings.Contains(rows["ip t dst"], `"RuleCount":0`) {
		t.Errorf("a jump target does not inherit the caller's rules: %s", rows["ip t dst"])
	}
	if len(rows) != 2 {
		t.Errorf("a rule in a chain with no chain object emits nothing: %v", rows)
	}
}

func TestAFalsyOrNonStringJumpTargetReachesNothing(t *testing.T) {
	rows := chainRows(t, `{"nftables":[
      {"chain":{"family":"ip","table":"t","name":"c","handle":1}},
      {"rule":{"family":"ip","table":"t","chain":"c","handle":2,"expr":[
        {"jump":{"target":""}},{"jump":{"target":null}},{"jump":{}},{"jump":"str"},{"jump":null}]}}
    ]}`)
	if !strings.Contains(rows["ip t c"], `"Unreferenced":true`) {
		t.Fatalf("got %s", rows["ip t c"])
	}
}

func TestVerdictTargetsNamesEachTargetOnceInDocumentOrder(t *testing.T) {
	doc, err := decodeDocument(strings.NewReader(
		`[{"jump":{"target":"x"}},{"jump":{"target":"x"}},{"goto":{"target":"y"}},{"jump":{"target":"a"},"goto":{"target":"b"}}]`))
	if err != nil {
		t.Fatal(err)
	}
	got := verdictTargets(doc)
	want := []string{"x", "y", "a", "b"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestMapReferencesReadsValuesNeverKeys(t *testing.T) {
	doc, err := decodeDocument(strings.NewReader(`{"@key":"plain","data":"@wanted","nested":["@also","bare"],"at":"@"}`))
	if err != nil {
		t.Fatal(err)
	}
	got := mapReferences(doc)
	for _, name := range []string{"wanted", "also", ""} {
		if _, ok := got[name]; !ok {
			t.Errorf("%q was not collected; got %v", name, got)
		}
	}
	if _, ok := got["key"]; ok {
		t.Errorf("a member NAMED @key is not a reference to anything; got %v", got)
	}
	if len(got) != 3 {
		t.Errorf("got %v", got)
	}
}
