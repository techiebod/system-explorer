package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// oneRule renders a single rule whose expr is the given JSON array, and
// returns its facts. Every expectation below was measured against the Python
// reference over the same document before it was written down.
func oneRule(t *testing.T, expr string) map[string]any {
	t.Helper()
	document := `{"nftables":[{"rule":{"family":"ip","table":"t","chain":"c","handle":9,"expr":` + expr + `}}]}`
	doc, err := decodeDocument(strings.NewReader(document))
	if err != nil {
		t.Fatalf("staging a document the collector cannot read: %v", err)
	}
	rows := nftRules(doc)
	if len(rows) != 1 {
		t.Fatalf("one rule entry, one row; got %d", len(rows))
	}
	encoded, err := json.Marshal(rows[0].facts)
	if err != nil {
		t.Fatal(err)
	}
	var facts map[string]any
	if err := json.Unmarshal(encoded, &facts); err != nil {
		t.Fatal(err)
	}
	return facts
}

func rendered(t *testing.T, expr string) string {
	t.Helper()
	text, _ := oneRule(t, expr)["Rendered"].(string)
	return text
}

func TestEveryStatementIsEitherRenderedOrRecorded(t *testing.T) {
	// The invariant the collection exists for: a row can never be thinner
	// than the rule without saying so.
	cases := []struct{ expr, text, comprehension string }{
		{`[]`, "", "full"},
		{`[{"accept":null}]`, "accept", "full"},
		{`[{"counter":{"packets":3,"bytes":9}},{"jump":{"target":"ts-input"}}]`, "counter jump ts-input", "full"},
		{`[{"masquerade":null}]`, "<unrendered masquerade>", "partial"},
		{`[{"queue":{"num":0}}]`, "<unrendered queue>", "partial"},
		{`[{"match":{"op":"==","left":{"fib":{"result":"oif"}},"right":true}},{"accept":null}]`, "<unrendered fib> accept", "partial"},
		{`[{"log":{"prefix":"refused "}},{"limit":{"rate":5}},{"comment":"anything at all"}]`, "log limit comment", "full"},
		{`[{"reject":{"type":"icmpx","expr":"admin-prohibited"}}]`, "reject", "full"},
	}
	for _, c := range cases {
		facts := oneRule(t, c.expr)
		if facts["Rendered"] != c.text {
			t.Errorf("%s\n  rendered %q, want %q", c.expr, facts["Rendered"], c.text)
		}
		if facts["Comprehension"] != c.comprehension {
			t.Errorf("%s: comprehension %q, want %q", c.expr, facts["Comprehension"], c.comprehension)
		}
	}
}

// A term that cannot be expanded appears AT ITS POSITION, because dropping it
// turns `fib oif lo accept` into `accept` — a narrow rule reading as an
// unconditional one, which is the inversion this renderer exists to prevent.
func TestAnUnrenderableTermKeepsItsPlace(t *testing.T) {
	if got := rendered(t, `[{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"10.0.0.1"}},{"masquerade":null},{"accept":null}]`); got != "ip saddr 10.0.0.1 <unrendered masquerade> accept" {
		t.Fatalf("got %q", got)
	}
}

func TestNegationIsRenderedInsideTheTextAndNoOtherOperatorIs(t *testing.T) {
	// The two most popular nftables exporters never read match.op at all, so
	// `ip saddr != 10.0.0.0/8` exports identically to its inverse. Every
	// operator OTHER than != is silently dropped by the reference — including
	// `in`, `<` and `>` — which is reproduced here, not corrected.
	if got := rendered(t, `[{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"tailscale0*"}}]`); got != "meta iifname != tailscale0*" {
		t.Fatalf("got %q", got)
	}
	if got := rendered(t, `[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"established"}}]`); got != "ct state established" {
		t.Fatalf("an `in` renders as though it were ==, with no residue: %q", got)
	}
	if facts := oneRule(t, `[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"established"}}]`); facts["Comprehension"] != "full" {
		t.Fatalf("and it still claims full comprehension: %v", facts["Comprehension"])
	}
}

func TestAMaskedComparisonKeepsItsMask(t *testing.T) {
	// Declining this branch left two rules per host reading `<unrendered &>
	// counter accept`: a mark test rendered as an unconditional accept.
	if got := rendered(t, `[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16711680]},"right":262144}}]`); got != "meta mark & 0xff0000 262144" {
		t.Fatalf("got %q", got)
	}
	if got := rendered(t, `[{"match":{"op":"!=","left":{"&":[{"ct":{"key":"mark"}},16711680]},"right":0}}]`); got != "ct mark & 0xff0000 != 0" {
		t.Fatalf("got %q", got)
	}
	// A non-integer mask declines the whole match — and the placeholder names
	// the ORIGINAL left-hand key, not the one the mask branch rewrote it to.
	if got := rendered(t, `[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},"0xff"]},"right":1}}]`); got != "<unrendered &>" {
		t.Fatalf("got %q", got)
	}
	// A null mask is no mask: the left side keeps its rewritten form and
	// loses the masking term entirely.
	if got := rendered(t, `[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},null]},"right":1}}]`); got != "meta mark 1" {
		t.Fatalf("got %q", got)
	}
}

func TestAnAnonymousSetShowsItsMembershipAndANamedOneItsName(t *testing.T) {
	// An anonymous set carries its elements right here, so rendering it as
	// "{ ... }" would claim full comprehension while hiding the membership
	// that decides what the rule matches. A named set is a reference whose
	// membership is a separate object, and the name is what the rule says.
	if got := rendered(t, `[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[22,53,8090]}}}]`); got != "tcp dport { 22, 53, 8090 }" {
		t.Fatalf("got %q", got)
	}
	if got := rendered(t, `[{"match":{"op":"!=","left":{"payload":{"protocol":"icmpv6","field":"type"}},"right":{"set":["nd-redirect",139]}}}]`); got != "icmpv6 type != { nd-redirect, 139 }" {
		t.Fatalf("mixed string and integer membership: %q", got)
	}
	if got := rendered(t, `[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":"@temp-ports"}}]`); got != "tcp dport @temp-ports" {
		t.Fatalf("got %q", got)
	}
	if got := rendered(t, `[{"match":{"left":{"ct":{"key":"x"}},"right":{"set":[{"range":[1,10]}]}}}]`); got != "ct x { 1-10 }" {
		t.Fatalf("got %q", got)
	}
	// The empty anonymous set carries a space each side of nothing.
	if got := rendered(t, `[{"match":{"left":{"ct":{"key":"x"}},"right":{"set":[]}}}]`); got != "ct x {  }" {
		t.Fatalf("got %q", got)
	}
}

func TestAPrefixRendersAsAddressSlashLength(t *testing.T) {
	if got := rendered(t, `[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":{"prefix":{"addr":"fe80::","len":64}}}}]`); got != "ip6 daddr fe80::/64" {
		t.Fatalf("got %q", got)
	}
	// A missing member interpolates the literal None, which is the
	// reference's answer and reads as a hole rather than as a valid prefix.
	if got := rendered(t, `[{"match":{"left":{"ct":{"key":"x"}},"right":{"prefix":{"addr":"10.0.0.0"}}}}]`); got != "ct x 10.0.0.0/None" {
		t.Fatalf("got %q", got)
	}
}

func TestCountersAreAbsentNeverZeroAndZeroIsNeverAbsent(t *testing.T) {
	// nftables has no implicit per-rule counters, so a rule without one has
	// no traffic history at all and a 0 would report an idle rule that is
	// simply uncounted. The opposite mistake is just as easy: a counter
	// READING of zero must be emitted.
	if facts := oneRule(t, `[{"accept":null}]`); facts["CounterPackets"] != nil || facts["CounterBytes"] != nil {
		t.Errorf("an uncounted rule carries neither fact: %v", facts)
	}
	facts := oneRule(t, `[{"counter":{"packets":0,"bytes":0}}]`)
	if facts["CounterPackets"] != 0.0 || facts["CounterBytes"] != 0.0 {
		t.Errorf("a zero reading is a reading: %v", facts)
	}
	// The two are independent, and an explicit null is an absence.
	partial := oneRule(t, `[{"counter":{"packets":5}}]`)
	if partial["CounterPackets"] != 5.0 || partial["CounterBytes"] != nil {
		t.Errorf("got %v", partial)
	}
	nulled := oneRule(t, `[{"counter":{"packets":null,"bytes":null}}]`)
	if nulled["CounterPackets"] != nil || nulled["CounterBytes"] != nil {
		t.Errorf("got %v", nulled)
	}
}

func TestACounterKeepsItsDigitsAboveTwoToTheFiftyThree(t *testing.T) {
	document := `{"nftables":[{"rule":{"family":"ip","table":"t","chain":"c","handle":9,"expr":[{"counter":{"packets":18446744073709551615,"bytes":9007199254740993}}]}}]}`
	doc, err := decodeDocument(strings.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(nftRules(doc)[0].facts)
	if err != nil {
		t.Fatal(err)
	}
	// Decoding into float64 emits 18446744073709552000 and 9007199254740992.
	for _, want := range []string{`"CounterPackets":18446744073709551615`, `"CounterBytes":9007199254740993`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("a u64 counter lost its digits: %s", encoded)
		}
	}
}

func TestVerdictAndJumpTargetAreIndependentAndLastJumpWins(t *testing.T) {
	facts := oneRule(t, `[{"accept":null},{"jump":{"target":"a"}},{"jump":{"target":"b"}}]`)
	if facts["Verdict"] != "accept" || facts["JumpTarget"] != "b" {
		t.Fatalf("got %v", facts)
	}
	if facts["Rendered"] != "accept jump a jump b" {
		t.Fatalf("got %q", facts["Rendered"])
	}
	// A verdict map's nested verdicts are NOT read as the rule's verdict.
	nested := oneRule(t, `[{"vmap":{"data":{"set":[["new",{"accept":null}]]}}}]`)
	if _, ok := nested["Verdict"]; ok {
		t.Fatalf("a vmap's inner accept is not this rule's verdict: %v", nested)
	}
}

func TestOpaqueIsComputedAndXtWinsOverTextFallback(t *testing.T) {
	xt := oneRule(t, `[{"xt":{"type":"match","name":"conntrack"}}]`)
	if xt["Comprehension"] != "opaque" || xt["OpaqueReason"] != "xt" || xt["Rendered"] != `xt match "conntrack"` {
		t.Fatalf("got %v", xt)
	}
	text := oneRule(t, `["ip saddr 10.0.0.0/8"]`)
	if text["Comprehension"] != "opaque" || text["OpaqueReason"] != "text-fallback" || text["Rendered"] != "ip saddr 10.0.0.0/8" {
		t.Fatalf("got %v", text)
	}
	// xt overwrites a text-fallback already recorded; the reverse does not
	// happen, because the text branch only sets it where nothing has.
	for _, expr := range []string{
		`["raw",{"xt":{"type":"target","name":"TCPMSS"}}]`,
		`[{"xt":{"type":"target","name":"TCPMSS"}},"raw"]`,
	} {
		if got := oneRule(t, expr)["OpaqueReason"]; got != "xt" {
			t.Errorf("%s: OpaqueReason %v", expr, got)
		}
	}
}

func TestResidueIsTheStatementsOwnJsonInTheDocumentsMemberOrder(t *testing.T) {
	facts := oneRule(t, `[{"mangle":{"key":{"meta":{"key":"mark"}},"value":{"|":[{"&":[{"meta":{"key":"mark"}},4278517759]},262144]}}}]`)
	residue, ok := facts["Residue"].([]any)
	if !ok || len(residue) != 1 {
		t.Fatalf("got %v", facts["Residue"])
	}
	// Python's json.dumps spacing, the payload's own member order, and no
	// re-sorting: a re-serialised statement is a different answer.
	const want = `{"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"|": [{"&": [{"meta": {"key": "mark"}}, 4278517759]}, 262144]}}}`
	if residue[0] != want {
		t.Fatalf("\n  got  %v\n  want %s", residue[0], want)
	}
}

func TestResidueRecordsEveryUnconsumedShape(t *testing.T) {
	cases := map[string][]string{
		`[42,{"accept":null}]`:   {"42"},
		`[{"a":1,"b":2}]`:        {`{"a": 1, "b": 2}`},
		`[null]`:                 {"null"},
		`["bare text"]`:          {`"bare text"`},
		`[{"masquerade":null}]`:  {`{"masquerade": null}`},
		`[{"match":{"left":1}}]`: {`{"match": {"left": 1}}`},
	}
	for expr, want := range cases {
		facts := oneRule(t, expr)
		residue, _ := facts["Residue"].([]any)
		if len(residue) != len(want) {
			t.Errorf("%s: residue %v", expr, facts["Residue"])
			continue
		}
		for i := range want {
			if residue[i] != want[i] {
				t.Errorf("%s\n  got  %v\n  want %v", expr, residue[i], want[i])
			}
		}
	}
	// A number statement contributes nothing to the text: the residue is the
	// only place it is stated.
	if got := rendered(t, `[42,{"accept":null}]`); got != "accept" {
		t.Errorf("got %q", got)
	}
}

func TestResidueCarriesTheQueryStringRule(t *testing.T) {
	// Deterministic and payload-driven: any '?' in a serialised statement
	// strips through to the next whitespace or quote, closing brace included.
	facts := oneRule(t, `[{"synproxy":{"url":"https://host/path?key=abc&z=1"}}]`)
	residue, _ := facts["Residue"].([]any)
	const want = `{"synproxy": {"url": "https://host/path?[query-stripped]"}}`
	if len(residue) != 1 || residue[0] != want {
		t.Fatalf("\n  got  %v\n  want %s", facts["Residue"], want)
	}
}

func TestPositionIsPerChainInDocumentOrder(t *testing.T) {
	// Evaluation is ordered and first-match-wins, so position is meaning. Two
	// chains interleaved each number from their own start.
	doc, err := decodeDocument(strings.NewReader(`{"nftables":[
      {"rule":{"family":"ip","table":"t","chain":"a","handle":1,"expr":[]}},
      {"rule":{"family":"ip","table":"t","chain":"b","handle":2,"expr":[]}},
      {"rule":{"family":"ip","table":"t","chain":"a","handle":3,"expr":[]}},
      {"rule":{"family":"ip6","table":"t","chain":"a","handle":4,"expr":[]}}
    ]}`))
	if err != nil {
		t.Fatal(err)
	}
	rows := nftRules(doc)
	want := map[string]int{
		"ip t a handle 1":  0,
		"ip t b handle 2":  0,
		"ip t a handle 3":  1,
		"ip6 t a handle 4": 0,
	}
	if len(rows) != len(want) {
		t.Fatalf("one row per rule entry; got %d", len(rows))
	}
	for _, row := range rows {
		if got := row.facts["Position"]; got != want[row.name] {
			t.Errorf("%s: position %v, want %d", row.name, got, want[row.name])
		}
	}
}

func TestOnlyRuleEntriesBecomeRows(t *testing.T) {
	doc, err := decodeDocument(strings.NewReader(`{"nftables":[
      {"metainfo":{"version":"1.0.9"}},
      {"table":{"family":"ip","name":"t","handle":1}},
      {"chain":{"family":"ip","table":"t","name":"c","handle":2}},
      {"set":{"family":"ip","table":"t","name":"s","handle":3}},
      {"map":{"family":"ip","table":"t","name":"m","handle":4}},
      {"rule":{"family":"ip","table":"t","chain":"c","handle":5,"expr":[]}}
    ]}`))
	if err != nil {
		t.Fatal(err)
	}
	rows := nftRules(doc)
	if len(rows) != 1 || rows[0].name != "ip t c handle 5" {
		t.Fatalf("one row, for the rule alone; got %v", rows)
	}
}

func TestARuleCommentNeverTravels(t *testing.T) {
	// The comment is a member of the RULE object, not of expr, and this
	// collection never reads it — which is what the canary variant's plant
	// tests. A comment STATEMENT inside expr renders as the bare word.
	doc, err := decodeDocument(strings.NewReader(`{"nftables":[
      {"rule":{"family":"ip","table":"t","chain":"c","handle":5,"comment":"se-canary-nft-4f21a9c7d0",
               "expr":[{"comment":"se-canary-nft-4f21a9c7d0"},{"accept":null}]}}
    ]}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(nftRules(doc)[0].facts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "se-canary") {
		t.Fatalf("a comment reached the wire: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"Rendered":"comment accept"`) {
		t.Fatalf("got %s", encoded)
	}
}

func TestTheRuleNameCarriesTheKernelHandle(t *testing.T) {
	doc, err := decodeDocument(strings.NewReader(`{"nftables":[
      {"rule":{"family":"inet","table":"nixos-fw","chain":"input-allow","handle":16,"expr":[]}},
      {"rule":{"family":"ip","table":"t","chain":"c","handle":12.0,"expr":[]}}
    ]}`))
	if err != nil {
		t.Fatal(err)
	}
	rows := nftRules(doc)
	if rows[0].name != "inet nixos-fw input-allow handle 16" {
		t.Errorf("got %q", rows[0].name)
	}
	if rows[1].name != "ip t c handle 12.0" {
		t.Errorf("the handle is interpolated as the document spelled it: %q", rows[1].name)
	}
}
