// The two-closure join, held to the reference's recorded traps — each case
// below is a defect that shipped once, with its date where the reference
// states one. These are unit tests over staged documents; the corpus variant
// holds the whole collection to a real capture.
package main

import (
	"strings"
	"testing"
)

func parseDoc(t *testing.T, raw string) jsonValue {
	t.Helper()
	doc, err := decodeDocument(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func rulesetOf(t *testing.T, entries ...string) jsonValue {
	t.Helper()
	return parseDoc(t, `{"nftables":[`+strings.Join(entries, ",")+`]}`)
}

const inputBase = `{"chain":{"family":"inet","table":"fw","name":"input",
	"handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}}`

func exposureFacts(t *testing.T, doc jsonValue, protocol string, port int) map[string]any {
	t.Helper()
	path := walkInputPath(doc)
	var admitting, certain, possible, gapRules []string
	for _, entry := range path {
		if !familyBearsOn(entry.rule.stringMember("family"), protocol) {
			continue
		}
		ruleExpr, _ := entry.rule.member("expr")
		expr := append(append([]jsonValue{}, entry.guards...), ruleExpr.array...)
		rendered := renderRule(jsonValue{kind: jsonArray, array: expr})
		unreadableVerdict := rendered.verdict == "" && !rendered.hasJump &&
			len(rendered.residue) > 0
		if rendered.verdict != "accept" && !unreadableVerdict {
			continue
		}
		sure, maybe := ruleBearsOn(rendered, expr, protocol, port)
		if unreadableVerdict {
			sure = false
		}
		if !maybe {
			continue
		}
		admitting = append(admitting, rendered.text)
		for _, source := range sourcesOf(expr) {
			if sure {
				certain = appendUnique(certain, source)
			}
			possible = appendUnique(possible, source)
		}
		if !sure {
			gapRules = append(gapRules, "gap")
		}
	}
	out := map[string]any{}
	if len(admitting) > 0 {
		out["admitting"] = admitting
	}
	if len(certain) > 0 {
		out["certain"] = certain
	}
	if len(possible) > 0 {
		out["possible"] = possible
	}
	out["gap"] = len(gapRules) > 0
	return out
}

// The guard-flattening inversion, measured against a live cloud host's
// ruleset 2026-08-13: the input chain jumps to an accept chain under
// `tcp dport 22 ip saddr`, and the accept inside has no conditions of its
// own. Flattened, the bare accept admitted every port from anywhere.
func TestAJumpGuardConstrainsTheAcceptInside(t *testing.T) {
	doc := rulesetOf(t, inputBase,
		`{"rule":{"family":"inet","table":"fw","chain":"input","handle":2,
		  "expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},
		          {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}},
		          {"jump":{"target":"svc"}}]}}`,
		`{"rule":{"family":"inet","table":"fw","chain":"svc","handle":3,
		  "expr":[{"counter":{"packets":0,"bytes":0}},{"accept":null}]}}`)

	admitted := exposureFacts(t, doc, "tcp", 22)
	if admitted["gap"] != false || len(admitted["certain"].([]string)) != 1 {
		t.Fatalf("the guarded accept is certain for the guarded port: %+v", admitted)
	}
	// The inversion: any OTHER port must not be admitted at all — the guard
	// travelled with the jump.
	other := exposureFacts(t, doc, "tcp", 443)
	if other["possible"] != nil {
		t.Fatalf("port 443 is outside the guard and admitted by nothing: %+v", other)
	}
}

// The ICMP credit, found live 2026-08-13: `meta l4proto ipv6-icmp accept`
// is fully rendered and was therefore CERTAIN — for a tcp socket. The meta
// protocol constraint must exclude it entirely.
func TestAMetaProtocolConstraintExcludesOtherProtocols(t *testing.T) {
	doc := rulesetOf(t, inputBase,
		`{"rule":{"family":"inet","table":"fw","chain":"input","handle":2,
		  "expr":[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"ipv6-icmp"}},
		          {"counter":null},{"accept":null}]}}`)
	admitted := exposureFacts(t, doc, "tcp", 22)
	if admitted["possible"] != nil {
		t.Fatalf("an icmp-only accept bears on no tcp socket: %+v", admitted)
	}
}

// The range drop: `tcp dport { 8000-8100 }` renders with no residue, and a
// closure extracting only bare integers read the constraint as absent — one
// range rule then admitted every port on the host, certainly, from anywhere.
func TestARangeDportConstrainsInsideAndOutside(t *testing.T) {
	doc := rulesetOf(t, inputBase,
		`{"rule":{"family":"inet","table":"fw","chain":"input","handle":2,
		  "expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[{"range":[8000,8100]}]}}},
		          {"accept":null}]}}`)
	inside := exposureFacts(t, doc, "tcp", 8050)
	if inside["certain"] == nil {
		t.Fatalf("8050 is inside the range and certainly admitted: %+v", inside)
	}
	outside := exposureFacts(t, doc, "tcp", 22)
	if outside["possible"] != nil {
		t.Fatalf("22 is outside the range and admitted by nothing: %+v", outside)
	}
}

// Negation is an exclusion and this closure models inclusions: reading
// `tcp dport != 22` as `== 22` turns a rule admitting everything BUT ssh
// into one admitting only ssh. An inequality costs the rule its certainty
// instead — conservative in the direction that cannot hurt.
func TestANegatedMatchIsPossibleButNeverCertain(t *testing.T) {
	doc := rulesetOf(t, inputBase,
		`{"rule":{"family":"inet","table":"fw","chain":"input","handle":2,
		  "expr":[{"match":{"op":"!=","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},
		          {"accept":null}]}}`)
	admitted := exposureFacts(t, doc, "tcp", 443)
	if admitted["certain"] != nil || admitted["possible"] == nil || admitted["gap"] != true {
		t.Fatalf("a negated match is possible, gapped, never certain: %+v", admitted)
	}
}

// A rule whose verdict could not be read might be an accept — a verdict map,
// or a statement nft could only emit as text. Skipping it dropped it from
// BOTH closures: silence where the honest answer is "something here might
// admit this and I cannot tell".
func TestAnUnreadableVerdictLandsInThePossibleClosure(t *testing.T) {
	doc := rulesetOf(t, inputBase,
		`{"rule":{"family":"inet","table":"fw","chain":"input","handle":2,
		  "expr":[{"vmap":{"key":{"ct":{"key":"state"}},"data":"@dispatch"}}]}}`)
	admitted := exposureFacts(t, doc, "tcp", 22)
	if admitted["certain"] != nil || admitted["possible"] == nil || admitted["gap"] != true {
		t.Fatalf("an unreadable verdict is possible, gapped, never certain: %+v", admitted)
	}
}

// An opaque xt guard on the jump must stay a guard: kept as residue, it
// costs every rule in the jumped-to chain its certainty rather than reading
// as no condition at all — the live host's `xt match "conntrack" jump
// nixos-fw-accept` shape.
func TestAnOpaqueGuardCostsTheSubtreeItsCertainty(t *testing.T) {
	doc := rulesetOf(t, inputBase,
		`{"rule":{"family":"inet","table":"fw","chain":"input","handle":2,
		  "expr":[{"xt":{"type":"match","name":"conntrack"}},{"jump":{"target":"svc"}}]}}`,
		`{"rule":{"family":"inet","table":"fw","chain":"svc","handle":3,
		  "expr":[{"accept":null}]}}`)
	admitted := exposureFacts(t, doc, "tcp", 22)
	if admitted["certain"] != nil || admitted["possible"] == nil || admitted["gap"] != true {
		t.Fatalf("an opaque guard leaves the subtree possible, never certain: %+v", admitted)
	}
}

// An ip-family rule decides nothing about an IPv6 socket and vice versa;
// crediting one with the other landed a whole table's rules on the wrong
// sockets. inet bears on both.
func TestFamilySelectsWhichSocketsARuleCanDecide(t *testing.T) {
	for family, verdicts := range map[string]map[string]bool{
		"ip":   {"tcp": true, "tcp6": false, "udp": true, "udp6": false},
		"ip6":  {"tcp": false, "tcp6": true},
		"inet": {"tcp": true, "tcp6": true, "udp": true, "udp6": true},
		"arp":  {"tcp": false, "udp": false},
	} {
		for protocol, want := range verdicts {
			if got := familyBearsOn(family, protocol); got != want {
				t.Errorf("familyBearsOn(%s, %s) = %v, want %v", family, protocol, got, want)
			}
		}
	}
}

// A cycle in the chain graph must shorten the walk, not hang it.
func TestAChainCycleTerminates(t *testing.T) {
	doc := rulesetOf(t, inputBase,
		`{"rule":{"family":"inet","table":"fw","chain":"input","handle":2,
		  "expr":[{"jump":{"target":"a"}}]}}`,
		`{"rule":{"family":"inet","table":"fw","chain":"a","handle":3,
		  "expr":[{"jump":{"target":"input"}}]}}`)
	if got := len(walkInputPath(doc)); got != 2 {
		t.Fatalf("the cycle walk visits each chain once: %d rules", got)
	}
}

func TestSourcesReadInTheRulesOwnWords(t *testing.T) {
	doc := rulesetOf(t, inputBase,
		`{"rule":{"family":"inet","table":"fw","chain":"input","handle":2,
		  "expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"tailscale0"}},
		          {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},
		          {"accept":null}]}}`,
		`{"rule":{"family":"inet","table":"fw","chain":"input","handle":3,
		  "expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":80}},
		          {"accept":null}]}}`)
	ssh := exposureFacts(t, doc, "tcp", 22)
	if certain := ssh["certain"].([]string); len(certain) != 1 ||
		!strings.Contains(certain[0], "tailscale0") {
		t.Fatalf("the iifname source in the rule's own words: %+v", ssh)
	}
	web := exposureFacts(t, doc, "tcp", 80)
	if certain := web["certain"].([]string); len(certain) != 1 || certain[0] != "anywhere" {
		t.Fatalf("no source constraint admits from anywhere, said plainly: %+v", web)
	}
}
