package main

// port-exposure: the joined answer nft and listening produce together — one
// row per listening socket, with the input-path rules that admit it and the
// two-closure answer to "where from". The two closures are the collection's
// whole discipline: `AdmittedFromCertain` may only under-claim and
// `AdmittedFromPossible` may only over-claim, because ignorance must never
// strengthen a claim. Every trap recorded in the reference travels with its
// port: the guard-flattening inversion, the meta-l4proto ICMP credit, the
// range-dport drop, negation-as-inclusion, and the unreadable verdict that
// vanished from both closures.

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// inputHooks: a rule only decides an inbound packet if control reaches it,
// and control starts at a base chain on the input hook.
const inputHook = "input"

// chainWalkMaxDepth bounds the jump graph: a cycle must not turn a page
// render into a hang, and a chain graph deeper than this is not something a
// static reader should claim to have followed anyway.
const chainWalkMaxDepth = 8

// pathCoverage is stated on every row, not only in the declaration: a
// consumer holding one object must be able to see that an empty admitting
// list is not a statement that nothing can reach this port.
const pathCoverage = "input path only; a port published through" +
	" prerouting/forward is not accounted for"

// socketFamilies: which address families can carry a socket's traffic. A
// rule in an `ip` table decides nothing about an IPv6 packet and vice versa
// — measured as ip6-only accepts certainly admitting IPv4 sockets. A
// dual-stack socket bound to :: does also receive IPv4-mapped traffic, which
// this does NOT model: an ip-family rule is not credited to a tcp6 socket,
// which under-claims, the only direction this collection may be wrong in.
var socketFamilies = map[string][]string{
	"tcp": {"ip", "inet"}, "udp": {"ip", "inet"},
	"tcp6": {"ip6", "inet"}, "udp6": {"ip6", "inet"},
}

func familyBearsOn(family, protocol string) bool {
	for _, allowed := range socketFamilies[protocol] {
		if family == allowed {
			return true
		}
	}
	return false
}

type guardedRule struct {
	rule   jsonValue
	guards []jsonValue
}

type pathKey struct{ family, table, chain string }

// walkInputPath is every rule reachable from an input base chain, in
// evaluation order, WITH the conditions guarding it.
//
// The guards are the dangerous direction. NixOS admits a port by jumping to
// nixos-fw-accept under `iifname tailscale0 tcp dport 22`, and the accept
// inside has no conditions of its own — a walk that flattened the two would
// report every port on the host as admitted from anywhere, the exact
// inversion this collection exists to prevent. Measured against a live
// single-purpose cloud host's ruleset, 2026-08-13.
//
// EVERY statement of the jumping rule is carried, not only the ones the
// renderer understands: keeping just the readable matches turns an opaque
// guard (`xt match "conntrack"`) into NO guard, and the bare accept inside
// read as unconditional again. Only a bare top-level jump/goto is dropped —
// control transfer with no matching content. A statement that nests its
// verdict (a ct-state vmap) IS the dispatch condition, so it stays, and it
// stays as residue: a vmap-dispatched subtree can never reach the certain
// answer, which is under-claiming, loudly.
//
// A chain already on the current path is not re-entered — conservative in
// the right direction: it can only shorten the list, and a shorter list can
// only narrow the certain answer.
func walkInputPath(doc jsonValue) []guardedRule {
	byChain := map[pathKey][]jsonValue{}
	var baseOrder []pathKey
	entries, _ := doc.member("nftables")
	for _, entry := range entries.array {
		switch {
		case entry.has("rule"):
			r := entry.get("rule")
			key := pathKey{r.stringMember("family"), r.stringMember("table"),
				r.stringMember("chain")}
			byChain[key] = append(byChain[key], r)
		case entry.has("chain"):
			c := entry.get("chain")
			if c.stringMember("hook") == inputHook {
				baseOrder = append(baseOrder, pathKey{c.stringMember("family"),
					c.stringMember("table"), c.stringMember("name")})
			}
		}
	}

	var ordered []guardedRule
	var walk func(key pathKey, depth int, seen map[pathKey]bool, guards []jsonValue)
	walk = func(key pathKey, depth int, seen map[pathKey]bool, guards []jsonValue) {
		if depth > chainWalkMaxDepth || seen[key] {
			return
		}
		onPath := make(map[pathKey]bool, len(seen)+1)
		for k := range seen {
			onPath[k] = true
		}
		onPath[key] = true
		for _, rule := range byChain[key] {
			expr, _ := rule.member("expr")
			ordered = append(ordered, guardedRule{rule: rule, guards: guards})
			for _, target := range verdictTargets(expr) {
				descendantGuards := append([]jsonValue{}, guards...)
				for _, statement := range expr.array {
					if statement.isObject() &&
						(statement.has("jump") || statement.has("goto")) {
						continue
					}
					descendantGuards = append(descendantGuards, statement)
				}
				walk(pathKey{key.family, key.table, target}, depth+1,
					onPath, descendantGuards)
			}
		}
	}
	for _, key := range baseOrder {
		walk(key, 0, map[pathKey]bool{}, nil)
	}
	return ordered
}

// classifyMatch: "destination" narrows WHAT is reached and decides whether a
// rule bears on a socket at all; "source" narrows WHERE FROM and is the
// answer; "other" is a renderable constraint this closure does not model,
// which costs the rule its certainty. It exists because the ICMP defect was
// not a parsing failure — the renderer printed `meta l4proto ipv6-icmp`
// perfectly — it was a COVERAGE MISMATCH: a term the renderer knew that the
// closure silently ignored, so a rule constraining protocol read as a rule
// constraining nothing.
func classifyMatch(match jsonValue) string {
	text, understood := renderMatch(match)
	if !understood || text == "" {
		return "" // unrenderable: the residue already accounts for it
	}
	left := match.get("left")
	if !left.isObject() || left.size() == 0 {
		return ""
	}
	key := left.firstKey()
	inner := left.get(key)
	field := ""
	if inner.isObject() {
		if key == "payload" {
			field = inner.stringMember("field")
		} else if key == "meta" {
			field = inner.stringMember("key")
		}
	}
	switch key {
	case "payload":
		switch field {
		case "dport", "protocol":
			return "destination"
		case "saddr":
			return "source"
		}
		return "other"
	case "meta":
		switch field {
		case "l4proto":
			return "destination"
		case "iifname", "iif", "iifgroup", "iifkind":
			return "source"
		}
		return "other"
	}
	return "other"
}

// portValues is the ports a dport match admits, or (nil, false) where the
// shape is unreadable. Ranges are the case that mattered: the renderer
// prints `tcp dport { 8000-8100 }` with no residue, so a closure extracting
// only the integers silently dropped the whole constraint — and an empty
// port set reads as "no port constraint", which made one range rule admit
// every port on the host, certainly, from anywhere.
func portValues(right jsonValue) (map[int]bool, bool) {
	if right.isInt() {
		port, err := strconv.Atoi(right.number)
		if err != nil {
			return nil, false
		}
		return map[int]bool{port: true}, true
	}
	set, ok := right.member("set")
	if !right.isObject() || !ok || !set.isArray() {
		return nil, false
	}
	ports := map[int]bool{}
	for _, element := range set.array {
		if element.isInt() {
			port, err := strconv.Atoi(element.number)
			if err != nil {
				return nil, false
			}
			ports[port] = true
			continue
		}
		bounds, ok := element.member("range")
		if !element.isObject() || !ok || !bounds.isArray() ||
			len(bounds.array) != 2 ||
			!bounds.array[0].isInt() || !bounds.array[1].isInt() {
			return nil, false
		}
		low, lowErr := strconv.Atoi(bounds.array[0].number)
		high, highErr := strconv.Atoi(bounds.array[1].number)
		if lowErr != nil || highErr != nil {
			return nil, false
		}
		// Bounded: a rule may legitimately admit 1-65535, and materialising
		// that is fine, but a malformed pair must not turn a page render
		// into an allocation.
		if !(0 <= low && low <= high && high <= 65535) {
			return nil, false
		}
		for port := low; port <= high; port++ {
			ports[port] = true
		}
	}
	return ports, true
}

// ruleBearsOn: (certainly bears on this socket, possibly bears on it).
// "Bears on" is about the DESTINATION — source constraints are the answer,
// not the filter. A rule with an unreadable clause is possible but never
// certain, which is the whole of the lower closure.
func ruleBearsOn(rendered renderedRule, expr []jsonValue, protocol string, port int) (bool, bool) {
	readable := len(rendered.residue) == 0
	// Constraints are INTERSECTED, per-term rather than pooled: a rule
	// reached through a jump carries the guard's constraints and its own,
	// and pooling unions what should narrow — `tcp dport 22 jump svc`
	// guarding `tcp dport 443 accept` admits neither port, where a single
	// dports list containing both said it admits both.
	var portSets []map[int]bool
	var protocolSets []map[string]bool
	for _, statement := range expr {
		if !statement.isObject() || !statement.has("match") {
			continue
		}
		body := statement.get("match")
		// A renderable constraint this closure does not model cannot leave
		// the rule certain: it narrows the traffic in a way nothing here
		// accounts for, so treating it as absent is exactly the inversion.
		if classifyMatch(body) == "other" {
			readable = false
		}
		left := body.get("left")
		if !left.isObject() {
			continue
		}
		// NEGATION IS AN EXCLUSION, and this closure models inclusions.
		// Reading `tcp dport != 22` as though it said `== 22` turns a rule
		// admitting everything BUT ssh into one admitting only ssh. Rather
		// than model exclusion sets, an inequality costs the rule its
		// certainty: correct, and conservative in the direction that cannot
		// hurt.
		if op, ok := body.member("op"); ok && op.text != "==" {
			readable = false
			continue
		}
		right := body.get("right")
		// A protocol can be constrained through meta as well as through the
		// packet's own header, and reading only the second credited an
		// ICMP-only accept with admitting tcp/22 from anywhere. Found on a
		// live host, 2026-08-13: `meta l4proto ipv6-icmp counter accept`,
		// fully rendered, and therefore CERTAIN — the worst place to be
		// wrong, because a certain answer is the one an operator is told
		// they can defend.
		if meta := left.get("meta"); left.has("meta") && meta.isObject() {
			if meta.stringMember("key") == "l4proto" && right.isString() {
				protocolSets = append(protocolSets,
					map[string]bool{right.text: true})
			}
			continue
		}
		if !left.has("payload") {
			continue
		}
		payload := left.get("payload")
		field := payload.stringMember("field")
		proto := payload.stringMember("protocol")
		if field == "dport" {
			ports, ok := portValues(right)
			if !ok {
				readable = false // a dport shape we cannot read
			} else {
				portSets = append(portSets, ports)
			}
			if proto == "tcp" || proto == "udp" {
				protocolSets = append(protocolSets, map[string]bool{proto: true})
			}
		} else if field == "protocol" && right.isString() {
			protocolSets = append(protocolSets, map[string]bool{right.text: true})
		}
	}
	wire := strings.ReplaceAll(protocol, "6", "")
	for _, allowed := range protocolSets {
		if !allowed[wire] {
			return false, false // a different protocol entirely
		}
	}
	for _, allowedPorts := range portSets {
		if !allowedPorts[port] {
			return false, false // a different port entirely
		}
	}
	// No dport constraint at all means the rule bears on every port, which
	// is what a blanket `iifname lo accept` does and is exactly the case an
	// operator most needs to see.
	return readable, true
}

// sourcesOf: where a rule admits traffic FROM, in the rule's own words. A
// rule with no source constraint admits from anywhere, and saying so plainly
// is the point — an empty list would read as "no sources", the opposite.
func sourcesOf(expr []jsonValue) []string {
	var sources []string
	for _, statement := range expr {
		if !statement.isObject() || !statement.has("match") {
			continue
		}
		body := statement.get("match")
		if classifyMatch(body) != "source" {
			continue
		}
		if text, _ := renderMatch(body); text != "" {
			sources = append(sources, text)
		}
	}
	if len(sources) == 0 {
		return []string{"anywhere"}
	}
	return sources
}

func appendUnique(list []string, value string) []string {
	for _, held := range list {
		if held == value {
			return list
		}
	}
	return append(list, value)
}

// emitExposure joins the two acquisitions this collection exists to join.
func emitExposure(out *emitter, stderr io.Writer, src source, collection string,
	doc jsonValue, generation uint64, objects *int) int {
	sockets, unread := acquireListening(src)
	if len(unread) == 4 {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unavailable",
			Detail: "none of the /proc/net socket tables could be read, so " +
				"what this host is listening on is unobservable rather than nothing"})
		fmt.Fprintln(stderr, "port-exposure:", strings.Join(unread, "; "))
		return exitOK
	}
	path := walkInputPath(doc)

	for _, socket := range sockets {
		protocol, port := socket.protocol, socket.port
		var admitting, certain, possible, gapRules []string
		for _, entry := range path {
			if !familyBearsOn(entry.rule.stringMember("family"), protocol) {
				continue
			}
			// The guards first: a rule inside a jumped-to chain is reached
			// only under the jumping rule's conditions, and they constrain
			// what it admits exactly as its own do.
			ruleExpr, _ := entry.rule.member("expr")
			expr := append(append([]jsonValue{}, entry.guards...), ruleExpr.array...)
			rendered := renderRule(jsonValue{kind: jsonArray, array: expr})
			// A rule whose VERDICT could not be read might be an accept — a
			// verdict map, or a statement nft could only emit as text.
			// Skipping it dropped it from BOTH closures: silence where the
			// honest answer is "something here might admit this and I
			// cannot tell".
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
			handle := "None"
			if h, ok := entry.rule.member("handle"); ok && h.isInt() {
				handle = h.number
			}
			where := entry.rule.stringMember("family") + "/" +
				entry.rule.stringMember("table") + "/" +
				entry.rule.stringMember("chain") + "/" + handle
			admitting = append(admitting, where+": "+rendered.text)
			for _, source := range sourcesOf(expr) {
				if sure {
					certain = appendUnique(certain, source)
				}
				possible = appendUnique(possible, source)
			}
			if !sure {
				gapRules = append(gapRules, where)
			}
		}
		facts := map[string]any{
			"Protocol":     protocol,
			"LocalAddress": socket.address,
			"LocalPort":    port,
			"Scope":        listeningScope(socket.address),
			"PathCoverage": pathCoverage,
		}
		if len(admitting) > 0 {
			facts["AdmittingRules"] = admitting
		}
		// Absent rather than an empty list where nothing was found: the
		// question "which rules admit this" was asked of the input path
		// alone, and an empty answer is about that path, never the port.
		if len(certain) > 0 {
			facts["AdmittedFromCertain"] = certain
		}
		if len(possible) > 0 {
			facts["AdmittedFromPossible"] = possible
		}
		if len(gapRules) > 0 {
			facts["ClosureGap"] = true
			facts["ClosureGapRules"] = gapRules
		} else if len(possible) > 0 {
			facts["ClosureGap"] = false
		}
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			Name:       fmt.Sprintf("%s %s:%d", protocol, socket.address, port),
			Type:       "port-exposure",
			Facts:      facts,
			At:         src.stamp(*objects),
		})
		*objects++
	}
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    len(sockets),
	})
	return exitOK
}
