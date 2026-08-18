package main

import "strings"

// One row per rule, in evaluation order within each chain, with what the rule
// SAYS rather than a count of how many there are.
//
// THE RENDERING DISCIPLINE, and it is the whole design. nftables' JSON
// grammar is wide, and it grows. A renderer that silently skipped a term it
// did not know would print `accept tcp dport 22` for a rule whose real text
// also says `iifname tailscale0` — not a smaller truth but the opposite
// claim, on the one surface where being confidently wrong is worst. So
// ignorance is COMPUTED: what the renderer consumed is subtracted from the
// rule's own expr array and whatever is left is carried on the row as
// Residue, which turns "an expression I did not understand" from an
// unobservable event into a per-row fact. And a term that cannot be expanded
// is rendered AT ITS POSITION as a placeholder rather than dropped, because
// omission inverts the rule's meaning and a placeholder cannot.

// Statements this renderer can state the meaning of. Anything outside this
// set becomes residue — a literal table rather than a series of type checks,
// so "what do we cover" is answerable by reading one line.
var renderedStatements = map[string]bool{
	"match": true, "counter": true, "accept": true, "drop": true,
	"reject": true, "return": true, "jump": true, "goto": true,
	"continue": true, "log": true, "limit": true, "comment": true,
}

// The verdicts a rule can end in. `queue` is named here and is NOT in
// renderedStatements, so it never reaches this test — it renders as
// `<unrendered queue>` and sets no Verdict. That is the reference's
// behaviour, contradicting its own glossary; reproduced, not corrected.
var terminalVerdicts = map[string]bool{
	"accept": true, "drop": true, "reject": true,
	"return": true, "continue": true, "queue": true,
}

// Left-hand sides of a match this renderer can name. Everything else — fib,
// socket, rt, osf, numgen, and whatever the next kernel adds — is residue.
var renderedMatchKeys = map[string]bool{"payload": true, "meta": true, "ct": true}

// renderMatch is (text, understood) for one match statement.
//
// Negation is rendered INSIDE the text rather than carried beside it as a
// flag. A separate `negated` boolean is ignorable, and it will be ignored —
// by a consumer selecting one column, by grep, by a model summarising a table
// — and the value it modifies reads as its own opposite when it is.
func renderMatch(match jsonValue) (string, bool) {
	left := match.get("left")
	op := match.get("op")
	if !match.has("op") {
		op = jsonValue{kind: jsonString, text: "=="}
	}
	right := match.get("right")

	if !left.isObject() || left.size() != 1 {
		return "", false
	}
	key := left.firstKey()

	// A masked comparison — nft writes `meta mark & 0xff0000 == 0x40000` and
	// its JSON nests the masked expression under "&". Tailscale writes every
	// one of its forward rules this way, so declining it left two rules per
	// host reading `<unrendered &> counter accept`: a mark test rendered as
	// an unconditional accept, which is the inversion this renderer exists to
	// prevent. The mask is part of the condition and is kept.
	var mask jsonValue
	masked := false
	if inner := left.get(key); key == "&" && inner.isArray() && len(inner.array) == 2 {
		expr := inner.array[0]
		mask, masked = inner.array[1], true
		if !expr.isObject() || expr.size() != 1 {
			return "", false
		}
		left = expr
		key = left.firstKey()
	}
	if !renderedMatchKeys[key] {
		return "", false
	}
	inner := left.get(key)
	var name string
	switch {
	case key == "payload" && inner.isObject():
		name = pythonStr(inner.get("protocol")) + " " + pythonStr(inner.get("field"))
	case inner.isObject():
		name = key + " " + pythonStr(inner.get("key"))
	default:
		return "", false
	}
	// A null mask is no mask: the reference unpacks it and then tests `is not
	// None`, so the left-hand side keeps its rewritten form and loses the
	// masking term.
	if masked && !mask.isNull() {
		if !mask.isInt() {
			return "", false
		}
		// Hex, because that is how a mask is written and read — 0xff0000 is
		// recognisable as the third byte where 16711680 is arithmetic.
		name = name + " & " + pythonHex(mask)
	}

	var value string
	switch {
	case right.isObject():
		prefix := right.get("prefix")
		set := right.get("set")
		switch {
		case right.has("prefix") && prefix.isObject():
			value = pythonStr(prefix.get("addr")) + "/" + pythonStr(prefix.get("len"))
		case right.has("set") && set.isArray():
			// An ANONYMOUS set carries its elements right here, so rendering
			// it as "{ ... }" would claim full comprehension while hiding the
			// membership that decides what the rule matches. A NAMED set
			// (@ports) is a reference whose membership is a separate object
			// and arrives as a plain string — the name is then what the rule
			// genuinely says, and is rendered as itself below.
			elements := make([]string, 0, len(set.array))
			for _, element := range set.array {
				switch {
				case element.isString() || element.isInt():
					elements = append(elements, pythonStr(element))
				case element.isObject() && element.get("range").isArray() && len(element.get("range").array) == 2:
					r := element.get("range")
					elements = append(elements, pythonStr(r.array[0])+"-"+pythonStr(r.array[1]))
				default:
					return "", false
				}
			}
			value = "{ " + strings.Join(elements, ", ") + " }"
		default:
			return "", false
		}
	case right.isString() || right.isInt():
		value = pythonStr(right)
	default:
		return "", false
	}

	negation := ""
	if op.isString() && op.text == "!=" {
		negation = "!= "
	}
	return name + " " + negation + value, true
}

// renderedRule is what one pass over a rule's expr array establishes: the
// text, the statements it did not consume, and the four facts a consumed
// statement can carry out.
type renderedRule struct {
	text         string
	residue      []jsonValue
	verdict      string
	jumpTarget   jsonValue
	hasJump      bool
	packets      jsonValue
	hasPackets   bool
	byteCount    jsonValue
	hasBytes     bool
	opaqueReason string
}

// renderRule walks expr once. Every statement is either rendered or recorded,
// and the two together account for the whole list — so a row can never be
// thinner than the rule without saying so.
func renderRule(expr jsonValue) renderedRule {
	var out renderedRule
	var parts []string
	for _, statement := range expr.array {
		if !statement.isObject() || statement.size() != 1 {
			// nft emits a bare string where it has no JSON encoder for an
			// expression, running its own text printer into a buffer instead.
			// The type change is the signal, and it is the one construct that
			// arrives already rendered — so it is kept verbatim and flagged.
			if statement.isString() {
				parts = append(parts, statement.text)
				if out.opaqueReason == "" {
					out.opaqueReason = "text-fallback"
				}
				out.residue = append(out.residue, statement)
				continue
			}
			out.residue = append(out.residue, statement)
			continue
		}
		verb := statement.firstKey()
		body := statement.get(verb)

		if verb == "xt" && body.isObject() {
			// nft's own convention, kept: the term appears at its position so
			// the rule keeps its shape, and the reader can see that a
			// condition exists whose content is not in this document. xt
			// overwrites a text-fallback already recorded; the reverse does
			// not happen.
			parts = append(parts, "xt "+pythonStr(body.get("type"))+" \""+pythonStr(body.get("name"))+"\"")
			out.opaqueReason = "xt"
			out.residue = append(out.residue, statement)
			continue
		}
		if !renderedStatements[verb] {
			parts = append(parts, "<unrendered "+verb+">")
			out.residue = append(out.residue, statement)
			continue
		}
		if verb == "match" && body.isObject() {
			text, understood := renderMatch(body)
			if understood && text != "" {
				parts = append(parts, text)
			} else {
				// AT ITS POSITION, which is the whole discipline. Dropping an
				// unrendered condition from the text turns `fib oif lo
				// accept` into `accept` — a narrow rule reading as an
				// unconditional one. The placeholder names the ORIGINAL
				// left-hand key, so a match whose mask branch bailed reads
				// `<unrendered &>` rather than the rewritten inner key.
				left := body.get("left")
				key := "expr"
				if left.isObject() && left.size() > 0 {
					key = left.firstKey()
				}
				parts = append(parts, "<unrendered "+key+">")
				out.residue = append(out.residue, statement)
			}
			continue
		}
		if verb == "counter" {
			// A non-object body leaves whatever a previous counter recorded,
			// which is the reference's behaviour and not obviously intended;
			// transcribed rather than tidied.
			if body.isObject() {
				out.packets, out.hasPackets = body.member("packets")
				out.byteCount, out.hasBytes = body.member("bytes")
				out.hasPackets = out.hasPackets && !out.packets.isNull()
				out.hasBytes = out.hasBytes && !out.byteCount.isNull()
			}
			parts = append(parts, "counter")
			continue
		}
		if verb == "jump" || verb == "goto" {
			// Last one wins, including a later jump with a non-object body,
			// which resets the target to nothing while still rendering.
			out.jumpTarget = jsonValue{kind: jsonNull}
			if body.isObject() {
				out.jumpTarget = body.get("target")
			}
			out.hasJump = out.jumpTarget.truthy()
			parts = append(parts, verb+" "+pythonStr(out.jumpTarget))
			continue
		}
		if terminalVerdicts[verb] {
			// The body is ignored entirely: `reject with icmpx type
			// admin-prohibited` renders as the single word reject.
			out.verdict = verb
			parts = append(parts, verb)
			continue
		}
		// log, limit and comment land here: each renders as its own word with
		// its body discarded and NO residue recorded, so a row whose log
		// prefix was dropped still reads Comprehension: full. That is the
		// reference's answer and the corpus holds it.
		parts = append(parts, verb)
	}
	out.text = strings.Join(parts, " ")
	return out
}

type ruleRow struct {
	name  string
	facts map[string]any
}

// nftRules derives one row per `rule` entry, in document order.
func nftRules(doc jsonValue) []ruleRow {
	var rows []ruleRow
	position := map[chainKey]int{}
	entries, _ := doc.member("nftables")
	for _, entry := range entries.array {
		if !entry.has("rule") {
			continue
		}
		rule := entry.get("rule")
		family := rule.stringMember("family")
		table := rule.stringMember("table")
		chain := rule.stringMember("chain")
		handle := rule.get("handle")

		// Ordinal within its own chain, counted in document order: nftables
		// evaluates top to bottom and the first match wins, so position is
		// meaning, not presentation.
		key := chainKey{family, table, chain}
		index := position[key]
		position[key] = index + 1

		rendered := renderRule(rule.get("expr"))
		facts := map[string]any{
			"Family":   family,
			"Table":    table,
			"Chain":    chain,
			"Position": index,
			"Rendered": rendered.text,
		}
		// The reference emits rule["handle"] unconditionally, which is a null
		// fact when the member is missing — a value the contract forbids at
		// any depth and check_stream refuses. Handle is declared an integer,
		// so an absent one lands on that type's zero rather than on a null.
		// No document nft produces omits it.
		if handle.isNull() {
			facts["Handle"] = 0
		} else {
			facts["Handle"] = handle
		}
		if rendered.verdict != "" {
			facts["Verdict"] = rendered.verdict
		}
		if rendered.hasJump {
			facts["JumpTarget"] = rendered.jumpTarget
		}
		// Comprehension is derived from the residue rather than set where a
		// branch happened to notice something: one computation, so a renderer
		// that grows a case cannot forget to update the claim.
		switch {
		case rendered.opaqueReason != "":
			facts["Comprehension"] = "opaque"
			facts["OpaqueReason"] = rendered.opaqueReason
		case len(rendered.residue) > 0:
			facts["Comprehension"] = "partial"
		default:
			facts["Comprehension"] = "full"
		}
		if len(rendered.residue) > 0 {
			residue := make([]string, 0, len(rendered.residue))
			for _, statement := range rendered.residue {
				residue = append(residue, reasonText(pythonDumps(statement)))
			}
			facts["Residue"] = residue
		}
		// Absent, never zero: nftables has no implicit per-rule counters, so
		// a rule without one has no traffic history at all and a 0 would
		// report an idle rule that is simply uncounted. A counter READING of
		// zero is emitted, which is the opposite mistake and just as easy.
		if rendered.hasPackets {
			facts["CounterPackets"] = rendered.packets
		}
		if rendered.hasBytes {
			facts["CounterBytes"] = rendered.byteCount
		}
		rows = append(rows, ruleRow{
			name:  family + " " + table + " " + chain + " handle " + pythonStr(handle),
			facts: facts,
		})
	}
	return rows
}
