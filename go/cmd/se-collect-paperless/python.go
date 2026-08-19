package main

import (
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The five error facts this collection can publish are built as PYTHON TEXT,
// not as JSON: `env.reason(tasks["classifier_error"])` runs str() over a raw
// document value and then bounds and scrubs it. That lands in a string fact
// the harness compares character for character, so Python's spellings are part
// of the answer — its str(True) == "True", its "None" for a missing member, its
// repr of a container. This file is that vocabulary, kept together so the
// reasons live in one place rather than scattered through the derivation. It
// is the same file se-collect-bazarr and se-collect-network carry, trimmed to
// what one bounded reason needs.

// ── str() and repr() ────────────────────────────────────────────────────

// pythonStr is str(value) over a decoded JSON document — what env.reason
// receives. A JSON string is itself; everything else goes through repr, which
// is why a component error the app spelled as a number reads as its digits and
// one spelled as an object reads as a Python dict literal.
func pythonStr(v jsonValue) string {
	if v.kind == jsonString {
		return v.text
	}
	return pythonRepr(v)
}

func pythonRepr(v jsonValue) string {
	switch v.kind {
	case jsonNull:
		return "None"
	case jsonBool:
		if v.boolean {
			return "True"
		}
		return "False"
	case jsonNumber:
		return pythonNumberText(v.number)
	case jsonString:
		return pythonStringRepr(v.text)
	case jsonArray:
		parts := make([]string, 0, len(v.array))
		for _, element := range v.array {
			parts = append(parts, pythonRepr(element))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case jsonObject:
		parts := make([]string, 0, len(v.members))
		for _, m := range v.members {
			parts = append(parts, pythonStringRepr(m.key)+": "+pythonRepr(m.value))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return "None"
}

// pythonStringRepr is repr(str): single quotes unless that would need
// escaping and double quotes would not, non-ASCII left alone where it is
// printable. Reachable only where a component's error member holds a container
// whose elements are strings — paperless writes sentences there and no
// committed payload does anything else — written out rather than approximated
// so that shape reads the same on both sides.
func pythonStringRepr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	out := []byte{quote}
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			out = append(out, '\\', byte(r))
		case r == '\n':
			out = append(out, '\\', 'n')
		case r == '\r':
			out = append(out, '\\', 'r')
		case r == '\t':
			out = append(out, '\\', 't')
		case r < 0x20 || r == 0x7f:
			out = append(out, '\\', 'x')
			out = appendHexDigits(out, uint32(r), 2)
		case r < 0x7f:
			out = append(out, byte(r))
		case unicode.IsPrint(r):
			out = utf8.AppendRune(out, r)
		case r <= 0xff:
			out = append(out, '\\', 'x')
			out = appendHexDigits(out, uint32(r), 2)
		case r <= 0xffff:
			out = append(out, '\\', 'u')
			out = appendHexDigits(out, uint32(r), 4)
		default:
			out = append(out, '\\', 'U')
			out = appendHexDigits(out, uint32(r), 8)
		}
	}
	return string(append(out, quote))
}

func appendHexDigits(out []byte, value uint32, width int) []byte {
	const hex = "0123456789abcdef"
	for shift := (width - 1) * 4; shift >= 0; shift -= 4 {
		out = append(out, hex[(value>>uint(shift))&0xf])
	}
	return out
}

// ── numbers ─────────────────────────────────────────────────────────────

// pythonNumberText is str() of what json.loads made of a number literal. The
// distinction that matters: a literal carrying a fraction or an exponent
// becomes a Python float and is re-spelled by repr, so "1E2" comes back as
// "100.0" — while an integer literal is arbitrary precision and comes back
// exactly as written. Only an error member that is a number depends on this;
// every count and every status word carries the literal itself, because the
// harness compares parsed values there.
func pythonNumberText(literal string) string {
	if literal == "" {
		return "0"
	}
	if isIntegerLiteral(literal) {
		if literal == "-0" {
			return "0"
		}
		return literal
	}
	f, err := strconv.ParseFloat(literal, 64)
	if err != nil {
		// Out of float64 range: Python's float() saturates to inf the same
		// way, and repr spells it as the JSON-invalid word json.dumps emits.
		if strings.HasPrefix(literal, "-") {
			f = math.Inf(-1)
		} else {
			f = math.Inf(1)
		}
	}
	return pythonFloatRepr(f)
}

// pythonFloatRepr is repr(float): the shortest round-tripping digits, then
// fixed notation unless the decimal point sits outside (-4, 16], and always a
// fractional part so the value cannot be misread as an integer.
func pythonFloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	// 'e' with precision -1 gives the shortest round-trip as d[.ddd]e±dd,
	// which is the same digit string Python starts from.
	shortest := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exponent, _ := strings.Cut(shortest, "e")
	sign := ""
	if strings.HasPrefix(mantissa, "-") {
		sign, mantissa = "-", mantissa[1:]
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	exp, err := strconv.Atoi(exponent)
	if err != nil {
		return shortest
	}
	// decpt is where the decimal point falls relative to the digit string:
	// value == 0.<digits> * 10^decpt.
	decpt := exp + 1
	if digits == "0" {
		decpt = 1
	}
	if decpt <= -4 || decpt > 16 {
		out := digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		return sign + out + "e" + formatExponent(decpt-1)
	}
	switch {
	case decpt <= 0:
		return sign + "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		return sign + digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		return sign + digits[:decpt] + "." + digits[decpt:]
	}
}

func formatExponent(exp int) string {
	sign := "+"
	if exp < 0 {
		sign, exp = "-", -exp
	}
	if exp < 10 {
		return sign + "0" + strconv.Itoa(exp)
	}
	return sign + strconv.Itoa(exp)
}

// ── the envelope's bounding and scrubbing ───────────────────────────────

// maxReasonLength is system_explorer.text.MAX_LENGTH, which envelope.reason
// applies by default and status_facts takes as it comes.
const maxReasonLength = 400

// oneLine collapses whitespace and bounds on a word boundary. The rule is
// stated in characters rather than bytes, and paperless writes these sentences
// itself in whatever locale the instance runs, so the count runs over runes.
func oneLine(value string, limit int) string {
	flat := strings.Join(strings.Fields(value), " ")
	runes := []rune(flat)
	if len(runes) <= limit {
		return flat
	}
	window := string(runes[:limit])
	head := window
	if cut := strings.LastIndexByte(window, ' '); cut >= 0 {
		head = window[:cut]
	}
	if head == "" {
		// No space in the window at all: the reference keeps it whole rather
		// than emitting a marker with nothing in front of it.
		head = window
	}
	return strings.TrimRight(head, " ,;:.([{-") + " … (truncated)"
}

// scrub removes the two credential shapes a URL carries, and this collection
// is the one where that is not a precaution: paperless's database check names
// the DSN it could not reach, which on a Postgres deployment is
// `postgresql://user:password@host/db` — the same two positions the adapter
// strips from the status document before any evidence ships.
//
// It is deliberately NOT the whole of the reference's scrub: that also
// substitutes the values of the ambient *_TOKEN / *_API_KEY / *_SECRET /
// *_PASSWORD environment variables, read from os.environ at call time, which
// would make this collector's output depend on the environment of whoever ran
// it — and this collector is itself addressed by SE_PAPERLESS_TOKEN, so the
// substitution would fire on its own credential and make one payload replay two
// ways. The ruling that parks the environment half is DESIGN's "the residue
// scrubber may not read ambient environment"; the two rules kept are functions
// of the payload alone.
func scrub(value string) string {
	return stripUserinfo(stripQueryStrings(value))
}

// A '?' anywhere in the text takes everything after it up to the next
// whitespace or quote — the reference's rule is a bare regex over failure
// text, not a URL parse, so it fires on any question mark a component's error
// sentence happens to hold.
func stripQueryStrings(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '?' {
			out.WriteByte(value[i])
			i++
			continue
		}
		end := i + 1
		for end < len(value) && !isQueryTerminator(value[end]) {
			end++
		}
		if end == i+1 {
			out.WriteByte('?')
			i++
			continue
		}
		out.WriteString("?[query-stripped]")
		i = end
	}
	return out.String()
}

func isQueryTerminator(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r', '"', '\'', '<', '>':
		return true
	}
	return false
}

// The other half of a URL that carries a credential: user:pass@host. Matched
// only where "://" precedes it, which is the reference's lookbehind.
func stripUserinfo(value string) string {
	var out strings.Builder
	i := 0
	for {
		at := strings.Index(value[i:], "://")
		if at < 0 {
			out.WriteString(value[i:])
			return out.String()
		}
		start := i + at + 3
		out.WriteString(value[i:start])
		end := start
		for end < len(value) && !isUserinfoTerminator(value[end]) {
			end++
		}
		if end > start && end < len(value) && value[end] == '@' {
			out.WriteString("[userinfo-stripped]@")
			i = end + 1
			continue
		}
		i = start
	}
}

func isUserinfoTerminator(c byte) bool {
	switch c {
	case '/', ' ', '\t', '\n', '\v', '\f', '\r', '"', '\'', '<', '>', '@':
		return true
	}
	return false
}

// reasonText is envelope.reason(text) — bound first, scrub second, in that
// order, because bounding a scrubbed string and scrubbing a bounded one cut in
// different places.
func reasonText(value string) string {
	return scrub(oneLine(value, maxReasonLength))
}
