package main

import (
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Two readings in this collector are PYTHON TEXT rather than JSON: a session's
// Title is `f"{grandparent} — {title}"` over two raw document members, and a
// library's native name is `str(key)` over another. Both land where the harness
// compares character for character, so Python's spellings are part of the answer
// — its str(True) == "True", its repr of a container, its "100.0" for the
// literal 1E2. This file is that vocabulary, kept together so the reasons live in
// one place rather than scattered through the derivation; it is the same file
// se-collect-bazarr and se-collect-network carry, trimmed to what one f-string
// and one str() need.

// pythonStr is str(value) over a decoded JSON document. A JSON string
// interpolates as itself; everything else goes through repr, which is why a
// null grandparent title would read as the four-character word None rather than
// as an empty string — though the truthiness gate above it means that shape
// never reaches here from the reference's own branch.
func pythonStr(v *value) string {
	if v != nil && v.kind == jsonString {
		return v.text
	}
	return pythonRepr(v)
}

func pythonRepr(v *value) string {
	if v == nil {
		return "None"
	}
	switch v.kind {
	case jsonNull:
		return "None"
	case jsonBool:
		if v.boolean {
			return "True"
		}
		return "False"
	case jsonNumber:
		return pythonNumberText(v.text)
	case jsonString:
		return pythonStringRepr(v.text)
	case jsonArray:
		parts := make([]string, 0, len(v.items))
		for _, element := range v.items {
			parts = append(parts, pythonRepr(element))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case jsonObject:
		parts := make([]string, 0, len(v.members.keys))
		for _, key := range v.members.keys {
			parts = append(parts, pythonStringRepr(key)+": "+pythonRepr(v.members.byKey[key]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return "None"
}

// pythonStringRepr is repr(str): single quotes unless that would need escaping
// and double quotes would not, non-ASCII left alone where it is printable.
// Reachable only where a session document puts a container where Plex puts a
// title, which no committed payload does — written out rather than approximated
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

// pythonNumberText is str() of what json.loads made of a number literal. The
// distinction that matters: a literal carrying a fraction or an exponent becomes
// a Python float and is re-spelled by repr, so "1E2" comes back as "100.0" —
// while an integer literal is arbitrary precision and comes back exactly as
// written. Only the interpolated text depends on this; a fact carries the
// literal itself, because the harness compares parsed values there.
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
		// Out of float64 range: Python's float() saturates to inf the same way,
		// and repr spells it as the JSON-invalid word json.dumps emits.
		if strings.HasPrefix(literal, "-") {
			f = math.Inf(-1)
		} else {
			f = math.Inf(1)
		}
	}
	return pythonFloatRepr(f)
}

// pythonFloatRepr is repr(float): the shortest round-tripping digits, then fixed
// notation unless the decimal point sits outside (-4, 16], and always a
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
	// 'e' with precision -1 gives the shortest round-trip as d[.ddd]e±dd, which
	// is the same digit string Python starts from.
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
