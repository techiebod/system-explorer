package main

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// The reference's arithmetic, spelled out.
//
// Everything in this file exists because adapters/downloaders.py does not pass
// its numbers through: it multiplies gigabytes by 1024³, rounds a fraction to
// one decimal place, and parses megabytes out of strings sabnzbd wrote. Each of
// those is a Python operation with a defined result, and the wire carries that
// result — `0.0` is not `0` and `9459665469` is not `9459665469.44` under the
// harness's typed equality. So the conversions are reproduced here rather than
// approximated, and the one place a language difference would show is the one
// place this file is careful.

// pythonFloatToken renders a float64 exactly as `json.dumps` renders a Python
// float, which is `repr`: the shortest digit string that round-trips, in fixed
// notation while the decimal point sits in (-4, 16], scientific outside it, and
// ALWAYS with a decimal point — repr(3.0) is "3.0" and Go's shortest form is
// "3". A port that dropped the ".0" would put an integer on a wire the
// declaration calls a number, which typed equality sees and `==` does not.
//
// Reports false for NaN and infinity. Python would emit both — json.dumps
// writes a bare NaN — and every reader downstream refuses the stream that
// carries one, so omitting the fact is the lawful half of the same reading
// rather than a different reading.
func pythonFloatToken(f float64) (string, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", false
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0", true
		}
		return "0.0", true
	}
	// Shortest round-tripping digits, read out of the scientific form so the
	// decimal exponent is explicit rather than inferred from Go's own
	// fixed-versus-scientific rule, which switches at a different place.
	sign := ""
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	if sci[0] == '-' {
		sign, sci = "-", sci[1:]
	}
	mantissa, exponent, _ := strings.Cut(sci, "e")
	power, err := strconv.Atoi(exponent)
	if err != nil {
		return "", false
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	// decpt is CPython's own name for it: the value is 0.<digits> × 10^decpt.
	decpt := power + 1
	switch {
	case decpt <= -4 || decpt > 16:
		out := digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		mark, e := "+", decpt-1
		if e < 0 {
			mark, e = "-", -e
		}
		// Two digits minimum, which is what CPython pads the exponent to.
		return sign + out + "e" + mark + fmt.Sprintf("%02d", e), true
	case decpt <= 0:
		return sign + "0." + strings.Repeat("0", -decpt) + digits, true
	case decpt >= len(digits):
		return sign + digits + strings.Repeat("0", decpt-len(digits)) + ".0", true
	default:
		return sign + digits[:decpt] + "." + digits[decpt:], true
	}
}

// pythonRound1 is `round(x, 1)` on a float: correctly rounded to one decimal
// place, ties to even, over the value's exact decimal expansion. Go's fixed-
// precision formatter rounds the same way over the same expansion, so the round
// trip through the formatted text IS the operation rather than an
// approximation of it — which matters because 12.35 is not exactly 12.35 in
// binary and a naive x*10 → round → /10 disagrees with Python about which side
// it falls.
func pythonRound1(x float64) (float64, bool) {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return 0, false
	}
	rounded, err := strconv.ParseFloat(strconv.FormatFloat(x, 'f', 1, 64), 64)
	if err != nil {
		return 0, false
	}
	return rounded, true
}

// pythonFloat is `float(value)` over a string: leading and trailing whitespace
// allowed, underscores allowed between digits (Python accepts the numeric
// literal grammar here), and everything else a ValueError — which the reference
// catches, dropping the fact rather than publishing a guess.
func pythonFloat(text string) (float64, bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0, false
	}
	if strings.ContainsAny(trimmed, "_") {
		trimmed = strings.ReplaceAll(trimmed, "_", "")
	}
	value, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// truncatedProduct is `int(float(x) * scale)`: the float multiply first, then
// truncation toward zero, in that order and at that precision. The order is the
// whole of it — 8.81 × 1024³ is 9459665469.44 as a float64 and 9459665469 as an
// int, and a port that scaled with integer arithmetic or rounded instead of
// truncating lands on a different byte.
//
// big.Float carries the truncation because Python's int has no width: a
// petabyte-scale reading would overflow an int64 silently, and a fact that
// wrapped negative is worse than one that is merely wrong.
func truncatedProduct(value, scale float64) (string, bool) {
	product := value * scale
	if math.IsNaN(product) || math.IsInf(product, 0) {
		return "", false
	}
	whole, _ := big.NewFloat(product).Int(nil)
	return whole.String(), true
}

// pythonInt is `int(value)` over a document value: an integer token exactly, a
// fractional one truncated toward zero, and a string parsed as Python parses
// one. Reports false where Python raises — a TypeError on null, a ValueError on
// text that is not a number — which is what the reference's except clause
// turns into "try the other member" or "drop the fact".
func pythonInt(v *value) (string, bool) {
	if v == nil {
		return "", false
	}
	switch v.kind {
	case jsonNumber:
		return integerFromToken(v.text)
	case jsonString:
		trimmed := strings.TrimSpace(v.text)
		trimmed = strings.ReplaceAll(trimmed, "_", "")
		// int() takes an integer literal only: int("2.7") is a ValueError even
		// though int(2.7) is 2, and reproducing that distinction is what keeps
		// the noofslots fallback firing on the same documents.
		if n, ok := new(big.Int).SetString(trimmed, 10); ok {
			return n.String(), true
		}
		return "", false
	default:
		return "", false
	}
}

// integerFromToken canonicalises a JSON number the way int() would: an integral
// token verbatim (through big.Int, so a leading zero or plus becomes the
// spelling Python's int would print and a u64 counter keeps every digit), a
// fractional one truncated toward zero.
func integerFromToken(text string) (string, bool) {
	if n, ok := new(big.Int).SetString(text, 10); ok {
		return n.String(), true
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return "", false
	}
	whole, _ := big.NewFloat(math.Trunc(f)).Int(nil)
	return whole.String(), true
}

// truthy is Python's `bool(value)` over a document value, which is not Go's
// notion of emptiness: an empty string and a zero are false, a non-empty string
// is true whatever it spells — sabnzbd writes "0" for several of its switches,
// and `bool("0")` is True. The reference calls bool() on the raw member, so the
// fact carries Python's answer and not a re-reading of the text.
func truthy(v *value) bool {
	if v == nil {
		return false
	}
	switch v.kind {
	case jsonNull:
		return false
	case jsonBool:
		return v.boolean
	case jsonNumber:
		f, err := strconv.ParseFloat(v.text, 64)
		return err == nil && f != 0
	case jsonString:
		return v.text != ""
	case jsonArray:
		return len(v.items) > 0
	case jsonObject:
		return len(v.members.keys) > 0
	}
	return false
}

// isIntegerNumber is `isinstance(x, int)` for a document member: a JSON number
// whose token carries no fraction and no exponent. Distinct from
// isinstance(x, (int, float)) on purpose — the reference uses both, and a
// transmission counter arriving as 2.0 would take the second branch and not the
// first.
func isIntegerNumber(v *value) bool {
	if v == nil || v.kind != jsonNumber {
		return false
	}
	_, ok := new(big.Int).SetString(v.text, 10)
	return ok
}

// isNumber is `isinstance(x, (int, float))`.
func isNumber(v *value) bool { return v != nil && v.kind == jsonNumber }

// numberValue carries a document number onto the wire as Python would print it:
// an integer verbatim, a float through repr. The token is not passed through
// blind, because Python re-renders what it decoded — a document spelling
// "1.50" becomes the float 1.5 and json.dumps writes "1.5".
func numberValue(v *value) *value {
	if !isNumber(v) {
		return nil
	}
	if token, ok := integerTokenOf(v.text); ok {
		return &value{kind: jsonNumber, text: token}
	}
	f, err := strconv.ParseFloat(v.text, 64)
	if err != nil {
		return nil
	}
	token, ok := pythonFloatToken(f)
	if !ok {
		return nil
	}
	return &value{kind: jsonNumber, text: token}
}

// integerTokenOf reports the canonical decimal spelling of an integral token.
func integerTokenOf(text string) (string, bool) {
	n, ok := new(big.Int).SetString(text, 10)
	if !ok {
		return "", false
	}
	return n.String(), true
}

// multiplyIntegerToken scales an integral token, keeping every digit: a
// percentDone of 1 becomes 100 and nothing goes through a float on the way.
func multiplyIntegerToken(token string, by int64) (string, bool) {
	n, ok := new(big.Int).SetString(token, 10)
	if !ok {
		return "", false
	}
	return n.Mul(n, big.NewInt(by)).String(), true
}

// smallIndex reads an integral token as a non-negative slice index, refusing
// anything that could not be one. The reference's guard is `0 <= status <
// len(...)`, so a negative or enormous status is a document this collector does
// not recognise and the fact is omitted rather than guessed.
func smallIndex(token string) (int, bool) {
	n, err := strconv.ParseInt(token, 10, 32)
	if err != nil || n < 0 {
		return 0, false
	}
	return int(n), true
}

// floatValue carries a computed float onto the wire under Python's repr.
// Returns nil where the value cannot travel as JSON, which `set` then drops.
func floatValue(f float64) *value {
	token, ok := pythonFloatToken(f)
	if !ok {
		return nil
	}
	return &value{kind: jsonNumber, text: token}
}

func boolValue(b bool) *value { return &value{kind: jsonBool, boolean: b} }
