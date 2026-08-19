package main

import (
	"math"
	"strings"
	"testing"
)

// Every expectation below is what CPython prints, checked against the
// interpreter rather than reasoned about: `repr(3.0)`, `round(0.145, 1)`,
// `int(8.81 * 1024 ** 3)`. This file is where the port and the reference are
// most likely to drift, because Go and Python disagree about all three by
// default and nothing else in the collector would notice.

func TestPythonFloatTokenMatchesRepr(t *testing.T) {
	cases := map[float64]string{
		0:        "0.0",   // Go's shortest form is "0", and the wire wants a number the declaration calls a number
		3:        "3.0",   // float("3.00") — the sabnzbd megabyte case
		1:        "1.0",   //
		100:      "100.0", //
		12.3:     "12.3",
		0.120223: "0.120223",
		1e15:     "1000000000000000.0", // fixed up to decpt 16, where Go's 'g' has already switched
		1e16:     "1e+16",              // and scientific past it
		1e-4:     "0.0001",
		1e-5:     "1e-05", // the exponent pads to two digits
		1e100:    "1e+100",
		-2.5:     "-2.5",
	}
	for value, want := range cases {
		got, ok := pythonFloatToken(value)
		if !ok || got != want {
			t.Errorf("pythonFloatToken(%v) = %q, %v; repr says %q", value, got, ok, want)
		}
	}
	for _, unrepresentable := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		if _, ok := pythonFloatToken(unrepresentable); ok {
			t.Errorf("%v has no JSON spelling and must be refused rather than emitted", unrepresentable)
		}
	}
}

// round(x, 1) rounds the exact binary value's decimal expansion, ties to even.
// The naive x*10 → round → /10 disagrees on 0.145, whose float64 is just under
// the tie, and on 0.25 → 0.2, where Python's tie-to-even differs from
// round-half-up.
func TestPythonRound1MatchesRound(t *testing.T) {
	cases := map[float64]float64{
		0:      0,
		50:     50,
		12.34:  12.3,
		12.35:  12.3, // 12.35 is below the tie in binary
		0.25:   0.2,  // an exact tie: to even
		0.35:   0.3,  // 0.35 is below the tie in binary
		2.675:  2.7,
		99.999: 100,
	}
	for value, want := range cases {
		got, ok := pythonRound1(value)
		if !ok || got != want {
			t.Errorf("pythonRound1(%v) = %v, %v; round() says %v", value, got, ok, want)
		}
	}
}

// int(float(x) * scale): the float multiply first, then truncation toward zero.
// A port that scaled in integer arithmetic, or rounded instead of truncating,
// lands on a different byte — 8.81 GB is 9459665469 and not 9459665470.
func TestTruncatedProductMatchesPython(t *testing.T) {
	cases := []struct {
		value float64
		scale float64
		want  string
	}{
		{8.81, 1 << 30, "9459665469"},
		{14.37, 1 << 30, "15429670010"},
		{0, 1024, "0"},
		{0.99, 1024, "1013"},
		// A petabyte of free space is past int64 in kilobyte units on no real
		// host, but Python's int has no width and this must not wrap.
		{1e12, 1 << 30, "1073741824000000000000"},
	}
	for _, one := range cases {
		got, ok := truncatedProduct(one.value, one.scale)
		if !ok || got != one.want {
			t.Errorf("truncatedProduct(%v, %v) = %q, %v; want %q", one.value, one.scale, got, ok, one.want)
		}
	}
}

// int() over a document value: an integer verbatim, a float truncated, a string
// of digits parsed — and a ValueError where Python raises one, which is what
// makes the noofslots fallback fire on the same documents.
func TestPythonIntMatchesInt(t *testing.T) {
	cases := []struct {
		document string
		want     string
		ok       bool
	}{
		{`{"v": 1}`, "1", true},
		{`{"v": 0}`, "0", true},
		{`{"v": 2.7}`, "2", true},
		{`{"v": -2.7}`, "-2", true},
		{`{"v": "42"}`, "42", true},
		{`{"v": "2.7"}`, "", false}, // int("2.7") is a ValueError even though int(2.7) is 2
		{`{"v": null}`, "", false},  // int(None) is a TypeError
		{`{"v": "x"}`, "", false},
		{`{"v": 18446744073709551615}`, "18446744073709551615", true}, // no float64 round trip
	}
	for _, one := range cases {
		document, err := decodeDocument([]byte(one.document))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := pythonInt(document.get("v"))
		if got != one.want || ok != one.ok {
			t.Errorf("pythonInt(%s) = %q, %v; want %q, %v", one.document, got, ok, one.want, one.ok)
		}
	}
}

// bool() over a document value, which is Python's truthiness and not Go's
// notion of emptiness. "0" is the one that catches people: sabnzbd writes it
// for several switches and it is a non-empty string.
func TestTruthyMatchesBool(t *testing.T) {
	cases := map[string]bool{
		`{"v": true}`:  true,
		`{"v": false}`: false,
		`{"v": null}`:  false,
		`{"v": 0}`:     false,
		`{"v": 1}`:     true,
		`{"v": ""}`:    false,
		`{"v": "0"}`:   true,
		`{"v": "no"}`:  true,
		`{"v": []}`:    false,
		`{"v": [1]}`:   true,
	}
	for document, want := range cases {
		parsed, err := decodeDocument([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		if got := truthy(parsed.get("v")); got != want {
			t.Errorf("truthy(%s) = %v, want %v", document, got, want)
		}
	}
}

// isinstance(x, int) and isinstance(x, (int, float)) are two different guards
// and the reference uses both — a transmission counter arriving as 2.0 takes
// the second branch and not the first.
func TestTheTwoNumericGuardsAreNotOneGuard(t *testing.T) {
	document, err := decodeDocument([]byte(`{"whole": 2, "fractional": 2.0, "text": "2"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !isIntegerNumber(document.get("whole")) || isIntegerNumber(document.get("fractional")) {
		t.Error("isIntegerNumber must accept 2 and refuse 2.0")
	}
	if !isNumber(document.get("fractional")) || isNumber(document.get("text")) {
		t.Error("isNumber must accept 2.0 and refuse a string")
	}
}

// round(int * 100, 1) returns an INT in Python, so a percentDone spelled 1
// rather than 1.0 puts 100 on the wire and not 100.0. Typed equality sees the
// difference and `==` does not.
func TestAWholePercentDoneStaysAnInteger(t *testing.T) {
	document, err := decodeDocument([]byte(`{"whole": 1, "fractional": 1.0, "part": 0.4567}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{"whole": "100", "fractional": "100.0", "part": "45.7"}
	for member, want := range cases {
		got := scaledPercentage(document.get(member))
		if got == nil || got.text != want {
			t.Errorf("scaledPercentage(%s) = %v, want %q", member, got, want)
		}
	}
}

// env.reason(): one line, bounded on a word boundary, and stripped of the two
// places a URL carries a credential. sabnzbd takes its key as a query
// parameter, so a client error line quoting a request URL is a credential
// channel.
func TestReasonBoundsAndStripsCredentials(t *testing.T) {
	cases := map[string]string{
		"plain text":           "plain text",
		"two\nlines  squashed": "two lines squashed",
		"GET http://host/api?apikey=abc123 failed": "GET http://host/api?[query-stripped] failed",
		"http://user:pw@host/api failed":           "http://[userinfo-stripped]@host/api failed",
	}
	for input, want := range cases {
		if got := reason(input); got != want {
			t.Errorf("reason(%q) = %q, want %q", input, got, want)
		}
	}
	// Idempotent for text that fits, which is the reference's own claim and the
	// property that lets a reason pass through more than one layer without
	// accumulating markers.
	if short := reason("plain text"); reason(short) != short {
		t.Error("reason() is not idempotent on text inside the bound")
	}

	// The cut, pinned to the reference's own arithmetic: bound at 400 runes,
	// back to the last word boundary, then the marker — which is 395 + 14 =
	// 409 characters for this input, measured against system_explorer.text.
	// Text that HAD to be cut is not idempotent, in the reference either: a
	// second pass re-truncates the 409 into 411. The port reproduces that
	// rather than improving on it, and it is why this pins the first pass's
	// length instead of asserting a fixed point.
	long := ""
	for len(long) < 600 {
		long += "wordy "
	}
	bounded := reason(long)
	if len([]rune(bounded)) != 409 {
		t.Errorf("the bounded reason is %d runes; the reference produces 409", len([]rune(bounded)))
	}
	if !strings.HasSuffix(bounded, " … (truncated)") {
		t.Errorf("a cut that does not say it was cut reads as damage: %q", bounded)
	}
}
