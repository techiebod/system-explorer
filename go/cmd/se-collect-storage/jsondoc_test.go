package main

import (
	"strings"
	"testing"
)

// A map decode randomises iteration, and the harness compares list members
// element-wise: the vdev order IS the order zpool keyed them.
func TestObjectMemberOrderSurvivesTheDecode(t *testing.T) {
	document := mustDecode(t, `{"z": 1, "a": 2, "m": 3, "a": 4}`)
	if got := strings.Join(document.members.keys, ","); got != "z,a,m" {
		t.Fatalf("key order %q — a repeated key keeps the first position", got)
	}
	// …and the last value, which is what the reference's decoder does.
	if document.get("a").text != "4" {
		t.Fatalf("repeated key took %q", document.get("a").text)
	}
	if string(document.encode()) != `{"z":1,"a":4,"m":3}` {
		t.Fatalf("re-encoded as %s", document.encode())
	}
}

// A guid past 2^53 is not exact in a float64 and a byte counter past 2^63 is
// not an int64: the token text is what travels, so neither becomes a
// different number on the way out.
func TestNumberTokensAreNeverReRendered(t *testing.T) {
	for _, token := range []string{
		"18444306082397320711",
		"39994735460352",
		"100000000000000000000",
		"1.0",
		"20.0",
		"1e3",
		"-0",
	} {
		document := mustDecode(t, `{"n": `+token+`}`)
		if got := document.get("n").text; got != token {
			t.Errorf("%s came back as %s", token, got)
		}
	}
}

// Null is never a fact value at any depth, and the judge refuses the whole
// stream for one — so the omission is enforced where members are written.
func TestSetDropsANilMemberRatherThanWritingNull(t *testing.T) {
	object := newObject()
	object.set("kept", stringValue("here"))
	object.set("dropped", nil)
	if got := string(object.encode()); got != `{"kept":"here"}` {
		t.Fatalf("encoded as %s", got)
	}
}

func TestTruthyIsPythonsTruthTest(t *testing.T) {
	cases := map[string]bool{
		`0`: false, `0.0`: false, `-0`: false, `1`: true, `-1`: true,
		`""`: false, `"x"`: true, `"0"`: true,
		`false`: false, `true`: true,
		`null`: false, `[]`: false, `[0]`: true, `{}`: false, `{"a":1}`: true,
	}
	for token, want := range cases {
		if got := truthy(mustDecode(t, token)); got != want {
			t.Errorf("truthy(%s) = %v, want %v", token, got, want)
		}
	}
	if truthy(nil) {
		t.Error("an absent member is falsy")
	}
}

func TestPyStrKeepsAGuidsDigits(t *testing.T) {
	cases := map[string]string{
		`18444306082397320711`: "18444306082397320711",
		`"already-a-string"`:   "already-a-string",
		`0`:                    "0",
		`true`:                 "True",
		`null`:                 "None",
	}
	for token, want := range cases {
		if got := pyStr(mustDecode(t, token)); got != want {
			t.Errorf("pyStr(%s) = %q, want %q", token, got, want)
		}
	}
}

// The encoder is the wire: a control character must be escaped and the
// catalogue prose's embedded tab and newline must survive intact.
func TestStringsAreEscapedExactlyAsJSONRequires(t *testing.T) {
	got := string(stringValue("one\ttwo\nthree \"q\" \\ <&>").encode())
	want := `"one\ttwo\nthree \"q\" \\ <&>"`
	if got != want {
		t.Fatalf("encoded as %s, want %s", got, want)
	}
}
