package main

import (
	"encoding/json"
	"sort"
)

// factRow is one object's facts, each held as the exact JSON token it will
// travel as and emitted under a sorted key order — which is what the reference
// emits, because its writer serialises every record with sorted keys.
//
// A token rather than a Go value, because pass-through members keep the WIRE's
// type and not the language's (DESIGN 19's ruling). Nothing this collection
// publishes is a number, so the tokens here are strings, one boolean and lists
// of strings; holding them as tokens is what stops a later fact of another
// type being routed through an `any` and re-rendered.
//
// There is no absent list and no null: a fact this derivation could not build
// is simply not set, which is DESIGN 19's omission, and no setter can write a
// null at all.
type factRow struct{ tokens map[string]string }

func newFactRow() *factRow { return &factRow{tokens: map[string]string{}} }

func (f *factRow) set(name, token string) { f.tokens[name] = token }

func (f *factRow) setString(name, value string) {
	f.set(name, string(appendJSONString(nil, value)))
}

func (f *factRow) setBool(name string, value bool) {
	if value {
		f.set(name, "true")
	} else {
		f.set(name, "false")
	}
}

func (f *factRow) setStrings(name string, values []string) {
	out := []byte{'['}
	for i, value := range values {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendJSONString(out, value)
	}
	f.set(name, string(append(out, ']')))
}

func (f *factRow) has(name string) bool {
	_, ok := f.tokens[name]
	return ok
}

func (f *factRow) encode() json.RawMessage {
	keys := make([]string, 0, len(f.tokens))
	for key := range f.tokens {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []byte{'{'}
	for i, key := range keys {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendJSONString(out, key)
		out = append(out, ':')
		out = append(out, f.tokens[key]...)
	}
	return append(out, '}')
}

// appendJSONString escapes exactly what JSON requires and nothing else. Go's
// own encoder escapes <, > and & as \u00xx by default; the reference does not,
// and while the harness parses before it compares, the two streams read beside
// each other in a failure report and should not differ on spelling.
func appendJSONString(dst []byte, s string) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			dst = append(dst, '\\', '"')
		case c == '\\':
			dst = append(dst, '\\', '\\')
		case c == '\n':
			dst = append(dst, '\\', 'n')
		case c == '\r':
			dst = append(dst, '\\', 'r')
		case c == '\t':
			dst = append(dst, '\\', 't')
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		default:
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}
