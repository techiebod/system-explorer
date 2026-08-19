package main

import "encoding/json"

// factRow is one object's facts: the names in the order they were derived,
// each value held as the exact JSON token it will travel as.
//
// A token rather than a Go value, because a pass-through fact keeps the WIRE's
// type and not the language's (DESIGN 19's ruling). Every version member is a
// string on every bazarr there is, and holding the token anyway is what stops
// that from being an assumption this parse enforces: a member the API ever
// spelled as a number travels as the number the document spelled, not as
// whatever a round trip through float64 would leave of it.
//
// There is no absent list and no null: a fact this derivation did not lift is
// simply not set, which is rule 7's omission, and set() has no way to write a
// null at all.
type factRow struct {
	keys   []string
	tokens map[string]string
}

func newFactRow() *factRow { return &factRow{tokens: map[string]string{}} }

// set records one fact, keeping the position it was FIRST given. That is what
// a Python dict does on reassignment, and the reference builds this row by
// updating one dict.
func (f *factRow) set(name, token string) {
	if _, seen := f.tokens[name]; !seen {
		f.keys = append(f.keys, name)
	}
	f.tokens[name] = token
}

// setValue carries a document member through untouched — the version facts,
// which the reference assigns straight off the parsed document.
func (f *factRow) setValue(name string, v jsonValue) {
	f.set(name, string(v.appendJSON(nil)))
}

func (f *factRow) setString(name, value string) {
	f.set(name, string(appendQuoted(nil, value)))
}

// setStrings writes a list fact. An EMPTY list is a value and not an absence:
// HealthIssues is [] on an instance raising nothing, which the glossary states
// and a port that dropped it for looking empty would lose.
func (f *factRow) setStrings(name string, values []string) {
	out := []byte{'['}
	for i, value := range values {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendQuoted(out, value)
	}
	f.set(name, string(append(out, ']')))
}

func (f *factRow) encode() json.RawMessage {
	out := []byte{'{'}
	for i, key := range f.keys {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendQuoted(out, key)
		out = append(out, ':')
		out = append(out, f.tokens[key]...)
	}
	return append(out, '}')
}
