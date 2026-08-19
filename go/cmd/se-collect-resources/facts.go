package main

import "encoding/json"

// factRow is one object's facts: the names in the order they were derived,
// each value held as the exact JSON token it will travel as.
//
// A token rather than a float64, because pass-through numbers keep the WIRE's
// type and not the language's (DESIGN 19's ruling). `0` and `0.0` are
// different answers under the typed equality the judge applies — and this
// collection carries both kinds on one row, a PSI share that is always a
// number beside a cgroup counter that is always an integer. Those counters are
// unsigned 64-bit: a memory high-water mark or a byte total past 2^53 would
// lose its last digits on a round trip through a float and nothing downstream
// could tell. So the type is decided once, where the kernel file is parsed,
// and the value is re-emitted from the bytes it was read from.
//
// There is no absent list and no null: a fact this parse could not lift is
// simply not set, which is rule 7's omission, and set() has no way to write a
// null at all.
type factRow struct {
	keys   []string
	tokens map[string]string
}

func newFactRow() *factRow { return &factRow{tokens: map[string]string{}} }

// set records one fact, keeping the position it was FIRST given. That is what
// a Python dict does on reassignment, and the reference builds this row by
// updating one dict — so a document that spelled a record twice orders the row
// the same way here as there.
func (f *factRow) set(name, token string) {
	if _, seen := f.tokens[name]; !seen {
		f.keys = append(f.keys, name)
	}
	f.tokens[name] = token
}

func (f *factRow) setString(name, value string) {
	f.set(name, string(appendJSONString(nil, value)))
}

func (f *factRow) has(name string) bool {
	_, ok := f.tokens[name]
	return ok
}

func (f *factRow) len() int { return len(f.keys) }

// clone is the row a walk's readings become. The readings are read once and
// laid on several rows' worth of derivation afterwards — the parent link, the
// depth, the delegation mark, the attribution — so the derivation copies
// rather than editing what the walk found, exactly as the reference's
// `dict(readings)` does.
func (f *factRow) clone() *factRow {
	out := newFactRow()
	for _, key := range f.keys {
		out.set(key, f.tokens[key])
	}
	return out
}

// merge lays one row's facts over another, in order. A name already present
// keeps its position and takes the new value, which is what a Python dict
// update does — and what the reference relies on when the remainder lands on
// the root row.
func (f *factRow) merge(other *factRow) {
	for _, key := range other.keys {
		f.set(key, other.tokens[key])
	}
}

func (f *factRow) encode() json.RawMessage {
	out := []byte{'{'}
	for i, key := range f.keys {
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
