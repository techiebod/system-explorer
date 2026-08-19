package main

import "encoding/json"

// factRow is one object's facts: the names in the order they were derived,
// each value held as the exact JSON token it will travel as.
//
// A token rather than a Go value, and this collection is the reason the rule
// exists rather than an application of it. StorageTotalBytes and
// StorageAvailableBytes are 63195054080 and 54911987712 on the committed
// capture — both above 2^32, both anchored as exact integers — and a round
// trip through float64 loses them silently while still printing something that
// looks like about 63 GB. So a pass-through fact keeps the WIRE's type and its
// digits (DESIGN 19's ruling), and the parse never sees a float at all.
//
// There is no absent list and no null: a fact this derivation did not lift is
// simply not set, which is rule 7's omission, and set() has no way to write a
// null at all. That is the whole of what the four *_error anchors assert — the
// document PRESENTS redis_error, celery_error, index_error and database.error
// holding JSON null, and a row carrying four null-valued facts is what this
// type makes unspellable.
type factRow struct {
	keys   []string
	tokens map[string]string
}

func newFactRow() *factRow { return &factRow{tokens: map[string]string{}} }

// set records one fact, keeping the position it was FIRST given. That is what
// a Python dict does on reassignment, and the reference builds this row by
// updating one dict with another.
func (f *factRow) set(name, token string) {
	if _, seen := f.tokens[name]; !seen {
		f.keys = append(f.keys, name)
	}
	f.tokens[name] = token
}

// setValue carries a document member through untouched — every count, every
// status word and the version string, which the reference assigns straight off
// the parsed document.
func (f *factRow) setValue(name string, v jsonValue) {
	f.set(name, string(v.appendJSON(nil)))
}

func (f *factRow) setString(name, value string) {
	f.set(name, string(appendQuoted(nil, value)))
}

// merge is `facts.update(status_facts(...))`: the component half of the row is
// built as its own dict and folded onto the inventory half in one step, which
// is why a status document that could not be read costs the row all of its
// component facts and none of its counts.
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
		out = appendQuoted(out, key)
		out = append(out, ':')
		out = append(out, f.tokens[key]...)
	}
	return append(out, '}')
}
