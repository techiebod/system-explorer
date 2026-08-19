package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
)

// A decoded control-socket answer, kept in the shape the wire carried it.
//
// encoding/json's map[string]any decode throws away the one property this
// collector is judged on: a number's TOKEN. `packet-queue-statistics` is a list
// of floats and `total-addresses` is an integer, and `0.0` is not `0` under the
// harness's typed equality — DESIGN's "pass-through numbers keep the wire's
// type, not the language's". So a number is carried as its literal text and
// re-emitted from the same bytes it was read from, and nothing that leaves this
// collector is routed through a float64.
//
// Member order is kept for the same reason the ports before this one keep it:
// it costs nothing and makes two runs of one payload byte-identical, which is
// what the determinism check asks for.
type jsonKind uint8

const (
	jsonNull jsonKind = iota
	jsonBool
	jsonNumber
	jsonString
	jsonArray
	jsonObject
)

type value struct {
	kind    jsonKind
	text    string // a string's content, or a number's token verbatim
	boolean bool
	items   []*value
	members *members
}

// members is an object's contents in document order. A repeated key takes the
// last value at the first key's position, which is what Python's decoder does
// and therefore what the reference read.
type members struct {
	keys  []string
	byKey map[string]*value
}

func newMembers() *members { return &members{byKey: map[string]*value{}} }

func (m *members) set(key string, v *value) {
	if _, seen := m.byKey[key]; !seen {
		m.keys = append(m.keys, key)
	}
	m.byKey[key] = v
}

// remove exists for one line of the reference: an option suppressed by
// never-send is merged in as a marker and then DELETED, so the row does not
// state a value the client is never handed. Deleting it is not the same as
// never setting it — the marker has to survive the merge in order to mask the
// wider scope's value, and only then go.
func (m *members) remove(key string) {
	if _, seen := m.byKey[key]; !seen {
		return
	}
	delete(m.byKey, key)
	for i, k := range m.keys {
		if k == key {
			m.keys = append(m.keys[:i], m.keys[i+1:]...)
			break
		}
	}
}

// ── decoding ────────────────────────────────────────────────────────────

func decodeDocument(raw []byte) (*value, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	document, err := decodeValue(decoder)
	if err != nil {
		return nil, err
	}
	// json.loads refuses trailing content and so does this: a second document
	// in the payload is a broken capture, never a longer answer.
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing bytes after the document")
	}
	return document, nil
}

func decodeValue(decoder *json.Decoder) (*value, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case nil:
		return &value{kind: jsonNull}, nil
	case bool:
		return &value{kind: jsonBool, boolean: t}, nil
	case json.Number:
		return &value{kind: jsonNumber, text: t.String()}, nil
	case string:
		return &value{kind: jsonString, text: t}, nil
	case json.Delim:
		switch t {
		case '[':
			// Non-nil even when empty: an empty array is a value, and the
			// difference between [] and absent is a statement — a subnet with
			// `"reservations": []` said something a subnet with no
			// reservations member did not.
			out := &value{kind: jsonArray, items: []*value{}}
			for decoder.More() {
				item, err := decodeValue(decoder)
				if err != nil {
					return nil, err
				}
				out.items = append(out.items, item)
			}
			_, err := decoder.Token()
			return out, err
		case '{':
			out := &value{kind: jsonObject, members: newMembers()}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object key is %T, not a string", keyToken)
				}
				item, err := decodeValue(decoder)
				if err != nil {
					return nil, err
				}
				out.members.set(key, item)
			}
			_, err := decoder.Token()
			return out, err
		}
	}
	return nil, fmt.Errorf("unexpected token %v", token)
}

// ── reading ─────────────────────────────────────────────────────────────

// get is nil-safe in both directions: a missing member and a member of a
// non-object both answer nil, which is the `dict.get` this code was ported
// from.
func (v *value) get(key string) *value {
	if v == nil || v.kind != jsonObject {
		return nil
	}
	return v.members.byKey[key]
}

// has separates "the member is absent" from "the member is null", which
// `dict.get(key, default)` cares about and `dict.get(key)` does not: the
// reference reads a subnet's lease time with
// `subnet.get("valid-lifetime", network.get(…))`, so a subnet that states the
// member as null takes the null and does NOT fall through to its shared
// network's value.
func (v *value) has(key string) bool {
	if v == nil || v.kind != jsonObject {
		return false
	}
	_, ok := v.members.byKey[key]
	return ok
}

// dig walks several members in one step, which is `(raw.get("a") or {}).get("b")`
// — the shape the reference uses for every nested read on these documents.
func (v *value) dig(keys ...string) *value {
	for _, key := range keys {
		v = v.get(key)
	}
	return v
}

func (v *value) isString() bool { return v != nil && v.kind == jsonString }

func (v *value) isObject() bool { return v != nil && v.kind == jsonObject }

// stated is `value is not None` for a member the reference passes straight to
// a facts dict: a missing member and an explicit null are one statement to
// Python's `.get`, and neither may become a fact (DESIGN 19 — a fact value is
// never null at any depth).
func (v *value) stated() bool { return v != nil && v.kind != jsonNull }

// truthy is Python's own truth test, which is what every `if subnet.get(…)` in
// the reference actually applies: an empty string, a zero, an empty list and an
// empty object are all false. It matters at exactly one place per collection —
// Kea normalises an unset hostname to `""` rather than dropping the member, so
// a port that tested for the member's PRESENCE would publish `Hostname: ""` on
// every reservation whose client never stated one.
func (v *value) truthy() bool {
	switch {
	case v == nil, v.kind == jsonNull:
		return false
	case v.kind == jsonBool:
		return v.boolean
	case v.kind == jsonString:
		return v.text != ""
	case v.kind == jsonNumber:
		f, err := strconv.ParseFloat(v.text, 64)
		return err == nil && f != 0
	case v.kind == jsonArray:
		return len(v.items) > 0
	case v.kind == jsonObject:
		return len(v.members.keys) > 0
	}
	return false
}

// arrayOf is `raw.get(key) or []`: a member that is absent, null or anything
// other than a list contributes no items. The reference writes that idiom at
// every list walk in this adapter, and the `or []` is what makes a null
// `reservations` member iterate as an empty one rather than raising.
func arrayOf(v *value) []*value {
	if v == nil || v.kind != jsonArray {
		return nil
	}
	return v.items
}

// isInteger is `isinstance(x, int)` for a document member — the test the
// reference applies before it publishes a lease time or an uptime.
func isInteger(v *value) bool {
	_, ok := v.integer()
	return ok
}

// numberEquals is Python's `x == n` for a document member: a value written 42
// and one written 42.0 are one number to it, and only the arithmetic that
// follows cares which. Used at the single place the reference compares against a
// literal rather than testing a type.
func numberEquals(v *value, n int64) bool {
	if v == nil || v.kind != jsonNumber {
		return false
	}
	f, err := strconv.ParseFloat(v.text, 64)
	return err == nil && f == float64(n)
}

// pythonText is `str(x)` for the members this collector keys on: a subnet id
// and a lease's subnet-id, which are joined between documents as STRINGS
// because that is the form statistic-get-all spells them in. Numbers keep the
// document's own token, which is what `str(int)` and `str(float)` produce for
// every value Kea writes — the one shape that would differ is exponent notation
// (`1e3` renders `1000.0` in Python), and no subnet id has ever been written
// that way.
func pythonText(v *value) string {
	switch {
	case v == nil, v.kind == jsonNull:
		return "None"
	case v.kind == jsonBool:
		if v.boolean {
			return "True"
		}
		return "False"
	case v.kind == jsonNumber, v.kind == jsonString:
		return v.text
	}
	return ""
}

// integer reads a JSON number the way `isinstance(x, int)` decides in the
// reference: an INTEGRAL token only. A float is not an int to Python — a
// fractional `valid-lifetime` publishes no LeaseTimeSeconds there and must
// publish none here — so a fractional token is refused rather than truncated.
func (v *value) integer() (int64, bool) {
	if v == nil || v.kind != jsonNumber {
		return 0, false
	}
	exact, err := strconv.ParseInt(v.text, 10, 64)
	if err != nil {
		return 0, false
	}
	return exact, true
}

// ── building ────────────────────────────────────────────────────────────

func stringValue(s string) *value { return &value{kind: jsonString, text: s} }

func numberValue(token string) *value { return &value{kind: jsonNumber, text: token} }

func newObject() *value { return &value{kind: jsonObject, members: newMembers()} }

// set drops a nil member rather than writing a null, and drops a null one for
// the same reason. Null is never a fact value at any depth (DESIGN 19) and the
// judge refuses the whole stream for one, so the omission is enforced at the
// single place members are written rather than swept for afterwards.
func (v *value) set(key string, member *value) {
	if !member.stated() {
		return
	}
	v.members.set(key, member)
}

// ── encoding ────────────────────────────────────────────────────────────

func (v *value) encode() json.RawMessage { return json.RawMessage(v.appendTo(nil)) }

func (v *value) appendTo(dst []byte) []byte {
	switch v.kind {
	case jsonNull:
		return append(dst, "null"...)
	case jsonBool:
		if v.boolean {
			return append(dst, "true"...)
		}
		return append(dst, "false"...)
	case jsonNumber:
		// The token as it was read: a queue average that must not become 0
		// instead of 0.0 depends on never re-rendering it.
		return append(dst, v.text...)
	case jsonString:
		return appendJSONString(dst, v.text)
	case jsonArray:
		dst = append(dst, '[')
		for i, item := range v.items {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = item.appendTo(dst)
		}
		return append(dst, ']')
	case jsonObject:
		dst = append(dst, '{')
		for i, key := range v.members.keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, key)
			dst = append(dst, ':')
			dst = v.members.byKey[key].appendTo(dst)
		}
		return append(dst, '}')
	}
	return append(dst, "null"...)
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

// roundHalfToEven is Python's round() on a float, which is what UsedPercent is
// computed with. Go's math.Round breaks ties AWAY from zero and Python's breaks
// them to EVEN, so a pool sitting exactly on a half — 1 of 8 addresses is
// 12.5% — would render 13 here and 12 there, a one-digit disagreement no test
// staged on a round number could ever see.
func roundHalfToEven(x float64) int64 {
	floor := math.Floor(x)
	switch diff := x - floor; {
	case diff > 0.5:
		return int64(floor) + 1
	case diff < 0.5:
		return int64(floor)
	default:
		if n := int64(floor); n%2 == 0 {
			return n
		}
		return int64(floor) + 1
	}
}
