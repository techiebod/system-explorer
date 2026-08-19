package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// A decoded API document, kept in the shape the wire carried it.
//
// encoding/json's map[string]any decode throws away the one property this
// collector is judged on: a number's TOKEN. `SessionCount` and `ItemCount` are
// integers the server counted, and DESIGN's ruling is that a pass-through number
// keeps the wire's type and not the language's — a float64 round trip turns 2
// into 2.0, which the harness's typed equality sees and a typed consumer reads
// as a different value. So a number is carried as its literal text and
// re-emitted from the same bytes it was read from, and nothing that leaves this
// collector is routed through a float64.
//
// Member order is kept for the reason the ports before this one keep it: it
// costs nothing and makes two runs of one payload byte-identical, which is what
// the determinism check asks for.
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

// ── decoding ────────────────────────────────────────────────────────────

func decodeDocument(raw []byte) (*value, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	document, err := decodeValue(decoder)
	if err != nil {
		return nil, err
	}
	// json.loads refuses trailing content and so does this: a second document
	// in the payload is a broken capture, never a longer section list.
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
			// difference between [] and absent is a statement — a container
			// with `"Metadata": []` said something a container with no
			// Metadata member did not.
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
// non-object both answer nil, which is the `(raw.get(k) or {}).get(j)` chain
// this code was ported from.
func (v *value) get(key string) *value {
	if v == nil || v.kind != jsonObject {
		return nil
	}
	return v.members.byKey[key]
}

// elements is `raw.get(k) or []` for an array member: anything that is not an
// array — missing, null, an object, a number — iterates as nothing here, which
// is the reading the reference takes for a container with no `Directory` and no
// `Metadata`. That last one is the whole point of the sessions collection: a
// document with no Metadata member is an authoritative emptiness, not a crash
// and not a decline.
func (v *value) elements() []*value {
	if v == nil || v.kind != jsonArray {
		return nil
	}
	return v.items
}

func (v *value) isObject() bool { return v != nil && v.kind == jsonObject }

// stated is `value is not None`: a missing member and an explicit null are one
// statement to Python's `.get`, and neither may become a fact (DESIGN 19 — a
// fact value is never null at any depth).
func (v *value) stated() bool { return v != nil && v.kind != jsonNull }

// truthy is Python's truth test over a decoded JSON value, which is the test the
// reference actually applies: `if container.get(member):`, `bool(raw[
// "refreshing"])`, `raw.get("sessionKey") or raw.get("ratingKey")`. Missing,
// null, false, zero, the empty string, the empty list and the empty object are
// all falsy there, and reproducing that exactly is what stops a server that
// answered `"friendlyName": ""` from publishing an empty name.
//
// A number is falsy when it is zero, whatever its spelling — `0`, `0.0` and
// `0e9` are one value to Python — so the token is parsed for this test alone.
// Nothing that leaves this collector is routed through the result.
func (v *value) truthy() bool {
	switch {
	case v == nil, v.kind == jsonNull:
		return false
	case v.kind == jsonBool:
		return v.boolean
	case v.kind == jsonString:
		return v.text != ""
	case v.kind == jsonArray:
		return len(v.items) > 0
	case v.kind == jsonObject:
		return len(v.members.keys) > 0
	case v.kind == jsonNumber:
		parsed, err := strconv.ParseFloat(v.text, 64)
		return err != nil || parsed != 0
	}
	return false
}

// isInteger is Python's `isinstance(value, int)` over what json.loads made of a
// number literal, which is the gate on SessionCount, ItemCount and both epoch
// stamps. A literal carrying a fraction or an exponent becomes a float there and
// fails the test; an integer literal is arbitrary precision and passes however
// long it is, which is why this asks about the LITERAL rather than about
// whether it fits an int64.
//
// One shape is deliberately NOT reproduced: Python's bool is a subclass of int,
// so `"size": true` satisfies `isinstance(size, int)` in the reference and would
// publish SessionCount 1. Nothing has ever seen this interface spell a count as
// a boolean, and publishing a count from one would be a worse answer than
// omitting it — so a boolean is not an integer here, and the divergence is
// stated rather than left for a reader to find.
func (v *value) isInteger() bool {
	return v != nil && v.kind == jsonNumber && isIntegerLiteral(v.text)
}

func isIntegerLiteral(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i++
	}
	if i == len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ── building ────────────────────────────────────────────────────────────

func stringValue(s string) *value { return &value{kind: jsonString, text: s} }

func boolValue(b bool) *value { return &value{kind: jsonBool, boolean: b} }

func newArray(items []*value) *value {
	if items == nil {
		items = []*value{}
	}
	return &value{kind: jsonArray, items: items}
}

func stringList(values []string) *value {
	items := make([]*value, 0, len(values))
	for _, one := range values {
		items = append(items, stringValue(one))
	}
	return newArray(items)
}

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
		// The token as it was read: an ItemCount of 2 must reach the wire as
		// the integer the container counted, never as 2.0.
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

// appendJSONString escapes exactly what JSON requires and nothing else. Go's own
// encoder escapes <, > and & as \u00xx by default; the reference does not, and
// while the harness parses before it compares, the two streams read beside each
// other in a failure report and should not differ on spelling.
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
