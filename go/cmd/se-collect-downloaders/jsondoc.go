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

// A decoded payload document, kept in the shape the wire carried it.
//
// encoding/json's map[string]any decode throws away the one property this
// collector is judged on: a number's TOKEN. `Internal` is a boolean and
// `PrivatePort` is an integer, and `false` is not `0` and `8080` is not
// `8080.0` under the harness's typed equality — DESIGN's "pass-through numbers
// keep the wire's type, not the language's". So a number is carried as its
// literal text and re-emitted from the same bytes it was read from, and
// nothing that leaves this collector is routed through a float64.
//
// Member order is kept for the same reason the two ports before this one keep
// it: it costs nothing and makes two runs of one payload byte-identical, which
// is what the determinism check asks for.
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
	// in the payload is a broken capture, never a longer container list.
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
			// with `"Ports": []` said something a container with no Ports
			// member did not.
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

// dig walks several members in one step, which is `(raw.get("a") or {}).get("b")`
// — the shape the reference uses for every nested read on this document.
func (v *value) dig(keys ...string) *value {
	for _, key := range keys {
		v = v.get(key)
	}
	return v
}

func (v *value) isString() bool { return v != nil && v.kind == jsonString }

// stated is `value is not None` for a member the reference passes straight to
// a facts dict: a missing member and an explicit null are one statement to
// Python's `.get`, and neither may become a fact (DESIGN 19 — a fact value is
// never null at any depth).
func (v *value) stated() bool { return v != nil && v.kind != jsonNull }

// text of a string member, or "" — the reference's `raw.get(k) or ""`.
func (v *value) stringOr(fallback string) string {
	if v.isString() {
		return v.text
	}
	return fallback
}

// integer reads a JSON number as Python's int() reads it: an integral token
// exactly, and a fractional one truncated toward zero. Both arms exist because
// the reference does `int(c.get("Created", 0))`, which accepts either — the
// int64 path first so a figure above 2^53 keeps every digit rather than
// arriving through a float.
func (v *value) integer() (int64, bool) {
	if v == nil || v.kind != jsonNumber {
		return 0, false
	}
	if exact, err := strconv.ParseInt(v.text, 10, 64); err == nil {
		return exact, true
	}
	approx, err := strconv.ParseFloat(v.text, 64)
	if err != nil || math.IsNaN(approx) || math.IsInf(approx, 0) {
		return 0, false
	}
	return int64(math.Trunc(approx)), true
}

// ── building ────────────────────────────────────────────────────────────

func stringValue(s string) *value { return &value{kind: jsonString, text: s} }

func stringArray(items []string) *value {
	out := &value{kind: jsonArray, items: []*value{}}
	for _, item := range items {
		out.items = append(out.items, stringValue(item))
	}
	return out
}

func newObject() *value { return &value{kind: jsonObject, members: newMembers()} }

// set drops a nil member rather than writing a null, and drops a null one for
// the same reason. Null is never a fact value at any depth (DESIGN 19) and the
// judge refuses the whole stream for one, so the omission is enforced at the
// single place members are written rather than swept for afterwards. This is
// also `_stated()` in adapters/docker.py, which is the half of the reference
// this port arrived alongside: ComposeProject is absent on every container no
// compose file created, and it was published as null on every one of them
// until the first capture was taken.
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
		// The token as it was read: a port number that must not become 8.08e3
		// depends on never re-rendering it.
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
