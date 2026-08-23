package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
)

// A decoded JSON document, with the two properties encoding/json's
// map[string]any decode throws away and this collector is judged on.
//
// Member ORDER is a fact here: the vdev walk emits rows in the order
// `zpool status -j` keys them, and the harness compares list members
// element-wise, so a map decode's randomised iteration fails every variant.
//
// Number TOKENS are a fact too: a pool guid is a full unsigned 64-bit value
// (18444306082397320711 in the healthy capture), which is neither an int64
// nor exact in a float64 — round-tripping it through either returns a
// different pool. The token text is carried verbatim and only ever parsed
// where an integer is genuinely wanted.
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

// members is an object's contents in document order. A repeated key takes
// the last value at the first key's position, which is what Python's decoder
// does and therefore what the reference read.
type members struct {
	keys  []string
	byKey map[string]*value
}

func newMembers() *members {
	return &members{byKey: map[string]*value{}}
}

func (m *members) set(key string, v *value) {
	if _, seen := m.byKey[key]; !seen {
		m.keys = append(m.keys, key)
	}
	m.byKey[key] = v
}

func (m *members) get(key string) *value {
	if m == nil {
		return nil
	}
	return m.byKey[key]
}

func (m *members) len() int {
	if m == nil {
		return 0
	}
	return len(m.keys)
}

// ── decoding ────────────────────────────────────────────────────────────

func decodeDocument(raw []byte) (*value, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	document, err := decodeValue(decoder)
	if err != nil {
		return nil, err
	}
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
			// difference between [] and absent is a statement.
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
// from. Only isNone tells nil from an explicit JSON null, and the two are
// the same statement everywhere the reference used `.get(...) is None`.
func (v *value) get(key string) *value {
	if v == nil || v.kind != jsonObject {
		return nil
	}
	return v.members.get(key)
}

func (v *value) object() *members {
	if v == nil || v.kind != jsonObject {
		return nil
	}
	return v.members
}

// isNone is `x is None` after a dict.get: absent and explicit null are one
// statement, and every reference test that spells `is None` means both.
func isNone(v *value) bool { return v == nil || v.kind == jsonNull }

// isString reports whether the document member is a JSON string, which is
// what `isinstance(x, str)` asks — the ScanAgeDays routing turns on it.
func (v *value) isString() bool { return v != nil && v.kind == jsonString }

// equalsString is Python's `==` against a string literal: only a string can
// satisfy it, so a numeric vdev_type is not the root container.
func (v *value) equalsString(want string) bool {
	return v != nil && v.kind == jsonString && v.text == want
}

// truthy is Python's truth test, which several reference branches turn on
// (`if vdev.get("devid")`, `if path`, `if not vdev.get("vdevs")`). Falsy:
// missing, null, false, zero, the empty string, the empty container.
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
		return !numberIsZero(v.text)
	case jsonString:
		return v.text != ""
	case jsonArray:
		return len(v.items) > 0
	case jsonObject:
		return v.members.len() > 0
	}
	return false
}

func numberIsZero(token string) bool {
	rational, ok := new(big.Rat).SetString(token)
	return ok && rational.Sign() == 0
}

// pyStr is Python's str(), which the reference applies to a guid before it
// becomes a stable name and to a vdev path before it is resolved. Strings
// are themselves and integers are their digits, which is the whole of what
// any captured document produces; the remaining shapes are reproduced as
// closely as a Go decode can and are named in the port's adjudications.
func pyStr(v *value) string {
	if v == nil {
		return "None"
	}
	switch v.kind {
	case jsonNull:
		return "None"
	case jsonBool:
		if v.boolean {
			return "True"
		}
		return "False"
	case jsonNumber, jsonString:
		return v.text
	}
	return string(v.encode())
}

// intOrNil is storage.py:191-195 — `int(str(raw))` inside a try — and its
// refusals are load-bearing, not incidental. A JSON 3.0 is a Python float
// whose str() is "3.0", which int() rejects, so the member is DROPPED rather
// than rounded: the difference between a counter present and a counter
// absent on the wire. Booleans, nulls, "-", "" and "0x10" are refused the
// same way, and an integer past 64 bits survives whole, because zpool's
// byte counters and guids routinely are.
func intOrNil(v *value) *big.Int {
	if v == nil {
		return nil
	}
	var text string
	switch v.kind {
	case jsonNumber:
		// Python's json decoder makes an int only from a token with no
		// fraction and no exponent; everything else became a float, whose
		// str() int() will not take.
		if strings.ContainsAny(v.text, ".eE") {
			return nil
		}
		text = v.text
	case jsonString:
		text = v.text
	default:
		return nil
	}
	parsed, ok := new(big.Int).SetString(strings.TrimSpace(text), 10)
	if !ok {
		return nil
	}
	return parsed
}

// ── building ────────────────────────────────────────────────────────────

func stringValue(s string) *value { return &value{kind: jsonString, text: s} }

func intValue(n int64) *value {
	return &value{kind: jsonNumber, text: fmt.Sprintf("%d", n)}
}

// floatValue renders the token as Python's json module would — the shortest
// round trip, with a trailing .0 kept, so 100.0 stays a float on the wire
// (resources' floatToken, restated here because the packages do not share).
func floatValue(f float64) *value {
	text := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(text, ".eE") {
		text += ".0"
	}
	return &value{kind: jsonNumber, text: text}
}

func bigValue(n *big.Int) *value {
	return &value{kind: jsonNumber, text: n.String()}
}

func newObject() *value { return &value{kind: jsonObject, members: newMembers()} }

func newArray() *value { return &value{kind: jsonArray, items: []*value{}} }

// set drops a nil member rather than writing a null. Null is never a fact
// value at any depth (DESIGN 19), and the judge refuses the whole stream for
// one — so the omission is enforced at the one place members are written
// rather than swept for afterwards.
func (v *value) set(key string, member *value) {
	if member == nil {
		return
	}
	v.members.set(key, member)
}

func (v *value) append(item *value) { v.items = append(v.items, item) }

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
		// The token as it was read: a counter above 2^53 and an integer
		// that must not become 2.0e13 both depend on never re-rendering it.
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
// own encoder escapes <, > and & as \u00xx by default; the reference does
// not, and while the harness parses before it compares, the two streams read
// beside each other in a failure report and should not differ on spelling.
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
