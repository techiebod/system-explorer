package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// A decoded journal entry, kept in the shape the wire carried it.
//
// encoding/json's map[string]any decode throws away the one property this
// collector is judged on: a value's TYPE and a number's TOKEN. A journal
// MESSAGE is usually a string and is an ARRAY OF BYTE VALUES when the entry is
// not valid UTF-8 — journalctl -o json's own rendering — and the reference
// copies whatever it found straight onto the row without looking. `12` and
// `12.0` are different answers under the harness's typed equality (DESIGN's
// "pass-through numbers keep the wire's type, not the language's"), so a
// number is carried as its literal text and re-emitted from the same bytes it
// was read from.
//
// Member order is kept because it costs nothing and makes two runs of one
// payload byte-identical, which is what the determinism check asks for.
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
	// in the payload is a broken capture, never a longer entry list.
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing bytes after the document")
	}
	return document, nil
}

// decodeLines reads the NDJSON journalctl actually writes: one entry per line,
// blank lines dropped. It is the live counterpart of decodeDocument, and it is
// a separate function rather than a mode because the two inputs are different
// documents — `journalctl -o json` emits a STREAM of objects and the replay
// payload is the parsed list that _run_journalctl returns, which is the seam's
// own shape (harness/bin/se-reference-collector). Mirrors the reference's
// `[json.loads(line) for line in stdout.splitlines() if line.strip()]`
// exactly, including that a line which is not an object is an error rather
// than a skipped entry.
func decodeLines(raw []byte) ([]*value, error) {
	var out []*value
	for i, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		document, err := decodeDocument([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("journal line %d is not a JSON document: %v", i+1, err)
		}
		out = append(out, document)
	}
	return out, nil
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
// from. `has` is the other half — the reference tests membership with `in`
// before it copies, so a member present and null is a member present.
func (v *value) get(key string) *value {
	if v == nil || v.kind != jsonObject {
		return nil
	}
	return v.members.byKey[key]
}

func (v *value) has(key string) bool {
	if v == nil || v.kind != jsonObject {
		return false
	}
	_, ok := v.members.byKey[key]
	return ok
}

func (v *value) isString() bool { return v != nil && v.kind == jsonString }

// ── building ────────────────────────────────────────────────────────────

func stringValue(s string) *value { return &value{kind: jsonString, text: s} }

// numberValue carries an integer as its decimal token, never through a
// float64: Priority and the two repeat counts are integers on the wire and a
// consumer in a typed language sees the difference between 6 and 6.0.
func numberValue(n int64) *value {
	return &value{kind: jsonNumber, text: strconv.FormatInt(n, 10)}
}

func newObject() *value { return &value{kind: jsonObject, members: newMembers()} }

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
		// The token as it was read: a figure the document spelled must not
		// come back re-rendered.
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
