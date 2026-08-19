package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
)

// A decoded paperless API document, kept in the shape the wire carried it.
//
// encoding/json's usual targets destroy two things this collector must
// preserve. `map[string]any` loses member order, which decides the order the
// facts are derived in. `float64` loses the digits: the two storage byte
// counts on the committed capture both exceed 2^32, and a version member that
// arrived as a number would come back rounded, with 12 indistinguishable from
// 12.0 — which the harness's typed_equal treats as two different readings. So
// numbers are carried as their literal text and objects as an ordered member
// list, and every pass-through fact is emitted from the same bytes it was read
// from (DESIGN 19's pass-through ruling).
type jsonKind uint8

const (
	jsonNull jsonKind = iota
	jsonBool
	jsonNumber
	jsonString
	jsonArray
	jsonObject
)

type jsonMember struct {
	key   string
	value jsonValue
}

type jsonValue struct {
	kind    jsonKind
	boolean bool
	number  string // the literal, exactly as the document spelled it
	text    string
	array   []jsonValue
	members []jsonMember
}

// The reference reads each response through json.loads, where a repeated
// member keeps the FIRST position and the LAST value and len() sees one key.
func (v *jsonValue) set(key string, value jsonValue) {
	for i := range v.members {
		if v.members[i].key == key {
			v.members[i].value = value
			return
		}
	}
	v.members = append(v.members, jsonMember{key: key, value: value})
}

func (v jsonValue) member(key string) (jsonValue, bool) {
	if v.kind != jsonObject {
		return jsonValue{}, false
	}
	for _, m := range v.members {
		if m.key == key {
			return m.value, true
		}
	}
	return jsonValue{}, false
}

// get is Python's dict.get: a missing member and a present null are one value
// here, because every reference site that reads one either tests truthiness or
// tests the type, and neither can tell them apart. That equivalence is what
// the four `*_error` absences anchor — the status document spells all four
// members and holds null in each, and `if tasks.get(member)` says the same
// thing about a null as about a member that was never there.
func (v jsonValue) get(key string) jsonValue {
	value, ok := v.member(key)
	if !ok {
		return jsonValue{kind: jsonNull}
	}
	return value
}

func (v jsonValue) isObject() bool { return v.kind == jsonObject }

// truthy is Python's bool(): empty containers, empty strings, zero and null
// are all false. It is the whole of `if raw.get("pngx_version")` and of every
// `if tasks.get(member)` in status_facts, which is why a component whose check
// the app spelled as an empty string publishes no status fact rather than one
// holding nothing.
func (v jsonValue) truthy() bool {
	switch v.kind {
	case jsonNull:
		return false
	case jsonBool:
		return v.boolean
	case jsonNumber:
		return numberIsNonZero(v.number)
	case jsonString:
		return v.text != ""
	case jsonArray:
		return len(v.array) > 0
	case jsonObject:
		return len(v.members) > 0
	}
	return false
}

// mapping is `raw.get(name) or {}` followed by a `.get` on the result — the
// three-way shape the three status sub-documents are read through. A falsy
// member (missing, null, or an empty object) becomes the empty mapping and
// yields no facts, which is a READING. A truthy member that is not an object
// has no `.get` at all: Python raises AttributeError there, status_facts never
// returns, and the caller records the whole component half as unobservable —
// so this reports it as a shape it could not fold rather than as an emptiness.
func mapping(v jsonValue) (jsonValue, bool) {
	if !v.truthy() {
		return jsonValue{kind: jsonObject}, true
	}
	if !v.isObject() {
		return jsonValue{}, false
	}
	return v, true
}

// isPythonInt is `isinstance(value, int)` over a value json.loads produced,
// which is the gate on all five inventory counts and on both storage byte
// counts. Two halves, and the second is the surprising one:
//
//   - an integer LITERAL is a Python int; one carrying a fraction or an
//     exponent is a float, so `3.0` and `3e0` state no count at all and the
//     fact is omitted. That is the same rule that keeps a paperless too old to
//     carry a member from publishing anything (rule 7).
//   - a JSON boolean is a Python bool, and bool SUBCLASSES int, so
//     `"documents_total": true` passes isinstance and the reference publishes
//     the fact holding True. Reproduced rather than corrected: this port's job
//     is to say what the reference says about the same bytes, and a document
//     that spelled a count as a boolean is a paperless bug for the estate to
//     see rather than one for this collector to hide.
func isPythonInt(v jsonValue) bool {
	switch v.kind {
	case jsonBool:
		return true
	case jsonNumber:
		return isIntegerLiteral(v.number)
	}
	return false
}

func isIntegerLiteral(literal string) bool {
	return !strings.ContainsAny(literal, ".eE")
}

func numberIsNonZero(literal string) bool {
	if isIntegerLiteral(literal) {
		// JSON forbids leading zeros, so an integer is zero exactly when it
		// spells no non-zero digit — 0 and -0 and nothing else.
		return strings.ContainsAny(literal, "123456789")
	}
	f, err := strconv.ParseFloat(literal, 64)
	if err != nil {
		// Out of float64 range parses as ±Inf with an error; either way the
		// value is not zero, which is the only question asked here.
		return true
	}
	return f != 0
}

// ── decoding ────────────────────────────────────────────────────────────

func decodeDocument(r io.Reader) (jsonValue, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	value, err := decodeValue(dec)
	if err != nil {
		return jsonValue{}, err
	}
	// json.loads refuses trailing content and so does this: a second document
	// in one response is a broken interface, never a longer answer.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return jsonValue{}, errors.New("trailing content after the document")
		}
		return jsonValue{}, err
	}
	return value, nil
}

func decodeValue(dec *json.Decoder) (jsonValue, error) {
	token, err := dec.Token()
	if err != nil {
		return jsonValue{}, err
	}
	return decodeToken(dec, token)
}

func decodeToken(dec *json.Decoder, token json.Token) (jsonValue, error) {
	switch t := token.(type) {
	case nil:
		return jsonValue{kind: jsonNull}, nil
	case bool:
		return jsonValue{kind: jsonBool, boolean: t}, nil
	case json.Number:
		return jsonValue{kind: jsonNumber, number: string(t)}, nil
	case string:
		return jsonValue{kind: jsonString, text: t}, nil
	case json.Delim:
		switch t {
		case '[':
			value := jsonValue{kind: jsonArray}
			for dec.More() {
				element, err := decodeValue(dec)
				if err != nil {
					return jsonValue{}, err
				}
				value.array = append(value.array, element)
			}
			if _, err := dec.Token(); err != nil {
				return jsonValue{}, err
			}
			return value, nil
		case '{':
			value := jsonValue{kind: jsonObject}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return jsonValue{}, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return jsonValue{}, fmt.Errorf("object key is not a string: %v", keyToken)
				}
				member, err := decodeValue(dec)
				if err != nil {
					return jsonValue{}, err
				}
				value.set(key, member)
			}
			if _, err := dec.Token(); err != nil {
				return jsonValue{}, err
			}
			return value, nil
		}
	}
	return jsonValue{}, fmt.Errorf("unexpected token %v", token)
}

// ── emission ────────────────────────────────────────────────────────────

func (v jsonValue) appendJSON(out []byte) []byte {
	switch v.kind {
	case jsonNull:
		return append(out, "null"...)
	case jsonBool:
		if v.boolean {
			return append(out, "true"...)
		}
		return append(out, "false"...)
	case jsonNumber:
		if v.number == "" {
			return append(out, '0')
		}
		return append(out, v.number...)
	case jsonString:
		return appendQuoted(out, v.text)
	case jsonArray:
		out = append(out, '[')
		for i, element := range v.array {
			if i > 0 {
				out = append(out, ',')
			}
			out = element.appendJSON(out)
		}
		return append(out, ']')
	case jsonObject:
		out = append(out, '{')
		for i, m := range v.members {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendQuoted(out, m.key)
			out = append(out, ':')
			out = m.value.appendJSON(out)
		}
		return append(out, '}')
	}
	return append(out, "null"...)
}

// appendQuoted is json.dumps' default string encoder, ensure_ascii included:
// everything outside printable ASCII becomes \uXXXX (a surrogate pair above
// the BMP). The reference's Emitter calls json.dumps without ensure_ascii=False,
// so this is the spelling the corpus holds — and while the harness parses
// before it compares, the two streams read beside each other in a failure
// report and should not differ on spelling.
func appendQuoted(out []byte, s string) []byte {
	out = append(out, '"')
	for _, r := range s {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			switch {
			case r >= 0x20 && r <= 0x7e:
				out = append(out, byte(r))
			case r > 0xffff:
				high, low := utf16.EncodeRune(r)
				out = appendEscape(out, high)
				out = appendEscape(out, low)
			default:
				out = appendEscape(out, r)
			}
		}
	}
	return append(out, '"')
}

func appendEscape(out []byte, r rune) []byte {
	const hex = "0123456789abcdef"
	return append(out, '\\', 'u',
		hex[(r>>12)&0xf], hex[(r>>8)&0xf], hex[(r>>4)&0xf], hex[r&0xf])
}
