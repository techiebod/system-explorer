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

// A decoded bazarr API document, kept in the shape the wire carried it.
//
// encoding/json's usual targets destroy two things this collector must
// preserve. `map[string]any` loses member order, which decides the order the
// facts are derived in. `float64` loses the digits: a version member an
// interface ever spelled as a number would come back rounded, and 12 would
// come back indistinguishable from 12.0, which the harness's typed_equal
// treats as two different readings. So numbers are carried as their literal
// text and objects as an ordered member list, and every pass-through fact is
// emitted from the same bytes it was read from (DESIGN 19's pass-through
// ruling).
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
// here, because every reference site that reads one tests truthiness and
// cannot tell them apart either.
func (v jsonValue) get(key string) jsonValue {
	value, ok := v.member(key)
	if !ok {
		return jsonValue{kind: jsonNull}
	}
	return value
}

func (v jsonValue) isObject() bool { return v.kind == jsonObject }

// truthy is Python's bool(): empty containers, empty strings, zero and null
// are all false. It is the whole of `if data.get(member)` in status_facts,
// which is why a bazarr wired to no manager publishes no SonarrVersion rather
// than a fact holding the empty string the document actually carries.
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
