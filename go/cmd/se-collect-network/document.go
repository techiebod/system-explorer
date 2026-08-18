package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// A decoded nft document, kept in the shape the wire carried it.
//
// encoding/json's usual targets destroy two things this collector must
// preserve. `map[string]any` loses member order, and the residue text is a
// verbatim re-serialisation of statements the renderer did not consume — a
// reordered member set is a different answer. `float64` loses the digits:
// a u64 packet counter above 2^53 comes back rounded, and 12 comes back
// indistinguishable from 12.0, which the harness's typed_equal treats as two
// different readings. So numbers are carried as their literal text and
// objects as an ordered member list, and every pass-through fact is emitted
// from the same bytes it was read from.
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

// The reference reads `nft -j list ruleset` through json.loads, where a
// repeated member keeps the FIRST position and the LAST value and len() sees
// one key. _render_match branches on len(left) == 1, so collapsing here is
// what keeps that test asking the same question a Python dict would answer.
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

// get is Python's dict.get: a missing member and a present null are one
// value here, because every reference site that reads one tests `is not None`
// or truthiness and cannot tell them apart either.
func (v jsonValue) get(key string) jsonValue {
	value, ok := v.member(key)
	if !ok {
		return jsonValue{kind: jsonNull}
	}
	return value
}

func (v jsonValue) has(key string) bool {
	_, ok := v.member(key)
	return ok
}

func (v jsonValue) isObject() bool { return v.kind == jsonObject }
func (v jsonValue) isArray() bool  { return v.kind == jsonArray }
func (v jsonValue) isString() bool { return v.kind == jsonString }
func (v jsonValue) isNull() bool   { return v.kind == jsonNull }

// isInt is Python's isinstance(x, int), bools included — bool subclasses int
// there, so a JSON true reaches the integer branch of the mask test and of
// the anonymous-set element test. Reproducing that is the difference between
// rendering `& 0x1` and declining the whole match.
func (v jsonValue) isInt() bool {
	switch v.kind {
	case jsonBool:
		return true
	case jsonNumber:
		return isIntegerLiteral(v.number)
	}
	return false
}

func (v jsonValue) size() int {
	switch v.kind {
	case jsonArray:
		return len(v.array)
	case jsonObject:
		return len(v.members)
	}
	return 0
}

func (v jsonValue) firstKey() string {
	if v.kind == jsonObject && len(v.members) > 0 {
		return v.members[0].key
	}
	return ""
}

// stringMember is how every identity component is read: family, table, chain
// and target are JSON strings on every document nft produces. A missing,
// null or non-string member reads as the empty string rather than becoming a
// null fact, which the contract forbids at any depth.
func (v jsonValue) stringMember(key string) string {
	m, ok := v.member(key)
	if !ok || m.kind != jsonString {
		return ""
	}
	return m.text
}

// truthy is Python's bool(): empty containers, empty strings, zero and null
// are all false. BaseChain is bool(chain["hook"]) and nothing else, so a
// chain carrying "hook": "" is NOT a base chain even though Hook is still
// emitted — two different tests on one member, deliberately kept apart.
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
	// in the payload is a broken capture, never a longer ruleset.
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

// MarshalJSON re-emits the value the document carried, digits included. The
// escaping is ASCII-only, which is what the reference's json.dumps does and
// costs nothing here: a \uXXXX escape and the character it names parse to the
// same string, and the harness compares parsed values.
func (v jsonValue) MarshalJSON() ([]byte, error) {
	return v.appendJSON(nil), nil
}

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
