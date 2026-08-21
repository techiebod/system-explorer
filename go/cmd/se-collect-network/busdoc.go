package main

import (
	"encoding/json"
	"fmt"
)

// busctl's own JSON rendering of a D-Bus reply is the native document for
// bus interfaces (DESIGN's 2026-08-19 ruling, first applied in
// se-collect-units): `busctl call … --json=short` emits
// {"type":"<signature>","data":[…]}, self-describing about D-Bus types, so
// a reader with a `from` path into it can re-run one command and compare.
//
// This is not a general D-Bus decoder. The two replies on this collector's
// acquisition path are both a{sv} GetAll answers, the reader states that
// signature and refuses anything else — deny-by-default at the document,
// the same discipline the replay seam applies at the payload.
type busDocument struct {
	Type string            `json:"type"`
	Data []json.RawMessage `json:"data"`
}

// variant is the one place the document nests its own type: `v` is rendered
// as {"type": …, "data": …}, which is how a{sv} keeps a property's
// signature beside its value.
type variant struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

const sigProperties = "a{sv}"

// propertiesOf reads one GetAll reply into its property map.
func propertiesOf(raw []byte) (map[string]variant, error) {
	var doc busDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("the reply is not a busctl document: %v", err)
	}
	if doc.Type != sigProperties || len(doc.Data) != 1 {
		return nil, fmt.Errorf("expected one %s argument, got %q with %d",
			sigProperties, doc.Type, len(doc.Data))
	}
	var properties map[string]variant
	if err := json.Unmarshal(doc.Data[0], &properties); err != nil {
		return nil, fmt.Errorf("the %s argument does not decode: %v", sigProperties, err)
	}
	return properties, nil
}

// Typed readers over a property map: each states the signature it expects
// and answers (zero, false) when the property is missing or differently
// typed — the CALLER decides whether that is an absent fact or a defect,
// because only it knows what the interface promises.

func propString(props map[string]variant, name string) (string, bool) {
	v, ok := props[name]
	if !ok || v.Type != "s" {
		return "", false
	}
	var s string
	return s, json.Unmarshal(v.Data, &s) == nil
}

func propBool(props map[string]variant, name string) (bool, bool) {
	v, ok := props[name]
	if !ok || v.Type != "b" {
		return false, false
	}
	var b bool
	return b, json.Unmarshal(v.Data, &b) == nil
}

func propU64(props map[string]variant, name string) (uint64, bool) {
	v, ok := props[name]
	if !ok || v.Type != "t" {
		return 0, false
	}
	var n uint64
	return n, json.Unmarshal(v.Data, &n) == nil
}

func propStrings(props map[string]variant, name string) ([]string, bool) {
	v, ok := props[name]
	if !ok || v.Type != "as" {
		return nil, false
	}
	var out []string
	if json.Unmarshal(v.Data, &out) != nil {
		return nil, false
	}
	if out == nil {
		out = []string{}
	}
	return out, true
}
