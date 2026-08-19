package main

import (
	"encoding/json"
	"fmt"
)

// busctl's own JSON rendering of a D-Bus reply is the native document for this
// interface (DESIGN's 2026-08-19 ruling): `busctl call … --json=short` emits
// {"type":"<signature>","data":[<one entry per reply argument>]}, so the
// document is self-describing about D-Bus types and a reader with a `from`
// path into it can re-run one command and compare.
//
// What this file is NOT is a general D-Bus decoder. Every reader below states
// the signature it expects and refuses anything else, because the four replies
// on the acquisition path have four fixed shapes and a decoder that shrugged
// at an unexpected one would turn an interface change into a thinner row
// instead of an error. Deny-by-default at the document, the same discipline
// the replay seam applies at the payload.
type busDocument struct {
	Type string            `json:"type"`
	Data []json.RawMessage `json:"data"`
}

// variant is the one place the document nests its own type: `v` is rendered as
// {"type": …, "data": …}, which is how a{sv} keeps a property's signature
// beside its value.
type variant struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// The signatures each reply on the acquisition path carries. Constants rather
// than literals at the call sites: the same string appears in the reader and
// in its error, and a reply whose signature moved is the thing this collector
// most needs to be loud about.
const (
	sigListUnits     = "a(ssssssouso)"
	sigListUnitFiles = "a(ss)"
	sigProperties    = "a{sv}"
	sigVariant       = "v"
	sigStringList    = "as"
	sigString        = "s"
)

// The ten members of a ListUnits row, in systemd's order. Named so the row
// reader indexes by meaning rather than by a number nobody can check.
const (
	rowName = iota
	rowDescription
	rowLoadState
	rowActiveState
	rowSubState
	rowFollowing
	rowPath
	rowJobID
	rowJobType
	rowJobPath
	rowMembers
)

func singleArgument(raw []byte, want string) (json.RawMessage, error) {
	var document busDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("the reply is not a busctl document: %v", err)
	}
	if document.Type != want {
		return nil, fmt.Errorf("the reply carries signature %q, not %q", document.Type, want)
	}
	if len(document.Data) != 1 {
		return nil, fmt.Errorf("the reply carries %d arguments, not 1", len(document.Data))
	}
	return document.Data[0], nil
}

// unitRow is one ListUnits entry with the seven members this collector reads.
// The three job members are decoded and dropped: a row of the wrong width is a
// different interface, and reading only what is wanted would hide that.
type unitRow struct {
	name, description, load, active, sub, following, path string
}

func decodeListUnits(raw []byte) ([]unitRow, error) {
	argument, err := singleArgument(raw, sigListUnits)
	if err != nil {
		return nil, fmt.Errorf("ListUnits: %v", err)
	}
	var entries [][]json.RawMessage
	if err := json.Unmarshal(argument, &entries); err != nil {
		return nil, fmt.Errorf("ListUnits: the argument is not an array of structs: %v", err)
	}
	rows := make([]unitRow, 0, len(entries))
	for index, entry := range entries {
		if len(entry) != rowMembers {
			return nil, fmt.Errorf("ListUnits: row %d has %d members, not %d", index, len(entry), rowMembers)
		}
		fields := make([]string, rowPath+1)
		for member := rowName; member <= rowPath; member++ {
			if err := json.Unmarshal(entry[member], &fields[member]); err != nil {
				return nil, fmt.Errorf("ListUnits: row %d member %d is not a string: %v", index, member, err)
			}
		}
		rows = append(rows, unitRow{
			name: fields[rowName], description: fields[rowDescription],
			load: fields[rowLoadState], active: fields[rowActiveState],
			sub: fields[rowSubState], following: fields[rowFollowing],
			path: fields[rowPath],
		})
	}
	return rows, nil
}

// decodeUnitFileNames reduces ListUnitFiles to the set the adapter builds from
// it: the basename of every unit file path. The distinction it draws is the
// whole point of the call — systemd synthesises a .mount unit for anything
// mounted outside its control, and such a unit has no file — so the enablement
// state beside each path is read past deliberately.
func decodeUnitFileNames(raw []byte) (map[string]bool, error) {
	argument, err := singleArgument(raw, sigListUnitFiles)
	if err != nil {
		return nil, fmt.Errorf("ListUnitFiles: %v", err)
	}
	var entries [][]string
	if err := json.Unmarshal(argument, &entries); err != nil {
		return nil, fmt.Errorf("ListUnitFiles: the argument is not an array of pairs: %v", err)
	}
	names := make(map[string]bool, len(entries))
	for index, entry := range entries {
		if len(entry) != 2 {
			return nil, fmt.Errorf("ListUnitFiles: row %d has %d members, not 2", index, len(entry))
		}
		path := entry[0]
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] == '/' {
				path = path[i+1:]
				break
			}
		}
		names[path] = true
	}
	return names, nil
}

// decodeStringListProperties keeps the `as` properties of a GetAll reply and
// drops the rest. Every property this collector reads off a unit that systemd
// could not load is a list of unit names; a property of another type is
// carried by nothing here, so decoding it would be inventing a use for it.
func decodeStringListProperties(raw []byte) (map[string][]string, error) {
	argument, err := singleArgument(raw, sigProperties)
	if err != nil {
		return nil, fmt.Errorf("GetAll: %v", err)
	}
	var properties map[string]variant
	if err := json.Unmarshal(argument, &properties); err != nil {
		return nil, fmt.Errorf("GetAll: the argument is not a property map: %v", err)
	}
	out := make(map[string][]string, len(properties))
	for name, value := range properties {
		if value.Type != sigStringList {
			continue
		}
		var list []string
		if err := json.Unmarshal(value.Data, &list); err != nil {
			return nil, fmt.Errorf("GetAll: property %s is signature %q and does not decode as one: %v", name, sigStringList, err)
		}
		out[name] = list
	}
	return out, nil
}

// decodeStringProperty reads a Properties.Get reply: a variant holding one
// string. The empty string is a legitimate answer and is returned as one —
// what it MEANS is the caller's, and for Slice it means the unit is in no
// cgroup, which is an absent fact rather than an empty one.
func decodeStringProperty(raw []byte) (string, error) {
	argument, err := singleArgument(raw, sigVariant)
	if err != nil {
		return "", fmt.Errorf("Get: %v", err)
	}
	var held variant
	if err := json.Unmarshal(argument, &held); err != nil {
		return "", fmt.Errorf("Get: the variant does not decode: %v", err)
	}
	if held.Type != sigString {
		return "", fmt.Errorf("Get: the variant holds signature %q, not %q", held.Type, sigString)
	}
	var value string
	if err := json.Unmarshal(held.Data, &value); err != nil {
		return "", fmt.Errorf("Get: the variant's value is not a string: %v", err)
	}
	return value, nil
}
