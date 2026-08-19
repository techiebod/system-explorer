package main

import (
	"regexp"
	"sort"
)

// nameVersionRe splits a Nix store name-version at the first hyphen followed
// by a digit. Non-greedy on purpose and anchored at the start: `python3.11-
// numpy-1.26.4` is the numpy package at 1.26.4, not python3.11 at
// "numpy-1.26.4", and only the leftmost split whose tail begins with a digit
// gets that right.
var nameVersionRe = regexp.MustCompile(`^(.+?)-([0-9].*)`)

// The dpkg status this collection answers about. dpkg keeps rows for packages
// that were removed but kept their configuration, and half a package is not an
// installed one — "which packages are installed" is the question, so a row in
// any other state is not a row here. rpm has no such state and reports only
// what is installed, which is why the format string asks it for no status
// field to filter on.
const dpkgInstalled = "installed"

// pkgRow is one published package: the native name it is known by, the facts
// that describe it, and the declared facts this manager genuinely does not
// carry. `name` is facts["Name"] lifted out because the emission order is
// keyed on it and re-reading it from the map at every comparison would be the
// sort key looking somewhere the sort does not.
type pkgRow struct {
	native string
	name   string
	facts  map[string]string
	absent []string
}

// inventory turns one manager's reading into the collection's rows, in
// emission order.
//
// The three branches are three interfaces, and the facts they can carry
// differ: dpkg and rpm hand over an architecture and no store path, the Nix
// store hands over a store path and no architecture. A fact a manager has no
// concept of is not declared absent — absent means "we looked at a document
// that could have carried it and it did not" — so each branch states only what
// its interface is about.
func inventory(got reading) []pkgRow {
	var rows []pkgRow
	switch got.manager {
	case managerNix:
		for _, nameVersion := range sortedKeys(got.store) {
			name, version := nameVersion, ""
			if match := nameVersionRe.FindStringSubmatch(nameVersion); match != nil {
				name, version = match[1], match[2]
			}
			rows = append(rows, newRow(nameVersion, map[string]string{
				"Name":      name,
				"Manager":   managerNix,
				"StorePath": got.store[nameVersion],
			}, pair{"Version", version}))
		}
	case managerDpkg:
		for _, fields := range got.rows {
			name, version, arch := field(fields, 0), field(fields, 1), field(fields, 2)
			if status := field(fields, 3); status != "" && status != dpkgInstalled {
				continue
			}
			rows = append(rows, newRow(name, map[string]string{
				"Name":    name,
				"Manager": managerDpkg,
			}, pair{"Version", version}, pair{"Architecture", arch}))
		}
	case managerRPM:
		for _, fields := range got.rows {
			name, version, arch := field(fields, 0), field(fields, 1), field(fields, 2)
			rows = append(rows, newRow(name, map[string]string{
				"Name":    name,
				"Manager": managerRPM,
			}, pair{"Version", version}, pair{"Architecture", arch}))
		}
	}
	// By name, then by the native name that is the row's identity — the
	// reference's own key. SliceStable, because a manager CAN report one name
	// twice (a multi-arch dpkg install is the same package twice over) and
	// those two rows tie on both members: stable keeps them in the order the
	// interface listed them instead of swapping them run to run.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].name != rows[j].name {
			return rows[i].name < rows[j].name
		}
		return rows[i].native < rows[j].native
	})
	return rows
}

// pair is an optional fact: the name it would be published under, and the
// value the document carried, which may be empty.
type pair struct{ fact, value string }

// newRow routes each optional fact to the channel that states the truth about
// it. An empty field is not an empty value: value, absent and unobservable
// each have their own channel and a fact value is never null or blank (DESIGN
// 19), so a package whose version the manager did not report says so on the
// absent list rather than shipping "" — or, as the Python reference does here,
// a null the stream rules refuse.
func newRow(native string, facts map[string]string, optional ...pair) pkgRow {
	var absent []string
	for _, opt := range optional {
		if opt.value != "" {
			facts[opt.fact] = opt.value
		} else {
			absent = append(absent, opt.fact)
		}
	}
	return pkgRow{native: native, name: facts["Name"], facts: facts, absent: absent}
}

// sortedKeys is the store's emission order. A Go map has none of its own and
// the reference sorts the store's items before it builds a single row, so the
// order is part of the derivation rather than a tidiness applied to it.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// field is the i-th field of a row, or "" — the reference pads every row to
// its format string's field count before unpacking it, so a short row is
// missing fields rather than a parse failure. The format is this collector's
// own (source.go), which is what makes the count a contract at all.
func field(fields []string, i int) string {
	if i < len(fields) {
		return fields[i]
	}
	return ""
}
