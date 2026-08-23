package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// A journal entry is opened by CURSOR, through the reference's own
// acquisition (`journalctl --cursor <c> -n 1`, adapters/logs.py _record) —
// not by searching the newest page, which would silently narrow "any entry
// the journal still holds" to "any entry younger than the page bound". The
// object response carries the entry's facts and the member-of edge to its
// unit — the edge the collection deliberately does NOT publish (collect.go),
// because the reference mints it only when an entry is opened. RepeatCount
// and RepeatWindow are page-derived and a single-record read has no page, so
// the opened object honestly lacks them, exactly as the reference's does.
// The EVIDENCE payload is the record as journald returned it, whole.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type verbEndRecord struct {
	Record    string `json:"record"`
	Verb      string `json:"verb"`
	Truncated bool   `json:"truncated"`
}

type evidenceDocumentRecord struct {
	Record    string `json:"record"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Canon     string `json:"canon,omitempty"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

type relationAssertionRecord struct {
	Record     string          `json:"record"`
	Collection string          `json:"collection"`
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Vantage    string          `json:"vantage"`
	Target     assertionTarget `json:"target"`
}

type assertionTarget struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// The declared bounds, pinned against declaration.json by test: a bound only
// in the declaration is a promise, one only here is undeclared authority.
const (
	objectVerbBytes   = 262144
	evidenceVerbBytes = 1048576
)

func verbDecline(out *emitter, stderr io.Writer, verb, collection, reason, detail string) int {
	out.emit(declineRecord{Record: "decline", Collection: collection,
		Reason: reason, Detail: detail})
	out.emit(verbEndRecord{Record: "verb_end", Verb: verb})
	return verbExit(out, stderr)
}

// verbEntry is the shared acquisition gate: both verbs open the same one
// record, and both route the seam's decline the same way.
func verbEntry(out *emitter, stderr io.Writer, src source, verb, cursor string) (*value, bool, int) {
	record, found, err := src.entry(cursor)
	var refused *declined
	if errors.As(err, &refused) {
		return nil, false, verbDecline(out, stderr, verb, collectionJournal,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, false, exitRuntime
	}
	if !found {
		return nil, false, verbDecline(out, stderr, verb, collectionJournal, "unavailable",
			"the journal holds no entry at that cursor")
	}
	return record, true, exitOK
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != collectionJournal {
		return verbDecline(out, stderr, "object", collection, "unsupported",
			"this collector serves journal only")
	}
	record, ok, code := verbEntry(out, stderr, src, "object", name)
	if !ok {
		return code
	}
	facts, err := entryFacts(record)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	out.emit(objectRecord{
		Record:     "object",
		Type:       "entry",
		Collection: collection,
		Name:       name,
		Facts:      facts.encode(),
		At:         src.stamp(0),
	})
	// The member-of edge to the entry's unit, minted exactly where the
	// reference mints it: on the opened object, never on the collection.
	if unit := record.get("_SYSTEMD_UNIT"); unit.isString() && unit.text != "" {
		out.emit(relationAssertionRecord{
			Record: "relation_assertion", Collection: collection,
			Name: name, Vantage: collection, Type: "member-of",
			Target: assertionTarget{Kind: "unit", Name: unit.text},
		})
	}
	out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
	return verbExit(out, stderr)
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != collectionJournal {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector serves journal only")
	}
	record, ok, code := verbEntry(out, stderr, src, "evidence", name)
	if !ok {
		return code
	}
	// The record as journald returned it, whole — member order and number
	// literals preserved by the document model.
	canonical := []byte(record.encode())
	truncated := false
	if len(canonical) > evidenceVerbBytes {
		// A truncated document marked truncated is still evidence; an
		// unmarked one is a lie about the system (DESIGN 19). The digest is
		// over the bytes AS SERVED, so it stays checkable.
		canonical = canonical[:evidenceVerbBytes]
		truncated = true
	}
	sum := sha256.Sum256(canonical)
	out.emit(evidenceDocumentRecord{
		Record:    "evidence_document",
		MediaType: "application/json",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Canon:     "jcs/1",
		Bytes:     len(canonical),
		Truncated: truncated,
	})
	if out.err == nil {
		if _, err := stdout.Write(append(canonical, '\n')); err != nil {
			out.err = err
		}
	}
	out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence", Truncated: truncated})
	return verbExit(out, stderr)
}

func verbExit(out *emitter, stderr io.Writer) int {
	if out.err != nil {
		fmt.Fprintln(stderr, "writing the response:", out.err)
		return exitRuntime
	}
	return exitOK
}
