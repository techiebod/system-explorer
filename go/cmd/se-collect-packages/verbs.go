package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// packages has no density behind its rows: the one listing carries every
// declared fact, so an object response is the row the inventory publishes,
// addressed by native name. The EVIDENCE payload follows the reference
// (adapters/packages.py get_evidence): the manager's name plus, for dpkg and
// rpm, the tab-split fields exactly as the tool printed them and the format
// string that ordered them. For nix it is the manager and the store path the
// row's facts derive from — and NOT the reference's sw link enumeration,
// because this port's capture format stages the derived name→path map and
// carries no link names; serving links live while replay could not would let
// the two paths drift, so the member is omitted whole until a capture
// carries the farm. The omission is pinned by test.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// verbReading is the shared acquisition gate: both verbs rest on the same
// listing collect does, and both route the seam's decline the same way.
func verbReading(out *emitter, stderr io.Writer, src source, verb string) (reading, bool, int) {
	got, err := src.packages()
	var refused *declined
	if errors.As(err, &refused) {
		return reading{}, false, verbDecline(out, stderr, verb, "packages",
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return reading{}, false, exitRuntime
	}
	return got, true, exitOK
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != "packages" {
		return verbDecline(out, stderr, "object", collection, "unsupported",
			"this collector serves packages only")
	}
	got, ok, code := verbReading(out, stderr, src, "object")
	if !ok {
		return code
	}
	for _, row := range inventory(got) {
		if row.native != name {
			continue
		}
		out.emit(objectRecord{
			Record:     "object",
			Type:       "package",
			Collection: collection,
			Name:       row.native,
			Facts:      row.facts,
			Absent:     row.absent,
			At:         src.stamp(0),
		})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}
	return verbDecline(out, stderr, "object", collection, "unavailable",
		"this collector publishes no object of that name in this collection")
}

// evidencePayload is the raw listing slice one row's facts were read from,
// and whether the name is among the rows THAT reading publishes.
func evidencePayload(got reading, name string) (map[string]json.RawMessage, bool) {
	rawString := func(s string) json.RawMessage {
		encoded, _ := json.Marshal(s)
		return encoded
	}
	payload := map[string]json.RawMessage{"manager": rawString(got.manager)}
	if got.manager == managerNix {
		storePath, held := got.store[name]
		if !held {
			return nil, false
		}
		payload["store_path"] = rawString(storePath)
		return payload, true
	}
	for _, fields := range got.rows {
		if len(fields) == 0 || fields[0] != name {
			continue
		}
		encoded, _ := json.Marshal(fields)
		payload["fields"] = encoded
		format := dpkgFormat
		if got.manager == managerRPM {
			format = rpmFormat
		}
		payload["format"] = rawString(format)
		return payload, true
	}
	return nil, false
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != "packages" {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector serves packages only")
	}
	got, ok, code := verbReading(out, stderr, src, "evidence")
	if !ok {
		return code
	}
	payload, found := evidencePayload(got, name)
	if !found {
		return verbDecline(out, stderr, "evidence", collection, "unavailable",
			"this collector publishes no object of that name in this collection")
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(stderr, "evidence payload:", err)
		return exitRuntime
	}
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
