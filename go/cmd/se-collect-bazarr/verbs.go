package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// bazarr has no density behind its one row: the pair of API reads carries
// every declared fact, so an object response is the row the collection
// publishes, addressed by name. The EVIDENCE payload is the two documents in
// the reference's shape (adapters/bazarr.py get_evidence): status and
// health, verbatim. One stated deviation: the reference raises when either
// read fails, where this side serves the half it has and carries the other
// as status_error/health_error with the same constant text the row's
// unobservable fact uses — unreadable and absent must not render the same,
// and an evidence request that crashed over a half-broken app would tell a
// reader nothing at all.

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

func verbReading(out *emitter, stderr io.Writer, src source, verb string) (reading, bool, int) {
	got, err := src.instance()
	var refused *declined
	if errors.As(err, &refused) {
		if err.Error() != refused.Error() {
			fmt.Fprintln(stderr, "instance:", err)
		}
		return reading{}, false, verbDecline(out, stderr, verb, collectionInstance,
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
	if collection != collectionInstance {
		return verbDecline(out, stderr, "object", collection, "unsupported",
			"this collector serves instance only")
	}
	got, ok, code := verbReading(out, stderr, src, "object")
	if !ok {
		return code
	}
	if name != instanceName {
		return verbDecline(out, stderr, "object", collection, "unavailable",
			"this collector publishes no object of that name in this collection")
	}
	out.emit(objectRecord{
		Record:     "object",
		Type:       "bazarr-instance",
		Collection: collection,
		Name:       instanceName,
		Facts:      instanceRow(got).encode(),
		At:         src.stamp(0),
	})
	out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
	return verbExit(out, stderr)
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != collectionInstance {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector serves instance only")
	}
	got, ok, code := verbReading(out, stderr, src, "evidence")
	if !ok {
		return code
	}
	if name != instanceName {
		return verbDecline(out, stderr, "evidence", collection, "unavailable",
			"this collector publishes no object of that name in this collection")
	}
	// The top level is assembled here (Go marshals map keys sorted, which is
	// the canon the digest names); each document inside keeps the API's own
	// member order and number spellings.
	payload := map[string]json.RawMessage{}
	unread, _ := json.Marshal(got.unobservable)
	if got.statusRead {
		payload["status"] = got.status.appendJSON(nil)
	} else {
		payload["status_error"] = unread
	}
	if got.healthRead {
		payload["health"] = got.health.appendJSON(nil)
	} else {
		payload["health_error"] = unread
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
