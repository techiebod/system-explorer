package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// protection has no density behind its rows, so an object response is the
// row the collection publishes, addressed by name. The EVIDENCE payloads are
// the reference's (adapters/protection.py get_evidence): a job's evidence
// carries the status document AND both receipts, because the pair IS the
// distinction between a run that failed and a job that has never run — and
// a receipt that would not open is shown as itself under its own key, never
// as a gap in the pair. A target's or destination's evidence is the
// manifest whole. Membership is checked in the same documents the payload
// serves.

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

const noSuchObject = "this collector publishes no object of that name in this collection"

func verbDecline(out *emitter, stderr io.Writer, verb, collection, reason, detail string) int {
	out.emit(declineRecord{Record: "decline", Collection: collection,
		Reason: reason, Detail: detail})
	out.emit(verbEndRecord{Record: "verb_end", Verb: verb})
	return verbExit(out, stderr)
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	build, serves := served[collection]
	if !serves {
		return verbDecline(out, stderr, "object", collection, "unsupported", servedNames)
	}
	built, err := build(src)
	var refused *declined
	if errors.As(err, &refused) {
		if err.Error() != refused.Error() {
			fmt.Fprintln(stderr, collection+":", err)
		}
		return verbDecline(out, stderr, "object", collection,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
		return exitRuntime
	}
	for _, one := range built {
		if one.name != name {
			continue
		}
		out.emit(objectRecord{
			Record:     "object",
			Type:       collectionTypes[collection],
			Collection: collection,
			Name:       one.name,
			Facts:      one.facts.encode(),
			At:         src.stamp(0),
		})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}
	return verbDecline(out, stderr, "object", collection, "unavailable", noSuchObject)
}

// ── evidence ────────────────────────────────────────────────────────────

// evidenceCanonical is the payload bytes for one object, and whether the
// name is among what the same documents publish.
func evidenceCanonical(src source, collection, name string) ([]byte, bool, error) {
	manifest, err := readManifest(src)
	if err != nil {
		return nil, false, err
	}
	payload := map[string]json.RawMessage{}
	if collection == "jobs" {
		hostname, err := src.hostname()
		if err != nil {
			return nil, false, err
		}
		status, err := readStatus(src, manifest, hostname)
		if err != nil {
			return nil, false, err
		}
		known := false
		for _, entry := range arrayItems(status.get("jobs")) {
			if entry.isObject() && entry.get("job").truthy() &&
				entry.get("job").pyStr() == name {
				known = true
				break
			}
		}
		if !known {
			return nil, false, nil
		}
		documents, faults, err := receipts(src, name)
		if err != nil {
			return nil, false, err
		}
		payload[statusPath] = status.encode()
		receiptsDoc := map[string]json.RawMessage{}
		for suffix, document := range documents {
			receiptsDoc[suffix] = document.encode()
		}
		encoded, _ := json.Marshal(receiptsDoc)
		payload[receiptsDir] = encoded
		if len(faults) > 0 {
			// Evidence must be able to show its object: a receipt that
			// would not open is shown as itself, never as a gap in the
			// pair the row rests on.
			encoded, _ := json.Marshal(faults)
			payload[receiptsDir+" (unreadable)"] = encoded
		}
	} else {
		section := manifest.get("destinations")
		if collection == "targets" {
			section = manifest.get("targets")
		}
		if !section.isObject() || !section.get(name).isObject() {
			return nil, false, nil
		}
		payload[manifestPath] = manifest.encode()
	}
	canonical, err := json.Marshal(payload)
	return canonical, true, err
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, serves := served[collection]; !serves {
		return verbDecline(out, stderr, "evidence", collection, "unsupported", servedNames)
	}
	canonical, found, err := evidenceCanonical(src, collection, name)
	var refused *declined
	if errors.As(err, &refused) {
		if err.Error() != refused.Error() {
			fmt.Fprintln(stderr, collection+":", err)
		}
		return verbDecline(out, stderr, "evidence", collection,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
		return exitRuntime
	}
	if !found {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", noSuchObject)
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
