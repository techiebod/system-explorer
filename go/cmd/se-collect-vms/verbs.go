package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// vms has no density behind its rows, so an object response is the row the
// collection publishes — facts and the UUID name family that survives a
// rename — addressed by name. The EVIDENCE payload is the reference's
// (adapters/vms.py get_evidence): the walk's whole entry for one domain,
// split as the reference splits it — every member except the XML under
// `info`, and the domain definition itself under `domain_xml`, because the
// XML is the half a person diffs against `virsh dumpxml` and the info half
// is libvirt's own runtime reading.

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

// verbDocument is the shared acquisition gate: both verbs answer from the
// same walk collect reads, and both route the seam's decline the same way.
func verbDocument(out *emitter, stderr io.Writer, src source, verb string) (*value, bool, int) {
	document, err := src.domains()
	var refused *declined
	if errors.As(err, &refused) {
		return nil, false, verbDecline(out, stderr, verb, collectionDomains,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, false, exitRuntime
	}
	return document, true, exitOK
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != collectionDomains {
		return verbDecline(out, stderr, "object", collection, "unsupported",
			"this collector serves domains only")
	}
	document, ok, code := verbDocument(out, stderr, src, "object")
	if !ok {
		return code
	}
	rows, err := domainRows(document)
	if err != nil {
		fmt.Fprintln(stderr, "domains:", err)
		return exitRuntime
	}
	for _, row := range rows {
		if row.name != name {
			continue
		}
		at, err := src.stamp(0)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		record := objectRecord{
			Record:     "object",
			Type:       "domain",
			Collection: collection,
			Name:       row.name,
			Facts:      row.facts.encode(),
			At:         at,
		}
		if row.names != nil {
			record.Names = row.names.encode()
		}
		out.emit(record)
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}
	return verbDecline(out, stderr, "object", collection, "unavailable", noSuchObject)
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != collectionDomains {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector serves domains only")
	}
	document, ok, code := verbDocument(out, stderr, src, "evidence")
	if !ok {
		return code
	}
	var entry *value
	for _, candidate := range arrayItems(document) {
		if n := candidate.get("name"); n != nil && n.kind == jsonString && n.text == name {
			entry = candidate
			break
		}
	}
	if entry == nil {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", noSuchObject)
	}
	// The reference's split: everything but the XML under `info`, the
	// definition under `domain_xml`. The top level is assembled here (Go
	// marshals map keys sorted, which is the canon the digest names); the
	// info document keeps libvirt's own member order.
	info := newObject()
	for _, key := range entry.members.keys {
		if key != "xml" {
			info.set(key, entry.members.byKey[key])
		}
	}
	canonical, err := json.Marshal(map[string]json.RawMessage{
		"info":       info.encode(),
		"domain_xml": entry.get("xml").encode(),
	})
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

func arrayItems(v *value) []*value {
	if v == nil || v.kind != jsonArray {
		return nil
	}
	return v.items
}

func verbExit(out *emitter, stderr io.Writer) int {
	if out.err != nil {
		fmt.Fprintln(stderr, "writing the response:", out.err)
		return exitRuntime
	}
	return exitOK
}
