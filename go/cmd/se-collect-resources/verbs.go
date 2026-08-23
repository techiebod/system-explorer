package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// resources has no density behind its rows, so an object response is the row
// the collection publishes — the full derivation, attribution and remainder
// included, because a row here that disagreed with the listing would be two
// answers about one cgroup. The EVIDENCE payload is the reference's
// (adapters/resources.py get_evidence): the kernel files the row was folded
// from, verbatim, keyed by their full paths — and membership is the same
// walk the collection is built from, so a name that only exists inside a
// delegated hierarchy gets no evidence vouching for another manager's
// cgroup. The root row alone carries /proc/stat, the denominator its
// unattributed remainder was computed against.

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

// evidenceFiles is the reference's file list, in its order: what one row was
// folded from.
var evidenceFiles = [...]string{
	"cpu.stat", "memory.current", "memory.peak", "memory.swap.current",
	"memory.events", "io.stat", "io.pressure", "cpu.pressure",
	"memory.pressure",
}

func verbDecline(out *emitter, stderr io.Writer, verb, collection, reason, detail string) int {
	out.emit(declineRecord{Record: "decline", Collection: collection,
		Reason: reason, Detail: detail})
	out.emit(verbEndRecord{Record: "verb_end", Verb: verb})
	return verbExit(out, stderr)
}

// verbRows is the shared derivation: the same tree, attribution and
// remainder collect computes, in the same order, for the same reason —
// /proc/stat after the tree, so a negative remainder cannot be manufactured
// out of the sampling gap.
func verbRows(out *emitter, stderr io.Writer, src source, verb string) (*tree, []row, bool, int) {
	found, err := readTree(src)
	var refused *declined
	if errors.As(err, &refused) {
		if err.Error() != refused.Error() {
			fmt.Fprintln(stderr, "workloads:", err)
		}
		return nil, nil, false, verbDecline(out, stderr, verb, collectionWorkloads,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, nil, false, exitRuntime
	}
	attribution := stallAttribution(found)
	remainder, err := unattributedCPU(src, found)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, nil, false, exitRuntime
	}
	return found, found.rows(remainder, attribution), true, exitOK
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != collectionWorkloads {
		return verbDecline(out, stderr, "object", collection, "unsupported",
			"this collector serves workloads only")
	}
	_, rows, ok, code := verbRows(out, stderr, src, "object")
	if !ok {
		return code
	}
	for _, one := range rows {
		if one.name != name {
			continue
		}
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			Type:       unitKind(one.name),
			Name:       one.name,
			Facts:      one.facts.encode(),
			At:         src.stamp(0),
		})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}
	return verbDecline(out, stderr, "object", collection, "unavailable", noSuchObject)
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != collectionWorkloads {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector serves workloads only")
	}
	found, rows, ok, code := verbRows(out, stderr, src, "evidence")
	if !ok {
		return code
	}
	published := false
	for _, one := range rows {
		if one.name == name {
			published = true
			break
		}
	}
	node := found.get(name)
	if !published || node == nil {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", noSuchObject)
	}
	payload := map[string]json.RawMessage{}
	rawString := func(s string) json.RawMessage {
		encoded, _ := json.Marshal(s)
		return encoded
	}
	readInto := func(path string) error {
		text, present, err := src.readText(path)
		if err != nil {
			return err
		}
		if !present {
			// The reference shows the OSError's own words here; this seam
			// folds "would not open" into one statement, so the value is a
			// constant rather than an errno nobody measured. Shown, never
			// omitted — an unreadable counter must not look like one the
			// kernel does not keep.
			payload[path] = rawString("not present")
			return nil
		}
		payload[path] = rawString(text)
		return nil
	}
	for _, filename := range evidenceFiles {
		if err := readInto(node.path + "/" + filename); err != nil {
			fmt.Fprintln(stderr, "workloads:", err)
			return exitRuntime
		}
	}
	if node.depth == 0 {
		// The root row is the only one carrying an unattributed remainder,
		// so it is the only one whose evidence owes the denominator.
		if err := readInto(procStat); err != nil {
			fmt.Fprintln(stderr, "workloads:", err)
			return exitRuntime
		}
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
