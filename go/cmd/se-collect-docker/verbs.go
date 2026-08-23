package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// docker has no density behind its rows, so an object response is the row
// the collection publishes, addressed by name — built by the SAME row
// builders collect uses. The EVIDENCE payload is the reference's
// (adapters/docker.py get_evidence): the per-object inspect document, with
// the value half of every NAME=VALUE entry under Env, Cmd and Entrypoint
// withheld wherever those keys appear — lists descended too, because the
// reference's walk once returned on anything that was not a dict and the
// docstring promised otherwise.
//
// One rule the reference does not need: the requested name is checked
// against the collection's OWN listing before any per-object path is built,
// because a collector treats every token as data — never as a path fragment
// — and the listing is the authority for what this collector published.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
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

// verbRows is the shared acquisition gate: both verbs answer from the same
// listing collect reads, and both route the seam's decline the same way.
func verbRows(out *emitter, stderr io.Writer, src source, verb, collection string) ([]row, bool, int) {
	spec := served[collection]
	document, err := src.document(spec.path)
	var refused *declined
	if errors.As(err, &refused) {
		return nil, false, verbDecline(out, stderr, verb, collection,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
		return nil, false, exitRuntime
	}
	built, err := spec.rows(document)
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
		return nil, false, exitRuntime
	}
	return built, true, exitOK
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, serves := served[collection]; !serves {
		return verbDecline(out, stderr, "object", collection, "unsupported",
			"this collector serves containers, volumes and networks only")
	}
	built, ok, code := verbRows(out, stderr, src, "object", collection)
	if !ok {
		return code
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

// secretListKeys is the reference's SECRET_LIST_KEYS: the inspect members
// whose list entries carry NAME=VALUE assignments.
var secretListKeys = map[string]bool{"Env": true, "Cmd": true, "Entrypoint": true}

// redactAssignments is envelope.redact_assignments: the value half of every
// NAME=VALUE entry withheld, the name kept — "is DATABASE_URL even set?" is
// a real question and the value is the credential. A token carrying no '='
// carries no value and stays legible.
func redactAssignments(list *value) bool {
	changed := false
	for i, item := range list.items {
		if !item.isString() {
			continue
		}
		name, separator := item.text, false
		if cut := strings.IndexByte(item.text, '='); cut >= 0 {
			name, separator = item.text[:cut], true
		}
		if separator {
			list.items[i] = stringValue(name + "=«redacted»")
			changed = true
		}
	}
	return changed
}

// redactInspect is the reference's _redact_env: every Env, Cmd and
// Entrypoint list anywhere in the document, dicts and lists descended alike,
// applied to a freshly fetched document nothing else holds.
func redactInspect(node *value) {
	if node == nil {
		return
	}
	switch node.kind {
	case jsonArray:
		for _, item := range node.items {
			redactInspect(item)
		}
	case jsonObject:
		for _, key := range node.members.keys {
			member := node.members.byKey[key]
			if secretListKeys[key] && member != nil && member.kind == jsonArray {
				redactAssignments(member)
				continue
			}
			redactInspect(member)
		}
	}
}

// inspectPath is the per-object Engine API path, built only AFTER the name
// was found in the collection's own listing.
func inspectPath(collection, name string) string {
	switch collection {
	case "containers":
		return "/containers/" + name + "/json"
	case "volumes":
		return "/volumes/" + name
	}
	return "/networks/" + name
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, serves := served[collection]; !serves {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector serves containers, volumes and networks only")
	}
	built, ok, code := verbRows(out, stderr, src, "evidence", collection)
	if !ok {
		return code
	}
	published := false
	for _, one := range built {
		if one.name == name {
			published = true
			break
		}
	}
	if !published {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", noSuchObject)
	}
	document, err := src.document(inspectPath(collection, name))
	var refused *declined
	if errors.As(err, &refused) {
		return verbDecline(out, stderr, "evidence", collection,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
		return exitRuntime
	}
	redactInspect(document)
	canonical := []byte(document.encode())
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
