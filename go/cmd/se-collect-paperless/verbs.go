package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// paperless has no density behind its one row: the pair of API reads carries
// every declared fact, so an object response is the row the collection
// publishes, addressed by name. The EVIDENCE payload is the two documents in
// the reference's shape (adapters/paperless.py get_evidence): statistics
// whole, and status with userinfo and query strings stripped from its two
// connection URLs — the paths the declaration's `redactions` member states,
// once, statically, rather than a list restated on every response. A status
// half that could not be read rides as status_error, the same constant text
// the row's StatusUnobservable fact carries: absent and unreadable must not
// render the same.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	row, err := instanceRow(got)
	if err != nil {
		fmt.Fprintln(stderr, "instance:", err)
		return exitRuntime
	}
	out.emit(objectRecord{
		Record:     "object",
		Type:       "paperless-instance",
		Collection: collection,
		Name:       instanceName,
		Facts:      row.encode(),
		At:         src.stamp(0),
	})
	out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
	return verbExit(out, stderr)
}

// The two credential positions the declaration's redactions name, the same
// two text.scrub() strips from failure text: userinfo, and the query string.
var credentialURLs = [...][2]string{
	{"database", "url"},
	{"tasks", "redis_url"},
}

// redactCredentialURLs is the reference's _redact_url_credentials: strip
// userinfo AND query from the status document's connection URLs, keeping
// scheme and host — the diagnostically useful halves. A value that needs no
// change keeps its exact original bytes; only an altered URL is respelled.
func redactCredentialURLs(status jsonValue) jsonValue {
	for _, position := range credentialURLs {
		section, member := position[0], position[1]
		holder := status.get(section)
		if !holder.isObject() {
			continue
		}
		value, held := holder.member(member)
		if !held || value.kind != jsonString {
			continue
		}
		if redacted, changed := redactOneURL(value.text); changed {
			holder.set(member, jsonValue{kind: jsonString, text: redacted})
			status.set(section, holder)
		}
	}
	return status
}

// redactOneURL is string surgery, not url.Parse round-tripping: Go's
// URL re-assembly percent-encodes the marker («redacted» became
// %C2%ABredacted%C2%BB), where the reference joins plain strings — and an
// unchanged URL must keep its exact original bytes either way.
func redactOneURL(raw string) (string, bool) {
	rest, changed := raw, false
	prefix := ""
	if cut := strings.Index(rest, "://"); cut >= 0 {
		prefix, rest = rest[:cut+3], rest[cut+3:]
	}
	end := len(rest)
	for _, stop := range []string{"/", "?", "#"} {
		if cut := strings.Index(rest, stop); cut >= 0 && cut < end {
			end = cut
		}
	}
	if at := strings.LastIndex(rest[:end], "@"); at >= 0 {
		rest = "«redacted»" + rest[at:]
		changed = true
	}
	if q := strings.Index(rest, "?"); q >= 0 {
		tail := ""
		if hash := strings.Index(rest[q:], "#"); hash >= 0 {
			tail = rest[q+hash:]
		}
		rest = rest[:q] + "?query-stripped" + tail
		changed = true
	}
	if !changed {
		return raw, false
	}
	return prefix + rest, true
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
	payload := map[string]json.RawMessage{
		"statistics": got.statistics.appendJSON(nil),
	}
	if got.statusRead {
		payload["status"] = redactCredentialURLs(got.status).appendJSON(nil)
	} else {
		encoded, _ := json.Marshal(got.unobservable)
		payload["status_error"] = encoded
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
