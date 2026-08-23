package main

// The object and evidence verbs (DESIGN 18) — the last of the fleet rollout
// R3c opened (register rows 1–2); this collector was the phase-3 skeleton
// whose queue entry promised them.
//
// The four collections are singletons named by the machine's hostname, and
// their collect functions emit whole responses — so the object verb answers
// by RUNNING the same function into a capture and re-serving its object,
// unobservable and decline records byte-for-byte: one derivation, no second
// spelling of it. The EVIDENCE payloads follow the reference
// (adapters/system.py get_evidence) where the seam reads the same
// interface: overview serves the raw /proc files by path; time serves
// timedate1's GetAll with timesync1's beside it when that daemon answers;
// boot serves the systemd manager's GetAll with the value half of every
// Environment assignment withheld — the manager-wide block passed to every
// executed process, found served verbatim once. One stated deviation:
// identity's evidence is os-release and the kernel hostname, because THIS
// port's identity rows are folded from those, where the reference's rest on
// hostname1's bus answer — evidence must show the documents the rows came
// from, and this collector never acquires hostname1.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// captureCollection runs the SAME function that emits the collection, into
// a buffer, and answers for one name: the object, unobservable and decline
// records to re-serve byte-for-byte (a commit is a collection-stream
// statement and is not), and whether the name matched at all.
func captureCollection(stderr io.Writer, src source, collection, name string) (kept []string, matched bool, code int) {
	serve := served[collection]
	var capture bytes.Buffer
	captured := newEmitter(&capture)
	objects := 0
	if code := serve(captured, stderr, src, collection, 0, &objects); code != exitOK {
		return nil, false, code
	}
	if captured.err != nil {
		fmt.Fprintln(stderr, "capturing the collection:", captured.err)
		return nil, false, exitRuntime
	}
	for _, line := range strings.Split(strings.TrimSpace(capture.String()), "\n") {
		if line == "" {
			continue
		}
		var envelope struct {
			Record string `json:"record"`
			Name   string `json:"name"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			fmt.Fprintln(stderr, "capturing the collection:", err)
			return nil, false, exitRuntime
		}
		switch envelope.Record {
		case "decline":
			// The collection's decline IS the verb's answer.
			return []string{line}, true, exitOK
		case "object":
			if envelope.Name == name {
				kept = append(kept, line)
				matched = true
			}
		case "unobservable":
			if envelope.Name == name {
				kept = append(kept, line)
			}
		}
	}
	return kept, matched, exitOK
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, known := served[collection]; !known {
		return verbDecline(out, stderr, "object", collection, "unsupported",
			"this collector does not serve this collection")
	}
	kept, matched, code := captureCollection(stderr, src, collection, name)
	if code != exitOK {
		return code
	}
	if !matched {
		return verbDecline(out, stderr, "object", collection, "unavailable", noSuchObject)
	}
	for _, line := range kept {
		if _, err := stdout.Write(append([]byte(line), '\n')); err != nil {
			fmt.Fprintln(stderr, "writing the response:", err)
			return exitRuntime
		}
	}
	out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
	return verbExit(out, stderr)
}

// ── evidence ────────────────────────────────────────────────────────────

// redactEnvironment withholds the value half of every NAME=VALUE entry in
// the manager's Environment property — envelope.redact_assignments, applied
// inside the busctl document so the served bytes carry the withholding.
func redactEnvironment(raw []byte) ([]byte, error) {
	var document busDocument
	if err := json.Unmarshal(raw, &document); err != nil || document.Type != sigProperties || len(document.Data) != 1 {
		// Not a GetAll answer this collector understands: served as it is,
		// because rewriting a document nobody parsed is how a redaction
		// silently becomes a corruption.
		return raw, nil
	}
	var props map[string]variant
	if err := json.Unmarshal(document.Data[0], &props); err != nil {
		return raw, nil
	}
	environment, held := props["Environment"]
	if !held {
		return raw, nil
	}
	var entries []string
	if err := json.Unmarshal(environment.Data, &entries); err != nil {
		return raw, nil
	}
	changed := false
	for i, entry := range entries {
		if cut := strings.IndexByte(entry, '='); cut >= 0 {
			entries[i] = entry[:cut] + "=«redacted»"
			changed = true
		}
	}
	if !changed {
		return raw, nil
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	props["Environment"] = variant{Type: environment.Type, Data: encoded}
	rebuilt, err := json.Marshal(props)
	if err != nil {
		return nil, err
	}
	document.Data[0] = rebuilt
	return json.Marshal(document)
}

// evidenceCanonical is the payload bytes for one object. Membership is the
// caller's: serveEvidence checks the name against the collection's own
// records via captureCollection, because the four collections name their
// singletons three different ways — the hostname, the literal "host", and
// the boot id — and a second spelling of those rules here would drift.
func evidenceCanonical(stderr io.Writer, src source, collection, name string) ([]byte, bool, error) {
	host, err := src.hostname()
	if err != nil {
		return nil, false, err
	}
	payload := map[string]json.RawMessage{}
	rawString := func(s string) json.RawMessage {
		encoded, _ := json.Marshal(s)
		return encoded
	}
	switch collection {
	case "overview":
		// The raw file contents, captured fresh; absent files (no PSI, no
		// ZFS) are absent from the payload too.
		for slug, path := range procPaths {
			if content := src.proc(slug); content != "" {
				payload[path] = rawString(content)
			}
		}
	case "identity":
		raw, err := src.osRelease()
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, &declinedEvidence{"absent", "no os-release on this host"}
		}
		if err != nil {
			return nil, false, err
		}
		payload["/etc/os-release"] = rawString(string(raw))
		payload["hostname"] = rawString(host)
	case "time":
		raw, err := src.timedate1()
		if err != nil {
			return nil, false, err
		}
		if !json.Valid(raw) {
			return nil, false, errors.New("timedate1 answered something that is not a document")
		}
		payload["org.freedesktop.timedate1"] = json.RawMessage(raw)
		// timesync1 rides beside it when that daemon answers; a host
		// without it serves the timedate half alone, as the reference does.
		if sync, err := src.timesync1(); err == nil && json.Valid(sync) {
			payload["org.freedesktop.timesync1.Manager"] = json.RawMessage(sync)
		}
	case "boot":
		raw, err := src.systemd1()
		if errors.Is(err, errNoSystemd) {
			return nil, false, &declinedEvidence{"absent", "no systemd on the system bus on this host"}
		}
		if err != nil {
			return nil, false, err
		}
		redacted, err := redactEnvironment(raw)
		if err != nil {
			return nil, false, err
		}
		payload["org.freedesktop.systemd1.Manager"] = json.RawMessage(redacted)
	}
	canonical, err := json.Marshal(payload)
	return canonical, true, err
}

// declinedEvidence carries a decline shape out of the evidence assembly.
type declinedEvidence struct{ reason, detail string }

func (d *declinedEvidence) Error() string { return d.reason + ": " + d.detail }

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, known := served[collection]; !known {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector does not serve this collection")
	}
	_, matched, code := captureCollection(stderr, src, collection, name)
	if code != exitOK {
		return code
	}
	if !matched {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", noSuchObject)
	}
	canonical, _, err := evidenceCanonical(stderr, src, collection, name)
	var refused *declinedEvidence
	if errors.As(err, &refused) {
		return verbDecline(out, stderr, "evidence", collection,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
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
