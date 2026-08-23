package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// plex has no density behind its rows, so an object response is the row the
// collection publishes, addressed by name — built by the SAME row builders
// collect uses. The EVIDENCE payloads are the reference's (adapters/plex.py
// get_evidence), fetched once with membership checked in that same document
// — the traefik/downloaders shape — because an acquire-then-refetch pair
// lets a session end between the two calls and ships 200 evidence that
// cannot show its object. The server's evidence is its root document;
// libraries and sessions serve the listing whole; a request serves its page
// walk — one page as itself, several under a `pages` member.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
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

// plexBody is one Plex document for evidence: the deployment gate, the
// fetch, and the server-silent decline, routed exactly as the row builders
// route them.
func plexBody(src source, path string) (*value, error) {
	deploy, err := gate(src)
	if err != nil {
		return nil, err
	}
	if len(deploy.missing) > 0 {
		reason := declineNoReceipts
		return nil, &reason
	}
	reply, err := src.document(path)
	if err != nil {
		return nil, err
	}
	if reply.detail != "" {
		reason := declineServerSilent
		return nil, &reason
	}
	return reply.doc, nil
}

// evidenceCanonical is the payload bytes for one object, and whether the
// name is among what the same document publishes.
func evidenceCanonical(src source, collection, name string) ([]byte, bool, error) {
	switch collection {
	case "server":
		body, err := plexBody(src, pathRoot)
		if err != nil {
			return nil, false, err
		}
		if name != serverName {
			return nil, false, nil
		}
		return []byte(body.encode()), true, nil
	case "libraries":
		body, err := plexBody(src, pathSections)
		if err != nil {
			return nil, false, err
		}
		for _, raw := range body.get("MediaContainer").get("Directory").elements() {
			if raw.get("key").stated() && pythonStr(raw.get("key")) == name {
				return []byte(body.encode()), true, nil
			}
		}
		return nil, false, nil
	case "sessions":
		body, err := plexBody(src, pathSessions)
		if err != nil {
			return nil, false, err
		}
		for _, raw := range body.get("MediaContainer").get("Metadata").elements() {
			key := raw.get("sessionKey")
			if !key.truthy() {
				key = raw.get("ratingKey")
			}
			if key.truthy() && pythonStr(key) == name {
				return []byte(body.encode()), true, nil
			}
		}
		return nil, false, nil
	case "requests":
		hasURL, hasKey := src.seerrConfigured()
		if !hasURL {
			refused := declineNoSeerr
			return nil, false, &refused
		}
		if !hasKey {
			refused := declineNoSeerrKey
			return nil, false, &refused
		}
		// The same page walk requestRows makes, kept whole: the pages ARE
		// the evidence, and the membership is checked in them.
		var pages []*value
		known := false
		skip := 0
		for page := 0; page < maxRequestPages; page++ {
			reply, err := src.seerr(requestsPath, fmt.Sprintf(
				"take=%d&skip=%d&sort=added", requestPageSize, skip))
			if err != nil {
				return nil, false, err
			}
			if reply.detail != "" {
				return nil, false, &declined{reason: "unavailable", detail: reply.detail}
			}
			results := reply.doc.get("results").elements()
			if len(results) == 0 {
				break
			}
			pages = append(pages, reply.doc)
			for _, raw := range results {
				if raw.get("id").stated() && pythonStr(raw.get("id")) == name {
					known = true
				}
			}
			skip += len(results)
			declared := reply.doc.get("pageInfo").get("results")
			if declared.isInteger() {
				if total, err := strconv.Atoi(declared.text); err == nil && skip >= total {
					break
				}
			}
		}
		if !known {
			return nil, false, nil
		}
		if len(pages) == 1 {
			return []byte(pages[0].encode()), true, nil
		}
		wrapper := newObject()
		list := &value{kind: jsonArray}
		list.items = append(list.items, pages...)
		wrapper.set("pages", list)
		return []byte(wrapper.encode()), true, nil
	}
	return nil, false, nil
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, serves := served[collection]; !serves {
		return verbDecline(out, stderr, "evidence", collection, "unsupported", servedNames)
	}
	canonical, found, err := evidenceCanonical(src, collection, name)
	var refused *declined
	if errors.As(err, &refused) {
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
