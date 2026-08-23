package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// traefik has no density behind its rows: the documents the collect walk
// reads carry every declared fact, so an object response is the row the
// collection publishes, addressed by name. The EVIDENCE payload follows the
// reference (adapters/traefik.py get_evidence): overview serves its three
// documents; a router serves its own list entry verbatim; a service serves
// its entry with backend-URL userinfo stripped (loadBalancer.servers[]
// url/address, serverStatus keys) — the docker provider never writes one,
// but a file-provider URL can carry basic-auth, and evidence reaches
// unauthenticated pollers. Membership comes from the same list the payload
// is cut from, fetched once, so a churn between two fetches cannot ship
// evidence that denies its object.

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

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	build, serves := served[collection]
	if !serves {
		return verbDecline(out, stderr, "object", collection, "unsupported", servedNames)
	}
	src.mark()
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
	return verbDecline(out, stderr, "object", collection, "unavailable",
		"this collector publishes no object of that name in this collection")
}

// ── evidence ────────────────────────────────────────────────────────────

// redactServiceEvidence is the reference's _redact_service_evidence, applied
// to a freshly fetched document nothing else holds: backend-URL userinfo
// stripped wherever the document carries one, through the SAME
// redactURLUserinfo the Servers and DownServers facts pass through
// (services.go) — one rule, not a second spelling of it.
func redactServiceEvidence(service *value) {
	if balancer := service.get("loadBalancer"); balancer.isObject() {
		if servers := balancer.get("servers"); servers != nil && servers.kind == jsonArray {
			for _, server := range servers.items {
				if !server.isObject() {
					continue
				}
				for _, member := range []string{"url", "address"} {
					// Only an existing string member is rewritten: set()
					// on a member the document never carried would ADD a
					// null the daemon did not write.
					if v := server.get(member); v.isString() {
						server.set(member, redactURLUserinfo(v))
					}
				}
			}
		}
	}
	if status := service.get("serverStatus"); status.isObject() {
		rewritten := newMembers()
		for _, key := range status.members.keys {
			redacted := redactURLUserinfo(stringValue(key))
			rewritten.set(redacted.text, status.members.byKey[key])
		}
		status.members = rewritten
	}
}

// evidenceCanonical is the payload bytes for one object, and whether the
// name is among the rows the same documents publish.
func evidenceCanonical(src source, collection, name string) ([]byte, bool, error) {
	switch collection {
	case "overview":
		overview, err := src.document(pathOverview)
		if err != nil {
			return nil, false, err
		}
		version, err := src.document(pathVersion)
		if err != nil {
			return nil, false, err
		}
		entrypoints, err := src.list(pathEntrypoints)
		if err != nil {
			return nil, false, err
		}
		if name != overviewName {
			return nil, false, nil
		}
		// The top level is assembled here (Go marshals map keys sorted,
		// which is the canon the digest names); each document inside keeps
		// the API's own member order and number spellings.
		canonical, err := json.Marshal(map[string]json.RawMessage{
			"overview":    overview.encode(),
			"version":     version.encode(),
			"entrypoints": entrypoints.encode(),
		})
		return canonical, true, err
	case "routers", "services":
		path := pathRouters
		if collection == "services" {
			path = pathServices
		}
		document, err := src.list(path)
		if err != nil {
			return nil, false, err
		}
		if document.kind != jsonArray {
			return nil, false, errors.New("the " + collection + " payload is not a list")
		}
		for _, raw := range document.items {
			entryName, err := routeName(raw)
			if err != nil || entryName != name {
				continue
			}
			if collection == "services" {
				redactServiceEvidence(raw)
			}
			return raw.encode(), true, nil
		}
		return nil, false, nil
	}
	return nil, false, nil
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, serves := served[collection]; !serves {
		return verbDecline(out, stderr, "evidence", collection, "unsupported", servedNames)
	}
	src.mark()
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
		return verbDecline(out, stderr, "evidence", collection, "unavailable",
			"this collector publishes no object of that name in this collection")
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
