package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The one server state Traefik calls healthy. Everything else counts as down
// for the fold, and the map is carried verbatim in DownServers for the ones
// that are not — adapters/traefik.py _UP.
const serverUp = "UP"

// The marker the reference leaves where userinfo was, so a withholding is
// visible rather than silent — system_explorer.agent.envelope.REDACTED. It is
// spelled here as the same bytes because it travels on the wire: a port with
// its own spelling would disagree with the reference on the one value whose
// whole job is to be recognisable.
const redactedMarker = "«redacted»"

// serviceRows is adapters/traefik.py `_service_items()`: one row per entry of
// /api/http/services, in the order Traefik listed them.
func serviceRows(src source) ([]row, error) {
	document, err := src.list(pathServices)
	if err != nil {
		return nil, err
	}
	if document.kind != jsonArray {
		return nil, errors.New("the services payload is not a list of services")
	}
	rows := make([]row, 0, len(document.items))
	for i, raw := range document.items {
		name, err := routeName(raw)
		if err != nil {
			return nil, fmt.Errorf("service %d: %v", i, err)
		}
		facts, err := serviceFacts(raw)
		if err != nil {
			return nil, fmt.Errorf("service %s: %v", name, err)
		}
		rows = append(rows, row{name: name, facts: facts})
	}
	return rows, nil
}

func serviceFacts(raw *value) (*value, error) {
	facts := newObject()
	// A member the document does not carry is left OFF the row rather than
	// nulled (DESIGN 19), and this is the collection that proved it: Traefik's
	// own internal services — api@internal, dashboard@internal, noop@internal,
	// present on every Traefik that has ever run — carry no `type` member at
	// all, so a port that nulled it would publish "Type": null for three of
	// three services on a stock install. `set` cannot write one.
	facts.set("Type", raw.get("type"))
	facts.set("Provider", raw.get("provider"))
	facts.set("Status", raw.get("status"))
	facts.set("UsedBy", whenTruthy(raw.get("usedBy")))

	if balancer := raw.get("loadBalancer"); balancer.isObject() {
		servers, err := serverURLs(balancer.get("servers"))
		if err != nil {
			return nil, err
		}
		facts.set("Servers", servers)
	}
	if status := raw.get("serverStatus"); status.isObject() && len(status.members.keys) > 0 {
		// The fold that turns a health map into a row: a green router over
		// ServersUp 0 is a front door onto nothing, and this is where that
		// shows. Anything that is not UP counts as down — Traefik reports UP
		// and DOWN, and a third word this collector has never met must not be
		// counted as healthy by default.
		down := []string{}
		for _, url := range status.members.keys {
			if state := status.members.byKey[url]; state.isString() && state.text == serverUp {
				continue
			}
			down = append(down, redactURLUserinfo(stringValue(url)).text)
		}
		sort.Strings(down)
		facts.set("ServersUp", countValue(len(status.members.keys)-len(down)))
		facts.set("ServersDown", countValue(len(down)))
		if len(down) > 0 {
			items := make([]*value, 0, len(down))
			for _, url := range down {
				items = append(items, stringValue(url))
			}
			facts.set("DownServers", newArray(items))
		}
	}
	failure, err := errorFact(raw.get("error"))
	if err != nil {
		return nil, err
	}
	facts.set("Error", failure)
	return facts, nil
}

// serverURLs is the balanced backends, or nothing at all. `url` first and
// `address` second is the reference's own fallback: an HTTP service's servers
// carry a url and a TCP service's carry an address, and this collection serves
// the first.
func serverURLs(servers *value) (*value, error) {
	if !servers.truthy() {
		return nil, nil
	}
	if servers.kind != jsonArray {
		return nil, errors.New("the load balancer's servers member is not a list")
	}
	items := make([]*value, 0, len(servers.items))
	for i, server := range servers.items {
		address := server.get("url")
		if !address.truthy() {
			address = server.get("address")
		}
		if !address.truthy() {
			// The reference would put a null inside the Servers list here, one
			// level below where a top-level sweep looks, and the judge refuses
			// a null fact at any depth. No provider writes a server with
			// neither member, so this is "I could not run" rather than a row
			// with a hole in it.
			return nil, fmt.Errorf("server %d carries neither a url nor an address", i)
		}
		items = append(items, redactURLUserinfo(address))
	}
	return newArray(items), nil
}

// redactURLUserinfo strips DSN userinfo from a backend URL, keeping the marker
// so the withholding is visible. The docker provider never writes one, but a
// file-provider server URL can carry basic-auth — and Servers, DownServers and
// the evidence payload all reach unauthenticated pollers.
//
// The rewrite is textual and touches only the netloc, which is exactly what
// urlsplit/urlunsplit do to every URL a Traefik provider produces: the rest of
// the string is carried through byte for byte rather than re-rendered. Two
// shapes round-trip differently and neither is one a provider writes — a scheme
// in uppercase, which Python lowercases on the way through, and a URL carrying
// whitespace or control characters, which Python strips.
func redactURLUserinfo(v *value) *value {
	if !v.isString() || !strings.Contains(v.text, "@") {
		return v
	}
	start, end, ok := netloc(v.text)
	if !ok {
		return v
	}
	at := strings.LastIndex(v.text[start:end], "@")
	if at < 0 {
		return v
	}
	host := v.text[start+at+1 : end]
	return stringValue(v.text[:start] + redactedMarker + "@" + host + v.text[end:])
}

// netloc is urlsplit's netloc, as an index range into the original string: the
// authority after `//`, ending at the first '/', '?' or '#'. The optional
// scheme in front is recognised the way urlsplit recognises one, so a path
// segment that merely contains "://" is not mistaken for an authority.
func netloc(url string) (start, end int, ok bool) {
	offset := 0
	if colon := strings.IndexByte(url, ':'); colon > 0 && isScheme(url[:colon]) {
		offset = colon + 1
	}
	if !strings.HasPrefix(url[offset:], "//") {
		return 0, 0, false
	}
	start = offset + 2
	length := strings.IndexAny(url[start:], "/?#")
	if length < 0 {
		return start, len(url), true
	}
	return start, start + length, true
}

// isScheme is RFC 3986's scheme production, which is what urlsplit accepts
// before the colon: a letter followed by letters, digits, '+', '-' or '.'.
func isScheme(text string) bool {
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return len(text) > 0
}
