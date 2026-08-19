package main

import (
	"errors"
	"fmt"
)

// The name a route with none is published under, which is the reference's own
// fallback. It exists because the row's name is the collator's key and a blank
// one would key every nameless route onto the same object.
const unnamed = "unnamed"

// routerRows is adapters/traefik.py `_router_items()`: one row per entry of
// /api/http/routers, in the order Traefik listed them. Traefik sorts its own
// listing by name, so nothing sorts it here — the answer's order is the API's.
func routerRows(src source) ([]row, error) {
	document, err := src.list(pathRouters)
	if err != nil {
		return nil, err
	}
	if document.kind != jsonArray {
		return nil, errors.New("the routers payload is not a list of routers")
	}
	rows := make([]row, 0, len(document.items))
	for i, raw := range document.items {
		name, err := routeName(raw)
		if err != nil {
			return nil, fmt.Errorf("router %d: %v", i, err)
		}
		facts, err := routerFacts(raw)
		if err != nil {
			return nil, fmt.Errorf("router %s: %v", name, err)
		}
		rows = append(rows, row{name: name, facts: facts})
	}
	return rows, nil
}

func routerFacts(raw *value) (*value, error) {
	facts := newObject()
	// Rule, Service, Provider and Status are the reference's four unconditional
	// members, and this is the one place the port does NOT reproduce it: the
	// reference writes `raw.get(…)` straight into the facts dict, so a router
	// document missing any of them publishes a null fact value — which
	// se.stream.1.json refuses at any depth and the replay judge refuses with
	// it. `set` omits instead, which is the lawful reading of the same
	// statement (DESIGN 19: value, absent and unobservable are three channels
	// and a null names none of them). No committed capture and no mutation
	// operator reaches the shape, and it is reported as a reference defect
	// rather than fixed here.
	facts.set("Rule", raw.get("rule"))
	facts.set("Service", raw.get("service"))
	// `or []`, not `set`: a router with no entrypoints listed is a router
	// mounted on nothing, and the empty list is the reference's statement of
	// that — distinct from a member it never carried.
	entryPoints := raw.get("entryPoints")
	if !entryPoints.truthy() {
		entryPoints = newArray(nil)
	}
	facts.set("EntryPoints", entryPoints)
	facts.set("Provider", raw.get("provider"))
	facts.set("Status", raw.get("status"))
	// `is not None`, so a priority of 0 is published: zero is the bottom of the
	// evaluation order, not an absence of one. Passed through as its token —
	// Traefik gives its own API router a priority two below 2^63, and a float64
	// round trip returns that as 2^63 exactly.
	facts.set("Priority", raw.get("priority"))
	facts.set("Middlewares", whenTruthy(raw.get("middlewares")))
	if tls := raw.get("tls"); tls.isObject() {
		// The presence of the block IS the fact: Traefik writes `tls: {}` for a
		// router that terminates TLS with every option defaulted, so the row
		// says true rather than repeating the options.
		facts.set("Tls", boolValue(true))
		facts.set("CertResolver", whenTruthy(tls.get("certResolver")))
	}
	failure, err := errorFact(raw.get("error"))
	if err != nil {
		return nil, err
	}
	facts.set("Error", failure)
	return facts, nil
}

// routeName is `raw.get("name") or "unnamed"` for a router or a service. The
// name travels as the object record's own `name` member, so it must be a
// string: the reference would publish whatever the document held there and the
// contract would refuse the record, which is a refusal to run rather than a
// row to build.
func routeName(raw *value) (string, error) {
	name := raw.get("name")
	if !name.truthy() {
		return unnamed, nil
	}
	if !name.isString() {
		return "", errors.New("the document names it with something that is not a string, and a row's name is what the collator keys on")
	}
	return name.text, nil
}

// errorFact is `error if isinstance(error, list) else [str(error)]`, bounded to
// the two spellings the interface produces. Traefik's own type is a list of
// strings and that is what every version of the API emits; a bare string is
// accepted because the reference's `str()` arm exists for it and costs nothing.
// Anything else — a number, an object — would take `str()` through Python's own
// repr, which is not a rendering this side can reproduce, so it is refused
// rather than guessed at. No document Traefik produces reaches it.
func errorFact(raw *value) (*value, error) {
	if !raw.truthy() {
		return nil, nil
	}
	switch raw.kind {
	case jsonArray:
		return raw, nil
	case jsonString:
		return newArray([]*value{raw}), nil
	default:
		return nil, fmt.Errorf("the error member is neither a list nor a string, and rendering one is Python's repr rather than a reading")
	}
}
