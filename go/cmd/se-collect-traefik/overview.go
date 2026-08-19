package main

import "errors"

// The one row this collection publishes, under the name the reference gives it
// — `overview:traefik`, so the collator's id is <prefix>:<name> and a port that
// moved either half would publish a second object for one proxy.
const overviewName = "traefik"

// Literal fact names per family member — a table, not string surgery, so every
// name this collector can emit is greppable in the source and the declaration
// can be checked against it. adapters/traefik.py _FAMILY_COUNTS, in its order.
//
// tcp and udp are deliberately absent: the reference reads the `http` block
// alone, because the routers and services collections beside this one are HTTP
// too and a total that counted three protocols would not add up to the rows a
// reader can see.
var overviewCounts = [...]struct{ family, member, fact string }{
	{"routers", "total", "RoutersTotal"},
	{"routers", "errors", "RoutersErrors"},
	{"routers", "warnings", "RoutersWarnings"},
	{"services", "total", "ServicesTotal"},
	{"services", "errors", "ServicesErrors"},
	{"services", "warnings", "ServicesWarnings"},
	{"middlewares", "total", "MiddlewaresTotal"},
	{"middlewares", "errors", "MiddlewaresErrors"},
	{"middlewares", "warnings", "MiddlewaresWarnings"},
}

// overviewRows is adapters/traefik.py `_overview_items()`: one row, built from
// three documents. They are acquired together because they describe one proxy
// and are published as one object — a version without its counts is half an
// answer, and the reference issues all three requests before it builds
// anything.
func overviewRows(src source) ([]row, error) {
	overview, err := src.document(pathOverview)
	if err != nil {
		return nil, err
	}
	version, err := src.document(pathVersion)
	if err != nil {
		return nil, err
	}
	entrypoints, err := src.list(pathEntrypoints)
	if err != nil {
		return nil, err
	}
	facts, err := overviewFacts(overview, version, entrypoints)
	if err != nil {
		return nil, err
	}
	return []row{{name: overviewName, facts: facts}}, nil
}

func overviewFacts(overview, version, entrypoints *value) (*value, error) {
	facts := newObject()
	// The reference's own construction order, so the two files read side by
	// side. `set` drops anything the document did not state, which is what
	// keeps a null off the row (DESIGN 19).
	facts.set("Version", whenTruthy(version.get("Version")))
	for _, count := range overviewCounts {
		// The count is passed through as the token the document spelled — a
		// figure re-rendered through a float64 would answer `0.0` where Traefik
		// said `0`, and the judge's typed equality sees the difference.
		facts.set(count.fact, overview.get("http").get(count.family).get(count.member))
	}
	facts.set("Providers", whenTruthy(overview.get("providers")))

	if entrypoints.kind != jsonArray {
		// `_get_list` returns what the endpoint answered, and this endpoint
		// answers a list. Anything else is a broken capture or an interface
		// this collector has never met, and neither is a statement about a
		// machine — so it is "I could not run".
		return nil, errors.New("the entrypoints payload is not a list of entrypoints")
	}
	names := []*value{}
	for _, entry := range entrypoints.items {
		// isinstance(entry, dict) in the reference: an entry that is not an
		// object names no entrypoint, and skipping it is what the reference
		// does rather than failing the row.
		if !entry.isObject() {
			continue
		}
		if name := entry.get("name"); name.truthy() {
			names = append(names, name)
		}
	}
	if len(names) > 0 {
		facts.set("EntryPoints", newArray(names))
	}
	return facts, nil
}

// whenTruthy is the `if x:` gate the reference puts on a member it then
// publishes verbatim — Version, Providers, Middlewares, UsedBy. It returns the
// value when Python would have taken it and nil when Python would have skipped
// it, so the truthiness test and the pass-through live in one place instead of
// being spelled at each site.
func whenTruthy(v *value) *value {
	if !v.truthy() {
		return nil
	}
	return v
}
