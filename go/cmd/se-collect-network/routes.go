package main

// The routes collection (register row 9, R3b): every route the kernel
// holds, in every table — ported from the reference with the lesson that
// made it what it is. `ip route show` defaults to main, and for a year
// that was all the shipping product reported: a host on a tailnet gets
// policy table 52 consulted at preference 5270 while main waits until
// 32766, so a route for the segment under the host's own feet silently
// outranks its connected route, ARP keeps answering, and the host looks
// half-alive. It took a site LAN down twice before anything could see it.
//
// So three documents are one reading: both families' full dumps, and the
// rule table that decides which route actually wins. ShadowsLocalPrefix is
// an exact structural comparison, not a judgement — this route is in a
// table consulted before main, and main holds a kernel-scope link route
// for the same destination — and the rule that fires on it is data in the
// declaration, warn and never critical, because on a deliberate split
// tunnel this shape is exactly what was intended.

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// familyOf reads the address family off the destination itself, so the
// label cannot contradict the address printed beside it — the reference's
// fix for rows stamped with whichever subprocess they arrived in.
// "" where the destination names no address (`default`).
func familyOf(destination string) string {
	host := destination
	if i := strings.IndexByte(destination, '/'); i >= 0 {
		host = destination[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

const mainTablePref = 32766

// tableText renders a table member however iproute2 spelled it: named
// tables are strings ("main", "local"), numbered ones are numbers — and
// table 52 is the exact case this collection exists for, so a reader that
// only accepted strings would fold the tailnet table into main.
func tableText(v jsonValue) string {
	switch v.kind {
	case jsonString:
		return v.text
	case jsonNumber:
		return v.number
	}
	return ""
}

// rulePreferences is table name → the lowest (most preferred) rule
// preference selecting it: the kernel walks rules ascending and takes the
// first table that answers, so the smallest number decides.
func rulePreferences(doc jsonValue) map[string]int {
	prefs := map[string]int{}
	for _, rule := range doc.array {
		table := tableText(rule.get("table"))
		pref, hasPref := rule.member("priority")
		if table == "" || !hasPref || !pref.isInt() {
			continue
		}
		p, err := strconv.Atoi(pref.number)
		if err != nil {
			continue
		}
		if existing, seen := prefs[table]; !seen || p < existing {
			prefs[table] = p
		}
	}
	return prefs
}

func collectRoutes(out *emitter, src source, collection string, generation uint64, objects *int) (int, error) {
	docs := map[string]jsonValue{}
	for family, read := range map[string]func() (jsonValue, error){
		"ipv4": src.ipRoute4, "ipv6": src.ipRoute6} {
		doc, err := read()
		if err != nil {
			return 0, err
		}
		docs[family] = doc
	}
	ruleDoc, err := src.ipRule()
	if err != nil {
		// The reference tolerates a missing rule table (no `ip rule`
		// support) and serves routes without preferences; a replay gap
		// stays fatal upstream.
		ruleDoc = jsonValue{kind: jsonArray}
		if isReplayGap(err) {
			return 0, err
		}
	}
	rules := rulePreferences(ruleDoc)
	mainPref, hasMainPref := rules["main"]
	if !hasMainPref {
		mainPref = mainTablePref
	}

	// Which destinations this host is DIRECTLY attached to, per family: a
	// kernel-scope link route in main is the definition of "on this
	// segment".
	connected := map[string]map[string]bool{}
	for family, doc := range docs {
		connected[family] = map[string]bool{}
		for _, route := range doc.array {
			table := tableText(route.get("table"))
			if table == "" {
				table = "main"
			}
			if table == "main" && route.stringMember("scope") == "link" {
				if dst := route.stringMember("dst"); dst != "" {
					connected[family][dst] = true
				}
			}
		}
	}

	emitted := 0
	for _, family := range [...]string{"ipv4", "ipv6"} {
		for _, route := range docs[family].array {
			dst := route.stringMember("dst")
			if dst == "" {
				dst = "default"
			}
			dev := route.stringMember("dev")
			if dev == "" {
				dev = "?"
			}
			table := tableText(route.get("table"))
			if table == "" {
				table = "main"
			}
			native := dst + " dev " + dev
			if gateway := route.stringMember("gateway"); gateway != "" {
				native += " via " + gateway
			}
			if table != "main" {
				native += " table " + table
			}
			facts := map[string]any{
				"Destination": dst,
				"Device":      dev,
				"Table":       table,
			}
			for _, p := range [...]struct{ fact, member string }{
				{"Gateway", "gateway"}, {"Protocol", "protocol"},
				{"Scope", "scope"}, {"PrefSrc", "prefsrc"},
				{"Metric", "metric"},
			} {
				if value, ok := route.member(p.member); ok && !value.isNull() {
					facts[p.fact] = value
				}
			}
			if pref, ok := rules[table]; ok {
				facts["RulePreference"] = pref
			}
			if pref, ok := rules[table]; ok && table != "main" &&
				pref < mainPref && connected[family][dst] {
				facts["ShadowsLocalPrefix"] = true
			}
			// Derived from the ROW: `default` carries no address, so it
			// keeps the dump's family — the one case where the call is the
			// only evidence.
			shown := familyOf(dst)
			if shown == "" {
				shown = family
			}
			facts["Family"] = shown
			out.emit(objectRecord{
				Record:     "object",
				Collection: collection,
				Name:       native,
				Type:       "route",
				Facts:      facts,
				At:         src.stamp(*objects),
			})
			emitted++
			*objects++
		}
	}
	return emitted, nil
}

// isReplayGap reports an error that must stay fatal: a payload the variant
// never staged, which no live tolerance may absorb.
func isReplayGap(err error) bool {
	return errors.Is(err, errUncaptured)
}
