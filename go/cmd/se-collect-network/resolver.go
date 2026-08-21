package main

// The resolver collection (register row 9, R3b, the last-but-one): which
// mechanism answers this host's lookups, and where they actually go.
// Ported from the reference with its founding correction intact — a host
// that resolves names all day through a dhcpcd-written resolv.conf spent
// its life declined because ONE implementation was absent; the question is
// universal and only the answer is not. So two modes, detected in order:
// resolve1 on the bus, else the file glibc reads, else the collection is
// genuinely unobservable.
//
// The resolve1 mode walks: the Manager's GetAll (which doubles as the
// availability probe), then GetLink and the Link's GetAll per interface —
// because DHCP-provided DNS lives on links, and the manager-level current
// server beside the fallback list once convinced an operator a host's
// primary DNS was a public resolver while every real query went to the
// LAN. One derived fact, NoLinkTakesDNSDefaultRoute, exists so the
// fallback-carries-default judgement can be rule-table data: the closed
// condition vocabulary cannot iterate a map, so the iteration's answer is
// a fact both implementations emit — present only when DefaultRoute was
// observable on every link that has servers, because cannot-see is not
// "no".

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
)

func collectResolver(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	managerRaw, err := src.resolve1Call(resolve1ManagerRequest())
	var emitErr error
	switch {
	case err == nil:
		emitErr = emitResolve1(out, stderr, src, collection, generation, objects, managerRaw)
	case errors.Is(err, errUncaptured):
		fmt.Fprintln(stderr, err)
		return exitRuntime
	default:
		text, target, exists := src.resolvConf()
		if !exists {
			out.emit(declineRecord{Record: "decline", Collection: collection,
				Reason: "unavailable",
				Detail: "resolve1 is not on the system bus and there is no " +
					"resolv.conf to read instead — how this host resolves names " +
					"is unobservable, not absent"})
			return exitOK
		}
		emitErr = emitFileResolver(out, src, collection, generation, objects, text, target)
	}
	if emitErr != nil {
		// The hostname seam refusing (an unstaged capture) is the only
		// error either emitter returns: "I could not run", never a decline
		// about a machine nobody observed.
		fmt.Fprintln(stderr, "resolver:", emitErr)
		return exitRuntime
	}
	return exitOK
}

// ── the file shape: what glibc reads ────────────────────────────────────

func emitFileResolver(out *emitter, src source, collection string, generation uint64, objects *int, text, target string) error {
	facts := map[string]any{"ResolverService": "libc-resolv.conf"}
	nameservers, search, options := parseResolvConf(text)
	facts["Nameservers"] = nameservers
	facts["SearchDomains"] = search
	facts["Options"] = options
	if target != "" {
		facts["ResolvConfTarget"] = target
	}
	if err := emitResolverObject(out, src, collection, generation, objects, facts); err != nil {
		return err
	}
	return nil
}

// parseResolvConf follows resolv.conf(5) by the file's own grammar, glibc
// semantics kept where they surprise: later `search` (or the deprecated
// `domain`) REPLACES earlier ones, options accumulate, comments open with
// # or ;.
func parseResolvConf(text string) (nameservers, search, options []string) {
	nameservers, search, options = []string{}, []string{}, []string{}
	for _, raw := range strings.Split(text, "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			nameservers = append(nameservers, fields[1])
		case "search", "domain":
			search = fields[1:]
		case "options":
			options = append(options, fields[1:]...)
		}
	}
	return nameservers, search, options
}

// ── the resolve1 shape ──────────────────────────────────────────────────

// serverAddr reads the address out of a resolve1 server struct — Manager
// entries are (iiay), Link entries (iay) — as the last byte-array field,
// whatever the arity, exactly as the reference reads it.
func serverAddr(entry variant) string {
	if !strings.HasSuffix(entry.Type, "ay)") {
		return ""
	}
	var fields []json.RawMessage
	if json.Unmarshal(entry.Data, &fields) != nil {
		return ""
	}
	for i := len(fields) - 1; i >= 0; i-- {
		var bytes []byte
		if json.Unmarshal(fields[i], &bytes) != nil {
			continue
		}
		if len(bytes) == 4 || len(bytes) == 16 {
			return net.IP(bytes).String()
		}
	}
	return ""
}

// structArray reads an a(...) property into its per-entry variants, each
// re-wrapped with the element signature so serverAddr can judge it.
func structArray(props map[string]variant, name string) []variant {
	v, ok := props[name]
	if !ok || !strings.HasPrefix(v.Type, "a(") {
		return nil
	}
	var raw []json.RawMessage
	if json.Unmarshal(v.Data, &raw) != nil {
		return nil
	}
	element := v.Type[1:]
	out := make([]variant, 0, len(raw))
	for _, entry := range raw {
		out = append(out, variant{Type: element, Data: entry})
	}
	return out
}

// The loopback ifindex is 1 by kernel construction. Servers homed there
// are system-scope: loopback is not a network, so there is no per-link
// narrowing for them to mean — the measured systemd-261 behaviour that
// once made an ifindex-0 filter fire a false warn on a host running a
// deliberate local recursive resolver.
const loopbackIfindex = 1

func globalDNSServers(entries []variant) []string {
	out := []string{}
	for _, entry := range entries {
		var fields []json.RawMessage
		if json.Unmarshal(entry.Data, &fields) != nil || len(fields) != 3 {
			continue
		}
		var ifindex int
		if json.Unmarshal(fields[0], &ifindex) != nil {
			continue
		}
		if ifindex != 0 && ifindex != loopbackIfindex {
			continue
		}
		if addr := serverAddr(entry); addr != "" {
			out = append(out, addr)
		}
	}
	return out
}

func emitResolve1(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int, managerRaw []byte) error {
	props, err := propertiesOf(managerRaw)
	if err != nil {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unavailable",
			Detail: "resolve1 answered with a document this collector cannot read"})
		fmt.Fprintln(stderr, "resolve1:", err)
		return nil
	}
	facts := map[string]any{"ResolverService": "systemd-resolved"}

	servers := globalDNSServers(structArray(props, "DNS"))
	fallback := []string{}
	for _, entry := range structArray(props, "FallbackDNS") {
		if addr := serverAddr(entry); addr != "" {
			fallback = append(fallback, addr)
		}
	}
	domains := []string{}
	for _, entry := range structArray(props, "Domains") {
		var fields []json.RawMessage
		if json.Unmarshal(entry.Data, &fields) != nil || len(fields) < 3 {
			continue
		}
		var name string
		var routeOnly bool
		if json.Unmarshal(fields[1], &name) != nil || name == "" {
			continue
		}
		if json.Unmarshal(fields[2], &routeOnly) == nil && routeOnly {
			name += " (route-only)"
		}
		domains = append(domains, name)
	}

	perLink, defaultRouteKnown, anyDefaultRoute := linkDNS(src)

	inUse := map[string]bool{}
	for _, server := range servers {
		inUse[server] = true
	}
	for _, entry := range perLink {
		for _, server := range entry.servers {
			inUse[server] = true
		}
	}
	inUseSorted := make([]string, 0, len(inUse))
	for server := range inUse {
		inUseSorted = append(inUseSorted, server)
	}
	sort.Strings(inUseSorted)

	if current, ok := props["CurrentDNSServer"]; ok {
		if addr := serverAddr(current); addr != "" {
			facts["CurrentDNSServer"] = addr
		}
	}
	facts["DNSServersInUse"] = inUseSorted
	facts["GlobalDNSServers"] = servers
	perLinkFacts := map[string]map[string]any{}
	for name, entry := range perLink {
		linkFacts := map[string]any{"DNSServers": entry.servers}
		if entry.current != "" {
			linkFacts["CurrentDNSServer"] = entry.current
		}
		if len(entry.domains) > 0 {
			linkFacts["Domains"] = entry.domains
		}
		if entry.defaultRouteKnown {
			linkFacts["DefaultRoute"] = entry.defaultRoute
		}
		perLinkFacts[name] = linkFacts
	}
	facts["PerLinkDNS"] = perLinkFacts
	facts["FallbackDNSServers"] = fallback
	facts["SearchDomains"] = domains
	for _, p := range [...]struct{ fact, member string }{
		{"DNSSEC", "DNSSEC"}, {"DNSOverTLS", "DNSOverTLS"},
		{"LLMNR", "LLMNR"}, {"MulticastDNS", "MulticastDNS"},
		{"ResolvConfMode", "ResolvConfMode"},
	} {
		if s, ok := propString(props, p.member); ok {
			facts[p.fact] = s
		}
	}
	if len(perLink) > 0 && defaultRouteKnown {
		facts["NoLinkTakesDNSDefaultRoute"] = !anyDefaultRoute
	}
	return emitResolverObject(out, src, collection, generation, objects, facts)
}

type linkEntry struct {
	servers           []string
	current           string
	domains           []string
	defaultRoute      bool
	defaultRouteKnown bool
}

// linkDNS walks every non-loopback interface's resolve1 link, keeping only
// links that carry servers, exactly as the reference walks. A link that
// vanishes mid-walk — or a call the capture never staged for a link with
// no DNS — contributes nothing, which is the reference's own tolerance.
func linkDNS(src source) (map[string]linkEntry, bool, bool) {
	perLink := map[string]linkEntry{}
	defaultRouteKnown := true
	anyDefaultRoute := false
	for _, entry := range src.ifNameIndex() {
		if entry.Name == "lo" {
			continue
		}
		pathRaw, err := src.resolve1Call(getLinkRequest(entry.Index))
		if err != nil {
			continue
		}
		var reply busDocument
		if json.Unmarshal(pathRaw, &reply) != nil || len(reply.Data) != 1 {
			continue
		}
		var linkPath string
		if json.Unmarshal(reply.Data[0], &linkPath) != nil || linkPath == "" {
			continue
		}
		linkRaw, err := src.resolve1Call(linkPropertiesRequest(linkPath))
		if err != nil {
			continue
		}
		props, err := propertiesOf(linkRaw)
		if err != nil {
			continue
		}
		servers := []string{}
		for _, server := range structArray(props, "DNS") {
			if addr := serverAddr(server); addr != "" {
				servers = append(servers, addr)
			}
		}
		if len(servers) == 0 {
			continue
		}
		link := linkEntry{servers: servers}
		if current, ok := props["CurrentDNSServer"]; ok {
			link.current = serverAddr(current)
		}
		for _, domain := range structArray(props, "Domains") {
			var fields []json.RawMessage
			if json.Unmarshal(domain.Data, &fields) != nil || len(fields) == 0 {
				continue
			}
			var name string
			if json.Unmarshal(fields[0], &name) == nil && name != "" {
				link.domains = append(link.domains, name)
			}
		}
		if route, ok := propBool(props, "DefaultRoute"); ok {
			link.defaultRoute = route
			link.defaultRouteKnown = true
			if route {
				anyDefaultRoute = true
			}
		} else {
			defaultRouteKnown = false
		}
		perLink[entry.Name] = link
	}
	return perLink, defaultRouteKnown && len(perLink) > 0, anyDefaultRoute
}

// ── the one object either mode emits ────────────────────────────────────

func emitResolverObject(out *emitter, src source, collection string, generation uint64, objects *int, facts map[string]any) error {
	name, err := src.hostname()
	if err != nil {
		return err
	}
	out.emit(objectRecord{
		Record:     "object",
		Collection: collection,
		Name:       name,
		Type:       "resolver",
		Facts:      facts,
		At:         src.stamp(*objects),
	})
	*objects++
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    1,
	})
	return nil
}
