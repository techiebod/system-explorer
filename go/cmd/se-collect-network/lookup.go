package main

// The lookup verb's two questions (DESIGN 18): route-get, the kernel's own
// answer for one destination; and resolve, resolved's answer for a name or —
// for an address — the reverse. Each response is one object record in the
// lookups namespace, its edge where one exists, then the terminator; a
// decline is data under this verb as under every other.

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// hostnameGate is the safety gate for the D-Bus string, not RFC hostname
// validation: underscore labels (_dmarc.example.com) are legitimate
// debugging queries.
var hostnameGate = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,253}$`)

// resolved's response flags (resolved-def.h): protocol in the low bits,
// SD_RESOLVED_AUTHENTICATED at 1 << 9. Only bits with settled meaning are
// decoded into facts.
const resolvedAuthenticated = 1 << 9

func resolveProtocol(flags int64) (string, bool) {
	switch {
	case flags&0b1 != 0:
		return "DNS", true
	case flags&0b110 != 0:
		return "LLMNR", true
	case flags&0b11000 != 0:
		return "mDNS", true
	}
	return "", false
}

// verbEndRecord arrives with this collector's first request-shaped verb;
// object and evidence will share it when the fleet rollout reaches here.
type verbEndRecord struct {
	Record    string `json:"record"`
	Verb      string `json:"verb"`
	Truncated bool   `json:"truncated"`
}

func verbExit(out *emitter, stderr io.Writer) int {
	if out.err != nil {
		fmt.Fprintln(stderr, "writing the response:", out.err)
		return exitRuntime
	}
	return exitOK
}

// decodeBusReply parses one busctl --json=short reply into the shared value
// model; `data` is the argument array.
func decodeBusReply(raw []byte) (jsonValue, error) {
	return decodeDocument(strings.NewReader(string(raw)))
}

func busArgument(reply jsonValue, i int) jsonValue {
	data, _ := reply.member("data")
	if i < len(data.array) {
		return data.array[i]
	}
	return jsonValue{kind: jsonNull}
}

func busInt(v jsonValue) int64 {
	if v.kind != jsonNumber {
		return 0
	}
	n, err := strconv.ParseInt(v.number, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func roundHalfEven1(x float64) float64 {
	return math.RoundToEven(x*10) / 10
}

func serveLookup(stdout, stderr io.Writer, src source, name, input string) int {
	out := newEmitter(stdout)
	switch name {
	case "route-get":
		return lookupRouteGet(out, stderr, src, input)
	case "resolve":
		return lookupResolve(out, stderr, src, input)
	}
	out.emit(declineRecord{Record: "decline", Collection: "lookups",
		Reason: "unsupported",
		Detail: "this collector's lookup palette holds route-get and resolve"})
	out.emit(verbEndRecord{Record: "verb_end", Verb: "lookup"})
	return verbExit(out, stderr)
}

func lookupRouteGet(out *emitter, stderr io.Writer, src source, input string) int {
	address, err := netip.ParseAddr(input)
	if err != nil {
		out.emit(declineRecord{Record: "decline", Collection: "lookups",
			Reason: "unsupported",
			Detail: "not an IPv4 or IPv6 address"})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "lookup"})
		return verbExit(out, stderr)
	}
	facts := map[string]any{"Destination": address.String()}
	doc, err := src.ipRouteGet(address.String())
	if err != nil {
		if isReplayGap(err) {
			fmt.Fprintln(stderr, "route-get:", err)
			return exitRuntime
		}
		// "RTNETLINK answers: Network is unreachable" is the kernel's
		// answer, not an acquisition failure.
		facts["RouteFound"] = false
		facts["KernelError"] = failureText(err, errIPSilent)
		return emitLookupObject(out, stderr, src, "route-get/"+input, facts, "", "")
	}
	route := jsonValue{}
	if len(doc.array) > 0 {
		route = doc.array[0]
	}
	facts["RouteFound"] = true
	if dst := route.stringMember("dst"); dst != "" {
		facts["Destination"] = dst
	}
	device := route.stringMember("dev")
	for fact, member := range map[string]string{
		"Gateway": "gateway", "Device": "dev", "PreferredSource": "prefsrc",
		"Protocol": "protocol",
	} {
		if text := route.stringMember(member); text != "" {
			facts[fact] = text
		}
	}
	// table, scope and metric arrive as ip spells them — a number or a word.
	for fact, member := range map[string]string{
		"Table": "table", "Scope": "scope", "Metric": "metric",
	} {
		if v, ok := route.member(member); ok && !v.isNull() {
			if v.kind == jsonString {
				facts[fact] = v.text
			} else if v.kind == jsonNumber {
				facts[fact] = json.RawMessage(v.number)
			}
		}
	}
	return emitLookupObject(out, stderr, src, "route-get/"+input, facts,
		"routes-via", device)
}

func lookupResolve(out *emitter, stderr io.Writer, src source, input string) int {
	address, addressErr := netip.ParseAddr(input)
	if addressErr != nil && !hostnameGate.MatchString(input) {
		out.emit(declineRecord{Record: "decline", Collection: "lookups",
			Reason: "unsupported",
			Detail: "not a hostname or IP address"})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "lookup"})
		return verbExit(out, stderr)
	}
	started, err := src.now()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	var request string
	if addressErr == nil {
		family := 2 // AF_INET
		if address.Is6() {
			family = 10 // AF_INET6
		}
		packed := address.AsSlice()
		tokens := make([]string, 0, len(packed)+4)
		tokens = append(tokens, "0", strconv.Itoa(family),
			strconv.Itoa(len(packed)))
		for _, b := range packed {
			tokens = append(tokens, strconv.Itoa(int(b)))
		}
		tokens = append(tokens, "0")
		request = resolve1Path + " " + resolve1Manager + " ResolveAddress iiayt " +
			strings.Join(tokens, " ")
	} else {
		request = resolve1Path + " " + resolve1Manager + " ResolveHostname isit " +
			"0 " + input + " 0 0"
	}
	facts := map[string]any{"Query": input}
	raw, callErr := src.resolve1Call(request)
	if callErr != nil {
		if isReplayGap(callErr) {
			fmt.Fprintln(stderr, "resolve:", callErr)
			return exitRuntime
		}
		// NXDOMAIN, QueryTimedOut, NoNameServers … are answers, not
		// failures. busctl surfaces the daemon's message rather than the
		// dbus error NAME, so Result carries resolved's own words — a
		// stated deviation from the reference's error-name verdict, in the
		// declaration's sentence.
		facts["Resolved"] = false
		facts["Result"] = strings.TrimPrefix(
			failureText(callErr, errCallFailed), "Call failed: ")
		return emitLookupObject(out, stderr, src, "resolve/"+input, facts, "", "")
	}
	finished, err := src.now()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	reply, err := decodeBusReply(raw)
	if err != nil {
		fmt.Fprintln(stderr, "resolve:", err)
		return exitRuntime
	}
	facts["Resolved"] = true
	if addressErr == nil {
		names := []any{}
		for _, pair := range busArgument(reply, 0).array {
			// (ifindex, name) pairs; the name is the answer.
			if len(pair.array) == 2 {
				names = append(names, pair.array[1].text)
			}
		}
		facts["Names"] = names
		flags := busInt(busArgument(reply, 1))
		if protocol, ok := resolveProtocol(flags); ok {
			facts["Protocol"] = protocol
		}
		facts["Authenticated"] = flags&resolvedAuthenticated != 0
	} else {
		addresses := []any{}
		for _, entry := range busArgument(reply, 0).array {
			if text := scopedAddr(src, entry); text != "" {
				addresses = append(addresses, text)
			}
		}
		facts["Addresses"] = addresses
		facts["CanonicalName"] = busArgument(reply, 1).text
		flags := busInt(busArgument(reply, 2))
		if protocol, ok := resolveProtocol(flags); ok {
			facts["Protocol"] = protocol
		}
		facts["Authenticated"] = flags&resolvedAuthenticated != 0
	}
	elapsed := (finished - started) * 1000
	if elapsed < 0 {
		elapsed = 0
	}
	facts["QueryTimeMs"] = roundHalfEven1(elapsed)
	return emitLookupObject(out, stderr, src, "resolve/"+input, facts, "", "")
}

// scopedAddr renders a resolve1 address struct (ifindex, family, bytes):
// '1.2.3.4', or 'fe80::1%eth0' — the scope suffix only carries meaning for
// link-local addresses, so it is added only there, and only where the
// interface table can name the index.
func scopedAddr(src source, entry jsonValue) string {
	if len(entry.array) != 3 {
		return ""
	}
	var packed []byte
	for _, b := range entry.array[2].array {
		packed = append(packed, byte(busInt(b)))
	}
	address, ok := netip.AddrFromSlice(packed)
	if !ok {
		return ""
	}
	text := address.String()
	if address.IsLinkLocalUnicast() {
		ifindex := int(busInt(entry.array[0]))
		for _, iface := range src.ifNameIndex() {
			if iface.Index == ifindex {
				text += "%" + iface.Name
				break
			}
		}
	}
	return text
}

// failureText is the tool's or the daemon's own words, unwrapped from the
// sentinel this package rides them on — the sentinel is routing, not answer.
func failureText(err, sentinel error) string {
	return strings.TrimSpace(strings.TrimPrefix(err.Error(), sentinel.Error()+":"))
}

func emitLookupObject(out *emitter, stderr io.Writer, src source, name string,
	facts map[string]any, edgeType, edgeTarget string) int {
	out.emit(objectRecord{
		Record:     "object",
		Collection: "lookups",
		Name:       name,
		Type:       "lookup-result",
		Facts:      facts,
		At:         src.stamp(0),
	})
	if edgeType != "" && edgeTarget != "" {
		out.emit(relationAssertionRecord{
			Record: "relation_assertion", Collection: "lookups",
			Name: name, Vantage: "lookups", Type: edgeType,
			Target: assertionTarget{Kind: "link", Name: edgeTarget},
		})
	}
	out.emit(verbEndRecord{Record: "verb_end", Verb: "lookup"})
	return verbExit(out, stderr)
}
