package main

// tailscale: the discovery source membership depends on (DESIGN 23) — the
// self node and every peer the coordination map knows, from the root
// collector's snapshot. The identity rule is the reference's, found live the
// day it was written: a row is named by the tailnet's own DNS label, never
// the free-text HostName, because a stock Mac calls itself "Henry's MacBook
// Pro" and a display name is unstable identity besides. A peer the map gives
// no DNS label is skipped, which is one fewer id shape in the world.

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// zero-time: Go stamps "never" as year one. Passed through raw, any future
// age arithmetic reads two millennia of staleness (audit 2026-08-10).
func nonZeroTime(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	moment, err := time.Parse(time.RFC3339, strings.Replace(raw, "Z", "+00:00", 1))
	if err != nil || moment.Year() <= 1 {
		return "", false
	}
	return raw, true
}

// keyExpiry is Self.KeyExpiry → (normalised UTC ISO, whole days until
// expiry). The days are computed HERE so the expiry rule stays clockless.
// Tagged nodes' keys do not expire: absent or Go's zero time is (none),
// never a verdict.
func keyExpiry(raw string, now float64) (string, int64, bool) {
	if raw == "" {
		return "", 0, false
	}
	moment, err := time.Parse(time.RFC3339, strings.Replace(raw, "Z", "+00:00", 1))
	if err != nil || moment.Year() <= 1 {
		return "", 0, false
	}
	seconds := float64(moment.UnixNano())/1e9 - now
	days := int64(seconds / 86400)
	if seconds < 0 && float64(days)*86400 != seconds {
		days-- // Python's floor division rounds toward minus infinity
	}
	return moment.UTC().Format("2006-01-02T15:04:05Z"), days, true
}

func publicKeyFamily(node jsonValue) map[string]any {
	if key := node.stringMember("PublicKey"); key != "" {
		return map[string]any{"stable": map[string]any{"public-key": key}}
	}
	return nil
}

func peerNativeID(node jsonValue) string {
	label := node.stringMember("DNSName")
	if i := strings.IndexByte(label, '.'); i >= 0 {
		label = label[:i]
	}
	return label
}

func epochISO(seconds float64) string {
	return time.Unix(int64(seconds), 0).UTC().Format("2006-01-02T15:04:05Z")
}

// tailscaleFacts carries the members self and peers share; the emitter adds
// each side's own.
func tailscaleFacts(facts map[string]any, node jsonValue) {
	setIf := func(fact, member string) {
		if text := node.stringMember(member); text != "" {
			facts[fact] = text
		}
	}
	setIf("HostName", "HostName")
	setIf("DNSName", "DNSName")
	if ips, ok := node.member("TailscaleIPs"); ok && ips.isArray() {
		list := []any{}
		for _, ip := range ips.array {
			list = append(list, ip.text)
		}
		facts["TailscaleIPs"] = list
	}
	setIf("OS", "OS")
	if online, ok := node.member("Online"); ok && online.kind == jsonBool {
		facts["Online"] = online.boolean
	}
	// tailscale reports "" while relayed or idle; absence says exactly that.
	setIf("Relay", "Relay")
	if routes, ok := node.member("PrimaryRoutes"); ok && routes.isArray() && len(routes.array) > 0 {
		list := []any{}
		for _, route := range routes.array {
			list = append(list, route.text)
		}
		facts["PrimaryRoutes"] = list
	}
}

func collectTailscale(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	doc, mtime, err := src.tailscale()
	if err == errTailscaleAbsent {
		// Unavailable, not absent: a host without the grant still HAS a
		// tailnet membership question, so nothing is retired — no commit,
		// prior state stands, marked stale by the collator. The reference
		// raises the same reason into an error envelope.
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     "unavailable",
			// errTailscaleAbsent's own text: one sentence for one
			// condition, in one place, rather than two spellings that
			// drift — decline detail travels to a hub and out over MCP.
			Detail: errTailscaleAbsent.Error(),
		})
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	now, err := src.now()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	self := doc.get("Self")
	facts := map[string]any{}
	tailscaleFacts(facts, self)
	if iso, days, ok := keyExpiry(self.stringMember("KeyExpiry"), now); ok {
		facts["KeyExpiry"] = iso
		facts["KeyExpiryDays"] = days
	}
	if option, ok := self.member("ExitNodeOption"); ok && option.kind == jsonBool {
		facts["ExitNodeOption"] = option.boolean
	}
	if suffix := doc.stringMember("MagicDNSSuffix"); suffix != "" {
		facts["MagicDNSSuffix"] = suffix
	}
	if state := doc.stringMember("BackendState"); state != "" {
		facts["BackendState"] = state
	}
	if health, ok := doc.member("Health"); ok && health.isArray() && len(health.array) > 0 {
		list := []any{}
		for _, message := range health.array {
			list = append(list, message.text)
		}
		facts["Health"] = list
	}
	// The SMART contract exactly: stamp when the collector wrote the
	// snapshot and how old that is now, so the staleness rule stays pure.
	facts["TailscaleSnapshotAt"] = epochISO(mtime)
	age := int64(now - mtime)
	if age < 0 {
		age = 0
	}
	facts["TailscaleSnapshotAgeSeconds"] = age

	name := peerNativeID(self)
	if name == "" {
		name = "self"
	}
	// The DNS label a row is named by is RENAMEABLE in the admin console;
	// the node key is the device (register row 6's audit). Presence-driven:
	// a snapshot without PublicKey attaches nothing.
	out.emit(objectRecord{
		Record: "object", Collection: collection, Type: "tailscale-self",
		Name: name, Facts: facts, Names: publicKeyFamily(self),
		At: src.stamp(*objects),
	})
	*objects++
	emitted := 1

	peers, _ := doc.member("Peer")
	for _, entry := range peers.members {
		peer := entry.value
		peerName := peerNativeID(peer)
		if peerName == "" {
			continue
		}
		peerFacts := map[string]any{}
		tailscaleFacts(peerFacts, peer)
		if seen, ok := nonZeroTime(peer.stringMember("LastSeen")); ok {
			peerFacts["LastSeen"] = seen
		}
		if addr := peer.stringMember("CurAddr"); addr != "" {
			peerFacts["CurAddr"] = addr
		}
		for _, counter := range [...]string{"RxBytes", "TxBytes"} {
			if v, ok := peer.member(counter); ok && v.kind == jsonNumber {
				// The wire's own spelling, pass-through (DESIGN 19).
				peerFacts[counter] = json.RawMessage(v.number)
			}
		}
		if exit, ok := peer.member("ExitNode"); ok && exit.kind == jsonBool {
			peerFacts["ExitNode"] = exit.boolean
		}
		out.emit(objectRecord{
			Record: "object", Collection: collection, Type: "tailscale-peer",
			Name: peerName, Facts: peerFacts, Names: publicKeyFamily(peer),
			At: src.stamp(*objects),
		})
		*objects++
		emitted++
	}
	out.emit(commitRecord{
		Record: "commit", Collection: collection, Generation: generation,
		Objects: emitted,
	})
	return exitOK
}
