package main

// The links collection — the last of the bare-guest nine, and the one the
// register called the largest single hole. Ported from the reference with
// its taxonomy intact: Kind is the kernel's most specific name for what a
// SOFTWARE device is (linkinfo, with tun/tap split one level down in
// info_data because tailscale0 and libvirt's taps otherwise arrive
// indistinguishable), LinkType is the ARPHRD name the kernel fills in for
// EVERYTHING, and the two are not alternatives — a bridge is "ether" as
// well as a bridge, and folding them would stop a bridge being
// distinguishable from its own ports.
//
// The applied order IS the enslavement tree: enslaved links sit under
// their master the way partitions sit under disks, walked depth-first in
// document order — and since R1's ruling the hierarchy itself travels as
// relations, so each enslaved link ASSERTS enslaved-to its master and the
// collator derives the tree from edges rather than from a coordinate.
//
// Two enrichments ride the row and their absence is silence, not
// evidence: the bridge fdb's learned MACs (what makes a veth attributable
// to its container — the port's own MAC identifies nothing) and LLDP
// neighbours where anything on the segment emits them.

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

func linkKind(link jsonValue) string {
	info := link.get("linkinfo")
	kind := info.stringMember("info_kind")
	if kind == "tun" {
		if mode := info.get("info_data").stringMember("type"); mode != "" {
			return mode
		}
	}
	return kind
}

// lldpByLink is neighbours per interface from networkctl's capture.
func lldpByLink(doc jsonValue) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, entry := range doc.get("Neighbors").array {
		ifname := entry.stringMember("InterfaceName")
		if ifname == "" {
			continue
		}
		for _, neighbour := range entry.get("Neighbors").array {
			row := map[string]any{}
			if v, ok := neighbour.member("SystemName"); ok && !v.isNull() {
				row["SystemName"] = v
			}
			if v, ok := neighbour.member("PortDescription"); ok && !v.isNull() {
				row["PortDescription"] = v
			} else if v, ok := neighbour.member("PortID"); ok && !v.isNull() {
				row["PortDescription"] = v
			}
			if v, ok := neighbour.member("ChassisID"); ok && !v.isNull() {
				row["ChassisID"] = v
			}
			out[ifname] = append(out[ifname], row)
		}
	}
	return out
}

// peerMACsByPort is the learned unicast MACs per bridge port. Excluded
// exactly as the reference excludes: self and permanent entries (a port
// attributed to itself) and group addresses by the multicast bit. The
// table is LEARNED and ages out — a missing MAC is "cannot say", never
// evidence that nothing is attached.
func peerMACsByPort(doc jsonValue) map[string][]string {
	out := map[string][]string{}
	for _, entry := range doc.array {
		port := entry.stringMember("ifname")
		mac := entry.stringMember("mac")
		master := entry.stringMember("master")
		if port == "" || mac == "" || master == "" || port == master {
			continue
		}
		flags := entry.get("flags")
		selfFlagged := false
		for _, flag := range flags.array {
			if flag.isString() && flag.text == "self" {
				selfFlagged = true
			}
		}
		if selfFlagged || entry.stringMember("state") == "permanent" {
			continue
		}
		var firstOctet int
		if _, err := fmt.Sscanf(mac, "%02x", &firstOctet); err != nil || firstOctet&1 == 1 {
			continue
		}
		out[port] = append(out[port], mac)
	}
	return out
}

func collectLinks(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	doc, err := src.ipAddr()
	if err != nil {
		if isReplayGap(err) {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unavailable", Detail: "iproute2 did not answer on this host"})
		fmt.Fprintln(stderr, "links:", err)
		return exitOK
	}
	lldp := lldpByLink(src.lldp())
	peerMACs := peerMACsByPort(src.fdb())

	// Enslavement count per master, from the same payload: the empty-bridge
	// rule keys on it, because a bridge with zero members is down by design.
	memberCounts := map[string]int{}
	for _, link := range doc.array {
		if master := link.stringMember("master"); master != "" {
			memberCounts[master]++
		}
	}

	type entry struct {
		name   string
		master string
		facts  map[string]any
	}
	byName := map[string]*entry{}
	order := []string{}
	for _, link := range doc.array {
		name := link.stringMember("ifname")
		if name == "" {
			continue
		}
		facts := map[string]any{
			"OperState": strings.ToLower(link.stringMember("operstate")),
		}
		if kind := linkKind(link); kind != "" {
			facts["Kind"] = kind
		}
		for _, p := range [...]struct{ fact, member string }{
			{"LinkType", "link_type"}, {"MTU", "mtu"},
			{"MACAddress", "address"}, {"Master", "master"},
		} {
			if value, ok := link.member(p.member); ok && !value.isNull() {
				facts[p.fact] = value
			}
		}
		addresses := []string{}
		for _, addr := range link.get("addr_info").array {
			local := addr.stringMember("local")
			prefix, hasPrefix := addr.member("prefixlen")
			if local != "" && hasPrefix && prefix.isInt() {
				addresses = append(addresses, local+"/"+prefix.number)
			}
		}
		facts["Addresses"] = addresses
		// Where the device physically is — omitted rather than nulled:
		// only a device on a bus has one, and absence is the statement
		// "not backed by hardware". The raw address is the join key to
		// hardware/pci, kept exactly as the kernel spells it.
		if parentDev := link.stringMember("parentdev"); parentDev != "" {
			if bus := link.stringMember("parentbus"); bus != "" {
				facts["ParentBus"] = bus
			}
			facts["ParentDev"] = parentDev
		}
		// The burned-in address, when it differs from the one in use —
		// the tell that a MAC has been overridden.
		if perm := link.stringMember("permaddr"); perm != "" &&
			perm != link.stringMember("address") {
			facts["PermanentMACAddress"] = perm
		}
		if facts["Kind"] == "bridge" || linkKind(link) == "bridge" {
			facts["BridgeMembers"] = memberCounts[name]
		}
		if macs := peerMACs[name]; len(macs) > 0 {
			sort.Strings(macs)
			facts["PeerMACAddresses"] = macs
		}
		if neighbours := lldp[name]; len(neighbours) > 0 {
			facts["LLDPNeighbors"] = neighbours
		}
		byName[name] = &entry{name: name,
			master: link.stringMember("master"), facts: facts}
		order = append(order, name)
	}

	// Enslaved links sit under their master, depth-first in document
	// order — membership readable from the shape of the list, exactly as
	// the reference orders it.
	children := map[string][]*entry{}
	roots := []*entry{}
	for _, name := range order {
		link := byName[name]
		if link.master != "" && byName[link.master] != nil {
			children[link.master] = append(children[link.master], link)
		} else {
			roots = append(roots, link)
		}
	}
	emitted, assertions := 0, 0
	var walk func(link *entry)
	walk = func(link *entry) {
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			Name:       link.name,
			Type:       "link",
			Facts:      link.facts,
			At:         src.stamp(*objects),
		})
		emitted++
		*objects++
		// The hierarchy as an EDGE, not a coordinate (the R1 ruling): the
		// collator derives the tree from these, and the target's name is
		// the master's name as published — resolvable by anything on this
		// host that claims it.
		if link.master != "" {
			out.emit(relationAssertionRecord{
				Record:     "relation_assertion",
				Collection: collection,
				Name:       link.name,
				Vantage:    collection,
				Type:       "enslaved-to",
				Target:     assertionTarget{Kind: "link", Name: link.master},
			})
			assertions++
		}
		for _, child := range children[link.name] {
			walk(child)
		}
	}
	for _, root := range roots {
		walk(root)
	}
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    emitted,
		Assertions: assertions,
	})
	return exitOK
}
