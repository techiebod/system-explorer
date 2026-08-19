package main

import "strconv"

// The config document is read by three of the four collections, and this file
// is the half they share: where a subnet4 declaration can be found, what the
// option-data merge means, and what one subnet states about itself.

// scope is one subnet4 declaration and the shared network enclosing it — nil at
// the top level, which is the `{}` the reference yields there.
type scope struct{ subnet, network *value }

// subnetScopes finds every subnet4 WHEREVER the config document declares it.
// config-get keeps subnets where they were written, so a walker that reads only
// Dhcp4.subnet4 loses every subnet declared inside shared-networks: their
// statistics rows would still appear — Kea files subnet[id].* regardless of
// membership — but with no CIDR, no options and no reservations. That is
// absence masked as a healthy row, and it is the reason this walk exists rather
// than a one-line list comprehension.
func subnetScopes(dhcp4 *value) []scope {
	var out []scope
	for _, subnet := range arrayOf(dhcp4.get("subnet4")) {
		if subnet.isObject() {
			out = append(out, scope{subnet: subnet})
		}
	}
	for _, network := range arrayOf(dhcp4.get("shared-networks")) {
		if !network.isObject() {
			continue
		}
		for _, subnet := range arrayOf(network.get("subnet4")) {
			if subnet.isObject() {
				out = append(out, scope{subnet: subnet, network: network})
			}
		}
	}
	return out
}

// option-data entries matched by NAME (config-get states name AND code; the
// name is the stable spelling). Only the two options an admin reads off a lease
// first: the gateway and the resolvers a client is handed.
var wantedOptions = map[string]string{
	"routers":             "Routers",
	"domain-name-servers": "DnsServers",
}

// The same two, as the fixed list the suppression sweep walks. A map's
// iteration order is randomised in Go, and this sweep must be deterministic
// even though its outcome is not order-dependent — two runs of one payload are
// byte-identical or the determinism check has nothing to say.
var optionFacts = [...]string{"Routers", "DnsServers"}

// optionValues is the wanted option values at ONE configuration scope. A null
// marks a never-send suppression: Kea withholds the option entirely, so the
// marker must mask any wider-scope value instead of letting it fall through —
// plain last-writer-wins ordering then matches Kea's most-specific-instance-wins
// merge. The flag is checked before the data because an entry carrying both
// never-send and data is still never sent.
func optionValues(optionData *value) *members {
	out := newMembers()
	for _, option := range arrayOf(optionData) {
		if !option.isObject() {
			continue
		}
		name := option.get("name")
		if !name.isString() {
			continue
		}
		fact, wanted := wantedOptions[name.text]
		if !wanted {
			continue
		}
		if suppressed := option.get("never-send"); suppressed != nil &&
			suppressed.kind == jsonBool && suppressed.boolean {
			out.set(fact, &value{kind: jsonNull})
			continue
		}
		if data := option.get("data"); data.isString() && data.text != "" {
			out.set(fact, data)
		}
	}
	return out
}

func mergeInto(into, from *members) {
	for _, key := range from.keys {
		into.set(key, from.byKey[key])
	}
}

// configSubnetFacts is the per-subnet facts the config document states on its
// own: the CIDR, the lease time (valid-lifetime: subnet override, else the
// enclosing shared network's, else the global value), the handed-out options
// folded in Kea's inheritance order, and how many host reservations pin
// addresses. Keyed by subnet id AS A STRING — the spelling the statistic keys
// use, which is the whole of the join between the two documents.
func configSubnetFacts(dhcp4 *value) map[string]*members {
	global := optionValues(dhcp4.get("option-data"))
	globalLifetime := dhcp4.get("valid-lifetime")
	out := map[string]*members{}
	for _, sc := range subnetScopes(dhcp4) {
		id := sc.subnet.get("id")
		if !id.stated() {
			continue
		}
		facts := newMembers()
		if cidr := sc.subnet.get("subnet"); cidr.truthy() {
			facts.set("Subnet", cidr)
		}
		// `subnet.get(k, network.get(k, global))` — the default is reached only
		// when the KEY IS ABSENT, so a subnet that states its lease time as
		// null takes the null and does not inherit. has() is what draws that
		// line; a nil-check would inherit and publish a lease time the subnet
		// explicitly declined to state.
		lifetime := globalLifetime
		if sc.network.has("valid-lifetime") {
			lifetime = sc.network.get("valid-lifetime")
		}
		if sc.subnet.has("valid-lifetime") {
			lifetime = sc.subnet.get("valid-lifetime")
		}
		if isInteger(lifetime) {
			facts.set("LeaseTimeSeconds", lifetime)
		}
		mergeInto(facts, global)
		mergeInto(facts, optionValues(sc.network.get("option-data")))
		mergeInto(facts, optionValues(sc.subnet.get("option-data")))
		for _, fact := range optionFacts {
			// The marker survived the merge: the most specific scope says
			// never-send, so the row must not state a value the client is never
			// handed.
			if held, ok := facts.byKey[fact]; ok && !held.stated() {
				facts.remove(fact)
			}
		}
		reservations := arrayOf(sc.subnet.get("reservations"))
		facts.set("ReservationCount", numberValue(strconv.Itoa(len(reservations))))
		unlisted := 0
		for _, reservation := range reservations {
			if !reservation.isObject() || !reservation.get("ip-address").truthy() {
				unlisted++
			}
		}
		if unlisted > 0 {
			facts.set("UnlistedReservations", numberValue(strconv.Itoa(unlisted)))
		}
		out[pythonText(id)] = facts
	}
	return out
}

// subnetCIDRs is subnet id (as the string other documents spell it) -> CIDR,
// wherever the config document declares the subnet. The lease rows' only use
// for the configuration: a lease states a subnet-id and nothing else about the
// network it came from.
func subnetCIDRs(dhcp4 *value) map[string]string {
	out := map[string]string{}
	for _, sc := range subnetScopes(dhcp4) {
		id := sc.subnet.get("id")
		cidr := sc.subnet.get("subnet")
		if id.stated() && cidr.truthy() {
			out[pythonText(id)] = cidr.text
		}
	}
	return out
}
