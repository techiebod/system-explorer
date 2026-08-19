package main

import "time"

// lease4 state in Kea's OWN vocabulary (its lease-cmds documentation: 0
// default, 1 declined, 2 expired-reclaimed), in Kea's own order.
var leaseStates = [...]string{"default", "declined", "expired-reclaimed"}

// leaseState names the three Kea defines and passes anything else through AS
// ITSELF — never renamed into words Kea does not use, because a state a future
// release adds is a reading to carry rather than one to guess at.
//
// A DIVERGENCE FROM THE DECLARATION lives here and is the reference's, not the
// port's: State is declared an enum over the three names, and this
// pass-through can put a NUMBER under that name on a Kea that grows a fourth
// state. The port reproduces the reference because agreement is the bar; the
// disagreement between the declaration and the code is reported rather than
// silently resolved in either direction.
func leaseState(state *value) *value {
	for number, name := range leaseStates {
		if numberEquals(state, int64(number)) {
			return stringValue(name)
		}
	}
	return state
}

// DHCP's infinite lifetime (RFC 2131). The lease never lapses, and arithmetic
// would assert a concrete year-2162 date for it instead.
const infiniteLifetime = 0xFFFFFFFF

// leaseRows serves the collection that is gated on a hook. lease4-get-all ships
// in libdhcp_lease_cmds, so on a Kea with no hooks loaded the interface does not
// exist at all and src.document returns the unsupported decline — which does not
// commit, so a host that merely lost its hook keeps the leases a previous batch
// published rather than having them retired.
func leaseRows(src source) ([]row, error) {
	answer, err := src.document(commandLeases)
	if err != nil {
		return nil, err
	}
	config, err := src.document(commandConfig)
	if err != nil {
		return nil, err
	}
	return buildLeaseRows(answer.dig("arguments", "leases"),
		subnetCIDRs(config.dig("arguments", "Dhcp4"))), nil
}

func buildLeaseRows(leases *value, cidrs map[string]string) []row {
	var rows []row
	for _, lease := range arrayOf(leases) {
		if !lease.isObject() {
			continue
		}
		ip := lease.get("ip-address")
		if !ip.truthy() {
			continue // no stable id can be minted for a lease with no address
		}
		facts := newObject()
		facts.set("IpAddress", ip)
		if hw := lease.get("hw-address"); hw.truthy() {
			facts.set("HwAddress", hw)
		}
		if hostname := lease.get("hostname"); hostname.truthy() {
			facts.set("Hostname", hostname)
		}
		// `is not None`, not truthiness: state 0 is a LIVE lease, and a
		// truthiness test would drop the state of every lease that is working.
		if state := lease.get("state"); state.stated() {
			facts.set("State", leaseState(state))
		}
		if cidr, ok := cidrs[pythonText(lease.get("subnet-id"))]; ok && cidr != "" {
			facts.set("Subnet", stringValue(cidr))
		}
		if expires, ok := expiresAt(lease); ok {
			facts.set("ExpiresAt", stringValue(expires))
		}
		rows = append(rows, row{name: pythonText(ip), facts: facts})
	}
	return rows
}

// expiresAt is allocation time plus valid lifetime, as UTC — or the word
// `never` for a lease granted DHCP's infinite lifetime. The infinite check
// comes FIRST and does not require cltt: a lease that never lapses does not
// need an allocation time for the answer to be true, and the arithmetic branch
// would otherwise turn 4294967295 seconds into a date in 2162 and present it as
// a fact.
func expiresAt(lease *value) (string, bool) {
	lifetime := lease.get("valid-lft")
	// Compared as a NUMBER rather than as an integer, because the reference's
	// test is `valid == 0xFFFFFFFF` and Python's == does not care whether the
	// document wrote it as an int or a float. The arithmetic below does care,
	// and says so with isinstance.
	if numberEquals(lifetime, infiniteLifetime) {
		return "never", true
	}
	valid, validOK := lifetime.integer()
	cltt, clttOK := lease.get("cltt").integer()
	if !clttOK || !validOK {
		return "", false
	}
	seconds := cltt + valid
	// The envelope reads 0 as "no timestamp here" rather than as 1970, and a
	// date derived from it would be a confident answer about a lease nobody
	// granted. Its other sentinel — the u64 max — is tested on the MICROSECOND
	// value, which no whole number of seconds can produce, so it is unreachable
	// from this caller and is not restated here as though it were.
	if seconds == 0 {
		return "", false
	}
	return time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05Z"), true
}
