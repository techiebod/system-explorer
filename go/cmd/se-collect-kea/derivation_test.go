package main

import (
	"testing"
)

// Everything below is a shape the LAB GUEST does not have. The committed
// capture is one top-level subnet with no shared network, no global
// reservation, no never-send suppression and no lease table, so replay
// equivalence says nothing about any of it — and each of these is a place the
// reference's own docstrings say a naive walk gets it wrong.

func document(t *testing.T, text string) *value {
	t.Helper()
	parsed, err := decodeDocument([]byte(text))
	if err != nil {
		t.Fatalf("test document is not JSON: %v", err)
	}
	return parsed
}

func factText(t *testing.T, facts *value, key string) string {
	t.Helper()
	held := facts.get(key)
	if held == nil {
		t.Fatalf("no %s fact in %s", key, facts.encode())
	}
	return held.text
}

// _subnet_scopes' whole reason for existing: config-get keeps a subnet where it
// was WRITTEN, and Kea files subnet[id].* statistics regardless of membership.
// A walker that read only Dhcp4.subnet4 emits the shared network's subnet as a
// row with a bare id and no CIDR, no options and no reservations — absence
// masked as a healthy row.
func TestASubnetInsideASharedNetworkIsFoundAndCarriesItsNetworksOptions(t *testing.T) {
	config := document(t, `{"Dhcp4": {
	  "valid-lifetime": 900,
	  "option-data": [{"name": "domain-name-servers", "data": "192.0.2.1"}],
	  "shared-networks": [{
	    "name": "upstairs",
	    "valid-lifetime": 1800,
	    "option-data": [{"name": "routers", "data": "192.0.2.254"}],
	    "subnet4": [{"id": 7, "subnet": "198.51.100.0/24",
	                 "reservations": [{"ip-address": "198.51.100.5"}]}]
	  }]
	}}`)
	stats := document(t, `{"subnet[7].total-addresses": [[64, "t"]],
	                       "subnet[7].assigned-addresses": [[16, "t"]]}`)

	rows := buildSubnetRows(stats, configSubnetFacts(config.get("Dhcp4")))
	if len(rows) != 1 {
		t.Fatalf("one subnet, wherever it is declared; got %d rows", len(rows))
	}
	if rows[0].name != "198.51.100.0/24" {
		t.Errorf("the row names the network, not the id: %q", rows[0].name)
	}
	if got := factText(t, rows[0].facts, "LeaseTimeSeconds"); got != "1800" {
		t.Errorf("the shared network's valid-lifetime beats the global one: %s", got)
	}
	if got := factText(t, rows[0].facts, "Routers"); got != "192.0.2.254" {
		t.Errorf("the shared network's option reaches the subnet: %s", got)
	}
	if got := factText(t, rows[0].facts, "DnsServers"); got != "192.0.2.1" {
		t.Errorf("the global option still applies where nothing overrides it: %s", got)
	}
	if got := factText(t, rows[0].facts, "ReservationCount"); got != "1" {
		t.Errorf("the reservations inside a shared network's subnet are its own: %s", got)
	}

	// And the reservation row is found by the same walk, wearing its subnet.
	reservations := buildReservationRows(config.get("Dhcp4"))
	if len(reservations) != 1 || reservations[0].name != "198.51.100.5" {
		t.Fatalf("the shared network's reservation is missing: %v", reservations)
	}
	if got := factText(t, reservations[0].facts, "Subnet"); got != "198.51.100.0/24" {
		t.Errorf("the reservation names its network: %s", got)
	}
}

// Kea's inheritance is most-specific-instance-wins, and never-send is not a
// value to be overridden but a suppression that must MASK the wider scope. A
// merge that dropped the marker instead of carrying it publishes the global
// gateway on a subnet whose clients are handed none.
func TestNeverSendMasksAWiderScopeInsteadOfFallingThroughToIt(t *testing.T) {
	config := document(t, `{"Dhcp4": {
	  "option-data": [
	    {"name": "routers", "data": "192.0.2.1"},
	    {"name": "domain-name-servers", "data": "192.0.2.2"}
	  ],
	  "subnet4": [{"id": 1, "subnet": "192.0.2.0/24", "option-data": [
	    {"name": "routers", "never-send": true, "data": "192.0.2.99"}
	  ]}]
	}}`)
	facts := configSubnetFacts(config.get("Dhcp4"))["1"]
	if _, present := facts.byKey["Routers"]; present {
		t.Error("a suppressed option must not state a value the client is never handed")
	}
	if facts.byKey["DnsServers"].text != "192.0.2.2" {
		t.Errorf("the suppression is per option, not per scope: %v", facts.byKey["DnsServers"])
	}
}

// The flag is checked BEFORE the data because an entry carrying both never-send
// and data is still never sent — which the fixture above relies on, and this
// pins on its own so a reordering cannot pass by accident.
func TestNeverSendBeatsTheDataBesideIt(t *testing.T) {
	merged := optionValues(document(t, `[{"name": "routers", "never-send": true,
	                                      "data": "192.0.2.1"}]`))
	held, present := merged.byKey["Routers"]
	if !present {
		t.Fatal("the marker must survive the merge in order to mask a wider scope")
	}
	if held.stated() {
		t.Fatalf("never-send is a suppression, not a value: %v", held.text)
	}
}

// `subnet.get(k, network.get(k, global))`: the default is reached only when the
// KEY IS ABSENT. A subnet that states its lease time as null has declined to
// state one, and must not inherit.
func TestAnExplicitNullLeaseTimeDoesNotInherit(t *testing.T) {
	config := document(t, `{"Dhcp4": {
	  "valid-lifetime": 900,
	  "subnet4": [{"id": 1, "subnet": "192.0.2.0/24", "valid-lifetime": null}]
	}}`)
	facts := configSubnetFacts(config.get("Dhcp4"))["1"]
	if _, present := facts.byKey["LeaseTimeSeconds"]; present {
		t.Errorf("a null override took the global value: %v", facts.byKey["LeaseTimeSeconds"])
	}
}

// A reservation with no ip-address mints no stable id and is listed nowhere.
// The subnet row is where it is accounted for, and the two members must
// reconcile: ReservationCount counts every entry, UnlistedReservations states
// the remainder, and a reader who subtracts gets the number of rows.
func TestAnAddresslessReservationIsCountedAndNotListed(t *testing.T) {
	config := document(t, `{"Dhcp4": {"subnet4": [{"id": 1, "subnet": "192.0.2.0/24",
	  "reservations": [
	    {"ip-address": "192.0.2.10", "hw-address": "02:00:00:00:00:01"},
	    {"hostname": "class-only", "client-classes": ["voip"]},
	    {"ip-address": "", "hw-address": "02:00:00:00:00:03"}
	  ]}]}}`)
	facts := configSubnetFacts(config.get("Dhcp4"))["1"]
	if got := facts.byKey["ReservationCount"].text; got != "3" {
		t.Errorf("ReservationCount counts every entry the configuration holds: %s", got)
	}
	if got := facts.byKey["UnlistedReservations"].text; got != "2" {
		t.Errorf("the empty string is not an address either: %s", got)
	}
	if rows := buildReservationRows(config.get("Dhcp4")); len(rows) != 1 {
		t.Fatalf("only the reservation with an address is listable: %v", rows)
	}
}

// Absent rather than zero. Rule 7 omits an inapplicable fact, and a helpful
// zero here would tell a reader that a remainder was computed and found empty
// on a subnet where there was nothing to remain.
func TestNoUnlistedRemainderMeansNoFactAtAll(t *testing.T) {
	config := document(t, `{"Dhcp4": {"subnet4": [{"id": 1, "subnet": "192.0.2.0/24",
	  "reservations": [{"ip-address": "192.0.2.10"}]}]}}`)
	facts := configSubnetFacts(config.get("Dhcp4"))["1"]
	if _, present := facts.byKey["UnlistedReservations"]; present {
		t.Error("a nil remainder is an absence, not a zero")
	}
}

// A GLOBAL reservation is not subnet-scoped, so its row carries no Subnet fact
// rather than an invented one — and it is still listed, which a walk over
// subnet4 alone would miss entirely.
func TestAGlobalReservationIsListedAndCarriesNoSubnet(t *testing.T) {
	rows := buildReservationRows(document(t, `{
	  "subnet4": [{"id": 1, "subnet": "192.0.2.0/24",
	               "reservations": [{"ip-address": "192.0.2.10"}]}],
	  "reservations": [{"ip-address": "192.0.2.200", "hostname": "everywhere"}]
	}`))
	if len(rows) != 2 {
		t.Fatalf("both reservations are rows: %v", rows)
	}
	global := rows[1]
	if global.name != "192.0.2.200" {
		t.Fatalf("the global reservation is listed last, as the config states it: %v", global)
	}
	if global.facts.get("Subnet") != nil {
		t.Error("a global reservation has no subnet, and the absence is the statement")
	}
	if factText(t, global.facts, "Hostname") != "everywhere" {
		t.Error("a global reservation states its facts like any other")
	}
}

// Kea normalises an unset member to the empty string rather than dropping it, so
// the tests are on TRUTH and not on presence — a port that checked whether the
// member exists publishes Hostname "" on every reservation whose client never
// stated one.
func TestEmptyStringsAreAbsencesAndNotValues(t *testing.T) {
	rows := buildReservationRows(document(t, `{"subnet4": [{"id": 1, "subnet": "",
	  "reservations": [{"ip-address": "192.0.2.10", "hostname": "", "hw-address": ""}]}]}`))
	if len(rows) != 1 {
		t.Fatalf("one row: %v", rows)
	}
	for _, absent := range []string{"Hostname", "HwAddress", "Subnet"} {
		if rows[0].facts.get(absent) != nil {
			t.Errorf("%s was published from an empty string", absent)
		}
	}
}

// A pool's own counters are filed under subnet[N].pool[M].*, which the tail
// pattern must NOT fold into the subnet's row: a pattern stopping at the first
// dot reports the pool arithmetic twice and, on a subnet with several pools,
// reports whichever pool was read last as the whole subnet.
func TestPoolCountersAreNotSubnetCounters(t *testing.T) {
	stats := document(t, `{
	  "subnet[1].total-addresses": [[100, "t"]],
	  "subnet[1].pool[0].total-addresses": [[999, "t"]],
	  "subnet[1].pool[1].total-addresses": [[888, "t"]]
	}`)
	rows := buildSubnetRows(stats, map[string]*members{})
	if len(rows) != 1 {
		t.Fatalf("one subnet: %v", rows)
	}
	if got := factText(t, rows[0].facts, "TotalAddresses"); got != "100" {
		t.Fatalf("the subnet's own total, not a pool's: %s", got)
	}
}

// The newest value is the FIRST element of the FIRST sample, and it is carried
// as the token the document spelled. A port that published samples[0] whole
// emits a list where an integer belongs, and one that published the second
// element emits the sample timestamp.
func TestOnlyTheNewestSamplesValueBecomesAFact(t *testing.T) {
	stats := document(t, `{"subnet[1].total-addresses": [[200, "newest"], [150, "older"]]}`)
	rows := buildSubnetRows(stats, map[string]*members{})
	if got := factText(t, rows[0].facts, "TotalAddresses"); got != "200" {
		t.Fatalf("got %s", got)
	}
}

// Numeric order, not lexicographic: subnet 2 comes before subnet 10, and the
// SubnetId fact is the number the key denotes rather than its spelling.
func TestSubnetRowsAreOrderedNumericallyAndTheIdIsCanonical(t *testing.T) {
	stats := document(t, `{
	  "subnet[10].total-addresses": [[10, "t"]],
	  "subnet[2].total-addresses": [[2, "t"]],
	  "subnet[007].total-addresses": [[7, "t"]]
	}`)
	rows := buildSubnetRows(stats, map[string]*members{})
	want := []string{"2", "7", "10"}
	if len(rows) != len(want) {
		t.Fatalf("three subnets: %v", rows)
	}
	for i, id := range want {
		if got := factText(t, rows[i].facts, "SubnetId"); got != id {
			t.Errorf("row %d carries SubnetId %s, want %s", i, got, id)
		}
	}
}

// UsedPercent exists only where a positive total makes the division meaningful,
// and it rounds the way Python's round() rounds — ties to EVEN. Go's math.Round
// breaks them away from zero, so a pool sitting exactly on a half is where the
// two implementations part company.
func TestUsedPercentIsOnlyMeaningfulAndRoundsTiesToEven(t *testing.T) {
	cases := []struct {
		total, assigned string
		want            string // "" means the fact must be absent
	}{
		{"200", "0", "0"},    // an empty pool is a reading of zero, not an absence
		{"200", "100", "50"}, //
		{"8", "1", "12"},     // 12.5 -> 12, ties to even
		{"8", "3", "38"},     // 37.5 -> 38, ties to even the other way
		{"3", "1", "33"},     //
		{"0", "0", ""},       // no pool: the question does not apply
		{"", "5", ""},        // no total at all
		{"200", "", ""},      // no assigned reading
		{"200.0", "100", ""}, // a float total is not an int to the reference
	}
	for _, c := range cases {
		stats := newObject()
		if c.total != "" {
			stats.members.set("subnet[1].total-addresses", document(t, "[["+c.total+`, "t"]]`))
		}
		if c.assigned != "" {
			stats.members.set("subnet[1].assigned-addresses", document(t, "[["+c.assigned+`, "t"]]`))
		}
		rows := buildSubnetRows(stats, map[string]*members{})
		if len(rows) == 0 {
			t.Fatalf("total %q assigned %q produced no row", c.total, c.assigned)
		}
		held := rows[0].facts.get("UsedPercent")
		if c.want == "" {
			if held != nil {
				t.Errorf("total %q assigned %q: UsedPercent %v, want absent", c.total, c.assigned, held.text)
			}
			continue
		}
		if held == nil || held.text != c.want {
			t.Errorf("total %q assigned %q: UsedPercent %v, want %s", c.total, c.assigned, held, c.want)
		}
	}
}

// ── leases: the collection no committed capture can reach ────────────────

func TestALeaseCarriesKeasOwnStateVocabularyAndPassesAnythingElseThrough(t *testing.T) {
	leases := document(t, `[
	  {"ip-address": "192.0.2.10", "state": 0, "subnet-id": 1},
	  {"ip-address": "192.0.2.11", "state": 1, "subnet-id": 1},
	  {"ip-address": "192.0.2.12", "state": 2, "subnet-id": 1},
	  {"ip-address": "192.0.2.13", "state": 9, "subnet-id": 1}
	]`)
	rows := buildLeaseRows(leases, map[string]string{"1": "192.0.2.0/24"})
	want := []string{"default", "declined", "expired-reclaimed", "9"}
	if len(rows) != len(want) {
		t.Fatalf("four leases: %v", rows)
	}
	for i, state := range want {
		if got := factText(t, rows[i].facts, "State"); got != state {
			t.Errorf("lease %d carries State %s, want %s", i, got, state)
		}
		if got := factText(t, rows[i].facts, "Subnet"); got != "192.0.2.0/24" {
			t.Errorf("lease %d joined to %s", i, got)
		}
	}
}

// State 0 is a LIVE lease. A truthiness test would drop the state of every
// lease that is working, which is every lease anybody asks about.
func TestTheDefaultStateIsPublishedRatherThanDroppedAsFalsy(t *testing.T) {
	rows := buildLeaseRows(document(t, `[{"ip-address": "192.0.2.10", "state": 0}]`), nil)
	if rows[0].facts.get("State") == nil {
		t.Fatal("state 0 is a live lease, not an absence")
	}
}

func TestLeaseExpiryIsAllocationPlusLifetimeAndNeverForTheInfiniteOne(t *testing.T) {
	cases := []struct {
		lease string
		want  string // "" means the fact must be absent
	}{
		// The value envelope.usec_to_iso answers for the same two figures, read
		// off the reference rather than computed here — a date this test worked
		// out for itself would be pinning arithmetic against arithmetic.
		{`{"ip-address": "192.0.2.10", "cltt": 1787128431, "valid-lft": 3600}`,
			"2026-08-19T09:33:51Z"},
		// DHCP's infinite lifetime: the lease never lapses, and the arithmetic
		// would assert a concrete date in 2162 instead.
		{`{"ip-address": "192.0.2.11", "cltt": 1787128431, "valid-lft": 4294967295}`, "never"},
		// …and it says `never` even with no allocation time, because a lease
		// that never lapses does not need one for the answer to be true.
		{`{"ip-address": "192.0.2.12", "valid-lft": 4294967295}`, "never"},
		{`{"ip-address": "192.0.2.13", "valid-lft": 3600}`, ""},
		{`{"ip-address": "192.0.2.14", "cltt": 1787128431}`, ""},
		// The envelope reads 0 as "no timestamp here" rather than as 1970.
		{`{"ip-address": "192.0.2.15", "cltt": 0, "valid-lft": 0}`, ""},
	}
	for _, c := range cases {
		rows := buildLeaseRows(document(t, "["+c.lease+"]"), nil)
		if len(rows) != 1 {
			t.Fatalf("%s produced %d rows", c.lease, len(rows))
		}
		held := rows[0].facts.get("ExpiresAt")
		if c.want == "" {
			if held != nil {
				t.Errorf("%s: ExpiresAt %v, want absent", c.lease, held.text)
			}
			continue
		}
		if held == nil || held.text != c.want {
			t.Errorf("%s: ExpiresAt %v, want %s", c.lease, held, c.want)
		}
	}
}

// A lease naming a subnet id the configuration no longer declares carries no
// Subnet — which is what a lease left behind by a removed subnet looks like, and
// is a different statement from a lease in a subnet with no CIDR.
func TestALeaseWithNoMatchingSubnetCarriesNoSubnetFact(t *testing.T) {
	rows := buildLeaseRows(document(t, `[{"ip-address": "192.0.2.10", "subnet-id": 99}]`),
		map[string]string{"1": "192.0.2.0/24"})
	if rows[0].facts.get("Subnet") != nil {
		t.Error("a subnet id nothing declares joins to nothing")
	}
}

func TestALeaseWithNoAddressMintsNoRow(t *testing.T) {
	rows := buildLeaseRows(document(t, `[{"hostname": "nameless"}, {"ip-address": ""},
	                                      {"ip-address": "192.0.2.10"}]`), nil)
	if len(rows) != 1 || rows[0].name != "192.0.2.10" {
		t.Fatalf("only the lease with an address can mint a stable id: %v", rows)
	}
}
