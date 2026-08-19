package main

// reservationRows folds the config document alone: one row per host
// reservation, wherever its subnet is declared, then the global
// Dhcp4.reservations.
//
// A global reservation is NOT subnet-scoped, so its row carries no Subnet fact
// rather than an invented one — the absence is the statement.
//
// A reservation stating no ip-address (a hostname- or class-only pin) mints no
// stable id and is skipped rather than given an invented one. The subnet row's
// ReservationCount still counts it and UnlistedReservations states the
// remainder, which is how the two collections reconcile: rule 7 puts the
// unlistable remainder on the wire instead of in a docstring.
func reservationRows(src source) ([]row, error) {
	config, err := src.document(commandConfig)
	if err != nil {
		return nil, err
	}
	return buildReservationRows(config.dig("arguments", "Dhcp4")), nil
}

func buildReservationRows(dhcp4 *value) []row {
	var rows []row
	for _, sc := range subnetScopes(dhcp4) {
		if !sc.subnet.get("id").stated() {
			continue
		}
		for _, reservation := range arrayOf(sc.subnet.get("reservations")) {
			facts, ip := reservationFacts(reservation)
			if facts == nil {
				continue
			}
			if cidr := sc.subnet.get("subnet"); cidr.truthy() {
				facts.set("Subnet", cidr)
			}
			rows = append(rows, row{name: ip, facts: facts})
		}
	}
	for _, reservation := range arrayOf(dhcp4.get("reservations")) {
		facts, ip := reservationFacts(reservation)
		if facts == nil {
			continue
		}
		rows = append(rows, row{name: ip, facts: facts})
	}
	return rows
}

// reservationFacts is the facts one reservation entry states, or nil for an
// entry that cannot mint a stable id.
//
// Kea normalises an unset hostname to `""` rather than dropping the member, so
// the tests here are on TRUTH and not on presence: a port that checked whether
// the member exists publishes `Hostname: ""` on every reservation whose client
// never stated one, and `HwAddress: ""` on every one identified by a client-id,
// a DUID or a flex-id — which is most of them on a real server.
//
// Only hw-address is read of the four identifier kinds. The other three are
// what the reservation is MATCHED on and say nothing a row is for; they are
// declared in the redaction list instead, because they are exactly what an
// evidence document must not hand over verbatim.
func reservationFacts(reservation *value) (*value, string) {
	if !reservation.isObject() {
		return nil, ""
	}
	ip := reservation.get("ip-address")
	if !ip.truthy() {
		return nil, ""
	}
	facts := newObject()
	facts.set("IpAddress", ip)
	if hw := reservation.get("hw-address"); hw.truthy() {
		facts.set("HwAddress", hw)
	}
	if hostname := reservation.get("hostname"); hostname.truthy() {
		facts.set("Hostname", hostname)
	}
	return facts, pythonText(ip)
}
