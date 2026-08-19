package main

// The row this collection publishes, and its native name. One Kea answers one
// control socket, so the name is a constant rather than anything read out of a
// document: the collator mints `daemon:kea-dhcp4` from the declared prefix and
// this name, which is the id the shipping adapter mints too.
const daemonName = "kea-dhcp4"

// daemonRows is the whole derivation: two documents, ONE row. version-get names
// the release answering the socket and status-get says what that process has
// been doing, so a collector that published a row per document would be
// answering a question nobody asked — and would report two DHCP servers where
// there is one.
func daemonRows(src source) ([]row, error) {
	version, err := src.document(commandVersion)
	if err != nil {
		return nil, err
	}
	status, err := src.document(commandStatus)
	if err != nil {
		return nil, err
	}

	facts := newObject()
	// `text` and not `arguments.extended`: the extended string begins with the
	// same release and continues into the linked library list and their build
	// dates, so a port that read it carries OpenSSL's version into a fact about
	// Kea. Truthiness rather than presence, because the reference's own test is
	// `if version.get("text")`.
	if text := version.get("text"); text.truthy() {
		facts.set("Version", text)
	}
	arguments := status.get("arguments")
	if uptime := arguments.get("uptime"); isInteger(uptime) {
		facts.set("Uptime", uptime)
	}
	// packet-queue-size is the configured CAPACITY, not occupancy — the
	// statistics list (moving averages over the last 10, 100 and 1000 packets)
	// is the only live queue signal status-get states. Carried as the list it
	// is, because only the list says which average is which.
	if queue := arguments.get("packet-queue-statistics"); queue != nil &&
		queue.kind == jsonArray && len(queue.items) > 0 {
		facts.set("QueueDepthAverages", queue)
	}
	return []row{{name: daemonName, facts: facts}}, nil
}
