package main

import (
	"errors"
	"fmt"
	"io"
	"sort"
)

// The one statement this collector makes on the unobservable channel, and it
// is a constant. Unobservable detail travels to a hub and out over MCP, and
// the reference composes this sentence from the payload's own `ip_note` —
// which under replay is a document value, so echoing it would be a redaction
// path nobody reviewed. The three sources it names are the three
// `_interface_addresses` asks, in order.
const addressUnobservable = "no address source could answer for this running guest: " +
	"the guest agent is refused on a read-only libvirt connection, libvirt holds " +
	"no DHCP lease for it, and the host ARP table has no entry for it"

// domainRow is one domain, reduced to what the collection publishes.
type domainRow struct {
	name  string
	facts *value
	// Law 1: the domain UUID, which is the one identifier that survives a
	// rename. Without it the collator keys a domain on its NAME alone, so
	// `virsh domrename` retires the object and mints a new one — the guest's
	// whole history gone, with nothing saying it was the same guest.
	names *value
	// Present only for a running guest whose address nothing could see: the
	// value exists and this reading cannot get it, which is the third channel
	// (DESIGN 19) and not a value, not an absence, and never a null.
	addressUnobservable bool
}

// domainRows is adapters/vms.py's acquire() for the `domains` collection: one
// row per entry of the `_domains_raw()` list, in the order libvirt walked
// them. The list order is the answer's order — nothing sorts the domains —
// so a port that keyed them into a map would publish a different `at`
// ordering on every run.
func domainRows(document *value) ([]domainRow, error) {
	if document == nil || document.kind != jsonArray {
		// The payload is `_domains_raw()`'s return value, which is a list.
		// Anything else is a broken capture rather than a statement about a
		// machine, so the batch reports "I could not run".
		return nil, errors.New("the staged domains payload is not a list of domains")
	}
	rows := make([]domainRow, 0, len(document.items))
	for i, domain := range document.items {
		row, err := buildDomain(domain)
		if err != nil {
			return nil, fmt.Errorf("domain %d: %v", i, err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// buildDomain is adapters/vms.py `_facts()` reduced to `summary_facts()`: the
// row's subset, in the reference's display order (_SUMMARY_KEYS). A subset
// because the UUID, the NIC and disk structures and the passed-through
// devices belong to the opened object, which this collector does not serve.
//
// Every member is written present-only — `set` drops a nil rather than
// writing a null — and that is the rule for ALL of them rather than an
// allowlist of the two that once broke. The reference's summary copy indexed
// its key tuple unconditionally, which assumed the one shape that sets the
// address pair, and every domain in either other shape blanked its host's
// whole collection: found live on two deployed hosts at once, 2026-08-12, as
// two different KeyErrors from one deploy. Omission is a legitimate shape for
// any fact under rule 7, so the next conditionally-emitted fact must not be
// able to reintroduce the outage by missing a second table.
func buildDomain(domain *value) (domainRow, error) {
	definition := domain.get("xml")
	if !definition.isString() {
		// The reference hands this member straight to ET.fromstring, which
		// raises rather than degrading when it is missing or not a string.
		// A refusal reproduces that: it is "I could not run", never a
		// decline, because no machine was observed to have no definition.
		return domainRow{}, errors.New("the domain carries no XML definition")
	}
	addresses, err := domainAddresses(domain.get("ips_by_mac"))
	if err != nil {
		return domainRow{}, err
	}

	facts := newObject()
	// Pass-through, with the document's own token and type: State is
	// libvirt's own word for the state (adapters/vms.py STATES), and the two
	// figures and two flags are what `dom.info()` and the flag calls
	// returned. Nothing is re-derived here, so nothing can be re-derived
	// differently from the reference.
	facts.set("State", domain.get("state"))
	facts.set("IPAddresses", addressFact(addresses))
	facts.set("MemoryMiB", domain.get("memory_mib"))
	facts.set("VCPUs", domain.get("vcpus"))
	facts.set("Autostart", domain.get("autostart"))
	facts.set("Persistent", domain.get("persistent"))
	facts.set("HostTaps", stringArray(hostTaps(definition.text)))
	if addresses == nil && domain.get("state").equalsString("running") {
		facts.set("IPAddressesUnobservable", stringValue(addressUnobservable))
	}

	// Law 1, added 2026-08-19 with the reference in the same commit. The UUID
	// was read, used as a fact, and never published as a NAME, so the one
	// identifier that survives a rename was not a join key anywhere. Emitted
	// only when the document carries it: a names block whose family is
	// missing would be a join key nobody may join on.
	var names *value
	if uuid := domain.get("uuid"); uuid.isString() && uuid.text != "" {
		stable := newObject()
		stable.set("uuid", uuid)
		names = newObject()
		names.set("stable", stable)
	}

	return domainRow{
		name:  domainName(domain),
		facts: facts,
		names: names,
		// The pair the reference publishes as a null value with a reason
		// beside it. Only HALF of that pair is unlawful: `IPAddresses: null`
		// is refused by the contract at any depth, and it is dropped. The
		// reason is an ordinary non-null string fact and it is KEPT, because
		// dropping it costs an opinion.
		//
		// This emitted an unobservable RECORD instead until 2026-08-19, on the
		// reasoning that DESIGN 19 gives could-not-read its own channel. The
		// live comparator disagreed with the reference on the first running
		// guest either had ever seen, and the reason is the one that matters:
		// `rules/vms.py` reads IPAddressesUnobservable as a FACT to decide
		// whether a guest's blank address column is a gap or an answer. Rules
		// are computed from facts and do not see the record channel, so a
		// collector that moves this statement there deletes the rule's only
		// input and the row loses the opinion that says "unknown rather than
		// absent". `units` has the same shape in MissingReferenceUnobservable,
		// which is what makes this a pattern rather than one collector's
		// quirk: until the rules layer reads records, the FACT is the channel
		// that works.
		//
		// A running guest with no address is the ORDINARY case for a bridged
		// guest, not an exotic one, so this shape is reached in production
		// even though no committed capture stages it.
		addressUnobservable: addresses == nil && domain.get("state").equalsString("running"),
	}, nil
}

// domainName is the row's name and the id the collator keys on. A domain that
// names itself with anything but a string could not travel the stream — the
// contract's name is a string — so it becomes the empty name rather than a
// number wearing a name's place, and the collator refuses what it cannot key.
func domainName(domain *value) string {
	if name := domain.get("name"); name.isString() {
		return name.text
	}
	return ""
}

// addressFact is SPEC section 2 rule 7's three arms, kept apart because they
// are three different claims that look alike in a table.
//
//   - Addresses observed: the list, sorted and deduplicated.
//   - Running, nothing could see one: the value exists and this agent cannot
//     read it. An empty list here said "this guest has no addresses", which is
//     a different and false claim — an appliance guest read [] while sitting
//     on its own address, because all three libvirt sources happened to be
//     silent at once. Emitted as an unobservable record by the caller.
//   - Not running: it has no address BECAUSE IT IS OFF, which is
//     inapplicability, so the fact is omitted rather than nulled or emptied.
func addressFact(addresses []string) *value {
	if addresses == nil {
		return nil
	}
	return stringArray(addresses)
}

// domainAddresses is `sorted({ip for ips in ips_by_mac.values() for ip in ips})`
// — every address across every interface, as one set. nil is the empty
// reading, which the caller routes by state; a non-empty result is the fact.
//
// The shapes below the reference would iterate into nonsense — a value that is
// not a list, an element that is not a string — refuse the batch instead. That
// is the one place this collection is not defensive about a document's types,
// and it is deliberate: a Python string iterates into its characters, so
// "reproducing" it would publish an address per letter.
func domainAddresses(byMAC *value) ([]string, error) {
	if byMAC == nil || byMAC.kind == jsonNull {
		// The reference indexes this member directly, so a missing one is a
		// crash there. Here it is the empty reading, because absent and
		// present-but-empty are the same statement to every branch that
		// follows: nobody could tell us an address.
		return nil, nil
	}
	if byMAC.kind != jsonObject {
		return nil, errors.New("ips_by_mac is not a map of interface addresses")
	}
	seen := map[string]bool{}
	var addresses []string
	for _, mac := range byMAC.members.keys {
		list := byMAC.members.byKey[mac]
		if list.kind != jsonArray {
			return nil, fmt.Errorf("the addresses for one interface are not a list")
		}
		for _, address := range list.items {
			if !address.isString() {
				return nil, fmt.Errorf("an interface address is not a string")
			}
			if !seen[address.text] {
				seen[address.text] = true
				addresses = append(addresses, address.text)
			}
		}
	}
	sort.Strings(addresses)
	return addresses, nil
}

// collectDomains serves the one collection this collector answers for.
func collectDomains(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	document, err := src.domains()
	var refused *declined
	if errors.As(err, &refused) {
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// absent is authoritative-empty: it must be able to retire the domains
		// a previous batch published, so it declines AND commits zero. No
		// other reason commits — nothing was established, so prior state
		// stands and the collator marks it stale.
		if refused.reason == "absent" {
			out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		}
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	rows, err := domainRows(document)
	if err != nil {
		fmt.Fprintln(stderr, "domains:", err)
		return exitRuntime
	}

	unobservable := 0
	for _, row := range rows {
		at, err := src.stamp(*objects)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		record := objectRecord{
			Record:     "object",
			Collection: collection,
			Name:       row.name,
			Facts:      row.facts.encode(),
			At:         at,
		}
		if row.names != nil {
			record.Names = row.names.encode()
		}
		out.emit(record)
		*objects++
	}
	out.emit(commitRecord{
		Record:       "commit",
		Collection:   collection,
		Generation:   generation,
		Objects:      len(rows),
		Unobservable: unobservable,
	})
	return exitOK
}
