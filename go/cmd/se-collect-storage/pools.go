package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
)

// The three statements a reading can make about one property, and the exact
// prose each carries. They are constants because decline and unobservable
// detail travel to a hub and out over MCP: a string built from payload bytes
// would be a redaction path nobody reviewed.
const (
	deviceUnresolvable = "no device alias tree could be read, so the member's kernel name cannot be resolved"
	proseScanEndTime   = "this OpenZFS renders scan end_time as prose, not an epoch, so no age can be derived from it"
	listUnreadable     = "zpool list could not be read; zpool status alone carries no capacity properties"
	shapeUnrecognised  = "a top-level vdev of a shape this reading does not recognise; " +
		"claiming a tolerance the walk cannot justify is the direction that gets somebody hurt"
)

// The five facts that come only from `zpool list`. Their order here is the
// order the reference builds them in, and the pop-and-declare loop below
// walks the same list, so the two cannot drift.
var capacityFacts = [...]struct{ fact, property string }{
	{"SizeBytes", "size"},
	{"AllocatedBytes", "allocated"},
	{"FreeBytes", "free"},
	{"CapacityPercent", "capacity"},
	{"FragmentationPercent", "fragmentation"},
}

// factSet is the pool's facts before the absent sweep. A key present with a
// nil value is the source reporting the property genuinely missing, which is
// a different statement from could-not-read and from a value — three
// statements, three channels, and a null names none of them (DESIGN 19). So
// the nil is carried HERE, where the sweep can partition on it, and never
// reaches the wire.
type factSet struct {
	keys  []string
	byKey map[string]*value
}

func newFactSet() *factSet { return &factSet{byKey: map[string]*value{}} }

func (f *factSet) put(key string, v *value) {
	if _, seen := f.byKey[key]; !seen {
		f.keys = append(f.keys, key)
	}
	f.byKey[key] = v
}

// pop removes a key outright, so it can reach neither the facts nor the
// absent list — what the caller does when the reason it is missing belongs
// on the unobservable channel instead.
func (f *factSet) pop(key string) {
	if _, ok := f.byKey[key]; !ok {
		return
	}
	delete(f.byKey, key)
	for i, existing := range f.keys {
		if existing == key {
			f.keys = append(f.keys[:i], f.keys[i+1:]...)
			break
		}
	}
}

func (f *factSet) split() (*value, []string) {
	facts, absent := newObject(), []string{}
	for _, key := range f.keys {
		if v := f.byKey[key]; v != nil {
			facts.set(key, v)
		} else {
			absent = append(absent, key)
		}
	}
	return facts, absent
}

// unobservableFact is one could-not-read, before it is lifted onto the wire
// with the collection and the object it belongs to.
type unobservableFact struct{ fact, reason, detail string }

// collectPools serves the one collection this collector answers for.
func collectPools(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	reading, err := src.zpool()
	var refused *declined
	if errors.As(err, &refused) {
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// absent is authoritative-empty: it must be able to retire objects a
		// previous batch published, so it declines AND commits zero. No
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
	now, err := src.now()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	// `zpool list` is enrichment: a nil listing is could-not-read, which is
	// a different statement from a listing that reported no such pool, and
	// the two land on different channels below.
	var listing *value
	if reading.list != nil {
		listing = reading.list.get("pools")
		if !truthy(listing) {
			listing = newObject()
		}
	}

	pools := reading.status.get("pools").object()
	emitted, unobservable := 0, 0
	for _, name := range keysOf(pools) {
		at, err := src.stamp(*objects)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		record, missing, err := buildPool(name, pools.byKey[name], listing, reading.links, now, at)
		if err != nil {
			fmt.Fprintf(stderr, "pool: %v\n", err)
			return exitRuntime
		}
		record.Collection = collection
		out.emit(record)
		*objects++
		emitted++
		for _, entry := range missing {
			out.emit(unobservableRecord{
				Record:     "unobservable",
				Collection: collection,
				Name:       name,
				Fact:       entry.fact,
				Reason:     entry.reason,
				Detail:     entry.detail,
			})
			unobservable++
		}
	}
	out.emit(commitRecord{
		Record:       "commit",
		Collection:   collection,
		Generation:   generation,
		Objects:      emitted,
		Unobservable: unobservable,
	})
	return exitOK
}

// buildPool is storage.py:861-1002 for one entry of the status document's
// pools map. The object's NAME is that map key — not the pool's own `name`
// member, which nothing reads, and not the guid.
func buildPool(name string, pool *value, listing *value, links *aliasTree, now, at float64) (objectRecord, []unobservableFact, error) {
	var rows []*vdevRow
	flattenPoolVdevs(pool, &rows, links)

	var unobservable []unobservableFact
	if links == nil {
		// The alias trees could not be read (live) or no devlinks payload
		// was captured (replay). Every leaf's Device is a could-not-read,
		// one record each — never a silent omission, which would say the
		// member has no kernel name, and never a claim about the machine
		// doing the replaying.
		for _, row := range rows {
			if row.isDisk {
				unobservable = append(unobservable, unobservableFact{
					fact:   "Vdevs/" + row.name + "/Device",
					reason: "unavailable",
					detail: deviceUnresolvable,
				})
			}
		}
	}

	poolListing := listing.get(name)
	props := poolListing.get("properties")
	caps := map[string]vdevCap{}
	collectCaps(poolListing.get("vdevs"), caps)
	mergeCaps(rows, caps)

	scan, err := computeScanFacts(pool.get("scan_stats"), now)
	if err != nil {
		return objectRecord{}, nil, err
	}

	facts := newFactSet()
	facts.put("State", nilIfNone(pool.get("state")))
	message, err := statusMessage(pool.get("status"))
	if err != nil {
		return objectRecord{}, nil, err
	}
	facts.put("StatusMessage", message)
	// Known data ERRORS, raw: the degraded capture reads 0 beside a member
	// carrying three checksum errors, because parity repaired every bad
	// block. This fact and the per-vdev counters answer different questions.
	facts.put("Errors", nilIfNone(pool.get("error_count")))

	facts.put("ScanFunction", scan.function)
	facts.put("ScanState", scan.state)
	facts.put("ScanEndTime", scan.endTime)
	if scan.hasAge {
		facts.put("ScanAgeDays", bigValue(scan.ageDays))
	}
	var extraAbsent []string
	if scan.scrubBlock != "" {
		// The reason stays a string fact because the rulebook cites it as
		// evidence; the null half moves to its own channel.
		facts.put("LastScrubEndTimeUnobservable", stringValue(scan.scrubBlock))
		unobservable = append(unobservable, unobservableFact{
			fact: "LastScrubEndTime", reason: "unavailable", detail: scan.scrubBlock,
		})
	}
	if !scan.hasAge {
		if scan.endTime.isString() {
			// An end time was reported, but as prose: the age exists and
			// this OpenZFS cannot let us derive it.
			unobservable = append(unobservable, unobservableFact{
				fact: "ScanAgeDays", reason: "unsupported", detail: proseScanEndTime,
			})
		} else {
			// No scan record, or a scan still running: there is genuinely no
			// end to measure an age from.
			extraAbsent = append(extraAbsent, "ScanAgeDays")
		}
	}

	for _, entry := range capacityFacts {
		facts.put(entry.fact, bigOrNil(intOrNil(propValue(props, entry.property))))
	}
	facts.put("Vdevs", rowFields(rows))
	facts.put("UnhealthyVdevs", unhealthyVdevs(rows))
	facts.put("VdevsWithErrors", vdevsWithErrors(rows))

	if listing == nil {
		// The properties are on the pool and `zpool list` is what could not
		// be read — five unobservables, not five absences. The per-vdev
		// capacity members degrade silently by the same acquisition, which
		// is the reference's own asymmetry and is reproduced.
		for _, entry := range capacityFacts {
			facts.pop(entry.fact)
			unobservable = append(unobservable, unobservableFact{
				fact: entry.fact, reason: "unavailable", detail: listUnreadable,
			})
		}
	}

	if layout, tolerated, ok := redundancy(rows); ok {
		facts.put("Redundancy", stringValue(layout))
		facts.put("DeviceFailuresTolerated", intValue(tolerated))
	} else {
		// The pool HAS a layout; this walk cannot justify a claim about it,
		// which is could-not-read and not has-no-such-property. Neither key
		// ever reaches the facts, so neither can land on absent.
		for _, fact := range [...]string{"Redundancy", "DeviceFailuresTolerated"} {
			unobservable = append(unobservable, unobservableFact{
				fact: fact, reason: "unsupported", detail: shapeUnrecognised,
			})
		}
	}

	factValues, missing := facts.split()
	absent := sortedStrings(append(extraAbsent, missing...))
	sort.SliceStable(unobservable, func(i, j int) bool {
		return unobservable[i].fact < unobservable[j].fact
	})

	return objectRecord{
		Record: "object",
		Name:   name,
		Facts:  factValues.encode(),
		Names:  poolNames(pool, rows),
		Absent: absent,
		At:     at,
	}, unobservable, nil
}

// statusMessage is `(pool.get("status") or "").strip() or None`: a key that
// is missing, null, empty or whitespace-only states nothing a reader can
// use, so it joins the genuinely-missing on the absent list rather than
// shipping "" as a fact. Interior whitespace is untouched — the degraded
// capture's catalogue prose keeps its embedded newline and tab.
func statusMessage(raw *value) (*value, error) {
	if !truthy(raw) {
		return nil, nil
	}
	if !raw.isString() {
		// The reference strips this member, and a document member that is
		// not a string stops the batch there rather than degrading — the
		// one place this collection is not defensive about a value's type.
		return nil, errors.New("the pool's status member is not a string")
	}
	trimmed := strings.TrimSpace(raw.text)
	if trimmed == "" {
		return nil, nil
	}
	return stringValue(trimmed), nil
}

// poolNames is law 1 for the pool: the guid that survives rename and import,
// the member names as ZFS records them, and the kernel paths a person
// searches for. Attached only when the stable family has something in it —
// a names block whose only family is ephemeral is a join key nobody may
// join on.
func poolNames(pool *value, rows []*vdevRow) json.RawMessage {
	stable := newObject()
	// `is not None`, not truthiness: a pool_guid of 0 is still the pool's
	// identifier.
	if guid := pool.get("pool_guid"); !isNone(guid) {
		stable.set("guid", stringValue(pyStr(guid)))
	}
	devices, kernels := newArray(), newArray()
	for _, row := range rows {
		if !row.isDisk {
			continue
		}
		devices.append(stringValue(row.name))
		if row.kernel != "" {
			kernels.append(stringValue("/dev/" + row.kernel))
		}
	}
	if len(devices.items) > 0 {
		stable.set("devices", devices)
	}
	if stable.members.len() == 0 {
		return nil
	}
	names := newObject()
	names.set("stable", stable)
	if len(kernels.items) > 0 {
		ephemeral := newObject()
		ephemeral.set("kernel", kernels)
		names.set("ephemeral", ephemeral)
	}
	return names.encode()
}

func rowFields(rows []*vdevRow) *value {
	// Always an array, empty when the pool has no vdev tree: [] is a value
	// and never joins the absent list.
	out := newArray()
	for _, row := range rows {
		out.append(row.fields)
	}
	return out
}

func bigOrNil(n *big.Int) *value {
	if n == nil {
		return nil
	}
	return bigValue(n)
}

func keysOf(m *members) []string {
	if m == nil {
		return nil
	}
	return m.keys
}
