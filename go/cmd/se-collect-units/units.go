package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ── naming the workload behind a transient scope ─────────────────────
//
// Container and VM runtimes register their workloads as transient scopes whose
// names carry an id and nothing an operator recognises. The unit itself holds
// no name — a docker scope's Description is dockerd's own "libcontainer
// container <the same id>" — so each runtime gets exactly the handle its own
// naming actually supports, and no more.
//
// Docker's naming supports the short id and no more: an edge would need
// container:<name>, and this collector cannot know the name without talking to
// Docker, which is not its acquisition path — so the id is published under the
// SAME fact name the docker collection uses and the two join on that value.
// libvirt's supports the domain name in full, because libvirt names the scope
// qemu-<domid>-<domain> and systemd escapes it, which is why that one alone
// mints a real cross-subsystem edge.
var (
	dockerScope  = regexp.MustCompile(`^docker-([0-9a-f]{12})[0-9a-f]*\.scope$`)
	machineScope = regexp.MustCompile(`^machine-qemu\\x2d\d+\\x2d(.+)\.scope$`)
	unitEscape   = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
)

// unescapeUnitName undoes systemd's C-escaping of a unit name: \x2d for '-',
// and so on. Only the \xNN form appears in machine and mount unit names.
func unescapeUnitName(name string) string {
	return unitEscape.ReplaceAllStringFunc(name, func(match string) string {
		value, err := strconv.ParseUint(match[2:], 16, 8)
		if err != nil {
			return match
		}
		return string(rune(value))
	})
}

// The unit types that live in the cgroup tree, and the interface each one's
// Slice property is read from.
var sliceIfaces = map[string]string{
	"service": "org.freedesktop.systemd1.Service",
	"scope":   "org.freedesktop.systemd1.Scope",
}

// Presentation order for units outside the cgroup tree — most diagnostic
// first, the device-unit wall last.
var tailOrder = []string{"socket", "timer", "path", "mount", "automount", "swap", "target", "device"}

// The directive an author writes -> the fact its unresolvable references land
// in. Grouped by consequence, because that is what separates a start-blocking
// defect from a documented no-op; the exact directive stays in the VALUE, so
// nothing about which word was written is lost.
var absentReferenceFacts = map[string]string{
	"Requires":  "MissingRequirements",
	"Requisite": "MissingRequirements",
	"BindsTo":   "MissingRequirements",
	"Wants":     "MissingWants",
	"Upholds":   "MissingWants",
	"After":     "MissingOrdering",
	"Before":    "MissingOrdering",
}

// The property on the ABSENT unit that names who wrote each directive. This is
// the backwards arrow: WantedBy on a name systemd could not load lists the
// units whose files say Wants= that name.
var absentReferenceInverse = map[string]string{
	"RequiredBy":  "Requires",
	"RequisiteOf": "Requisite",
	"BoundBy":     "BindsTo",
	"WantedBy":    "Wants",
	"UpheldBy":    "Upholds",
	"Before":      "After",
	"After":       "Before",
}

// Every reverse property that names a unit which wrote SOMETHING about this
// name, used only for the absent name's own page. Deliberately a superset of
// absentReferenceInverse, because the two maps answer different questions:
// that one is "what did an author write that has a consequence they can fix",
// which is why Conflicts= and PartOf= are excluded from it; this one is "why
// is this inert entry in the listing at all", and for a name whose only
// referrers conflict with it those two directives are the entire answer.
var referrerProperties = func() map[string]string {
	out := map[string]string{"ConsistsOf": "PartOf", "ConflictedBy": "Conflicts"}
	for property, directive := range absentReferenceInverse {
		out[property] = directive
	}
	return out
}()

// The bound: one probe per not-found unit, so the cost is len(not-found),
// which was 23-42 on every host measured. The cap is defensive rather than
// expected — a host with a pathological dependency graph must not turn a
// collection into hundreds of round trips. Units beyond it are NOT quietly
// dropped: each is stated as unobservable, because "not probed" and "nothing
// references it" are the two answers this collector exists to keep apart.
const missingUnitProbeLimit = 200

// How many per-unit reads are in flight at once. This side spawns busctl per
// call, so the pool is what keeps a 735-unit host from spawning two hundred
// processes at the same instant. Bounded rather than unbounded, and the results
// are keyed by unit so the order they finish in cannot reach the stream.
//
// The reference now uses the same bound, for a reason this side does not have.
// Sharing one bus connection was taken to make the fan-out free; measured
// 2026-08-19, it is where the fan-out costs most, because dbus_fast lets a
// non-blocking send's EAGAIN escape and the failed read spells itself as "no
// slice". So both sides bound this, and neither does so for the other's reason.
const probeParallelism = 8

func unitType(name string) string {
	if cut := strings.LastIndexByte(name, '.'); cut >= 0 {
		return name[cut+1:]
	}
	return name
}

// sliceParent reads a slice's parent out of its own name: system-getty.slice
// lives in system.slice, a top-level slice lives in -.slice, and -.slice is
// the root. An escaped dash (\x2d) is not a separator and survives the split,
// which is why the cut is on the last literal '-' of the stem.
func sliceParent(name string) string {
	if name == "-.slice" {
		return ""
	}
	stem := strings.TrimSuffix(name, ".slice")
	if cut := strings.LastIndexByte(stem, '-'); cut >= 0 {
		return stem[:cut] + ".slice"
	}
	return "-.slice"
}

// workloadFacts is whatever the scope's own name can prove about the workload
// inside it.
func workloadFacts(name string, facts *factRow) {
	if match := dockerScope.FindStringSubmatch(name); match != nil {
		facts.setString("ContainerID", match[1])
		return
	}
	if match := machineScope.FindStringSubmatch(name); match != nil {
		facts.setString("MachineName", unescapeUnitName(match[1]))
	}
}

// referenceFor formats one referencing unit's absent-reference facts:
// {fact: ["<absent unit> (<Directive>=)", …]}. One formatter for the whole
// walk, sorted so two collections of an unchanged host do not reorder a value.
func referenceFor(pairs []directiveReference) map[string][]string {
	grouped := map[string]map[string]bool{}
	for _, pair := range pairs {
		fact, wanted := absentReferenceFacts[pair.directive]
		if !wanted {
			continue
		}
		if grouped[fact] == nil {
			grouped[fact] = map[string]bool{}
		}
		grouped[fact][fmt.Sprintf("%s (%s=)", pair.other, pair.directive)] = true
	}
	out := map[string][]string{}
	for fact, values := range grouped {
		out[fact] = sortedKeys(values)
	}
	return out
}

type directiveReference struct{ directive, other string }

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// referencedBy is the same edges read from the absent name's end: the answer
// to the only question a reader can arrive at one of these rows with. A unit
// systemd could not load has no fragment, no cgroup and no runtime of any
// kind; what it HAS is the reason it is listed at all, which is that other
// units name it.
func referencedBy(properties map[string][]string) []string {
	found := map[string]bool{}
	for property, directive := range referrerProperties {
		for _, referrer := range properties[property] {
			found[fmt.Sprintf("%s (%s=)", referrer, directive)] = true
		}
	}
	if len(found) == 0 {
		return nil
	}
	return sortedKeys(found)
}

// absentProbe is one not-found unit's reading: its reverse properties, or why
// they could not be read.
//
// A not-found unit is the one thing on this bus most likely to disappear
// between being listed and being asked about: systemd keeps its Unit object
// only while something references it, so a reload landing in that window
// collects it and the path 404s. That is a reading that did not happen, never
// a unit nothing references — hence a reason string rather than an empty map.
type absentProbe struct {
	name       string
	properties map[string][]string
	reason     string
}

// absentReferences walks the arrow BACKWARDS, which is the whole reason it is
// affordable. After=/Wants=/Requires= are per-unit properties and probing
// every unit for them would be one round trip per unit, several hundred on an
// ordinary host. But systemd stores each dependency together with its inverse,
// and a not-found unit still has a Unit object with the inverse side populated
// — that is WHY systemd lists it at all — so the probe is one GetAll per
// NOT-FOUND unit and it yields precisely the map wanted.
//
// The two returns are different subjects on purpose. Facts about a reference
// land on the unit that WROTE it, which is the row with a fragment and an
// owner. The absent name's own row gets the other half of the same walk: who
// references it when the probe worked, and why that is unknown when it did
// not. Those two are mutually exclusive by construction — one map, never both
// keys — because "nobody references this" and "nobody could be asked" are the
// pair this collector exists to keep apart.
// A per-unit read that failed because the VARIANT never staged it, kept apart
// from one that failed because a unit vanished. The second is ordinary and
// costs that unit a fact; the first is a broken capture, and swallowing it
// would let a corpus with a missing reply replay as a host whose units happened
// to be quieter — a wrong answer with nothing to say it was one. Recorded
// rather than raised at the call site because the walks below are concurrent
// and the first failure is the one worth reporting.
type uncapturedGuard struct {
	mu    sync.Mutex
	first error
}

func (g *uncapturedGuard) note(err error) {
	if !isUncaptured(err) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.first == nil {
		g.first = err
	}
}

func absentReferences(src source, stderr writer, rows []unitRow, guard *uncapturedGuard) (map[string][]directiveReference, map[string]absentFacts) {
	type absent struct{ name, path string }
	var listed []absent
	for _, row := range rows {
		if row.load == "not-found" {
			listed = append(listed, absent{row.name, row.path})
		}
	}
	sort.Slice(listed, func(i, j int) bool {
		if listed[i].name != listed[j].name {
			return listed[i].name < listed[j].name
		}
		return listed[i].path < listed[j].path
	})

	byAbsent := map[string]absentFacts{}
	for _, entry := range listed[min(len(listed), missingUnitProbeLimit):] {
		byAbsent[entry.name] = absentFacts{unobservable: fmt.Sprintf(
			"this host lists %d units it could not load, more than the %d one "+
				"collection will probe, and this name was not among those probed "+
				"— so which units reference it is unread here, not none",
			len(listed), missingUnitProbeLimit)}
	}

	probed := listed[:min(len(listed), missingUnitProbeLimit)]
	results := make([]absentProbe, len(probed))
	var wait sync.WaitGroup
	tickets := make(chan struct{}, probeParallelism)
	for index, entry := range probed {
		wait.Add(1)
		go func(index int, entry absent) {
			defer wait.Done()
			tickets <- struct{}{}
			defer func() { <-tickets }()
			raw, err := src.unitProperties(entry.path)
			if err == nil {
				var properties map[string][]string
				properties, err = decodeStringListProperties(raw)
				if err == nil {
					results[index] = absentProbe{name: entry.name, properties: properties}
					return
				}
			}
			// The error's KIND is kept, not its message: it is the part that
			// distinguishes a denied call from a vanished one, and the part
			// that carries no interpolated payload. Whatever busctl said goes
			// to stderr, where a person debugging can read it.
			fmt.Fprintf(stderr, "units: %s: %v\n", entry.name, err)
			guard.note(err)
			results[index] = absentProbe{name: entry.name, reason: probeFailure(err)}
		}(index, entry)
	}
	wait.Wait()

	pairs := map[string][]directiveReference{}
	for _, result := range results {
		if result.properties == nil {
			byAbsent[result.name] = absentFacts{unobservable: fmt.Sprintf(
				"the dependency properties of this absent name could not be read "+
					"(%s), so which units reference it is unknown rather than none",
				result.reason)}
			continue
		}
		// Stored only when it found something: a probe that ran and turned up
		// no referrer leaves BOTH facts absent, and that pair is itself the
		// answer — the unobservable fact marks the reading that never
		// happened, so its absence beside an absent ReferencedBy says the
		// question was asked and came back empty.
		if found := referencedBy(result.properties); found != nil {
			byAbsent[result.name] = absentFacts{referencedBy: found}
		}
		for property, directive := range absentReferenceInverse {
			for _, referrer := range result.properties[property] {
				pairs[referrer] = append(pairs[referrer],
					directiveReference{directive: directive, other: result.name})
			}
		}
	}

	return pairs, byAbsent
}

// absentFacts is what a row for a name systemd could not load carries, and the
// two members are mutually exclusive by construction — one or the other, never
// both. "Nobody references this" and "nobody could be asked" are the pair this
// collector exists to keep apart, and a shape that could carry both at once
// would let a reader take the empty one for an answer.
//
// They are separate members rather than one map because they are separate
// TYPES on the wire: ReferencedBy is a list of referrers and the unobservable
// reason is one sentence, and a port that published the sentence as a
// one-element list would be wrong under typed equality while looking right in
// any dynamic reader.
type absentFacts struct {
	referencedBy []string
	unobservable string
}

// probeFailure names a failed probe in the one word that separates the two
// conditions, and never in the words of whatever tool reported it: a decline's
// detail travels to a hub and out over MCP, and busctl's message interpolates
// the object path, which carries the unit's name.
func probeFailure(err error) string {
	if isUncaptured(err) {
		return "NotCaptured"
	}
	return "CallFailed"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// row is one emitted object before it becomes a record: its native name, the
// type its name declares, and its facts.
type row struct {
	name  string
	kind  string
	facts *factRow
	// Facts this row could not READ, as opposed to facts it does not have.
	// DESIGN 19 gives those two separate channels and this collector used to
	// spell both as a missing fact — which for Slice means "accounts to no
	// slice", a positive claim about the machine. Ruled 2026-08-19.
	unobservable []unobservable
}

// unobservable is one could-not-read, named per fact. `reason` is the decline
// vocabulary minus `absent`, because could-not-read-because-it-is-not-there is
// the absent list's statement and lives on its own channel.
type unobservable struct {
	fact, reason, detail string
}

// buildRows is the whole derivation: four documents in, the collection's rows
// out, in the order the reference emits them.
func buildRows(src source, stderr writer) ([]row, error) {
	listing, err := src.listUnits()
	if err != nil {
		return nil, err
	}
	rows, err := decodeListUnits(listing)
	if err != nil {
		return nil, err
	}

	// Which units exist as a FILE, in one call rather than a FragmentPath read
	// per unit. The distinction is the point: systemd synthesises a .mount
	// unit for anything mounted outside its control, and such a unit has no
	// fragment — so RequiresMountsFor= against it degrades to an ordering hint
	// or nothing at all, silently.
	//
	// A failure here is NOT a statement about the host. An older systemd, or a
	// denied call, leaves the set empty and the claim unmade, because a
	// collector that could not read the file list would otherwise accuse every
	// mount on the machine of being synthesised.
	haveFile := map[string]bool{}
	if raw, err := src.listUnitFiles(); err != nil {
		fmt.Fprintln(stderr, "units: ListUnitFiles:", err)
	} else if names, err := decodeUnitFileNames(raw); err != nil {
		fmt.Fprintln(stderr, "units: ListUnitFiles:", err)
	} else {
		haveFile = names
	}

	// Before the row loop, because a row's facts must be complete when it is
	// built: a fact merged afterwards would reach a consumer with nothing
	// behind it.
	// A capture that staged the listing and not everything the listing names is
	// a broken capture. The two per-unit walks below both survive a failed read
	// on purpose — a unit really can vanish between the listing and the probe —
	// so nothing else would notice.
	guard := &uncapturedGuard{}
	byReferrer, byAbsent := absentReferences(src, stderr, rows, guard)

	// The reference sorts the listing before it walks it, and unit names are
	// unique within one ListUnits reply, so a comparison on the name alone
	// reproduces that order. The remaining string members break a tie that
	// systemd does not produce — kept so a duplicated name orders the same way
	// on both sides rather than by whichever arrived first.
	ordered := append([]unitRow(nil), rows...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		for _, pair := range [][2]string{
			{a.name, b.name}, {a.description, b.description},
			{a.load, b.load}, {a.active, b.active}, {a.sub, b.sub},
			{a.following, b.following}, {a.path, b.path},
		} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return false
	})

	items := map[string]*row{}
	order := make([]string, 0, len(ordered))
	paths := map[string]string{}
	for _, entry := range ordered {
		facts := newFactRow()
		facts.setString("LoadState", entry.load)
		facts.setString("ActiveState", entry.active)
		facts.setString("SubState", entry.sub)
		facts.setString("Description", entry.description)
		// Mounts only, deliberately. A .scope or .slice is runtime by nature
		// and flagging those would be noise; a .mount that nothing wrote a
		// file for is the case where a dependency quietly does not exist. Only
		// claimed when the file list was actually read, so a denied
		// ListUnitFiles stays silent instead of accusing every unit.
		if len(haveFile) > 0 && strings.HasSuffix(entry.name, ".mount") && !haveFile[entry.name] {
			facts.setBool("RuntimeSynthesised", true)
		}
		workloadFacts(entry.name, facts)
		// What this unit names that systemd could not load — on the row,
		// because an operator sorting a units page for configuration debt
		// cannot open eight hundred units to find the four that carry it.
		for fact, values := range referenceFor(byReferrer[entry.name]) {
			facts.setStrings(fact, values)
		}
		// And, on a row for a name systemd could not load, who asked for it —
		// the only thing such a row can say beyond the fact of its own
		// absence, and the reason an operator keeps these rows at all.
		if found, absent := byAbsent[entry.name]; absent {
			if found.referencedBy != nil {
				facts.setStrings("ReferencedBy", found.referencedBy)
			}
			if found.unobservable != "" {
				facts.setString("MissingReferenceUnobservable", found.unobservable)
			}
		}
		items[entry.name] = &row{name: entry.name, kind: unitType(entry.name), facts: facts}
		order = append(order, entry.name)
		paths[entry.name] = entry.path
	}

	sliceOf, sliceUnreadable := readSlices(src, stderr, order, paths, guard)
	if guard.first != nil {
		return nil, guard.first
	}

	children := map[string][]string{}
	var orphans []string
	for _, name := range order {
		var parent string
		switch kind := unitType(name); {
		case kind == "slice":
			parent = sliceParent(name)
		case sliceIfaces[kind] != "":
			parent = sliceOf[name]
			if parent != "" {
				items[name].facts.setString("Slice", parent)
			} else if problem := sliceUnreadable[name]; problem != "" {
				// A reading that did not happen, on its own channel. Without
				// this the row is indistinguishable from a unit that accounts
				// to no slice — which is a positive claim about the machine,
				// not a gap (DESIGN 19; ruled 2026-08-19).
				items[name].unobservable = append(items[name].unobservable,
					unobservable{
						fact:   "Slice",
						reason: "unavailable",
						detail: "the unit's Slice property did not answer: " + problem,
					})
			}
		default:
			continue
		}
		if _, known := items[parent]; known {
			children[parent] = append(children[parent], name)
		} else if name != "-.slice" {
			orphans = append(orphans, name)
		}
	}

	// Depth-first from the root slice: the systemctl-status tree an operator
	// sees at the top of `systemctl status`. Nothing on the wire carries the
	// depth — a stream's record order is not significant (DESIGN 19) — so this
	// is reproduced because the order is what the collection IS, and it is
	// pinned by a test here rather than by the corpus, which cannot see it.
	var emitted []row
	seen := map[string]bool{}
	var walk func(string)
	walk = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		emitted = append(emitted, *items[name])
		kids := append([]string(nil), children[name]...)
		sort.Strings(kids)
		for _, child := range kids {
			walk(child)
		}
	}
	var roots []string
	if _, hasRoot := items["-.slice"]; hasRoot {
		roots = append(roots, "-.slice")
	}
	sort.Strings(orphans)
	roots = append(roots, orphans...)
	for _, root := range roots {
		walk(root)
	}

	var tail []row
	for _, name := range order {
		if !seen[name] {
			tail = append(tail, *items[name])
		}
	}
	sort.SliceStable(tail, func(i, j int) bool {
		a, b := tailRank(tail[i].kind), tailRank(tail[j].kind)
		if a != b {
			return a < b
		}
		if tail[i].kind != tail[j].kind {
			return tail[i].kind < tail[j].kind
		}
		return tail[i].name < tail[j].name
	})
	return append(emitted, tail...), nil
}

func tailRank(kind string) int {
	for index, known := range tailOrder {
		if known == kind {
			return index
		}
	}
	return len(tailOrder)
}

// readSlices asks each service and scope which slice it accounts to. One
// property read per unit rather than a walk of cgroupfs, and a failure on any
// one of them costs that unit its Slice fact and nothing else — a unit can
// vanish between the listing and the read, and a collection that failed over
// it would report a whole host as unreadable because one transient scope ended.
// The second return is why a unit's Slice could not be read, keyed by unit. It
// used to be stderr alone, so a consumer saw a row with no Slice and could not
// tell that from a unit which accounts to none.
func readSlices(src source, stderr writer, order []string, paths map[string]string, guard *uncapturedGuard) (map[string]string, map[string]string) {
	type answer struct{ name, slice, problem string }
	var wanted []string
	for _, name := range order {
		if sliceIfaces[unitType(name)] != "" {
			wanted = append(wanted, name)
		}
	}
	answers := make([]answer, len(wanted))
	var wait sync.WaitGroup
	tickets := make(chan struct{}, probeParallelism)
	for index, name := range wanted {
		wait.Add(1)
		go func(index int, name string) {
			defer wait.Done()
			tickets <- struct{}{}
			defer func() { <-tickets }()
			answers[index] = answer{name: name}
			raw, err := src.unitSlice(paths[name], sliceIfaces[unitType(name)])
			if err != nil {
				fmt.Fprintf(stderr, "units: %s: Slice: %v\n", name, err)
				guard.note(err)
				answers[index] = answer{name: name, problem: "the property read failed"}
				return
			}
			value, err := decodeStringProperty(raw)
			if err != nil {
				fmt.Fprintf(stderr, "units: %s: Slice: %v\n", name, err)
				answers[index] = answer{name: name, problem: "the property did not decode"}
				return
			}
			answers[index] = answer{name: name, slice: value}
		}(index, name)
	}
	wait.Wait()
	out := make(map[string]string, len(answers))
	unreadable := map[string]string{}
	for _, got := range answers {
		// The empty string is systemd's answer for a unit that accounts to no
		// slice — a not-found service answers exactly that — and an empty read
		// is not a slice membership, so it becomes no fact rather than a blank
		// one.
		if got.slice != "" {
			out[got.name] = got.slice
		}
		if got.problem != "" {
			unreadable[got.name] = got.problem
		}
	}
	return out, unreadable
}
