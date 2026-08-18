package main

import (
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The group vdevs, closed (storage.py:47). A cache or log device leaving is
// not the pool leaving and a spare standing by protects nothing yet, so a
// group labels its whole subtree and is graded by nothing. Membership is by
// NAME and nothing else — the containers zpool emits carry no vdev_type at
// all — which is why this is a set of keys and never a type test.
var zfsGroupVdevs = map[string]bool{"logs": true, "l2cache": true, "spares": true}

// Parity comes from the vdev's NAME. zpool reports vdev_type "raidz" for
// raidz1, raidz2 and raidz3 alike and carries no nparity member anywhere in
// the document, so the only place the number exists is the name zpool
// assigned ("raidz1-0"). Exactly one digit, anchored at the start:
// draid2:4d:12c:1s-0 is a draid2.
var parityName = regexp.MustCompile(`^(raidz|draid)([0-9])`)

// The alias trees a vdev reference resolves through, in the order the live
// acquisition lists them (storage.py:273). by-id is where zpool's own path
// member points; by-partuuid is how stripe leaves are named; mapper is a
// pool imported over dm/LUKS nodes, whose /dev/mapper name is not its kernel
// name.
var devlinkTrees = [...]string{"/dev/disk/by-id", "/dev/disk/by-partuuid", "/dev/mapper"}

// aliasTree is {alias path: kernel block name} for every device symlink the
// acquisition could see. A nil tree is "no tree was readable" — could-not-
// read, which the caller routes to the unobservable channel — and is a
// different statement from a tree that was read and holds nothing for these
// members, which is a silent absence. The corpus pins both ends.
//
// targets is kept beside the map because the last resolution clause asks
// whether a bare reference appears as an alias TARGET, and only a string
// target can equal a vdev's name.
type aliasTree struct {
	byAlias map[string]string
	targets map[string]bool
}

func newAliasTree() *aliasTree {
	return &aliasTree{byAlias: map[string]string{}, targets: map[string]bool{}}
}

func (t *aliasTree) add(alias, kname string) {
	t.byAlias[alias] = kname
	if kname != "" {
		t.targets[kname] = true
	}
}

// addRaw records a document member whose value is not a string. The
// reference keeps it: a truthy value resolves and is interpolated into the
// Device, a falsy one is no hit at all — and neither can ever equal a vdev
// name, so neither joins the target set.
func (t *aliasTree) addRaw(alias string, target *value) {
	if truthy(target) {
		t.byAlias[alias] = pyStr(target)
		return
	}
	t.byAlias[alias] = ""
}

// vdevRow is one flattened vdev: the record members it publishes, plus the
// handful of readings every downstream derivation asks it for. They are
// extracted once, here, so redundancy and health read what the row states
// rather than re-deriving it from the document a second way.
type vdevRow struct {
	name   string
	depth  int
	fields *value // the emitted row, in the reference's member order

	isDisk bool   // Type == "disk", the gate on Names, Device and the sweep
	kind   string // lower(str(Type or "")) — the redundancy walk's reading
	state  *value // nil when the document reported none
	group  string // "" for a data vdev
	kernel string // the resolved kernel name, "" when unresolved

	readErrors     *big.Int
	writeErrors    *big.Int
	checksumErrors *big.Int
}

// flattenVdevs is the depth-first walk of storage.py:338-418, in document
// order. Two rules carry all the weight:
//
// A node is a CONTAINER — emitting no row — iff its vdev_type is the string
// "root" or its map key is a group name. There is no depth condition on
// either, at any level.
//
// A container does not advance depth, so the pool's root is transparent and
// its children are Depth 1. Depth is therefore "emitted ancestors + 1", not
// tree depth.
func flattenVdevs(nodes *value, out *[]*vdevRow, links *aliasTree, group string, depth int) {
	tree := nodes.object()
	if tree == nil {
		return
	}
	for _, name := range tree.keys {
		node := tree.byKey[name]
		isContainer := node.get("vdev_type").equalsString("root") || zfsGroupVdevs[name]
		nextGroup := group
		if zfsGroupVdevs[name] {
			nextGroup = name
		}
		childDepth := depth
		if !isContainer {
			*out = append(*out, buildRow(name, node, links, nextGroup, depth))
			childDepth = depth + 1
		}
		flattenVdevs(node.get("vdevs"), out, links, nextGroup, childDepth)
	}
}

func buildRow(name string, node *value, links *aliasTree, group string, depth int) *vdevRow {
	// Stripe pools omit vdev_type (and state) on their leaves entirely; a
	// childless vdev under a non-group parent is a plain disk in zpool's own
	// semantics, so it resolves a Device like a typed leaf. A node that HAS
	// children and no type keeps no Type member at all — DESIGN 19 forbids a
	// null standing in for an absent key.
	vdevType := node.get("vdev_type")
	if isNone(vdevType) && !truthy(node.get("vdevs")) {
		vdevType = stringValue("disk")
	}
	if isNone(vdevType) {
		vdevType = nil
	}

	row := &vdevRow{
		name:   name,
		depth:  depth,
		fields: newObject(),
		isDisk: vdevType.equalsString("disk"),
		state:  node.get("state"),
	}
	if isNone(row.state) {
		row.state = nil
	}
	if truthy(vdevType) {
		row.kind = strings.ToLower(pyStr(vdevType))
	}
	if group != "data" {
		row.group = group
	}

	row.fields.set("Name", stringValue(name))
	row.fields.set("Depth", intValue(int64(depth)))
	row.fields.set("Type", vdevType)
	row.fields.set("State", row.state)

	if row.isDisk {
		// zpool's own path member is authoritative and the map key is only
		// a fallback (some hosts lack the matching by-id link). links being
		// nil means the acquisition itself was unreadable, which the CALLER
		// turns into one unobservable record per leaf — a missing Device
		// here must never impersonate absence.
		kname, resolved := "", false
		if links != nil {
			if path := node.get("path"); truthy(path) {
				kname, resolved = resolveKname(pyStr(path), links)
			}
			if !resolved {
				kname, _ = resolveKname(name, links)
			}
		}
		row.kernel = kname
		if kname != "" {
			row.fields.set("Device", stringValue("block-device:"+kname))
		}

		// Law 1, per leaf: the stable names a collator joins pool members to
		// block devices on, plus the kernel path a person searches for. The
		// guid is stringified because a vdev guid is a full u64; the devid
		// is NOT — that asymmetry is the reference's (storage.py:392 vs 396)
		// and is reproduced rather than tidied.
		stable := newObject()
		if guid := node.get("guid"); !isNone(guid) {
			stable.set("guid", stringValue(pyStr(guid)))
		}
		if strings.HasPrefix(name, "wwn-") {
			stable.set("wwn", stringValue(name))
		}
		if devid := node.get("devid"); truthy(devid) {
			stable.set("devid", devid)
		}
		leafNames := newObject()
		if stable.members.len() > 0 {
			leafNames.set("stable", stable)
		}
		if kname != "" {
			ephemeral := newObject()
			ephemeral.set("kernel", stringValue("/dev/"+kname))
			leafNames.set("ephemeral", ephemeral)
		}
		if leafNames.members.len() > 0 {
			row.fields.set("Names", leafNames)
		}
	}

	if row.group != "" {
		row.fields.set("Group", stringValue(row.group))
	}
	row.readErrors = intOrNil(node.get("read_errors"))
	row.writeErrors = intOrNil(node.get("write_errors"))
	row.checksumErrors = intOrNil(node.get("checksum_errors"))
	setBig(row.fields, "ReadErrors", row.readErrors)
	setBig(row.fields, "WriteErrors", row.writeErrors)
	setBig(row.fields, "ChecksumErrors", row.checksumErrors)
	return row
}

func setBig(target *value, key string, n *big.Int) {
	if n == nil {
		return
	}
	target.set(key, bigValue(n))
}

// resolveKname maps a vdev path or name to a kernel block name through the
// devlinks map ONLY (storage.py:308-335). No filesystem read happens here:
// under replay the map is the CAPTURE's, so the answer stays a fact about
// the captured machine rather than the one replaying it.
//
// The second return distinguishes "no answer" from an answer of "" — the
// /dev/ case yields an empty tail, which is not a hit and also suppresses
// the name fallback, exactly as the reference's None-vs-"" test does.
func resolveKname(ref string, links *aliasTree) (string, bool) {
	if strings.HasPrefix(ref, "/") {
		if kname := links.byAlias[ref]; kname != "" {
			return kname, true
		}
		// A node named directly — /dev/sdc1, /dev/vdb — dereferences
		// nothing: the basename IS the kernel name, which is what lets a
		// virtio disk (which grows no by-id link) still resolve.
		tail := strings.TrimPrefix(ref, "/dev/")
		if strings.HasPrefix(ref, "/dev/") && !strings.Contains(tail, "/") {
			return tail, true
		}
		return "", false
	}
	// The bare-name lookup searches by-id and by-partuuid only; a mapper
	// alias resolves solely through an absolute path.
	for _, tree := range devlinkTrees[:2] {
		if kname := links.byAlias[tree+"/"+ref]; kname != "" {
			return kname, true
		}
	}
	// A bare kernel name (a pool imported as plain sdc) appears in the map
	// as an alias TARGET, never as an alias.
	if links.targets[ref] {
		return ref, true
	}
	return "", false
}

// ── capacity enrichment from zpool list -v ──────────────────────────────

type vdevCap struct {
	size     *big.Int
	alloc    *big.Int
	capacity *big.Int
}

// collectCaps recurses the LIST document's vdev tree for one pool, keyed by
// vdev name. An entry exists only where `allocated` parses, which is what
// excludes the leaves `zpool list -v` reports as "-"; last write wins, as
// the reference's dict assignment does.
func collectCaps(nodes *value, caps map[string]vdevCap) {
	tree := nodes.object()
	if tree == nil {
		return
	}
	for _, name := range tree.keys {
		node := tree.byKey[name]
		props := node.get("properties")
		if alloc := intOrNil(propValue(props, "allocated")); alloc != nil {
			caps[name] = vdevCap{
				size:     intOrNil(propValue(props, "size")),
				alloc:    alloc,
				capacity: intOrNil(propValue(props, "capacity")),
			}
		}
		collectCaps(node.get("vdevs"), caps)
	}
}

// propValue is storage.py:457-458 — `(props[key] or {})["value"] or None`.
// The trailing `or None` is why an empty-string property reads as absent
// while "0" survives as the integer zero.
func propValue(props *value, key string) *value {
	entry := props.get(key)
	if !truthy(entry) {
		return nil
	}
	member := entry.get("value")
	if !truthy(member) {
		return nil
	}
	return member
}

func mergeCaps(rows []*vdevRow, caps map[string]vdevCap) {
	for _, row := range rows {
		entry, ok := caps[row.name]
		if !ok {
			continue
		}
		// A member can still be nil (a leaf reporting "-" for size): the
		// same null-is-no-statement rule as the walk's own members.
		setBig(row.fields, "SizeBytes", entry.size)
		setBig(row.fields, "AllocatedBytes", entry.alloc)
		setBig(row.fields, "CapacityPercent", entry.capacity)
	}
}

// ── health ──────────────────────────────────────────────────────────────

// unhealthyVdevs lists every row whose state is neither ONLINE nor AVAIL nor
// absent, in walk order. Each exclusion is deliberate: AVAIL is a spare
// standing by and protecting nothing yet, and a row that reported no state
// at all made no statement to disagree with. Group members are included —
// a faulted cache disk is still a faulted device.
func unhealthyVdevs(rows []*vdevRow) *value {
	out := newArray()
	for _, row := range rows {
		if row.state == nil || row.state.equalsString("ONLINE") || row.state.equalsString("AVAIL") {
			continue
		}
		out.append(stringValue(row.name))
	}
	return out
}

// vdevsWithErrors lists every row carrying a non-zero counter, in walk
// order. A missing counter is zero; ANY of the three qualifies. This answers
// a different question from unhealthyVdevs and shares no membership rule
// with it: the degraded capture's OFFLINE member has no errors, and its
// error-carrying member is ONLINE.
func vdevsWithErrors(rows []*vdevRow) *value {
	out := newArray()
	for _, row := range rows {
		if nonZero(row.readErrors) || nonZero(row.writeErrors) || nonZero(row.checksumErrors) {
			out.append(stringValue(row.name))
		}
	}
	return out
}

func nonZero(n *big.Int) bool { return n != nil && n.Sign() != 0 }

// ── redundancy ──────────────────────────────────────────────────────────

// redundancy answers (how this pool is laid out, how many whole devices it
// survives losing) over the FLATTENED rows — storage.py:612-672.
//
// A pool is only as redundant as its weakest data vdev, because losing any
// one of them loses the pool, so a mixed layout is named in full and graded
// by the minimum. The third return is false where the walk cannot read the
// layout at all, and the caller must then claim nothing: an unrecognised
// top-level shape is could-not-read, and claiming a tolerance this walk
// cannot justify is the direction that gets somebody hurt.
func redundancy(rows []*vdevRow) (layout string, tolerated int64, ok bool) {
	var kinds []string
	var tolerance []int64
	current, memberCount := "", 0

	// closeVdev finishes the vdev the walk just left. False where it cannot
	// be read — a mirror with one counted member is unreadable, not
	// zero-tolerant, and that refusal propagates to the whole pool.
	closeVdev := func() bool {
		if current == "" {
			return true
		}
		if current == "mirror" {
			if memberCount < 2 {
				return false
			}
			kinds = append(kinds, "mirror")
			tolerance = append(tolerance, int64(memberCount-1))
		}
		current, memberCount = "", 0
		return true
	}

	for _, row := range rows {
		if row.group != "" {
			continue // logs, l2cache, spares: not data vdevs
		}
		switch {
		case row.depth == 1:
			if !closeVdev() {
				return "", 0, false
			}
			switch {
			case row.kind == "disk":
				kinds = append(kinds, "stripe")
				tolerance = append(tolerance, 0)
			case row.kind == "mirror":
				current = "mirror"
			default:
				parity := parityName.FindStringSubmatch(row.name)
				if parity == nil || (row.kind != "raidz" && row.kind != "draid") {
					return "", 0, false
				}
				kinds = append(kinds, parity[0])
				digit, _ := strconv.ParseInt(parity[2], 10, 64)
				tolerance = append(tolerance, digit)
			}
		case row.depth == 2 && current == "mirror" && row.kind == "disk":
			// Members are counted as the walk passes them, scoped to the
			// mirror currently open, or a pool of two mirrors would credit
			// each with the other's disks.
			memberCount++
		}
	}
	if !closeVdev() || len(kinds) == 0 {
		return "", 0, false
	}
	// The join keeps duplicates; only the TEST dedupes. Two bare disks and
	// a raidz2 read "stripe + stripe + raidz2", because the layout names
	// what is there rather than the set of things that are there.
	if distinctCount(kinds) == 1 {
		layout = kinds[0]
	} else {
		layout = strings.Join(kinds, " + ")
	}
	tolerated = tolerance[0]
	for _, t := range tolerance[1:] {
		if t < tolerated {
			tolerated = t
		}
	}
	return layout, tolerated, true
}

func distinctCount(values []string) int {
	seen := map[string]bool{}
	for _, v := range values {
		seen[v] = true
	}
	return len(seen)
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
