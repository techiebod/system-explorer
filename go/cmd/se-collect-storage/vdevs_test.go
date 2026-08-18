package main

import (
	"math/big"
	"testing"
)

func mustDecode(t *testing.T, raw string) *value {
	t.Helper()
	document, err := decodeDocument([]byte(raw))
	if err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return document
}

func walk(t *testing.T, raw string, links *aliasTree) []*vdevRow {
	t.Helper()
	var rows []*vdevRow
	flattenVdevs(mustDecode(t, raw), &rows, links, "data", 1, "")
	return rows
}

func names(rows []*vdevRow) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.name)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A node is dropped iff its vdev_type is "root" or its key is a group name —
// no depth condition on either. The dropped node does not advance depth, so
// the pool's root is transparent and its children are Depth 1.
func TestTheContainerRuleHasNoDepthCondition(t *testing.T) {
	rows := walk(t, `{
	  "pool": {"vdev_type": "root", "vdevs": {
	     "raidz1-0": {"vdev_type": "raidz", "vdevs": {
	        "a": {"vdev_type": "disk"},
	        "spares": {"vdev_type": "disk", "state": "FAULTED"}
	     }},
	     "logs": {"vdevs": {"lg": {"vdev_type": "disk"}}}
	  }}
	}`, nil)

	if got := names(rows); !equal(got, []string{"raidz1-0", "a", "lg"}) {
		t.Fatalf("walk order/membership: %v", got)
	}
	if rows[0].depth != 1 || rows[1].depth != 2 {
		t.Errorf("the root is transparent: depths were %d/%d", rows[0].depth, rows[1].depth)
	}
	// A leaf keyed `spares` inside a raidz is dropped along with its state,
	// so a FAULTED disk so keyed reaches no derived list. That is what the
	// reference does; the docstring implies otherwise.
	if len(unhealthyVdevs(rows).items) != 0 {
		t.Error("a group-keyed leaf emits no row and can therefore be in no list")
	}
	// A group container does not advance depth either: its member sits
	// beside the data vdevs at Depth 1, labelled by the group.
	if rows[2].depth != 1 || rows[2].group != "logs" {
		t.Errorf("group member: depth %d group %q", rows[2].depth, rows[2].group)
	}
}

// Stripe pools omit vdev_type and state entirely; a childless vdev under a
// non-group parent is a plain disk. A node WITH children and no type keeps
// no Type member at all.
func TestTypeIsInferredOnlyForAChildlessNode(t *testing.T) {
	rows := walk(t, `{"parent": {"vdevs": {"leaf": {}}}}`, nil)
	if rows[0].isDisk || rows[0].fields.get("Type") != nil {
		t.Error("a node with children and no vdev_type carries no Type")
	}
	if !rows[1].isDisk {
		t.Error("a childless untyped node is a disk")
	}
	if rows[0].fields.get("State") != nil {
		t.Error("a null must never stand in for a state zpool did not report")
	}
}

func TestResolveKname(t *testing.T) {
	links := newAliasTree()
	links.add("/dev/disk/by-id/a", "sda")
	links.add("/dev/disk/by-partuuid/p", "sdb")
	links.add("/dev/mapper/crypt", "dm-0")

	cases := []struct {
		ref     string
		kname   string
		resolve bool
	}{
		{"/dev/disk/by-id/a", "sda", true},
		{"/dev/sdc1", "sdc1", true},
		{"/dev/mapper/crypt", "dm-0", true},
		{"/dev/mapper/other", "", false},
		{"a", "sda", true},
		{"p", "sdb", true},
		{"sda", "sda", true},   // a bare kernel name is an alias TARGET
		{"dm-0", "dm-0", true}, // including one only /dev/mapper points at
		{"nothing", "", false},
		{"/var/tmp/disk1", "", false},
		// Neither a hit nor a miss: the empty tail suppresses the name
		// fallback AND leaves the row without a Device.
		{"/dev/", "", true},
	}
	for _, c := range cases {
		kname, resolved := resolveKname(c.ref, links)
		if kname != c.kname || resolved != c.resolve {
			t.Errorf("%q -> (%q,%v), want (%q,%v)", c.ref, kname, resolved, c.kname, c.resolve)
		}
	}
}

// nil is "no tree was readable" and an empty tree is "read, holds nothing" —
// one emits a record per disk leaf and the other emits nothing at all.
func TestAnUnreadableTreeIsNotAnEmptyOne(t *testing.T) {
	document := `{"pool": {"vdev_type": "root", "vdevs": {"a": {"vdev_type": "disk"}}}}`
	unreadable := walk(t, document, nil)
	empty := walk(t, document, newAliasTree())
	if unreadable[0].fields.get("Device") != nil || empty[0].fields.get("Device") != nil {
		t.Fatal("neither tree resolves this leaf, so neither row carries a Device")
	}
	// The difference is not on the row; it is which channel the caller opens,
	// and that turns on links being nil.
	if unreadable[0].kernel != "" || empty[0].kernel != "" {
		t.Fatal("no kernel name was resolvable either way")
	}
}

func TestIntOrNilRefusesEverythingIntCannotParse(t *testing.T) {
	cases := map[string]string{ // JSON token -> want, "" meaning nil
		`3`:                     "3",
		`"3"`:                   "3",
		`" 3 "`:                 "3",
		`"+5"`:                  "5",
		`-2`:                    "-2",
		`3.0`:                   "", // a Python float, and int("3.0") raises
		`3.7`:                   "",
		`1e3`:                   "",
		`true`:                  "",
		`false`:                 "",
		`null`:                  "",
		`"-"`:                   "",
		`""`:                    "",
		`"0x10"`:                "",
		`[]`:                    "",
		`{}`:                    "",
		`100000000000000000000`: "100000000000000000000", // past 2^64, kept whole
	}
	for token, want := range cases {
		got := intOrNil(mustDecode(t, token))
		if want == "" {
			if got != nil {
				t.Errorf("%s -> %s, want a dropped member", token, got)
			}
			continue
		}
		if got == nil || got.String() != want {
			t.Errorf("%s -> %v, want %s", token, got, want)
		}
	}
}

func layoutOf(t *testing.T, raw string) (string, int64, bool) {
	t.Helper()
	return redundancy(walk(t, raw, nil))
}

func TestRedundancyIsGradedByTheWeakestDataVdev(t *testing.T) {
	root := func(children string) string {
		return `{"p": {"vdev_type": "root", "vdevs": {` + children + `}}}`
	}
	disk := `{"vdev_type": "disk"}`
	cases := []struct {
		label     string
		document  string
		layout    string
		tolerated int64
		ok        bool
	}{
		{"raidz1", root(`"raidz1-0": {"vdev_type":"raidz","vdevs":{"a":` + disk + `}}`), "raidz1", 1, true},
		{"raidz3", root(`"raidz3-0": {"vdev_type":"raidz","vdevs":{"a":` + disk + `}}`), "raidz3", 3, true},
		{"draid2", root(`"draid2:4d:12c:1s-0": {"vdev_type":"draid","vdevs":{"a":` + disk + `}}`), "draid2", 2, true},
		{"stripe", root(`"d": ` + disk), "stripe", 0, true},
		{"mirror of three", root(`"mirror-0": {"vdev_type":"mirror","vdevs":{"a":` + disk + `,"b":` + disk + `,"c":` + disk + `}}`), "mirror", 2, true},
		{
			// Two mirrors do not lend each other members.
			"two mirrors of two",
			root(`"mirror-0": {"vdev_type":"mirror","vdevs":{"a":` + disk + `,"b":` + disk + `}},
			      "mirror-1": {"vdev_type":"mirror","vdevs":{"c":` + disk + `,"d":` + disk + `}}`),
			"mirror", 1, true,
		},
		{
			// Distinct kinds trigger the join; duplicates are NOT collapsed.
			"stripe + stripe + raidz2",
			root(`"x": ` + disk + `, "y": ` + disk + `, "raidz2-2": {"vdev_type":"raidz","vdevs":{"a":` + disk + `}}`),
			"stripe + stripe + raidz2", 0, true,
		},
		{
			"raidz1 + stripe",
			root(`"raidz1-0": {"vdev_type":"raidz","vdevs":{"a":` + disk + `}}, "z": ` + disk),
			"raidz1 + stripe", 0, true,
		},
		{
			// Groups are skipped and do not close a pending mirror.
			"groups are not data",
			root(`"raidz1-0": {"vdev_type":"raidz","vdevs":{"a":` + disk + `}},
			      "logs": {"vdevs": {"lg": ` + disk + `}},
			      "spares": {"vdevs": {"sp": ` + disk + `}}`),
			"raidz1", 1, true,
		},
		{"empty pool", root(``), "", 0, false},
		{"raidz with no parity digit", root(`"raidz-0": {"vdev_type":"raidz","vdevs":{"a":` + disk + `}}`), "", 0, false},
		{"a raidz name typed something else", root(`"raidz1-0": {"vdev_type":"weird","vdevs":{"a":` + disk + `}}`), "", 0, false},
		{
			// A mirror mid-replace: the second slot is a `replacing` row, so
			// only one member is counted and the whole pool is refused.
			"mirror mid-replace",
			root(`"mirror-0": {"vdev_type":"mirror","vdevs":{"a":` + disk + `,
			       "replacing-1": {"vdev_type":"replacing","vdevs":{"old":` + disk + `,"new":` + disk + `}}}}`),
			"", 0, false,
		},
	}
	for _, c := range cases {
		layout, tolerated, ok := layoutOf(t, c.document)
		if layout != c.layout || tolerated != c.tolerated || ok != c.ok {
			t.Errorf("%s: (%q,%d,%v), want (%q,%d,%v)", c.label, layout, tolerated, ok, c.layout, c.tolerated, c.ok)
		}
	}
}

func TestHealthListsAnswerDifferentQuestions(t *testing.T) {
	rows := walk(t, `{"p": {"vdev_type": "root", "vdevs": {
	   "raidz1-0": {"vdev_type": "raidz", "state": "DEGRADED", "vdevs": {
	      "clean":    {"vdev_type": "disk", "state": "ONLINE"},
	      "offline":  {"vdev_type": "disk", "state": "OFFLINE"},
	      "repaired": {"vdev_type": "disk", "state": "ONLINE", "checksum_errors": 3},
	      "stateless":{"vdev_type": "disk"}
	   }},
	   "spares": {"vdevs": {"sp": {"vdev_type": "disk", "state": "AVAIL"}}}
	}}}`, nil)

	unhealthy := unhealthyVdevs(rows)
	if len(unhealthy.items) != 2 ||
		unhealthy.items[0].text != "raidz1-0" || unhealthy.items[1].text != "offline" {
		t.Errorf("unhealthy: %s", unhealthy.encode())
	}
	errored := vdevsWithErrors(rows)
	if len(errored.items) != 1 || errored.items[0].text != "repaired" {
		t.Errorf("with errors: %s", errored.encode())
	}
}

func TestCapacityJoinsOnlyWhereAllocatedParses(t *testing.T) {
	caps := map[string]vdevCap{}
	collectCaps(mustDecode(t, `{
	  "top":  {"properties": {"size": {"value": "100"}, "allocated": {"value": "40"},
	                          "capacity": {"value": "40"}},
	           "vdevs": {"leaf": {"properties": {"size": {"value": "50"},
	                                             "allocated": {"value": "-"}}}}}
	}`), caps)
	if _, ok := caps["leaf"]; ok {
		t.Error("a leaf reporting '-' for allocated contributes no entry")
	}
	entry, ok := caps["top"]
	if !ok || entry.alloc.Cmp(big.NewInt(40)) != 0 || entry.size.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("top: %v", entry)
	}
}
