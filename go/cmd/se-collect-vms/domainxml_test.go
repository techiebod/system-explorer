package main

import (
	"reflect"
	"testing"
)

// The tap walk is a path, not a search, and each case below is a shape that
// separates the two. ElementTree's `findall("./devices/interface")` and
// `find("target")` are both literal, and a port that searched the document
// for `target` elements instead would attribute a disk's target device to a
// NIC — the one fact whose whole purpose is attributing a host device to a
// workload.
func TestHostTapsReadsTheInterfacePathAndNothingElse(t *testing.T) {
	cases := []struct {
		name     string
		document string
		want     []string
	}{
		{
			"a NIC with a tap",
			`<domain><devices><interface><target dev="vnet4"/></interface></devices></domain>`,
			[]string{"vnet4"},
		},
		{
			// The committed corpus's shape: a guest on a libvirt-managed
			// network names no host device, and empty is the truth rather
			// than a gap.
			"a NIC on a managed network",
			`<domain><devices><interface><source network="default"/></interface></devices></domain>`,
			nil,
		},
		{
			// `<target dev="vda"/>` under a disk is a GUEST device name. A
			// search for target elements would publish vda as a host tap and
			// hand an operator a device that does not exist on the host.
			"a disk's target is not a NIC's",
			`<domain><devices><disk><target dev="vda" bus="virtio"/></disk></devices></domain>`,
			nil,
		},
		{
			// find() takes the FIRST direct target child; a second is ignored
			// rather than overwriting it.
			"two targets on one NIC",
			`<domain><devices><interface><target dev="vnet1"/><target dev="vnet2"/></interface></devices></domain>`,
			[]string{"vnet1"},
		},
		{
			// `if target is not None and target.get("dev")`: the element being
			// there is not the same as it naming something.
			"a target with no dev",
			`<domain><devices><interface><target/></interface></devices></domain>`,
			nil,
		},
		{
			"sorted, and one entry per device",
			`<domain><devices><interface><target dev="vnet9"/></interface>` +
				`<interface><target dev="vnet2"/></interface>` +
				`<interface><target dev="vnet9"/></interface></devices></domain>`,
			[]string{"vnet2", "vnet9"},
		},
		{
			// An interface nested deeper than devices/interface is not a NIC
			// of this domain — a <qemu:commandline> block or a malformed
			// definition can carry one, and the path is what refuses it.
			"a nested interface is not a device",
			`<domain><devices><hostdev><devices><interface><target dev="vnet5"/>` +
				`</interface></devices></hostdev></devices></domain>`,
			nil,
		},
		{
			// A namespaced tag is `{uri}target` to ElementTree, which is not
			// the string it searches for. Without the check, libvirt's own
			// extensions would be read as devices by this port and by nothing
			// else.
			"a namespaced target is a different tag",
			`<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0">` +
				`<devices><interface><qemu:target dev="vnet6"/></interface></devices></domain>`,
			nil,
		},
		{
			// ElementTree raises before it yields a single element, so the
			// reference's `except ET.ParseError` returns EMPTY device lists —
			// not the elements it read before the break.
			"a truncated document yields nothing at all",
			`<domain><devices><interface><target dev="vnet4"/></interface>`,
			nil,
		},
		{
			"an empty document is `no element found`",
			``,
			nil,
		},
		{
			"junk after the document element is refused whole",
			`<domain><devices><interface><target dev="vnet4"/></interface></devices></domain><domain/>`,
			nil,
		},
	}
	for _, c := range cases {
		if got := hostTaps(c.document); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: hostTaps = %v, want %v", c.name, got, c.want)
		}
	}
}

// The address set, which is one set across every interface rather than a list
// per NIC: a guest answering on one address through two interfaces has one
// address, and the reference's own comprehension says so.
func TestDomainAddressesAreOneSortedSetAcrossInterfaces(t *testing.T) {
	document, err := decodeDocument([]byte(
		`{"aa": ["10.0.0.2", "10.0.0.10"], "bb": ["10.0.0.2"], "cc": []}`))
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := domainAddresses(document)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.10", "10.0.0.2"}
	if !reflect.DeepEqual(addresses, want) {
		t.Errorf("addresses %v, want %v — sorted as strings, which is what "+
			"Python's sorted() over a set of str does", addresses, want)
	}
}

// A missing or empty map is the empty reading, because every branch that
// follows asks the same question of both: did anything answer.
func TestAnUnansweredMapIsTheEmptyReading(t *testing.T) {
	for _, staged := range []string{`{}`, `null`} {
		document, err := decodeDocument([]byte(staged))
		if err != nil {
			t.Fatal(err)
		}
		addresses, err := domainAddresses(document)
		if err != nil || addresses != nil {
			t.Errorf("%s: got %v, %v", staged, addresses, err)
		}
	}
	if addresses, err := domainAddresses(nil); err != nil || addresses != nil {
		t.Errorf("a missing member: got %v, %v", addresses, err)
	}
}

// The one place this collection is not defensive about a document's types,
// and it is deliberate. The reference iterates whatever it finds, and a
// Python string iterates into its characters — so "reproducing" a string
// where a list belongs would publish an address per letter.
func TestAnAddressListOfTheWrongShapeRefusesRatherThanIterating(t *testing.T) {
	for _, staged := range []string{
		`{"aa": "10.0.0.2"}`,
		`{"aa": [10]}`,
		`[]`,
	} {
		document, err := decodeDocument([]byte(staged))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := domainAddresses(document); err == nil {
			t.Errorf("%s: the batch must refuse rather than invent a reading", staged)
		}
	}
}
