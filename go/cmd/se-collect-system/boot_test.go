// The boot collection's shapes: the BIOS host (eight EFI facts absent,
// stated), the non-NixOS host (four pointer facts absent), the UEFI host
// with a stale ordered entry — the condition the boot-order-stale rule
// exists for — and the load-option parse against hand-built binary
// fixtures, because no lab guest boots UEFI and the parse must not wait
// for one to be provably right.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
)

const systemdDoc = `{"type":"a{sv}","data":[{"Version":{"type":"s","data":"257.6-1"},"SystemState":{"type":"s","data":"running"},"NFailedUnits":{"type":"u","data":0},"NJobs":{"type":"u","data":0},"KernelTimestamp":{"type":"t","data":1787320000000000},"UserspaceTimestamp":{"type":"t","data":1787320004000000},"FinishTimestamp":{"type":"t","data":1787320009500000},"Architecture":{"type":"s","data":"x86-64"},"Virtualization":{"type":"s","data":"kvm"},"ConfusingExtra":{"type":"(so)","data":["x","/y"]}}]}`

func bootObject(t *testing.T, src *fakeSource) (map[string]any, []string) {
	t.Helper()
	var out, errs bytes.Buffer
	if code := collect(&out, &errs, src, []string{"boot"},
		map[string]uint64{"boot": 5}); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record["record"] == "object" {
			var listed []string
			for _, name := range record["absent"].([]any) {
				listed = append(listed, name.(string))
			}
			return record["facts"].(map[string]any), listed
		}
	}
	t.Fatal("no object emitted")
	return nil, nil
}

func TestBootOnABiosNonNixosHostStatesItsAbsences(t *testing.T) {
	src := &fakeSource{sysd: []byte(systemdDoc)}
	facts, absent := bootObject(t, src)
	if facts["Firmware"] != "bios" || facts["SystemState"] != "running" ||
		facts["SystemdVersion"] != "257.6-1" || facts["NFailedUnits"] != float64(0) {
		t.Fatalf("%+v", facts)
	}
	if facts["FinishTimestamp"] != "2026-08-21T13:46:49Z" {
		t.Fatalf("%v", facts["FinishTimestamp"])
	}
	// The object is named by the boot it describes: the fake's boot id,
	// dashes stripped.
	if facts["BootID"] != "4f2a1c8e7b3d4a919e2f6c5d8a0b1e37" {
		t.Fatalf("%v", facts["BootID"])
	}
	for _, name := range append(efiFacts[:], nixFacts[:]...) {
		if !has(absent, name) {
			t.Fatalf("%s must be absent on this host: %v", name, absent)
		}
	}
}

func TestBootReadsTheNixosPointersAndTheGeneration(t *testing.T) {
	src := &fakeSource{sysd: []byte(systemdDoc), nixp: &nixPointers{
		Current:     "/nix/store/aaa-nixos-system-host-25.11",
		Booted:      "/nix/store/aaa-nixos-system-host-25.11",
		Default:     "/nix/store/bbb-nixos-system-host-25.11",
		ProfileLink: "system-207-link",
	}}
	facts, absent := bootObject(t, src)
	if facts["CurrentSystem"] != "/nix/store/aaa-nixos-system-host-25.11" ||
		facts["SystemProfile"] != "/nix/store/bbb-nixos-system-host-25.11" ||
		facts["SystemProfileGeneration"] != float64(207) {
		t.Fatalf("%+v", facts)
	}
	for _, name := range nixFacts {
		if has(absent, name) {
			t.Fatalf("%s present yet absent-listed: %v", name, absent)
		}
	}
}

// loadOptionBytes hand-builds an EFI_LOAD_OPTION: attributes, a UTF-16LE
// description, a GPT HardDrive node carrying the partition GUID, a File
// node, and the end node.
func loadOptionBytes(attributes uint32, description string, guidLE []byte, filePath string) []byte {
	var out bytes.Buffer
	desc := utf16.Encode([]rune(description))
	hardDrive := make([]byte, 42)
	hardDrive[0], hardDrive[1] = 0x04, 0x01
	binary.LittleEndian.PutUint16(hardDrive[2:4], 42)
	copy(hardDrive[24:40], guidLE) // node offset 20..36 → +4 header
	hardDrive[41] = 2              // SignatureType GPT
	file := utf16.Encode([]rune(filePath))
	fileNode := make([]byte, 4+2*len(file)+2)
	fileNode[0], fileNode[1] = 0x04, 0x04
	binary.LittleEndian.PutUint16(fileNode[2:4], uint16(len(fileNode)))
	for i, u := range file {
		binary.LittleEndian.PutUint16(fileNode[4+2*i:], u)
	}
	end := []byte{0x7F, 0xFF, 0x04, 0x00}
	fplLen := len(hardDrive) + len(fileNode) + len(end)

	var header [6]byte
	binary.LittleEndian.PutUint32(header[0:4], attributes)
	binary.LittleEndian.PutUint16(header[4:6], uint16(fplLen))
	out.Write(header[:])
	for _, u := range desc {
		var pair [2]byte
		binary.LittleEndian.PutUint16(pair[:], u)
		out.Write(pair[:])
	}
	out.Write([]byte{0, 0})
	out.Write(hardDrive)
	out.Write(fileNode)
	out.Write(end)
	return out.Bytes()
}

// The GUID 12345678-9abc-def0-1234-56789abcdef0 in its on-disk bytes_le
// spelling: first three groups byte-swapped, last two as printed.
var guidLE = []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde,
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}

func withHeader(payload []byte) []byte {
	return append([]byte{7, 0, 0, 0}, payload...)
}

func TestParseLoadOptionDecodesTheTwoNodesAnOperatorAsksAbout(t *testing.T) {
	option := parseLoadOption(loadOptionBytes(1, "Linux Boot Manager", guidLE,
		`\EFI\systemd\systemd-bootx64.efi`))
	if option.description != "Linux Boot Manager" || option.attributes&1 != 1 {
		t.Fatalf("%+v", option)
	}
	if option.partitionUUID != "12345678-9abc-def0-1234-56789abcdef0" {
		t.Fatalf("the GUID must come back in RFC 4122 spelling from its "+
			"mixed-endian bytes: %s", option.partitionUUID)
	}
	if option.filePath != `\EFI\systemd\systemd-bootx64.efi` {
		t.Fatalf("%q", option.filePath)
	}
}

func TestUefiFactsAndTheStaleOrderedEntry(t *testing.T) {
	resolved := loadOptionBytes(1, "Resolved", guidLE, `\EFI\a.efi`)
	staleGUID := append([]byte{}, guidLE...)
	staleGUID[0] = 0xFF
	stale := loadOptionBytes(1, "Gone", staleGUID, `\EFI\b.efi`)
	src := &fakeSource{sysd: []byte(systemdDoc),
		vars: map[string][]byte{
			"BootOrder":   withHeader([]byte{0x00, 0x00, 0x01, 0x00}), // 0000, 0001
			"BootCurrent": withHeader([]byte{0x00, 0x00}),
			"BootNext":    withHeader([]byte{0x01, 0x00}),
			"SecureBoot":  withHeader([]byte{1}),
			"SetupMode":   withHeader([]byte{0}),
			"Timeout":     withHeader([]byte{5, 0}),
			"Boot0000":    withHeader(resolved),
			"Boot0001":    withHeader(stale),
		},
		partmap: map[string]string{"12345678-9abc-def0-1234-56789abcdef0": "vda2"}}
	facts, absent := bootObject(t, src)
	if facts["Firmware"] != "uefi" || facts["SecureBoot"] != true ||
		facts["BootNext"] != "Boot0001" || facts["BootTimeoutSeconds"] != float64(5) {
		t.Fatalf("%+v", facts)
	}
	order := facts["BootOrder"].([]any)
	if len(order) != 2 || order[0] != "Boot0000" {
		t.Fatalf("%v", order)
	}
	entries := facts["BootEntries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("%v", entries)
	}
	first := entries[0].(map[string]any)
	if first["Device"] != "block-device:vda2" || first["Stale"] != false ||
		first["Current"] != true || first["OrderPosition"] != float64(1) {
		t.Fatalf("%+v", first)
	}
	second := entries[1].(map[string]any)
	if second["Stale"] != true {
		t.Fatalf("%+v", second)
	}
	if _, present := second["Device"]; present {
		t.Fatal("an unresolvable entry has no Device member — null members " +
			"are omitted, never carried, because the stream refuses a null " +
			"at any depth")
	}
	staleOrdered := facts["StaleOrderedBootEntries"].([]any)
	if len(staleOrdered) != 1 || staleOrdered[0] != "Boot0001" {
		t.Fatalf("the rule's fact: %v", staleOrdered)
	}
	if has(absent, "BootEntries") {
		t.Fatalf("%v", absent)
	}
}

func TestUnsetSystemdTimestampsGoAbsent(t *testing.T) {
	doc := strings.Replace(systemdDoc,
		`"FinishTimestamp":{"type":"t","data":1787320009500000}`,
		`"FinishTimestamp":{"type":"t","data":0}`, 1)
	src := &fakeSource{sysd: []byte(doc)}
	facts, absent := bootObject(t, src)
	if _, present := facts["FinishTimestamp"]; present || !has(absent, "FinishTimestamp") {
		t.Fatal("a zero systemd timestamp is a reading nobody took: absent, " +
			"never 1970")
	}
}
