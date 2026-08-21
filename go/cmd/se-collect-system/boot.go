package main

// The boot collection (register row 9, R3b): what this boot is, whether
// systemd finished it cleanly, what the firmware would boot next time, and
// — on NixOS — which of the three system closures agree. Ported
// member-for-member from the reference's _boot, with each acquisition's
// absence its own grouped statement: no efivarfs is a BIOS host and eight
// facts absent, no /run/current-system is a non-NixOS host and four.
//
// The load-option parse is the deep half: EFI_LOAD_OPTION is Attributes
// u32, FilePathListLength u16, a NUL-terminated UTF-16LE description, then
// a device path list, of which only the two node kinds an operator asks
// about are decoded — the GPT partition a boot entry points at and the
// loader path on it. Everything else is passed over, exactly as the
// reference passes it.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// isBootEntryName recognises BootXXXX, four hex digits exactly.
func isBootEntryName(name string) bool {
	if len(name) != 8 || !strings.HasPrefix(name, "Boot") {
		return false
	}
	_, err := strconv.ParseUint(name[4:], 16, 16)
	return err == nil
}

type loadOption struct {
	attributes    uint32
	description   string
	partitionUUID string
	filePath      string
}

// parseLoadOption decodes one Boot#### variable's payload (attribute
// header already stripped). Truncated input yields what could be read —
// the reference's own tolerance, because a firmware writes these and a
// parser that refused a vendor's sloppy tail would lose the whole entry
// over bytes nobody reads.
func parseLoadOption(data []byte) loadOption {
	var out loadOption
	if len(data) < 6 {
		return out
	}
	out.attributes = binary.LittleEndian.Uint32(data[:4])
	fplLen := int(binary.LittleEndian.Uint16(data[4:6]))
	i := 6
	for i+1 < len(data) && !(data[i] == 0 && data[i+1] == 0) {
		i += 2
	}
	out.description = decodeUTF16LE(data[6:min(i, len(data))])
	devicePath := data[min(i+2, len(data)):]
	if fplLen < len(devicePath) {
		devicePath = devicePath[:fplLen]
	}
	for j := 0; j+4 <= len(devicePath); {
		nodeType, nodeSub := devicePath[j], devicePath[j+1]
		nodeLen := int(binary.LittleEndian.Uint16(devicePath[j+2 : j+4]))
		if nodeLen < 4 || j+nodeLen > len(devicePath) {
			break
		}
		node := devicePath[j+4 : j+nodeLen]
		switch {
		case nodeType == 0x04 && nodeSub == 0x01 && len(node) >= 38 && node[37] == 2:
			// Media/HardDrive node with a GPT signature: the partition
			// GUID, in EFI's mixed-endian spelling.
			out.partitionUUID = guidString(node[20:36])
		case nodeType == 0x04 && nodeSub == 0x04:
			out.filePath = strings.TrimRight(decodeUTF16LE(node), "\x00")
		case nodeType == 0x7F:
			return out
		}
		j += nodeLen
	}
	return out
}

func decodeUTF16LE(data []byte) string {
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(data[i:i+2]))
	}
	return string(utf16.Decode(units))
}

// guidString renders a GPT GUID from its on-disk mixed-endian bytes: the
// first three groups little-endian, the last two big — RFC 4122's dashed
// lowercase, the same spelling Python's uuid.UUID(bytes_le=…) produces.
func guidString(b []byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// The EFI fact names that stand or fall with efivarfs, absent together on
// a BIOS host.
var efiFacts = [...]string{
	"SecureBoot", "SetupMode", "BootCurrent", "BootNext", "BootOrder",
	"BootTimeoutSeconds", "BootEntries", "StaleOrderedBootEntries",
}

var nixFacts = [...]string{
	"CurrentSystem", "BootedSystem", "SystemProfile", "SystemProfileGeneration",
}

func collectBoot(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	at, err := src.stamp(*objects)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	raw, err := src.systemd1()
	switch {
	case errors.Is(err, errNoSystemd):
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "absent", Detail: "no systemd on the system bus on this host"})
		out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		return exitOK
	case errors.Is(err, errUncaptured):
		fmt.Fprintln(stderr, err)
		return exitRuntime
	case err != nil:
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unavailable", Detail: "systemd is here and its manager did not answer on the system bus"})
		fmt.Fprintln(stderr, "systemd1:", err)
		return exitOK
	}
	props, perr := propertiesOf(raw)
	if perr != nil {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unavailable", Detail: "the systemd manager answered with a document this collector cannot read"})
		fmt.Fprintln(stderr, "systemd1:", perr)
		return exitOK
	}

	facts := map[string]any{}
	var absent []string
	missing := func(names ...string) { absent = append(absent, names...) }

	// The boot id, dashes stripped exactly as the reference strips them —
	// it is also this object's native name, "unknown" when unreadable,
	// because a boot that cannot name itself is still the boot being
	// described.
	bootID, _ := src.bootID()
	bootID = strings.ReplaceAll(strings.TrimSpace(bootID), "-", "")
	facts["BootID"] = bootID
	name := bootID
	if name == "" {
		name = "unknown"
	}

	if state, ok := propString(props, "SystemState"); ok {
		facts["SystemState"] = state
	} else {
		missing("SystemState")
	}
	for prop, fact := range map[string]string{
		"NFailedUnits": "NFailedUnits", "NJobs": "NJobs"} {
		// u32 on the bus; propU64 refuses the type, so read the variant
		// directly for the two count members.
		if v, ok := props[prop]; ok && v.Type == "u" {
			var n uint64
			if jsonUnmarshalNumber(v.Data, &n) {
				facts[fact] = n
				continue
			}
		}
		missing(fact)
	}
	if version, ok := propString(props, "Version"); ok {
		facts["SystemdVersion"] = version
	} else {
		missing("SystemdVersion")
	}
	for prop, fact := range map[string]string{
		"KernelTimestamp":    "KernelTimestamp",
		"UserspaceTimestamp": "UserspaceTimestamp",
		"FinishTimestamp":    "FinishTimestamp"} {
		if usec, ok := propU64(props, prop); ok {
			if iso, real := usecToISO(usec); real {
				facts[fact] = iso
				continue
			}
		}
		missing(fact)
	}

	if pointers := src.nix(); pointers != nil {
		nixFact := func(fact, value string) {
			if value != "" {
				facts[fact] = value
			} else {
				missing(fact)
			}
		}
		nixFact("CurrentSystem", pointers.Current)
		nixFact("BootedSystem", pointers.Booted)
		nixFact("SystemProfile", pointers.Default)
		link := pointers.ProfileLink
		if strings.HasPrefix(link, "system-") && strings.HasSuffix(link, "-link") {
			if gen, err := strconv.ParseInt(
				link[len("system-"):len(link)-len("-link")], 10, 64); err == nil {
				facts["SystemProfileGeneration"] = gen
			} else {
				missing("SystemProfileGeneration")
			}
		} else {
			missing("SystemProfileGeneration")
		}
	} else {
		missing(nixFacts[:]...)
	}

	if vars := src.efivars(); vars != nil {
		emitEFI(facts, missing, vars, src)
	} else {
		// Absence of efivarfs is the fact — a BIOS host — and it is what
		// keeps the EFI rules from firing there.
		facts["Firmware"] = "bios"
		missing(efiFacts[:]...)
	}

	sort.Strings(absent)
	out.emit(objectRecord{
		Record:     "object",
		Type:       "boot",
		Collection: collection,
		Name:       name,
		Facts:      facts,
		Absent:     absent,
		At:         at,
	})
	*objects++
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    1,
	})
	return exitOK
}

func emitEFI(facts map[string]any, missing func(...string), vars map[string][]byte, src source) {
	facts["Firmware"] = "uefi"
	payload := func(name string) []byte {
		raw := vars[name]
		if len(raw) > 4 {
			return raw[4:] // the 4-byte attribute header
		}
		return nil
	}
	u16At := func(name string) (uint64, bool) {
		data := payload(name)
		if len(data) >= 2 {
			return uint64(binary.LittleEndian.Uint16(data[:2])), true
		}
		return 0, false
	}
	boolAt := func(name string) (bool, bool) {
		data := payload(name)
		if len(data) >= 1 {
			return data[0] != 0, true
		}
		return false, false
	}

	if v, ok := boolAt("SecureBoot"); ok {
		facts["SecureBoot"] = v
	} else {
		missing("SecureBoot")
	}
	if v, ok := boolAt("SetupMode"); ok {
		facts["SetupMode"] = v
	} else {
		missing("SetupMode")
	}
	orderRaw := payload("BootOrder")
	orderIDs := make([]uint64, 0, len(orderRaw)/2)
	order := make([]string, 0, len(orderRaw)/2)
	for k := 0; k+1 < len(orderRaw); k += 2 {
		id := uint64(binary.LittleEndian.Uint16(orderRaw[k : k+2]))
		orderIDs = append(orderIDs, id)
		order = append(order, fmt.Sprintf("Boot%04X", id))
	}
	facts["BootOrder"] = order
	current, hasCurrent := u16At("BootCurrent")
	if hasCurrent {
		facts["BootCurrent"] = fmt.Sprintf("Boot%04X", current)
	} else {
		missing("BootCurrent")
	}
	if next, ok := u16At("BootNext"); ok {
		facts["BootNext"] = fmt.Sprintf("Boot%04X", next)
	} else {
		missing("BootNext")
	}
	if timeout, ok := u16At("Timeout"); ok {
		facts["BootTimeoutSeconds"] = timeout
	} else {
		missing("BootTimeoutSeconds")
	}

	names := make([]string, 0, len(vars))
	for name := range vars {
		if isBootEntryName(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	entries := make([]map[string]any, 0, len(names))
	staleOrdered := []string{}
	for _, name := range names {
		data := payload(name)
		if len(data) == 0 {
			continue
		}
		num, _ := strconv.ParseUint(name[4:], 16, 16)
		option := parseLoadOption(data)
		// Null members are OMITTED per entry, not carried: the stream
		// refuses a null at any depth, and "no reading" inside an entry
		// is a missing member exactly as it is at the top of a row.
		entry := map[string]any{
			"ID":          fmt.Sprintf("Boot%04X", num),
			"Description": option.description,
			"Active":      option.attributes&1 != 0,
			"Current":     hasCurrent && num == current,
		}
		position := 0
		for k, id := range orderIDs {
			if id == num {
				position = k + 1
				break
			}
		}
		if position > 0 {
			entry["OrderPosition"] = position
		}
		if option.filePath != "" {
			entry["FilePath"] = option.filePath
		}
		if option.partitionUUID != "" {
			if kernel := src.partitionDevice(option.partitionUUID); kernel != "" {
				entry["Device"] = "block-device:" + kernel
				entry["Stale"] = false
			} else {
				entry["Stale"] = true
				if position > 0 {
					staleOrdered = append(staleOrdered, entry["ID"].(string))
				}
			}
		}
		entries = append(entries, entry)
	}
	facts["BootEntries"] = entries
	facts["StaleOrderedBootEntries"] = staleOrdered
}

// jsonUnmarshalNumber reads one bus variant payload into a uint64.
func jsonUnmarshalNumber(data []byte, into *uint64) bool {
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return false
	}
	*into = v
	return true
}
