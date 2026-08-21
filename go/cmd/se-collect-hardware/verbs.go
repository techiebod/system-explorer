package main

// The object and evidence verbs (DESIGN 18, landed at R3c under the
// re-baseline's register rows 1–2). A collector is addressed by the native
// name it published — it does not know what id the collator minted — and
// every request token is data: never a path fragment, never an option, never
// part of a command string.
//
// hardware's density is not a second bus call the row could not afford, as
// units' is. It is the WHOLE sysfs directory: the row publishes the dozen
// attributes a page needs, and the object verb publishes every readable file
// in the device's own directory, which is where a question nobody anticipated
// gets answered. That makes object and evidence unusually close here, and the
// difference is the one that matters everywhere — object serves FACTS this
// collector stands behind, evidence serves the DOCUMENT they were read from,
// with the syspath, the udev reply and udisks2's own objects beside it.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

type verbEndRecord struct {
	Record    string `json:"record"`
	Verb      string `json:"verb"`
	Truncated bool   `json:"truncated"`
}

type evidenceDocumentRecord struct {
	Record    string `json:"record"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Canon     string `json:"canon,omitempty"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

// The declared bounds, pinned against declaration.json by test: a bound only
// in the declaration is a promise, one only here is undeclared authority.
const (
	objectVerbBytes   = 262144
	evidenceVerbBytes = 1048576
)

// deviceDirectory is where one object's own sysfs directory lives, per
// collection. The scsi tree is three classes, because a name in that
// collection may be a host, an expander or a device and the walk that
// published it knows which — this asks in the same order the walk built them.
func deviceDirectory(src source, collection, name string) (string, bool) {
	switch collection {
	case collectionPCI:
		return existingDirectory(src, path.Join(pciDevices, name))
	case collectionUSB:
		return existingDirectory(src, path.Join(usbDevices, name))
	case collectionNVMe:
		return existingDirectory(src, path.Join(nvmeDevices, name))
	case collectionSCSI:
		for _, base := range []string{scsiHosts, sasExpanders, scsiDevices} {
			if found, ok := existingDirectory(src, path.Join(base, name)); ok {
				return found, true
			}
		}
	}
	return "", false
}

func existingDirectory(src source, candidate string) (string, bool) {
	// A sysfs device directory always holds a uevent file, so the probe is a
	// presence test on that — through exists() rather than read(), because
	// the reference probes the same way and a read of an absent path is
	// uncaptured under replay where a probe of one is a recorded `false`.
	if src.exists(path.Join(candidate, "uevent")) {
		return candidate, true
	}
	return "", false
}

// attributes is every readable file in one device's directory, by name.
//
// Read through the same primitives the walk uses, so a value here is the value
// the row was built from rather than a second reading of the same file. A
// directory entry that is itself a directory, or a file the kernel refuses to
// read in this context, is skipped — sysfs has both, and neither is a failure.
func attributes(src source, base string) map[string]any {
	out := map[string]any{}
	for _, entry := range src.listdir(base) {
		value, ok := src.read(path.Join(base, entry))
		// A name with nothing to read is left OUT rather than carried as a
		// null: a directory entry may be a subdirectory, a write-only
		// trigger or a BINARY page — a SCSI VPD page, an EDID blob — and
		// none of those is an attribute whose value is nothing. The binary
		// ones travel through readBytes, which asks for them by name.
		if !ok || value == "" || !utf8.ValidString(value) {
			continue
		}
		out[entry] = value
	}
	return out
}

// The DMI attributes the evidence document does not serve, as the platform
// collection's `redactions` declare them.
//
// The row facts are a vendor, a model, a firmware release and four topology
// counts, every one identical on every machine of that model — which is what
// the collection's exemption used to say, adding that DMI ALSO carries
// product_serial, chassis_serial, board_serial and product_uuid, and that this
// collector read none of them. The evidence verb reads the DMI directory
// WHOLE, so from R3c it reads all four, and the exemption became false the
// moment the verb landed. It was replaced by this list rather than reworded:
// the four are the machine's own identity, and evidence is the last place a
// reader may be shown one.
var withheldDMI = [...]string{
	"product_serial", "chassis_serial", "board_serial", "product_uuid",
}

func withheld(dmi map[string]any) map[string]any {
	for _, name := range withheldDMI {
		delete(dmi, name)
	}
	return dmi
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if !served[collection] {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unsupported", Detail: "this collector does not serve this collection"})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}
	if absent := sysfsPresent(src); absent != nil {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: declineNoSysfs.reason, Detail: declineNoSysfs.detail})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}

	// The row, rebuilt from the same walk that publishes the collection: the
	// object verb overlays density on a row, and a row here that disagreed
	// with the listing would be two answers about one device. The walk is a
	// directory read rather than a bus round trip, so re-running it costs a
	// listing rather than the hundreds of calls units' row deliberately
	// avoids.
	var row *item
	for _, candidate := range acquire(src, collection) {
		if candidate.name == name {
			found := candidate
			row = &found
			break
		}
	}
	if err := src.failure(); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", collection, err)
		return exitRuntime
	}
	if row == nil {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unavailable",
			Detail: "this collector publishes no object of that name in this collection"})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}

	facts := map[string]any{}
	for fact, value := range row.facts {
		facts[fact] = value
	}
	// The density: every readable attribute of the device's own directory,
	// under the name sysfs gives it, so a reader can see what the row chose
	// from. Only for a collection whose objects ARE devices — the platform
	// row is the machine and its directory is the DMI tree, which the
	// evidence document carries whole.
	var absent []string
	if base, ok := deviceDirectory(src, collection, name); ok {
		for attribute, value := range attributes(src, base) {
			// Never a fact this collection declares: the row's reading of an
			// attribute is the declared one, and a raw second spelling beside
			// it would be two answers to one question. The raw file is in the
			// evidence document, where it belongs.
			if _, declared := facts[attribute]; !declared {
				facts["sysfs:"+attribute] = value
			}
		}
	} else if collection != collectionPlatform {
		absent = append(absent, "sysfs")
	}
	if err := src.failure(); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", collection, err)
		return exitRuntime
	}

	sort.Strings(absent)
	out.emit(objectRecord{
		Record:     "object",
		Collection: collection,
		Name:       row.name,
		Type:       row.kind,
		Names:      row.names,
		Facts:      facts,
		At:         src.stamp(0),
	})
	for _, edge := range rowAssertions(collection, *row) {
		out.emit(edge)
	}
	out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
	return verbExit(out, stderr)
}

// ── evidence ────────────────────────────────────────────────────────────

// evidencePayload is the raw documents one object's facts were read from —
// the reference's own payload shape, collection by collection. Nothing here
// is our interpretation: the sysfs attributes as written, the udev reply as
// udevadm printed it, udisks2's own managed objects, lscpu's document.
func evidencePayload(src source, collection, name string) (map[string]any, bool) {
	if collection == collectionPlatform {
		payload := map[string]any{
			"dmi":   withheld(attributes(src, dmi)),
			"lscpu": nil,
		}
		if cpu, err := src.lscpu(); err == nil {
			payload["lscpu"] = cpu
		}
		if total, ok := memTotalBytes(src); ok {
			payload["meminfo_MemTotal_bytes"] = total
		}
		return payload, true
	}
	base, ok := deviceDirectory(src, collection, name)
	if !ok {
		return nil, false
	}
	payload := map[string]any{"syspath": src.realpath(base)}
	switch collection {
	case collectionPCI, collectionUSB:
		payload["udev"] = src.udev(base)
	default:
		payload["attributes"] = attributes(src, base)
		// udisks2's own objects for the block device this backs, where the
		// daemon is on the bus at all. Absent is a reading — a host without
		// udisks2 has no such document — and it travels as an explicit null
		// so a reader can tell "asked, nothing there" from "never asked".
		payload["udisks2"] = nil
		if raw, ok := src.drivesRaw(); ok {
			if block := evidenceBlock(src, collection, base, name); block != "" {
				if objects, held := raw[block]; held {
					payload["udisks2"] = objects
				}
			}
		}
	}
	return payload, true
}

// evidenceBlock is the block device whose udisks2 objects belong with this
// row: a scsi device's own block node, or an NVMe controller's FIRST
// namespace — the same choice the health merge makes, so evidence and facts
// answer for one device rather than two.
func evidenceBlock(src source, collection, base, name string) string {
	if collection == collectionNVMe {
		for _, entry := range src.listdir(base) {
			if strings.HasPrefix(entry, name+"n") {
				return entry
			}
		}
		return ""
	}
	if blocks := src.listdir(path.Join(base, "block")); len(blocks) > 0 {
		return blocks[0]
	}
	return ""
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if !served[collection] {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unsupported", Detail: "this collector does not serve this collection"})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence"})
		return verbExit(out, stderr)
	}
	if absent := sysfsPresent(src); absent != nil {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: declineNoSysfs.reason, Detail: declineNoSysfs.detail})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence"})
		return verbExit(out, stderr)
	}
	payload, found := evidencePayload(src, collection, name)
	if err := src.failure(); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", collection, err)
		return exitRuntime
	}
	if !found {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unavailable",
			Detail: "this collector publishes no object of that name in this collection"})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence"})
		return verbExit(out, stderr)
	}
	// Go marshals map keys sorted, which is the canon the digest names:
	// re-reading and re-digesting is a meaningful comparison rather than a
	// coin toss over key ordering (DESIGN 19).
	canonical, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(stderr, "evidence payload:", err)
		return exitRuntime
	}
	truncated := false
	if len(canonical) > evidenceVerbBytes {
		// A truncated document marked truncated is still evidence; an
		// unmarked one is a lie about the system (DESIGN 19). The digest is
		// over the bytes AS SERVED, so it stays checkable.
		canonical = canonical[:evidenceVerbBytes]
		truncated = true
	}
	sum := sha256.Sum256(canonical)
	out.emit(evidenceDocumentRecord{
		Record:    "evidence_document",
		MediaType: "application/json",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Canon:     "jcs/1",
		Bytes:     len(canonical),
		Truncated: truncated,
	})
	if out.err == nil {
		if _, err := stdout.Write(append(canonical, '\n')); err != nil {
			out.err = err
		}
	}
	out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence", Truncated: truncated})
	return verbExit(out, stderr)
}

func verbExit(out *emitter, stderr io.Writer) int {
	if out.err != nil {
		fmt.Fprintln(stderr, "writing the response:", out.err)
		return exitRuntime
	}
	return exitOK
}
