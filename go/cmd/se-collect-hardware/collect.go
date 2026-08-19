package main

import (
	"encoding/json"
	"fmt"
	"io"
)

// Stream records as Go structs, every member the contract names and no other:
// the schemas are closed precisely because an open object is how a struct's
// exported field names once shipped as {"Stable":…} without a test going red
// (se.stream.1.json), so the json tags here ARE the wire and a missing one is
// a wire bug.
type beginRecord struct {
	Record      string            `json:"record"`
	Request     string            `json:"request"`
	Batch       string            `json:"batch"`
	Declaration string            `json:"declaration"`
	BootID      string            `json:"boot_id"`
	Timens      int64             `json:"timens"`
	Instance    *string           `json:"instance"` // no omitempty: null means host-native and only null means it
	Generations map[string]uint64 `json:"generations"`
}

// There is no `names` member and no `absent` member, and both are absences by
// construction rather than by omitempty. The reference's row builder attaches
// neither, and publishing a name family here would key the collator on a name
// no other implementation of this collection publishes.
type objectRecord struct {
	Record     string         `json:"record"`
	Collection string         `json:"collection"`
	Name       string         `json:"name"`
	Facts      map[string]any `json:"facts"`
	At         float64        `json:"at"`
}

type declineRecord struct {
	Record     string `json:"record"`
	Collection string `json:"collection"`
	Reason     string `json:"reason"`
	Detail     string `json:"detail"`
}

type commitRecord struct {
	Record     string `json:"record"`
	Collection string `json:"collection"`
	Generation uint64 `json:"generation"`
	// All three counts, always, zero when zero: they are required members
	// precisely so a subject cannot disable the truncation check by omitting
	// the count (DESIGN 19).
	Objects      int `json:"objects"`
	Assertions   int `json:"assertions"`
	Unobservable int `json:"unobservable"`
}

type endRecord struct {
	Record  string  `json:"record"`
	Request string  `json:"request"`
	Batch   string  `json:"batch"`
	CPUMS   float64 `json:"cpu_ms"`
	WallMS  float64 `json:"wall_ms"`
}

// emitter serialises records as NDJSON and keeps the first write error: once
// stdout is gone the stream is truncated no matter what else runs, so the
// batch reports "I could not run" rather than pretending the missing tail was
// intentional.
type emitter struct {
	encoder *json.Encoder
	err     error
}

func newEmitter(w io.Writer) *emitter {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return &emitter{encoder: encoder}
}

func (e *emitter) emit(record any) {
	if e.err == nil {
		e.err = e.encoder.Encode(record)
	}
}

// The five collections this collector serves, in one place: the collect loop
// dispatches on it and `declare` names the same five, so a collection served
// by one and not the other is unspellable.
const (
	collectionPlatform = "platform"
	collectionPCI      = "pci"
	collectionUSB      = "usb"
	collectionSCSI     = "scsi"
	collectionNVMe     = "nvme"
)

var served = map[string]bool{
	collectionPlatform: true,
	collectionPCI:      true,
	collectionUSB:      true,
	collectionSCSI:     true,
	collectionNVMe:     true,
}

// collect runs one batch: begin, each requested collection under its issued
// generation, end.
func collect(stdout, stderr io.Writer, src source, order []string, generations map[string]uint64) int {
	bootID, err := src.bootID()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	batch, err := src.batch()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	out := newEmitter(stdout)
	out.emit(beginRecord{
		Record:      "begin",
		Request:     batch, // request := batch by ruling (appendix C); the collator correlates by the connection it dialled
		Batch:       batch,
		Declaration: src.declaration(),
		BootID:      bootID,
		Timens:      src.timens(),
		Instance:    nil, // host-native: this collector fronts no fleet-named instance
		Generations: generations,
	})

	absent := sysfsPresent(src) != nil
	emitted := 0
	for _, collection := range order {
		if !served[collection] {
			// A collection this collector never published is DECLINED, not
			// sanitised and not crashed on (DESIGN 18). unsupported — the
			// reason that reaches whoever maintains the request — and no
			// commit, so prior state stands rather than being retired by a
			// batch that never looked.
			out.emit(declineRecord{
				Record:     "decline",
				Collection: collection,
				Reason:     "unsupported",
				Detail:     "this collector serves platform, pci, usb, scsi and nvme",
			})
			continue
		}
		if absent {
			// absent is authoritative-empty (DESIGN 19): it must be able to
			// retire the rows a previous batch published, so it declines AND
			// commits zero.
			out.emit(declineRecord{
				Record:     "decline",
				Collection: collection,
				Reason:     declineNoSysfs.reason,
				Detail:     declineNoSysfs.detail,
			})
			out.emit(commitRecord{
				Record: "commit", Collection: collection,
				Generation: generations[collection],
			})
			continue
		}
		if err := src.beginCollection(); err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		items := acquire(src, collection)
		// The seam refused something before anything is committed. It is "I
		// could not run" and never a decline: a document nobody captured says
		// nothing about any machine, and committing a partial walk would
		// retire every row the missing half would have carried.
		if err := src.failure(); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", collection, err)
			return exitRuntime
		}
		for _, row := range items {
			out.emit(objectRecord{
				Record:     "object",
				Collection: collection,
				Name:       row.name,
				Facts:      row.facts,
				At:         src.stamp(emitted),
			})
			emitted++
		}
		out.emit(commitRecord{
			Record: "commit", Collection: collection,
			Generation: generations[collection], Objects: len(items),
		})
	}

	cpu, wall := src.costs()
	out.emit(endRecord{Record: "end", Request: batch, Batch: batch, CPUMS: cpu, WallMS: wall})

	if out.err != nil {
		fmt.Fprintln(stderr, "writing the stream:", out.err)
		return exitRuntime
	}
	return exitOK
}

func acquire(src source, collection string) []item {
	switch collection {
	case collectionPlatform:
		return platformItems(src, src.hostname())
	case collectionPCI:
		return pciItems(src)
	case collectionUSB:
		return usbItems(src)
	case collectionSCSI:
		items := scsiItems(src)
		mergeSCSIHealth(src, items)
		return items
	case collectionNVMe:
		items := nvmeItems(src)
		mergeNVMeHealth(src, items)
		return items
	}
	return nil
}
