package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
)

// row is one committed object: the native name the collator keys on, and the
// facts. No opinions and no health verdict — the reference computes both and
// emission.items() publishes neither, because a severity is a judgement over a
// rulebook and the collector stream carries readings.
type row struct {
	name  string
	facts *value
}

// The dark-client reading, as a CONSTANT and not as the exception's text.
//
// adapters/downloaders.py writes `f"{type(exc).__name__}: {exc}"` into
// StatusUnobservable, which on the live path is an httpx exception carrying the
// request URL — and a download-client URL is deployment configuration that can
// embed basic-auth userinfo, while sabnzbd's key rides in the query string. A
// fact leaves the host exactly as a decline detail does, so this port puts the
// constant on the wire and the real error on stderr, where a person debugging
// reads it and no redaction pass has to be trusted.
//
// The cost is stated rather than hidden: on a host where a client is dark, this
// collector and the reference will disagree about this fact's value. That is a
// live-comparator adjudication and no replay can reach it — a variant stages
// every document or none.
const (
	transmissionUnobservable = "the transmission RPC did not answer"
	sabUnobservable          = "the sabnzbd API did not answer"
)

// clientRows is `_client_items()`: one row per CONFIGURED client, in the
// reference's own order — transmission, then sabnzbd. A client with no receipts
// is simply absent; rows exist for what is configured.
func clientRows(src source, stderr io.Writer) ([]row, error) {
	gates := src.clients()
	var rows []row
	if gates.transmission {
		facts, err := transmissionClientFacts(src, stderr)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row{name: clientTransmission, facts: facts})
	}
	if gates.sab {
		facts, err := sabClientFacts(src, gates, stderr)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row{name: clientSabnzbd, facts: facts})
	}
	return rows, nil
}

// transmissionClientFacts is `_transmission_client_row()`. Both documents or
// neither: session-get carries the version and the free space, session-stats
// carries the counts, and a row built from one of them would be half an answer
// wearing a whole one's face — which is why the reference issues both before it
// builds anything and treats a failure of either as a dark client.
func transmissionClientFacts(src source, stderr io.Writer) (*value, error) {
	facts := newObject()
	facts.set("Client", stringValue(clientTransmission))

	session, sessionErr := src.document(callSessionGet)
	stats, statsErr := src.document(callSessionStats)
	if err := errors.Join(sessionErr, statsErr); err != nil {
		if fatalAcquisition(err) {
			return nil, err
		}
		fmt.Fprintln(stderr, "transmission:", err)
		facts.set("StatusUnobservable", stringValue(transmissionUnobservable))
		return facts, nil
	}

	if version := session.get("version"); truthy(version) {
		facts.set("Version", version)
	}
	// -1 is transmission's own way of saying it could not measure the download
	// directory, and it is an int, so a port testing only the type publishes a
	// negative byte count. The reference's `free >= 0` is what refuses it — and
	// the fact is then OMITTED rather than zeroed, because "not measured" and
	// "no space left" are different statements.
	if free := session.get("download-dir-free-space"); isIntegerNumber(free) {
		if token, ok := integerTokenOf(free.text); ok && token[0] != '-' {
			facts.set("DiskFreeBytes", &value{kind: jsonNumber, text: token})
		}
	}
	for _, pair := range [...]struct{ fact, member string }{
		{"ActiveTorrentCount", "activeTorrentCount"},
		{"PausedTorrentCount", "pausedTorrentCount"},
		{"TorrentCount", "torrentCount"},
		{"DownloadRateBytes", "downloadSpeed"},
		{"UploadRateBytes", "uploadSpeed"},
	} {
		// `isinstance(x, int)` and not `(int, float)`: transmission states these
		// as whole counts, and a fractional one is a document this collector
		// does not recognise rather than a figure to truncate.
		if member := stats.get(pair.member); isIntegerNumber(member) {
			facts.set(pair.fact, numberValue(member))
		}
	}
	return facts, nil
}

// sabClientFacts is `_sab_client_row()`. A URL with no key is a STATED-FAULT
// row rather than a missing one: the client is configured, so the row exists
// and says what it still needs — a manager dispatching to it is blocked either
// way, and a row that quietly vanished would make "no sabnzbd here" and
// "sabnzbd cannot be asked" byte-identical.
func sabClientFacts(src source, gates clientGates, stderr io.Writer) (*value, error) {
	facts := newObject()
	facts.set("Client", stringValue(clientSabnzbd))
	if !gates.sabKey {
		facts.set("ConfigMissing", stringArray([]string{sabKeyVariable}))
		return facts, nil
	}
	document, err := src.document(callQueue)
	if err != nil {
		if fatalAcquisition(err) {
			return nil, err
		}
		fmt.Fprintln(stderr, "sabnzbd:", err)
		facts.set("StatusUnobservable", stringValue(sabUnobservable))
		return facts, nil
	}
	queueClientFacts(document.get("queue"), facts)
	return facts, nil
}

// queueClientFacts is `sab_queue_client_facts()`: the client-level half of
// sabnzbd's queue document, which is where it states its own vantage — speeds,
// depth, pause state, and the disk it measures from INSIDE its own mount.
func queueClientFacts(queue *value, facts *value) {
	if queue == nil || queue.kind != jsonObject {
		return // `(await self._sab("queue")).get("queue") or {}`
	}
	if version := queue.get("version"); truthy(version) {
		facts.set("Version", version)
	}
	if paused := queue.get("paused"); paused.stated() {
		facts.set("Paused", boolValue(truthy(paused)))
	}
	// kbpersec is a STRING of kilobytes per second; the conversion to bytes
	// happens once here rather than in every consumer, which is the same
	// argument the GB members below carry.
	if rate, ok := pythonFloat(queue.get("kbpersec").stringOr("")); ok {
		if token, ok := truncatedProduct(rate, 1024); ok {
			facts.set("DownloadRateBytes", &value{kind: jsonNumber, text: token})
		}
	}
	// noofslots_total is sabnzbd's OWN counting and it is not the length of the
	// slots list: a paused job sits in the queue and is not counted. The
	// fallback fires only where the first member is missing or unreadable, so a
	// present zero stands as the client's answer rather than being second-
	// guessed by a row count.
	if token, ok := pythonInt(queue.get("noofslots_total")); ok {
		facts.set("QueueCount", &value{kind: jsonNumber, text: token})
	} else if slots := queue.get("noofslots"); slots.stated() {
		if token, ok := pythonInt(slots); ok {
			facts.set("QueueCount", &value{kind: jsonNumber, text: token})
		}
	}
	bytesOf := map[string]int64{}
	for _, pair := range [...]struct{ fact, member string }{
		{"DiskFreeBytes", "diskspace1"},
		{"DiskTotalBytes", "diskspacetotal1"},
	} {
		if gigabytes, ok := pythonFloat(queue.get(pair.member).stringOr("")); ok {
			if token, ok := truncatedProduct(gigabytes, 1<<30); ok {
				facts.set(pair.fact, &value{kind: jsonNumber, text: token})
				if n, err := strconv.ParseInt(token, 10, 64); err == nil {
					bytesOf[pair.fact] = n
				}
			}
		}
	}
	// Minted on both implementations because the disk rule names one fact
	// and a threshold, and the closed condition vocabulary cannot do the
	// arithmetic (register row 8's residue). Only where the client states
	// BOTH halves — rule 7 invents no percentage without a denominator the
	// source stated. Python's round is half-even; math.RoundToEven here.
	if total, free := bytesOf["DiskTotalBytes"], bytesOf["DiskFreeBytes"]; total > 0 {
		if _, held := bytesOf["DiskFreeBytes"]; held {
			percent := math.RoundToEven(float64(total-free) * 100 / float64(total))
			facts.set("DiskUsedPercent", &value{kind: jsonNumber,
				text: strconv.FormatInt(int64(percent), 10)})
		}
	}
}

// fatalAcquisition separates a client that did not answer from a capture that
// is broken. The first is an observation and belongs on the row; the second is
// "I could not run" and must never become a fact, because a row carrying this
// harness's own error text would read as a statement about a machine nobody
// observed.
func fatalAcquisition(err error) bool { return errors.Is(err, errUncaptured) }
