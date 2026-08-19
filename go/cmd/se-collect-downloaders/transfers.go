package main

import (
	"fmt"
	"io"
	"strings"
)

// transmissionStatus is transmission's documented status vocabulary, by RPC
// enum position: its own names, not inventions, and the int is the wire form
// while the name is how every transmission surface renders it. A closed set
// indexed by position — a port that carried only the values it had met would
// publish nothing at all for a seeding torrent, which is the state a completed
// one sits in indefinitely.
var transmissionStatus = [...]string{
	"stopped", "check-wait", "check", "download-wait", "download",
	"seed-wait", "seed",
}

// transferRows is `_transfer_items()`: per-client degradation, transmission's
// rows first and sabnzbd's after. One dark client costs its own rows and not
// the other's; only EVERY configured client failing is "I could not run".
//
// What the collector contract has no room for is the failure LINE the shipping
// adapter carries beside the surviving rows. Over the HTTP contract that line
// rides an error envelope with status `partial`; over this one a commit is
// authoritative for the whole collection, so a half-dark sweep commits the
// survivor's transfers and silently retires the dark client's. The reference
// does exactly this and so does this port — agreement is the bar — and the
// named client goes to stderr so the condition is at least legible in the
// journal.
func transferRows(src source, stderr io.Writer) ([]row, error) {
	gates := src.clients()
	var rows []row
	var asked, failed []string

	if gates.transmission {
		asked = append(asked, clientTransmission)
		document, err := src.document(callTorrentGet)
		switch {
		case fatalAcquisition(err):
			return nil, err
		case err != nil:
			fmt.Fprintln(stderr, "transmission transfers:", err)
			failed = append(failed, clientTransmission)
		default:
			rows = append(rows, torrentRows(document)...)
		}
	}
	if gates.sab {
		asked = append(asked, clientSabnzbd)
		switch {
		case !gates.sabKey:
			// A URL-configured, keyless sabnzbd flows through the SAME failure
			// path as a dark one: silently omitting it would make "sab has no
			// transfers" and "sab could not be asked" byte-identical.
			fmt.Fprintf(stderr, "sabnzbd transfers: configured by URL but %s is missing\n", sabKeyVariable)
			failed = append(failed, clientSabnzbd)
		default:
			document, err := src.document(callQueue)
			switch {
			case fatalAcquisition(err):
				return nil, err
			case err != nil:
				fmt.Fprintln(stderr, "sabnzbd transfers:", err)
				failed = append(failed, clientSabnzbd)
			default:
				rows = append(rows, slotRows(document.get("queue"))...)
			}
		}
	}

	if len(asked) > 0 && len(failed) == len(asked) {
		return nil, fmt.Errorf("no client answered — %s", strings.Join(failed, "; "))
	}
	return rows, nil
}

// torrentRows is `_transmission_transfers()`. The join key is the info-hash,
// lowercased: the managers state it uppercase and transmission states it
// lowercase, and this side owns the normalisation because this side is the one
// whose API stated the key. A torrent with no hash is skipped rather than
// published under an empty name — an object the collator cannot key is an
// object nothing can ever join to or retire.
func torrentRows(document *value) []row {
	torrents := document.get("torrents")
	if torrents == nil || torrents.kind != jsonArray {
		return nil // `payload.get("torrents") or []`
	}
	rows := make([]row, 0, len(torrents.items))
	for _, raw := range torrents.items {
		digest := strings.ToLower(raw.get("hashString").stringOr(""))
		if digest == "" {
			continue
		}
		rows = append(rows, row{name: digest, facts: torrentFacts(raw)})
	}
	return rows
}

// torrentFacts is `torrent_facts()`.
func torrentFacts(raw *value) *value {
	facts := newObject()
	facts.set("Client", stringValue(clientTransmission))
	// The reference writes `raw.get("name")` unconditionally, so a torrent with
	// no name member publishes a NULL fact value — refused by the contract's
	// recursive fact_value and by the replay judge. The lawful half of the same
	// reading is the omission, which is what this does; the divergence is
	// reported rather than hidden, and every torrent transmission has ever
	// answered with carries a name.
	facts.set("Name", raw.get("name"))

	if status := raw.get("status"); isIntegerNumber(status) {
		if index, ok := smallIndex(status.text); ok && index < len(transmissionStatus) {
			facts.set("Status", stringValue(transmissionStatus[index]))
		}
	}
	// percentDone is a FRACTION and the fact is a percentage, so the reference
	// multiplies and rounds — and `round` on a Python int returns an int, so a
	// document spelling 1 rather than 1.0 puts an integer on the wire. Both
	// arms are here because typed equality sees the difference.
	if percent := raw.get("percentDone"); isNumber(percent) {
		facts.set("PercentDone", scaledPercentage(percent))
	}
	for _, pair := range [...]struct{ fact, member string }{
		{"RateDownloadBytes", "rateDownload"},
		{"RateUploadBytes", "rateUpload"},
		{"SizeWhenDoneBytes", "sizeWhenDone"},
		{"LeftUntilDoneBytes", "leftUntilDone"},
	} {
		if member := raw.get(pair.member); isNumber(member) {
			facts.set(pair.fact, numberValue(member))
		}
	}
	if code := raw.get("error"); isIntegerNumber(code) {
		// The canonical spelling, because "0" is the test and "-0" and "00"
		// are the same integer: comparing the token as written would call
		// either of them non-zero and publish an error line for a healthy
		// torrent.
		token, _ := integerTokenOf(code.text)
		facts.set("Error", &value{kind: jsonNumber, text: token})
		// The error line rides ONLY a non-zero code. transmission leaves the
		// member as an empty string when nothing is wrong, so a port that
		// published it whenever it was present would put "" on every healthy
		// row — and one that published it whenever it was non-empty agrees
		// with the reference on every capture and disagrees the moment a
		// client leaves stale text beside a cleared code.
		if text := raw.get("errorString"); token != "0" && truthy(text) {
			facts.set("ErrorString", stringValue(reason(text.stringOr(""))))
		}
	}
	if stalled := raw.get("isStalled"); stalled.stated() {
		facts.set("IsStalled", boolValue(truthy(stalled)))
	}
	return facts
}

// slotRows is `_sab_transfers()`: one row per queue slot, keyed on sabnzbd's
// own nzo id VERBATIM — it is case-sensitive and the managers state it exactly
// as sabnzbd minted it, so nothing here normalises it.
func slotRows(queue *value) []row {
	if queue == nil || queue.kind != jsonObject {
		return nil
	}
	slots := queue.get("slots")
	if slots == nil || slots.kind != jsonArray {
		return nil
	}
	rows := make([]row, 0, len(slots.items))
	for _, raw := range slots.items {
		nzo := raw.get("nzo_id")
		if !truthy(nzo) {
			continue
		}
		rows = append(rows, row{name: nzo.stringOr(""), facts: slotFacts(raw)})
	}
	return rows
}

// slotFacts is `sab_slot_facts()`.
func slotFacts(raw *value) *value {
	facts := newObject()
	facts.set("Client", stringValue(clientSabnzbd))
	// Both written unconditionally by the reference, so a slot missing either
	// member publishes a null fact — the same shape as Name above, and the
	// same lawful reading taken here.
	facts.set("Name", raw.get("filename"))
	facts.set("Status", raw.get("status"))

	// A STRING percentage: sabnzbd writes "0", and float() is what the
	// reference calls, so the fact is a number and not the token.
	if percentage := raw.get("percentage"); percentage.stated() {
		if parsed, ok := pythonFloat(percentage.stringOr("")); ok {
			facts.set("PercentDone", floatValue(parsed))
		}
	}
	// Megabytes, kept in sabnzbd's own unit rather than converted: the client
	// counts in MB and translating into the byte facts transmission publishes
	// would invent a precision sabnzbd never stated.
	for _, pair := range [...]struct{ fact, member string }{
		{"SizeMB", "mb"},
		{"LeftMB", "mbleft"},
	} {
		if parsed, ok := pythonFloat(raw.get(pair.member).stringOr("")); ok {
			facts.set(pair.fact, floatValue(parsed))
		}
	}
	if left := raw.get("timeleft"); truthy(left) {
		facts.set("TimeLeft", left)
	}
	return facts
}

// scaledPercentage is `round(percent * 100, 1)` with Python's own type rule: an
// int stays an int through both operations, and a float goes through the
// decimal rounding the reference's round() performs.
func scaledPercentage(percent *value) *value {
	if token, ok := integerTokenOf(percent.text); ok {
		scaled, ok := multiplyIntegerToken(token, 100)
		if !ok {
			return nil
		}
		return &value{kind: jsonNumber, text: scaled}
	}
	fraction, ok := pythonFloat(percent.text)
	if !ok {
		return nil
	}
	rounded, ok := pythonRound1(fraction * 100)
	if !ok {
		return nil
	}
	return floatValue(rounded)
}
