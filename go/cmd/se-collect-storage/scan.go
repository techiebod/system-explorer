package main

import (
	"errors"
	"math"
	"math/big"
	"strings"
	"time"
)

// scanReading is one pool's scan_stats, read honestly in all three shapes
// zfs produces (storage.py:146-188). scan_stats is ONE record — the most
// recent scan, whatever kind it was — and both dishonest readings of it
// reached deployed pools:
//
//   - A scan in progress renders end_time as 0 under --json-int, and 0 is an
//     int, so a pool mid-scrub derived a 1970 end and a twenty-thousand-day
//     age (found live 2026-08-12). Zero means "has not ended", not the epoch.
//   - A resilver REPLACES the scrub's record, so after one the time since the
//     last completed scrub cannot be read from this pool at all — the value
//     exists and cannot be seen, which is an unobservable record and not
//     silence beside a months-stale scrub.
type scanReading struct {
	function *value // raw, nil where the document reported none
	state    *value // raw, nil where the document reported none
	endTime  *value // the ScanEndTime FACT, nil where there is none

	ageDays    *big.Int // valid only when hasAge
	hasAge     bool     // whether ScanAgeDays is in the dict at all
	scrubBlock string   // the LastScrubEndTime reason, "" when there is none
}

// computeScanFacts derives the scan facts against `now` — the one place this
// collector reads the wall clock, which is why the replay pin exists. A live
// clock here would rot the committed corpus pair the day after it was
// captured.
func computeScanFacts(scan *value, now float64) (*scanReading, error) {
	out := &scanReading{}

	endTime := scan.get("end_time")
	if isNone(endTime) {
		endTime = nil
	}
	// `end_time == 0` in the reference, which a JSON false satisfies as
	// surely as a 0 or a 0.0. Everything after this point reads "no end yet"
	// and "no record" identically, because they are the same statement.
	if equalsPythonZero(endTime) {
		endTime = nil
	}

	// isinstance(end_time, int) — true for a JSON integer, and true for a
	// JSON true, because a Python bool IS an int. A token carrying a
	// fraction or an exponent decoded to a float and is not one.
	var seconds *big.Int
	var formattable bool
	if endTime != nil {
		switch {
		case endTime.kind == jsonNumber && !strings.ContainsAny(endTime.text, ".eE"):
			seconds, _ = new(big.Int).SetString(endTime.text, 10)
			formattable = true
		case endTime.kind == jsonBool:
			// Only `true` reaches here; _epoch_iso runs int("True") on it
			// and gets nothing, so the end time is None while the age is
			// still derived against 1.
			seconds = big.NewInt(1)
		}
	}

	switch {
	case seconds != nil:
		if formattable {
			iso, err := epochISO(seconds)
			if err != nil {
				return nil, err
			}
			out.endTime = stringValue(iso)
		}
		// Whole days by floor division, so a future end time is negative
		// rather than clamped — the reference states what it read.
		out.ageDays = big.NewInt(int64(math.Floor((now - bigFloat(seconds)) / 86400)))
		out.hasAge = true
	case endTime != nil:
		// An OpenZFS too old for --json-int renders end_time as prose. It is
		// kept verbatim and no age is derived from it; the caller routes the
		// missing age to the unobservable channel rather than to absence.
		out.endTime = endTime
	}

	out.function = nilIfNone(scan.get("function"))
	out.state = nilIfNone(scan.get("state"))

	if out.function != nil && !out.function.equalsString("SCRUB") {
		if !out.function.isString() {
			// The reference lowercases this member to build the reason, and
			// a document member that is not a string stops the batch there.
			return nil, errors.New("scan_stats.function is not a string")
		}
		out.scrubBlock = "the last recorded scan is a " + strings.ToLower(out.function.text) +
			", and ZFS keeps only the most recent scan's record — the time since " +
			"the last completed scrub cannot be read from this pool"
	}
	return out, nil
}

func nilIfNone(v *value) *value {
	if isNone(v) {
		return nil
	}
	return v
}

func equalsPythonZero(v *value) bool {
	if v == nil {
		return false
	}
	switch v.kind {
	case jsonBool:
		return !v.boolean
	case jsonNumber:
		return numberIsZero(v.text)
	}
	return false
}

func bigFloat(n *big.Int) float64 {
	f, _ := new(big.Float).SetInt(n).Float64()
	return f
}

// epochISO is UTC always, second resolution, a literal trailing Z: no
// fractional part and no offset form, so two hosts' readings are comparable
// as text.
//
// The figure itself never reaches the error text: stderr goes straight to
// the journal and bypasses every redaction path, so a diagnostic names the
// member and never its value (DESIGN 19).
func epochISO(seconds *big.Int) (string, error) {
	if !seconds.IsInt64() {
		return "", errOutOfCalendar
	}
	moment := time.Unix(seconds.Int64(), 0).UTC()
	if year := moment.Year(); year < 1 || year > 9999 {
		return "", errOutOfCalendar
	}
	return moment.Format("2006-01-02T15:04:05Z"), nil
}

var errOutOfCalendar = errors.New("the scan end_time falls outside the representable calendar")
