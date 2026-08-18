package main

import (
	"testing"
)

// 2026-08-16T09:00:00Z, the moment the healthy capture was taken.
const capturedNow = 1786870800.0

func readScan(t *testing.T, raw string) *scanReading {
	t.Helper()
	reading, err := computeScanFacts(mustDecode(t, raw), capturedNow)
	if err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	return reading
}

// Zero means "has not ended", not the epoch. A port that formats any int as
// a timestamp reports a pool scrubbing right now as last scrubbed
// 1970-01-01, twenty thousand days ago — found live on a scrubbing pool.
func TestAnEndTimeOfZeroIsNoEndAtAll(t *testing.T) {
	for _, raw := range []string{
		`{"function": "SCRUB", "state": "SCANNING", "end_time": 0}`,
		`{"function": "SCRUB", "state": "SCANNING", "end_time": 0.0}`,
		`{"function": "SCRUB", "state": "SCANNING", "end_time": false}`,
	} {
		scan := readScan(t, raw)
		if scan.endTime != nil {
			t.Errorf("%s: end time %s", raw, scan.endTime.encode())
		}
		if scan.hasAge {
			t.Errorf("%s: an age was derived from a scan that has not ended", raw)
		}
	}
}

func TestAnIntegerEndTimeBecomesUTCToTheSecond(t *testing.T) {
	scan := readScan(t, `{"function": "SCRUB", "state": "FINISHED", "end_time": 1786602071}`)
	if scan.endTime == nil || scan.endTime.text != "2026-08-13T06:21:11Z" {
		t.Fatalf("end time %v", scan.endTime)
	}
	// (1786870800 - 1786602071) // 86400 == 3
	if !scan.hasAge || scan.ageDays.Int64() != 3 {
		t.Fatalf("age %v", scan.ageDays)
	}
}

// Whole days by FLOOR division, so a scan whose end time is in the future
// reads negative rather than being clamped to a comfortable zero.
func TestAFutureEndTimeReadsNegative(t *testing.T) {
	scan := readScan(t, `{"end_time": 1786970800}`)
	if !scan.hasAge || scan.ageDays.Int64() != -2 {
		t.Fatalf("age %v", scan.ageDays)
	}
}

// An OpenZFS too old for --json-int renders end_time as prose. It is kept
// verbatim and no age is derived; a number carrying a fraction is a float,
// which is not an epoch either.
func TestANonIntegerEndTimeIsCarriedVerbatimWithNoAge(t *testing.T) {
	prose := readScan(t, `{"end_time": "Sun 1 Feb 16:14:52 GMT 2026"}`)
	if prose.endTime == nil || prose.endTime.text != "Sun 1 Feb 16:14:52 GMT 2026" || prose.hasAge {
		t.Fatalf("prose: %v hasAge=%v", prose.endTime, prose.hasAge)
	}
	float := readScan(t, `{"end_time": 1786602071.0}`)
	if float.endTime == nil || float.endTime.kind != jsonNumber || float.hasAge {
		t.Fatalf("float: %v hasAge=%v", float.endTime, float.hasAge)
	}
}

// A resilver REPLACES the scrub's record, so after one the time since the
// last completed scrub cannot be read from this pool at all. Silence beside
// a months-stale scrub is absence-as-health; the pair states the unknown.
func TestAResilverBlocksTheScrubReading(t *testing.T) {
	scan := readScan(t, `{"function": "RESILVER", "state": "FINISHED", "end_time": 1786602071}`)
	want := "the last recorded scan is a resilver, and ZFS keeps only the most " +
		"recent scan's record — the time since the last completed scrub cannot " +
		"be read from this pool"
	if scan.scrubBlock != want {
		t.Fatalf("reason %q", scan.scrubBlock)
	}
	if plain := readScan(t, `{"function": "SCRUB"}`); plain.scrubBlock != "" {
		t.Error("a scrub record blocks nothing")
	}
	if none := readScan(t, `{}`); none.scrubBlock != "" {
		t.Error("no record at all blocks nothing")
	}
}

// An empty scan_stats and a missing one are the same statement, because the
// reference collapses both before reading anything out of it.
func TestNoScanRecordLeavesEveryScanFactUnset(t *testing.T) {
	for _, raw := range []string{`{}`, `null`} {
		scan := readScan(t, raw)
		if scan.function != nil || scan.state != nil || scan.endTime != nil || scan.hasAge {
			t.Errorf("%s: %+v", raw, scan)
		}
	}
}
