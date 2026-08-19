package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// The row this collection publishes, and its native name. One resolver
// answers one control socket, so the name is a constant rather than anything
// read out of a document: the collator mints `daemon:unbound` from the
// declared prefix and this name, which is the id the shipping adapter mints
// too.
const daemonName = "unbound"

// The stats records this collection lifts, and the fact each becomes.
//
// Keyed on the WHOLE record name, `total.` prefix included. That is the
// discriminating half: `stats_noreset` reports every counter twice on a
// multi-threaded resolver — once per thread as `threadN.…` and once summed as
// `total.…` — and a parse that matched on the tail would publish whichever
// line it read last, which on a two-thread daemon is one thread's traffic
// wearing the whole resolver's name.
var counters = map[string]string{
	"total.num.queries":             "NumQueries",
	"total.num.cachehits":           "CacheHits",
	"total.num.cachemiss":           "CacheMiss",
	"total.num.prefetch":            "Prefetches",
	"total.requestlist.current.all": "RequestListCurrent",
	"total.recursion.time.avg":      "RecursionTimeAvgSeconds",
}

// The two number shapes the reference's parse can produce, in ITS order: it
// tries int() first and float() second, so a token that satisfies both travels
// as an integer — which is the difference between `0` and `0.0` on the wire,
// and the whole of what typed equality is for.
var (
	integerToken    = regexp.MustCompile(`^[+-]?[0-9]+$`)
	jsonNumberToken = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
)

// numberToken renders one document value as the JSON number it will travel
// as, or reports that it is not a number at all — which is the reference's
// `continue`, dropping the record rather than publishing a guess.
func numberToken(text string) (string, bool) {
	if integerToken.MatchString(text) {
		// Arbitrary precision, because the value is carried rather than held.
		// big.Int also canonicalises what int() accepts and JSON does not: a
		// leading zero, a leading plus.
		if n, ok := new(big.Int).SetString(text, 10); ok {
			return n.String(), true
		}
		return "", false
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
		// Not a number, or one that cannot travel: JSON has no NaN and no
		// infinity. The reference would publish either — json.dumps writes a
		// bare NaN — and every reader downstream refuses the stream that
		// carries it, so omitting the fact is the lawful half of the same
		// reading rather than a different reading.
		return "", false
	}
	if jsonNumberToken.MatchString(text) {
		return text, true // the document's own spelling, digit for digit
	}
	return strconv.FormatFloat(value, 'g', -1, 64), true
}

// parseStatus reads the `status` document: `key: value` lines, of which two
// have envelope homes. Everything else — the verbosity, the module chain, the
// pid — stays in evidence, because a fact must be cited by an opinion, used in
// identity or a relation, or be part of the declared answer (DESIGN 15).
func parseStatus(text string, facts *factRow) {
	for _, line := range strings.Split(text, "\n") {
		key, value, _ := strings.Cut(line, ":")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case key == "version" && value != "":
			facts.setString("Version", value)
		case key == "uptime":
			// "3648 seconds" — the field is two tokens and only the first is
			// the number. Digits and nothing else: a signed or fractional
			// uptime is not a reading this daemon takes, and the reference's
			// own isdigit() test refuses both.
			fields := strings.Fields(value)
			if len(fields) > 0 && isASCIIDigits(fields[0]) {
				if token, ok := numberToken(fields[0]); ok {
					facts.set("Uptime", token)
				}
			}
		}
	}
}

// parseStats reads the `stats_noreset` document: strict `key=value` records,
// one per line, machine format rather than prose. A line with no `=` is not a
// record and a record this collection does not lift is not a fact.
func parseStats(text string, facts *factRow) {
	for _, line := range strings.Split(text, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		fact, wanted := counters[strings.TrimSpace(key)]
		if !wanted {
			continue
		}
		if token, ok := numberToken(strings.TrimSpace(value)); ok {
			facts.set(fact, token)
		}
	}
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// daemonRow is the whole derivation: two documents, one row. Both commands
// feed the same object — the status document names the daemon and the stats
// document says what it has been doing — so a collector that published a row
// per document would be answering a question nobody asked.
func daemonRow(got reading) *factRow {
	facts := newFactRow()
	parseStatus(got.status, facts)
	parseStats(got.stats, facts)
	return facts
}

// collectDaemon serves the one collection this collector answers for.
func collectDaemon(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	got, err := src.daemon()
	var refused *declined
	if errors.As(err, &refused) {
		if err.Error() != refused.Error() {
			// The record carries the constant, because decline detail travels
			// to a hub and out over MCP. Whatever the seam wrapped around it —
			// the errno, the socket path, the daemon's own refusal — stays
			// here on stderr, where a person debugging can read it and no
			// redaction path has to be reviewed for it. Printed only when
			// there IS something wrapped, so an ordinary absence does not
			// restate itself into the journal on every sweep.
			fmt.Fprintln(stderr, "daemon:", err)
		}
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// absent is authoritative-empty: it must be able to retire the daemon
		// a previous batch published, so it declines AND commits zero. No
		// other reason commits — nothing was established, so prior state
		// stands and the collator marks it stale.
		if refused.reason == "absent" {
			out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		}
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	out.emit(objectRecord{
		Record:     "object",
		Collection: collection,
		Name:       daemonName,
		Facts:      daemonRow(got).encode(),
		At:         src.stamp(*objects),
	})
	*objects++
	// One row, no health and no relations: no opinion, no severity, no
	// assertion, no unobservable. The zeroes below are the statement rather
	// than a placeholder — this collection reports what the resolver said and
	// judges none of it, which is the same stance the subsystem took before
	// the tier split.
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    1,
	})
	return exitOK
}
