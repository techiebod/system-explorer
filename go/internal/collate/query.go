// Fact filters and pagination for the objects route (register rows 11 and
// 12), ported from the shipping agent's envelope.apply_fact_filters and
// paginate — the semantics that survived three review passes there are
// carried, not re-derived.
//
// The one deliberate divergence: a value matches against its JSON
// spelling ("true", "95", raw arrays), not Python's str() ("True"). This
// wire serves JSON, and matching what a consumer can see in the response
// beats matching a spelling this implementation never emits.
package collate

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// ceilingFor reads one collection's declared record ceiling out of its
// declaration document; 0 when none is declared (the fallback bound then
// applies). Unreadable documents also yield 0 rather than an error: the
// bound degrades to the fallback, it does not take the route down.
func ceilingFor(document, collection string) int {
	if document == "" {
		return 0
	}
	var doc declaredDocument
	if json.Unmarshal([]byte(document), &doc) != nil {
		return 0
	}
	for _, c := range doc.Collections {
		if c.Name == collection {
			return c.Ceiling.Records
		}
	}
	return 0
}

// refusal is a request the route must refuse, with the same status the
// shipping agent used: a malformed question is 422, never an empty page —
// a mistyped filter indistinguishable from a healthy empty answer was
// rule 7's exact lie, and it lands hardest on the consumer with no column
// headers to glance at.
type refusal struct {
	status int
	detail string
}

const defaultPageLimit = 500
const fallbackMaxLimit = 1000

// parsePage splits a query string into fact filters and the two paging
// parameters. limit 0 means "not requested".
func parsePage(q url.Values) (map[string]string, int, string, *refusal) {
	filters := map[string]string{}
	limit := 0
	cursor := ""
	for key, values := range q {
		value := ""
		if len(values) > 0 {
			value = values[0]
		}
		switch key {
		case "limit":
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return nil, 0, "", &refusal{422, "limit must be an integer"}
			}
			if parsed < 1 {
				return nil, 0, "", &refusal{422, "limit must be >= 1"}
			}
			limit = parsed
		case "cursor":
			cursor = value
		default:
			filters[key] = value
		}
	}
	return filters, limit, cursor, nil
}

// fold is the near-miss equivalence: case and underscores. "activestate",
// "ACTIVESTATE" and "active_state" all fold to what "ActiveState" folds
// to — the guesses a consumer typing from memory actually makes.
func fold(key string) string {
	return strings.ReplaceAll(strings.ToLower(key), "_", "")
}

// checkNearMiss refuses a filter key that is a provable near-miss of a
// carried fact, naming the real one. Refusal stops at PROVABLE
// near-misses, deliberately: the fact vocabulary is open, so "no row
// carries this key right now" is a statement about the moment, not the
// vocabulary — ?RuntimeSynthesised=true on a host with no synthesised
// mounts is a correct question whose honest answer is the empty page,
// and refusing it would flip one query between ok and error as host
// state drifts. A typo with no near-miss gets the empty page too: on an
// open vocabulary the two cannot be told apart, and inventing an error
// would claim knowledge this tier does not have.
//
// carried is computed from the rows AS SERVED — after secret facts are
// withheld — so a secret fact is never a twin and never filterable: a
// filter over one matches nothing whatever the value, which is what
// keeps this route from becoming a value oracle for a fact it refuses
// to print.
func checkNearMiss(filters map[string]string, carried map[string]bool) *refusal {
	if len(filters) == 0 || len(carried) == 0 {
		return nil
	}
	names := make([]string, 0, len(carried))
	for name := range carried {
		names = append(names, name)
	}
	sort.Strings(names)
	for key := range filters {
		if carried[key] {
			continue
		}
		// Operators belong on the VALUE (?ActiveState=!failed); a key
		// wearing one is provably not a fact name, so strip them before
		// folding and the predictable misplacement finds its twin.
		folded := fold(strings.TrimSuffix(strings.TrimPrefix(key, "!"), "*"))
		for _, name := range names {
			if fold(name) == folded {
				return &refusal{422,
					"no fact named " + strconv.Quote(key) + " here, but " +
						strconv.Quote(name) + " is carried — fact names are " +
						"matched exactly"}
			}
		}
	}
	return nil
}

// factText is the spelling a value matches against: a JSON string
// unquoted, everything else its raw JSON token — numbers, booleans,
// arrays exactly as the response prints them.
func factText(raw []byte) string {
	text := string(raw)
	if unquoted, err := strconv.Unquote(text); err == nil && strings.HasPrefix(text, `"`) {
		return unquoted
	}
	return text
}

// matchValue applies one filter value to one fact spelling. A leading "!"
// negates, a trailing "*" prefix-matches, and they compose ("!/run*").
// present=false is an absent fact, which matches only negated filters:
// absence is not equal to anything, but it is honestly not-equal to
// everything.
func matchValue(text string, present bool, wanted string) bool {
	negate := strings.HasPrefix(wanted, "!")
	pattern := strings.TrimPrefix(wanted, "!")
	if !present {
		return negate
	}
	var hit bool
	if strings.HasSuffix(pattern, "*") {
		hit = strings.HasPrefix(text, strings.TrimSuffix(pattern, "*"))
	} else {
		hit = text == pattern
	}
	return hit != negate
}

// paginate is offset pagination over the filtered count: the cursor is an
// opaque stringified offset, explicit so a client never has to infer
// truncation, and the applied limit is bounded by the collection's own
// declared ceiling — a read must not serve more than the collection is
// allowed to hold (DESIGN 19: the ceiling is the collection's scope made
// visible, and this is the read side honouring it).
func paginate(total, requested int, cursor string, ceiling int) (offset, applied int, next *string) {
	maxLimit := fallbackMaxLimit
	if ceiling > 0 {
		maxLimit = ceiling
	}
	applied = requested
	if applied == 0 {
		applied = defaultPageLimit
	}
	if applied > maxLimit {
		applied = maxLimit
	}
	if parsed, err := strconv.Atoi(cursor); err == nil && parsed > 0 {
		offset = parsed
	}
	if offset > total {
		offset = total
	}
	if offset+applied < total {
		text := strconv.Itoa(offset + applied)
		next = &text
	}
	return offset, applied, next
}
