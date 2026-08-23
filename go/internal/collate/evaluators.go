package collate

// The named evaluators: the fifth of opinions that need real code
// (DESIGN 17, ruled 2026-08-23).
//
// **Why this exists at all.** The condition vocabulary is closed and
// small on purpose — an expression language that could grow becomes a
// plugin-supplied evaluator by increments, which is third-party code in
// the judging path. Two rules in the ported fleet cannot be expressed in
// it: a slice's stall judged against `StallExplainedBy`, which is a map
// indexed by another fact's own NAME, and protection's target coverage,
// which is set algebra over hop lists. Widening the vocabulary for two
// rules was refused — appendix A's budget asks a new member to delete one
// or name a defect it alone catches — so the derivation stays in code and
// the opinion stays declared.
//
// **Three properties make this a mechanism rather than an escape hatch,
// and the first is the one that matters.** This table is CLOSED and
// in-tree: a declaration NAMES an evaluator and cannot ship one. So a
// plugin gains no ability to run code here, which is the whole line the
// rules-as-data design rests on.
//
// The second: the rule row keeps every other member — key, level,
// grounds, sentence, cites — so a surface renders it identically to a
// table-decided one, nothing arrives at the collator undeclared, and the
// declaration itself says which opinions the table does not decide.
//
// The third is the cost, stated where it bites rather than discovered by
// whoever hits it: **a collector this repository does not ship can
// express the four fifths and cannot express these.** A third case
// reopens the decision, because two rules justify a seam and a steady
// trickle would mean the vocabulary is wrong.

import (
	"fmt"
	"sort"
)

// An evaluator decides one rule over one object's facts. It returns
// whether the rule fired, and it may not return an error: an evaluator
// that cannot decide reports false, for the same reason an unevaluable
// condition does not fire — the honest reading of "I could not decide"
// is silence rather than alarm.
type evaluator func(facts map[string]any) bool

// evaluators is the closed set. Adding a member is a deliberate act and
// a review, exactly as adding a vocabulary member is.
var evaluators = map[string]evaluator{
	// resources: a slice's stall, judged against the per-fact
	// attribution maps. Three, because the reference states three
	// different things and the difference between them is the point —
	// an unread member is not a quiet one.
	"slice-stall-unexplained":       sliceStallUnexplained,
	"slice-stall-unexplained-minor": sliceStallUnexplainedMinor,
	"slice-stall-unattributed":      sliceStallUnattributed,
	// protection: set algebra over hop lists. Three, and they are
	// MUTUALLY EXCLUSIVE — the reference is an if/elif/else, and rules
	// evaluate independently, so each evaluator carries the exclusion
	// its branch had. Without that a target would state three severities
	// of one condition at once.
	"protection-no-durable-copy":    protectionNoDurableCopy,
	"protection-no-durable-history": protectionNoDurableHistory,
	"protection-hop-unimplemented":  protectionHopUnimplemented,
}

// KnownEvaluator reports whether a name is in the closed set. Exported so
// RulesFor can refuse a declaration naming one that does not exist —
// refused rather than skipped, because a rule silently dropped is an
// opinion an operator expects and never sees.
func KnownEvaluator(name string) bool {
	_, held := evaluators[name]
	return held
}

// EvaluatorNames is the set, sorted — for the refusal message, so a
// declaration that named a typo is told what it could have named.
func EvaluatorNames() []string {
	names := make([]string, 0, len(evaluators))
	for name := range evaluators {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func evaluate(name string, facts map[string]any) bool {
	run, held := evaluators[name]
	if !held {
		// Unreachable through RulesFor, which refuses an unknown name at
		// load. Silence rather than a panic if it is ever reached another
		// way: a judging path that crashes on a bad declaration costs the
		// host every other opinion in the collection.
		return false
	}
	return run(facts)
}

// --- resources: a slice stalling that nothing inside it accounts for ---

// sliceStallFloor is the share of a minute below which a slice states
// nothing at all. The gap between a slice and its members at that size is
// inside the slack the attribution already allows for two independently
// decaying averages, so a claim either way is a coin toss dressed as a
// finding — and the number stays on the row for anyone who wants it.
const sliceStallFloor = 1.0

// sliceStallAttention is the share at which a slice's own UNEXPLAINED
// stall claims attention, per resource: the same bar a single workload
// must clear. Ours, which is why these rules carry `threshold` grounds.
//
// The map is keyed by the FACT'S OWN NAME, and so are the three
// attribution facts — which is precisely what the condition vocabulary
// cannot express. It tests a fact against a value; it cannot test a map
// against a key it computes from the fact it is already reading.
var sliceStallAttention = map[string]float64{
	"PsiIoFullAvg60":     20.0,
	"PsiMemoryFullAvg60": 10.0,
}

// sliceStallResources is the readings a slice is judged on. One list, so
// the tables keyed by these facts cannot come to disagree about which
// readings a slice states anything about.
var sliceStallResources = []string{"PsiIoFullAvg60", "PsiMemoryFullAvg60"}

// sliceStallUnexplained fires where a slice is stalling and no member
// workload accounts for it.
//
// **A slice's stall is not its own finding when a member explains it.** A
// slice's "full" share is the time in which every non-idle task under it
// was stalled, so a member making progress LOWERS it: the slice is both
// less specific than the member responsible and smaller than it. Found by
// the operator on 2026-08-13 — a container scope at 65.27% listed
// directly beneath the slice containing it at 56.35%, one stall reported
// twice, the second time with the culprit's name removed.
//
// **And an unread member is not a quiet one.** Where attribution could
// not be established, this does NOT fire: reporting it as "nothing
// explains this" would invent the interesting finding out of a gap in the
// reading. That case is its own rule with its own wording.
//
// **Each resource is judged on its own facts.** A slice can be explained
// for I/O and unexplained for memory in the same minute, and one boolean
// across both would be false for one of them.
func sliceStallUnexplained(facts map[string]any) bool {
	return unexplainedStall(facts, func(name string, stall float64) bool {
		return stall >= sliceStallAttention[name]
	})
}

// sliceStallUnexplainedMinor is the same condition below the attention
// bar. Its own rule at `info` rather than a level computed inside one
// evaluator, because the LEVEL is a declared member a reader can see and
// disagree with — moving it into code would hide a policy decision inside
// a word that means "not a decision" (DESIGN 17).
func sliceStallUnexplainedMinor(facts map[string]any) bool {
	return unexplainedStall(facts, func(name string, stall float64) bool {
		return stall < sliceStallAttention[name]
	})
}

func unexplainedStall(facts map[string]any, band func(string, float64) bool) bool {
	explained := mapFact(facts, "StallExplainedBy")
	unobservable := mapFact(facts, "StallAttributionUnobservable")
	unexplained := mapFact(facts, "StallUnexplained")
	for _, name := range sliceStallResources {
		stall, ok := numberFact(facts, name)
		if !ok || stall < sliceStallFloor || !band(name, stall) {
			continue
		}
		if truthy(explained[name]) || truthy(unobservable[name]) {
			continue
		}
		if truthy(unexplained[name]) {
			return true
		}
	}
	return false
}

// sliceStallUnattributed fires where a slice is stalling and whether a
// member accounts for it COULD NOT BE ESTABLISHED.
//
// Worded and levelled differently from the unexplained case on purpose:
// pressure that could not be read is not pressure that was absent, so
// this is a gap in the reading rather than a finding about the slice.
// Reporting it as "nothing explains this" would invent the interesting
// finding out of a hole in the evidence — the founding failure, inverted.
func sliceStallUnattributed(facts map[string]any) bool {
	unobservable := mapFact(facts, "StallAttributionUnobservable")
	explained := mapFact(facts, "StallExplainedBy")
	for _, name := range sliceStallResources {
		stall, ok := numberFact(facts, name)
		if !ok || stall < sliceStallFloor {
			continue
		}
		if truthy(explained[name]) {
			continue
		}
		if truthy(unobservable[name]) {
			return true
		}
	}
	return false
}

// --- protection: a declared target nothing sends to -------------------

// durableGap is the set test the whole protection family turns on: EVERY
// independent destination this target declares is among the hops that
// were never built.
//
// **Set algebra over two carried lists**, which is what the vocabulary
// cannot express: `non_empty` can say a list has members and `in` can
// test a scalar against a LITERAL set, but neither can test one carried
// list for containment in another.
//
// An empty independent set is not a gap: a target that declares no
// independent destination has nothing this rule can find missing, and
// treating the empty set as trivially contained would fire on every
// target in the estate.
func durableGap(facts map[string]any) bool {
	independent := stringsFact(facts, "IndependentDestinations")
	if len(independent) == 0 {
		return false
	}
	missing := map[string]bool{}
	for _, hop := range stringsFact(facts, "UnimplementedHops") {
		missing[hop] = true
	}
	for _, destination := range independent {
		if !missing[destination] {
			return false
		}
	}
	return true
}

// The three protection target rules are MUTUALLY EXCLUSIVE. The reference
// is an if/elif/else and rules here evaluate independently, so each
// evaluator carries the exclusion its branch had — without it a target
// would state three severities of one condition at once, which is the
// severity column teaching an operator that it cannot be trusted.
//
// The two fields the split turns on are not one field. `Class` says the
// ESTATE cannot recreate this from its own definitions; it does not say
// the data exists nowhere else. `Kind` is what distinguishes them: a
// saas-pull's original still lives with a provider the estate does not
// control, so losing every copy here costs a re-download — and the
// deletion history, which is the actual reason such a target is classed
// backup at all. Grading it beside a target that exists nowhere else
// overstates the loss on exactly the rows an operator would check first.
func protectionNoDurableHistory(facts map[string]any) bool {
	return len(stringsFact(facts, "UnimplementedHops")) > 0 &&
		facts["Class"] == "backup" && facts["Kind"] == "saas-pull" &&
		durableGap(facts)
}

func protectionNoDurableCopy(facts map[string]any) bool {
	return len(stringsFact(facts, "UnimplementedHops")) > 0 &&
		facts["Class"] == "backup" && facts["Kind"] != "saas-pull" &&
		durableGap(facts)
}

// protectionHopUnimplemented is the residual branch: something is
// declared and unbuilt, but it is not the whole independent set. The
// target's other hops can read green while this one has no job behind it.
func protectionHopUnimplemented(facts map[string]any) bool {
	if len(stringsFact(facts, "UnimplementedHops")) == 0 {
		return false
	}
	return !(facts["Class"] == "backup" && durableGap(facts))
}

// --- reading facts, the same way match() does -------------------------

// numberFact reads a numeric fact. JSON numbers decode as float64, and an
// integer arriving as some other Go numeric type is a caller that built
// facts by hand — accepted, because the alternative is a rule that is
// silently false in a test and true in production.
func numberFact(facts map[string]any, name string) (float64, bool) {
	switch value := facts[name].(type) {
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	default:
		return 0, false
	}
}

func mapFact(facts map[string]any, name string) map[string]any {
	if held, ok := facts[name].(map[string]any); ok {
		return held
	}
	return map[string]any{}
}

func stringsFact(facts map[string]any, name string) []string {
	raw, ok := facts[name].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// truthy reads a map member that may be a bool or a reason string. Both
// shapes appear: StallExplainedBy carries the accounting workload's name,
// StallUnexplained carries a boolean. A non-empty string is a statement
// that something was found, which is what "explained" means.
func truthy(value any) bool {
	switch held := value.(type) {
	case bool:
		return held
	case string:
		return held != ""
	case nil:
		return false
	default:
		return true
	}
}

// evaluatorRefusal is the message a declaration naming an unknown
// evaluator gets. Named so the refusal is one sentence in one place.
func evaluatorRefusal(key, name, collection string) error {
	return fmt.Errorf(
		"rule %q in %s names the evaluator %q, which this collator does not "+
			"have; the set is closed and in-tree — a declaration NAMES an "+
			"evaluator and cannot ship one — and the names are %v",
		key, collection, name, EvaluatorNames())
}
