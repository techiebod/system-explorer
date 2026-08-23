// Self-evident opinions, evaluated from the rule table a declaration
// carries (DESIGN 17, contract/se.declaration.1.json).
//
// **Here, because this is the lowest tier that can reach the facts.** Law
// 2 puts an opinion at that tier and nowhere else, and for a fact about
// one host that tier is the collator: the collector produced the reading
// and the hub is a network hop away from it. A collector gains no new
// obligation for this — the rules are DATA in the declaration it already
// publishes, so a plugin says why one of its facts is alarming without
// shipping any judging code at all.
//
// **Only self-evident opinions live here, and that is not a preference.**
// Intent never reaches a host, so a rule travelling with a declaration
// cannot be intent-relative; those are the hub's, from intent.
//
// **A rule may only cite and read facts the same collection declares.**
// That is acceptance item 7 at the rule table: a fact with no declared
// axis has no kind, no unit and no sentence, so an opinion resting on one
// would be a judgement nobody can interpret and a citation nobody can
// follow.
package collate

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Rule is one row of a collection's declared rule table.
type Rule struct {
	Key     string          `json:"key"`
	Level   string          `json:"level"`
	Grounds string          `json:"grounds"`
	When    json.RawMessage `json:"when"`
	// Evaluator names an in-tree function that decides this rule instead
	// of a condition (DESIGN 17, ruled 2026-08-23). Exactly one of When
	// and Evaluator is carried; the contract holds that with a oneOf and
	// RulesFor holds it here, because a rule with both is two answers to
	// one question and a rule with neither fires on nothing.
	Evaluator string   `json:"evaluator"`
	Sentence  string   `json:"sentence"`
	Cites     []string `json:"cites"`
}

// Opinion is one fired rule about one object.
type Opinion struct {
	Object   string   `json:"object"`
	Instance *string  `json:"instance"`
	Key      string   `json:"key"`
	Level    string   `json:"level"`
	Grounds  string   `json:"grounds"`
	Sentence string   `json:"sentence"`
	Cites    []string `json:"cites"`
}

type declaredFact struct {
	Discloses string `json:"discloses"`
}

type declaredCollection struct {
	Name     string                     `json:"name"`
	Question string                     `json:"question"`
	Prefix   string                     `json:"prefix"`
	Facts    map[string]json.RawMessage `json:"facts"`
	Rules    []Rule                     `json:"rules"`
	// The declared record ceiling, honoured by the read side too: a page
	// may never serve more than the collection is allowed to hold.
	Ceiling struct {
		Records int `json:"records"`
	} `json:"ceiling"`
}

type declaredDocument struct {
	Collections []declaredCollection `json:"collections"`
}

// RulesFor returns one collection's rule table from a declaration
// document, and refuses a table that reaches outside what the collection
// declares.
//
// Refused rather than skipped: a rule quietly dropped for citing an
// undeclared fact is an opinion an operator expects and never sees, which
// is worse than a collector that will not load. An empty document (a
// store written before declarations were kept) yields no rules and no
// error — it cannot evaluate, and saying "no rules" would be reporting
// absence where nobody could ask.
func RulesFor(document, collection string) ([]Rule, error) {
	if document == "" {
		return nil, nil
	}
	var doc declaredDocument
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return nil, fmt.Errorf("declaration is unreadable: %w", err)
	}
	for _, c := range doc.Collections {
		if c.Name != collection {
			continue
		}
		for _, rule := range c.Rules {
			for _, cited := range rule.Cites {
				if _, ok := c.Facts[cited]; !ok {
					return nil, fmt.Errorf(
						"rule %q cites %q, which %s does not declare; an opinion may "+
							"only cite what a reader can go and look at",
						rule.Key, cited, collection)
				}
			}
			hasWhen := len(rule.When) > 0
			hasEvaluator := rule.Evaluator != ""
			if hasWhen == hasEvaluator {
				// Refused rather than resolved by precedence: a rule
				// carrying both is two answers to one question with no
				// stated winner, and one carrying neither is an opinion
				// that can never fire — an operator would wait for it.
				return nil, fmt.Errorf(
					"rule %q in %s carries %s; a rule is decided by a condition "+
						"or by a named evaluator, and exactly one of them",
					rule.Key, collection,
					map[bool]string{true: "both a condition and an evaluator",
						false: "neither a condition nor an evaluator"}[hasWhen])
			}
			if hasEvaluator && !KnownEvaluator(rule.Evaluator) {
				return nil, evaluatorRefusal(rule.Key, rule.Evaluator, collection)
			}
			if err := checkConditionFacts(rule.When, c.Facts, rule.Key, collection); err != nil {
				return nil, err
			}
		}
		return c.Rules, nil
	}
	return nil, nil
}

// checkConditionFacts walks a condition and refuses any leaf naming a
// fact the collection does not declare — the same rule as `cites`, on the
// other half of the rule, because a condition READING an undeclared fact
// would let one decide an opinion without ever appearing in its citation
// list.
func checkConditionFacts(raw json.RawMessage, facts map[string]json.RawMessage,
	key, collection string) error {
	if len(raw) == 0 {
		return nil
	}
	var node map[string]json.RawMessage
	if err := json.Unmarshal(raw, &node); err != nil {
		return fmt.Errorf("rule %q has an unreadable condition: %w", key, err)
	}
	if nested, ok := node["all"]; ok {
		return checkConditionList(nested, facts, key, collection)
	}
	if nested, ok := node["any"]; ok {
		return checkConditionList(nested, facts, key, collection)
	}
	if nested, ok := node["not"]; ok {
		return checkConditionFacts(nested, facts, key, collection)
	}
	if rawFact, ok := node["fact"]; ok {
		var name string
		if err := json.Unmarshal(rawFact, &name); err != nil {
			return fmt.Errorf("rule %q names an unreadable fact: %w", key, err)
		}
		if _, declared := facts[name]; !declared {
			return fmt.Errorf(
				"rule %q reads %q, which %s does not declare; a condition on an "+
					"undeclared fact decides an opinion without appearing in its citations",
				key, name, collection)
		}
	}
	return nil
}

func checkConditionList(raw json.RawMessage, facts map[string]json.RawMessage,
	key, collection string) error {
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("rule %q has an unreadable condition list: %w", key, err)
	}
	for _, item := range list {
		if err := checkConditionFacts(item, facts, key, collection); err != nil {
			return err
		}
	}
	return nil
}

// Judge applies a rule table to one object's facts.
func Judge(rules []Rule, object string, instance *string, facts map[string]any) []Opinion {
	var out []Opinion
	for _, rule := range rules {
		var fired bool
		var err error
		if rule.Evaluator != "" {
			// The declared row decides everything a reader sees; only the
			// TEST is code. An evaluator returns no error for the same
			// reason an unevaluable condition does not fire: "I could not
			// decide" reads as silence, never as alarm.
			fired = evaluate(rule.Evaluator, facts)
		} else {
			fired, err = match(rule.When, facts)
		}
		if err != nil || !fired {
			// A condition that could not be evaluated does NOT fire. An
			// opinion minted from a comparison that failed would be a
			// judgement about nothing, and the honest reading of "I could
			// not decide" is silence rather than alarm.
			continue
		}
		out = append(out, Opinion{
			Object: object, Instance: instance, Key: rule.Key, Level: rule.Level,
			Grounds: rule.Grounds, Sentence: rule.Sentence, Cites: rule.Cites,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func match(raw json.RawMessage, facts map[string]any) (bool, error) {
	var node map[string]json.RawMessage
	if err := json.Unmarshal(raw, &node); err != nil {
		return false, err
	}
	if nested, ok := node["all"]; ok {
		return every(nested, facts, true)
	}
	if nested, ok := node["any"]; ok {
		return every(nested, facts, false)
	}
	if nested, ok := node["not"]; ok {
		inner, err := match(nested, facts)
		if err != nil {
			return false, err
		}
		return !inner, nil
	}
	rawFact, ok := node["fact"]
	if !ok {
		return false, fmt.Errorf("condition names no fact")
	}
	var name string
	if err := json.Unmarshal(rawFact, &name); err != nil {
		return false, err
	}
	value, has := facts[name]

	if want, ok := node["present"]; ok {
		var expected bool
		if err := json.Unmarshal(want, &expected); err != nil {
			return false, err
		}
		// Presence, never truthiness: zero, false and the empty string are
		// readings, and treating them as absence is the null-fact family
		// arriving in the judging layer.
		return has == expected, nil
	}
	if !has {
		// Every other test needs a value. A missing fact makes the test
		// undecidable rather than false — see Judge: undecidable is silence.
		return false, nil
	}
	if want, ok := node["non_empty"]; ok {
		var expected bool
		if err := json.Unmarshal(want, &expected); err != nil {
			return false, err
		}
		list, isList := value.([]any)
		return isList && (len(list) > 0) == expected, nil
	}
	if want, ok := node["equals"]; ok {
		return sameJSON(value, want)
	}
	if want, ok := node["not_equals"]; ok {
		same, err := sameJSON(value, want)
		return !same, err
	}
	if want, ok := node["in"]; ok {
		var options []json.RawMessage
		if err := json.Unmarshal(want, &options); err != nil {
			return false, err
		}
		for _, option := range options {
			if same, err := sameJSON(value, option); err == nil && same {
				return true, nil
			}
		}
		return false, nil
	}
	if want, ok := node["at_least"]; ok {
		return compare(value, want, func(a, b float64) bool { return a >= b })
	}
	if want, ok := node["at_most"]; ok {
		return compare(value, want, func(a, b float64) bool { return a <= b })
	}
	return false, fmt.Errorf("condition carries no recognised test")
}

func every(raw json.RawMessage, facts map[string]any, all bool) (bool, error) {
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return false, err
	}
	for _, item := range list {
		got, err := match(item, facts)
		if err != nil {
			return false, err
		}
		if all && !got {
			return false, nil
		}
		if !all && got {
			return true, nil
		}
	}
	return all, nil
}

func sameJSON(value any, want json.RawMessage) (bool, error) {
	var expected any
	if err := json.Unmarshal(want, &expected); err != nil {
		return false, err
	}
	left, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	right, err := json.Marshal(expected)
	if err != nil {
		return false, err
	}
	return string(left) == string(right), nil
}

func compare(value any, want json.RawMessage, ok func(a, b float64) bool) (bool, error) {
	number, isNumber := value.(float64)
	if !isNumber {
		// A numeric test against a non-number is undecidable, not false.
		return false, fmt.Errorf("not a number")
	}
	var threshold float64
	if err := json.Unmarshal(want, &threshold); err != nil {
		return false, err
	}
	return ok(number, threshold), nil
}

// SecretFacts names the values a collection declares as credentials.
//
// `secret` means withheld at source and never emitted, so one arriving
// here is already a collector misbehaving — which is exactly why every
// tier that can check does. A plugin is code this repository does not
// ship, and defence that only works when everybody behaves is not
// defence. The NAME is not the secret and is reported, so a reader can
// tell a withheld value from an absent one.
func SecretFacts(document, collection string) (map[string]bool, error) {
	if document == "" {
		return nil, nil
	}
	var doc struct {
		Collections []struct {
			Name  string                  `json:"name"`
			Facts map[string]declaredFact `json:"facts"`
		} `json:"collections"`
	}
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return nil, fmt.Errorf("declaration is unreadable: %w", err)
	}
	for _, c := range doc.Collections {
		if c.Name != collection {
			continue
		}
		out := map[string]bool{}
		for name, spec := range c.Facts {
			if spec.Discloses == "secret" {
				out[name] = true
			}
		}
		return out, nil
	}
	return nil, nil
}
