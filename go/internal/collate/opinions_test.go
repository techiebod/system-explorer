// The rule table: what fires, what does not, and what is refused outright.
package collate

import (
	"encoding/json"
	"strings"
	"testing"
)

func declWithRules(rules string) string {
	return `{"schema":"se.declaration/1","collector":"storage","version":"0.7.0",
	 "collections":[{"name":"pools","question":"q","prefix":"pool","freshness":"60s",
	 "perishability":"perishable","answer":["State"],
	 "facts":{"State":{"type":"string","temperament":"state","kind":"observed","discloses":"nothing","sentence":"."},
	          "CapacityPercent":{"type":"integer","temperament":"gauge","kind":"observed","discloses":"nothing","sentence":"."},
	          "UnhealthyVdevs":{"type":"list","temperament":"state","kind":"derived","discloses":"nothing","sentence":"."}},
	 "rules":` + rules + `}]}`
}

func rulesOrFail(t *testing.T, document string) []Rule {
	t.Helper()
	rules, err := RulesFor(document, "pools")
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	return rules
}

func facts(t *testing.T, raw string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAnInterfaceGroundedRuleFires(t *testing.T) {
	rules := rulesOrFail(t, declWithRules(`[{"key":"pool-degraded","level":"critical",
	 "grounds":"interface","when":{"fact":"State","equals":"degraded"},
	 "sentence":"ZFS reports this pool degraded.","cites":["State"]}]`))
	got := Judge(rules, "pool:tank", nil, facts(t, `{"State":"degraded"}`))
	if len(got) != 1 || got[0].Key != "pool-degraded" || got[0].Grounds != "interface" {
		t.Fatalf("%+v", got)
	}
	if len(Judge(rules, "pool:tank", nil, facts(t, `{"State":"ok"}`))) != 0 {
		t.Fatal("a healthy pool must mint no opinion")
	}
}

func TestAThresholdRuleKeepsItsGroundsDistinct(t *testing.T) {
	// 90 is OUR number, and a surface rendering it identically to the
	// interface's own verdict would present our opinion as the machine's.
	rules := rulesOrFail(t, declWithRules(`[{"key":"pool-nearly-full","level":"warn",
	 "grounds":"threshold","when":{"fact":"CapacityPercent","at_least":90},
	 "sentence":"This pool is above 90% full.","cites":["CapacityPercent"]}]`))
	got := Judge(rules, "pool:tank", nil, facts(t, `{"CapacityPercent":93}`))
	if len(got) != 1 || got[0].Grounds != "threshold" {
		t.Fatalf("%+v", got)
	}
	if len(Judge(rules, "pool:tank", nil, facts(t, `{"CapacityPercent":89}`))) != 0 {
		t.Fatal("below the threshold is silence")
	}
}

func TestPresenceIsNotTruthiness(t *testing.T) {
	rules := rulesOrFail(t, declWithRules(`[{"key":"capacity-unread","level":"info",
	 "grounds":"interface","when":{"fact":"CapacityPercent","present":false},
	 "sentence":"No capacity reading.","cites":["CapacityPercent"]}]`))
	if len(Judge(rules, "p", nil, facts(t, `{"CapacityPercent":0}`))) != 0 {
		t.Fatal("zero is a reading; treating it as absence is the null-fact family in the judging layer")
	}
	if len(Judge(rules, "p", nil, facts(t, `{"State":"ok"}`))) != 1 {
		t.Fatal("a genuinely absent fact must fire present:false")
	}
}

func TestAnEmptyListIsAReadingAndAMissingOneIsNot(t *testing.T) {
	rules := rulesOrFail(t, declWithRules(`[{"key":"vdevs-unhealthy","level":"warn",
	 "grounds":"interface","when":{"fact":"UnhealthyVdevs","non_empty":true},
	 "sentence":"Some vdevs are unhealthy.","cites":["UnhealthyVdevs"]}]`))
	if len(Judge(rules, "p", nil, facts(t, `{"UnhealthyVdevs":[]}`))) != 0 {
		t.Fatal("an empty list is a reading of health")
	}
	if len(Judge(rules, "p", nil, facts(t, `{"UnhealthyVdevs":["a"]}`))) != 1 {
		t.Fatal("a populated list must fire")
	}
	if len(Judge(rules, "p", nil, facts(t, `{}`))) != 0 {
		t.Fatal("a missing list is undecidable, and undecidable is silence")
	}
}

func TestCompoundConditions(t *testing.T) {
	rules := rulesOrFail(t, declWithRules(`[{"key":"degraded-and-full","level":"critical",
	 "grounds":"threshold","when":{"all":[{"fact":"State","equals":"degraded"},
	  {"fact":"CapacityPercent","at_least":90}]},
	 "sentence":"Degraded and nearly full.","cites":["State","CapacityPercent"]},
	 {"key":"not-ok","level":"info","grounds":"interface",
	  "when":{"not":{"fact":"State","equals":"ok"}},
	  "sentence":"Not ok.","cites":["State"]},
	 {"key":"either","level":"info","grounds":"interface",
	  "when":{"any":[{"fact":"State","equals":"gone"},{"fact":"State","in":["degraded","faulted"]}]},
	  "sentence":"Either.","cites":["State"]}]`))
	got := Judge(rules, "p", nil, facts(t, `{"State":"degraded","CapacityPercent":95}`))
	keys := []string{}
	for _, o := range got {
		keys = append(keys, o.Key)
	}
	if strings.Join(keys, ",") != "degraded-and-full,either,not-ok" {
		t.Fatalf("all three fire, in key order: %v", keys)
	}
	if len(Judge(rules, "p", nil, facts(t, `{"State":"ok","CapacityPercent":95}`))) != 0 {
		t.Fatal("an ok pool below every condition mints nothing")
	}
}

// Acceptance item 7's last half, at the rule table.
func TestARuleCitingAnUndeclaredFactIsRefused(t *testing.T) {
	_, err := RulesFor(declWithRules(`[{"key":"k","level":"warn","grounds":"interface",
	 "when":{"fact":"State","equals":"degraded"},"sentence":"s","cites":["Invented"]}]`), "pools")
	if err == nil || !strings.Contains(err.Error(), "go and look at") {
		t.Fatalf("an opinion may only cite declared facts: %v", err)
	}
}

func TestARuleReadingAnUndeclaredFactIsRefused(t *testing.T) {
	// The other half: a condition on an undeclared fact would decide an
	// opinion without ever appearing in its citation list.
	_, err := RulesFor(declWithRules(`[{"key":"k","level":"warn","grounds":"interface",
	 "when":{"all":[{"fact":"State","equals":"degraded"},{"fact":"Invented","equals":1}]},
	 "sentence":"s","cites":["State"]}]`), "pools")
	if err == nil || !strings.Contains(err.Error(), "without appearing in its citations") {
		t.Fatalf("a condition may only read declared facts: %v", err)
	}
}

func TestNoDeclarationYieldsNoRulesAndNoClaim(t *testing.T) {
	rules, err := RulesFor("", "pools")
	if err != nil || rules != nil {
		t.Fatalf("a store that cannot produce a declaration cannot evaluate, and "+
			"saying 'no rules' would report absence where nobody could ask: %v %v", rules, err)
	}
}

func TestACollectionWithNoRuleTableIsSilentNotEmpty(t *testing.T) {
	rules, err := RulesFor(declWithRules(`[]`), "pools")
	if err != nil {
		t.Fatal(err)
	}
	// An empty table is DECLARED: it evaluates to no opinions, which is a
	// different statement from a collection that declared none at all.
	if rules == nil || len(rules) != 0 {
		t.Fatalf("an empty table is a table: %v", rules)
	}
}

func TestAnUndecidableComparisonIsSilence(t *testing.T) {
	rules := rulesOrFail(t, declWithRules(`[{"key":"k","level":"warn","grounds":"threshold",
	 "when":{"fact":"State","at_least":90},"sentence":"s","cites":["State"]}]`))
	if len(Judge(rules, "p", nil, facts(t, `{"State":"degraded"}`))) != 0 {
		t.Fatal("a numeric test on a string is undecidable; an opinion minted from a " +
			"comparison that failed would be a judgement about nothing")
	}
}
