package collate

// The named-evaluator seam itself (DESIGN 17, ruled 2026-08-23) — the
// three properties that make it a mechanism rather than an escape hatch,
// each asserted rather than described.
//
// The first is the one that matters: a declaration NAMES an evaluator
// and cannot ship one, which is what keeps third-party code out of the
// judging path. If that ever stops holding, the rules-as-data design has
// been repealed by a member nobody re-reviewed.

import (
	"strings"
	"testing"
)

const evaluatorFacts = `"facts":{
 "PsiIoFullAvg60":{"type":"number","unit":"percent","temperament":"gauge","kind":"observed","discloses":"nothing","sentence":"."},
 "StallUnexplained":{"type":"object","temperament":"state","kind":"derived","derived_from":["PsiIoFullAvg60"],"discloses":"nothing","sentence":"."}}`

func declarationWith(rule string) string {
	return `{"collections":[{"name":"slices","question":"q","prefix":"slice",` +
		evaluatorFacts + `,"rules":[` + rule + `]}]}`
}

func TestADeclarationMayNameAnEvaluatorAndMayNotShipOne(t *testing.T) {
	// The closed set is the line. A name outside it is refused at LOAD
	// rather than skipped at judge time, because a rule quietly dropped
	// is an opinion an operator expects and never sees.
	_, err := RulesFor(declarationWith(
		`{"key":"k","level":"warn","grounds":"threshold","evaluator":"my-own-code",
		  "sentence":"s","cites":["PsiIoFullAvg60"]}`), "slices")
	if err == nil {
		t.Fatal("a declaration naming an evaluator this collator does not have " +
			"must be refused; accepting it is third-party code in the judging path")
	}
	// And the refusal says what could have been named, so a typo is a
	// fix rather than an investigation.
	if !strings.Contains(err.Error(), "slice-stall-unexplained") {
		t.Errorf("the refusal names the set: %v", err)
	}
}

func TestARuleCarriesExactlyOneOfConditionAndEvaluator(t *testing.T) {
	both := `{"key":"k","level":"warn","grounds":"threshold",
	  "when":{"fact":"PsiIoFullAvg60","at_least":20},
	  "evaluator":"slice-stall-unexplained","sentence":"s","cites":["PsiIoFullAvg60"]}`
	if _, err := RulesFor(declarationWith(both), "slices"); err == nil {
		t.Error("both is two answers to one question with no stated winner")
	}
	neither := `{"key":"k","level":"warn","grounds":"threshold",
	  "sentence":"s","cites":["PsiIoFullAvg60"]}`
	if _, err := RulesFor(declarationWith(neither), "slices"); err == nil {
		t.Error("neither is an opinion that can never fire, and an operator " +
			"would wait for it")
	}
}

func TestAnEvaluatorRuleStillCitesOnlyDeclaredFacts(t *testing.T) {
	// The seam moves the TEST into code, never the citation discipline:
	// an opinion citing a fact nobody declared is one a reader cannot go
	// and look at, whichever half of the rule decided it.
	_, err := RulesFor(declarationWith(
		`{"key":"k","level":"warn","grounds":"threshold",
		  "evaluator":"slice-stall-unexplained","sentence":"s","cites":["NoSuchFact"]}`),
		"slices")
	if err == nil {
		t.Fatal("acceptance item 7 holds for an evaluator rule too")
	}
}

func TestAnEvaluatorRuleKeepsEveryOtherMember(t *testing.T) {
	// So a surface renders it identically to a table-decided one, and
	// the declaration itself says which opinions the table does not
	// decide — the coverage rule applied to the rule table.
	rules, err := RulesFor(declarationWith(
		`{"key":"slice-stall-unexplained","level":"warn","grounds":"threshold",
		  "evaluator":"slice-stall-unexplained","sentence":"the slice stalled",
		  "cites":["PsiIoFullAvg60","StallUnexplained"]}`), "slices")
	if err != nil {
		t.Fatal(err)
	}
	fired := Judge(rules, "slice:system", nil, map[string]any{
		"PsiIoFullAvg60":   54.55,
		"StallUnexplained": map[string]any{"PsiIoFullAvg60": true},
	})
	if len(fired) != 1 {
		t.Fatalf("%+v", fired)
	}
	opinion := fired[0]
	if opinion.Level != "warn" || opinion.Grounds != "threshold" ||
		opinion.Sentence != "the slice stalled" || len(opinion.Cites) != 2 {
		t.Fatalf("an evaluator rule is a whole opinion: %+v", opinion)
	}
}

func TestAnEvaluatorThatCannotDecideIsSilent(t *testing.T) {
	// Same rule as an unevaluable condition: "I could not decide" reads
	// as silence, never as alarm. Here the facts the evaluator reads are
	// simply absent.
	rules, err := RulesFor(declarationWith(
		`{"key":"slice-stall-unexplained","level":"warn","grounds":"threshold",
		  "evaluator":"slice-stall-unexplained","sentence":"s",
		  "cites":["PsiIoFullAvg60"]}`), "slices")
	if err != nil {
		t.Fatal(err)
	}
	if fired := Judge(rules, "slice:system", nil, map[string]any{}); len(fired) != 0 {
		t.Fatalf("%+v", fired)
	}
}

func TestEveryNamedEvaluatorIsReachedByADeclaration(t *testing.T) {
	// An evaluator no shipped declaration names is code in the judging
	// path that nothing exercises — the same shape as a guard whose
	// pattern never matches, which this estate has shipped twice.
	// COVERAGE: this asserts the set is non-empty and every member is
	// callable; that each is named by a SHIPPED declaration is
	// conformance's, which reads the declaration files.
	if len(EvaluatorNames()) == 0 {
		t.Fatal("the seam exists for rules that use it")
	}
	for _, name := range EvaluatorNames() {
		if !KnownEvaluator(name) {
			t.Errorf("%s is listed and not resolvable", name)
		}
		// Callable over empty facts without panicking: a judging path
		// that crashes on a sparse row costs the host every other
		// opinion in the collection.
		evaluate(name, map[string]any{})
	}
}
