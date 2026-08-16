# Seven Gates

*The gated build of the three-tier rebuild: what gets written in each phase, the tests that open each gate, the rules that keep the repository shipping throughout.*

This plan executes [The Observation Model](DESIGN.md) and its Appendix C. The model says what and why; this says when, where, in what order, and by whom. Where the two disagree, the model wins — and where the model is silent, work stops and the gap goes to its adjudication queue, per its own governance rule.

## 01 · Five standing rules

> **1 · A gate is a set of tests, not a feeling**
>
> Every gate names its items from the model's twelve-test acceptance suite. A phase is done when its items pass — on the lab guest, in CI — and not before, and no phase begins until the previous gate is green. Two items run at *every* gate regardless: the shipping product's 2,077-test suite stays green, and the canary-credential check (item 11) passes on whatever channels exist so far.

> **2 · The repository ships the old product until the cut**
>
> `main` always builds and ships the current agent. The new stack grows in new top-level directories, additive, merged continuously — no long-lived branch, because a long-lived branch is two disagreeing documents written in code. From gate 2 onward the shipping adapters take **bug fixes only**: a moving porting target is how a rewrite never lands, and the live false-green (the never-run job ladder) is a bug, not a feature.

> **3 · The lab guest is the whole world until gate 5**
>
> Development deploys to VM-lab guests exclusively: full control, instant rebuild, no coordination with anything, and destruction is free. The estate is not touched until the cut — with one exception, supervised capture of corpus variants only real hardware has been in (a degraded pool, a populated enclosure).

> **4 · The old agent is the reference implementation**
>
> It runs *beside* the new stack on the same guest, and a comparator diffs the two products' answers for the same host. Parity — modulo declared renames and the re-minted ids — is how "is the port correct?" becomes a report instead of a judgement. The comparator is a development tool, not a deployment gate; it retires with the cut.

> **5 · Silence is a blocker at every tier of worker**
>
> Every executing agent's brief carries the same instruction: where the design document is unclear, silent, or contradicts the code you are writing, **stop, file the gap to the adjudication queue, and take other work.** Guessing is how the last architecture accumulated the drift this one exists to prevent — and the weaker the model, the more explicitly this must be said to it.

## 02 · The development loop

![diagram](assets/plan-figure-1.svg)

***Why a guest and not the estate:** both stacks observe the same live system, so the comparator's diff is meaningful; and the guest can be destroyed at every wrong turn, so no experiment needs anyone's permission. Federation tests use a second guest as a second "site".*

## 03 · Repository shape

```
system-explorer/
  contract/              # NEW · phase 0 — the JSON Schemas, versioned; the shared ground truth
  corpus/                # NEW · phase 1 — captured pairs per source × OS × version, anonymised, canaried
  harness/               # NEW · phase 1 — replay, collator, and protocol-crash harnesses
  go/
    cmd/se-collect-*/    # NEW · phase 2+ — one static binary per collector
    cmd/se-collate/      # NEW · phase 2 — the collator
    internal/
  src/system_explorer/   # the shipping product — bug fixes only from gate 2; retired at the cut
  conformance/           # the shipping product's suite — green at every merge until the cut
  test/vm-lab/           # existing — gains capture and corpus-regeneration verbs
  docs/DESIGN.md         # NEW · phase 0 — the observation model, canonical in-repo from gate 0
  docs/PLAN.md           # this document
```

Two notes on that tree. **The design document moves into the repository at phase 0** and the markdown becomes canonical — executing agents work in checkouts and worktrees, not in a browser, and rulings should land as reviewable diffs. **The corpus is public**, which is why anonymisation is a phase-1 deliverable and not an afterthought: structural consistency preserved, canaries planted, nothing real.

## 04 · The phases

### Phase 0 — contract freeze (small)

The queue rulings land; the wire schemas (declaration, stream, intent, problem-domain object, vocabularies) are extracted from the design document into `contract/` as real versioned JSON Schema files; hosted CI is stood up — the repository currently has none — running the old suite, the new toolchain, and **validation of every example in the design document against the schemas**, the check that would have caught both broken examples that document has shipped. The document itself ports to `docs/DESIGN.md`.

> **Gate 0 opens when**
>
> the adjudication queue holds no wire-blocking items — anything remaining carries a written proposal and blocks only the phase that consumes it · `contract/` exists and every design-doc example validates in CI · hosted CI is green on both toolchains.

### Phase 1 — corpus and harnesses (medium)

The three empty buckets get their machinery before any product code exists to hide behind. The capture pipeline: lab guests produce payload-plus-emitted-records pairs (the old agent generates the expected half), anonymised, canary credentials planted. The **replay harness** runs any collector binary against captured payloads and diffs its records against the committed expectation — the language-neutral seam, checking the outside of the process. The **collator harness** feeds recorded streams in and asserts minted ids, joins, observabilities and opinions out. The **protocol-crash harness** kills processes at every record, commit, transaction and checkpoint boundary. Tests written in this phase: acceptance items 8 and 11, plus the harness fixtures for 1–7.

> **Gate 1 opens when**
>
> the pipeline works end-to-end for two sources on two OSes · item 8 (an empty environment cannot go green) · item 11 across the channels that exist so far.

### Phase 2 — walking skeleton on a guest (medium, sequential)

The smallest honest slice of the architecture, end to end: the collator core in Go — socket activation, batch/commit/generation application as one durable transaction, the store, minimal REST — plus *one* trivial collector (system identity: os-release and hostname, no privileges, present on all five OSes), the systemd units, the slice, and the NixOS module, deployed to a lab guest. This is where the contracts become code, and where every protocol mistake is cheapest.

> **Gate 2 opens when**
>
> items 2, 3, 4, 5 pass on the skeleton · the stack runs on a guest inside its slice budget · the old suite is untouched and green.

### Phase 3 — the collector fleet (large, parallel)

One collector per shipping adapter, each by the same loop: **capture its corpus first**, write the collector until replay equivalence holds, then live decline-correctness across the other lab OSes, then the comparator parity report against the old agent on the same guest. The collator's joins, identity walk, relations and opinion ladders grow alongside, fed by the collator harness. The old behavioural fixtures (8,600 lines, already fixture-shaped) convert to corpus expectations as each collector ports — converted, never deleted, since the old suite still guards the shipping product.

> **Gate 3 opens when**
>
> every first-party collector passes replay and lab-live checks · items 1, 6, 7 · the parity report per collection is clean or its diffs are named and accepted.

### Phase 4 — hub and protocol (medium)

The Python hub evolves: the connection reverses (collator dials in), checkpoint protocol with manifest and atomic promotion, `unswept` and the freeze, declarations travelling up, findings re-keyed to the new scope with the reset displayed. The intent declaration and hash federation land, tested with **two guests as two sites** — including the NAT-mode dial direction. First problem-domain object assembled end to end.

> **Gate 4 opens when**
>
> items 9 and 10 pass · the checkpoint crash suite is green · a two-guest estate renders one coherent view with reach and coverage stated.

### Phase 5 — surfaces (medium, parallel)

Server-rendered HTML/CSS UI at both scales from one token system; MCP on collator and hub with a tool per route in the same commit; the MQTT findings projection with birth, last-will, and republish. The design library decision comes off the queue before this phase starts.

> **Gate 5 opens when**
>
> item 11 across every channel including UI, MCP and MQTT · MCP-parity check · UI smoke on both scales.

### Phase 6 — the cut (small, supervised)

Exactly as the design document's §06 rules it: the canary host first, then the estate; old agent retired; snapshot stores archived read-only; findings reset displayed; SPEC.md and COLLECTOR-DEPLOYMENT.md disposed and Appendix B closed. Estate-touching and partly destructive, so it runs with the owner present, one staged review gate per boundary — state, plan, and what is *not* changing, at each step.

> **Gate 6 — done — when**
>
> item 12 · the full acceptance suite green on the canary, then per site · no undisposed rule left in either superseded document.

## 05 · Execution assignments

Which worker executes which phase is tracked outside this repository, with the plan's
owner. The binding rules travel with every brief regardless of who holds it: the gate
reviewer never wrote the code under review, and rule 5 — silence in the design document
is a blocker, never a licence to guess.

---

*Companion to The Observation Model; where they disagree, the model wins. Phases small/medium/large are relative effort, deliberately not day counts — the gates, not a calendar, decide when a phase ends.*
