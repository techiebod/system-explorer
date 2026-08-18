# Seven Gates

*The gated build of the three-tier rebuild: what gets written in each phase, the tests that open each gate, the rules that keep the repository shipping throughout.*

This plan executes [The Observation Model](DESIGN.md) and its Appendix C. The model says what and why; this says when, where, in what order, and by whom. Where the two disagree, the model wins — and where the model is silent, work stops and the gap goes to its adjudication queue, per its own governance rule.

## 01 · Six standing rules

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

> **6 · A guard ships with the reversion that proves it discriminates**
>
> Not a test the fixed code passes — a demonstration that the unfixed code fails, executed. Round two found the round-one repair pinned by tests that stayed green with their fixes reverted: a check written to catch a known defect catches that defect and generalises to nothing. So every guard lands with its reversion run and shown red, an adversary's passing-wrong subject joins the suite as a permanent fixture, and a challenger-vs-reference mismatch is an adjudication, never a verdict — the reference has to be able to lose.

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
>
> *Retracted 2026-08-16: this gate's first green was false — the round-two audit showed the items passing for the wrong reasons. The criteria stand, but gate 1 now opens only through gate 1.5 below.*

### Phase 1.5 — the repair (medium)

A second adversarial round (six agents, 34 findings, 14 reproduced first-hand) showed gate 1's green was false: the published contract was enforced by nothing, the corpus certified a wrong answer about a firewall and punished the correct one, real identifiers sat unscrubbed in unpushed commits, and the round-one repair tests mostly pinned nothing. Scope, in order:

1. **Adapter truth** — recursive vmap/goto reachability walk, device resolution moved behind the replay seam, names published per law 1, no null fact values.
2. **Harness** — issued generations on the request line, the two-regimes law made self-enforcing (every dropped member has a named structural rule, proven exhaustively), typed fact equality, clone-safe corpus loading.
3. **Contract teeth** — every object closed, a rejection suite so a gutted schema is a red run.
4. **Scrubber** — manifest-driven deny-by-default classification, keyed substitution, an independent detector as the publish gate.
5. **Corpus** — reconstructed, re-scrubbed, regenerated, every variant carrying planted-truth anchors written at staging time.
6. **Guard discipline** — a guard ships with the reversion that proves it discriminates; the round's own passing-wrong collectors join the suite as permanent regression fixtures.
7. **Lab variants** — degraded pool, goto-reached chain, family-asymmetric ruleset, partial read, relation assertions, unobservable records, the three non-absent decline reasons, an nft-rules canary.
8. **History** — the six unpushed commits re-authored from origin/main as a clean series (the plaintext never enters public history), then push, then CI's first run from a clean checkout.
9. **Differential guard** — corpus payloads as seeds, a structural mutator, reference-versus-challenger disagreement as the verdict; every judge-fooling collector kept as a fixture that must disagree under mutation, so each catch closes a class rather than an instance.

> **Gate 1.5 — re-scoped 2026-08-17 — opens when**
>
> every previously-found exploit prints red · **no collector wrong about any committed capture passes** (judge soundness — decidable, absolute) · **every collector that has ever fooled a judge disagrees with the reference under the mutation set** (the differential guard — class-closing, held as regression) · a fresh fleet finds no new judge failure · coverage and the three replay bounds are declared, each with its authenticating venue named · the suite is green from a fresh clone. Only then does gate 1 open and Phase 2 (walking skeleton) begin.
>
> *The original second criterion — "no new passing-wrong collector at equal effort" — was retired after the first re-fleet closed the gate on it: it is an unbounded universal that no finite corpus can decide, pegging the verdict to adversary imagination rather than to properties of the artifact — the subset-guard defect, at process level. Coverage failures are owned by the differential guard and the live comparator, not by implied completeness.*

The round's generalisable lesson is now standing rule 6 (§01): every guard ships with its reversion, and a challenger-vs-reference mismatch is an adjudication, not a verdict.

### Phase 2 — walking skeleton on a guest (medium, sequential)

The smallest honest slice of the architecture, end to end: the collator core in Go — socket activation, batch/commit/generation application as one durable transaction, the store, minimal REST — plus *one* trivial collector (system identity: os-release and hostname, no privileges, present on all five OSes), the systemd units, the slice, and the NixOS module, deployed to a lab guest. This is where the contracts become code, and where every protocol mistake is cheapest.

> **Gate 2 opens when**
>
> items 2, 3, 4, 5 pass on the skeleton · the stack runs on a guest inside its slice budget · the old suite is untouched and green.

### Phase 3 — the collector fleet (large, parallel)

One collector per shipping adapter, each by the same loop: **capture its corpus first**, write the collector until replay equivalence holds, then live decline-correctness across the other lab OSes, then the comparator parity report against the old agent on the same guest. The collator's joins, identity walk, relations and opinion ladders grow alongside, fed by the collator harness. The old behavioural fixtures (8,600 lines, already fixture-shaped) convert to corpus expectations as each collector ports — converted, never deleted, since the old suite still guards the shipping product.

**Storage and network are the exemplars, and they go first** — not because they are easy but because they are the only two whose corpora were captured in phase 1, so their loop starts at step two, and the only two the mutation guard has operators for. They set the pattern the fleet copies.

The judge needed work before it could judge them, and that work is scope, not preamble:

1. **A collection is a coverage dimension.** *Done.* The coverage report named collectors, variant kinds, operating systems and interface versions and no dimension a collection could vanish on, which is how `nft-rules` stayed served-but-uncaptured behind a residual only a reader would find. `corpus/network/rules` closes it — the first pair to open two collections, built on the canary payload so the plant in a rule comment finally judges the collection that renders operator text. The seam now declares what it can replay and refuses the rest, closing a live escape where `collect links:5` read the interface of the machine *replaying* the corpus.
2. **The mutation guard points at ported collectors.** *Done.* Every call site passed a fixture or the reference; nothing passed a port, so the tier's demands on the artefacts this phase ships were enforced by nothing. Now a partition over the ported set: judged under every operator, or named with the venue that owns it.
3. **`se-capture` could not regenerate a ported collector's pair.** *Done.* It hardcoded the Python shim as the reference and never consults the ported table, so `corpus/system/healthy` declared itself re-stageable while nothing committed could re-stage it. It now resolves the reference through the one retirement table, and every pair is held to reproducing byte-for-byte — which also binds the two issuance seeds, `meta.collections` and `expected.jsonl`, that agreed and were required to by nothing.
4. **Nothing exercised `declare` or `probe`.** *Done.* The contract has three verbs and the harness drove one, so every judge graded a collector against the corpus and none against its own promises. The check §18 calls cheap and generic now exists: emitted implies declared across all three fact channels, declared implies observed or named in the residual ledger, and begin's digest hashes exactly the bytes `declare` emits.
5. **The differential guard could not carry a text-payload collector.** *Done.* `write_payloads` wrote every stem as `.json`, so a collector whose native documents are text would have been handed a directory its own seam cannot read and blamed for the REFUSED. The extension now follows the value's type. The system collector stays a named residual for the other reason: it has no second implementation to disagree with.
6. **A scrub manifest was required of no collector.** *Done.* Its absence silently meant "declares no address fields" where the truth would be "was never classified", and those are not the same statement.

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
