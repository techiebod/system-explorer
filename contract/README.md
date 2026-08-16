# The contract package

The wire schemas of [docs/DESIGN.md](../docs/DESIGN.md), as versioned JSON Schema
(2020-12). The design document is the record of intent and outranks these files;
where they disagree, the document wins and these get fixed.

| File | Governs | Design sections |
|---|---|---|
| `se.vocabularies.1.json` | the closed vocabularies every other schema draws on | appendix A |
| `se.declaration.1.json` | a collector's static declaration | 19 |
| `se.stream.1.json` | one NDJSON record of a collect batch | 19 |
| `se.intent.1.json` | the estate's intent declaration | 21 |
| `se.answer.1.json` | a problem-domain answer | 24 |

Rules, from the document:

- **Members and meanings are binding; spelling may still move** until a schema's
  first consumer ships, after which renames are versioned like anything else.
- **Additive members never bump the version.** A breaking change is a new file
  beside the old one, never an edit in place.
- **Published profiles stay open** (`additionalProperties` unconstrained):
  closing them is how a producer's additive change becomes a consumer's outage.
  The deliberate negatives — a `commit` may not carry `complete`, a relation
  assertion may not carry `observability`, and an assertion `target` may not
  carry an `id` — encode rulings, not style.
- Every schema here must be exercised by at least one example in the design
  document; `conformance/test_contract_package.py` enforces both directions.
