# Invention record (private: do not publish or share outside the attorney)

Started 2026-11-12. One dated entry per candidate method, so the history shows when each idea was conceived and
when it was made to work. This is a record for a patent attorney to assess. It is not a claim, and it does not
say anything is patentable or novel: that needs a prior-art search.

Rules for this file:
* Add the entry (problem, method as steps, how it differs from the usual approach) BEFORE building the feature.
* Fill "implemented in" and "proven by" with a real commit and a passing test when it exists. Never fill them with a plan.
* State the human contribution (the decision, the idea, the requirement). Inventors must be people; much of the code was
  written with AI assistance, so write down what the named person decided and why.
* Do not demo, publish, post or put in a tender document any entry here until the attorney has filed.
* India: Patents Act s.3(k) excludes computer programs "per se", so each entry should describe a technical effect
  (for example evidence integrity or verifiable provenance), not only a user-interface arrangement.

## Candidates

| # | Candidate method | Status | Implemented in | Proven by |
|---|---|---|---|---|
| 1 | Provenance-linked evidence card: a record, its source file, table, row, page, byte offset, length and recovery state, and the raw bytes at that offset, shown as one unit; unrecorded values read "not recorded" | exists | 6d7fda3 (2026-11-12) `ui/renderer/inspectors/EvidenceCard.tsx` | `ui/tests/ui_shell_test.ts`, `tests/test_ui_fts5_paginator.py` |
| 2 | "Unknown" as a first-class value through parser, store, UI and export, with tests that fail if any layer substitutes a default (direction, status, time, page, counterparty) | exists | R-01..R-20, U-07 (see `REVIEW_FINDINGS_2.md`) | `tests/test_legal_output_integrity.py`, `tests/test_financial_integrity.py`, `ui/tests/workbench_store_test.ts` |
| 3 | Merged (clustered) records that keep the list of contributing source rows and byte locations | planned (X-13) | - | - |
| 4 | Hash-chained audit log; chain head embedded in every report, annexure and package | planned | - | - |
| 5 | "Limitations" section generated from the processing log: what was not decoded, truncated, or encrypted without a key | planned | - | - |
| 6 | Fail-closed disposition gate: no export is built until every item has an explicit decision; masking applied to data before rendering | partly exists (gate in `exhibit_packager.py`) | 50cadf9 | `tests/test_legal_output_integrity.py` (to be generalised) |
| 7 | Machine-readable "certificate facts" bundle kept separate from any legal form | planned | - | - |
| 8 | Reviewer round trip: tags exported from a portable package as a file bound to the package hash, merged with an audit entry | planned | - | - |
| 9 | Lead-versus-fact labelling: every inferred link shows its matching rule beside it and is excluded from the graph unless the rule is exact | exists | H-11, R-11, `fiat_crypto_bridge.py`, evidence card Links tab | `tests/test_legal_output_integrity.py` |
| 10 | Eight-stage investigation-order navigation with expanding current stage (appearance; design-registration candidate) | exists | 6d7fda3 `workspace/stages.ts`, `StageNavigator.tsx` | `ui/tests/ui_shell_test.ts` |

## Per-entry notes (fill in with the attorney)

For each entry: problem solved; steps of the method; what a person skilled in the field would normally do instead;
the technical effect; who decided what (human contribution); earliest date and commit.

### Entry 1: evidence card
* Problem: examiners must show where a displayed value came from; tools often show a decoded value with the source in a separate view.
* Method: one card that binds the decoded record, its recorded provenance fields and the bytes read from the working copy at the recorded offset; absent fields shown as "not recorded".
* Human contribution: _to be written by the named inventor._

### Entry 2: unknown as a first-class value
* Problem: parsers and viewers that fill missing fields with a plausible default (incoming, success, now) put invented facts in reports.
* Method: a pipeline-wide rule that a missing value stays missing from parser to export, enforced by tests that inject records with each field absent and assert the output says unknown.
* Human contribution: _to be written by the named inventor._

## Independence notes

* No vendor screenshot, manual, schema file or layout was used as a design source for the interface (`UI_DESIGN.md`).
* Parsers read other tools' export containers (.ufdr, .xry, .ofb) for interoperability only. The attorney should
  confirm that is acceptable for each format.
* Open question for the attorney: the 28-column canonical chat schema (`CHAT_COLUMNS` in
  `parsers/enterprise_1tb_chat_and_container_engine.py`) was originally written to mirror another product's chat
  column set. Decide whether to keep it, or redesign the column set from the data model before filing.
* `tests/test_independence_guard.py` fails if product code cites another product as its design target.
