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
| 2 | "Unknown" as a first-class value through parser, store, UI and export, with tests that fail if any layer substitutes a default (direction, status, time, page, counterparty) | exists | R-01..R-20, U-07 (see `REVIEW_FINDINGS_2.md`) | `tests/test_review_regressions.py`, `tests/test_financial_integrity.py`, `ui/tests/workbench_store_test.ts` |
| 3 | Merged (clustered) records that keep the list of contributing source rows, with page and byte offset where the main file is the whole truth | exists (rows, state, page and offset for live rows; offsets for WAL-served rows still planned) | Phase 5B.1 commits on `feature/parity-and-independence`: `parsers/heuristic_engine.py`, `parsers/sqlite_locator.py` | `tests/test_tx_provenance.py` (`test_merged_record_lists_every_contributing_row`, `test_recorded_offset_is_the_real_cell_in_the_file`) |
| 4 | Hash-chained audit log; chain head embedded in every report, annexure and package | exists | f3a931c, 69b4704, 13644e9 (2026-11-12) `src/audit/ledger.py` | `tests/test_audit.py`, `tests/test_examination_report.py` |
| 5 | "Limitations" section generated from the processing log: what was not decoded, truncated, or encrypted without a key | exists (failures, warnings, encrypted-without-key, and files seen but not decoded, from the per-file coverage record, 2026-11-12) | 69b4704 `parsers/examination_report.py`; 5B.4 `parsers/api_server.py`, `parsers/ui_fts5_paginator.py` | `tests/test_examination_report.py`, `tests/test_coverage_and_search.py` |
| 6 | Fail-closed disposition gate: no export is built until every item has an explicit decision; masking applied to data before rendering | exists | 50cadf9, 13644e9 `parsers/review_package.py` | `tests/test_review_package.py` |
| 7 | Machine-readable facts bundle kept separate from any legal form (the tool refuses to generate the form) | exists | 69b4704 `/api/report/facts` | `tests/test_examination_report.py` (`test_no_statutory_form_routes_exist`) |
| 8 | Reviewer round trip: tags exported from a portable package as a file bound to the package hash, merged with an audit entry | planned | - | - |
| 9 | Lead-versus-fact labelling: every inferred link shows its matching rule beside it and is excluded from the graph unless the rule is exact | exists | H-11, R-11, `fiat_crypto_bridge.py`, evidence card Links tab | `tests/test_review_regressions.py` |
| 10 | Eight-stage investigation-order navigation with expanding current stage (appearance; design-registration candidate) | exists | 6d7fda3 `workspace/stages.ts`, `StageNavigator.tsx` | `ui/tests/ui_shell_test.ts` |

## Per-entry notes (fill in with the attorney)

For each entry: problem solved; steps of the method; what a person skilled in the field would normally do instead;
the technical effect; who decided what (human contribution); earliest date and commit.

### Entry 1: evidence card
* Problem: examiners must show where a displayed value came from; tools often show a decoded value with the source in a separate view.
* Method: one card that binds the decoded record, its recorded provenance fields and the bytes read from the working copy at the recorded offset; absent fields shown as "not recorded".
* Human contribution: _to be written by the named inventor._

### Entry 3: merged records keep their sources
* Problem: tools merge duplicate rows from several tables or apps into one display record and then cannot say which stored rows it came from.
* Method: every parsed row carries (table, rowid, recovery state, page, byte offset); merging takes the union of the contributing rows; the stored provenance line lists each one; the offset is withheld when a write-ahead log means the main file may not hold the newest version.
* Also (supports entries 1 and 2): a time value is labelled with what it means (epoch, offset-converted, local zone unknown), and no UTC or IST is stated unless the source fixes the instant.
* Human contribution: _to be written by the named inventor._

### Entry 2: unknown as a first-class value
* Problem: parsers and viewers that fill missing fields with a plausible default (incoming, success, now) put invented facts in reports.
* Method: a pipeline-wide rule that a missing value stays missing from parser to export, enforced by tests that inject records with each field absent and assert the output says unknown.
* Human contribution: _to be written by the named inventor._

### Entry 5: limitations and coverage from the record of what was done
* Problem: a report that lists only what was found hides what was not read; a reviewer cannot tell an empty result from a file that was never decoded.
* Method: the ingest writes one coverage row per file it looked at (decoded, partly decoded, not decoded with the reason, failed, encrypted with no key), and every stored record carries the parser and version that produced it (null if unknown). The report's Limitations section is generated from the same record, so it cannot omit a file the coverage lists.
* Human contribution: _to be written by the named inventor._

## Independence notes

* No vendor screenshot, manual, schema file or layout was used as a design source for the interface (`UI_DESIGN.md`).
* Parsers read other tools' export containers (.ufdr, .xry, .ofb) for interoperability only. The attorney should
  confirm that is acceptable for each format.
* Open question for the attorney: the 28-column canonical chat schema (`CHAT_COLUMNS` in
  `parsers/enterprise_1tb_chat_and_container_engine.py`) was originally written to mirror another product's chat
  column set. Decide whether to keep it, or redesign the column set from the data model before filing.
* `tests/test_independence_guard.py` fails if product code cites another product as its design target.
