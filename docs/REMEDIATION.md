# Remediation status for REVIEW_FINDINGS.md

Date: 2026-11-12. Test status after this work: Python 477 passed, 0 failed (was 429 passed, 3 failed);
TypeScript suites all pass; `tsc --noEmit` and `vite build` succeed.

## Fixed (with regression tests)

| Finding | What changed | Tests |
|---|---|---|
| C-01 | Legacy ingest copies evidence to a staging dir; `connect_forensic_sqlite(read_only=True)` uses `mode=ro` | `test_evidence_integrity.py` |
| C-02 | Electron backend parses a working copy (folder, or file + `-wal/-shm/-journal`); read-write fallback removed; originals re-hashed after ingest | `test_evidence_integrity.py` |
| C-03 | Sample data removed from Section 230, NCRP, mule network, Sankey, Section 63 dialog. Endpoints refuse (422) or return an explicit empty result | `test_no_sample_data.py` |
| C-04 | Hex window never synthesises bytes (Python and TypeScript); missing file or offset past EOF is an error shown in the viewer. Window now always contains the target | `test_ui_fts5_paginator.py`, TS tests |
| C-05 | Certificate generated from recorded facts: pre and post hash with an explicit MATCH/MISMATCH/NOT RECORDED line, processing log, failures listed, no "O_RDONLY", HTML escaped, 412 without a case. Folder hashing uses a sorted path+hash manifest and raises on unreadable files | `test_evidence_integrity.py` |
| C-06 | UI maps `Type`, `Date`/`Timestamp_*` correctly; unknown direction and status show as UNKNOWN; timestamps parsed explicitly (UTC/IST/offset), unparsed shows "Unknown" not 1970; real provenance parsed; all rows paged | TS tests |
| C-07 | Carved cells are promoted to transactions only if the database has a payment-shaped table | `test_financial_integrity.py` |
| C-08 | Records merge only on an identical reference ID | `test_financial_integrity.py` |
| C-09 | Invented byte offsets (`rowid * 128` etc.) removed; provenance carries table and rowid, offset only when real | existing suite |
| C-10 | One shared amount parser (`src/core/amounts.py`) handles lakh grouping and rejects fragments; used by both carvers, SMS grammar and the amount column cleaner | `test_amounts.py` |
| C-11 | 37-column messenger frames are mapped onto the canonical chats table (body, sender, application, provenance kept); columns that cannot be stored are logged | `test_financial_integrity.py` |
| C-12 | Missing status is UNKNOWN, undetermined direction stays TRANSFER; no synthesised IDs or counterparties; explicit type beats status keywords | `test_financial_integrity.py` |
| H-01 | Zip/tar/E01 extraction rejects traversal, never reuses stale files, disambiguates case collisions (also in the legacy pipeline) | `test_evidence_integrity.py` |
| H-02 (part) | Offset-aware strings convert to true UTC; `dd/mm/yyyy` is day-first | `test_financial_integrity.py` |
| H-07 | Reconciliation: reference match, or amount + direction + date window (each phone row used once); "wiped from phone" inference removed; API counters fixed | `test_financial_integrity.py` |
| H-08 | Transactions stamped with application and source file at parse time; multiple databases of one app no longer overwrite each other | existing suite |
| H-09 | WhatsApp: one row per message (no per-recipient duplication), read only if `read_timestamp`, status from `message.status`, 1:1 sender falls back to chat JID | via `test_phase6_7.py` |
| H-11 | Graph excludes failed, pending, carved and direction-unknown rows; roles labelled as leads with the rule shown | existing suite |
| H-12 | CORS restricted to the app origins, Host header allow-list, and every file endpoint is confined to the case workspace and evidence source (SQLite endpoints redirect to the working copy) | `test_no_sample_data.py` |
| H-13 | Per-file processing log (stage, file, error) returned and stored; unsupported containers fail with 422 | `test_evidence_integrity.py` |
| M-07 (part) | Evidence strings HTML-escaped in the certificate | `test_evidence_integrity.py` |
| L-02 | `PluginRegistry.match_path(None)` returns None | `test_phase6_7.py` |
| 3.1, 3.2, 3.3 | The three known failing tests are fixed (canonical 28-column schema with value assertions; test calls the instance method; Signal fixture shifts cell content out of the 80 reserved bytes) | |

## UI/UX changes
- Section 63, NCRP 1930 and Section 230 dialogs rewritten: data from the case, required-field validation with a visible reason, loading, empty and error states, `role="dialog"`/`aria-modal`, Escape to close, labelled inputs, focus rings. NCRP checkboxes now actually control what is exported (they were ignored). Certificate preview is a sandboxed iframe.
- Locations view shows real records or an honest empty state (hard-coded gallery removed).
- Ledger: unknown direction shown neutrally, unrecorded offsets shown as "not recorded", CSV export escapes quotes and neutralises formula injection, rows are keyboard operable.
- Global: text is selectable again (body was `user-select: none`), `:focus-visible` outline, reduced-motion support.
- Overclaims removed from the UI ("O_RDONLY", "Air-Gapped", "Verified on Both", "Wiped from Phone").

## Not done (still open)
- **S-01 (decisive):** the tested `src/` engines (VFS, provenance, SQLite/WAL, UPI, banking, DLT, correlator, crypto, legal) are still not wired into either product pipeline. Choosing and wiring one stack is a design decision, not a patch.
- H-02 remainder: the transaction `Date` column is still an unlabelled naive string (UTC when from an epoch, wall time when from a string); the odd-hour badge inherits that. WebKit/out-of-range values still fall through as raw numbers.
- H-03 to H-06, H-14, H-15, M-08 to M-10, L-01, L-03: defects in `src/sqlite`, `src/vfs`, `src/crypto`, `src/dlt` (not reachable from the product today, so not fixed here).
- M-01 (WAL frame validity in `wal_rollback_analyzer`), M-02 (carver alignment), M-03 (recovered-state counts by substring), M-04/M-05 (cross-app healing, counterparties written to contacts), M-06 (OS type always "android").
- Annexure truncation to 50/30 rows in the TypeScript Section 63 generator (that generator is no longer used by the UI and should be deleted with the other duplicate TypeScript engines).
- Legacy dashboard (`main.py`, `src/workstation_app`) still contains H-10 sample devices and figures; its evidence-modifying path (C-01) is fixed, but the review's recommendation to retire it stands.
- No per-launch API token (Electron change); origin and Host checks and path confinement are in place instead.
- Not exercised: real vendor containers, E01, and the Electron shell end to end.
