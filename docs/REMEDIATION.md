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

## Phase 2 (second review, `REVIEW_FINDINGS_2.md`), in progress

Test status: Python 501 passed, 0 failed; TypeScript suites pass; `tsc --noEmit` and `vite build` succeed;
the Electron app was launched and ran end to end (see X-09).

| Finding | What changed | Tests |
|---|---|---|
| X-01 | NCRP sheet: State, Police Station, Officer and Crime Category come from the request; blank is written `NOT_PROVIDED`. "YES_DECONFLICTED" replaced by `AUTOMATED_RULES_PASSED`. Acknowledgement number required. NCRP dialog has the four fields | `test_legal_output_integrity.py` |
| X-02 | Section 230 bundle fails closed: every item needs an explicit tag (`DISCLOSABLE` to release); an untagged item aborts before anything is written; `PROTECTED_VICTIM_IDENTITY` and `UNRELIED_PRIVATE_DATA` are withheld; UI and API require a decision per file | same |
| X-03 | Exhibit file names reduced to a single sanitised component with an index prefix; writes verified to stay inside the bundle | same |
| X-04 | Victim name masked (case-insensitive) in file names, cards, paths, timestamps, EXIF and HTML; HTML escaped; anonymisation without a name is refused | same |
| X-05 | Biller match is whole-word (`francesca@ybl` no longer matches `cesc`); victim lock also compares VPA | same |
| X-06 | NCRP CSV written with `csv` (quoting) and formula-injection neutralised | same |
| X-07 | Section 94 draft: operator never inferred from a mobile number; officer, station, FIR and sections must be supplied; invented "48 hours" removed; marked DRAFT. (Drafter is still not called by the API.) | same |
| X-08, L-07 | Benchmark endpoint disabled unless `BHARAT_ENABLE_BENCHMARK=1`; output directory check uses path containment, not a string prefix | same |
| X-10 | SQLCipher open/decrypt uses a real SQLCipher driver (`sqlcipher3`) if installed, otherwise logs "not installed" and returns nothing; opened `mode=ro`; unexpected errors logged. Decryption is therefore **not available** until a driver is installed or `src/crypto/sqlcipher` is wired (Phase 4) | same |
| X-11 | IST timestamps are real IST (`ist_now_str`), not machine local time | same |
| X-09, H-12 (rest) | Per-launch API token (`X-Bharat-Token`, `BHARAT_API_TOKEN`) enforced for every `/api/` request; backend on a free random port and never reused; renderer window is `sandbox: true`; `will-navigate`, `window.open` and permission requests denied; IPC handlers accept only our own pages; `showItemInFolder` takes only local absolute paths; backend gets an allow-listed environment instead of the whole one | `TestApiToken`; launched `electron .`: backend came up on a random port, token passed through the sandboxed preload, renderer calls returned 200 |

Not yet done from the second review: X-12 and the rest of U-01..U-05 (UI claims; part of the UI redesign), L-04..L-06,
dossier_builder unconditional claims (unwired), and the Phase 1 review of the remaining modules.
