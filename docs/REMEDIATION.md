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

Test status: Python 493 passed, 0 failed; TypeScript suites pass; `tsc --noEmit` and `vite build` succeed;
the Electron app was launched and ran end to end (see X-09).

| Finding | What changed | Tests |
|---|---|---|
| X-01 | NCRP sheet: State, Police Station, Officer and Crime Category come from the request; blank is written `NOT_PROVIDED`. "YES_DECONFLICTED" replaced by `AUTOMATED_RULES_PASSED`. Acknowledgement number required. NCRP dialog has the four fields | `test_review_regressions.py` |
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

### Phase 2, second batch (open items from the first review, plus findings made while fixing them)

| Finding | What changed | Tests |
|---|---|---|
| Legacy dashboard (H-10) | `main.py` and `src/workstation_app` deleted with the tests that exercised their sample data; README and architecture updated | suite |
| Duplicate TS engines | `ui/main/` (including an old Electron main with `nodeIntegration: true`), `ui/shared/universal_hasher.ts`, `loadGoldenDataset` and the 8 TS suites that asserted the demo data deleted; the store test now uses its own fixture and asserts nothing is preloaded. TS Section 63 generator (annexure truncation) gone with them | `workbench_store_test.ts` |
| M-01 | WAL frames follow SQLite's validity chain (header checksum, salt, rolling checksum, last commit). All-zero checksums are no longer valid. Recovered rows say `OLDER VERSION OF PAGE (committed WAL frame #n)` or `RESIDUAL WAL FRAME #n (reason)`; the old "MODIFIED / WIPED" wording asserted an inference | `test_review_regressions.py`, `test_hardened_freelist_wal_carver.py` |
| M-02 | Slack scan tries every byte offset (it stepped by 4, missing cells at other alignments); freeblocks are decoded as bare records because SQLite overwrites the first 4 bytes of a freed cell; a truncated column no longer shifts later columns. The real-WAL test now also finds a record in the database file's gap that the old stride missed, so it asserts coverage of all 10 VPAs rather than exactly 10 rows | same |
| M-03 | Recovered counts and filters match the `State=` field. SQLite `LIKE` is case-insensitive, so `%WAL%` had been counting every path containing "wallet" | same |
| M-04 | Amount + date matches no longer overwrite counterparty or direction. A unique candidate is stored in a new `Possible_Link` column as an unconfirmed lead; an ambiguous name is not upgraded to a VPA. Exact reference-ID healing is unchanged | same, e2e test updated |
| M-05 | Payees derived into contacts are labelled `DERIVED: payee seen in transactions (not an address-book entry)`; the invented `Verified Counterparty` identifier is gone | same |
| M-06 | OS type detected from the extraction layout (`android`/`ios`/`unknown`). "Acquisition time" is no longer set to the time the tool processed the files; it is `Not recorded` and `processedAtUtc` is reported separately | same |

### New finding while testing (not fixed yet)
- **X-13** (see `REVIEW_FINDINGS_2.md`): transactions in the case store have no provenance and no normalised time. This also
  covers the H-02 remainder. It needs the provenance threaded through clustering, so it is scheduled with the `src/` wiring
  (Phase 4, stage C) and not patched around.

Not yet done from the second review: X-12 and the rest of U-01..U-05 (UI claims; part of the UI redesign), L-04..L-06,
dossier_builder unconditional claims (unwired), and the Phase 1 review of the remaining modules.

### Phase 1b: continued review (2026-11-12). See `REVIEW_FINDINGS_2.md` section 5

Fixed with regression tests: R-01 (generic classifier invents direction, status, counterparty, coordinates), R-02 (messenger
parsers hard-code INCOMING/RECEIVED; call direction from call result), R-03 (silent wallet-table truncation), R-04 (random
"chain of custody" IDs), R-05 (banking narration direction), R-06 (balance-gap detector), R-07 (UTR/Aadhaar validator),
R-08 (UPI decoders always DEBIT_SENT, missing status = SUCCESS), R-09 (Section 63 certificate time), R-10 (OCR confidence
label), R-11 (fiat/crypto alignment), R-12 (tautological victim-lock test). Python: 498 passed.
Open: X-14 (same default in unwired decoders), U-06 (two views with no data source), L-08, X-13.

### Phase 1c: final review pass (2026-11-12). See `REVIEW_FINDINGS_2.md` section 6

Fixed with regression tests: R-13 (messenger parsers: direction, status, page number, recovery label, swallowed failures),
R-13b (knowledgeC timeline never read), Q-1 (deep_sqlite truncation, invented labels, substring columns), Q-2 (owner dossier
took any `@` value as the owner), Q-3 (benchmark verdicts), R-14 (OCR Aadhaar guess, `ocr_performed`), R-15 (analysis time
used as transaction time), R-16 (varint/Snappy/LevelDB truncation), R-17 (fixture special case in wei conversion),
R-18 (Binance P2P defaults), R-19 (laundering-chain correlator), X-14 (direction defaults in unwired decoders),
U-07 (UI re-invented direction, provenance, case particulars and labels), U-08 (CSV export truncation and formulas), T-01.
Python: 508 passed. TypeScript: store, CSV and client suites pass; `tsc --noEmit` clean.
Open: X-13, U-01..U-06 (redesign), Q-1 amount unit, R-16 block CRC, L-08, X-12. Unread modules are listed in the coverage statement.

### Phase 1d: unread modules (2026-11-12). See `REVIEW_FINDINGS_2.md` section 7
Fixed with regression tests: R-20a..R-20f. Python: 515 passed. Open: Hive box format unverified, Telegram date 0 in `telegram_decoder.py`.

### Phase 3: interface redesign (2026-11-12). See `UI_DESIGN.md` and `REVIEW_FINDINGS_2.md` section 8
Done: eight-stage shell, three themes with a contrast test, preferences (theme, density, text size, time zone, rest reminder), evidence card with source bytes and pinning (`/api/case/findings`), command palette, Court output page, RecordTable; U-01..U-06, U-09..U-11, X-15..X-17 fixed; old shell, APK and remote-access views, duplicate chat bubble view removed; `cellebrite-alternative` keyword removed.
Python 517 passed; `npm run test:ts` passes (adds contrast and shell tests); `tsc` clean; `vite build` OK; looked at in Electron in all three themes.
Open: older views not redesigned (chat table, ledger, graph, wizard); generators do not read findings; Phase 4 (wire `src/`, X-13).

### Phase 5P: independence and patent readiness (2026-11-12, branch `feature/parity-and-independence`)
Done: vendor-derived names removed from product code (`PA_CATEGORIZED_CHAT_COLUMNS` to `CHAT_COLUMNS`, `get_pa_project_tree_counts` to `get_project_tree_counts`, `commercial_parity_engine` to `generic_table_engine`, `PARITY_GAP_REPORT.md` to `COVERAGE_COMPARISON_REPORT.md`, the "Chainalysis / TRM" export label to "Export address list (CSV)"); comments citing another product as the design target reworded; guard tests added (Python and TypeScript); `docs/THIRD_PARTY_LICENSES.md` and `docs/INVENTION_RECORD.md` created.
Python 518 passed; `npm run test:ts` passes. Open for the attorney: the 28-column chat schema's origin, libewf LGPL handling, inventorship.
Next: Phase 5A (replace court outputs with the examination report, facts annexure, audit log and portable package).

### Phase 5A: court outputs replaced by facts (2026-11-12, branch `feature/parity-and-independence`)
Decision (user): the tool does not generate legal forms. It gives the examiner the facts, and the examiner prepares and signs any certificate in the lab's own format.
Done, one commit per step:
1. `src/audit`: hash-chained, persistent audit log and hash manifest, written new (the old `legal_and_bsa` ledger left the actor out of the hash, labelled UTC as IST, was memory-only, and the old manifest marked every item "verified" at registration; its Merkle tree duplicated an odd node).
2. `parsers/examination_report.py` plus `/api/report/examination`, `/api/report/facts`, `/api/audit`; audit events on ingest, case open, pin, unpin, report and package.
3. `parsers/review_package.py` plus `/api/report/package`: fail-closed per-file decisions, masking, safe names, manifest with Merkle root and audit head.
4. Removed: Section 63 certificate, Section 230 bundle, NCRP freeze sheet, Section 94 drafter, dossier builder (`src/legal_and_bsa`, `src/dossier_and_exhibits`, parts of `src/unk_triage_and_bsa_studio`, their API routes, 61 tests). `src/unk_triage` keeps the key broker, schema mapper and entropy profiler. The `is_relied_upon_for_sec230_bnss` column became `is_relied_upon`.
5. UI: stage 8 is Report & export; the three statutory dialogs and the court-output page are gone; the fabricated chat "Dossier view", invented participant bios and a fake provenance record were removed (REVIEW_FINDINGS_2 section 9).
Guards: `test_no_statutory_form_routes_exist`, `test_report_contains_no_legal_form_wording`, and the renderer check in `ui/tests/ui_shell_test.ts`.
Python 491 passed; `npm run test:ts` passes; `tsc` clean; `vite build` OK; the new screen was opened in Electron and the endpoints exercised against a running server on the test evidence.
Open: `/api/report/package` lists media files only; tag-based selection and the reviewer round trip (5C.10); `abilities.md` is not re-verified line by line (a status banner says so); `financial_graph_and_storyboard/freeze_cart_manager.py` still has a "freeze cart" for graph views.
