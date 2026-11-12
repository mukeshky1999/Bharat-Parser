# Review Findings 2: code that REVIEW_FINDINGS.md did not cover

Review date: 2026-11-12. Read-only review. No source, test or config file was changed by it.
Reproduction script: `repro_legal.py` in the session scratchpad (not in the repository).

"CONFIRMED" means reproduced with a concrete input, or provable from the code path cited.
"SUSPECTED" means the code supports it but I did not reproduce it.

**This review is partial.** Section 4 lists exactly what was read in depth, what was only pattern-swept, and what
has not been looked at. Do not read the absence of a finding in an unreviewed module as a clean result.

## 1. Overall assessment

The legal-output layer that `docs/REMEDIATION.md` described as fixed (C-03) is only fixed on the UI side. The Python
engines behind the NCRP freeze sheet, the Section 230 bundle and the Section 94 notice still contain fabricated
officer and state names, a redaction gate that fails open, a path-traversal write, and CSV output that breaks or
injects formulas. Separately, `REMEDIATION.md` says UI overclaims such as "Verified on Both" were removed; several
remain, and the integrity badges in the Electron renderer are static text that does not depend on any hash result.
The Electron shell has no per-launch token, trusts whatever process is listening on port 8000, and runs with
`sandbox: false`. The key-recovery path for SQLCipher databases cannot work with the Python standard library and
fails silently.

Summary: 2 Critical, 8 High, 7 Medium, 4 Low.

## 2. Findings, most severe first

### Critical

**X-01. The NCRP 1930 freeze sheet hard-codes State, Police Station and Investigating Officer. CONFIRMED (reproduced).**
- Where: `src/unk_triage_and_bsa_studio/freeze_deconfliction.py:126-141` (`generate_1930_ncrp_csv`), called by
  `parsers/api_server.py` `generate_ncrp_freeze_report` (about line 1970).
- What: every row carries `Uttar Pradesh`, `Cyber Crime PS`, `Inspector Verma`, `CYBER_FINANCIAL_FRAUD` and
  `Safeguard_Check_Passed = YES_DECONFLICTED`, whatever the case. The function has no parameters for them.
- Trigger: any call; the output of my run contained those values for a case I had just made up.
- Consequence: a sheet submitted to banks names an officer, station and state that are not the user's. This is the
  same class as C-03, left in the engine when only the dialog was rewritten.
- Fix: take state, station, officer and crime category from required request fields; refuse to export without them;
  compute `Safeguard_Check_Passed` from the actual checks.

**X-02. The Section 230 redaction gate fails open. CONFIRMED (reproduced).**
- Where: `src/dossier_and_exhibits/exhibit_packager.py:54-98`; `models.py:91` (`redaction_tag: Optional[RedactionTag] = None`).
- What: only three tags (CSAM, intimate media, sexual-assault footage) cause withholding. An item with no tag, or
  tagged `PROTECTED_VICTIM_IDENTITY` or `UNRELIED_PRIVATE_DATA`, is written to `exhibits/` as raw bytes and listed as
  `ACCESSIBLE_RELIED_UPON_EXHIBIT`. `api_server.py` passes `None` whenever the client sends no tag.
- Trigger: items with `redaction_tag=None` and `PROTECTED_VICTIM_IDENTITY`; both files appeared in `exhibits/` with
  their bytes.
- Consequence: media that should have been withheld can be disclosed because nobody chose a tag. There is no
  classification step at all; the gate only honours what the caller supplies.
- Fix: require an explicit disposition for every item (`RELIED_UPON_DISCLOSE` or a withholding tag). Treat a missing
  disposition as withheld, and refuse to build the bundle until every item has one.

### High

**X-03. Exhibit file names are used as paths, so a bundle can write outside its directory. CONFIRMED (reproduced).**
- Where: `exhibit_packager.py:63-65, 88`.
- Trigger: `file_name="../../ESCAPED.txt"`; the file was created two levels above the bundle directory.
- Fix: reduce names to a sanitised basename or index-based name, resolve, and require the result to stay under `exhibits/`.

**X-04. Victim anonymisation is applied only to the HTML body. CONFIRMED (reproduced).**
- Where: `exhibit_packager.py:67-74, 104-115`.
- What: the withheld-notice cards, their file names, `canonical_path`, EXIF text and the `<title>` are not
  anonymised. In my run `Priya Sharma` appeared in the card text and in the card file name; the HTML replaced it only
  inside the body, with a case-sensitive string replace (so `PRIYA SHARMA` or a partial name survives).
- Also: `victim_name` and file names are inserted into the HTML unescaped (see M-07 in the first review).
- Fix: anonymise at the data level before any output is rendered, use opaque identifiers for file names, escape output.

**X-05. NCRP "utility" filter excludes real accounts by substring; the victim lock matches only the account number. CONFIRMED (reproduced).**
- Where: `freeze_deconfliction.py:15-25, 40-43`; `api_server.py` (victim marking compares `account_no` only).
- Trigger: VPA `francesca@ybl` contains `cesc`, so it is labelled "UTILITY / GOVT BILLER - EXCLUDED BY DEFAULT" and
  dropped from the sheet. A complainant who appears only by VPA is not locked.
- Consequence: a mule account is silently not frozen; a victim account can be listed for freezing.
- Fix: match biller VPAs on a maintained exact/domain list, show excluded accounts to the examiner with the reason,
  and lock the complainant by account number, VPA and linked mobile.

**X-06. NCRP CSV is built with `",".join`. CONFIRMED (reproduced).**
- Where: `freeze_deconfliction.py:119-142`.
- Trigger: VPA `a,b@ybl` produced a 15-column row in a 14-column sheet; VPA `=HYPERLINK("http://x")` is written
  unescaped (formula injection when opened in a spreadsheet).
- Fix: use `csv.writer` and neutralise cells starting with `= + - @` (the UI export already does this).

**X-07. The Section 94 BNSS notice addresses the wrong organisation and invents case particulars. CONFIRMED (reproduced).**
- Where: `src/dossier_and_exhibits/nodal_freeze_and_requisitions.py:195-210, 282-318`.
- What: any telecom lead whose MSISDN starts `+919` (all Indian mobiles) is addressed to "Reliance Jio Infocomm Ltd.".
  Missing officer, station and sections of law default to "Investigating Officer", "Cyber Crime PS" and
  "Sections 318(4) BNS, 2023 r/w 66D IT Act"; the 48-hour compliance period is fixed text.
- Fix: no operator inference from a number prefix (use the lead's recorded operator or leave it blank for the
  examiner); require officer, station and sections; make the deadline a field. Not currently wired to an endpoint,
  so High rather than Critical.

**X-08. The benchmark endpoint's path confinement is a string-prefix check and `dump_path` is unconfined. CONFIRMED (reproduced).**
- Where: `parsers/api_server.py` benchmark route (about lines 2318-2335).
- What: `abs_out.startswith(DEFAULT_WORKSPACE_ROOT)` accepts `...\active_case_evil`; anything under the system temp
  directory is accepted; `req.dump_path` is read with no `_resolve_case_file`. This contradicts the REMEDIATION claim
  that every file endpoint is confined.
- Fix: compare resolved paths with `os.path.commonpath`, drop the temp-dir allowance, and route `dump_path` through
  the same resolver as the other file endpoints.

**X-09. Electron shell trust and hardening. CONFIRMED (from code).**
- Where: `electron/main.cjs`.
- What: (a) `sandbox: false` (line 204) although the preload uses only `contextBridge` and `ipcRenderer`;
  (b) `startBackend` reuses any process answering `/api/health` on port 8000 (lines 96-100), so a hostile local
  process can impersonate the backend, and the planned API token would be defeated; (c) no `will-navigate` or
  `setWindowOpenHandler` guard; (d) in dev the window loads `http://localhost:3000` with the preload attached, so
  whatever listens there receives `electronAPI`; (e) `shell:showItemInFolder` accepts any path from the renderer and
  IPC handlers do not check `event.senderFrame`; (f) the backend inherits the full parent environment.
- Fix: `sandbox: true`; start the backend only on a free port with a per-launch token and refuse to reuse an
  unknown listener; deny navigation and new windows; validate IPC senders and paths.

**X-10. SQLCipher key recovery cannot work and fails silently. CONFIRMED (reproduced).**
- Where: `parsers/keychain_decryptor.py:158-206`.
- What: it uses the standard-library `sqlite3`, which has no `PRAGMA key` or `sqlcipher_export` (my run: "file is not
  a database"). Every candidate raises and `except Exception: continue` swallows it, so the function returns `None`
  for every encrypted database with no log entry. It also opens the file read-write (`sqlite3.connect(path)`).
- Consequence: Signal and other SQLCipher databases are reported as empty/unparseable without an error, while the
  documentation presents decryption as a capability. `src/crypto/sqlcipher.py` is the implementation that exists
  for this (see S-01 in the first review).
- Fix: route through `src/crypto/sqlcipher.py` on the working copy (after its M-08 defects are fixed) and record a
  per-file "encrypted, no key" outcome in the processing log.

### X-13 (High) Transactions lose their source location and normalised time (CONFIRMED on the fixtures; FIXED in Phase 5B.1, see the end of this entry)

Found by ingesting `test_evidence/paisa.db` and reading the stored rows (second review, continued).

- The transaction path (`parse_database_artifacts` -> `synthesize_and_deduplicate_records`) reduces each row to
  seven columns (`Date, Transaction_ID, Linked_Reference_IDs, Amount, Counterparty, Status, Type`) and merges rows
  into clusters. Table, rowid, byte offset and source page are dropped. Result in the case store: every transaction
  has `Forensic_Provenance = NULL`, `Timestamp_IST = NULL`, `Direction = NULL`, and `Application` is the file name
  (`paisa.db`), not an app.
- Consequence: no transaction can point back to its evidence row, so the evidence card, the Section 63 certificate
  and any cross-examination answer "where is this in the phone?" cannot be produced for the ledger. Chats do carry
  it (`msgstore.db :: <path> :: message :: RowID=1 :: State=Allocated B-Tree`).
- Also: `Date` is a naive string of unknown zone (H-02 remainder). The odd-hour badge and the IST/UTC display both
  inherit that.
- Fix (planned, Phase 4 stage C, with the `src/provenance` and `src/core/timestamps` wiring): carry
  `(source file, table, rowid, offset)` through clustering as a list of contributing rows, and store
  `Timestamp_UTC`, `Timestamp_IST`, `Timestamp_Raw` from one converter.
- **Fixed (Phase 5B.1, `tests/test_tx_provenance.py`, 16 tests).**
  * Each parsed row keeps its table and rowid (`SELECT rowid, *`; a view or WITHOUT ROWID table has none and says "Not recorded").
    Clustering unions the source rows of everything it merges, so a merged transaction lists every contributing row.
    The store line has the chat shape: `file :: table :: RowID=n :: State=... :: Page=p :: Offset=0x...` joined with ` + `.
  * Page and absolute byte offset come from `parsers/sqlite_locator.py` (the `src/sqlite` reader). They are given only when the main file is the
    whole truth: if a write-ahead log with frames sits beside the database the newest row version may be in the log, so the offset reads "Not recorded".
  * One converter (`timestamp_record`) gives `Timestamp_Raw`, `Timestamp_UTC`, `Timestamp_IST` and `Timestamp_Basis`. A numeric epoch is UTC;
    an offset-aware string is converted to UTC; a bare local string such as `2026-11-01 22:43:19` (every row in the `paisa.db` fixture) is
    `LOCAL_ZONE_UNKNOWN` and claims **no** UTC or IST. A time read from a PhonePe-style reference ID is `DERIVED_FROM_TRANSACTION_ID`, also without a zone.
  * The renderer used to show such a bare string as an IST time (it treated it as UTC and added 5:30). It now shows the clock time as recorded,
    marked "zone not recorded", and the evidence card says the same.
  * `Direction` follows the recorded `Type` (DEBIT is OUTGOING, CREDIT is INCOMING); a TRANSFER has no established direction and stays empty.
  * Case stores written before this change gain the three new columns when opened.
  * Not changed: `Application` is still the file name when the app cannot be identified from the path (an app-identification question, not provenance).

### Medium

**U-01. Integrity indicators in the renderer are static text. CONFIRMED (from code).**
- `ExtractionSummaryTab.tsx:~503` shows "BIT-FOR-BIT SEAL PASS" whenever the integrity card renders, with no dependence on a hash comparison result; `ProjectTreeDock.tsx:526` shows
  "Air-Gapped PASS"; `ProjectTreeDock.tsx:122` shows "VFS Indexed • Bit-Verified" whenever a case is loaded;
  `ExtractionSummaryTab.tsx:315` shows "100% Offline • Strict Read-Only"; `ChatsMasterWorkspace.tsx:1180, 1341`
  claim "SHA-256 Verified" and "SHA-256 match validated" for voice notes and images, although that file contains no hash computation or comparison at all (grep for `sha256`/`hash` finds nothing);
  `TopRibbonBar.tsx:245` shows "SHA-256 Verified" whenever any hash string exists, with no comparison.
- Consequence: the screen asserts verification the software did not perform. Same class as C-05.

**U-02. Overclaims `REMEDIATION.md` says were removed are still present. CONFIRMED (from code).**
- `BankCdrFusionView.tsx:331, 413` ("Verified Both", "VERIFIED BOTH PHONE & BANK"); CSV buttons titled
  "court-admissible" in `ChatsMasterWorkspace.tsx:643` and `UPIMasterLedgerView.tsx:367`; "Air-Gapped" in
  `ExtractionSummaryTab.tsx:274, 303` and in `exhibit_packager.py`'s docstring. A reference-ID match may deserve
  "Matched"; an amount-and-window match should not read "Verified".

**U-03. Ingestion progress is a timer, not the pipeline. CONFIRMED (from code).**
`ExtractionSummaryTab.tsx:119-123` switches the displayed phase at 1.2 s, 2.4 s and 3.6 s regardless of what the
backend is doing, and `Loader2 animate-spin` stays on. The processing log from H-13 is the truthful source.

**U-04. The screenshot button only shows an alert claiming a Section 63 timestamp. CONFIRMED (from code).**
`TopRibbonBar.tsx:282`. Nothing is captured, hashed or stored.

**U-05. Demo data still ships in the renderer bundle. CONFIRMED (from code).**
`workbenchStore.ts:138, 395-1010` (`loadGoldenDataset`): invented chats and payments (for example
`target.account1@ybl`, a wallet address, UTR `982730192834`) with fake provenance (`REF_EVIDENCE_DUMP_01`,
fixed `rawPayloadHex`). Nothing in the renderer calls it, but it is reachable through the store, and the
first review asked for it to be removed (§4).

**X-11. NCRP/nodal exports use local time labelled IST and float money. CONFIRMED (from code).**
`nodal_freeze_and_requisitions.py:97, 155, 240` and `dossier_builder.py:42` format `datetime.now()` with a literal
"IST (+05:30)"; on a machine not set to IST the label is wrong. Totals are summed as floats and rounded
(`nodal_freeze_and_requisitions.py:62-103`); use `Decimal`.

**X-12. Dossier text asserts findings that are not computed. CONFIRMED (from code); unwired.**
`src/dossier_and_exhibits/dossier_builder.py` prints "Attributed User KYC Identities: Verified via SIM Bindings,
Aadhaar/PAN OCR, and App Accounts." and "Rapid Layer-1 to Layer-2 disbursement detected (< 15 mins)" for every
dossier. Not imported by `api_server.py`; fix before wiring.

### Low

**L-04.** `package.json` keywords include `cellebrite-alternative`; remove it from anything you publish or register.
**L-05.** `nodal_freeze_and_requisitions.py:89-92` counts accounts and VPAs in one set, so the "accounts" total mixes both.
**L-06.** `NodalFreezeExporter` and `Section94BnssRequisitionDrafter` are not called by any endpoint (only `NodalFreezeExporter` is imported). Either wire them with the X-01/X-07 fixes or delete them.
**L-07.** `ForensicBenchmarkRecorder` (1,170 lines) runs the whole pipeline on a path and writes reports; it is a developer tool exposed on the production API.

## 3. Test quality (first pass)

I counted assertions in `tests/` with a script: 1,997 `assert` statements, 1,166 of them equality checks, and
about 384 whose shape is weak (`is not None`, `len(...) > 0`, bare truthiness, `isinstance`, substring presence).
The weak share is highest in `test_phase7_module7_3_qr_and_receipts.py` (22 of 68),
`test_phase7_module7_4_kyc_and_ocr.py` (23 of 67) and `test_phase11_ingestion_and_workstation_ui.py` (32 of 131).
This is a count by shape, not a judgement of each test. The larger issue remains S-01: passing tests for modules the
product does not import say little about product behaviour. I did not run `tests/e2e/` or audit its assertions.

## 4. Coverage

Read in depth, with reproductions:
- `electron/main.cjs` and `electron/preload.cjs` (all).
- `src/dossier_and_exhibits/exhibit_packager.py`, `nodal_freeze_and_requisitions.py`, and the model defaults used by them.
- `src/unk_triage_and_bsa_studio/freeze_deconfliction.py`.
- The API handlers for Section 230, NCRP, OCR, chat redline and benchmark in `parsers/api_server.py`.
- `parsers/keychain_decryptor.py` (decrypt function) with a standard-library reproduction.
- `src/dossier_and_exhibits/dossier_builder.py` (the header and chapters 1-3 only).
- Renderer static-claim and demo-data sweep (grep) with the cited lines read.

Pattern-swept only (database opens, `except Exception: pass`, hard-coded defaults), not read for logic:
- `parsers/social_interaction_comms_parsers.py`, `commercial_parity_engine.py`, `custodial_wallet_parser.py`,
  `deep_sqlite.py`, `account_profiler.py`, `vpa_harvester.py`, `os_privacy_spillover.py`, `protobuf_decoder.py`,
  `leveldb_parser.py`, `npci_storage_carver.py`, `wallet_deleted_recovery.py`, `zero_knowledge_miner.py`.
  The sweep found only the one read-write open (X-10); all other `sqlite3.connect` calls use `mode=ro`.
  It also found 12 `except Exception: pass` blocks in `social_interaction_comms_parsers.py` and 21 in
  `commercial_parity_engine.py`, which are candidates for the H-13 silent-failure class.

Reviewed after the first version of this document (2026-11-12): the `Forensic_Provenance` values the
product stores (X-13), `corroboration_engine.heal_counterparties_across_apps` (M-04/M-05), `wal_rollback_analyzer`
(M-01), `freelist_carver` (M-02), and the recovered-state SQL in `ui_fts5_paginator` (M-03). All were fixed except X-13.

Not reviewed:
- `src/banking`, `src/correlator`, `src/whatsapp`, `src/telegram_signal`, `src/nonsqlite`, `src/legal_and_bsa`,
  `src/web3`, `src/cex`, `src/seedhunter`, the rest of `src/upi`.
- Internals of `bilingual_ocr_engine.py`, `myers_redline_engine.py` and the body of `tools/forensic_benchmark_recorder.py`.
- The logic of `ChatsMasterWorkspace`, `MuleLinkGraphTab`, `CryptoWalletView`, `SQLiteWizardTab`,
  `FileSystemExplorerTab`, `MaliciousApkView`, `RemoteAccessView`, `OsSpilloverView`, `ContactsView`, `CallLogsView`,
  `PAFieldInspector`; only the claims above were checked.
- `tests/e2e/` and `ui/tests/` assertions.

## 5. Continued review (2026-11-12, after the fixes above)

Method: product-path parsers first (what `parsers/api_server.py` actually runs), then the `src/` modules by a
risk scan (invented defaults, direction guesses, local time labelled IST, substring matching) followed by reading
the hits. Every item marked FIXED has a regression test in `tests/test_review_regressions.py`.

| ID | Where | Finding | Status |
|---|---|---|---|
| R-01 | `parsers/commercial_parity_engine.py` generic classifier | With no direction column every chat and call was "Incoming"; missing coordinates became a (0, 0) map pin; a zero-duration call was "Missed" regardless of direction; payments got status `COMPLETED`, counterparty `AppGenie Counterparty` and a made-up `GEN_n` transaction ID; a carved record with no amount became a 0.00 transaction | FIXED |
| R-02 | `parsers/chat_social_privacy_parsers.py` (iOS Signal, Zangi calls, Element, Session, Snapchat, Instagram, dating apps; 10 sites) | Direction hard-coded `INCOMING`, status `RECEIVED`/`DELIVERED`, recipient "This Device (Owner)" for every row, with no sent/received column read. WhatsApp call direction was derived from the call result (a connected call became OUTGOING) | FIXED (now UNKNOWN). Reading the real from-me column per app is future work |
| R-03 | `parsers/custodial_wallet_parser.py` `_safe_sample` | Tables were read with `LIMIT 500..10000` and truncated silently | FIXED (a TRUNCATED warning is logged). Not yet shown in the UI processing log |
| R-04 | `parsers/wallet_provenance.py` | `Chain_Of_Custody_ID` was a random UUID per run: not a custody chain and different on every export | FIXED (stable id from case, source hash and row) |
| R-05 | `src/banking/narration_parser.py` | Direction by `"CR" in text` (matches CRED, SCRIPT, MICRO) with DEBIT as the default | FIXED (whole-token cues, UNKNOWN) |
| R-06 | `src/correlator/fraud_detector.py` | Balance gaps computed across all transactions with no account tail pooled as "UNKNOWN_ACCT"; unknown direction treated as credit; a gap over 50 INR asserted as CRITICAL "missing/deleted bank alert" | FIXED (skipped, skipped, hedged) |
| R-07 | `src/correlator/utr_validator.py` | "VALID_NPCI_YDDD_MATCH" returned when no date was compared; a Verhoeff pass (about 1 in 10 random numbers) reported as an Aadhaar number | FIXED (renamed to `STRUCTURALLY_VALID_DATE_NOT_CHECKED` and `POSSIBLE_AADHAAR_NUMBER`) |
| R-08 | `src/upi/{phonepe,gpay,paytm,whatsapp_pay}.py` | Every record `DEBIT_SENT`; missing status `SUCCESS` | FIXED (`infer_direction` from an explicit column or owner VPA, else UNKNOWN; status UNKNOWN). These decoders are still not called by the product |
| R-09 | `src/legal_and_bsa/bsa_certificate_generator.py` | Section 63 certificate time was machine local time labelled IST (same as X-11) | FIXED |
| R-10 | `parsers/api_server.py` OCR endpoint | `confidence_score` is a constant chosen by which rule matched (0.98, 0.95...), presented as a confidence | FIXED (labelled `confidence_basis`) |
| R-11 | `parsers/fiat_crypto_bridge.py` | A UPI debit and a crypto order whose amounts differ by more than 20% were kept as a "Temporal Match" if within 20 minutes; the text said the debit was "aligned with" the order | FIXED (dropped; wording is "Possible link (a lead, not proof)") |
| R-12 | `tests/test_m4_adversarial_stress.py` | The victim-account lock test asserted `value in [True, False]`, which cannot fail | FIXED (asserts the lock) |
| X-14 | `src/high_opsec`, `src/social_voip`, `src/telegram_signal` decoders (about 12 sites) | Same default `INCOMING_RECEIVED` as R-02 | OPEN. Not called by the product; fix when a module is wired (Phase 4) |
| U-06 | `RemoteAccessView`, `MaliciousApkView` | Shown in the UI but nothing feeds them: `sessions={[]}` is literal, the store never receives APK findings, and the backend has no APK analysis | OPEN. Hide or label "not available" in the redesign |
| L-08 | `parsers/enterprise_1tb_chat_and_container_engine.py` | `int(row.get('from_me') or 0)` treats a NULL flag as "Incoming" (8 sites). The columns are real, so this only matters for NULLs | OPEN (Low) |
| L-09 | `src/seedhunter/vault_unwrapper.py` | Unwraps keystores/vaults with a password it is given; it does not guess passwords. Not wired. Any wiring must take an examiner-supplied password and write an audit entry | NOTE |

### Coverage after this pass
Read for logic: the product-path code listed in section 4, plus `commercial_parity_engine` (generic classifier and carved-record
classifier), the direction/status/provenance fields of `chat_social_privacy_parsers`, `custodial_wallet_parser` (sampling),
`wallet_provenance`, `fiat_crypto_bridge`, `corroboration_engine` (healing), `wal_rollback_analyzer`, `freelist_carver`,
`src/banking/narration_parser`, `src/correlator/{fraud_detector,utr_validator}`, `src/upi` decoders (direction and status),
`src/legal_and_bsa/bsa_certificate_generator` (time), `src/seedhunter/vault_unwrapper` (purpose only), and OCR classification.

Scanned but not read line by line: `src/whatsapp`, `src/nonsqlite`, `src/web3`, `src/cex`, the rest of `src/seedhunter`,
`src/telegram_signal`, `social_interaction_comms_parsers.py`, `deep_sqlite.py`, `account_profiler.py`, `vpa_harvester.py`,
`os_privacy_spillover.py`, the body of the benchmark recorder, the OCR image path, and the React views' internal logic
(only their claims and data sources were checked). `tests/e2e` was run (all pass) but its assertions were only sampled.
None of the scanned `src/` modules is called by the product today, so a defect there cannot reach an output until Phase 4 wires it.

## 6. Final review pass (2026-11-12): the files that had only been scanned

Method: each remaining module was read for the same classes of defect as before (a value invented where the evidence is
silent, a guess shown as fact, a label that claims more than was checked, a failure that looks like "nothing found").
Items marked FIXED have a regression test in `tests/test_review_regressions.py` or `ui/tests/`.

| ID | Where | Finding | Status |
|---|---|---|---|
| R-13 | `parsers/social_interaction_comms_parsers.py` (17 sites) | Facebook Msys, Skype/Teams, WeChat, LINE, IMO/Kakao, Twitter/LinkedIn, Truecaller, OLX, ShareChat rows had direction "Incoming" and status "Delivered"/"Sent" hard-coded, and `Page_Number = rowid // 32 + 1` (a made-up page); a "recalled" message was labelled `RECALLED_FREELIST` although it was read from the live table; a failure to open a database was swallowed with `pass` | FIXED (UNKNOWN; page 0; label says "unsent flag set"; failure logged) |
| R-13b | `parsers/os_privacy_spillover.py` knowledgeC | `dict(r)` on a plain cursor raised, the exception was swallowed, so the iOS foreground-app timeline was always empty; the stream pattern `app.inFocus` does not match the real `/app/inFocus` | FIXED |
| Q-1 | `parsers/deep_sqlite.py` | Row caps (5,000 to 30,000) cut tables silently; chat sender/recipient defaulted to "Local Device/User" / "Counterparty"; columns were chosen by substring (`to` matched `total`, `ts` matched `status`); PhonePe/WhatsApp status defaulted to SUCCESS; a failed app-specific parse looked like an empty database | FIXED (TRUNCATED warning, "Unknown", whole-token column match, UNKNOWN status, failure logged). The amount unit is still assumed to be paise for `amount` columns: OPEN, needs a real PhonePe sample |
| Q-2 | `parsers/account_profiler.py` | The owner dossier took the first value containing `@` in any key as the owner's VPA and e-mail (a payee stored in preferences became "the owner"), the first five IFSCs found anywhere were listed as the owner's linked bank accounts, and the malformed-XML fallback did the same | FIXED (key must say vpa/email; IFSC labelled "seen in evidence, not confirmed as owner's"; fallback removed) |
| Q-2b | `parsers/vpa_harvester.py` | Read errors returned an empty result as if nothing was found | FIXED (logged). Phone numbers split across a 16 MB chunk boundary are missed: OPEN (Low) |
| Q-3 | `tools/forensic_benchmark_recorder.py` | "SURPASSED VENDOR" whenever our record count was higher (more rows is not better: could be false positives); an empty extraction scored 100% quality; a run with no vendor report printed "100% FULL INTERNAL PARITY" | FIXED (count-only wording, empty = 0, "no vendor count to compare"). The endpoint stays off unless `BHARAT_ENABLE_BENCHMARK=1` |
| R-14 | `src/geospatial_media_and_tamper/bilingual_ocr_engine.py`, `/api/ocr/analyze` | A bare 12-digit number that passes Verhoeff (about 1 in 10) was classed an Aadhaar card and removed from the UTR list; with Tesseract missing the "OCR" reads only text embedded in the file but the response did not say so | FIXED (UIDAI wording required; response carries `ocr_performed`) |
| R-15 | `src/web3/engine.py`, `src/cex/binance.py`, `src/cex/indian_cex.py` | A record with no timestamp was given `datetime.now()`: the examiner's clock became the transaction time (7 sites) | FIXED (empty = not recorded) |
| R-15b | `src/web3/{ledgerlive,tronlink,metamask,models}.py` | `tx_status` defaulted to "CONFIRMED": a wallet cache is not proof of on-chain confirmation | FIXED where the record has no status (`UNVERIFIED_LOCAL_RECORD`); an explicit status in the record is kept |
| R-16 | `src/nonsqlite/{varint,snappy,leveldb}.py` | An unterminated varint was returned as a complete value; a corrupt or short Snappy stream returned a partial buffer as the whole block; LevelDB entries running past the block were emitted with short keys/values | FIXED (raise / skip with a warning). Block CRCs are still not verified: OPEN |
| R-17 | `src/web3/address_utils.py` | `format_bigint_decimal` special-cased the hex `0x152d02c7e14af6800000` to 100 ETH to match a test fixture; that value is 10^23 wei = 100,000 ETH, so the real balance would have been understated 1000-fold | FIXED (special case removed; fixtures use the correct hex for 100 ETH) |
| R-18 | `src/cex/binance.py`, `src/cex/models.py` | A P2P order with no `orderStatus` became `COMPLETED_RELEASED`, with no `tradeType` a BUY, and the counterparty was taken from the wrong side | FIXED (UNKNOWN) |
| R-19 | `src/seedhunter/correlator.py` | The rupee-to-crypto "laundering chain" linked UPI payments to an order on amount alone when a timestamp was missing, searched every subset of up to 5 payments out of any number of candidates (a coincidental sum labelled "smurfing"), and matched a withdrawal on same currency OR similar amount | FIXED (needs timestamps, at most 12 candidates, asset AND amount) |
| X-14 | `src/whatsapp`, `src/telegram_signal`, `src/high_opsec`, `src/social_voip`, `src/hyperlocal_travel` | Default direction `INCOMING_RECEIVED` for rows with no direction flag | FIXED (UNKNOWN where no flag is read; an explicit 0/1 flag is still honoured) |
| U-07 | `ui/renderer/state/workbenchStore.ts`, `PATableWorkspace`, `ChatsMasterWorkspace`, `CryptoWalletView` | The UI undid the backend fixes: `isFromMe` false was shown as "Incoming" (so UNKNOWN looked received, in the grid, the inspector and the CSV); contacts and calls got an invented provenance (page 1, offset 0, 64 bytes, payload `00`, state ACTIVE); calls defaulted to INCOMING / ANSWERED; the case manifest was pre-filled with `FIR/CYB/2026/01`, "Cyber Crime PS", "State HQ", "Forensic Examiner"; hash time defaulted to the time the page was opened; the crypto view and "TRM/Chainalysis manifest" export defaulted app to Binance, asset to USDT, amount to 0, offset to 0x0 and every unlabelled address to "Mule Off-Ramp Target" | FIXED |
| U-08 | `ChatsMasterWorkspace` CSV export | Built as a `data:` URI with `encodeURI`: everything after the first `#` in any message was cut off; message text was not protected against spreadsheet formulas | FIXED (shared `utils/csv.ts`: Blob, formula-safe cells, "not recorded" offsets; test `ui/tests/csv_export_test.ts`) |
| T-01 | `tests/e2e/test_tier1_sqlite_recovery.py` | `assertGreaterEqual(len(df), 0)` cannot fail | FIXED (type and provenance assertion) |

### Still open after this pass
- X-13 (transactions lose provenance and normalised time in the case store): scheduled with Phase 4 stage C.
- U-01 to U-06 (static "BIT-FOR-BIT SEAL PASS", "Air-Gapped PASS", "SHA-256 Verified", "Verified Both", the screenshot alert, timer-based ingest phases, the two views with no data source): done as part of the UI redesign because those components are being replaced.
- Q-1 amount unit, R-16 block CRC, Q-2b chunk boundary, L-08, X-12.

### Coverage statement
Read for logic in this pass: `social_interaction_comms_parsers` (all direction/status/page/recovery fields and error handling),
`deep_sqlite`, `account_profiler`, `vpa_harvester`, `os_privacy_spillover` (notification and knowledgeC paths),
`bilingual_ocr_engine` entity extraction and classification, `forensic_benchmark_recorder` scoring and verdicts,
`src/nonsqlite/{varint,snappy}` and the LevelDB block reader, `src/web3/{address_utils,engine}`,
`src/cex/{binance P2P path, models}`, `src/seedhunter/{correlator, seed_hunter}`, and the store, table, export and crypto code in the UI.

Found by pattern search and fixed at the hit, but the module around the hit was not read line by line:
`src/whatsapp/decoder.py`, `src/telegram_signal/*`, `src/high_opsec/*`, `src/social_voip/*`, `src/hyperlocal_travel/dating_decoder.py`.

Not read: `src/nonsqlite/{mmkv,segb,protobuf}`, `src/telegram_signal/tl_deserializer`, `src/web3/{cakewallet,trustwallet}`,
the rest of `src/cex/binance.py` (withdrawal and deposit paths), `src/seedhunter/{hd_derivator, vault_unwrapper internals}`,
and the layout code of the React views (only data handling, labels and exports were read). None of the unread modules is
called by the product today, so a defect there cannot reach an output until Phase 4 wires it; each is read before it is wired.

## 7. The previously unread modules (2026-11-12)

All nine modules listed as "not read" in section 6 were then read line by line.

| ID | Where | Finding | Status |
|---|---|---|---|
| R-20a | `src/web3/cakewallet.py` | `continue` inside the frame loop without advancing the offset: an endless loop on the first frame whose value is not JSON; swap pair defaulted to USDT-TRC20 to XMR and amount to "0.0"; a missing time became 1970-01-01; carved JSON was labelled ORIGINAL_RECORD; read errors swallowed. The assumed Hive frame layout is unverified against a real box | FIXED (all but the format, which is documented as UNVERIFIED in the class docstring; do not wire until a real sample confirms it) |
| R-20b | `src/web3/trustwallet.py` | A keystore with no `coin` was treated as Ethereum, a missing `type` as "app holds the seed", non-dict JSON crashed | FIXED (`UNKNOWN` network / control mode) |
| R-20c | `src/cex/binance.py` | KYC name = the last MMKV key containing "name" (so "userName", "nickName"); user id matched "guid"; asset, fiat currency, rail and network defaulted to USDT / INR / UPI / TRON; second-resolution timestamps dropped; unlisted order status became "in escrow"; an e-mail address was extracted as a VPA; name mismatch reported as "triangulation confirmed" | FIXED (whole-word key match, last write wins, nothing defaulted, mismatch documented as a lead) |
| R-20d | `src/nonsqlite/{mmkv,segb,protobuf}.py` | Encrypted MMKV without a key was parsed as plaintext (junk records); SEGB v1 had no date range check (crash on garbage), and the write time was shown as the event time; protobuf nesting was unbounded and printable text that also parsed as a message was silently read as a message | FIXED (no key = no records and a warning; blank date; depth limit 24; both readings kept with `ambiguous_text_or_message`) |
| R-20e | `src/telegram_signal/tl_deserializer.py` | A read past the end of the blob returned 0, so a truncated message got id 0 and date 1970; the string scan could supply a phone, username or message text with no indication | FIXED (`parse_complete`, `heuristic_fields`, date None). `telegram_decoder.py` still turns a missing date into 0: OPEN (fix when wired) |
| R-20f | `src/seedhunter/hd_derivator.py`, `vault_unwrapper.py` | BIP-39 input was not NFKD-normalised (wrong seed for non-ASCII passphrases); one missing RIPEMD-160 aborted every network; scrypt with real parameters (n=262144) raised on the default memory limit; the keystore set its own unbounded work factor | FIXED. Only index 0 of each account is derived, so no match does not mean no activity (documented) |

Coverage: every file under `src/` that the plan listed as unread has now been read. The layout code of the React views is replaced by the redesign, not reviewed separately.

## 8. Found while building and running the new interface (2026-11-12)

| ID | Where | Finding | Status |
|---|---|---|---|
| U-01..U-06 | `ExtractionSummaryTab`, `ChatsMasterWorkspace`, `BankCdrFusionView`, old shell | Static "BIT-FOR-BIT SEAL PASS", "Air-Gapped PASS", "SHA-256 Verified" (any hash), "Verified Both", "Verified Ingest", a screenshot alert claiming a Section 63 timestamp, ingest phases advanced by `setTimeout`, two views with no data source | FIXED (see `UI_DESIGN.md` section 6) |
| U-09 | old `PATableWorkspace` | The "Timeline Activity" chart was a hard-coded array of bar heights | FIXED (rewritten as `RecordTable`; chart is computed from records with a recorded time) |
| U-10 | `ExtractionSummaryTab` | Crashed the whole screen (`Account_Holder_Names.join is not a function`) as soon as a real case was loaded: the backend sends a string such as "Not Found" where the view expected a list | FIXED (`dossierText`) |
| X-15 | `/api/case/ingest` | Opening the same case id twice appended the records a second time (31 contacts became 62, in every output) | FIXED (store rebuilt on ingest; regression test) |
| X-16 | `/api/case/hex-window`, `_resolve_case_file` | Provenance paths are relative to the evidence root, but the resolver only tried the process directory and the workspace, so the Source bytes view always answered 403 | FIXED (also tries the working copy and the evidence folder; traversal still returns 403) |
| X-17 | `IngestCaseRequest`, `/api/case/state`, fusion endpoints | The examiner and agency defaulted to "Forensic Examiner" / "State Cyber Crime Investigation Division" (and similar) when not supplied | FIXED (empty unless supplied) |
| U-11 | store | Selecting any row fetched a hex window, so every click on a row whose file is unavailable raised an error toast | FIXED (bytes load when the Source bytes tab is opened) |

Still open from the interface work: the older views keep their internal layouts (listed in `UI_DESIGN.md` section 7); the generators do not read pinned findings.

## 9. Found while replacing the statutory generators (2026-11-12, Phase 5A)

| ID | Where | Finding | Status |
|---|---|---|---|
| A-01 | `src/legal_and_bsa/chain_of_custody.py` | The entry hash left out `actor_or_subsystem`, so the actor could be edited without breaking the chain; the "IST" label was UTC (`strftime` of a UTC time with a literal IST suffix); the ledger lived only in memory; a timestamp of 0 was treated as absent | REPLACED by `src/audit/ledger.py` (actor in the hash, real IST, persisted, tests) |
| A-02 | `src/legal_and_bsa/hash_manifest.py` | Every item was stamped `IMMUTABILITY_VERIFIED_IDENTICAL` when registered, with no re-hash (same class as U-01); the Merkle tree duplicated an odd last node, so `[a,b,c]` and `[a,b,c,c]` shared a root | REPLACED by `src/audit/manifest.py` |
| A-03 | `src/unk_triage_and_bsa_studio/schema_mapper.py`, `engine.py` | `examiner_name` defaulted to "Examiner" and was written to the promotion ledger | FIXED (empty) |
| U-12 | `ChatsMasterWorkspace` "Dossier view" | For any thread it showed "HIGH RISK SYNDICATE", a default profile "Elena, 26 :: Crypto Investor", sample VPAs (`victim@okhdfcbank / mule@paytm`), a sample phone number and a hard-coded modus operandi that cited "Section 63 BSA audit standards" | REMOVED |
| U-13 | `ChatsMasterWorkspace` thread list, header and table | A per-app invented participant profile ("@mule_handler :: Escrow specialist", "Military Grade ID: 1084920194", "Elena, 26 :: 4.2 km") shown for every Tinder, Telegram, Zangi or Session thread | REMOVED |
| U-14 | `ExtractionSummaryTab` | A handler built a provenance record with an invented payload (decoding to "ACCOUNTS_IDENTITY_SEAL..."), length 64 and state ACTIVE; never called | REMOVED |
| X-18 | `/api/report/sec230-bnss` (old) | The client chose the output directory, so a bundle could be written anywhere | REMOVED with the route; the review package writes only under the case workspace |

## 10. Phase 5B.1: `src/sqlite` defects fixed (2026-11-12)

The four confirmed `src/sqlite` defects from the first review are fixed and pinned by `tests/test_sqlite_engine_fixes.py`
(eight tests; seven of them fail against the previous code, checked by stashing the fix).

| ID | Fix |
|---|---|
| H-03 | The schema is read by walking `sqlite_schema` from page 1 through interior pages, so a database with more than one schema page (for example 120 tables) no longer reads as empty. |
| H-04 | After a recovered cell the carver continues after that cell instead of skipping one more byte, so adjacent deleted rows are all found (600 of 600; it was 301, every second row). |
| H-05 | Records are given to the table whose column count equals the record, checked against each column's declared affinity. A record shorter than the table (rows from before `ALTER TABLE ADD COLUMN`) fills the first columns and nothing is shifted. If more than one table still fits, the record is labelled `AMBIGUOUS: a | b` instead of going to whichever table came first. |
| H-06 | A column is a rowid alias only when its declared type is exactly `INTEGER` (not `INT` or `BIGINT`), is not `DESC`, and the table is not WITHOUT ROWID. The table-constraint form `PRIMARY KEY (id)` is recognised for one `INTEGER` column. Stored 64-bit keys are no longer replaced by the rowid. |

Still open from the first review's `src/` list: M-08 (`src/crypto/sqlcipher.py` checks only page 1 and re-signs WAL frames) and H-14, H-15, M-09, M-10, L-01, L-03.
The carver and engine are not yet called for recovered transactions; only the b-tree reader is used (through the row locator) for live rows.
