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

Not reviewed:
- `src/banking`, `src/correlator`, `src/whatsapp`, `src/telegram_signal`, `src/nonsqlite`, `src/legal_and_bsa`,
  `src/web3`, `src/cex`, `src/seedhunter`, the rest of `src/upi`.
- Internals of `bilingual_ocr_engine.py`, `myers_redline_engine.py` and the body of `tools/forensic_benchmark_recorder.py`.
- The logic of `ChatsMasterWorkspace`, `MuleLinkGraphTab`, `CryptoWalletView`, `SQLiteWizardTab`,
  `FileSystemExplorerTab`, `MaliciousApkView`, `RemoteAccessView`, `OsSpilloverView`, `ContactsView`, `CallLogsView`,
  `PAFieldInspector`; only the claims above were checked.
- `tests/e2e/` and `ui/tests/` assertions.
