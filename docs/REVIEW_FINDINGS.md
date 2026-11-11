# Review Findings: Bharat Forensic Suite (post-merge)

Review date: 2026-11-11. Read-only review; no source, test, config or fixture file was modified.
Reproduction scripts and their data are in the session scratchpad, not in the repository.

"CONFIRMED" means reproduced with a concrete input, or provable directly from the code path cited.
"SUSPECTED" means the code supports it but I did not reproduce it.

## 1. Overall assessment

The "production ready / court admissible" claims do not hold, and the tool should not be used to produce
material for a court in its current state. Three problems are decisive. First, the product paths write to
evidence: the legacy dashboard checkpoints and deletes a WAL in a source folder, and the Electron backend
parses folder/file evidence in place and creates `-shm` files beside it. Second, several legal outputs are
built from hard-coded sample data rather than the case (the Section 230 BNSS bundle, the NCRP 1930 freeze
sheet, the Sankey "money trail", the mule-network fallback, default device identity and hash in the
Section 63 dialog), and the hex "provenance" viewer invents bytes when it cannot read the file. Third, the
Section 63 certificate asserts read-only handling and a pre/post hash match that the code never performs.
Beneath that, the financial layer silently produces wrong values: distinct transactions are merged, deleted
free text becomes "deleted transactions", amounts are mis-parsed, missing status becomes SUCCESS, and in
the Electron UI every transaction is shown as DEBIT dated 1970-01-01. A structural fact explains much of
the gap between test results and behaviour: the carefully specified `src/` engines (VFS, provenance,
SQLite/WAL, UPI, banking, DLT, correlator, crypto, legal) are not imported by either product pipeline, so
most of the 364 passing tests exercise code the application does not run. Parts of the low-level code are
sound (varint, overflow arithmetic, WAL checksum chaining in `src/sqlite/wal.py`), but that is not what the
user sees.

## 2. Findings, most severe first

Summary: 12 Critical, 15 High, 10 Medium, 3 Low.

### Critical

**C-01. Legacy dashboard ingestion modifies evidence databases and deletes their WAL. CONFIRMED (reproduced).**
- Where: `src/core/sqlite_manager.py:21-33`, used by `src/workstation_app/ingestion_pipeline.py:593` (`_introspect_sqlite`); folder ingest at `ingestion_pipeline.py:428-432` passes original paths.
- What: `connect_forensic_sqlite(read_only=True)` opens the file read-write and only sets `PRAGMA query_only`. That does not stop the checkpoint SQLite runs when the last connection closes.
- Trigger: a folder containing `msgstore.db` (16,384 bytes) plus an un-checkpointed `msgstore.db-wal` (4,152 bytes), ingested with `LiveForensicIngestEngine.ingest_local_path`. After ingest the DB hash changed (`1840f4f9…` to `0f737699…`) and the WAL file no longer existed.
- Consequence: source evidence altered; WAL-only (often deleted) records destroyed. The WAL was then read as empty, so it was never hashed, and the reported "Product A" hash covers only the pre-mutation DB.
- Fix: never open evidence with SQLite. Copy DB, `-wal`, `-journal` to a case working directory, hash the originals first, and open only the copy (`mode=ro`). Verify the source hash again after processing.

**C-02. Electron backend parses folder and single-file evidence in place and writes into the evidence folder. CONFIRMED (reproduced).**
- Where: `parsers/api_server.py:372-398` (`discovered_files` are the original paths), then `extract_profile_from_sqlite`, `parse_database_artifacts` etc. (`parsers/heuristic_engine.py:733, 1415`, and about 60 other `mode=ro` opens). Read-write fallback at `parsers/enterprise_1tb_chat_and_container_engine.py:123-127`.
- What: `mode=ro` on a WAL-mode database still creates a `-shm` file next to it. The fallback in `_open_ro_sqlite` opens read-write if the URI open fails.
- Trigger: same WAL folder as C-01, run through the five per-file parsers the pipeline calls. A new 32,768-byte `msgstore.db-shm` appeared in the evidence folder after `extract_profile_from_sqlite`.
- Consequence: evidence directory changed by the tool; a later directory hash will not match the "pre-ingestion" hash. The certificate's read-only statement (C-05) is false for this input type.
- Fix: same as C-01. Remove the read-write fallback.

**C-03. Legal outputs are generated from hard-coded sample data, not from the case. CONFIRMED (from code).**
- Section 230 BNSS bundle: `parsers/api_server.py` `generate_sec230_bnss_report` always packages two built-in `SensitiveMediaItem`s (`payment_receipt_01.jpg` with the SHA-256 of an empty file, and a fake "POCSO" stream). No case data is read.
- NCRP 1930 freeze sheet: `ui/renderer/views/Ncrp1930FreezeModal.tsx:41-70` holds a fixed candidate list (`987654321012 / SBIN0001234 / mule1@oksbi`, `112233445566 / ICIC0005678 / mule2@icici`, …) and has no code that replaces it; the backend (`generate_ncrp_freeze_report`) uses the same list when none is sent, and `GET /api/report/ncrp-freeze` always does.
- Mule network: `GET /api/graph/mule-network` returns a built-in "Victim Source → Mule Layer 1 → … → Tron TRC-20 Escrow" graph with amounts and UTRs whenever the case has no graph nodes, and always builds the Sankey layout from those built-in nodes.
- Sankey SVG: `src/financial_graph_and_storyboard/sankey_canvas.py:165+` is a static drawing (₹1,50,000, "SBI YONO A/C", "FixedFloat XMR") served by `GET /api/graph/sankey-svg` for every case.
- Section 63 dialog: `ui/renderer/views/Sec63BsaModal.tsx:52-76` falls back to a fabricated device (Redmi Note 12, IMEIs, serial), SHA-256 `a1b2c3d4…`, `verified: true`, and pre-filled officer, FIR and court names.
- Consequence: a freeze request naming account numbers that are not in the evidence; a disclosure bundle and a money-trail diagram unrelated to the case; a certificate carrying an invented hash and IMEI.
- Fix: delete every sample default from product code paths. Return an explicit "no data" result. Require candidates, items and device metadata to come from the case store, and refuse to render otherwise.

**C-04. The hex "provenance" viewer fabricates bytes. CONFIRMED (reproduced).**
- Where: `parsers/ui_fts5_paginator.py` `read_provenance_hex_window` (block commented "construct deterministic byte window"); second copy in `ui/renderer/state/workbenchStore.ts:268-290`.
- Trigger: `read_provenance_hex_window(file_path="Z:\\does\\not\\exist\\msgstore.db", byte_offset=4096, window_size=256)` returned 256 bytes (`f00000293c4f6275…`). The same happens for a real file when the offset is past EOF. `/api/inspector/hex` then returns `success: true` with a SHA-256 of those bytes.
- Consequence: an examiner is shown, and may exhibit, bytes that are not on the device.
- Fix: return an error when the file or offset cannot be read. Remove both generators.

**C-05. The Section 63 certificate asserts facts the software does not establish. CONFIRMED (from code).**
- Where: `parsers/api_server.py:1543-1547` (declarations b, c, d); `parsers/api_server.py:277` (`"verified": True` unconditionally); `ui/main/reporting/sec63-bsa-generator.ts` (banner "DUAL-HASH INTEGRITY VERIFIED (PRE-INGESTION & POST-INGESTION MATCH 100% CONFIRMED)" is literal HTML, printed even when the hash is `N/A`; `SOFTWARE_BUILD_HASH` is a constant; `byteOffsetAccuracyAffidavit: true`).
- What: there is no post-ingestion hash anywhere in the codebase. "O_RDONLY" is false (C-01, C-02). The "Total Verified" column is a row count. The byte-offset affidavit covers offsets that are fabricated (C-09) or fixed at zero (C-06).
- Related hashing defects in `compute_hashes_streaming` (`api_server.py:243-281`): directory hashing omits file names, does not sort directories, and silently skips unreadable files; a missing or empty input yields the empty-string hash marked verified.
- Fix: compute and store a post-processing hash and print the comparison result, including a mismatch. Generate each statement from recorded facts. Hash folders with a sorted path+hash manifest (as `src/provenance/hasher.py` already does) and fail on unreadable files.

**C-06. In the Electron UI every transaction is DEBIT and dated 1970-01-01; every chat message is INCOMING and dated 1970-01-01. CONFIRMED (code path, timestamp part reproduced).**
- Where: `ui/renderer/state/workbenchStore.ts:1045-1105`.
- What: the mapping reads `r.Direction` (backend stores `Type`; `Direction` is always NULL) with `|| 'DEBIT'`; reads `r.Timestamp_IST` for transactions (always NULL; backend stores `Date`); sets `isFromMe: r.Direction === 'OUTGOING'` while the WhatsApp parser emits `'Outgoing'`; and feeds chat `Timestamp_IST` strings such as `2024-01-15 16:00:00 IST (+05:30)` to `Date.parse`.
- Trigger: `normalizeTimestamp('', 'ISO_8601')` and `normalizeTimestamp('2024-01-15 16:00:00 IST (+05:30)', 'ISO_8601')` both return `1970-01-01 05:30:00.000 IST`.
- Also: payer and payee are both set to the counterparty; `status` defaults to SUCCESS; provenance is hard-coded to table `transactions`, page 1, offset 0, 64 bytes; only the first 200 rows per category are loaded, and certificate counts use that array's length.
- Consequence: the UPI ledger view, its CSV export and the Section 63 annexure (which print `tx.direction` and `tx.timestamp.istFormatted`) show wrong direction and wrong time for every row.
- Fix: one typed contract between backend and UI. Map `Type`, `Date`/UTC, and real provenance; render "unknown" rather than a default; page through all rows.

**C-07. The live carver turns deleted text into "deleted transactions". CONFIRMED (reproduced).**
- Where: `parsers/freelist_carver.py:148-225` (`_record_to_transaction`) and `:383-410` (raw string pass), called from `parsers/heuristic_engine.py:2077-2092`.
- What: any record or printable string with a VPA-like token, an amount-like token and a date is emitted as a transaction with status `DELETED (Cell Carved)`. There is no schema or table check. Integers divisible by 100 are treated as paise; any float from 1 to 500,000 is an amount.
- Trigger: table `notes(id, body, created)` with 300 rows of "bhai kal tak Rs 5000 bhej dena ramesh0@okaxis pe, abhi nahi bheja hai …" ("not sent yet"), then `DELETE`. `parse_database_artifacts` returned 49 transactions of ₹5,000 to `ramesh*@okaxis`, status `DELETED (Cell Carved)`.
- Consequence: payments that never happened enter the ledger, the graph and the mule alerts.
- Fix: carve against the owning table's schema, keep carved rows in their source table's shape, and never promote text to a transaction.

**C-08. De-duplication merges distinct transactions into a composite that never existed. CONFIRMED (reproduced).**
- Where: `parsers/heuristic_engine.py:902-1005` (compatibility rules) and `:1163-1215` (clustering); same rules in `deduplicate_master_timeline` and `parsers/corroboration_engine.py:321-420`.
- What: within one amount, records merge when IDs are in different namespaces, times are within 15 minutes **or 315-345 minutes apart**, or either date is missing, and a name is always "compatible" with any VPA.
- Trigger: three ₹500 records: UTR `412345678901` to "Ramesh Kumar" SUCCESS at 10:30; PhonePe ID `T2401151040001234567` to `suresh@ybl` FAILED at 10:40; a third to "Mahesh Traders" with no date. Output: one row, ID `412345678901`, counterparty `suresh@ybl`, status FAILED.
- Consequence: transactions dropped; a real UTR attached to the wrong party and status.
- Fix: merge only on an identical reference ID. Otherwise keep both rows and record a "possible duplicate" link.

**C-09. Byte offsets in chat provenance are invented. CONFIRMED (from code, one case reproduced).**
- Where: about 40 sites, e.g. `parsers/chat_social_privacy_parsers.py:370, 641, 770`, `parsers/social_interaction_comms_parsers.py:213…`, `parsers/os_privacy_spillover.py:147, 197`.
- What: `Byte_Offset` is `rowid * 128` (or 96, 64, 256, 32); line 770 uses `hash(str(row_id))`, which changes between runs. `Page_Number` is 0.
- Trigger: Telegram message `mid=5001` reported `Byte_Offset 0x00075360` (5001 × 96).
- Consequence: false provenance under a certificate that swears to byte-offset accuracy.
- Fix: report table and rowid only, unless the offset comes from a real B-tree walk.

**C-10. Amount parsing returns wrong values without error. CONFIRMED (reproduced).**
- `parsers/heuristic_engine.py:780-787` `clean_amount_series`: `"Rs.500"` and `"Rs. 500"` give 0.5; `"500 for 2 items"` gives 5002; `"INR 2000 on 12 Jan"` gives 200012.
- `parsers/freelist_carver.py:40-43` and `src/sqlite/carver.py:33-36` `AMOUNT_VALID_RE`: `"Rs 1,00,000"` and `"Rs.1,50,000.00"` give 1.0 (Indian lakh grouping not handled).
- `src/dlt/sms_grammar.py:18-21` `AMOUNT_PATTERN` (not wired into a product, see S-01): `"Rs.1500.00"` gives 150.0, `"INR 25000"` gives 250.0, `"Rs 1240"` gives 124.0.
- Fix: one amount parser: strip a currency prefix, then match `\d+(?:,\d{2,3})*(?:\.\d{1,2})?` in full with a trailing boundary; reject anything else. Unit-test against real bank SMS.

**C-11. Non-WhatsApp chat messages are stored without body, application or sender. CONFIRMED (reproduced).**
- Where: `parsers/ui_fts5_paginator.py:414-420` (keeps only columns common to the DataFrame and the table) with the 37-column schema from `parsers/chat_social_privacy_parsers.py:35` versus the 28-column `chats` table.
- Trigger: a Telegram `cache4.db` row parsed and ingested; the stored row had `Application`, `Message_Body`, `Sender_Identifier`, `Recipient_Identifier`, `Forensic_Provenance` all NULL.
- Consequence: Telegram, Signal, Snapchat, Instagram and others show as empty messages; text search misses them.
- Fix: one chat schema (see §3.1); make ingest fail on unmapped columns instead of dropping them.

**C-12. Missing status becomes SUCCESS; unknown direction becomes DEBIT; placeholder counterparties and IDs are invented. CONFIRMED (reproduced).**
- Where: `parsers/heuristic_engine.py:1100-1125, 1262-1275`; `src/upi/phonepe.py:172-176, 193`; `src/upi/gpay.py:140, 219`; `src/upi/paytm.py:98`; `src/upi/whatsapp_pay.py:105`.
- Trigger: a row with status `"0"`, no type, ID `T2403010900001234567`, no counterparty came out as SUCCESS / DEBIT / "PhonePe Merchant / Bill Payment". A row to `billu.singh@oksbi` with no type came out DEBIT (substring "bill") with invented ID `UPI_REF_202403020900`. `_infer_transaction_type` turns type CREDIT with status "UNPAID" into DEBIT (substring "PAID").
- The `src/upi` decoders set `tx_direction=DEBIT_SENT` for every PhonePe, GPay, Paytm and WhatsApp Pay row.
- Fix: carry `UNKNOWN` for status and direction; never synthesise IDs or counterparties in evidential columns; match keywords on word boundaries and prefer the explicit type column.

### High

**H-01. Archive entries can be written outside the case workspace (zip-slip / tar-slip). CONFIRMED (reproduced).**
- Where: `parsers/enterprise_1tb_chat_and_container_engine.py:351-358` and the TAR and E01 equivalents.
- Trigger: a ZIP entry `../../../ESCAPED_OUTSIDE_WORKSPACE.json` was created three levels above `extracted_dbs`.
- Related: `if not os.path.exists(local_out)` means a second entry whose path differs only by case (`Data/…/MsgStore.db`) is recorded as materialised but the first file's content is used; re-ingesting different evidence under the same case ID reuses stale files.
- Fix: resolve the target and require it to stay under `extracted_dbs`; reject `..`; name files by entry index or hash; never reuse an existing file.

**H-02. Timestamps: timezone-aware strings mislabelled, day/month swapped, unlabelled UTC. CONFIRMED (reproduced).**
- Where: `parsers/app_overrides.py:663-715` (`normalize_timestamp_value`), `parsers/enterprise_1tb_chat_and_container_engine.py:201-254`.
- `format_timestamp_triplet('2024-01-15T10:30:00+05:30')` returns `10:30:00 UTC / 16:00:00 IST` (true UTC is 05:00).
- `'05/01/2024 10:30:00'` becomes 1 May 2024, while `'13/01/2024'` becomes 13 January (no `dayfirst` anywhere in the repository). This also affects bank statements (`parsers/multi_source_fusion.py:117`).
- The transaction `Date` column is a naive string: UTC when derived from an epoch, local wall time when derived from a string, with no label. The same instant appears as `04:30:00` or `10:30:00`. The "Odd-Hour 12AM–5AM" risk badge (`heuristic_engine.py:1016-1017`) is computed on that value, so 10:27 IST was flagged as odd-hour.
- Values outside 2015-2035, WebKit microseconds, and seconds passed with a millisecond hint come back as the raw number in the UTC and IST columns.
- Fix: carry timezone-aware datetimes end to end; parse Indian formats explicitly; store raw, UTC and IST for every record; show "unparsed" rather than the raw number.

**H-03. `src/sqlite` engine returns zero records when `sqlite_schema` spans more than one page. CONFIRMED (reproduced).**
- Where: `src/sqlite/engine.py:487-489` (accepts page type 0x05 then parses its cells as leaf cells).
- Trigger: database with 81 tables (page 1 type 0x05) and 20 rows in `messages`: 0 records, no error.
- Consequence: any real app database with many tables (WhatsApp `msgstore.db`) reads as empty.
- Fix: walk the schema B-tree from page 1 through interior pages.

**H-04. `src/sqlite` carver recovers only every second adjacent deleted cell. CONFIRMED (reproduced).**
- Where: `src/sqlite/carver.py:376-380` (`p = payload_start + P; break` followed by the loop's `p += 1`).
- Trigger: 600 rows deleted; 301 recovered, all with even rowids.
- Fix: `continue` after setting `p`.

**H-05. `src/sqlite` carver attributes records to the wrong table and shifts columns. CONFIRMED (reproduced).**
- Where: `src/sqlite/carver.py:351-375`; `src/sqlite/engine.py:680-700` (`_find_matching_table_for_page`).
- What: the first table with the same column count wins; text printability is the only check. The "N+1 columns" branch drops the first column, but rows written before `ALTER TABLE ADD COLUMN` are short at the end, so values shift by one.
- Trigger: tables `contacts` and `payments`, both four columns; 500 deleted `payments` rows; 227 were reported under `contacts`.
- Fix: use the page owner where known; otherwise score every candidate on affinity and report ambiguity.

**H-06. `src/sqlite` primary-key handling overwrites or loses stored IDs. CONFIRMED (reproduced).**
- Where: `src/sqlite/engine.py:118-131, 640-642`.
- Trigger: `txn_id BIGINT PRIMARY KEY` with value 987654321012 is reported as 1 (the rowid). `id INTEGER, …, PRIMARY KEY(id)` is reported as None.
- Fix: rowid alias only for a column declared exactly `INTEGER PRIMARY KEY`, including the single-column table-constraint form.

**H-07. Bank-statement reconciliation marks rows "Verified" on amount alone. CONFIRMED (from code).**
- Where: `parsers/multi_source_fusion.py:186-204`.
- What: with no reference match, any phone transaction of the same amount (any date, any party, reusable) yields "✅ Verified on Both Phone & Bank Statement". Unmatched rows are labelled "Wiped from Phone / Other Device".
- Also: `parsers/api_server.py` counts statuses `"MATCHED"` and `"UNMATCHED_BANK"`, which never occur, so the API always reports 0 matched.
- Fix: require a reference match, or amount plus date window plus party, with graded labels; drop the "wiped" inference.

**H-08. Transactions reach the case store with no application, source file or provenance. CONFIRMED (reproduced).**
- Where: `parsers/api_server.py:497-520, 615-616`; `parsers/ui_fts5_paginator.py:414-420`.
- Trigger: 49 carved transactions ingested; `Application`, `Source_File`, `Forensic_Provenance` NULL; counts reported 49 active, 0 recovered.
- Consequence: no ledger row can be traced to its source; the certificate's active/recovered split is wrong.
- Also: `app_artifacts[app_label] = arts` overwrites earlier databases of the same app.
- Fix: stamp each record with app, source path, table, rowid and recovery method when it is parsed.

**H-09. WhatsApp parser duplicates group messages and overstates delivery and read status. CONFIRMED (reproduced).**
- Where: `parsers/enterprise_1tb_chat_and_container_engine.py:1398-1400, 1461`.
- Trigger: 3 messages, one group message with 3 receipts: 5 rows out. Delivery receipts with NULL `read_timestamp` were reported "Read" with a "Read_Timestamp_IST". An outgoing message with status 0 was reported "Delivered". An incoming 1:1 message had an empty `Sender_Identifier`.
- Fix: aggregate receipts per message; derive status from `message.status` and `read_timestamp`; fall back to the chat JID for 1:1 senders.

**H-10. Legacy dashboard fabricates device identity, money figures and timeline metadata. CONFIRMED (reproduced).**
- Where: `src/workstation_app/ingestion_pipeline.py:190-395` (two built-in "seized devices"), `:520-545`, `:620-636`.
- Trigger: after ingesting the test folder: IMEI `869018273619283`; `disputed_flow_inr = 95000.0` (₹95,000 per 12-digit number found); phone number `919876543210` listed as a UTR; timeline timestamps equal to ingest time with `clock_integrity: NTP_VERIFIED`, invented `cell_offset` and hex preview; `product_b_sha256 = sha256(master + "_staging")`; `merkle_root` is not a Merkle root.
- Fix: remove, or retire this UI (see §4).

**H-11. Graph roles and mule alerts are built on unfiltered, direction-defaulted data. CONFIRMED (from code).**
- Where: `parsers/graph_intelligence.py:29-62, 146-200, 261-300`; `parsers/api_server.py` (mule-network role rule).
- What: FAILED and carved rows are counted; unknown direction is drawn as outgoing; a counterparty with more than ₹20,000 in and out is "Middleman / Rapid Pass-Through Account, CRITICAL" with no time test; `Confidence: 94` is a constant.
- Fix: include only successful, directed transactions; present these as leads with the rule shown; remove fixed confidence numbers.

**H-12. Local API allows any web page to read workstation files. CONFIRMED (from code).**
- Where: `parsers/api_server.py:111-117` (CORS `*`, no authentication); `/api/inspector/hex` (no path check, unlike `/api/case/hex-window`); `/api/sqlite/inspect`; `/api/ocr/analyze`; `/api/case/ingest`.
- Consequence: a page open in the examiner's browser can call `127.0.0.1:8000` and read arbitrary files or start ingestion.
- Fix: per-launch token from Electron, CORS limited to the app origin, and the workspace/evidence path check on every file endpoint.

**H-13. Parse failures are discarded and unsupported containers report success. CONFIRMED (from code).**
- Where: `parsers/api_server.py:455-513` (six `except Exception: pass` per file); `parsers/heuristic_engine.py` throughout; `parsers/enterprise_1tb_chat_and_container_engine.py:468-472`.
- What: a database that fails to parse yields "no data" with no record. A `.ufd`, or an `.xry`/`.ofb` that is not a ZIP, is catalogued as one RAW file and ingest returns `success: true` with zero artifacts.
- Fix: per-file processing log stored in the case and shown in the UI and report; fail loudly on unsupported containers.

**H-14. `src/sqlite/journal.py` ignores the database page size. CONFIRMED (reproduced).**
- Where: `src/sqlite/journal.py:84-87`.
- Trigger: PERSIST journal (header zeroed after commit) for a 1,024-byte-page database with 10 deleted rows in its pre-image: 0 pages read. The 4,096-byte case worked.
- Also: record checksums are never verified, so stale records are accepted.
- Fix: take page size from the database header; verify checksums.

**H-15. `src/vfs` returns wrong bytes or mutates evidence in several container cases. CONFIRMED (reproduced).**
- `src/vfs/indexer.py:571`: `Manifest.db` opened read-write; an iOS backup's `Manifest.db` changed hash and its WAL was deleted.
- `src/vfs/indexer.py:283` with `src/vfs/reader.py:108-112`: uncompressed `.ab` members are read without the header offset; expected `HELLO-EVIDENCE…`, got 24 zero bytes then `HELLO-EVI`.
- `src/vfs/indexer.py:514-521`: unknown ZIP methods are labelled deflate (bzip2 member raised a zlib error); method 93 (zstd) is returned still compressed; the encryption flag is ignored; CRC and length are never checked.
- `src/vfs/reader.py:62`: any path containing `_` is run through `LIKE`; a query for `msg_store.db` also returned `msgXstore.db`.
- `src/vfs/reader.py:196-206`: companion WAL lookup has no `container_id` filter (SUSPECTED cross-device mix in a shared catalog). UFED multi-payload indexing overwrites `container_sources` for the shared ID (SUSPECTED).
- Not wired into a product (S-01), hence High rather than Critical.

### Medium

**M-01. WAL analysis in the live path ignores frame validity. CONFIRMED (from code); consequence SUSPECTED.**
`parsers/wal_rollback_analyzer.py:150-165, 230-300`: salt and checksum results are computed and never used; "latest" is the last frame in the file. After a WAL restart, stale tail frames are treated as current and current rows can be labelled "MODIFIED / WIPED". Fix: use only the valid salt/checksum chain up to the last commit; classify the rest as residual.

**M-02. Live carver alignment and freeblock parsing. CONFIRMED (from code).**
`parsers/freelist_carver.py:316` scans slack in steps of 4 bytes, so most cell starts are never tried; `:292-296` reads a payload-size varint at freeblock+4, which is mid-cell. Both lose recoverable records.

**M-03. Counts treat any provenance containing "WAL", "SLACK" or "CARVED" as recovered. CONFIRMED (reproduced).**
`parsers/ui_fts5_paginator.py:490`: two live chats from `com.Slack/…` and `…/wallet_chat.db` were counted as 0 active, 2 recovered. Fix: a dedicated recovery-state column.

**M-04. Cross-app "healing" links parties by amount and time. CONFIRMED (from code).**
`parsers/corroboration_engine.py:321-420`: counterparties and direction are copied between unrelated same-amount transactions within 15 minutes or about 5.5 hours; a name is expanded to whichever VPA last carried that name. In the Electron pipeline the healed frames feed the owner dossier, not the stored ledger.

**M-05. Counterparties are written into the contacts list. CONFIRMED (from code).**
`parsers/heuristic_engine.py:2160-2175`, `corroboration_engine.py:425-445`: payees become "contacts", some labelled "Verified Counterparty".

**M-06. Device and acquisition metadata are defaults. CONFIRMED (from code).**
`parsers/api_server.py:413-431`: serial number is the case ID; acquisition time is ingest time; `istFormatted` is UTC time with the text "IST"; every database is parsed with `os_type="android"`, and `heuristic_engine.py:1400-1401` is a no-op for iOS.

**M-07. Section 63 annexure truncation and unescaped evidence strings. CONFIRMED (from code).**
`ui/main/reporting/sec63-bsa-generator.ts`: annexures are cut to 50 transactions and 30 chats with no notice; VPA, names, app and case fields are inserted into HTML unescaped (same for `case_name` in `api_server.py`).

**M-08. `src/crypto/sqlcipher.py` verifies only page 1 and re-signs WAL frames. CONFIRMED (from code).**
HMAC is checked for page 1 in the probe only; `forced_profile` skips all checks; `_decrypt_wal_frames` writes a fresh valid checksum chain for every frame without checking the original, so torn frames become valid.

**M-09. `src/sqlite` record decoder returns 0 for truncated integers; every record gets `corroboration_score=1.0`. CONFIRMED (from code).**
`src/sqlite/record.py:27-70`; `src/sqlite/engine.py:447-456` (also applied to speculative carved rows).

**M-10. `src/dlt/sms_grammar.py` misclassifies ordinary alerts. CONFIRMED (reproduced).**
"…call 1930 to report" and "Dear Account holder…" are classified `LIEN_HOLD_OR_FREEZE_ALERT` (substrings "1930", "hold"); a credit containing "consent" is a debit (substring "sent"); a bill reminder is a debit by fallback; `919223008333` is taken as the UTR. Not wired (S-01).

### Low

**L-01.** `src/core/timestamps.py:186-195`: the nanosecond branch is unreachable (values above 1.16e17 hit FILETIME first) and Cocoa seconds in auto mode read as 1992. Failures return the raw number in the UTC and IST fields. Reproduced; not wired.

**L-02.** `PluginRegistry.match_path(None)` raises `AttributeError` on an instance (`parsers/plugin_loader.py:1092`).

**L-03.** `src/provenance/ledger.py` calls its audit table "immutable"; it is an ordinary table with no hash chaining.

## 3. The three known failing tests

**3.1 `test_heuristic_engine_whatsapp_routing_never_flattens`.**
Root cause: the merge changed the import in `parsers/heuristic_engine.py:63-65` from `parsers.chat_social_privacy_parsers.parse_whatsapp_full_forensics` (37 columns, includes `Artifact_ID`) to the function of the same name in `parsers/enterprise_1tb_chat_and_container_engine.py` (28 columns, returns a tuple). The test asserts the 37-column list.
The two schemas share only 10 columns. The case store and the UI use the 28-column one, so the 37-column parsers lose their message body at ingest (C-11).
Recommendation: make the 28-column store schema canonical and extend it with real provenance fields (source file, table, rowid, recovery method). Convert `chat_social_privacy_parsers` and `social_interaction_comms_parsers` to emit it. Keep one WhatsApp parser, and fix H-09 in it. Then change the test to assert the canonical list and real values (body, sender, direction, timestamp), not column presence.

**3.2 `test_match_path_dual_and_keyword_invocations`.**
Root cause: the test calls an instance method on the class. The method is correct as an instance method; the archived `self=None` singleton redirect was a patch to pass this test.
Recommendation: fix the test (remove cases 3-5, or call a module-level `match_path()` backed by a default registry if a convenience is wanted). Add a `None`/empty guard to the method (L-02).

**3.3 `test_signal_ios_96hex_key_and_wal_decryption`.**
Root cause: the fixture, not `src/crypto`. `create_synthetic_sqlcipher_v4_db_and_wal` builds an ordinary database (cells fill the page to byte 4095), sets header byte 20 to 80, and encrypts only bytes 0-4015 of each page. The last 80 bytes of each page are discarded. I confirmed that page 1's only schema cell starts at offset 4009, so the `CREATE TABLE messages` record is cut off; the decrypted output has no schema and the engine returns 0 rows. On page 2 the first three rows (offsets 4015-4069) are also lost.
Recommendation: build the fixture with real reserved bytes (a SQLCipher build, or shift cell content down by 80 bytes inside the test helper, which is what the archived `conftest.py` did globally). Independently, fix M-08, and note H-03 will affect real Signal databases.

## 4. Structural recommendations

- **S-01. Wire the engines or delete them.** Neither `parsers/api_server.py` nor `main.py` imports `src/vfs`, `src/provenance`, `src/sqlite`, `src/upi`, `src/banking`, `src/dlt`, `src/correlator`, `src/crypto`, `src/whatsapp`, `src/legal_and_bsa` or `src/core/timestamps`. The product runs `parsers/` heuristics instead. Pick one stack. The sounder base is `src/` staging and provenance plus a fixed `src/sqlite`, with `parsers/` reduced to app-specific decoders.
- **One implementation per concern.** There are three timestamp converters (`src/core`, `parsers/app_overrides` + `enterprise…`, `ui/shared`), three carvers, two WAL readers, and two Section 63 generators. Keep decoding and reporting in Python; the UI should render what the backend returns.
- **TypeScript engines.** Remove `ui/main` parsers, carvers, VFS and hashing that only `ui/tests` exercise. Remove `loadReferenceGoldenDataset` and other demo data from the shipped bundle.
- **Kebab/snake duplicates.** Keep one of each of the six pairs; the snake files are re-exports (`sec63_bsa_generator.ts` is one line).
- **Two UIs.** Retire the legacy dashboard (`main.py`, `src/workstation_app`); it is the source of C-01 and H-10.
- **Tests.** Add evidence-integrity tests (hash every source file before and after every pipeline), golden tests on real-shaped databases with exact expected values, and a rule that no product module contains sample data.

## 5. Coverage

Reviewed in depth, with reproductions:
- `parsers/api_server.py` (all of it), `parsers/ui_fts5_paginator.py` (ingest, counts, hex window).
- `parsers/heuristic_engine.py` financial path (amounts, direction, de-duplication, carving integration), `parsers/freelist_carver.py`, `parsers/wal_rollback_analyzer.py`, `parsers/app_overrides.normalize_timestamp_value`, `parsers/multi_source_fusion.py` (bank statement and reconciliation).
- `parsers/enterprise_1tb_chat_and_container_engine.py`: container materialisation, timestamp triplet, WhatsApp parser.
- `src/vfs/*`, `src/provenance/hasher.py` and `ledger.py`, `src/core/timestamps.py`, `src/core/sqlite_manager.py`.
- `src/sqlite/*` (varint, record, overflow, header, WAL, journal, carver, engine), `src/crypto/sqlcipher.py`.
- `src/workstation_app/ingestion_pipeline.py`, `src/dlt/sms_grammar.py`, `src/upi/phonepe.py` and `gpay.py`.
- `ui/renderer/state/workbenchStore.ts` (backend mapping, hex), `ui/main/reporting/sec63-bsa-generator.ts`, `Sec63BsaModal.tsx`, `Ncrp1930FreezeModal.tsx`, `ui/shared/forensic-types.ts` `normalizeTimestamp`.
- The three failing tests and the archived `conftest.py`.

Skimmed:
- `parsers/corroboration_engine.py`, `parsers/graph_intelligence.py`, `parsers/chat_social_privacy_parsers.py` (Telegram parser and offset sites only), `parsers/plugin_loader.py`, `parsers/ewf_adapter.py`, `src/financial_graph_and_storyboard/sankey_canvas.py`, merge diffs for the files in brief §3.5 (line counts and the `parsers/` diffs read in full; `src/` diffs only for the carver).

Not reviewed:
- `src/banking`, `src/correlator`, `src/nonsqlite` (LevelDB, MMKV, SEGB, protobuf), `src/telegram_signal`, `src/whatsapp`, `src/legal_and_bsa`, `src/dossier_and_exhibits`, `src/web3`, `src/cex`, `src/seedhunter`, telemetry, geolocation, OCR/KYC and the other `src/` feature modules.
- `parsers/social_interaction_comms_parsers.py`, `commercial_parity_engine.py`, `custodial_wallet_parser.py`, `deep_sqlite.py`, `account_profiler.py`, `vpa_harvester.py`, `keychain_decryptor.py`, `os_privacy_spillover.py`, `protobuf_decoder.py`.
- `electron/`, `tools/forensic_benchmark_recorder.py`, `tests/e2e/`, `ui/tests/`, most React views, and the other `ui/main` engines.
- Test validity was assessed only through the three failing tests and the wiring finding (S-01); I did not audit assertions across the suite.
- E01 handling and real vendor containers (UFDR, XRY, GrayKey) were not exercised; all reproductions used small synthetic inputs.
