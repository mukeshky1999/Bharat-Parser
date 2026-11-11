# Review Brief: Bharat Forensic Suite (post-merge)

Prepared 2026-11-11, after the merge cleanup. Read `README.md` first for layout and commands.

## 1. What this software does and why correctness matters

This is post-extraction analysis software, in the same category as Physical Analyzer, XRY and
Oxygen. It reads already-acquired Android/iOS extractions (ZIP/TAR/iOS backup/raw images),
recovers and decodes app data, and produces reports intended for Indian legal proceedings
(Section 63 BSA 2023 certificates, BNSS Sec 230, NCRP 1930 freeze requests).

For a forensic tool, these failures are worse than a crash:

- **Silent wrong output**: wrong timestamp, wrong counterparty, wrong direction, a merged or
  dropped record, a "recovered" record that was never on the device.
- **Evidence mutation**: any write to source evidence, or a hash computed over something other
  than the bytes actually read.
- **Swallowed errors**: `except Exception: pass` that turns a parse failure into "no data".
- **Overclaiming**: confidence, provenance or "verified" labels the code does not earn.

## 2. Known current failures (from the root, `pytest tests --ignore=tests/e2e`)

364 passed, 3 failed:

1. `tests/test_phase6_7.py::TestHeuristicEngineCategorizedRouting::test_heuristic_engine_whatsapp_routing_never_flattens`
   **Merge regression.** It passes against the archived bharat-pa-forensics. The merged
   `parsers/chat_social_privacy_parsers.py` (~line 1769) and `parsers/heuristic_engine.py`
   (~line 1461) now fall through to `parsers/enterprise_1tb_chat_and_container_engine.parse_whatsapp_full_forensics`,
   which returns a different column schema (no `Artifact_ID`, etc.). Decide which WhatsApp
   chat schema is canonical, then make one parser authoritative.
2. `tests/test_phase6_7.py::TestPluginRegistryCompleteness::test_match_path_dual_and_keyword_invocations`
   The test calls `PluginRegistry.match_path(path)` on the class. The archived original "fixed"
   this by making instance methods accept `self=None` and redirect to a singleton. That hack was
   deliberately **not** ported. Either the test is wrong, or the API should expose a proper
   classmethod/module function.
3. `tests/test_phase2_module2_2_crypto.py::test_signal_ios_96hex_key_and_wal_decryption`
   Decryption reports success but yields 0 message rows. In the original project this passed
   only because its `conftest.py` monkeypatched the SQLCipher fixture generator, `sqlite3.connect`
   and `cryptography`'s AES key wrap (see §3.1). Determine whether the bug is in the fixture or in
   `src/crypto/` (reserved-bytes / page-offset handling).

## 3. Red flags already spotted (verify, then judge)

1. **Test-environment monkeypatching** (archived `Bharart Analyzer/conftest.py`, not carried over):
   it replaced `sqlite3.connect` with a WAL-preserving connection, filtered
   `CREATE TABLE sqlite_sequence`, padded 16-byte keys before `aes_key_wrap`, and replaced a
   SQLCipher fixture builder. Any test that only passed under those patches is not evidence the
   product works. The root `tests/conftest.py` keeps only a benign `zipfile` ZIP64 fixture patch.
2. **Patch-to-pass pattern**: the `self=None` registry hack above. Look for similar shapes
   elsewhere: broad `try/except` fallbacks, "if test path then …" branches, results shaped to
   satisfy assertions.
3. **Two parallel implementations** of the same domains:
   - Python `src/` + `parsers/` vs TypeScript `ui/main/` (UPI parsers, carvers, VFS, hashing,
     BSA report). The UI imports `ui/main/case_manager/case_db` and
     `ui/main/reporting/sec63_bsa_generator`, so some reporting runs in TypeScript, separate
     from the Python engines. They can disagree.
   - Six kebab/snake duplicate folder pairs in `ui/main/`: `case-manager`/`case_manager`,
     `hash-guard`/`hash_guard`, `parsers/indian-banking`/`indian_banking`,
     `parsers/indian-upi`/`indian_upi`, `parsers/cybercrime`/`cybercrime_apps`,
     `reporting/sec63-bsa-generator.ts`/`sec63_bsa_generator.ts`.
   - Two UIs: Electron+React (`parsers/api_server.py`) and the legacy dashboard
     (`main.py` → `src/workstation_app`).
4. **Overclaiming text in code and output**: `tests/e2e/runner.py` prints "Ready for Court
   Production Certification". The docs in `docs/merge-history/` claim "100% COMPLETE — PRODUCTION
   READY & COURT ADMISSIBLE".
5. **Merge-time edits to core decoders** (root is newer than both originals). These deserve
   careful diff review against the archive:
   `src/core/timestamps.py` (116 → 223 lines), `src/vfs/indexer.py` (535 → 695),
   `src/sqlite/carver.py`, `src/sqlite/overflow.py`, `src/sqlite/varint.py`, `src/sqlite/wal.py`,
   `src/nonsqlite/leveldb.py`, `src/correlator/utr_validator.py`, `src/upi/{gpay,paytm,phonepe,whatsapp_pay}.py`,
   `src/telegram_signal/tl_deserializer.py`, `src/web3/tronlink.py`, `src/cex/indian_cex.py`,
   `parsers/{heuristic_engine,chat_social_privacy_parsers,enterprise_1tb_chat_and_container_engine,vpa_harvester,__init__}.py`.
   Original copies: `E:\v8\_archive\combined_originals_2026-11-11\{Bharart Analyzer\src, bharat-pa-forensics\parsers}`.

## 4. Review priorities (about 100k lines; go deep, in this order)

1. **Evidence integrity**: `src/vfs/`, `src/provenance/`, read-only/staging logic, hashing,
   `parsers/api_server.py` file access (path traversal, the hex-window endpoint, what it binds
   to), anything that writes near evidence.
2. **Low-level recovery correctness**: `src/sqlite/` (varint, overflow, WAL, journal, freelist and
   carver), `parsers/freelist_carver.py`, `parsers/wal_rollback_analyzer.py`, `src/nonsqlite/`.
   Check bounds, off-by-one errors, page-size and reserved-bytes handling, and false-positive
   carving.
3. **Time**: `src/core/timestamps.py` and every epoch conversion (Unix s/ms/µs, Apple Cocoa,
   WebKit, .NET ticks), plus IST/UTC handling. A wrong timestamp is the most common silent
   forensic error.
4. **Financial attribution**: `src/upi/`, `src/banking/`, `src/dlt/`, `src/correlator/`, and the
   counterparty/VPA logic in `parsers/heuristic_engine.py` (§2.1). Check direction, amount
   parsing, UTR validation, and cross-app "healing" that might invent links.
5. **Messengers**: WhatsApp/Telegram/Signal decoders and the schema split in §2.1.
6. **Reporting / legal output**: `src/legal_and_bsa/`, `src/dossier_and_exhibits/`,
   `ui/main/reporting/`. What does the certificate assert, and is each assertion backed by data?
7. **Test validity**: are fixtures realistic, and do the assertions check real values or just
   "not empty"?

## 5. Out of scope / noise

`node_modules/`, `.venv/`, `dist/`, `scratch/` (runtime case stores), `.workspace_tmp/`,
`docs/merge-history/` (historical claims, not status), `test_evidence/` binaries (read-only fixtures).

## 6. Expected output

A findings list ranked by severity. Each finding gives file:line, what is wrong, a concrete
input that triggers it, the forensic consequence, and a suggested fix. Separate **confirmed**
findings (reproduced or proven from code) from **suspected** ones. Don't modify source or fixtures
during the review pass.
