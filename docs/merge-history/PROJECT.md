# Project: Bharat Forensic Suite (Unified Android & iOS Post-Extraction Suite)

## Architecture
A production-ready Android & iOS Post-Extraction Mobile Forensic Suite tailored for the Indian ecosystem, unifying the deep mathematical decoders and statutory compliance of `Bharart Analyzer` with the commercial-grade Electron + React 19 workbench and high-performance FTS5 case store of `bharat-pa-forensics`.

- **Frontend Desktop Shell**: Electron 45 + React 19 + TypeScript + Vite + Tailwind CSS v4 (`src/renderer/`, `electron/`).
- **Backend REST Engine**: Python 3.10+ FastAPI on `http://127.0.0.1:8000` (`parsers/api_server.py`) with `CaseUIPaginatorStore` (28-column Physical Analyzer schema + SQLite FTS5 virtual tables + mmap hex window).
- **Core Ingestion & Recovery**: Zero-extraction streaming VFS (`src/vfs/`), 4-state SQLite WAL recovery + time-travel diffing (`src/sqlite/wal.py`, `parsers/wal_rollback_analyzer.py`), 28-byte rollback journal recovery (`src/sqlite/journal.py`), 4-zone residual carver (`src/sqlite/carver.py`, `parsers/freelist_carver.py`), binary LevelDB decoder (`src/nonsqlite/leveldb.py`), MMKV (`src/nonsqlite/mmkv.py`), and SHA-256 dual hashing with Product A/B staging (`src/provenance/hasher.py`, `ledger.py`).
- **Indian Ecosystem Parsers**: 42+ app manifests and domain sub-engines covering UPI (PhonePe, GPay, Paytm, BHIM, CRED, WhatsApp Pay), 15+ domestic/corporate banking apps & AePS agent apps, Truecaller, regional & privacy chats, Indian quick-commerce & mobility (Swiggy, Zomato, Blinkit, Zepto, Uber, Ola, Rapido, IRCTC, Where is My Train, DigiYatra), 15 custodial crypto exchanges + FIU-IND domestic exchanges + Web3 + BIP-39 Seed Hunter, and system core artifacts.
- **Corroboration & Graph Intelligence**: Cross-app counterparty and UTR healer (`parsers/corroboration_engine.py`), 4-way UTR correlator (`src/correlator/engine.py`), Myers redline diffing, 4-stage SVG Sankey money trail, and NetworkX mule syndicate graph.
- **Statutory Court Compliance**: Section 63 BSA 2023 / Section 65B IEA certificate generator, Section 230 BNSS defense disclosure copy with judicial inspection cards, and 1930 NCRP bank freeze requisition manager with victim safeguard lock.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | MERGE_STATE.md Audit & Tracking | File-by-file merge checklist, audit comparison, tracking completed/pending | M1 | Survey / R1 |
| 2 | Clean Repository Structure | Unified directory structure ignoring .venv, node_modules, .git, etc. | M1 | Survey / R1 |
| 3 | UFED Ingestion & Hash Cross-Check | .ufd, .ufdx, .ufdr container parsing, ET.iterparse report.xml streaming, hash validation | M2 | Survey / R2 |
| 4 | Tar Archive Engine (>8GB) | POSIX UStar, PAX extended headers, GNU LongLinks, 64-bit binary sizes | M2 | Survey / R2 |
| 5 | Zip Archive Engine (ZIP64) | Central directory backward scan, ZIP64 locator, extra field 0x0001, memory streaming | M2 | Survey / R2 |
| 6 | Android ADB Backup Handler | AbUnpacker header calculation (lines 4/9), zlib streaming payload | M2 | Survey / R2 |
| 7 | iOS Backup Handler | Manifest.db querying, binary plist size extraction, 6-rule domain normalizer, keychain-2.db | M2 | Survey / R2 |
| 8 | SQLite 4-State WAL & Time-Travel | 4-state classification, rolling Fibonacci checksums, historical multi-revision diffing | M2 | Survey / R2 |
| 9 | SQLite Rollback Journal Decoder | 28-byte sector decoding, PERSIST/TRUNCATE offset scan, pre-transaction page restore | M2 | Survey / R2 |
| 10 | 4-Zone Freelist & Slack Carver | In-page freeblock reverse serial alignment, unallocated gaps, Indian VPA/UTR/Amount filters | M2 | Survey / R2 |
| 11 | Plist Readers | Native XML and Apple binary bplist00 decoder | M2 | Survey / R2 |
| 12 | Binary LevelDB Parser | .log 32KB blocks, WriteBatch, .ldb/.sst footers, pure Snappy decompression, tombstones | M2 | Survey / R2 |
| 13 | SHA-256 Dual Hashing & Provenance | Product A baseline, Product B1 read-only lock, Product B2 staging, deterministic manifest | M2 | Survey / R2 |
| 14 | PhonePe UPI Forensics | TID timestamp extraction (clock rollback detection), Bullhorn chats, scanned VPA cache | M3 | Survey / R3 |
| 15 | Google Pay (Tez) Forensics | Protobuf units+nanos, amount_micros, dual-name attribution, feed items | M3 | Survey / R3 |
| 16 | Paytm & BHIM UPI Forensics | Passbook ledger, wallet transactions, saved beneficiaries, MMKV order states, 12-digit UTR | M3 | Survey / R3 |
| 17 | CRED & Substring Disambiguation | Resolves 'cred' vs 'credited' collision, cashflow ledger, credit card payments | M3 | Survey / R3 |
| 18 | WhatsApp Pay Forensics | Milli-rupee math (amount_1000/1000.0), extra_data/country_data JSON VPA/UTR parsing | M3 | Survey / R3 |
| 19 | Indian Banking & AePS Parsers | PSU/private banks (SBI, HDFC, ICICI, Axis, Kotak, etc.), CBS narration parser, IFSC resolver | M3 | Survey / R3 |
| 20 | Truecaller Forensics | tc.db caller ID & search cache, msg.db IM/SMS/Flash messages, spam tags | M3 | Survey / R3 |
| 21 | Instant Messaging & Social Parsers | WhatsApp (crypt14/15 + WAL carver), Telegram (cache4.db + TL), Signal, ShareChat, Moj, Instagram | M3 | Survey / R3 |
| 22 | Quick-Commerce & Mobility Parsers | Swiggy, Zomato, Blinkit, Zepto, Uber, Ola, Rapido, IRCTC, Where is My Train, DigiYatra | M3 | Survey / R3 |
| 23 | Crypto Wallets & P2P Escrow | 15 custodial exchanges, FIU-IND domestic exchanges, Binance/Bybit P2P, TronLink, BIP-39 | M3 | Survey / R3 |
| 24 | Core System Artifacts & Anti-Forensics | Call logs, SMS DLT grammar, Contacts, Chrome/Safari, APK trojan auditor, Clock gap audit | M3 | Survey / R3 |
| 25 | Corroboration & Counterparty Healing | Cross-app VPA/Name counterparty auto-population via UTR/Amount correlation | M3 | Survey / R3 |
| 26 | Standardized PA 28-Column Schema | Unification of all extracted records into CaseUIPaginatorStore and 18 Forensic Groups | M3 | Survey / R3 |
| 27 | FastAPI REST Backend Server | Fast endpoints for case ingest, tree counts, paginated records, hex inspector, BSA report | M4 | Survey / R4 |
| 28 | Electron & React 19 UI Workbench | Cellebrite PA layout: Top Ribbon, Category Tree, Multi-Tab Canvas, 5D Inspector, Synced Hex | M4 | Survey / R4 |
| 29 | Case Manager & Ingestion Modal | Native OS file/folder pickers, multi-format container intake, live progress stream | M4 | Survey / R4 |
| 30 | Synced 3-Pane Hex & SQLite Wizard | Address/Hex/ASCII panes, cell provenance auto-scroll, database schema & row explorer | M4 | Survey / R4 |
| 31 | Indian Artifact Inspector Views | Dedicated views for UPI Master Ledger, Bank CDR Fusion, Chats Master, Crypto, APKs | M4 | Survey / R4 |
| 32 | Timeline & Mule Link Graph | NetworkX/PyVis force-directed graph, syndicate role classifier, chargesheet chain tracer | M4 | Survey / R4 |
| 33 | Advanced Visual & Forensic Engines | Myers redline diffing, 4-stage SVG Sankey money trail, bilingual Devanagari OCR studio | M4 | Survey / R4 |
| 34 | Court-Admissible BSA Generator | Section 63 BSA 2023 certificate, Sec 230 BNSS defense copy, 1930 NCRP bank freeze cart | M4 | Survey / R4 |
| 35 | End-to-End Test Suite (Tiers 1-4) | Comprehensive opaque-box and integration test suite across all features | M5 / Test | Survey / AC |
| 36 | 100% Complete Implementation | Zero placeholder/truncation comments, zero stubs, py_compile & UI build verification | M5 | Survey / R5 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Repository Audit & State Setup | Audit catalog, create MERGE_STATE.md, establish clean target repository structure | none | DONE |
| M2 | Core Forensic Ingestion Engine | Merge UFED, Tar, Zip64, ADB, iOS, 4-state WAL, journal, freelist, LevelDB, SHA-256 | M1 | DONE |
| M3 | Indian App Parsers Standardized | Merge all UPI, banking, Truecaller, chat, shopping, crypto, system parsers & corroboration | M2 | DONE |
| M4 | API Bridge & Forensic UI | Wire FastAPI backend to Electron/React 19 UI with all inspectors, viewers, reports | M3 | DONE |
| M5 | E2E Testing & System Verification | Pass 100% E2E test suite, verify zero truncation/stubs, boot application end-to-end | M4 | DONE |

## Interface Contracts
### Ingestion Engine (`src/vfs/`, `src/sqlite/`, `src/nonsqlite/`) ↔ Parser Sub-engines (`parsers/`, `src/upi/`, etc.)
- Ingestion engine delivers indexed file streams (`vfs_open_memory_stream`) and staged SQLite families (`StagedSQLiteFamily`: base DB, -wal, -journal locked read-only Product B1 + writable Product B2).
- Low-level carvers deliver structured `CarvedRecord` instances with page number, cell offset, varint column types, raw byte slices, and confidence scores (1-6).

### Parsers ↔ Case Storage & API Server (`parsers/ui_fts5_paginator.py`, `parsers/api_server.py`)
- Parsers emit records conforming to the 28-column PA Categorized Schema:
  `case_id, evidence_id, artifact_id, app_name, package_id, category, subcategory, timestamp_raw, timestamp_utc, timestamp_ist, source_file, physical_offset, recovery_status, direction, sender_id, sender_name, receiver_id, receiver_name, amount, currency, utr_or_ref, status, description, message_text, media_path, raw_json, confidence_score, audit_hash`.
- `CaseUIPaginatorStore` bulk inserts records into SQLite with FTS5 lexical/trigram indexing, updating live tree category counts.

### API Server (`parsers/api_server.py`) ↔ Frontend Client (`src/renderer/api/forensicClient.ts`)
- REST Endpoints on `http://127.0.0.1:8000`:
  * `POST /api/case/ingest`: Trigger extraction ingestion with streaming step events.
  * `GET /api/case/tree-counts`: Returns live counts per category for the Category Tree dock.
  * `GET /api/artifacts/query`: Paginated query (page, page_size, category, search_query, date_range, sort_by).
  * `GET /api/inspector/hex`: Returns windowed 4KB hex/ASCII chunk around physical byte offset.
  * `GET /api/chats/thread`: Returns chronological conversation messages with recovery tags.
  * `GET /api/graph/mule-network`: Returns NetworkX node/edge payload for Link Graph.
  * `POST /api/report/sec63-bsa`: Generates Section 63 BSA 2023 statutory certificates.
  * `POST /api/report/sec230-bnss`: Generates Section 230 BNSS defense disclosure packages with victim safeguards.

## Code Layout
- `E:\v8\combined\`: Unified Project Root
  - `MERGE_STATE.md`: Authoritative merge tracking document (M1 COMPLETE, M2 COMPLETE)
  - `package.json`, `vite.config.ts`, `tsconfig.json`, `tailwind.config.js`: UI build configuration
  - `electron/`: Electron desktop lifecycle shell (`main.cjs`, `preload.cjs`)
  - `src/renderer/`: React 19 UI desktop workbench (views, workspace, inspectors, components, state)
  - `parsers/`: Python backend parsers, manifests, FTS5 paginator, API server, and corroboration engine
  - `src/`: Deep forensic core engines (vfs, sqlite, nonsqlite, upi, banking, legal_and_bsa, etc.)
  - `tests/`: Comprehensive test suite (ingestion, parsers, bridge, E2E tests)
  - `test_evidence/`: Test dumps, mock databases, and extraction fixtures
