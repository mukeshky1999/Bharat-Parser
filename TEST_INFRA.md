# TEST_INFRA.md — 4-Tier Forensic E2E Testing Infrastructure

**Bharat Forensic Suite: Unified Android & iOS Post-Extraction Forensic Suite**  
**Specification Version:** 1.0.0  
**Status:** Comprehensive Opaque-Box & Integration Test Infrastructure Specification  

---

## 1. Architectural Philosophy & Quality Objectives

The Bharat Forensic Suite operates under strict judicial and evidentiary standards governed by the **Bharatiya Sakshya Adhiniyam (BSA) 2023** (Section 63) and the **Bharatiya Nagarik Suraksha Sanhita (BNSS) 2023** (Section 230). In digital forensics, tests cannot merely assert superficial "status == 200" or rely on mock stub implementations. Every assertion must be grounded in an authoritative source of forensic truth:

1. **Deterministic Evidentiary Invariants**: Cryptographic hashes (SHA-256, MD5), byte-exact physical offsets, IEEE 754 financial arithmetic (paisa-exact and milli-rupee integer math), and canonical timezone normalization (UTC + IST `Asia/Kolkata`).
2. **Zero Facades & Zero Mocks**: All test cases exercise real binary decoders, real SQLite engines, real B-Tree/WAL parsers, real cryptographic transformations, and real FastAPI/FTS5 case stores.
3. **Progressive Testability & Isolation**: Tests set up their own isolated state under `.workspace_tmp/`, utilize pre-generated authentic forensic fixtures (`test_evidence/`), and tear down all allocated state cleanly without cross-test contamination.
4. **Adversarial Hardening**: The test suite actively injects damaged B-Tree headers, truncated WAL frames, zero-byte archives, adversarial JSON/protobuf payloads, extreme financial amounts, unallocated binary noise, and anti-forensic clock manipulations.

---

## 2. Systematic 4-Tier Test Architecture

```
                  ┌──────────────────────────────────────────────┐
                  │ Tier 4: Real-World Application Scenarios     │
                  │ Multi-Hop Mule Syndicates, BSA Court Pack    │
                  └──────────────────────┬───────────────────────┘
                                         │
                  ┌──────────────────────▼───────────────────────┐
                  │ Tier 3: Cross-Feature Combinations           │
                  │ Archive -> VFS -> WAL -> Carve -> Heal -> BSA │
                  └──────────────────────┬───────────────────────┘
                                         │
                  ┌──────────────────────▼───────────────────────┐
                  │ Tier 2: Boundary & Corner Cases              │
                  │ Corrupt Headers, Truncated WALs, Floats      │
                  └──────────────────────┬───────────────────────┘
                                         │
                  ┌──────────────────────▼───────────────────────┐
                  │ Tier 1: Feature Coverage (>=5 per feature)   │
                  │ Ingestion, SQLite, UPI, Bank, Chat, Crypto.. │
                  └──────────────────────────────────────────────┘
```

---

## 3. Tier 1: Feature Coverage (>= 5 Tests Per Domain)

Tier 1 validates the primary behavior and interface contracts across the nine core functional domains of the unified forensic suite:

### 3.1 Domain 1: Ingestion Engine (`src/vfs/`, `parsers/enterprise_1tb_chat_and_container_engine.py`)
- **T1.1.1 — UFED Container Ingestion**: Validates parsing of `.ufd`, `.ufdx`, and `.ufdr` containers, extraction of device metadata (IMEI, Serial, OS version), and cross-validation of SHA-256/MD5 hashes against container manifests.
- **T1.1.2 — POSIX & PAX Tar Engine**: Validates zero-extraction indexing of POSIX UStar and PAX extended header archives (>8GB simulation), verifying GNU LongLink name resolution and 64-bit binary sizes.
- **T1.1.3 — ZIP64 Archive Engine**: Validates backward Central Directory scanning, ZIP64 end-of-central-directory locator parsing, extra field `0x0001` 64-bit offsets, and uncompressed stream extraction.
- **T1.1.4 — Android ADB Backup Handler**: Validates Android `AbUnpacker` header calculation (lines 4/9), magic `ANDROID BACKUP` verification, and zlib streaming inflation.
- **T1.1.5 — iOS Logical Backup Handler**: Validates `Manifest.db` querying, Apple binary property list (`bplist00`) decoding, 6-rule domain normalization (`AppDomain-`, `HomeDomain-`), and staging.
- **T1.1.6 — Dual Hashing & Provenance Ledger**: Validates Product A baseline hashing, Product B1 read-only locking, Product B2 working copy staging, and evidentiary ledger insertion.

### 3.2 Domain 2: SQLite Recovery & Storage Forensics (`src/sqlite/`, `parsers/wal_rollback_analyzer.py`, `parsers/freelist_carver.py`)
- **T1.2.1 — 4-State WAL Frame Classification**: Validates classification of WAL frames into `VALID_COMMITTED`, `VALID_UNCOMMITTED`, `CORRUPTED_CHECKSUM`, and `ZERO_PADDED`.
- **T1.2.2 — Rolling Fibonacci WAL Checksum Engine**: Validates calculation of cumulative 64-bit WAL checksum pairs using SQLite's exact rolling checksum algorithm.
- **T1.2.3 — 28-Byte Rollback Journal Decoder**: Validates 28-byte sector header decoding, PERSIST/TRUNCATE offset scanning, and pre-transaction page restoration.
- **T1.2.4 — 4-Zone Freelist & Slack Carver**: Validates scanning of leaf page unallocated spaces, freeblock chains, freelist trunk/leaf pages, and post-EOF residual slack space.
- **T1.2.5 — SQLite Varint & Serial Type Decoder**: Validates variable-length integer parsing (1 to 9 bytes) and record header serial type decoding (integers, IEEE 754 floats, text, blobs, nulls).
- **T1.2.6 — Corrupted SQLite Recovery**: Validates recovery of partially clobbered B-Tree pages with broken cell pointer arrays using sliding window carving.

### 3.3 Domain 3: Indian UPI App Parsers (`src/upi/`, `parsers/app_overrides.py`, `parsers/vpa_harvester.py`)
- **T1.3.1 — PhonePe Forensics & Clock Rollback**: Validates PhonePe Room JSON database parsing, `amountInPaise` to INR conversion, 12-digit UTR extraction, and Transaction ID (`TID`) millisecond timestamp extraction for anti-forensic clock rollback detection.
- **T1.3.2 — Google Pay (Tez) Protobuf Forensics**: Validates decoding of Google Pay Protobuf wire formats, extracting `google.type.Money` (`units` + `nanos`), `amount_micros`, dual-name attribution (sender/receiver), and feed items.
- **T1.3.3 — Paytm Passbook & BHIM UPI**: Validates Paytm SQLite passbook ledger, wallet transactions, saved beneficiaries, MMKV order state decoding, and NPCI BHIM 12-digit numeric UTRs.
- **T1.3.4 — WhatsApp Pay Forensics**: Validates milli-rupee division math (`amount_1000 / 1000.0`), nested `country_data` JSON parsing, and counterparty VPA extraction.
- **T1.3.5 — Universal BharatQR EMVCo Decoder**: Validates recursive Tag-Length-Value (TLV) parsing of EMVCo/NPCI BharatQR strings (Merchant VPA Tag 26/27, Merchant Category Code Tag 52, City Tag 60, PIN code Tag 61).
- **T1.3.6 — CRED Forensics & Substring Disambiguation**: Validates CRED credit card payment parsing while preventing substring collisions between `'cred'` and `"credited"`.

### 3.4 Domain 4: Indian Banking & Financial Ecosystem (`src/banking/`, `parsers/multi_source_fusion.py`)
- **T1.4.1 — PSU & Private Bank CBS Narration Parser**: Validates Core Banking System (CBS) narration parsing for SBI, HDFC, ICICI, Axis, Kotak, extracting mode (`UPI/NEFT/IMPS/RTGS`), counterparty name, VPA, and 12-digit UTR.
- **T1.4.2 — Offline 40+ Bank IFSC Directory Resolver**: Validates resolution of 40+ Indian bank IFSC prefix codes to bank names, branch locations, and clearing types without external network requests.
- **T1.4.3 — AePS Biometric Cashout & RD Service Telemetry**: Validates Aadhaar-enabled Payment System (AePS) agent app decoding, Biometric Registered Device (RD) service logs, Aadhaar masks, and terminal cashout events.
- **T1.4.4 — Deterministic Bank Statement Password Unlocker**: Validates automated decryption of password-protected PDF bank statements using deterministic Indian forensic masks (PAN + DOB, Name + Mobile, Account Number).
- **T1.4.5 — Cardless ATM Cashout Runner Correlator**: Validates cross-referencing OTP requests, cardless cashout tokens (SBI YONO Cash, ICICI Cardless), and ATM GPS coordinates.

### 3.5 Domain 5: Truecaller & Telephony Forensics (`src/unified_chat/truecaller_decoder.py`, `parsers/social_interaction_comms_parsers.py`)
- **T1.5.1 — Truecaller Caller ID & Profile Cache**: Validates extraction of cached names, spam scores, spam categories, national format numbers, and email identities from `tc.db`.
- **T1.5.2 — Truecaller IM & SMS Decoder**: Validates extraction of peer-to-peer instant messages, SMS mirror threads, media attachments, and message delivery statuses from `msg.db`.
- **T1.5.3 — Spam & Syndicate Role Classifier**: Validates classification of contacts into spam categories (telemarketer, scammer, loan shark, mule recruiter) based on Truecaller score thresholds.
- **T1.5.4 — Unified Call Log & Truecaller Fusion**: Validates enrichment of native Android/iOS call history records with Truecaller caller ID identities.
- **T1.5.5 — Truecaller Freelist Carving**: Validates recovery of deleted search queries and looked-up phone numbers from SQLite page freelists.

### 3.6 Domain 6: Instant Messaging & Regional Social (`src/whatsapp/`, `src/telegram_signal/`, `parsers/chat_social_privacy_parsers.py`)
- **T1.6.1 — WhatsApp Message Recovery & WAL Carving**: Validates extraction of active and deleted WhatsApp messages from `msgstore.db` and dirty `msgstore.db-wal`.
- **T1.6.2 — WhatsApp Crypt14/Crypt15 Decryption & Diffing**: Validates cryptographic decryption of WhatsApp encrypted backup files and rolling backup differential recovery.
- **T1.6.3 — Telegram `cache4.db` & TL Binary Deserializer**: Validates extraction of secret chats, peer channels, user IDs, and binary Type-Language (TL) schema deserialization.
- **T1.6.4 — Signal Messenger Decryption**: Validates decryption and extraction of Signal encrypted messages, recipient identities, and attachment digests.
- **T1.6.5 — Regional & High-OpSec Social Messengers**: Validates parsers for ShareChat, Moj, Session, SimpleX, and Instagram Direct threads.

### 3.7 Domain 7: Crypto Exchanges & Web3 Wallets (`src/cex/`, `src/web3/`, `src/seedhunter/`, `parsers/custodial_wallet_parser.py`)
- **T1.7.1 — Custodial Crypto Exchange Ledger**: Validates order book, deposit, and withdrawal parsing across 15 custodial exchanges (Binance, Bybit, CoinDCX, WazirX, CoinSwitch).
- **T1.7.2 — FIU-IND Domestic Registered Exchanges**: Validates compliance ledger extraction for domestic Indian FIU-IND reporting entities.
- **T1.7.3 — Binance & Bybit P2P Escrow Extraction**: Validates peer-to-peer escrow trades, INR bank account linkages, counterparty nicknames, and chat logs.
- **T1.7.4 — TronLink TRC-20 USDT Decoders**: Validates decoding of TRC-20 transfer parameters (smart contract address, recipient base58 address, 6-decimal USDT conversion).
- **T1.7.5 — BIP-39 2048-Word Seed Hunter & HD Derivator**: Validates byte-level scanning of raw memory/storage for BIP-39 mnemonic phrases and hierarchical deterministic (HD) address derivation (m/44'/60'/0'/0, m/84'/0'/0'/0).

### 3.8 Domain 8: FastAPI Backend & Forensic UI Bridge (`parsers/api_server.py`, `parsers/ui_fts5_paginator.py`)
- **T1.8.1 — Case Ingestion Endpoint (`POST /api/case/ingest`)**: Validates intake of forensic containers, streaming progress tracking, and concurrency locking (409 on overlap).
- **T1.8.2 — Project Category Tree Counts (`GET /api/case/tree-counts`)**: Validates real-time category counts across the 18 canonical forensic groups.
- **T1.8.3 — Paginated Artifact Query (`GET /api/artifacts/query`)**: Validates pagination, category filtering, timestamp range sorting, and FTS5 lexical/trigram full-text search.
- **T1.8.4 — Synced Hex Window Inspector (`GET /api/inspector/hex`)**: Validates windowed 4KB hex/ASCII byte chunk extraction around a physical offset with path traversal defense (403 on traversal).
- **T1.8.5 — Conversation Thread Inspector (`GET /api/chats/thread`)**: Validates chronological chat message aggregation with recovery status tags.
- **T1.8.6 — Mule Syndicate Link Graph (`GET /api/graph/mule-network`)**: Validates NetworkX node/edge payload generation for force-directed link graph visualization.

### 3.9 Domain 9: Statutory Court Reporting & Evidence Integrity (`src/legal_and_bsa/`, `parsers/api_server.py`)
- **T1.9.1 — Section 63 BSA 2023 Statutory Certificate**: Validates automated generation of Section 63(4)(c) Bharatiya Sakshya Adhiniyam certificate with cryptographic system hashes and condition statements.
- **T1.9.2 — Section 230 BNSS Defense Disclosure Pack**: Validates generation of Section 230 Bharatiya Nagarik Suraksha Sanhita disclosure copies with judicial inspection cards and victim safeguard redaction.
- **T1.9.3 — 1930 NCRP Bank Freeze Requisition Cart**: Validates compilation of immediate bank freeze requisitions for National Cyber Crime Reporting Portal (NCRP) submission.
- **T1.9.4 — Dual SHA-256 Evidentiary Ledger**: Validates immutable append-only ledger recording every file origin, offset, extraction tool, and cryptographic hash.
- **T1.9.5 — Merkle Audit Hash Tree**: Validates Merkle tree root hash calculation over all parsed artifacts to detect any post-analysis data tampering.

---

## 4. Tier 2: Boundary & Corner Cases

Tier 2 tests system resilience under hostile inputs, malformed structures, extreme numeric ranges, and edge-condition boundary boundaries:

- **T2.1 — Corrupted SQLite Headers**: Databases with corrupted magic bytes (`SQLite format 3\000`), invalid page sizes (non-power-of-two, <512, >65536), or unallocated freelist cycle pointers.
- **T2.2 — Truncated WAL Frame Files**: WAL files abruptly truncated in the middle of a transaction frame header, incomplete commit frames, and salt mismatches.
- **T2.3 — Zero-Byte and Empty Container Archives**: Empty `.tar`, zero-byte `.zip`, and `.ab` files with missing payloads, asserting graceful failure without unhandled exceptions.
- **T2.4 — Extreme Financial Amounts**: Edge transaction amounts: ₹0.00, ₹0.01 (1 paisa), ₹99,99,99,999.99 (crores), floating-point precision hazards (`0.1 + 0.2 != 0.3`), and negative chargebacks.
- **T2.5 — Unallocated Disk Space Noise & Sliding Window**: 50MB raw disk image (`test_disk.dd`) containing pseudorandom noise with embedded fragments, asserting zero false-positive table detections in random byte streams.
- **T2.6 — Missing Encryption Salts & Broken JSON/Protobuf**: Corrupted MMKV payload buffers, truncated protobuf varints, broken UTF-8 surrogates, and malformed JSON in Room database columns.
- **T2.7 — TRAI DLT Substring Collision ("cred" vs "credited")**: SMS messages containing words like `"accredited"`, `"incredible"`, or `"credited"` asserting zero false-positive matches for the CRED application.
- **T2.8 — Clock Gap Anomalies & Anti-Forensics**: Extraction artifacts with modified timestamps jumping backward in time (anti-forensic time travel), detecting deliberate device clock rollback.

---

## 5. Tier 3: Cross-Feature Combinations

Tier 3 exercises multi-engine pipelines from raw extraction containers to finalized statutory court reports:

### Pipeline 3.1: Raw Archive -> VFS -> SQLite WAL -> UPI Parser -> Corroborator -> Case Store -> BSA Export
```
[Tar/Zip Archive]
       │
       ▼ (Zero-Extraction Indexing)
[VFS Engine & Normalizer]
       │
       ▼ (Product B1/B2 Staging)
[Staged SQLite + Dirty WAL]
       │
       ▼ (4-State Classification & Rollback Analysis)
[Recovered SQLite Transactions]
       │
       ▼ (PhonePe & GPay Domain Parsers)
[Raw Financial Records]
       │
       ▼ (Cross-App UTR & Counterparty Healing)
[Corroboration Engine]
       │
       ▼ (FTS5 Lexical/Trigram Virtual Tables)
[CaseUIPaginatorStore]
       │
       ▼ (Section 63 Statutory Generator)
[Section 63 BSA 2023 Certificate & Merkle Audit Trail]
```

### Pipeline 3.2: Logical Extraction -> VFS Reader -> Freelist Carver -> WhatsApp Recovery -> FTS5 Chat Thread -> Hex Inspector
Validates extracting deleted WhatsApp messages from unallocated leaf page slack, inserting into FTS5 paginated store, querying conversational thread, and extracting physical 4KB hex/ASCII window from byte offsets.

### Pipeline 3.3: Multi-Source Fusion -> SMS DLT Harvester + UPI Ledger -> Counterparty Healer -> Myers Redline Diff -> Section 230 BNSS Package
Validates ingesting split-table SMS alerts, correlating with UPI transactions via 12-digit UTR, healing missing receiver VPAs, computing redline diffs, and exporting Section 230 BNSS defense disclosure packages.

---

## 6. Tier 4: Real-World Application Scenarios

Tier 4 simulates complex real-world forensic investigations encountered by law enforcement and statutory examiners:

### Scenario 4.1: Multi-Hop Money Mule Syndicate Investigation
- **Simulation**:
  1. Primary Victim initiates ₹1,00,000 fraud payment via Google Pay to Mule VPA `mule_entry@okaxis`.
  2. Mule 1 splits funds: ₹45,000 sent via PhonePe to Mule 2 VPA `layer2_mule@ybl` (UTR `630911223344`).
  3. Mule 2 moves ₹45,000 via SBI YONO CBS IMPS transfer to P2P merchant bank account.
  4. P2P merchant releases 500 USDT on Binance P2P escrow (Order `#BNB982341209`).
  5. USDT transferred on Tron blockchain to external TRC-20 wallet `TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf`.
- **Forensic Verification**:
  * Unified pipeline reconstructs the 5-hop chain across 5 disparate applications.
  * UTR correlator matches Bank CBS narration with PhonePe UTR.
  * Link graph classifies nodes: Victim (Source), Mule 1 (Layer 1 Mule), Mule 2 (Layer 2 Mule), P2P Merchant (Onramp), Tron Wallet (Cashout Destination).
  * 1930 NCRP Freeze Requisition correctly locks Mule 1 and Mule 2 bank accounts while protecting Victim account with safeguard lock.

### Scenario 4.2: Dirty Acquisition Cross-App Healing & UTR Reconciliation
- **Simulation**:
  1. Device extraction contains incomplete PhonePe database where transaction table recorded amount and UTR but receiver VPA was nullified due to app crash/corruption.
  2. Device SMS inbox contains DLT bank alert: `"AD-HDFCBK: Rs 15,000.00 debited for UPI to priya88@okhdfcbank Ref 839201948201"`.
  3. Device Google Pay database contains cached contact entry for `priya88@okhdfcbank` with display name `"Priya Sharma"`.
- **Forensic Verification**:
  * Cross-app corroboration engine links the orphan PhonePe record to the SMS alert via UTR `839201948201`.
  * Counterparty healer auto-populates receiver VPA `priya88@okhdfcbank` and receiver name `"Priya Sharma"`.
  * Confidence score is calibrated (Healed: Level 5).

### Scenario 4.3: Anti-Forensics Tampering Audit & Section 63 BSA 2023 Statutory Export
- **Simulation**:
  1. Suspect rolled back device clock by 3 days before deleting WhatsApp and PhonePe evidence.
  2. Sideloaded malicious APK (`com.fake.anydesk.trojan`) detected in `/data/app/`.
  3. Freelist carver recovers 15 deleted secret messages and transactions.
- **Forensic Verification**:
  * Clock gap auditor detects discrepancy between PhonePe `TID` timestamp and SQLite metadata timestamp.
  * Sideloaded APK auditor flags remote-access trojan permissions.
  * Section 63 BSA generator auto-drafts Section 63(2)(c) anomaly compensation paragraphs documenting clock rollback and recovered slack space records.
  * Output certificate is fully court-admissible with Merkle root hash.

---

## 7. Authoritative Sources of Expected Outputs

| Domain / Test | Input | Authoritative Truth Oracle |
|---|---|---|
| **Hashing** | Container / file byte stream | NIST FIPS 180-4 SHA-256 standard via Python `hashlib.sha256()` |
| **Tar / Zip** | Archive binary headers | POSIX.1-2001 (IEEE Std 1003.1) / PKWARE ZIP Appnote 6.3.4 |
| **SQLite WAL** | WAL binary frames | SQLite 3.x WAL Specification & Fibonacci Checksum Math |
| **Varint Decoding** | 1-9 byte binary sequences | SQLite Record Format Specification Section 2.1 |
| **PhonePe TID** | 35-character alphanumeric TID | PhonePe Timestamp Epoch Decoder: `int(TID[2:15]) / 1000.0` |
| **GPay Money** | Protobuf wire format | Google Protocol Buffers `google.type.Money` spec |
| **WhatsApp Pay** | Integer `amount_1000` | NPCI / WhatsApp Pay decimal specification: `amount_1000 / 1000.0` |
| **BharatQR** | EMVCo TLV string | EMVCo Merchant-Presented QR Code Specification v1.1 |
| **IFSC Resolution** | 11-character IFSC code | RBI National Clearing Cell Directory of Bank Branch Codes |
| **BSA Certification** | Evidence Ledger & Artifacts | Bharatiya Sakshya Adhiniyam 2023, Section 63 Schedule Format |

---

## 8. Test Execution Commands

```bash
# Execute entire E2E test suite across all 4 tiers
python tests/e2e/runner.py --tier all

# Execute specific tiers
python tests/e2e/runner.py --tier 1
python tests/e2e/runner.py --tier 2
python tests/e2e/runner.py --tier 3
python tests/e2e/runner.py --tier 4

# Run with pytest
python -m pytest tests/e2e/ -v

# Verify compilation of all test modules
python -m py_compile tests/e2e/*.py
```
