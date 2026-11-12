# BharatAnalyzer Sovereign Forensics Suite — Complete Capabilities & Supported Apps Matrix (`abilities.md`)

> **Version:** 2.0.0 (Unified Post-Merger Build) | **Operating Mode:** 100% Air-Gapped Offline | **Target Jurisdictions:** Indian Cyber-Financial Ecosystem (NPCI/RBI/TRAI/UIDAI/BSA 2023/BNSS 2023) + Global High-OpSec & Web3

This document catalogs every application, operating system artifact, extraction container, binary wire protocol, database format, cryptographic scheme, analytical correlation engine, interactive UI workbench feature, and statutory courtroom deliverable supported by the merged suite inside `E:\v8\combined`.

---

## 1. HIGH-LEVEL CAPABILITY FOOTPRINT

| Capability Dimension | Merged Coverage | Primary Modules |
| :--- | :--- | :--- |
| **Registered App Plugin Manifests** | **80 App Plugins** across UPI, Banking, Crypto, Chat, Privacy, Social, and Dating | `parsers/plugin_loader.py` (`PluginRegistry`) |
| **Extended Banking, Corporate, AePS & RD Apps** | **35+ Banking/Corporate/AePS/RD Sandboxes** + **150,000+ RBI IFSC branch lookup** | `src/banking/`, `parsers/app_overrides.py` |
| **Custodial Crypto Wallets & Exchanges** | **15 Tier-1/Tier-2 Custodial Wallets** (7 data classes) + **7 Web3 Self-Custody** + **7 Indian CEX** | `parsers/custodial_wallet_parser.py`, `src/web3/`, `src/cex/` |
| **Social, VoIP, Burners & Regional Apps** | **15 Social/Cross-Border Manifests** + **13 Dating/Matrimonial** + **Covert Dead-Drops & Betting** | `parsers/social_interaction_comms_parsers.py`, `src/social_voip/`, `src/unified_chat/`, `src/hyperlocal_travel/` |
| **Hyperlocal Delivery, Mobility & Travel** | **19 Indian Commerce, Ride-Hailing, Rail & Aviation platforms** | `src/hyperlocal_travel/` |
| **Core Forensic Domain Sub-Packages** | **40 Sub-Packages** (286 Python modules) + **32 High-Throughput Engines/API** + **48 TS Engine Modules** | `src/`, `parsers/`, `bharat-pa-forensics/src/main/` |
| **Interactive Workstation Views & Modals** | **29 React 19 + Zustand UI components/views/inspectors** + **Native Electron 45 Shell** | `bharat-pa-forensics/src/renderer/`, `electron/` |
| **REST API & Paginated Storage** | **31 FastAPI Endpoints** backed by **12 SQLite Tables + 6 FTS5 Virtual Search Indexes** | `parsers/api_server.py`, `parsers/ui_fts5_paginator.py` |

---

## 2. SUPPORTED CONTAINERS, FILESYSTEMS & DISK IMAGES

### 2.1 Container & Extraction Formats
| Category | Supported Extensions / Signatures | Parsing & Zero-Copy Streaming Capabilities | Modules |
| :--- | :--- | :--- | :--- |
| **Commercial Mobile Extractions** | `.ufdr`, `.ufd`, `.ufdx` (Cellebrite), `.xry` (MSAB XRY), `.ofb` (Oxygen Forensic Detective), GrayKey & VeraKey archives | Streaming XML manifest parsing (`report.xml`, `deviceinfo.xml`, `extraction.xml`); selective materialization ignoring gigabytes of irrelevant video/APK blobs while pulling DBs, WALs, journals, Keychains, XMLs, plists, and LevelDB stores | `src/vfs/indexer.py`, `parsers/enterprise_1tb_chat_and_container_engine.py`, `src/main/vfs/zip_indexer.ts` |
| **Archive Containers** | `.tar`, `.tar.gz`, `.tgz`, `.zip` (Standard + ZIP64 >4 GB) | O(1) offset/central-directory indexing, strict read-only range streaming (`O_RDONLY`), selective artifact materialization (`should_materialize_artifact`) | `src/vfs/reader.py`, `src/main/vfs/tar_indexer.ts`, `src/main/vfs/read-only-vfs.ts` |
| **Android Backup Streams** | `.ab` (`ANDROID_AB_STREAM` / `ANDROID BACKUP` magic) | Parses `.ab` header (backup version, compression flag, encryption algorithm) and inflates deflate payload streams cleanly | `src/vfs/indexer.py` (`AbUnpacker`), `src/main/vfs/ab_unpacker.ts` |
| **iOS Logical / Full-FS Backups** | iTunes / Finder backup directories (`Manifest.db`, `Manifest.plist`, SHA-1 2-char bucket dirs) | Resolves hashed backup IDs to logical app domains (`AppDomain-*`, `AppDomainGroup-*`) | `src/vfs/indexer.py`, `src/identity/ios.py` |
| **EnCase & Raw Forensic Images** | `.E01`, `.Ex01`, `.L01`, `.dd`, `.bin`, `.img`, raw APFS/ext4/F2FS dumps | EnCase segment wrapper (`EwfImgInfo`) with `pyewf` + `pytsk3` directory walker and 1 TB+ sliding-window `mmap` scanning | `parsers/ewf_adapter.py`, `parsers/enterprise_1tb_chat_and_container_engine.py`, `bharat-pa-forensics/test_disk.py` |
| **Unpacked Directories & Single DBs** | Unpacked OS folder dumps, standalone `.db`, `.sqlite`, `.sqlite3`, `.csv`, `.xlsx` | Recursive `userdata`/`/data/data/`/SDCard path normalization (`CanonicalPathNormalizer`), `build.prop` device profiling | `src/vfs/normalizer.py`, `src/main/vfs/folder_vfs.ts`, `parsers/api_server.py` |

### 2.2 Identity, Dual-App Clone & Ghost App Resolution
- **Android Multi-User & OEM Clone Profiles (`src/identity/android.py`, `src/identity/abx.py`):** Parses `/data/system/packages.xml` (both legacy text XML and Android 12+ Android Binary XML `ABX`), resolves Linux UIDs (`u0_a123`, `u999_a*`, `u95_a*`, `u10_a*`), and uncovers dual/cloned financial or chat apps installed inside Xiaomi Dual Apps, Samsung Secure Folder (`Knox`), OnePlus Parallel Apps, Vivo/Oppo App Clone, and Credential-Encrypted (`/data/user_de/`) sandboxes.
- **iOS Container Mapping (`src/identity/ios.py`):** Parses `.com.apple.mobile_container_manager.metadata.plist` to map ephemeral Apple Container UUIDs (`Data/Application/<UUID>`) back to Bundle IDs and stitches `Shared/AppGroup/<UUID>` companions (critical for WhatsApp, Signal, PhonePe, and Paytm extensions).
- **Ghost App Residual Discovery (`src/identity/ghost.py`):** Detects traces of uninstalled financial, spyware, or wipe-tool apps using Tripartite State Modeling (`APP_UNINSTALLED_GHOST`) across orphaned folders, ART profiles, notification logs, and PackageManager tombstones.

---

## 3. LOW-LEVEL STORAGE, DATABASE & BINARY WIRE RECOVERY

### 3.1 SQLite Engine & 4-Zone Residual Recovery
- **Direct B-Tree & Corrupt Header Reader (`src/sqlite/header.py`, `record.py`, `varint.py`, `overflow.py`):** Parses SQLite 100-byte database headers, leaf/interior table B-Tree headers, 9-byte Big-Endian SQLite varints, 13 serial types, overflow page chains with cycle guards, and schema DDL (`parse_create_table_sql`).
- **Write-Ahead Log (WAL) Analyzer (`src/sqlite/wal.py`, `parsers/wal_rollback_analyzer.py`, `src/main/sqlite_carver/wal_analyzer.ts`):**
  - Verifies WAL magic (`0x377f0682` / `0x377f0683`), salt-1/salt-2, and cumulative checksum chains (Big-Endian / Little-Endian).
  - Classifies frames into 4 forensic states: **Active/Committed**, **Uncommitted (Crash/Pending)**, **Superseded/Historical Revision**, and **Orphaned/Salt-Mismatched**, reconstructing pre-deletion and pre-edit row versions.
- **Rollback Journal Reader (`src/sqlite/journal.py`):** Parses `-journal` hot/cold sector headers and pre-modification database page images (`JournalPage`).
- **4-Zone Freelist, Freeblock & Unallocated Carver (`src/sqlite/carver.py`, `parsers/freelist_carver.py`, `parsers/corrupt_db_carver.py`, `parsers/generic_table_engine.py`, `src/main/carvers/sqlite-binary-carver.ts`):**
  - Traverses Freelist trunk/leaf chains, intra-page freeblock linked lists (`freeblock_carver.ts`), unallocated slack space between cell content area and page header, and mmap-sliced raw image carving (`carve_deleted_all_categories_mmap`).
  - Enforces Indian FinTech sanity validation (exact `KNOWN_UPI_SUFFIXES` regex `VPA_VALID_RE`, 12-digit UTR & PhonePe `T`-ID validator `UTR_VALID_RE`, realistic INR bounds) to prevent binary noise false positives.
- **Zero-Knowledge & Zero-Code Schema Discovery:**
  - `parsers/zero_knowledge_miner.py`: Unsupervised extraction of financial, chat, URL, VPA, and mobile artifacts from unrecognized SQLite tables.
  - `parsers/generic_table_engine.py` (`app_genie_classify_table`): Universal 6-model classifier categorizing arbitrary tables into Chats, Transactions, Contacts, Calls, Locations, or Credentials.
  - `src/unk_triage_and_bsa_studio/schema_mapper.py` (`ZeroCodeSchemaMapper`): Lets examiners interactively promote unknown SQLite columns to `SemanticColumnRole` (`TIMESTAMP_EPOCH`, `ACTOR_SOURCE_IDENTIFIER`, `ACTOR_TARGET_IDENTIFIER`, `MESSAGE_OR_EVENT_BODY_TEXT`, `FINANCIAL_OR_CRYPTO_AMOUNT`) into the Unified Super-Timeline.

### 3.2 Non-SQLite, Wire-Format & Browser Storage Engines
| Format / Subsystem | Capabilities & Internal Structures Parsed | Modules |
| :--- | :--- | :--- |
| **Google LevelDB & RocksDB** | `.ldb` SSTable block parser, `.log` write-ahead records, `MANIFEST`, Snappy block decompression, Delete Tombstone tracking (`ValueOperationType`), key cleanup (`clean_user_key`) | `src/nonsqlite/leveldb.py`, `src/nonsqlite/snappy.py`, `parsers/leveldb_parser.py` |
| **Tencent MMKV** | Protobuf-framed key-value parsing, append-history overwrite tracking (Layer 1 vs historical Layer 2), mmap slack carving beyond valid length markers | `src/nonsqlite/mmkv.py`, `src/main/binary_decoders/mmkv_decoder.ts` |
| **Apple Biome `SEGB` v1 & v2** | Binary `SEGB` header/frame walker, event timestamps, state flags, Protobuf payload extraction across 84+ Biome behavioral event types | `src/nonsqlite/segb.py`, `src/ios_telemetry/biome_screentime_decoder.py` |
| **Schema-Less Protocol Buffers** | Recursive wire-format decoder (Varint, 64-bit, Length-Delimited, 32-bit, ZigZag) with schema inference & `google.type.Money` (`units`+`nanos`) financial extraction | `src/nonsqlite/protobuf.py`, `src/nonsqlite/varint.py`, `parsers/protobuf_decoder.py`, `src/main/binary_decoders/protobuf_decoder.ts` |
| **MessagePack, CBOR, LZ4, Zstd, Brotli, Zlib** | Pure-Python LZ4 Block & Frame decompressors, CBOR tag/byte decoder, MessagePack stream parser, Zlib/Gzip/Zstd/Brotli recursive multi-layer container unpacker | `parsers/generic_table_engine.py`, `parsers/app_overrides.py` |
| **Apple Plist, NSKeyedArchiver & typedstream** | Binary `bplist00` unpacking, recursive `$objects` `NSKeyedArchiver` UID graph resolution, iOS `attributedBody` `NSAttributedString` `typedstream` unpacker | `parsers/generic_table_engine.py`, `src/dlt/attributed_body.py` |
| **Embedded WebViews & Caches** | Chromium Simple Cache (`*_0`, `*_1`, `*_s`), iOS `NSURLCache` (`Cache.db` + `fsCachedData/<UUID>`), `Cookies.binarycookies` hybrid-endian parser, IndexedDB/LocalStorage LevelDB, JWT token header/claim decoder | `src/webview/*` (7 modules) |

### 3.3 Cryptographic Key Broker & Decryption
- **SQLCipher v1–v4 & Page-Level Decryptor (`src/crypto/sqlcipher.py`, `parsers/keychain_decryptor.py`, `src/main/sqlite_carver/sqlcipher_crypto.ts`):** Supports custom page sizes (1024/4096), KDF iterations (4000 / 64000 / 256000), PBKDF2 HMAC-SHA1/SHA256/SHA512, custom plaintext header flags, validating SQLite header magic on Page 1.
- **WhatsApp `.crypt12` / `.crypt14` / `.crypt15` Decryptor (`src/crypto/whatsapp.py`, `src/main/parsers/keystore/whatsapp_key.ts`):** Derives AES-256-GCM keys from 64-digit/32-byte root keys or Android `/data/data/com.whatsapp/files/key`, handles Protobuf/header IV offset extraction.
- **WeChat WCDB (`EnMicroMsg.db`) Password Derivation (`src/crypto/wcdb.py`):** Derives candidate 7-char MD5(`IMEI + UIN`) database keys automatically.
- **Apple Notes Decryptor (`src/crypto/applenotes.py`):** RFC 3394 AES Key Unwrap + AES-128-GCM row-level note body decryption.
- **Keychain & Keystore Harvester (`src/crypto/keyring.py`, `src/main/parsers/keystore/shared_prefs_keys.ts`):** Harvests keys/tokens/PIN salts from iOS `keychain-2.db` and Android `shared_prefs/*.xml`.
- **Bank Statement PDF Unlocker (`src/banking/pdf_unlocker.py`):** Deterministic password cracking using Indian bank conventions (`First4LettersOfName + DDMM`, `DDMMYYYY`, PAN uppercase, mobile last digits) with RC4/AES PDF decryption.
- **Disguised Vault Unmasker (`src/visual_residuals/vault_unmasker.py`):** Executes Known-Plaintext Attack (KPA) on obfuscated image/video magic headers (`FF D8 FF`, `89 50 4E 47`, `ftyp`), reversing 1-byte XOR, multi-byte repeating XOR, byte-swapping, and prepended decoy headers used by Calculator Vault, Audio Manager Vault, and NQ Vault.
- **Interactive Key-Broker Hot-Patcher (`src/unk_triage_and_bsa_studio/key_broker_hotpatcher.py`):** Applies newly supplied examiner passphrases/PINs/keys through a 5-step incremental DAG re-index in **under 3.0 seconds** without re-ingesting the full 1 TB container.

---

## 4. COMPLETE SUPPORTED APPLICATIONS & ECOSYSTEM MATRIX

### 4.1 Indian UPI, Super-Apps, Wallets & NPCI Binding (23 Apps / Subsystems)
| # | Application / Subsystem | Android Package ID(s) | iOS Bundle / Group ID(s) | Target Databases / Files | Specific Forensic Capabilities |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **PhonePe & PhonePe Business** | `com.phonepe.app`, `com.phonepe.app.beta`, `com.phonepe.app.preprod`, `com.phonepe.app.business` | `com.phonepe.PhonePeApp`, `com.phonepe.iosapp`, `group.com.phonepe`, `com.phonepe.business` | `ZTRANSACTIONENTITY`, `TRANSACTION_HISTORY`, `ZTRANSACTION`, `P2P_TRANSACTIONS` | Zlib/Base64 JSON blob unpacking, Bullhorn in-app P2P chat extraction, `PHONEPE_TID_RE` (`T`+YYMMDDHHmmss) embedded timestamp extraction & **clock tampering alert**, owner vs counterparty direction fix, `paisa -> INR` overflow guard |
| 2 | **Google Pay (Tez / India)** | `com.google.android.apps.nbu.paisa.user`, `com.google.android.apps.nbu.paisa.merchant`, `com.google.android.apps.walletnfcrel` | `com.google.Tez`, `com.google.ios.pay`, `com.google.pay`, `group.com.google.Tez`, `com.google.paisa` | `paisa.db`, `tez_database`, `transactions`, `txn_history`, `upi_transactions`, `tez_transactions`, `feed_items`, `sync_entities` | Decodes embedded `google.type.Money` Protobufs (`units` + `nanos`), micros conversion, `sender_vpa`/`receiver_vpa` attribution, 12-digit UTR extraction from Protobuf streams |
| 3 | **Paytm & Paytm Business** | `net.one97.paytm`, `net.one97.paytm.business`, `com.paytm.merchants` | `net.one97.paytm`, `group.net.one97.paytm`, `com.paytm.business` | `payments`, `paytm_payments`, `passbook.db`, `passbook_entries`, `order_history`, MMKV stores | Passbook ledger parsing, MMKV wallet/order history carving, wallet-to-bank & UPI split settlement decoding |
| 4 | **BHIM UPI (NPCI)** | `in.org.npci.upiapp` | `in.org.npci.upiapp`, `group.in.org.npci.upiapp`, `com.npci.bhim` | `transactions`, `tx_history`, `pending_transactions`, `rkstorage` | Pending Collect Request scam tagging, React Native AsyncStorage (`rkstorage`) JSON unpacking |
| 5 | **CRED** | `com.dreamplug.androidapp`, `com.dreamplug.android`, `com.dreamplug.spend` | `com.dreamplug.spend`, `com.dreamplug.cred`, `group.com.dreamplug` | `transactions`, `payments`, `card_payments`, `cashflow_transactions`, `ZTRANSACTION` | Credit card bill & UPI merchant payments (with `'cred'` vs `'credited'` SMS false-positive collision guard) |
| 6 | **Amazon Pay India** | `in.amazon.mShop.android.shopping`, `com.amazon.mShop.android.shopping` | `com.amazon.Amazon`, `com.amazon.AmazonIN`, `group.com.amazon` | `apay_transactions`, `order_history`, `upi_transactions` | Wallet reloads, gift-card voucher laundering signals, UPI order cross-links |
| 7 | **WhatsApp Pay** | `com.whatsapp` | `net.whatsapp.WhatsApp` | `msgstore.db` (`pay_transaction` / `wa_pay`) | Scaled integer decoding (`amount_1000 / 1000.0`), P2P chat-inline transfer linkage |
| 8 | **Super.money (Flipkart)** | `money.super.payments`, `com.supermoney` | `money.super.app`, `com.supermoney.ios` | `transactions`, `upi_transactions`, `rkstorage` | Cashback/UPI ledger & AsyncStorage extraction |
| 9 | **Navi UPI** | `com.naviapp` | `com.naviapp`, `group.com.naviapp` | `transactions`, `payment_history`, `rkstorage` | UPI & instant loan disbursement ledger extraction |
| 10 | **Jupiter Money** | `money.jupiter`, `space.amica.jupiter` | `money.jupiter.ios`, `space.amica.jupiter` | `transactions`, `account_statement`, `rkstorage` | Federal/CSB neo-bank co-branded statement & UPI logs |
| 11 | **Fi Money** | `com.epifi.paisa`, `money.fi.app` | `com.epifi.fi`, `money.fi.app` | `transactions`, `ledger_entries`, `upi_transactions` | Neo-bank account & UPI payment ledger extraction |
| 12 | **Slice** | `indwin.c3.shareapp`, `com.slicepay.Slice`, `com.slicepay` | `com.slicepay.Slice`, `group.com.slicepay.Slice` | `transactions`, `passbook`, `rkstorage` | Prepaid/Slice UPI & credit transfer records |
| 13 | **MobiKwik** | `com.mobikwik_new`, `com.mobikwik.android` | `com.mobikwik`, `com.mobikwik.ios`, `group.com.mobikwik` | `transactions`, `wallet_history`, `upi_transactions` | Wallet + ZIP BNPL + UPI transaction extraction |
| 14 | **Freecharge** | `com.freecharge.android`, `com.freecharge` | `com.freecharge.ios`, `com.freecharge`, `group.com.freecharge` | `transactions`, `wallet_transactions`, `upi_transactions` | Axis-backed UPI & recharge ledger parsing |
| 15 | **Airtel Thanks / Payments** | `com.myairtelapp`, `com.airtel.thanks` | `com.airtel.myairtel`, `group.com.airtel.myairtel` | `transactions`, `payment_history`, `rkstorage` | Airtel Payments Bank wallet & UPI transaction extraction |
| 16 | **JioFinance / JioPaymentsBank** | `com.jio.finance`, `com.ril.jio.paymentsbank`, `com.jio.myjio`, `com.jio.jiopay` | `com.jio.finance`, `com.ril.jio.paymentsbank`, `group.com.jio.finance` | `transactions`, `upi_history`, `payment_transactions`, `rkstorage` | JioPay/JioFinance wallet & UPI records |
| 17 | **BharatPe & Merchant** | `com.bharatpe.app`, `com.bharatpe.merchant` | `com.bharatpe`, `group.com.bharatpe`, `com.bharatpe.ios` | `transactions`, `settlements`, `rkstorage` | Merchant QR settlements & mule collection tracking |
| 18 | **FamPay** | `com.fampay.in` | `com.fampay.in`, `in.fampay.app` | `transactions`, `passbook`, `rkstorage` | Minor/youth prepaid & UPI wallet tracking |
| 19 | **Bajaj Finserv** | `org.altruist.BajajExperia`, `com.bajajfinserv.upi`, `com.bajajfinserv.direct` | `com.bajajfinserv.in`, `org.altruist.bajajfinserv.app` | `transactions`, `upi_transactions`, `payment_history`, `rkstorage` | Wallet/UPI/EMI loan payment tracking |
| 20 | **Tata Neu** | `com.tatadigital.tcp` | `com.tatadigital.tcp`, `com.tatadigital.neu` | `transactions`, `upi_transactions`, `payments`, `rkstorage` | Tata Pay UPI & NeuCard ledger extraction |
| 21 | **Samsung Wallet / Pay** | `com.samsung.android.spay`, `com.samsung.android.spaymini` | *(N/A)* | `transactions`, `upi_transactions`, `history` | Samsung Pay India UPI & tokenized card logs |
| 22 | **NPCI Common Library Vault** | `org.npci.upi.security.pinactivitycomponent` | *(iOS Keychain)* | Encrypted CL token/credential XML & Keystore blobs | Audits hardware keystore attestation & CL token rotation (`src/binding/cl_vault.py`) |
| 23 | **Juspay Godel Payment SDK** | `in.juspay.godel` | *(Embedded)* | SDK WebView/logs | Detects silent SIM-binding SDK hooks (`src/binding/trojan_detector.py`) |

- **Additional UPI Protocol & Hardware Capabilities (`src/upi/`, `src/binding/`, `parsers/`):**
  - `UniversalQRDecoder` & `UPIAndBharatQRUnpacker`: Parses `upi://pay?...` deep-link parameters (`pa`, `pn`, `am`, `cu`, `tr`, `tn`, `mc`) and recursive **EMVCo BharatQR TLV** merchant strings (Tags `00`–`62`, Tag `26`/`27` UPI sub-tags).
  - `TelephonyProviderDecoder` & `OutboundBindingSMSDecoder`: Maps Dual-SIM **ICCID / IMSI** history and audits silent outbound Virtual Mobile Number (**VMN**) binding SMS (`+91` binary data port SMS) to detect **Ghost SIM-Binding Trojans** (`GhostSIMBindingTrojanDetector` 3-point verdict).
  - **UPI Lite & UPI Circle Delegation:** Extracts small-ticket offline UPI Lite loads and secondary delegate/delegator limits (`UPILiteAndCircleDelegation`).

---

### 4.2 Domestic PSU, Private, Corporate, Payments Banking, AePS & Biometric RD Apps (36+ Apps)
| Tier | Bank / Platform | Android Package ID(s) / iOS Bundle ID(s) | Specific Capabilities (`PluginRegistry` + `src/banking/`) |
| :--- | :--- | :--- | :--- |
| **PSU Banking** | **YONO SBI & YONO Lite** | `com.sbi.lotusintouch`, `com.sbi.yono`, `com.sbi.SBIFreedomPlus`, `com.sbi.upi`, iOS `com.sbi.yono(.lite)` | Passbook sync, mPassbook cache, IMPS/NEFT/RTGS narration parsing |
| **PSU Banking** | **bob World / BoB mPassbook** | `com.bankofbaroda.mconnect`, `com.baroda.mpassbook`, `com.bankofbaroda.upi`, iOS `in.co.bankofbaroda.mpassbook` | mPassbook SQLite/XML ledger + beneficiary cooling checks |
| **PSU Banking** | **PNB One & mPassbook** | `com.Version1`, `com.pnb.mPassbook`, `com.fss.pnbpsp`, `com.fss.pnb`, iOS `com.pnb.pnbone` | PNB account statements & UPI PSP binding logs |
| **PSU Banking** | **Canara ai1 & ePassbook** | `com.canarabank.mobility`, `com.canarabank.epassbook`, iOS `com.canarabank.ai1` | Passbook cache & IMPS/UPI statement extraction |
| **PSU Banking** | **Union Bank Vyom** | `com.infrasoft.uboi`, `com.unionbank.ecommerce.mobile.android`, iOS `com.unionbank.vyom` | mPassbook & account transfer extraction |
| **PSU Banking** | **IndOASIS (Indian Bank)** | `com.IndianBank.IndOASIS`, `com.indianbank.indoasis`, `com.infrasofttech.indianbank`, iOS `in.indianbank.indoasis` | Offline ledger & statement parsing |
| **PSU Banking** | **IDBI, BOI, Central Bank, UCO, IOB, IPPB / DakPay** | `com.snapwork.IDBI`, `com.boi.ua.android`, `com.infrasofttech.CentralBank`, `com.lcode.ucobank`, `com.iob.iobmobile`, `com.ippb.app`, `in.ippbonline.mobile`, `com.dop.dakpay` | Unified PSU mPassbook & India Post Payments Bank extraction |
| **Private Banking** | **ICICI iMobile Pay & Pockets** | `com.csam.icici.bank.imobile`, `com.icicibank.pockets`, iOS `com.icicibank.imobile` | Account statement, recent txns & Pockets prepaid ledger |
| **Private Banking** | **HDFC MobileBanking & PayZapp** | `com.snapwork.hdfc`, `com.hdfcbank.payzapp`, `com.hdfcbank.android.now`, iOS `com.hdfcbank.*` | Account ledger, PayZapp wallet, `rkstorage` parsing |
| **Private Banking** | **Axis Mobile & Netbanking** | `com.axis.mobile`, `com.axis.netbanking`, iOS `com.axisbank.mobilebanking` | Mini-statement & UPI ledger parsing |
| **Private Banking** | **Kotak 811 & Kotak Neo** | `com.msf.kbank.mobile`, `com.kotak.neo`, iOS `com.kotak.mobilebanking` | Account activity & statement logs |
| **Private Banking** | **IDFC FIRST, IndusMobile/Indie, FedMobile, YES BANK IRIS, RBL MoBank** | `com.idfcfirstbank.optimus`, `com.idfcbank.mobileBanking`, `com.indusind.indusmobile`, `com.indusind.indie`, `com.fedmobile`, `in.irisbyyes.app`, `com.yesbank`, `com.rblbank.mobank` | Account statements, beneficiary cool-off audit & passbook logs |
| **Corporate Banking** | **SBI YONO Business, ICICI InstaBIZ, HDFC CBX, Axis Corporate, Kotak fyn, bob World Business** | `com.sbi.yonobusiness`, `com.icicibank.instabiz`, `com.hdfc.cbx`, `com.axis.AxisCorporate`, `com.kotak.fyn`, `com.bankofbaroda.bobworldbusiness` | Maker / Checker corporate approval attribution (`CorporateRole`) & bulk payout audit (`src/banking/engine.py`) |
| **AePS & BC Agent Apps** | **SpiceMoney, Fino Mitra, PayNearby, Relipay, Roinet Xpresso, Ezeepay, Bankit Agent, CSC DigiPay, Fino BPay** | `in.spicemoney.spicemoney`, `com.finopaymentbank.finomitra`, `com.finopaytech.bpay`, `com.bnb.paynearby`, `com.rnfi.relipay`, `com.roinet.xpresso`, `com.ezeepay.service`, `in.bankit.agent`, `com.csc.digipay` | Aadhar Enabled Payment System (AePS) cash-out mule agent attribution, Aadhaar/RRN reference audit |
| **Biometric RD Services** | **Mantra MFS100 / MFS110, Morpho IDEMIA, Startek FM220, SecuGen** | `com.mantra.rdservice`, `com.mantra.mfs110.rdservice`, `com.scl.rdservice`, `com.acpl.registersdk`, `com.secugen.rdservice` | Pairs USB fingerprint RD scanner serial logs with AePS agent cash-out events (`src/banking/engine.py`) |

- **Additional Banking Capabilities:**
  - `CoreBankingNarrationParser`: Parses NEFT / RTGS / IMPS / UPI / ATM / ACH bank narrations into counterparty names, bank account masks, UTR/RRN numbers, and payment rails.
  - `OfflineIFSCResolver` (`src/banking/ifsc_resolver.py`, `parsers/vpa_harvester.py`): Validates 11-character IFSC syntax (`^[A-Z]{4}0[A-Z0-9]{6}$`) and offline resolves bank + branch + city/state/jurisdiction via `BANK_CODE_MAP` & `KNOWN_BRANCH_REGISTRY`.
  - `CardlessRunnerCorrelator` (`src/banking/cardless_runner.py`): Links OTP-triggered cardless ATM cash-out tokens (SBI YONO Cash, ICICI Cardless) with ATM branch GPS & nearby mule phone presence.

---

### 4.3 Cryptocurrency: Self-Custody Web3, Custodial Wallets & Global/Indian CEX (29+ Platforms)

#### A. Self-Custody Web3 Wallets (`src/web3/`, `PluginRegistry`)
| Wallet | Package / Bundle IDs | Specific Capabilities |
| :--- | :--- | :--- |
| **MetaMask Mobile** | Android/iOS `io.metamask.MetaMask` | LevelDB/MMKV recursive vault JSON unpacking, hashcat-ready scrypt/PBKDF2 keystore extraction, ERC-20/swap history |
| **Trust Wallet** | `com.wallet.crypto.trustapp` / `com.sixdays.trust` | Multi-coin address keystore & transaction history extraction (`wallet_history`) |
| **TronLink Pro** | TronLink Android/iOS sandboxes | **TRON USDT (TRC-20)** specialist: bi-directional `hex41` <-> Base58Check (`T...`) conversion & BigInt arbitrary-precision decimals |
| **Cake Wallet (Monero / XMR)** | Cake Wallet Android/iOS stores | Privacy coin parsing & **25-word Monero mnemonic** recovery |
| **Phantom (Solana)** | Phantom stores | Solana Base58 SPL address & transaction validation |
| **Ledger Live** | Ledger Live companion stores | Hardware-backed xpub, account discovery & portfolio audit |
| **Bitget Wallet (BitKeep) & Blockchain.com** | `com.bitkeep.wallet`, `com.blockchainvault` | Hybrid Web3 keystore & multi-chain address recovery |

#### B. Global & Indian FIU-IND Centralized Exchanges (`src/cex/`, `parsers/crypto_p2p_parser.py`)
| Platform | Package / Bundle IDs | Compliance Tier / Specific Capabilities |
| :--- | :--- | :--- |
| **Binance** | `com.binance.dev`, `com.binance.us`, iOS `com.binance.BinanceApp`, `com.czzhao.binance` | Global P2P (`orders`, `p2p_orders`, `c2c_orders`), MMKV Layer-1/Layer-2 recovery, HTTP/WebView decompression, in-order P2P seller/buyer chat logs, off-chain Binance Pay vs on-chain tracking, **triangulation fraud detection** |
| **Bybit** | `com.bybit.app`, iOS `com.bybit.Bybit` | P2P trade escrow orders & wallet histories (`p2p_trade`) |
| **KuCoin** | `com.kubi.kucoin`, iOS `com.kucoin.KuCoin` | Order & P2P escrow extraction (`p2p`) |
| **CoinDCX** | `com.coindcx`, `com.coindcx.btc`, iOS `com.coindcx.CoinDCX` | Domestic FIU-IND Indian CEX: INR deposits, PAN/Aadhaar KYC refs, Section 194S 1% VDA TDS tracking |
| **WazirX** | `com.wrx.offline`, `com.wazirx.wazirx`, iOS `com.wrx.wazirx` | P2P INR-USDT orders, trades & bank details |
| **CoinSwitch Kuber** | `com.coinswitch.kuber` | INR-VDA orders, KYC & linked bank extraction |
| **ZebPay** | `zebpay.Application`, iOS `com.zebpay.alkaloid` | Fiat/crypto orders, penny-drop IFSC & Section 194S TDS |
| **Mudrex, Giottus & Flitpay** | `com.mudrex`, `com.mudrex.app`, `com.giottus` | Indian VDA orderbooks, KYC documents, wallet addresses |

#### C. 15 Custodial Wallets Matrix (`parsers/custodial_wallet_parser.py` — 7 Data Classes)
Covers **Tier 1 (High Prevalence)** and **Tier 2 (Emerging / Regional)**:
- **Tier 1:** Coinbase (`com.coinbase.android` / `com.coinbase.consumer`), Crypto.com (`co.mona.android` / `co.mona.Mona`), Bitget (`com.bitget.exchange`), MEXC (`com.mexcpro.client` / `com.mexc.exchange`), Gate.io (`io.gate.gateapp`), Kraken (`com.kraken.invest.app`), Nexo (`com.nexowallet` / `com.nexo.mobile`), Bitstamp (`net.bitstamp.app`), Blockchain.com (`com.blockchainvault`), Bitget Wallet (`com.bitkeep.wallet`).
- **Tier 2:** YouHodler (`com.youhodler.youhodler`), BitMart (`com.bitmart.exchange`), HTX / Huobi (`com.huobi.app`), Giottus (`com.giottus`), Mudrex (`com.mudrex`).
- **7 Normalized Data Classes Extracted:** User profile/UID, Tier & KYC status, Linked Mobile/Email, Deposit/Withdraw Addresses + Multi-chain detection, Wallet Transactions, Order/P2P History, Risk & Provenance badges.

#### D. Seed Hunter, HD Derivation & Blockchain Validators (`src/seedhunter/`, `src/validators/`, `parsers/fiat_crypto_bridge.py`)
- **Cross-System Seed Hunter (`seed_hunter.py`):** Hunts plaintext, numbered, fragmented, or obfuscated **2048-word BIP-39** phrases, **25-word Monero** seeds, WIF private keys, and 64-hex private keys across SQLite, notes, clipboard, and gallery OCR.
- **Offline HD Derivation (`hd_derivator.py`):** Offline BIP-32, BIP-44 (`m/44'/60'`, `m/44'/195'`), BIP-84 (`bc1...`), and SLIP-0010 derivation to prove ownership against suspect addresses without internet access.
- **Address Checksum & ABI Tools:** Keccak-256 **EIP-55** EVM checksum validation, **TRON Base58Check**, **Bitcoin Base58/Bech32**, **Solana** validation; **ERC-20 / TRC-20 ABI Call-Data Unpacker** (`transfer`, `transferFrom`, `approve`, swap selectors); **WalletConnect v2** malicious dApp approval / unlimited allowance phishing drainer detector.
- **Rupee-to-USDT Bridge (`src/seedhunter/correlator.py`, `parsers/fiat_crypto_bridge.py`):** Correlates bank/UPI INR debits within a temporal/amount window against Binance/Indian CEX P2P buy orders and on-chain USDT hops.

---

### 4.4 Messaging, Privacy, High-OpSec, Social, VoIP, Dating & Covert Channels (50+ Platforms)

#### A. Mainstream & Modded Messengers
| App | Package / Bundle IDs | Deep Forensic Capabilities |
| :--- | :--- | :--- |
| **WhatsApp & Business (+ GB/FM/Dual clones)** | `com.whatsapp`, `com.whatsapp.w4b`, iOS `net.whatsapp.WhatsApp(.SMB)` | Decodes `msgstore.db`, `wa.db`, `ChatStorage.sqlite`; **@lid -> Phone JID unmasking**, View-Once media recovery, message reactions, edit history, **Revoked/Deleted message recovery**, rolling `.crypt12/.crypt14/.crypt15` diff-merging, companion linked-device tracking (`src/whatsapp/`, `parsers/enterprise_1tb_chat_and_container_engine.py`) |
| **Telegram & Telegram X** | `org.telegram.messenger`, `org.telegram.plus`, `org.thunderdog.challegram`, iOS `ph.telegra.Telegra` | `cache4.db`, `tgdata.db`, multi-account slot discovery (`userconfig.xml`), native **MTProto TL binary stream deserialization** (`decode_tl_user`, `decode_tl_message`), Secret Chat (`enc_chats`) metadata (`src/telegram_signal/`, `parsers/chat_social_privacy_parsers.py`) |
| **Signal** | `org.thoughtcrime.securesms`, iOS `org.whispersystems.signal` | `signal.db` / `Signal.sqlite`, SQLCipher keystore unwrapping, `recipient`/`thread`/`mms`/`sms`/`part` correlation (`src/telegram_signal/signal_decoder.py`) |

#### B. High-OpSec & Decentralized Criminal/Handler Messengers (`src/high_opsec/`, `PluginRegistry`)
- **Session (Oxen Onion-Routed):** `network.loki.messenger` / `com.loki-project.loki-messenger` — SQLCipher key unwrap, 64/66-hex `05`/`15`/`25` Session ID attribution, Closed Groups & SOGS Open Communities (`session_decoder.py`).
- **SimpleX Chat (Zero-ID Queues):** `chat.simplex.app` — Parses `simplex_v1_chat.db`, extracts `smp://` relay queue links and carves `item_deleted` residuals (`simplex_decoder.py`).
- **Zangi Private Messenger:** `com.beint.zangi` — Decodes **10-XXXX-XXXX** virtual numbers, CoreData `ZMESSAGE`/`ZCONVERSATION`/`ZCONTACT` (`privacy_messengers_decoder.py`).
- **Element / Matrix:** `im.vector.app`, `im.vector.alpha` — `roomevents`, `timeline_events`, `@user:homeserver` Matrix IDs & E2EE `crypto_store`.
- **Threema:** `ch.threema.app` — 8-character Threema ID & message store (`threema.db`).
- **Briar:** `org.briarproject.briar.android` — Peer-to-peer Tor/Bluetooth H2 database parsing.
- **XMPP / Conversations, Wire, Wickr:** `eu.siacs.conversations` JID + OMEMO key fingerprints, Wire & Wickr metadata, plus `CrossAppCovertHandleHunter` discovering Session IDs / SimpleX invites / Zangi handles shared inside mainstream apps.

#### C. Social Media, Cross-Border Handler VoIP, Burners & Indian Marketplaces (`src/social_voip/`, `src/unified_chat/`, `parsers/social_interaction_comms_parsers.py`)
- **Meta Ecosystem:** **Facebook Messenger & Lite** (`com.facebook.orca`, `com.facebook.katana`, `com.facebook.mlite`, iOS `com.facebook.Messenger`) covering legacy `threads_db2` + Msys/Armadillo E2EE `reverb.db`; **Instagram Direct** (`com.instagram.android`, `com.burbn.instagram`) `direct.db`; **Threads** (`com.instagram.barcelona`, `com.burbn.threads`).
- **Snapchat & Discord:** **Snapchat** (`com.snapchat.android` / `com.toyopagroup.picaboo`) joining `arroyo.db` Protobufs with `tcspahn.db` UUIDs + ephemeral snap preservation; **Discord** (`com.discord` / `com.hammerandchisel.discord`) decoding 64-bit Snowflake timestamps + `kv_storage` + Chromium Simple Cache.
- **Work & Social Platforms:** **Microsoft Teams** (`com.microsoft.teams`), **Skype** (`com.skype.raider`), **X / Twitter** (`com.twitter.android` / `com.atebits.Tweetie2`), **Reddit Chat**, **LinkedIn** (`com.linkedin.android` / `voyager.db`).
- **Asian / Middle-Eastern Handler VoIP (Dubai/SE-Asia Cyber Syndicates):** **Botim**, **IMO** (`com.imo.android.imoim`), **Tencent WeChat** (`com.tencent.mm` `EnMicroMsg.db` WCDB), **LINE** (`jp.naver.line.android`), **Viber** (`com.viber.voip`), **KakaoTalk** (`com.kakao.talk`).
- **Truecaller Deep Intelligence:** `com.truecaller` / `com.truesoftware.TrueCaller` — `tc.db` unsaved caller-ID directory + spam community scores + `msg.db` IM / SMS / Flash Messages enrichment.
- **Virtual Burner Number Apps (`src/social_voip/burner_bridge.py`):** **TextNow, 2ndLine, NextPlus, Hushed, Dingtone** — Extracts `+1`/`+44` virtual numbers & incoming OTPs used to register anonymous Indian scam WhatsApp/Telegram accounts.
- **Regional Indian Marketplaces & Apps:** **OLX India** (`com.olx.southasia`), **ShareChat** (`in.mohalla.sharechat`), **Moj**, **IndiaMART**, **JioChat / Arattai** — Extracts buyer/seller QR-scam chats and audio room transcripts.
- **Covert Dead-Drops & Betting Platforms (`src/unified_chat/covert_and_betting_decoder.py`):** **Betting App LiveChats** (LiveChatInc / Tawk.to webview Simple Cache parsing UTRs & bookie VPAs), **Collaborative Dead-Drops** (Google Keep, Google Docs comments, encrypted Apple Notes, Email Drafts via WAL carving), and **Multiplayer Game Chats** (Ludo King, PUBG).

#### D. Dating & Matrimonial Forensics (13+ Platforms — `src/hyperlocal_travel/dating_decoder.py`)
- **Global Dating:** **Tinder** (`com.tinder` / `com.cardify.tinder`), **Bumble** (`com.bumble.app` / `com.mosocial.Bumble`), **Hinge** (`co.hinge.app`), **Grindr** (`com.grindrapp.android`), **Happn**, **OkCupid**, **Badoo**.
- **Indian Dating & Matrimonial:** **Aisle**, **TrulyMadly**, **QuackQuack**, **Schmooze**, **Shaadi.com**, **BharatMatrimony**, **Jeevansathi**.
- **Capabilities:** Passport / Travel Mode spoofing detection, unmatched peer chat recovery from `-wal`, automatic phone/WhatsApp/Telegram off-platform handoff extraction.

---

### 4.5 Indian Hyperlocal Delivery, Mobility, Railways & Aviation (19 Platforms — `src/hyperlocal_travel/`)
| Vertical | Platforms Covered | Extracted Evidence |
| :--- | :--- | :--- |
| **Food, Quick-Commerce & P2P Couriers** | **Swiggy**, **Swiggy Genie**, **Zomato**, **Blinkit**, **Zepto**, **Flipkart**, **Amazon IN**, **Porter**, **Borzo** | Micro-location hideout reconstruction: flat/floor/building names, security gate codes, delivery instructions, alternate receiver phone attribution |
| **Ride-Hailing & ONDC Mobility** | **Uber**, **Ola**, **Rapido**, **Namma Yatri**, **InDrive**, **BluSmart** | Google Encoded Polyline unpacking to GPS waypoints, driver RTO registration plates, third-party guest trip bookings |
| **Indian Railways & Aviation** | **IRCTC**, **Where is My Train**, **UTS**, **DigiYatra** | Offline cell-tower live train locations (Where is My Train), PNR/passenger manifests, **IATA Resolution 792 BCBP** boarding pass barcode decoding (DigiYatra) |

---

## 5. OS BEHAVIORAL TELEMETRY, GEOLOCATION, MEDIA, OCR & ANTI-FORENSICS

### 5.1 DLT Financial SMS & OS Notification Spillover (`src/dlt/`, `parsers/os_privacy_spillover.py`)
- **TRAI DLT Anatomy:** Parses standard 6-character Indian telecom headers (`VM-BOBSMS-S`, `VD-BOBTXN`, `VK-HDFCBK`, `AX-SBIINB`, etc.), extracts service/bank/circle codes, and flags SMSC spoofing anomalies.
- **10-Category Banking SMS Grammar:** Extracts Debits, Credits, UPI, ATM withdrawals, Card spends, Mandates/Auto-Pay, OTPs, Balance alerts, and Loan/EMI notices while blocking promotional spam & bank-mask false counterparties.
- **RCS & Notification Ledgers:** Joins Android `mmssms.db` and Google Messages `bugle_db` split-table RCS parts (`com.google.android.apps.messaging`, Samsung/Xiaomi/OnePlus/Oppo/Vivo MMS); extracts deleted app messages & hidden banking OTPs from `notification_log.db`, Gboard/OEM keyboard caches (`user_dict.db`), and clipboard tokens.

### 5.2 iOS & Android Behavioral Telemetry + Geolocation (`src/ios_telemetry/`, `src/android_telemetry/`, `src/geolocation/`)
- **Apple iOS:** `knowledgeC.db` CoreDuet (36+ columns, app focus/lock/charger state), Biome `SEGB` v1/v2 (84 event streams), Screen Time `RMAdminStore`, Apple Unified Logs `.tracev3` (physical accelerometer vs UI display orientation contradiction for spoofing/stand-use audits), `healthdb_secure.sqlite` steps/flights alibi verification, `/.fseventsd/` gzip 1SLG/2SLG records & "Gap of Darkness" mass-wipe detection.
- **Android:** Daily `UsageStats` binary Protobuf & XML decoder, 3-Source `AppOps` (`appops.xml`/ABX) sensor mic/camera/location audit, Google Digital Wellbeing & Samsung Forest, Health Connect & Network Data Usage (`netstats`).
- **Geolocation & Movement:** iOS `cache_encryptedB.db` & `routined` Significant Locations, Android on-device Google Timeline/Maps navigation, LTE ECI & 5G NR NCI cell tower CGI decoding, MAC 6-octet Wi-Fi/BT normalization, Haversine impossible-velocity check, **Offline PMTiles v3 Web Mercator renderer**, and **Hybrid Online/Offline Reverse Geocoder** (OSM Nominatim with persistent SQLite cache + embedded **66-city Indian Gazetteer** spanning all states and UTs).

### 5.3 Media Provenance, Visual Residuals, OCR, KYC & Aadhaar QR (`src/media_library/`, `src/visual_residuals/`, `src/qr_and_receipts/`, `src/kyc_and_ocr/`, `src/geospatial_media_and_tamper/`)
- **OS Media Libraries & Carving:** iOS `Photos.sqlite` & `Syndication.sqlite` (trashed state, hidden albums, computational search scenes), Android `external.db` (Scoped Storage `.trashed-*`), Apple Live Photo companion UUID pairing, **Android Motion Photo embedded MP4 carver** (`GCamera:MicroVideoOffset`), **6-tier C2PA Content Credentials (JUMBF box) cryptographic validator**, and **64-bit Perceptual Difference Hash (dHash)** clustering.
- **Visual Residuals:** iOS SplashBoard & Android `TaskSnapshot` Protobuf/KTX app-switcher screenshot reconstruction; iOS `.ithmb` slot decoding; Android **Glide / Fresco / Coil / DiskLruCache** orphaned thumbnail reconstruction.
- **UIDAI Aadhaar Secure QR & BharatQR:** Full mathematical unpacker decoding BigInt byte streams -> Gzip decompression -> **extracted demographic attributes + embedded JPEG-2000 owner photograph**, alongside Verhoeff $D_5$ tamper status checks.
- **5-Point Forged Payment Receipt Detector:** Detects known fake receipt generator APKs (`com.fake.gpayreceipt`, `com.fake.phonepe`, `com.fakepay`, `com.fakepaytm.receipt`, `com.phonepe.faketransaction`, `com.prankpayment`, `com.spoof.paytm`, `com.spoofpay.india`, `com.mparivahan.update.overlay`), verifies PhonePe `T`-ID Julian date parity, EXIF/software editing markers, and cross-checks UTRs against device databases.
- **Air-Gapped Bilingual OCR & Indian KYC Validators:** Offline Hindi (Devanagari `०–९` -> ASCII `0–9` numeral normalization) + English (`hin+eng`) OCR with Tesseract & pure-Python PNG chunk (`iTXt`/`tEXt`/`zTXt`) fallback; positional OCR homoglyph normalizer (`0`/`O`, `1`/`I`/`l`, `5`/`S`); deterministic validators for **PAN (10-char structural + entity letter)**, **Indian Passport TD3 MRZ**, **Aadhaar Verhoeff $D_5$**, **GSTIN Mod-36**, and **grid-aware BIP-39 Seed Screenshot Reconstructor**.

### 5.4 Anti-Forensics, Clock Tampering & Cybercrime Malware Auditor (`src/antiforensics/`, `src/main/binary_decoders/dex_scanner.ts`)
- **Root, Hook & Jailbreak Audit:** Detects unlocked bootloaders, Magisk root policy & Zygisk DenyList hiding (`magisk.db`), repackaged/hidden Magisk Manager, KernelSU, APatch, LSPosed/Xposed hooks, iOS Jailbreaks, TrollStore, and ADB USB debugging exposure.
- **Clock Tampering & Wiping Detection:** ROWID inversion checks (`row N+1 timestamp < row N timestamp`), `TIME_SET` / `TIMEZONE_CHANGED` OS events, SQLite sequence-tail deletion gaps (`sqlite_sequence > MAX(rowid)`), telemetry-proven wipe gaps, surgical `mtime`/`atime`/`ctime`/`btime` timestomping, and bulk backup/restore migrations.
- **Mock GPS & Sensor Contradiction:** Flags Mock GPS APKs (`com.lexa.fakegps`, `com.incorporateapps.fakegps`, `com.blogspot.newapphorizons.fakegps`, `ru.gavrikov.mocklocations`, `com.lerist.fakelocation`, `com.gpsjoystick`, `io.github.jqssun.gpssetter`), Android `AppOps OP_58` (`MOCK_LOCATION`), iOS USB Xcode simulated location, GPS vs Cell/Wi-Fi discrepancy, and GPS movement while charging with zero Health steps.
- **Indian APK Trojan, C2 & Remote Access Auditor:** Scans `.apk` / `classes.dex` strings to extract hardcoded **Telegram Bot C2 tokens** + attacker `chat_id`s, **Firebase RealtimeDB C2 endpoints**, DuckDNS/Ngork URLs, **USSD Call-Forwarding Hijacks (`*21*`, `*401*`, `*61*`)**, malicious APK SMS-forwarders, and **AnyDesk (`ad_svc.trace`), TeamViewer, and RustDesk** remote-takeover session traces.

---

## 6. ANALYTICAL CORRELATION, VISUALIZATION & WORKSTATION CAPABILITIES

1. **Multi-Source Corroboration & Reconciliation (`parsers/corroboration_engine.py`, `src/correlator/`):**
   - Cross-heals masked/missing counterparties across App DBs, DLT SMS, Notifications, and Truecaller.
   - **4-Way UTR Correlator & Fraud Detector:** Scores corroboration (`0.0–1.0`), distinguishes genuine 12-digit UTRs from Verhoeff-valid 12-digit Aadhaar numbers (blocking Aadhaar leaks from false UTR matching), flags rapid in-out mule bursts, split smurfing, circular loops, and balance gaps.
   - **Bank Statement CSV + Telecom CDR Fusion (`parsers/multi_source_fusion.py`):** Reconciles official bank CSV/XLSX statements against extracted app ledgers and correlates suspicious fund transfers within $\pm 15\text{ minutes}$ of voice/SMS/tower CDR hits.
2. **Syndicate Link Graph, Financial Sankey & Storyboard (`parsers/graph_intelligence.py`, `src/financial_graph_and_storyboard/`, `src/entity_and_timeline/`):**
   - Constrained Disjoint-Set Union (`DSU`) entity resolution & Unified Master Owner Dossier.
   - NetworkX & PyVis interactive syndicate topology classifying **Victims**, **Mule Accounts (Layer-1/Layer-2)**, **Aggregators**, and **Master Kingpins** + **Charge-Sheet Hop Extractor** (`Victim -> L1 -> L2 -> Kingpin/USDT`).
   - **Interactive 5-Stage SVG Sankey Canvas** (`Source -> Layer 1 -> Layer 2 -> Aggregator/FX -> USDT`), 5-swimlane **Action-Burst Storyboard** (60-second / 5-minute behavioral windows), and Barnes-Hut Quadtree WebGL2 physics layout.
3. **Workflow-Stage Workbench (`bharat-pa-forensics/src/renderer/`):**
   - Virtualized **>10M-row** data grid with sub-10ms FTS5 + RoaringBitmap filtering, **Quantile Milestone Seeker**, dual timezone toggle (UTC vs IST `+05:30` Court Triplet), and host-XSS/CSV-formula/BiDi RTL spoof neutralization (`HostileEvidenceSanitizer`).
   - **ChatsMasterWorkspace:** Unified bubble reconstruction (supporting **28-column PA Schema**), $O(\log N)$ Fenwick Tree dynamic-height scroller, Cross-Platform Hopping ("Follow the Suspect") Thread Stitcher, Voice-Note Waveform visualizer, and **Myers $O(ND)$ Unicode Grapheme Redline Diff Viewer** highlighting edited/revoked financial amounts (`<del>` vs `<ins>`).
   - **Synchronized 3-Pane Hex, ASCII & Data Interpreter Inspector (`SyncedHexViewer`, `EvidenceCard`):** Jumps directly to the exact `mmap` byte offset / SQLite page inside evidence files and decodes little/big endian ints, Unix/Cocoa/WebKit epochs, Varints, and raw text on hover.
   - **SQLite B-Tree Query Wizard, VFS Explorer & 4 KB Shannon Entropy Skyline (`SQLiteWizardTab`, `FileSystemExplorerTab`, `entropy_profiler.py`):** Interactive read-only SQL/table browser and Chi-Square randomness profiler distinguishing AES-encrypted ciphertexts from compressed streams and plaintext.
4. **Vendor Differential Benchmark Recorder (`tools/forensic_benchmark_recorder.py`):**
   - 5-stage diagnostic pipeline benchmarking coverage & performance against UFDR/XRY/Oxygen reports with automatic **PII sanitization** (`[Aadhaar Redacted]`, `[PAN Redacted]`) generating `COVERAGE_COMPARISON_REPORT.md` & `benchmark_telemetry_ledger.json`.

---

## 7. STATUTORY COURTROOM COMPLIANCE & LAW ENFORCEMENT OUTPUTS

1. **Section 63(4)(c) BSA 2023 Certificate (`src/legal_and_bsa/`, `src/unk_triage_and_bsa_studio/bsa_report_studio.py`, `src/main/reporting/sec63-bsa-generator.ts`):**
   - Replaces Section 65B(4) IEA 1872 while optionally rendering dual BSA/IEA headings for legacy/transitional FIRs.
   - Enforces a **Mandatory 6-Point Pre-Flight Statutory Gate**: (1) Part A Deponent & Part B Expert credentials present, (2) Pre-ingest vs Post-ingest Master Image SHA-256 bit-exact match, (3) All exhibits carry Dual SHA-256 + MD5 (`Product A` & `Product B`), (4) Immutable SHA-256 **Merkle Audit Trail** verified with 0 broken links, (5) POCSO / CSAM / Intimate media locked before defense disclosure, (6) PDF/A-3b & embedded font check.
2. **Section 230 BNSS 2023 Dual Disclosure Package (`src/dossier_and_exhibits/exhibit_packager.py`):**
   - Generates synchronized **Master Court Copy** (unredacted for Judge/FSL) alongside **Section 230 BNSS Defense Disclosure Copy** complying with *P. Gopalkrishnan v. State of Kerala (2019)* and **Section 72 BNS 2023** (anonymizing victim PII and replacing protected intimate/CSAM media with **Statutory Judicial-Inspection Notice Cards**).
3. **Golden-Hour 1930 NCRP Bank Lien Export (`src/unk_triage_and_bsa_studio/freeze_deconfliction.py`, `Ncrp1930FreezeModal.tsx`):**
   - **3-Color Safeguard De-Confliction:** Hard-locks Complainant/Victim accounts (`is_freeze_locked=True`, `freeze_checkbox_disabled=True`) so investigating officers can never accidentally freeze a victim's own bank account; automatically excludes whitelisted utility/govt billers (`irctc`, `bescom`, `billdesk`, `uppcl`, etc.); exports **14-column 1930 NCRP CFCFRMS CSV** freeze packets with SHA-256 digest.
4. **Section 94 BNSS / Section 91 CrPC Nodal Requisitions (`src/dossier_and_exhibits/nodal_freeze_and_requisitions.py`):**
   - Auto-drafts formal bank KYC, IPDR/CDR tower dump, and VDA/CEX exchange freeze requisitions grouped by crime typology (Digital Arrest, Pig Butchering, Investment Mule, Loan App Harassment).
