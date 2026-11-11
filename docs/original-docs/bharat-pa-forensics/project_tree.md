bharat-pa-forensics/
├── package.json
├── electron-builder.yml                  # Air-gapped Windows (.exe/.msi) & Linux (.AppImage) bundler
├── Cargo.toml                            # Rust workspace for high-speed binary & SQLite B-Tree carvers
│
├── native-core/                          # [RUST N-API ADDON] Zero-copy binary & carving engine
│   ├── src/
│   │   ├── lib.rs                        # Node-API bridge exposing async streaming functions to Electron
│   │   ├── vfs/                          # Virtual File System (reads 120GB .tar/.zip/.ufd without unzipping)
│   │   │   ├── tar_indexer.rs            # Builds byte-offset index of TAR archives in O_RDONLY mode
│   │   │   ├── zip_indexer.rs            # ZIP64 Central Directory random-access stream reader
│   │   │   └── ab_unpacker.rs            # Android Backup (.ab) & UFED (.ufd) metadata parser
│   │   ├── sqlite_carver/                # Lab-grade raw SQLite & WAL engine (No standard SQLite driver)
│   │   │   ├── btree_walker.rs           # Walks table interior/leaf pages & maps exact 0x hex offsets
│   │   │   ├── freeblock_carver.rs       # Carves deleted rows from unallocated cells & freeblocks
│   │   │   ├── wal_analyzer.rs           # Parses .db-wal frames to timeline historical/deleted states
│   │   │   └── sqlcipher_decrypt.rs      # Decrypts SQLCipher DBs using keys harvested from dump
│   │   ├── binary_decoders/              # Low-level binary format decoders
│   │   │   ├── protobuf_raw.rs           # Schema-less & schema-aware Protobuf wire decoder (GPay)
│   │   │   ├── telegram_tl.rs            # Telegram cache4.db TL-schema binary deserializer
│   │   │   ├── leveldb_reader.rs         # LevelDB (.ldb/.log) parser for Crypto Wallets & Chrome
│   │   │   ├── mmkv_reader.rs            # Tencent MMKV binary parser (Paytm / WeChat / Loan Apps)
│   │   │   └── dex_scanner.rs            # Scans sideloaded APK classes.dex for Telegram Bot tokens & C2 URLs
│   │   └── hash_guard/
│   │       └── dual_hasher.rs            # Multi-threaded SHA-256 + MD5 pre/post ingestion verifier
│
├── src/
│   ├── main/                             # [ELECTRON MAIN PROCESS]
│   │   ├── index.ts                      # App lifecycle, strict CSP, network-blocker (100% air-gap enforcement)
│   │   ├── ipc/                          # Typed IPC channels (Ingestion, Query, HexStream, Export)
│   │   ├── case_manager/
│   │   │   ├── case_db.ts                # Per-case SQLite + FTS5 database manager
│   │   │   ├── audit_logger.ts           # Tamper-evident chain-of-custody & examiner action logger
│   │   │   └── timestamp_engine.ts       # Dual-timezone normalizer (Raw Epoch/WebKit -> UTC -> IST +05:30)
│   │   ├── licensing/
│   │   │   └── hardware_lock.ts          # Offline Ed25519 license check bound to Motherboard UUID + CPU ID
│   │   │
│   │   ├── parsers/                      # [MODULAR ARTIFACT PARSER REGISTRY]
│   │   │   ├── registry.ts               # Auto-matches VFS file paths & magic bytes to parser plugins
│   │   │   ├── keystore/
│   │   │   │   ├── whatsapp_key.ts       # Extracts WhatsApp crypt14/15 AES keys from /files/key
│   │   │   │   └── shared_prefs_keys.ts  # Harvests SQLCipher/Tink keys from XML & plist files
│   │   │   ├── indian_upi/               # Dedicated Indian Payment Ecosystem Parsers
│   │   │   │   ├── phonepe.parser.ts     # TransactionsStore, Foxtrot, Ghost Intents, TxID timestamp decoder
│   │   │   │   ├── gpay_india.parser.ts  # paisa.db + nested Protobuf payment & chat decoder
│   │   │   │   ├── paytm.parser.ts       # Passbook SQLite + MMKV cache decoder
│   │   │   │   ├── bhim_npci.parser.ts   # BHIM UPI & collect request logs
│   │   │   │   └── cred_wallets.parser.ts# CRED, Amazon Pay, Mobikwik, Freecharge parsers
│   │   │   ├── indian_banking/           # Banking App & OS Spillover Correlation Engine
│   │   │   │   ├── sbi_yono.parser.ts    # YONO SBI, HDFC, ICICI iMobile, Axis, Fino, Airtel Payments Bank
│   │   │   │   ├── sms_dlt_ledger.ts     # TRAI DLT SMS header parser -> builds structured UTR & balance ledger
│   │   │   │   ├── notif_spillover.ts    # Extracts deleted banking/UPI alerts from notification_log.db
│   │   │   │   └── upi_correlator.ts     # Merges App DB + SMS + Notification + OCR into 1 Master Transaction
│   │   │   ├── cybercrime_apps/          # Criminal & Mule Infrastructure Parsers
│   │   │   │   ├── sms_forwarder_apk.ts  # Detects OTP-stealing Mule APKs & extracts Telegram Bot C2 IDs
│   │   │   │   ├── remote_access.parser.ts # AnyDesk (ad_svc.trace), TeamViewer, RustDesk session logs
│   │   │   │   ├── crypto_wallets.ts     # Binance P2P, TrustWallet, TronLink (USDT TRC-20) LevelDB parsers
│   │   │   │   └── multi_user_clones.ts  # Android User 10/999 (Dual Apps / Secure Folder / Vaults)
│   │   │   └── messengers/
│   │   │       ├── whatsapp.parser.ts    # msgstore.db, wa.db, pay.db (WhatsApp UPI), view-once tracking
│   │   │       ├── telegram.parser.ts    # cache4.db TL-schema chats, secret chats, media cache
│   │   │       └── signal_session.ts     # Signal & Session messenger parsers
│   │   │
│   │   ├── intelligence/                 # [OFFLINE AI, OCR & REGEX CORRELATION]
│   │   │   ├── ocr_worker.ts             # Offline ONNX/Tesseract pipeline for UPI screenshot & QR decoding
│   │   │   ├── indian_lea_regex.ts       # Pre-compiled extractors: 12-digit UTR, VPA, IFSC, PAN, Crypto, IMEI
│   │   │   └── mule_graph_engine.ts      # Builds Node-Link money trail & common-contact graphs
│   │   │
│   │   └── reporting/
│   │       ├── sec63_bsa_generator.ts    # Auto-generates Part A & Part B Section 63 BSA (2023) PDF Certificates
│   │       └── ufdr_exporter.ts          # Exports court-ready HTML/PDF/XLSX reports with byte offsets
│   │
│   └── renderer/                         # [PHYSICAL ANALYZER REPLICA UI - REACT + TAILWIND]
│       ├── workspace/
│       │   ├── PAWorkbench.tsx           # 4-Pane Dockable Layout (Project Tree, Center Tabs, Provenance, Hex)
│       │   ├── TopRibbonBar.tsx          # PA-style ribbon toolbar with quick filters & hash status badge
│       │   └── ProjectTreeDock.tsx       # Left hierarchical tree: Analyzed Data, UPI Hub, File System, Keys
│       ├── views/
│       │   ├── ExtractionSummaryTab.tsx  # Device metadata, Dual-Hashes, Detected High-Risk Apps & Mule Alerts
│       │   ├── ArtifactTableGrid.tsx     # Virtualized 1M-row grid with [Active / WAL / Carved] badges
│       │   ├── ChatBubbleView.tsx        # PA-style WhatsApp/Telegram/GPay chat thread + inline payment cards
│       │   ├── UPIMasterLedgerView.tsx   # Unified financial ledger correlating App + SMS + Notification + OCR
│       │   ├── MuleLinkGraphTab.tsx      # Interactive visual graph of VPA -> Bank A/c -> Crypto USDT hops
│       │   ├── SQLiteWizardTab.tsx       # Built-in PA-style visual SQLite & Freeblock explorer
│       │   └── FileSystemExplorerTab.tsx # Raw VFS tree browser with previewer & plist/proto tree view
│       └── inspectors/
│           ├── ProvenanceSidebar.tsx     # Right pane: File path, Table, Page, Offset, Raw/UTC/IST timestamps
│           └── SyncedHexViewer.tsx       # Bottom pane: Virtualized Hex/ASCII viewer highlighting selected row