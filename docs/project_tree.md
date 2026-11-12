# BharatAnalyzer Sovereign Forensics Suite — Complete Project Tree (`project_tree.md`)

> **Merged Root:** `E:\v8\combined\` | **Frontend / Desktop / Packaging Workspace:** `E:\v8\combined\bharat-pa-forensics\`
> **Tree Exclusions:** Virtual environments (`.venv/`, `venv/`), `node_modules/`, Git internals (`.git/`), Python bytecode (`__pycache__/`), build/dist/test caches (`dist/`, `build/`, `build_backend/`, `dist_backend/`, `dist-test/`, `.pytest_cache/`, `.ruff_cache/`, `.workspace_tmp/`), and multi-thousand-file installer output inside `bharat-pa-forensics/release/` are intentionally excluded/summarized for clarity.

---

## 1. MERGED WORKSPACE ARCHITECTURE OVERVIEW

The merged project follows a unified **two-tier workspace layout**:
1. **`E:\v8\combined\` (Canonical Backend & Verification Root):**
   - `src/` — **40** consolidated forensic domain packages (**286 Python files**, incl. static assets in `workstation_app/static/`), strictly containing the newest merged & remediated versions (17 modules upgraded over legacy `Bharart Analyzer/src/`).
   - `parsers/` — **32** consolidated high-throughput extraction, SQLite/WAL carving, custodial crypto, graph intelligence, `CaseUIPaginatorStore` FTS5 pagination, and FastAPI REST API modules.
   - `electron/` — Unified Electron 45 desktop main & preload scripts (`main.cjs`, `preload.cjs`).
   - `tools/` — Automated 5-Stage Vendor Differential Benchmark Recorder (`forensic_benchmark_recorder.py`).
   - `tests/` — Consolidated **68 Python test modules** (42 phased suites + 16 4-Tier E2E runner suites + M2–M5 adversarial stress suites + REST API & challenger verifiers).
   - `test_evidence/` — Ground-truth binary fixtures (`msgstore.db`, `paisa.db`, `test_disk.dd`, `android_logical_extraction.zip`, etc.).
2. **`E:\v8\combined\bharat-pa-forensics\` (React 19 UI, TypeScript Engine & Packaging Workspace):**
   - Hosts Node/Vite/Tailwind v4/TypeScript (`package.json`, `vite.config.ts`, `tsconfig.json`, `tailwind.config.js`), PyInstaller (`bharat_backend.spec`), Electron Builder (`electron-builder.yml`), Python `.venv/`, Node `node_modules/`, orchestration `scripts/`, **29 React 19 UI files (`src/renderer/`)**, **48 offline TypeScript engine modules (`src/main/`, `src/shared/`)**, **10 TypeScript test suites (`src/tests/`)**, and **10 unique hardened parity/API/TS unit tests (`tests/`)**.

---

## 2. VERIFIED UNIFIED DIRECTORY TREE (`E:\v8\combined\`)

```text
E:\v8\combined\
├── .gitignore
├── MERGE_STATE.md                                  # Persistent audit & merge verification state ledger
├── abilities.md                                    # Exhaustive capability & supported apps inventory
├── architecture.md                                 # Full-stack technical & statutory architecture specification
├── command.md                                      # Unified setup, execution, packaging & test CLI manual
├── project_tree.md                                 # This verified project tree document
├── TEST_INFRA.md                                   # (Teamwork artifact) E2E test infrastructure audit
├── TEST_READY.md                                   # (Teamwork artifact) Test readiness verification report
├── .agents/                                        # Teamwork workflow & verification handoff metadata
│
├── electron/                                       # Native Electron 45 desktop wrapper (unified root copy)
│   ├── main.cjs                                    # Main process: spawns FastAPI :8000, manages IPC & taskkill cleanup
│   └── preload.cjs                                 # contextBridge exposing window.electronAPI native OS dialogs
│
├── tools/                                          # Forensic diagnostics & vendor benchmarking
│   ├── __init__.py
│   └── forensic_benchmark_recorder.py              # 5-Stage benchmark vs Cellebrite/XRY/Oxygen + PII sanitizer
│
├── parsers/                                        # High-throughput API, 1 TB+ VFS, FTS5 & Indian/Social Parsers (32 files)
│   ├── __init__.py                                 # Package initializer + SQLite identifier safety helpers
│   ├── account_profiler.py                         # Owner identity profiler & Master Owner Dossier builder
│   ├── api_server.py                               # FastAPI REST engine (31 endpoints, Port 8000, concurrency locks)
│   ├── app_overrides.py                            # Per-app schema overrides, Indian bank SMS rules & spam blocker
│   ├── chat_social_privacy_parsers.py              # PA-grade WhatsApp, Telegram TL, Signal, Zangi, Element, Session parsers
│   ├── commercial_parity_engine.py                 # Recursive LZ4/CBOR/MsgPack/NSKeyedArchiver unpacker + App Genie + mmap carver
│   ├── corroboration_engine.py                     # Multi-source signal harvester, RCS split-table joiner & counterparty healer
│   ├── corrupt_db_carver.py                        # Raw SQLite corrupted page carver & regression fault simulator
│   ├── crypto_address_validator.py                 # Byte-level EVM EIP-55, TRON, Bitcoin Base58/Bech32 validators
│   ├── crypto_p2p_parser.py                        # Global & Indian CEX P2P order/escrow extractor
│   ├── custodial_wallet_parser.py                  # 15 Custodial Wallet manifests (Tier 1 & 2) across 7 normalized classes
│   ├── deep_sqlite.py                              # Deep PhonePe/WhatsApp SQLite & Zlib/Protobuf blob inspector
│   ├── enterprise_1tb_chat_and_container_engine.py # Zero-OOM 1 TB+ streaming container engine & 28-col PA chat schema
│   ├── ewf_adapter.py                              # EnCase (.E01/.Ex01/.L01) pyewf + pytsk3 extent adapter
│   ├── fiat_crypto_bridge.py                       # Temporal/amount INR UPI <-> USDT P2P / custodial alignment engine
│   ├── freelist_carver.py                          # SQLite B-Tree unallocated cell & freelist carver
│   ├── graph_intelligence.py                       # NetworkX syndicate roles, mule alerts, charge-sheet chain & PyVis HTML
│   ├── heuristic_engine.py                         # Multi-table heuristic transaction/chat/contact extractor & deduplicator
│   ├── keychain_decryptor.py                       # In-memory keyring & SQLCipher v3/v4 page decryptor
│   ├── leveldb_parser.py                           # Pure-Python LevelDB SSTable / log carver & classifier
│   ├── multi_source_fusion.py                      # Bank CSV/XLSX reconciliation + Telecom CDR (+-15 min) fusion
│   ├── npci_storage_carver.py                      # Non-SQLite Protobuf/MMKV & upi://pay NPCI protocol carver
│   ├── os_privacy_spillover.py                     # Notification log, keyboard/clipboard & App Switcher snapshot carver
│   ├── plugin_loader.py                            # AppPlugin & PluginRegistry hosting 80 app manifests
│   ├── protobuf_decoder.py                         # Schema-less raw wire-format Protobuf & schema synthesizer
│   ├── social_interaction_comms_parsers.py         # 15 Social, Messenger, Discord, Skype, Teams, Asian VoIP & Truecaller parsers
│   ├── ui_fts5_paginator.py                        # CaseUIPaginatorStore: 12 SQLite tables + 6 FTS5 virtual tables (<10ms paging)
│   ├── vpa_harvester.py                            # Raw-byte VPA & RBI IFSC harvester + Indian mobile validator
│   ├── wal_rollback_analyzer.py                    # 4-state WAL checksum verifier & multi-revision frame differ
│   ├── wallet_deleted_recovery.py                  # Custodial wallet deleted/unallocated row carver
│   ├── wallet_provenance.py                        # Wallet container/path provenance tracker
│   └── zero_knowledge_miner.py                     # Unsupervised financial/chat discovery across unknown SQLite tables
│
├── src/                                            # Core Deep Forensic Kernel (40 Sub-Packages, 286 Python files)
│   ├── __init__.py
│   ├── android_telemetry/                          # Android behavioral telemetry & AppOps (6 files)
│   │   ├── __init__.py
│   │   ├── appops_decoder.py                       # 3-source ABX AppOps privacy sensor auditor
│   │   ├── engine.py                               # AndroidTelemetryEngine orchestrator
│   │   ├── health_connect_decoder.py               # Android Health Connect & Netstats decoder
│   │   ├── models.py
│   │   ├── usagestats_decoder.py                   # UsageStats daily binary Protobuf & XML decoder
│   │   └── wellbeing_decoder.py                    # Google Digital Wellbeing & Samsung Forest decoder
│   ├── antiforensics/                              # OS tamper, clock rollback, Mock GPS & APK trojans (6 files)
│   │   ├── __init__.py
│   │   ├── clock_gap_detector.py                   # ROWID clock-rollback, TIME_SET & sequence gap detector
│   │   ├── engine.py                               # AntiForensicsEngine master orchestrator
│   │   ├── integrity_auditor.py                    # Bootloader, Magisk/Zygisk, KernelSU, APatch, LSPosed, TrollStore audit
│   │   ├── location_spoof_auditor.py               # Mock GPS packages, OP_58 & sensor contradiction engine
│   │   ├── malware_auditor.py                      # APK trojan, Telegram/Firebase C2, USSD hijack (*21*/*401*), AnyDesk trace
│   │   └── models.py
│   ├── banking/                                    # PSU, Private, Corporate, AePS, IFSC & PDF Unlocker (6 files)
│   │   ├── __init__.py
│   │   ├── cardless_runner.py                      # Cardless ATM cash-out token & runner correlator
│   │   ├── engine.py                               # IndianBankingSandboxEngine (35+ banks, Corporate, AePS, RD scanners)
│   │   ├── ifsc_resolver.py                        # Offline 11-char RBI IFSC branch & jurisdiction resolver
│   │   ├── models.py
│   │   ├── narration_parser.py                     # NEFT/RTGS/IMPS/UPI core banking narration extractor
│   │   └── pdf_unlocker.py                         # Deterministic bank statement PDF password cracker & RC4 decryptor
│   ├── binding/                                    # SIM, eSIM, VMN SMS & NPCI Common Library Vault (6 files)
│   │   ├── __init__.py
│   │   ├── cl_vault.py                             # NPCI CL vault & hardware keystore binding audit
│   │   ├── engine.py                               # SIMBindingForensicEngine
│   │   ├── models.py
│   │   ├── sms_audit.py                            # Outbound VMN verification & binary port SMS decoder
│   │   ├── telephony.py                            # Dual-SIM ICCID/IMSI historical ledger decoder
│   │   └── trojan_detector.py                      # 3-point Ghost SIM-Binding Trojan detector
│   ├── cex/                                        # Global & Domestic Indian FIU-IND Exchanges (4 files)
│   │   ├── __init__.py
│   │   ├── binance.py                              # Binance, Bybit & KuCoin MMKV L1/L2 + P2P escrow + triangulation fraud
│   │   ├── engine.py                               # CEXAndP2PExchangeEngine
│   │   ├── indian_cex.py                           # CoinDCX, WazirX, CoinSwitch, Mudrex, ZebPay, Flitpay + Sec 194S TDS
│   │   └── models.py
│   ├── chat_reconstructor_and_redline/             # Fenwick Scroller, Myers Diff & Audio Waveforms (6 files)
│   │   ├── __init__.py
│   │   ├── audio_waveform_processor.py             # Offline voice-note peak waveform & transcript cache
│   │   ├── engine.py                               # UnifiedChatReconstructorEngine
│   │   ├── fenwick_scroller.py                     # O(log N) Binary Indexed Tree variable-height bubble scroller
│   │   ├── hopping_timeline_stitcher.py            # Cross-platform "Follow the Suspect" hopping timeline stitcher
│   │   ├── models.py
│   │   └── myers_redline_engine.py                 # Unicode grapheme-aware Myers SES diff engine (<del>/<ins>)
│   ├── core/                                       # Shared Core Invariants (3 files)
│   │   ├── __init__.py
│   │   ├── enums.py                                # 5D Matrix, 6-Tier Confidence, 18 Forensic Groups (G01-G18), C2PA tiers
│   │   ├── sqlite_manager.py                       # Thread-safe SQLite connection pool (WAL, busy_timeout=30s)
│   │   └── timestamps.py                           # Multi-epoch ForensicTimestamp & IST (+05:30) Court Triplet
│   ├── correlator/                                 # 4-Way UTR Validation & Fraud Ring Detection (5 files)
│   │   ├── __init__.py
│   │   ├── engine.py                               # FinancialCorrelatorEngine
│   │   ├── fraud_detector.py                       # Smurfing, mule-ring burst, circular loop & balance gap detector
│   │   ├── models.py
│   │   ├── utr_validator.py                        # 12-digit NPCI Julian UTR vs UIDAI Aadhaar Verhoeff disambiguator
│   │   └── vpa_resolver.py                         # Master VPA suffix/PSP routing & identity graph builder
│   ├── crypto/                                     # Cryptographic Key Broker (7 files)
│   │   ├── __init__.py
│   │   ├── applenotes.py                           # Apple Notes RFC 3394 + AES-128-GCM decryptor
│   │   ├── engine.py                               # CryptographicKeyBrokerEngine
│   │   ├── keyring.py                              # iOS Keychain & Android Keystore credential harvester
│   │   ├── models.py
│   │   ├── sqlcipher.py                            # Universal page-level SQLCipher (v1-v4) & WCDB decryptor
│   │   ├── wcdb.py                                 # WeChat EnMicroMsg.db IMEI+UIN password derivation
│   │   └── whatsapp.py                             # WhatsApp .crypt12/.crypt14/.crypt15 decryptor
│   ├── dlt/                                        # TRAI DLT Financial SMS & OS Notifications (6 files)
│   │   ├── __init__.py
│   │   ├── attributed_body.py                      # iOS NSAttributedString typedstream unpacker
│   │   ├── dlt_headers.py                          # TRAI 6-char DLT header parser, circle resolver & SMSC spoof check
│   │   ├── engine.py                               # DLTFinancialSMSNotificationEngine
│   │   ├── models.py
│   │   ├── notifications.py                        # Android/iOS OS financial notification ledger parser
│   │   └── sms_grammar.py                          # 10-category financial SMS extraction grammar
│   ├── dossier_and_exhibits/                       # Crime Dossiers, Sec 94 & Sec 230 BNSS Packaging (5 files)
│   │   ├── __init__.py
│   │   ├── dossier_builder.py                      # Crime-typology dossier builder
│   │   ├── engine.py                               # DossierAndExhibitPackagerEngine
│   │   ├── exhibit_packager.py                     # Air-gapped Sec 230 BNSS defense copy packager & POCSO shield
│   │   ├── models.py
│   │   └── nodal_freeze_and_requisitions.py        # Nodal freeze sheets & Sec 94 BNSS / Sec 91 CrPC requisitions
│   ├── entity_and_timeline/                        # DSU Entity Resolution & 50M+ Super-Timeline (6 files)
│   │   ├── __init__.py
│   │   ├── action_burst_correlator.py              # Sliding-window 5-minute multi-channel behavioral burst correlator
│   │   ├── edge_synthesizer.py                     # Typed directed graph edge synthesizer
│   │   ├── engine.py                               # EntityGraphAndTimelineEngine
│   │   ├── entity_resolver.py                      # Constrained Disjoint-Set Union (DSU) entity resolver
│   │   ├── models.py
│   │   └── super_timeline.py                       # Nanosecond-normalized unified super-timeline builder
│   ├── evidentiary/                                # 5D Matrix, Tripartite Ledger & UNK Sweeper (5 files)
│   │   ├── __init__.py
│   │   ├── engine.py                               # EvidentiaryStateEngine
│   │   ├── enums.py                                # Dim A-E enums, R1-R6 maturity, Tripartite state, UNK storage formats
│   │   ├── ledger.py                               # Tripartite ledger DB & G01-G18 group rollup
│   │   ├── models.py
│   │   └── sweeper.py                              # Unclassified & unparsed artifacts sweeper (UNK & PHY)
│   ├── financial_graph_and_storyboard/             # WebGL2 Force Graph, Sankey & Freeze Cart (6 files)
│   │   ├── __init__.py
│   │   ├── action_burst_storyboard.py              # 5-swimlane 60-second kinetic behavioral storyboard
│   │   ├── engine.py                               # FinancialGraphAndStoryboardEngine
│   │   ├── freeze_cart_manager.py                  # Polygon lasso nodal freeze cart manager
│   │   ├── graph_physics_engine.py                 # Barnes-Hut Quadtree WebGL2 physics + circular loop detector
│   │   ├── models.py
│   │   └── sankey_canvas.py                        # Interactive 5-stage Rupee-to-USDT SVG Sankey canvas
│   ├── geolocation/                                # Multi-Tier Spatial, Radio & Cellular Engine (5 files)
│   │   ├── __init__.py
│   │   ├── cellular_decoder.py                     # LTE ECI / 5G NCI CGI tower decoder & radio handshake auditor
│   │   ├── engine.py                               # GeolocationEngine
│   │   ├── google_timeline_decoder.py              # Android Google Timeline & Maps navigation decoder
│   │   ├── ios_location_decoder.py                 # iOS cache_encryptedB.db & routined Significant Locations
│   │   └── models.py
│   ├── geospatial_media_and_tamper/                # PMTiles Map, dHash, Bilingual OCR & Tamper Modal (7 files)
│   │   ├── __init__.py
│   │   ├── bilingual_ocr_engine.py                 # Hindi (hin) + English (eng) OCR + Devanagari numeral normalizer
│   │   ├── engine.py                               # GeospatialMediaAndTamperEngine
│   │   ├── hybrid_map_geocoder.py                  # OSM Nominatim SQLite cache + 66-city Indian Gazetteer + SVG grid
│   │   ├── models.py
│   │   ├── perceptual_dhash_clustering.py          # 64-bit dHash Hamming-distance image clusterer
│   │   ├── pmtiles_map_engine.py                   # Offline PMTiles v3 Web Mercator projection engine
│   │   └── tamper_inspector_modal.py               # 3-mode curtain-wipe & forgery inspector
│   ├── high_opsec/                                 # Decentralized & Privacy Messengers (6 files)
│   │   ├── __init__.py
│   │   ├── cross_app_hunter.py                     # Cross-app covert handle & invite URI hunter
│   │   ├── engine.py                               # HighOpSecMessengersEngine
│   │   ├── models.py
│   │   ├── privacy_messengers_decoder.py           # Zangi, XMPP/Conversations OMEMO, Threema, Element/Matrix, Briar
│   │   ├── session_decoder.py                      # Session onion messenger SQLCipher & 66-hex ID decoder
│   │   └── simplex_decoder.py                      # SimpleX zero-ID smp:// queue & item_deleted carver
│   ├── hyperlocal_travel/                          # Indian Delivery, Mobility, Rail/Air & Dating (6 files)
│   │   ├── __init__.py
│   │   ├── dating_decoder.py                       # 13+ dating/matrimonial platforms + Passport spoof + WAL recovery
│   │   ├── delivery_decoder.py                     # Swiggy/Genie, Zomato, Blinkit, Zepto, Flipkart, Amazon, Porter, Borzo
│   │   ├── engine.py                               # HyperlocalTravelDatingEngine
│   │   ├── mobility_decoder.py                     # Uber, Ola, Rapido, Namma Yatri, InDrive, BluSmart + Polyline unpacker
│   │   ├── models.py
│   │   └── travel_decoder.py                       # IRCTC, Where is My Train, UTS & DigiYatra IATA BCBP decoder
│   ├── identity/                                   # OS Container, UID, Clone & Ghost App Resolvers (5 files)
│   │   ├── __init__.py
│   │   ├── abx.py                                  # Android Binary XML (ABX) decoder for packages.xml
│   │   ├── android.py                              # Android Linux UID, multi-user & clone profile resolver
│   │   ├── catalog.py                              # IdentitySandboxCatalog database
│   │   ├── ghost.py                                # Uninstalled ghost app residual detector
│   │   └── ios.py                                  # iOS MCM plist UUID <-> Bundle ID & Shared App Group resolver
│   ├── ios_telemetry/                              # iOS Behavioral Pattern-of-Life & Logs (7 files)
│   │   ├── __init__.py
│   │   ├── biome_screentime_decoder.py             # Biome SEGB v1/v2 (84 streams) + RMAdminStore Screen Time
│   │   ├── coreduet_decoder.py                     # CoreDuet knowledgeC.db relational + binary plist decoder
│   │   ├── engine.py                               # IOSTelemetryEngine
│   │   ├── fsevents_decoder.py                     # APFS /.fseventsd/ 1SLG/2SLG binary parser & gap detector
│   │   ├── health_decoder.py                       # Apple Health healthdb_secure.sqlite step/flight alibi auditor
│   │   ├── models.py
│   │   └── unified_logs_orientation_decoder.py     # .tracev3 Unified Logs & physical vs display orientation
│   ├── kyc_and_ocr/                                # Indian KYC Validation, Homoglyph & Seed Grid OCR (6 files)
│   │   ├── __init__.py
│   │   ├── engine.py                               # VisualKYCAndOCREngine
│   │   ├── financial_instrument_extractor.py       # Bank cheques, DD, passbooks & bearer token extractor
│   │   ├── homoglyph_normalizer.py                 # Position-constrained OCR homoglyph corrector
│   │   ├── kyc_validator.py                        # PAN, Aadhaar Verhoeff D5, Passport TD3 MRZ, GSTIN Mod-36 validators
│   │   ├── models.py
│   │   └── seed_grid_reconstructor.py              # Grid-aware 12/24-word BIP-39 screenshot reconstructor
│   ├── legal_and_bsa/                              # Section 63(4)(c) BSA 2023 & Merkle Chain (5 files)
│   │   ├── __init__.py
│   │   ├── bsa_certificate_generator.py            # Statutory Part A & Part B BSA Sec 63 certificate generator
│   │   ├── chain_of_custody.py                     # Tamper-evident SHA-256 Merkle Chain-of-Custody ledger
│   │   ├── engine.py                               # LegalComplianceAndBsaEngine
│   │   ├── hash_manifest.py                        # Hierarchical manifest & Merkle root builder
│   │   └── models.py
│   ├── media_library/                              # OS Photos & C2PA Media Provenance (5 files)
│   │   ├── __init__.py
│   │   ├── android_mediaprovider_decoder.py        # Android external.db, Scoped Storage trash & Google Photos
│   │   ├── binary_provenance_carver.py             # Android Motion Photo MP4 carver, Live Photo pairing, C2PA boxes
│   │   ├── engine.py                               # OSMediaLibraryEngine
│   │   ├── ios_photos_decoder.py                   # iOS Photos.sqlite & Syndication.sqlite deep relational decoder
│   │   └── models.py
│   ├── nonsqlite/                                  # Universal Binary K-V & Protobuf Storage Engines (8 files)
│   │   ├── __init__.py
│   │   ├── engine.py                               # NonSQLiteForensicEngine
│   │   ├── leveldb.py                              # Google LevelDB / IndexedDB .ldb/.log/tombstone decoder
│   │   ├── mmkv.py                                 # Tencent MMKV append-history & mmap slack carver
│   │   ├── models.py
│   │   ├── protobuf.py                             # Schema-less raw wire-format Protobuf decoder
│   │   ├── segb.py                                 # Apple Biome SEGB v1/v2 stream parser
│   │   ├── snappy.py                               # Pure-Python Snappy block decompressor
│   │   └── varint.py                               # LEB128 varint & 64-bit ZigZag decoder
│   ├── provenance/                                 # Dual Hashing, Security Attributes & Timestamps (4 files)
│   │   ├── __init__.py
│   │   ├── hasher.py                               # Product A & Product B Dual SHA-256 + vendor log verifier
│   │   ├── ledger.py                               # Immutable courtroom provenance ledger
│   │   ├── security.py                             # POSIX/SELinux xattr, permissions & timestomp decoder
│   │   └── timestamps.py                           # 5-epoch timestamp normalizer & 5-column court schema
│   ├── qr_and_receipts/                            # Aadhaar QR, BharatQR & Receipt Forgery Detector (5 files)
│   │   ├── __init__.py
│   │   ├── aadhaar_unpacker.py                     # UIDAI BigInt -> Gzip -> JPEG-2000 face & VTC extractor
│   │   ├── barcode_qr_engine.py                    # BarcodeAndReceiptForensicEngine
│   │   ├── forged_receipt_detector.py              # 5-point fake UPI/bank receipt APK & Julian date detector
│   │   ├── models.py
│   │   └── upi_bharatqr_unpacker.py                # upi://pay & EMVCo BharatQR recursive TLV unpacker
│   ├── seedhunter/                                 # BIP-39 / Monero Seed Hunter & Fiat-Crypto Bridge (7 files)
│   │   ├── __init__.py
│   │   ├── bip39_wordlist.py                       # Embedded offline 2048-word BIP-39 & Monero dictionaries
│   │   ├── correlator.py                           # 4-way Rupee-to-USDT laundering chain correlator
│   │   ├── engine.py                               # SeedHunterCorrelatorEngine
│   │   ├── hd_derivator.py                         # Offline BIP-32, BIP-44, BIP-84 & SLIP-0010 derivation
│   │   ├── models.py
│   │   ├── seed_hunter.py                          # Cross-system mnemonic, Monero 25-word, WIF & raw key hunter
│   │   └── vault_unwrapper.py                      # Web3 keystore v3 (scrypt/PBKDF2) & MetaMask vault unwrapper
│   ├── social_voip/                                # Social Media, Handler VoIP & Burner Bridge (6 files)
│   │   ├── __init__.py
│   │   ├── burner_bridge.py                        # +1/+44 virtual burner OTP -> WA/TG profile linker
│   │   ├── cross_border_voip_decoder.py            # Botim, IMO, WeChat, LINE, Viber decoders
│   │   ├── engine.py                               # SocialVoIPBurnerEngine
│   │   ├── meta_decoder.py                         # Instagram Direct & Facebook Messenger/Armadillo decoder
│   │   ├── models.py
│   │   └── snapchat_discord_decoder.py             # Snapchat arroyo.db + Discord Snowflake/SimpleCache decoder
│   ├── sqlite/                                     # Low-Level SQLite Forensics (9 files)
│   │   ├── __init__.py
│   │   ├── carver.py                               # 4-zone B-tree carver with Indian VPA/UTR/INR domain filters
│   │   ├── engine.py                               # ForensicSQLiteEngine master coordinator
│   │   ├── header.py                               # 100-byte DB header & B-Tree page header parser
│   │   ├── journal.py                              # Rollback -journal sector header & page reader
│   │   ├── models.py
│   │   ├── overflow.py                             # Bounded overflow page chain reassembler
│   │   ├── record.py                               # Record header & 13 serial-type payload decoder
│   │   ├── varint.py                               # 9-byte Big-Endian SQLite varint codec
│   │   └── wal.py                                  # Shared WAL header, checksum & 4-state frame classifier
│   ├── telegram_signal/                            # Telegram & Signal Deep Decoders (5 files)
│   │   ├── __init__.py
│   │   ├── engine.py                               # TelegramSignalEngine
│   │   ├── models.py
│   │   ├── signal_decoder.py                       # Signal Android/iOS signal.db / Signal.sqlite decoder
│   │   ├── telegram_decoder.py                     # cache4.db, userconfig.xml multi-slot & dialog UID unpacker
│   │   └── tl_deserializer.py                      # Telegram MTProto Type Language (TL) binary stream reader
│   ├── unified_chat/                               # Truecaller, Marketplaces, Betting & Correlator (5 files)
│   │   ├── __init__.py
│   │   ├── correlator.py                           # Cross-platform actor resolution & thread stitching
│   │   ├── covert_and_betting_decoder.py           # LiveChat/Tawk.to betting, Keep/Docs/Notes dead-drops, OLX/ShareChat
│   │   ├── engine.py                               # RegionalCovertUnifiedChatEngine
│   │   ├── models.py
│   │   └── truecaller_decoder.py                   # Truecaller tc.db spam/caller-ID + msg.db IM/SMS/Flash decoder
│   ├── unk_triage_and_bsa_studio/                  # Entropy Profiler, Schema Promoter, Hot-Patcher & BSA Studio (7 files)
│   │   ├── __init__.py
│   │   ├── bsa_report_studio.py                    # WYSIWYG Court Master vs Sec 230 BNSS dual HTML + 6-point gate
│   │   ├── engine.py                               # UnkTriageAndBsaStudioMasterEngine
│   │   ├── entropy_profiler.py                     # 4 KB sliding-window Shannon entropy & Chi-Square histogrammer
│   │   ├── freeze_deconfliction.py                 # 3-tier victim/utility safeguard lock + 14-col 1930 NCRP CSV
│   │   ├── key_broker_hotpatcher.py                # <3.0s 5-step incremental DAG key-broker hot-patcher
│   │   ├── models.py
│   │   └── schema_mapper.py                        # Zero-Code unknown SQLite/Protobuf column promoter
│   ├── upi/                                        # Indian UPI Super-Apps & QR Decoders (7 files)
│   │   ├── __init__.py
│   │   ├── engine.py                               # UPISuperAppForensicEngine
│   │   ├── gpay.py                                 # Google Pay paisa.db / Money Protobuf decoder
│   │   ├── models.py
│   │   ├── paytm.py                                # Paytm passbook & order history decoder
│   │   ├── phonepe.py                              # PhonePe Zlib JSON, Bullhorn P2P & TID clock check
│   │   ├── qr.py                                   # Universal upi://pay & EMVCo BharatQR TLV parser
│   │   └── whatsapp_pay.py                         # WhatsApp Pay (amount_1000) & BHIM/FamPay/CRED decoder
│   ├── validators/                                 # Cryptographic Address Checksums & ABI Calldata (5 files)
│   │   ├── __init__.py
│   │   ├── abi_unpacker.py                         # ERC-20/TRC-20 transfer & swap ABI calldata decoder
│   │   ├── address_validators.py                   # Pure-Python Keccak-256 EIP-55, Base58Check, Bech32 validators
│   │   ├── engine.py                               # ValidatorsAndABIEngine
│   │   ├── models.py
│   │   └── walletconnect.py                        # WalletConnect v2 dApp session & unlimited-approval drainer audit
│   ├── vfs/                                        # Zero-Extraction Virtual Filesystem Substrate (4 files)
│   │   ├── __init__.py
│   │   ├── fingerprint.py                          # Magic-byte container fingerprinter
│   │   ├── indexer.py                              # ZIP/TAR/AB/UFED/iOS backup VFS indexer (AbUnpacker, UfdParser)
│   │   ├── normalizer.py                           # CanonicalPathNormalizer across Android/iOS/OEM roots
│   │   └── reader.py                               # Range-streaming VFSReader & StagedSQLiteFamily coordinator
│   ├── visual_residuals/                           # Task Snapshots, Image Caches & Vault Unmasker (5 files)
│   │   ├── __init__.py
│   │   ├── app_switcher_decoder.py                 # iOS SplashBoard KTX & Android TaskSnapshot Protobuf decoder
│   │   ├── engine.py                               # VisualResidualsEngine
│   │   ├── models.py
│   │   ├── thumbnail_cache_reconstructor.py        # iOS .ithmb + Android Glide/Fresco/Coil/DiskLruCache reconstructor
│   │   └── vault_unmasker.py                       # KPA XOR/byte-swap/header unmasker for Calculator & NQ Vaults
│   ├── web3/                                       # Self-Custody Web3 Wallet Decoders (8 files)
│   │   ├── __init__.py
│   │   ├── address_utils.py                        # Base58Check <-> hex41 & BigInt token math
│   │   ├── cakewallet.py                           # Cake Wallet & Monero (XMR) decoder
│   │   ├── engine.py                               # Web3SelfCustodyWalletsEngine
│   │   ├── ledgerlive.py                           # Ledger Live hardware companion decoder
│   │   ├── metamask.py                             # MetaMask Mobile recursive JSON/vault extractor
│   │   ├── models.py
│   │   ├── tronlink.py                             # TronLink Pro TRC-20 USDT sandbox decoder
│   │   └── trustwallet.py                          # Trust Wallet multi-coin keystore decoder
│   ├── webview/                                    # Embedded Browser & HTTP Cache Forensics (7 files)
│   │   ├── __init__.py
│   │   ├── binarycookies.py                        # Apple Cookies.binarycookies hybrid-endian parser
│   │   ├── crawler.py                              # WebViewForensicEngine
│   │   ├── jwt.py                                  # JWT Base64URL header/payload claims unpacker
│   │   ├── localstorage.py                         # Chromium LevelDB & iOS WebKit LocalStorage decoder
│   │   ├── models.py
│   │   ├── nsurlcache.py                           # iOS Cache.db + fsCachedData/<UUID> payload correlator
│   │   └── simplecache.py                          # Chromium Simple Cache (*_0/*_1/*_s) binary parser
│   ├── whatsapp/                                   # Deep WhatsApp Ecosystem Engine (4 files)
│   │   ├── __init__.py
│   │   ├── decoder.py                              # msgstore.db/wa.db/ChatStorage.sqlite + @lid unmasking
│   │   ├── engine.py                               # WhatsAppEcosystemEngine
│   │   ├── models.py
│   │   └── recovery.py                             # Revoked/edited recovery & rolling .crypt15 diff-merger
│   ├── workstation_app/                            # Standalone Threaded HTTP Workstation Server & Web UI (6 files)
│   │   ├── static/
│   │   │   ├── app.js
│   │   │   ├── index.html
│   │   │   └── styles.css
│   │   ├── __init__.py
│   │   ├── case_dataset_provider.py
│   │   ├── dashboard_server.py                     # ThreadingHTTPServer + FastAPI diagnostic workstation (Port 8765)
│   │   └── ingestion_pipeline.py                   # LiveForensicIngestEngine
│   ├── workstation_shell_and_hex/                  # Virtual Grid Math, Facet Hub, Sanitizer & 3-Pane Hex (6 files)
│   │   ├── __init__.py
│   │   ├── engine.py                               # WorkstationShellEngine
│   │   ├── facet_filter_hub.py                     # RoaringBitmap 18-group sub-ms facet hub
│   │   ├── hex_provenance_inspector.py             # Synchronized 3-pane Hex/ASCII/Data Interpreter engine
│   │   ├── models.py
│   │   ├── security_sanitizer.py                   # Hostile HTML/XSS, CSV formula & BiDi RTL spoof defense
│   │   └── virtual_grid_pager.py                   # Keyset pagination & quantile milestone seeker
│   └── zero_omission_and_fts5/                     # Zero-Omission Accounting, Entropy & Dual FTS5 (6 files)
│       ├── __init__.py
│       ├── engine.py                               # ZeroOmissionAndFts5Engine
│       ├── fallback_introspector.py                # UNK DB introspection fallback
│       ├── fts5_roaring_engine.py                  # RoaringBitmap32 + unicode61/trigram/Indic NFC FTS5 engine
│       ├── magic_and_entropy.py                    # Extension-vs-magic discrepancy + entropy classifier
│       ├── models.py
│       └── vfs_auditor.py                          # 100% VFS accounting completeness auditor
│
├── test_evidence/                                  # Ground-Truth Binary Evidence Fixtures (13 files)
│   ├── android_logical_extraction.zip
│   ├── msgstore.db
│   ├── msgstore.db-shm
│   ├── msgstore.db-wal
│   ├── paisa.db
│   ├── test_disk.dd
│   └── android_logical_extraction/
│       └── data/
│           ├── data/
│           │   ├── com.google.android.apps.nbu.paisa.user/databases/
│           │   │   ├── paisa.db
│           │   │   ├── paisa.db-shm
│           │   │   └── paisa.db-wal
│           │   └── com.whatsapp/databases/
│           │       ├── msgstore.db
│           │       ├── msgstore.db-shm
│           │       └── msgstore.db-wal
│           └── media/0/WhatsApp/Media/fake_video.mp4
│
├── tests/                                          # Unified Root Verification Suite (68 Python files)
│   ├── __init__.py
│   ├── conftest.py                                 # Path isolation + ZIP64 fixture monkeypatch
│   ├── adversarial_m2_stress.py
│   ├── adversarial_m3_stress.py
│   ├── test_adversarial_m4_challenge.py
│   ├── test_challenger_verification.py
│   ├── test_m4_adversarial_stress.py
│   ├── test_m5_challenger_adversarial.py
│   ├── test_phase1_module1_1_vfs.py
│   ├── test_phase1_module1_2_provenance.py
│   ├── test_phase1_module1_3_identity.py
│   ├── test_phase1_module1_4_evidentiary.py
│   ├── test_phase2_module2_1_sqlite.py
│   ├── test_phase2_module2_2_crypto.py
│   ├── test_phase2_module2_3_nonsqlite.py
│   ├── test_phase2_module2_4_webview.py
│   ├── test_phase3_module3_1_upi.py
│   ├── test_phase3_module3_2_npci_cl.py
│   ├── test_phase3_module3_3_banking.py
│   ├── test_phase3_module3_4_dlt_sms.py
│   ├── test_phase3_module3_5_correlator.py
│   ├── test_phase4_module4_1_banking.py
│   ├── test_phase4_module4_1_web3_wallets.py
│   ├── test_phase4_module4_2_cex_p2p.py
│   ├── test_phase4_module4_3_validators_abi.py
│   ├── test_phase4_module4_4_seed_correlator.py
│   ├── test_phase5_module5_1_whatsapp.py
│   ├── test_phase5_module5_2_telegram_signal.py
│   ├── test_phase5_module5_3_high_opsec.py
│   ├── test_phase5_module5_4_social_voip_burners.py
│   ├── test_phase5_module5_5_unified_chat.py
│   ├── test_phase6_module6_1_ios_telemetry.py
│   ├── test_phase6_module6_2_android_telemetry.py
│   ├── test_phase6_module6_3_geolocation.py
│   ├── test_phase6_module6_4_hyperlocal_travel.py
│   ├── test_phase6_module6_5_anti_forensics.py
│   ├── test_phase7_module7_1_media_library.py
│   ├── test_phase7_module7_2_visual_residuals.py
│   ├── test_phase7_module7_3_qr_and_receipts.py
│   ├── test_phase7_module7_4_kyc_and_ocr.py
│   ├── test_phase8_module8_1_entity_graph_and_timeline.py
│   ├── test_phase8_module8_2_zero_omission_and_fts5.py
│   ├── test_phase8_module8_3_legal_compliance_and_bsa.py
│   ├── test_phase8_module8_4_dossier_and_exhibits.py
│   ├── test_phase9_module9_1_workstation_shell_and_hex.py
│   ├── test_phase9_module9_2_unified_chat_and_redline.py
│   ├── test_phase9_module9_3_financial_graph_and_storyboard.py
│   ├── test_phase9_module9_4_geospatial_media_and_tamper.py
│   ├── test_phase9_module9_5_unk_triage_and_bsa_studio.py
│   ├── test_phase10_remediation_ocr_map_app.py
│   ├── test_phase11_ingestion_and_workstation_ui.py
│   ├── test_ui_api_server.py
│   └── e2e/                                        # 4-Tier End-to-End Integration Suite (16 files)
│       ├── __init__.py
│       ├── conftest.py
│       ├── env_setup.py                            # Priority sys.path & isolated scratch setup
│       ├── runner.py                               # CLI E2E orchestrator (--tier 1..4 | all)
│       ├── test_tier1_banking.py
│       ├── test_tier1_chats.py
│       ├── test_tier1_crypto.py
│       ├── test_tier1_ingestion.py
│       ├── test_tier1_reporting.py
│       ├── test_tier1_sqlite_recovery.py
│       ├── test_tier1_truecaller.py
│       ├── test_tier1_ui_bridge.py
│       ├── test_tier1_upi_parsers.py
│       ├── test_tier2_boundary_corner.py
│       ├── test_tier3_cross_feature.py
│       └── test_tier4_real_world.py
│
└── bharat-pa-forensics/                            # React 19 UI, TypeScript Engine & Desktop Build Workspace
    ├── bharat_backend.spec                         # PyInstaller one-dir spec bundling FastAPI + parsers/
    ├── command.md                                  # (Subproject legacy docs — superseded by root command.md)
    ├── electron-builder.yml                        # NSIS Installer + Portable x64 packaging config
    ├── generate_forensic_test_data.py              # Synthetic UPI/Chat/Crypto fixture generator
    ├── index.html                                  # React SPA entry HTML
    ├── package-lock.json
    ├── package.json                                # Node scripts (start, dev, build, desktop:build, test:python, test:ts)
    ├── phases.md                                   # (Subproject design notes)
    ├── project_tree.md                             # (Subproject legacy tree)
    ├── requirements.txt                            # Unified backend/build Python dependencies
    ├── tailwind.config.js                          # Tailwind CSS v4 configuration
    ├── test_disk.py                                # Raw disk image sanity checker
    ├── tsconfig.json                               # TypeScript 7 strict configuration
    ├── ui_layout.md                                # (Subproject UI layout spec)
    ├── vite.config.ts                              # Vite 8 + React 19 + Tailwind CSS v4 config (Port 3000)
    ├── scripts/
    │   ├── build_desktop_exe.ps1                   # 3-step Vite + PyInstaller + Electron-Builder automation
    │   ├── diff_duplicate_folders.ps1              # Cross-workspace parity diff helper (PowerShell)
    │   ├── diff_duplicate_folders.sh               # Cross-workspace parity diff helper (Bash)
    │   └── start_all.py                            # Dual-process FastAPI (:8000) + Vite (:3000) launcher
    ├── src/
    │   ├── declarations.d.ts
    │   ├── shared/
    │   │   ├── forensic-types.ts                   # Shared TypeScript interfaces, provenance & timestamp normalizer
    │   │   └── universal_hasher.ts
    │   ├── main/                                   # Native TypeScript Offline Forensic Engines (48 files)
    │   │   ├── index.ts
    │   │   ├── binary_decoders/
    │   │   │   ├── axml_parser.ts                  # Binary AndroidManifest AXML decoder
    │   │   │   ├── dex_scanner.ts                  # Dalvik DEX string scanner (Bot tokens/chat_ids/URLs)
    │   │   │   ├── mmkv_decoder.ts                 # TypeScript MMKV wire decoder
    │   │   │   ├── protobuf_decoder.ts             # Raw Protobuf wire decoder
    │   │   │   └── telegram_tl.ts                  # MTProto TL binary reader
    │   │   ├── carvers/
    │   │   │   ├── sqlite-binary-carver.ts
    │   │   │   ├── sqlite-varint.ts
    │   │   │   └── wal-carver.ts
    │   │   ├── case-manager/
    │   │   │   └── audit-logger.ts
    │   │   ├── case_manager/
    │   │   │   ├── audit_logger.ts                 # Backward-compat re-export stub
    │   │   │   ├── case_db.ts                      # Local SQLite case metadata manager
    │   │   │   └── timestamp_engine.ts             # PhonePe TxID & Unix/Clock-tamper detector
    │   │   ├── hash-guard/
    │   │   │   └── dual-hasher.ts                  # O_RDONLY stream Dual SHA-256 + MD5 guard
    │   │   ├── hash_guard/
    │   │   │   └── dual_hasher.ts                  # Backward-compat re-export stub
    │   │   ├── intelligence/
    │   │   │   ├── indian_lea_regex.ts             # NPCI VPA, UTR, IFSC, PAN, Aadhaar LEA regexes
    │   │   │   └── mule_graph_engine.ts
    │   │   ├── ipc/
    │   │   │   └── forensic-ipc.ts                 # ReadOnlyVFS IPC handlers (vfs:open-dump, read-byte-range, etc.)
    │   │   ├── licensing/
    │   │   │   └── hardware-lock.ts                # Offline hardware/USB dongle binding lock
    │   │   ├── parsers/
    │   │   │   ├── registry.ts                     # 2-pass TS VFS parser orchestrator
    │   │   │   ├── cybercrime/
    │   │   │   │   └── mule-apk-and-crypto.ts
    │   │   │   ├── cybercrime_apps/
    │   │   │   │   ├── crypto_wallets.ts
    │   │   │   │   ├── remote_access.parser.ts
    │   │   │   │   └── sms_forwarder_apk.ts
    │   │   │   ├── indian-banking/
    │   │   │   │   └── upi-correlator.ts
    │   │   │   ├── indian_banking/
    │   │   │   │   ├── notif_spillover.ts
    │   │   │   │   ├── sms_dlt_ledger.ts
    │   │   │   │   └── upi_correlator.ts
    │   │   │   ├── indian-upi/
    │   │   │   │   └── upi-deep-parsers.ts
    │   │   │   ├── indian_upi/
    │   │   │   │   ├── gpay_india.parser.ts
    │   │   │   │   ├── paytm.parser.ts
    │   │   │   │   └── phonepe.parser.ts
    │   │   │   ├── keystore/
    │   │   │   │   ├── shared_prefs_keys.ts
    │   │   │   │   └── whatsapp_key.ts
    │   │   │   └── messengers/
    │   │   │       ├── telegram.parser.ts
    │   │   │       └── whatsapp.parser.ts
    │   │   ├── reporting/
    │   │   │   ├── sec63-bsa-generator.ts          # Statutory Sec 63 BSA 2023 HTML certificate generator
    │   │   │   └── sec63_bsa_generator.ts          # Backward-compat re-export stub
    │   │   ├── sqlite_carver/
    │   │   │   ├── freeblock_carver.ts
    │   │   │   ├── sqlcipher_crypto.ts             # WhatsApp Crypt14/15 + SQLCipher TS crypto
    │   │   │   ├── sqlite_binary.ts
    │   │   │   └── wal_analyzer.ts
    │   │   └── vfs/
    │   │       ├── ab_unpacker.ts
    │   │       ├── folder_vfs.ts
    │   │       ├── read-only-vfs.ts
    │   │       ├── tar_indexer.ts
    │   │       ├── vfs_reader.ts
    │   │       └── zip_indexer.ts
    │   ├── renderer/                               # React 19 + Zustand + Tailwind v4 Workbench UI (29 files)
    │   │   ├── index.css
    │   │   ├── main.tsx
    │   │   ├── api/
    │   │   │   └── forensicClient.ts               # Typed REST/Electron client (1,235L)
    │   │   ├── state/
    │   │   │   └── workbenchStore.ts               # Zustand global case/tab/inspector/toast state (1,193L)
    │   │   ├── inspectors/
    │   │   │   ├── EvidenceCard.tsx                # Details / source bytes / links / pin for the selected record
    │   │   │   └── SyncedHexViewer.tsx             # Synchronized mmap hex/ASCII byte viewer (embedded in the card)
    │   │   ├── workspace/
    │   │   │   ├── AppShell.tsx                    # Layout, resizable panes, global keys (Ctrl+K, Ctrl+B, Alt+1..8, F6)
    │   │   │   ├── CaseBar.tsx  integrity.ts       # Case line + integrity line from recorded hashes
    │   │   │   ├── StageNavigator.tsx  stages.ts   # The eight stages and their views
    │   │   │   ├── Workspace.tsx                   # Breadcrumb + view router
    │   │   │   ├── RecordTable.tsx                 # Contacts and Calls table
    │   │   │   ├── CommandPalette.tsx  SettingsDialog.tsx  StatusLine.tsx  Toasts.tsx
    │   │   └── views/                              # 19 Specialized Forensic Investigation Views & Modals
    │   │       ├── AddExtractionModal.tsx
    │   │       ├── BankCdrFusionView.tsx           # Bank CSV + Telecom CDR (+-15 min) correlation UI
    │   │       ├── CallLogsView.tsx
    │   │       ├── ChatBubbleView.tsx              # Bubble visualizer + Myers Redline toggle
    │   │       ├── ChatsMasterWorkspace.tsx        # Unified thread browser + 28-col PA table + bubble mode (1,349L)
    │   │       ├── ContactsView.tsx
    │   │       ├── CryptoWalletView.tsx            # 15 Custodial + P2P Orders + Bridge + Harvested Addresses
    │   │       ├── ExtractionSummaryTab.tsx        # Owner Dossier, Dual SHA-256 verification & device summary
    │   │       ├── FileSystemExplorerTab.tsx       # Zero-copy VFS catalog tree + on-demand inspection
    │   │       ├── LocationsMediaView.tsx          # GPS/Tower map & media provenance view
    │   │       ├── MaliciousApkView.tsx            # Trojanned APKs, C2 tokens & USSD hijacks
    │   │       ├── MuleLinkGraphTab.tsx            # NetworkX/PyVis syndicate graph + SVG Sankey money trail
    │   │       ├── Ncrp1930FreezeModal.tsx         # 1930 NCRP bank lien modal with Complainant Victim Lock
    │   │       ├── OsSpilloverView.tsx             # Notification, clipboard & App Switcher residuals
    │   │       ├── RemoteAccessView.tsx            # AnyDesk / TeamViewer / RustDesk traces
    │   │       ├── Sec230BnssModal.tsx             # Section 230 BNSS defense disclosure modal
    │   │       ├── Sec63BsaModal.tsx               # Section 63(4)(c) BSA 2023 statutory certificate studio
    │   │       ├── SQLiteWizardTab.tsx             # Live table & query explorer over raw evidence SQLite
    │   │       └── UPIMasterLedgerView.tsx         # 4-way corroborated UPI & Banking ledger
    │   └── tests/                                  # TypeScript Engine & Workbench Tests (10 files)
    │       ├── forensic_engine_test.ts
    │       ├── pa_workbench_pagination_test.ts
    │       ├── phase1_test.ts
    │       ├── phase2_test.ts
    │       ├── phase3_test.ts
    │       ├── phase4_test.ts
    │       ├── phase5_test.ts
    │       ├── phase6_7_test.ts
    │       ├── runner.ts
    │       └── test_forensic_client.ts
    ├── tests/                                      # Unique Hardened API/Parity/FTS5 Tests (10 files)
    │   ├── test_commercial_parity_engine.py
    │   ├── test_e01_adapter.py
    │   ├── test_enterprise_1tb_engine.py
    │   ├── test_forensic_benchmark_recorder.py
    │   ├── test_forensic_client.ts
    │   ├── test_hardened_api_server.py
    │   ├── test_hardened_freelist_wal_carver.py
    │   ├── test_phase6_7.py
    │   ├── test_social_interaction_comms_parsers.py
    │   └── test_ui_fts5_paginator.py
    └── [Mirrored Runtime Folders]                  # Required until CWD build scripts point to root (see removal notes)
        ├── electron/                               # (Mirrored copy used by electron-builder inside bharat-pa-forensics/)
        ├── parsers/                                # (Bundled by bharat_backend.spec; contains newer plugin_loader & npci_storage_carver shims)
        ├── scratch/active_case/                    # Runtime case DBs (case_ui_store.db / bharat_case_store.db)
        ├── test_evidence/                          # Local copy (retains uncheckpointed 45 KB msgstore.db-wal fixture)
        └── tools/                                  # Mirrored benchmark harness
```

---

## 3. LEGACY & TRANSIENT DIRECTORIES (SUMMARIZED)

To keep the primary workspace tree readable, the following legacy/generated directories exist outside the active runtime path or contain compiler/build outputs:

- **`Bharart Analyzer/` (Legacy Source Folder — ~11.44 MB source + ~58.85 MB `.workspace_tmp`):**
  - Its `src/` (286 files) and `tests/` (42 files) are **100% consolidated into root `src/` and `tests/`**, where root `src/` has 17 newer/remediated modules.
  - Only a small set of standalone helper/reference files still reside exclusively in `Bharart Analyzer/`: `main.py` (246L standalone HTTP workstation launcher on port 8765), `scripts/setup_ocr_models.py`, `conftest.py`, `create_mock_db.py`, `mock_forensic_data.sqlite`, `plan/` (43 design specs), and legacy docs (`Architecture`, `ARCHITECTURE.md`, `commands.md`, `project_tree`, `project_tree.md`, `requirements.txt`).
- **Build & Cache Artifacts (Excluded above):**
  - `bharat-pa-forensics/release/` (~806.17 MB): Compiled `BharatAnalyzer-Setup-2.0.0.exe`, `BharatAnalyzer-Portable-2.0.0.exe`, and `win-unpacked/`.
  - `bharat-pa-forensics/dist_backend/` (~128.71 MB) & `build_backend/` (~68.99 MB): PyInstaller `bharat_backend.exe` bundle and work files.
  - `bharat-pa-forensics/dist/`, `bharat-pa-forensics/dist-test/`, root `dist/`: Compiled Vite UI static bundles.
  - `bharat-pa-forensics/.venv/` (~267.12 MB) & `bharat-pa-forensics/node_modules/` (~779.24 MB): Local Python 3.15.2 and Node 24/Electron 45 environments.
