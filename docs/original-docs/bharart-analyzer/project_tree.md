# BHARAT ANALYZER — COMPLETE PROJECT FILE TREE

```text
Bharat Analyzer (E:\v8\Bharart Analyzer)
├── .agents/                                             # Agentic execution rules and skills
│   ├── rules/
│   │   └── AGENTS.md                                   # Production Forensic Parser Constitution & Invariants
│   ├── settings.json                                   # Environment configuration
│   └── skills/
│       └── tdd-subpoint-builder/
│           └── SKILL.md                                # Strict 2-Turn TDD Subpoint Execution Protocol
├── .gitignore                                          # Git repository exclusions
├── conftest.py                                         # Global Pytest configuration & workspace isolation
├── main.py                                             # Unified Single-Command Workstation & Diagnostic Launcher
├── requirements.txt                                    # Python production & test dependencies
├── commands.md                                         # Command manual for execution & verification
├── ARCHITECTURE.md                                     # Comprehensive 10-Phase forensic engine architecture
├── project_tree.md                                     # Complete project structure and file manifest
├── scripts/                                            # Utility scripts
│   └── setup_ocr_models.py                             # Downloads official Hindi/English Tesseract traineddata
├── plan/                                               # 41 Master Plan Specification Documents
│   ├── master_plan.md                                  # Global 8-Phase + Phase 9 Master Roadmap
│   ├── phase_1_module_1_1_vfs_engineering_specification.md
│   ├── phase_1_module_1_2_hashing_and_provenance_specification.md
│   ├── phase_1_module_1_3_identity_and_sandbox_resolver_specification.md
│   ├── phase_1_module_1_4_5d_evidentiary_engine_specification.md
│   ├── phase_2_module_2_1_forensic_sqlite_engine_specification.md
│   ├── phase_2_module_2_2_cryptographic_key_broker_specification.md
│   ├── phase_2_module_2_3_non_sqlite_binary_storage_decoders_specification.md
│   ├── phase_2_module_2_4_universal_webview_crawler_specification.md
│   ├── phase_3_module_3_1_upi_super_app_decoders_specification.md
│   ├── phase_3_module_3_2_npci_common_library_and_sim_binding_specification.md
│   ├── phase_3_module_3_3_indian_banking_apps_specification.md
│   ├── phase_3_module_3_4_dlt_financial_sms_and_notification_parser_specification.md
│   ├── phase_3_module_3_5_4_way_utr_correlator_and_fraud_detector_specification.md
│   ├── phase_4_crypto_web3_and_exchange_forensics_specification.md
│   ├── phase_4_module_4_1_web3_self_custody_wallets_specification.md
│   ├── phase_4_module_4_2_centralized_exchange_and_p2p_forensics_specification.md
│   ├── phase_4_module_4_3_blockchain_address_validators_abi_and_walletconnect_specification.md
│   ├── phase_4_module_4_4_bip_39_seed_hunter_hd_derivation_and_rupee_usdt_correlator_specification.md
│   ├── phase_5_module_5_1_whatsapp_ecosystem_decoder_specification.md
│   ├── phase_5_module_5_2_telegram_and_signal_decoder_specification.md
│   ├── phase_5_module_5_3_high_opsec_messengers_decoder_specification.md
│   ├── phase_5_module_5_4_social_voip_and_burner_apps_specification.md
│   ├── phase_5_module_5_5_regional_covert_and_unified_chat_specification.md
│   ├── phase_6_module_6_1_ios_behavioral_telemetry_specification.md
│   ├── phase_6_module_6_2_android_behavioral_telemetry_specification.md
│   ├── phase_6_module_6_3_geolocation_and_triangulation_specification.md
│   ├── phase_6_module_6_4_indian_hyper_local_travel_and_dating_specification.md
│   ├── phase_6_module_6_5_anti_forensics_tamper_and_malware_specification.md
│   ├── phase_7_module_7_1_os_media_library_and_provenance_specification.md
│   ├── phase_7_module_7_2_ephemeral_visual_residuals_snapshots_thumbnails_and_vaults_specification.md
│   ├── phase_7_module_7_3_qr_decoder_aadhaar_secure_qr_and_forged_receipt_specification.md
│   ├── phase_7_module_7_4_offline_ocr_and_indian_kyc_classifier_specification.md
│   ├── phase_8_module_8_1_entity_graph_and_super_timeline_specification.md
│   ├── phase_8_module_8_2_zero_omission_unk_audit_and_fts5_engine_specification.md
│   ├── phase_8_module_8_3_indian_legal_compliance_and_section_63_bsa_specification.md
│   ├── phase_8_module_8_4_crime_dossier_builder_nodal_freeze_and_exhibit_packager_specification.md
│   ├── phase_9_module_9_1_core_workstation_shell_and_3_pane_hex_verification_specification.md
│   ├── phase_9_module_9_2_unified_chat_reconstructor_and_redline_viewer_specification.md
│   ├── phase_9_module_9_3_webgl_financial_crypto_graph_and_storyboard_specification.md
│   ├── phase_9_module_9_4_offline_geospatial_map_media_wall_and_tamper_inspector_specification.md
│   └── phase_9_module_9_5_unk_triage_key_broker_and_section_63_bsa_studio_specification.md
├── src/                                                # Production Forensic Engine Modules (41 Subsystems)
│   ├── __init__.py
│   ├── core/                                           # Global Core Enums & Dual Timestamps
│   │   ├── __init__.py
│   │   ├── enums.py                                    # 18 Canonical Forensic Groups, 5D State, 6-Tier Confidence
│   │   ├── sqlite_manager.py                           # Thread-safe forensic SQLite connection manager (WAL/busy timeout)
│   │   └── timestamps.py                               # Epoch conversions (Unix, Cocoa, WebKit) & UTC/IST sync
│   ├── vfs/                                            # Phase 1.1: Virtual Filesystem Ingestion & Normalizer
│   │   ├── __init__.py
│   │   ├── fingerprint.py                              # Magic bytes & archive container detection
│   │   ├── indexer.py                                  # Zero-copy directory tree and stream indexer
│   │   ├── normalizer.py                               # Path canonicalization & separator mapping
│   │   └── reader.py                                   # Seekable multi-slice archive stream reader
│   ├── provenance/                                     # Phase 1.2: Dual SHA-256 Chain of Custody & Metadata
│   │   ├── __init__.py
│   │   ├── hasher.py                                   # Product A vs Product B Dual SHA-256 generator
│   │   ├── ledger.py                                   # Tamper-evident custody ledger
│   │   ├── security.py                                 # SELinux labels & POSIX/xattr permissions
│   │   └── timestamps.py                               # btime, mtime, ctime forensic preservation
│   ├── identity/                                       # Phase 1.3: Pre-Flight Identity & Sandbox Resolver
│   │   ├── __init__.py
│   │   ├── android_resolver.py                         # Android packages.xml, UIDs & multi-user profiles
│   │   ├── engine.py                                   # Consolidated identity resolver coordinator
│   │   ├── ios_resolver.py                             # iOS MCM metadata plist & AppGroup mapper
│   │   └── models.py                                   # Identity, container and sandbox data models
│   ├── evidentiary/                                    # Phase 1.4: 5D Evidentiary State Matrix Engine
│   │   ├── __init__.py
│   │   ├── engine.py                                   # 5D State evaluation coordinator
│   │   ├── enums.py                                    # 5D Matrix dimensions (A, B, C, D, E)
│   │   ├── ledger.py                                   # Case SQLite evidentiary state storage
│   │   ├── models.py                                   # Provenance pointers & evidentiary models
│   │   └── sweeper.py                                  # Evidence consistency auditor
│   ├── sqlite/                                         # Phase 2.1: Forensic SQLite & Freelist Carver
│   │   ├── __init__.py
│   │   ├── carver.py                                   # Freelist & unallocated cell carver with 6-tier tags
│   │   ├── engine.py                                   # Multi-engine SQLite coordinator
│   │   ├── header.py                                   # SQLite page & header parser
│   │   ├── journal.py                                  # Rollback journal decoder
│   │   ├── models.py                                   # B-Tree page, cell & record data structures
│   │   ├── overflow.py                                 # Overflow chain assembler
│   │   ├── record.py                                   # Record format & type payload decoder
│   │   ├── varint.py                                   # 64-bit SQLite varint decoder
│   │   └── wal.py                                      # WAL frame decoder & superseded frame reader
│   ├── crypto/                                         # Phase 2.2: Cryptographic Key-Broker & Vault Decryptor
│   │   ├── __init__.py
│   │   ├── applenotes.py                               # Apple Notes AES-GCM decryptor
│   │   ├── engine.py                                   # Key-broker coordinator
│   │   ├── keyring.py                                  # Keychain-2.db & Android Keystore extractor
│   │   ├── models.py                                   # Master key, salt & crypto payload models
│   │   ├── sqlcipher.py                                # SQLCipher v3/v4 PBKDF2 HMAC-SHA1/SHA512 engine
│   │   ├── wcdb.py                                     # WeChat WCDB key derivator
│   │   └── whatsapp.py                                 # WhatsApp crypt12/14/15 key-unwrapper
│   ├── nonsqlite/                                      # Phase 2.3: Non-SQLite Binary Storage Decoders
│   │   ├── __init__.py
│   │   ├── engine.py                                   # Non-SQLite multi-format coordinator
│   │   ├── leveldb.py                                  # LevelDB / RocksDB .ldb & MANIFEST decoder
│   │   ├── mmkv.py                                     # MMKV mmap parser & CRC slack carver
│   │   ├── models.py                                   # Binary record & wire models
│   │   ├── protobuf.py                                 # Schema-less Protobuf wire decoder
│   │   ├── segb.py                                     # Apple SEGB v1 & v2 record parser
│   │   ├── snappy.py                                   # Snappy decompressor
│   │   └── varint.py                                   # Generic binary varint reader
│   ├── webview/                                        # Phase 2.4: Universal Embedded WebView Sandbox Crawler
│   │   ├── __init__.py
│   │   ├── binarycookies.py                            # Apple BinaryCookies parser
│   │   ├── crawler.py                                  # /data/data/<pkg>/app_webview & WebKit crawler
│   │   ├── jwt.py                                      # JWT token decoder & expiry extractor
│   │   ├── localstorage.py                             # LocalStorage LevelDB extractor
│   │   ├── models.py                                   # Web session, cookie & storage models
│   │   ├── nsurlcache.py                               # iOS NSURLCache SQLite decoder
│   │   └── simplecache.py                              # Chromium SimpleCache stream decoder
│   ├── upi/                                            # Phase 3.1: Indian UPI Super-App Decoders
│   │   ├── __init__.py
│   │   ├── engine.py                                   # Consolidated UPI multi-app engine
│   │   ├── gpay.py                                     # Google Pay India (paisa.db / tez_database)
│   │   ├── models.py                                   # UPI transaction, VPA & state models
│   │   ├── paytm.py                                    # Paytm wallet & UPI SQLite decoder
│   │   ├── phonepe.py                                  # PhonePe transaction & contact parser
│   │   ├── qr.py                                       # BharatQR & UPI deep-link parser
│   │   └── whatsapp_pay.py                             # WhatsApp Pay UPI metadata extractor
│   ├── binding/                                        # Phase 3.2: NPCI Common Library & SIM Binding
│   │   ├── __init__.py
│   │   ├── cl_vault.py                                 # NPCI CL credentials vault extractor
│   │   ├── engine.py                                   # Binding verification coordinator
│   │   ├── models.py                                   # SIM binding & telephony data models
│   │   ├── sms_audit.py                                # Silent SMS device binding auditor
│   │   ├── telephony.py                                # Dual-SIM ICCID & IMSI correlator
│   │   └── trojan_detector.py                          # Banking overlay & Accessibility abuse detector
│   ├── banking/                                        # Phase 3.3: Indian Domestic Banking Apps & PDF Unlocker
│   │   ├── __init__.py
│   │   ├── cardless_runner.py                          # Cardless cash withdrawal log extractor
│   │   ├── engine.py                                   # Banking apps multi-store coordinator
│   │   ├── ifsc_resolver.py                            # Offline RBI IFSC master registry resolver
│   │   ├── models.py                                   # Bank statement, narration & account models
│   │   ├── narration_parser.py                         # Banking narration grammar engine (IMPS/NEFT/UPI)
│   │   └── pdf_unlocker.py                             # Deterministic bank statement PDF unlocker
│   ├── dlt/                                            # Phase 3.4: DLT Financial SMS & System Notifications
│   │   ├── __init__.py
│   │   ├── attributed_body.py                          # Apple attributedBody bplist decoder
│   │   ├── dlt_headers.py                              # TRAI DLT 6-character header classifier
│   │   ├── engine.py                                   # Financial SMS & notification coordinator
│   │   ├── models.py                                   # DLT message & notification record models
│   │   ├── notifications.py                            # Android & iOS DuetExpertCenter notification cache
│   │   └── sms_grammar.py                              # Financial transaction SMS grammar parser
│   ├── correlator/                                     # Phase 3.5: 4-Way UTR Financial Correlator & Fraud Detector
│   │   ├── __init__.py
│   │   ├── engine.py                                   # 4-Way Correlator coordinator
│   │   ├── fraud_detector.py                           # Mule ring, velocity spike & layering detector
│   │   ├── models.py                                   # Financial chain, corroboration & cluster models
│   │   ├── utr_validator.py                            # 12-digit UPI UTR validator & Aadhaar Verhoeff
│   │   └── vpa_resolver.py                             # VPA handle & bank routing resolver
│   ├── web3/                                           # Phase 4.1: Web3 Self-Custody Wallets
│   │   ├── __init__.py
│   │   ├── address_utils.py                            # Checksummed address formatters
│   │   ├── cakewallet.py                               # Cake Wallet (Monero) vault parser
│   │   ├── engine.py                                   # Web3 wallets coordinator
│   │   ├── ledgerlive.py                               # Ledger Live desktop/mobile DB decoder
│   │   ├── metamask.py                                 # MetaMask vault JSON extractor
│   │   ├── models.py                                   # Web3 address, token balance & tx models
│   │   ├── tronlink.py                                 # TronLink USDT TRC-20 wallet parser
│   │   └── trustwallet.py                              # Trust Wallet multi-coin HD vault parser
│   ├── cex/                                            # Phase 4.2: Centralized Exchanges & P2P Escrow
│   │   ├── __init__.py
│   │   ├── binance.py                                  # Binance LevelDB/MMKV session parser
│   │   ├── engine.py                                   # CEX multi-exchange coordinator
│   │   ├── indian_cex.py                               # CoinDCX, WazirX, CoinSwitch & Mudrex parser
│   │   └── models.py                                   # P2P trade, KYC tier & bank account models
│   ├── validators/                                     # Phase 4.3: Address Validators, ABI Unpacker & WalletConnect
│   │   ├── __init__.py
│   │   ├── abi_unpacker.py                             # ERC-20 / TRC-20 transfer ABI parameter unpacker
│   │   ├── address_validators.py                       # EVM, TRON, Bitcoin & Solana address regex/checksums
│   │   ├── engine.py                                   # Blockchain validator coordinator
│   │   ├── models.py                                   # Contract call & signature models
│   │   └── walletconnect.py                            # WalletConnect relay session log parser
│   ├── seedhunter/                                     # Phase 4.4: BIP-39 Seed Hunter & HD Derivator
│   │   ├── __init__.py
│   │   ├── bip39_wordlist.py                           # Complete 2,048-word BIP-39 offline dictionary
│   │   ├── correlator.py                               # INR UPI-to-USDT P2P trade flow correlator
│   │   ├── engine.py                                   # Seed hunter & derivation coordinator
│   │   ├── hd_derivator.py                             # BIP-44 / BIP-84 hierarchical deterministic derivation
│   │   ├── models.py                                   # Seed phrase, private key & derivation models
│   │   ├── seed_hunter.py                              # Wordlist sliding window & entropy scanner
│   │   └── vault_unwrapper.py                          # AES-GCM / PBKDF2 hashcat-ready vault exporter
│   ├── whatsapp/                                       # Phase 5.1: WhatsApp Ecosystem & Cloned Mods
│   │   ├── __init__.py
│   │   ├── decoder.py                                  # ChatStorage.sqlite & msgstore.db decoder
│   │   ├── engine.py                                   # WhatsApp unified coordinator
│   │   ├── models.py                                   # Message, participant, media & reaction models
│   │   └── recovery.py                                 # Deleted message & freelist recovery
│   ├── telegram_signal/                                # Phase 5.2: Telegram & Signal Forensics
│   │   ├── __init__.py
│   │   ├── engine.py                                   # Telegram & Signal coordinator
│   │   ├── models.py                                   # Channel, secret chat & disappearing models
│   │   ├── signal_decoder.py                           # Signal.sqlite OWSPrimaryStorage & Keystore decoder
│   │   ├── telegram_decoder.py                         # Telegram cache4.db & iOS postbox decoder
│   │   └── tl_deserializer.py                          # Telegram Type-Language (TL) binary deserializer
│   ├── high_opsec/                                     # Phase 5.3: High-OpSec & Privacy Messengers
│   │   ├── __init__.py
│   │   ├── cross_app_hunter.py                         # Cross-app contact & session correlator
│   │   ├── engine.py                                   # Privacy messengers coordinator
│   │   ├── models.py                                   # Session, SimpleX, Briar & Threema models
│   │   ├── privacy_messengers_decoder.py               # Threema, Wickr & Element/Matrix decoder
│   │   ├── session_decoder.py                          # Session SQLCipher session.db & 66-hex IDs
│   │   └── simplex_decoder.py                          # SimpleX simplex_v1_chat.db agent parser
│   ├── social_voip/                                    # Phase 5.4: Social, VoIP & Burner Messengers
│   │   ├── __init__.py
│   │   ├── burner_bridge.py                            # TextNow, 2ndLine & burner number correlator
│   │   ├── cross_border_voip_decoder.py                # Botim, IMO & WeChat EnMicroMsg.db decoder
│   │   ├── engine.py                                   # Social & VoIP multi-app coordinator
│   │   ├── meta_decoder.py                             # Instagram direct.db & Messenger msys decoder
│   │   ├── models.py                                   # VoIP call, ephemeral chat & handle models
│   │   └── snapchat_discord_decoder.py                 # Snapchat arroyo.db & Discord LevelDB decoder
│   ├── unified_chat/                                   # Phase 5.5: Unified Chat Model & Covert Channels
│   │   ├── __init__.py
│   │   ├── correlator.py                               # Cross-platform thread & identity matcher
│   │   ├── covert_and_betting_decoder.py               # Gaming chats (Ludo/PUBG) & betting app parser
│   │   ├── engine.py                                   # Unified chat coordinator
│   │   ├── models.py                                   # Master unified chat message schema
│   │   └── truecaller_decoder.py                       # Truecaller caller ID & IM database decoder
│   ├── ios_telemetry/                                  # Phase 6.1: iOS Behavioral Telemetry & Biome
│   │   ├── __init__.py
│   │   ├── apple_biome_decoder.py                      # Apple Biome SEGB stream decoder (84 streams)
│   │   ├── duet_expert_center_decoder.py               # DuetExpertCenter notificationAndSuggestionDB
│   │   ├── engine.py                                   # iOS telemetry coordinator
│   │   ├── fsevents_gap_auditor.py                     # /.fseventsd/ gap analysis & log bracketing
│   │   ├── knowledgec_decoder.py                       # knowledgeC.db event stream decoder
│   │   ├── models.py                                   # Behavioral telemetry & orientation models
│   │   ├── screen_time_decoder.py                      # Screen Time RMAdminStore decoder
│   │   └── unified_logs_orientation_decoder.py         # Unified logs UI orientation & tracev3 decoder
│   ├── android_telemetry/                              # Phase 6.2: Android Behavioral Telemetry & AppOps
│   │   ├── __init__.py
│   │   ├── appops_decoder.py                           # AppOps discrete tracking & permission controller
│   │   ├── engine.py                                   # Android telemetry coordinator
│   │   ├── health_connect_decoder.py                   # Health Connect fitness & biometric records
│   │   ├── models.py                                   # UsageStats & AppOps event models
│   │   ├── usagestats_decoder.py                       # Daily UsageStats event protobufs vs aggregates
│   │   └── wellbeing_decoder.py                        # Digital Wellbeing & Samsung forest decoder
│   ├── geolocation/                                    # Phase 6.3: Multi-Source Geolocation & Triangulation
│   │   ├── __init__.py
│   │   ├── cellular_decoder.py                         # Cell tower BSSID, LAC & RSSI triangulator
│   │   ├── engine.py                                   # Geolocation multi-source coordinator
│   │   ├── google_timeline_decoder.py                  # Android on-device Google Timeline parser
│   │   ├── ios_location_decoder.py                     # iOS cache_encryptedB.db & routined Local.sqlite
│   │   └── models.py                                   # Geolocation point, track & confidence models
│   ├── hyperlocal_travel/                              # Phase 6.4: Indian Hyper-Local Mobility, Delivery & Dating
│   │   ├── __init__.py
│   │   ├── dating_decoder.py                           # Tinder, Bumble & Hinge match/location parser
│   │   ├── delivery_decoder.py                         # Zomato, Swiggy, Blinkit & Zepto order addresses
│   │   ├── engine.py                                   # Hyper-local multi-app coordinator
│   │   ├── mobility_decoder.py                         # Uber, Ola, Rapido & Namma Yatri ride logs
│   │   ├── models.py                                   # Order, trip, ride & delivery address models
│   │   └── travel_ticketing_decoder.py                 # IRCTC, MakeMyTrip & Where Is My Train parser
│   ├── antiforensics/                                  # Phase 6.5: Anti-Forensics, Clock Skew & Tamper Auditor
│   │   ├── __init__.py
│   │   ├── clock_gap_detector.py                       # Monotonic sequence vs TIME_SET clock skew
│   │   ├── engine.py                                   # Anti-forensics & malware coordinator
│   │   ├── integrity_auditor.py                        # Backup-restore btime clustering & anomaly detector
│   │   ├── location_spoof_auditor.py                   # Mock location apps & mock provider flags
│   │   ├── malware_auditor.py                          # Magisk, KernelSU, APK downgrades & accessibility abuse
│   │   └── models.py                                   # Tamper, clock skew & indicator models
│   ├── media_library/                                  # Phase 7.1: OS Media Libraries & C2PA Provenance
│   │   ├── __init__.py
│   │   ├── android_media_provider.py                   # Android external.db trashed & generation tracker
│   │   ├── c2pa_validator.py                           # C2PA JUMBF box validator (6-tier hierarchy)
│   │   ├── engine.py                                   # Media library & C2PA coordinator
│   │   ├── exif_iptc_parser.py                         # EXIF / IPTC camera serial & GPS extractor
│   │   ├── ios_photos_sqlite.py                        # iOS Photos.sqlite ZASSET, syndication & trash
│   │   └── models.py                                   # Media asset, C2PA manifest & EXIF models
│   ├── visual_residuals/                               # Phase 7.2: Ephemeral Visual Residuals & Hidden Vaults
│   │   ├── __init__.py
│   │   ├── app_switcher_decoder.py                     # iOS Snapshots & Android system_ce snapshots
│   │   ├── engine.py                                   # Visual residuals coordinator
│   │   ├── models.py                                   # Snapshot, thumbnail & orphaned visual models
│   │   ├── thumbnail_cache_reconstructor.py            # Android .thumbnails & Glide/Fresco caches
│   │   └── vault_unmasker.py                           # Calculator vault / disguised app unmasker
│   ├── qr_and_receipts/                                # Phase 7.3: QR Decoders, Aadhaar Secure QR & Receipt Fraud
│   │   ├── __init__.py
│   │   ├── aadhaar_unpacker.py                         # Aadhaar Secure QR decompressed VTC & photo extractor
│   │   ├── barcode_qr_engine.py                        # Air-gapped QR, DataMatrix & barcode reader
│   │   ├── forged_receipt_detector.py                  # Forged payment screenshot & font anomaly detector
│   │   ├── models.py                                   # QR payload, Aadhaar card & receipt models
│   │   └── upi_bharatqr_unpacker.py                    # UPI BharatQR EMVCo format unpacker
│   ├── kyc_and_ocr/                                    # Phase 7.4: Air-Gapped OCR & Indian KYC Classifier
│   │   ├── __init__.py
│   │   ├── archive_inspector.py                        # Nested APK & encrypted zip/rar inspector
│   │   ├── engine.py                                   # OCR & KYC multi-pipeline coordinator
│   │   ├── kyc_classifier.py                           # PAN, Aadhaar, Passport & Driving License regex/OCR
│   │   ├── models.py                                   # KYC document, seed match & archive models
│   │   ├── ocr_engine.py                               # Air-gapped offline OCR text extractor
│   │   └── pdf_office_inspector.py                     # PDF/DOCX hidden metadata & black box redactor
│   ├── entity_and_timeline/                            # Phase 8.1: Entity Resolution Graph & Super-Timeline
│   │   ├── __init__.py
│   │   ├── action_burst_correlator.py                  # 5-minute multi-channel behavioral burst clusterer
│   │   ├── edge_synthesizer.py                         # Dynamic graph edge synthesis & weight calculator
│   │   ├── engine.py                                   # Entity graph & super-timeline coordinator
│   │   ├── entity_resolver.py                          # Multi-identifier entity resolution engine
│   │   ├── models.py                                   # Graph node, edge, cluster & timeline models
│   │   └── super_timeline.py                           # 50M+ event normalized SQLite Super-Timeline
│   ├── zero_omission_and_fts5/                         # Phase 8.2: Zero-Omission UNK Audit & FTS5 Search
│   │   ├── __init__.py
│   │   ├── engine.py                                   # Zero-omission & FTS5 search coordinator
│   │   ├── fallback_introspector.py                    # Unknown binary/sqlite fallback extractor
│   │   ├── fts5_roaring_engine.py                      # SQLite FTS5 index with phonetic & proximity search
│   │   ├── magic_and_entropy.py                        # Magic byte & Shannon block entropy classifier
│   │   ├── models.py                                   # UNK triage audit & FTS search models
│   │   └── vfs_auditor.py                              # VFS file coverage completeness auditor
│   ├── legal_and_bsa/                                  # Phase 8.3: Indian Legal Compliance & BSA Sec 63(4)(c)
│   │   ├── __init__.py
│   │   ├── bsa_certificate_generator.py                # Statutory Section 63(4)(c) BSA 2023 certificate
│   │   ├── chain_of_custody_ledger.py                  # Immutable SHA-256 Merkle audit trail
│   │   ├── court_report_exporter.py                    # PDF/A-3b & Section 230 BNSS defense copy exporter
│   │   ├── engine.py                                   # Legal compliance coordinator
│   │   └── models.py                                   # Certificate, Merkle node & audit ledger models
│   ├── dossier_and_exhibits/                           # Phase 8.4: Crime Dossier Builder & Requisition Engine
│   │   ├── __init__.py
│   │   ├── dossier_builder.py                          # Comprehensive crime dossier builder
│   │   ├── engine.py                                   # Dossier & exhibit packaging coordinator
│   │   ├── exhibit_packager.py                         # Standalone self-contained court exhibit packager
│   │   ├── models.py                                   # Dossier, requisition & exhibit models
│   │   └── nodal_freeze_and_requisitions.py            # Section 94 BNSS & Section 91 CrPC requisition generator
│   ├── workstation_shell_and_hex/                      # Phase 9.1: Core Workstation Shell & 3-Pane Hex Viewer
│   │   ├── __init__.py
│   │   ├── engine.py                                   # Workstation shell & hex inspection coordinator
│   │   ├── facet_filter_hub.py                         # 18 Forensic Groups multi-facet filter hub
│   │   ├── hex_provenance_inspector.py                 # Synchronized 3-pane raw hex / ASCII / data inspector
│   │   ├── models.py                                   # Hex range, facet filter & inspection models
│   │   ├── security_sanitizer.py                       # Zero-trust UI sanitization & CSV formula neutralizing
│   │   └── virtual_grid_pager.py                       # 10M+ row sub-10ms virtual grid scroller
│   ├── chat_reconstructor_and_redline/                 # Phase 9.2: Chat Reconstructor & Myers Redline
│   │   ├── __init__.py
│   │   ├── audio_waveform_processor.py                 # Offline RMS audio amplitude peak decoderr
│   │   ├── engine.py                                   # Chat reconstruction coordinator
│   │   ├── fenwick_scroller.py                         # O(log N) Fenwick tree virtual list scroller
│   │   ├── hopping_timeline_stitcher.py                # Cross-platform message hopping timeline stitcher
│   │   ├── models.py                                   # Chat bubble, waveform & redline models
│   │   └── myers_redline_engine.py                     # Myers diff redline engine for edited/unsent messages
│   ├── financial_graph_and_storyboard/                 # Phase 9.3: WebGL Financial Graph & Storyboard
│   │   ├── __init__.py
│   │   ├── action_burst_storyboard.py                  # Step-by-step kinetic transaction storyboard
│   │   ├── engine.py                                   # Financial visualization coordinator
│   │   ├── freeze_cart_manager.py                      # Multi-bank freeze requisition cart manager
│   │   ├── graph_physics_engine.py                     # 2D force-directed WebGL topology engine
│   │   ├── models.py                                   # Graph node, Sankey flow & storyboard models
│   │   └── sankey_canvas.py                            # Layer-by-layer Sankey money trail renderer
│   ├── geospatial_media_and_tamper/                    # Phase 9.4 & 10: Offline Map, Tamper, Bilingual OCR & Geocoder
│   │   ├── __init__.py
│   │   ├── bilingual_ocr_engine.py                     # 3-tier Hindi (Devanagari) + English OCR & Indic normalizer
│   │   ├── engine.py                                   # Geospatial, media & tamper coordinator
│   │   ├── hybrid_map_geocoder.py                      # OSM Nominatim reverse geocoder & 66-city Indian Gazetteer fallback
│   │   ├── models.py                                   # Map tile, perceptual hash & tamper models
│   │   ├── perceptual_dhash_clustering.py              # Difference Hash (dHash) Hamming distance clusterer
│   │   ├── pmtiles_map_engine.py                       # Offline vector PMTiles map tile engine
│   │   └── tamper_inspector_modal.py                   # Split-pane tamper & metadata diff inspector
│   ├── unk_triage_and_bsa_studio/                      # Phase 9.5: UNK Triage Workbench & BSA Studio
│   │   ├── __init__.py
│   │   ├── bsa_report_studio.py                        # WYSIWYG Section 63 BSA & Sec 230 BNSS dual preview
│   │   ├── engine.py                                   # UNK Triage & BSA Studio master coordinator
│   │   ├── entropy_profiler.py                         # 4 KB sliding-window Shannon block entropy skyline
│   │   ├── freeze_deconfliction.py                     # Complainant safeguard lock & 1930 NCRP CSV generator
│   │   ├── key_broker_hotpatcher.py                    # Password harvester & 5-step incremental DAG patcher
│   │   ├── models.py                                   # Entropy, schema promotion & BSA dossier models
│   │   └── schema_mapper.py                            # Zero-code SQLite table introspector & schema mapper
│   └── workstation_app/                                # Phases 10 & 11: Forensic Workstation Server & Multi-File UI
│       ├── __init__.py
│       ├── case_dataset_provider.py                    # Pre-populated forensic case dataset provider (FIR 104/2026)
│       ├── dashboard_server.py                         # Multi-threaded HTTP server & REST endpoint router
│       ├── ingestion_pipeline.py                       # Real Evidence Dump Ingestion Pipeline & Dynamic Case Engine
│       └── static/                                     # Commercial-Grade Workstation Frontend Assets
│           ├── app.js                                  # Interactive controller (7 Workspace Panels & Tri-Pane Hex)
│           ├── index.html                              # Production HTML5 Shell & Top Command Ribbon
│           └── styles.css                              # Forensic dark theme & color-coded 4-layer hex grid
└── tests/                                              # 42 Rigorous Acceptance Test Suites (233 Passing Tests)
    ├── test_phase1_module1_1_vfs.py
    ├── test_phase1_module1_2_provenance.py
    ├── test_phase1_module1_3_identity.py
    ├── test_phase1_module1_4_evidentiary.py
    ├── test_phase2_module2_1_sqlite.py
    ├── test_phase2_module2_2_crypto.py
    ├── test_phase2_module2_3_nonsqlite.py
    ├── test_phase2_module2_4_webview.py
    ├── test_phase3_module3_1_upi.py
    ├── test_phase3_module3_2_npci_cl.py
    ├── test_phase3_module3_3_banking.py
    ├── test_phase3_module3_4_dlt_sms.py
    ├── test_phase3_module3_5_correlator.py
    ├── test_phase4_module4_1_web3_wallets.py
    ├── test_phase4_module4_2_cex_p2p.py
    ├── test_phase4_module4_3_validators_abi.py
    ├── test_phase4_module4_4_seed_correlator.py
    ├── test_phase5_module5_1_whatsapp.py
    ├── test_phase5_module5_2_telegram_signal.py
    ├── test_phase5_module5_3_high_opsec.py
    ├── test_phase5_module5_4_social_voip_burners.py
    ├── test_phase5_module5_5_unified_chat.py
    ├── test_phase6_module6_1_ios_telemetry.py
    ├── test_phase6_module6_2_android_telemetry.py
    ├── test_phase6_module6_3_geolocation.py
    ├── test_phase6_module6_4_hyperlocal_travel.py
    ├── test_phase6_module6_5_anti_forensics.py
    ├── test_phase7_module7_1_media_library.py
    ├── test_phase7_module7_2_visual_residuals.py
    ├── test_phase7_module7_3_qr_and_receipts.py
    ├── test_phase7_module7_4_kyc_and_ocr.py
    ├── test_phase8_module8_1_entity_graph_and_timeline.py
    ├── test_phase8_module8_2_zero_omission_and_fts5.py
    ├── test_phase8_module8_3_legal_compliance_and_bsa.py
    ├── test_phase8_module8_4_dossier_and_exhibits.py
    ├── test_phase9_module9_1_workstation_shell_and_hex.py
    ├── test_phase9_module9_2_unified_chat_and_redline.py
    ├── test_phase9_module9_3_financial_graph_and_storyboard.py
    ├── test_phase9_module9_4_geospatial_media_and_tamper.py
    ├── test_phase9_module9_5_unk_triage_and_bsa_studio.py
    ├── test_phase10_remediation_ocr_map_app.py
    └── test_phase11_ingestion_and_workstation_ui.py
```
