# BharatAnalyzer Sovereign Forensics Suite — Detailed System Architecture (`architecture.md`)

> **Version:** 2.0.0 | **Physical Layout:** `E:\v8\combined\` (Unified Core & Engines) + `E:\v8\combined\bharat-pa-forensics\` (React 19 Workbench, TypeScript Carvers & Desktop Packager) | **Execution Mode:** 100% Air-Gapped Offline

---

## 1. ARCHITECTURAL OVERVIEW & SYSTEM CONVERGENCE

The merged **BharatAnalyzer Sovereign Forensics Suite** combines two complementary software systems into a single end-to-end platform:
1. **The High-Throughput Workstation Stack (`parsers/`, `electron/`, `bharat-pa-forensics/src/renderer/`, `bharat-pa-forensics/src/main/`):**
   - Delivers an interactive **Electron 45 + React 19 + Tailwind CSS v4 + Zustand** Cellebrite Physical Analyzer-grade workbench connected over localhost HTTP (`127.0.0.1:8000`) to a **31-endpoint FastAPI REST server** and a **1 TB+ SQLite FTS5 Paginated Case Store** (`CaseUIPaginatorStore`).
   - Also provides a native **Node.js / TypeScript** offline processing layer (`bharat-pa-forensics/src/main/`) for direct Electron IPC VFS streaming, Dalvik DEX scanning, and SQLite carving.
2. **The Deep Forensic Kernel (`src/` — 40 Domain Sub-Packages, 286 Python Modules):**
   - Delivers deep binary/cryptographic decoders, Indian financial/telecom/KYC/anti-forensics engines, 5-Dimensional Evidentiary State tracking, 18-Group canonical classification (`G01`–`G18`), Myers $O(ND)$ grapheme redline diffing, SVG Sankey visualizations, bilingual Hindi+English OCR, <3-second incremental key-broker DAG hot-patching, 1930 NCRP victim safeguard locks, and **Section 63 BSA 2023 / Section 230 BNSS 2023** courtroom dossier compilation.

```text
+=====================================================================================================+
|                            1. NATIVE DESKTOP & PRESENTATION SHELL (UI)                             |
|  Electron 45 Main Process (electron/main.cjs)                                                       |
|   - Spawns & monitors FastAPI (:8000) or packaged bharat_backend.exe | Zero-zombie taskkill /T /F   |
|   - Context-isolated preload.cjs -> window.electronAPI + TypeScript IPC (vfs:open-dump, byte-range)|
|                                                                                                     |
|  React 19 + Tailwind v4 + Zustand Store (bharat-pa-forensics/src/renderer/)                         |
|   - PAWorkbench -> TopRibbonBar | LeftVerticalRail | ProjectTreeDock (Active / WAL+Carved badges)   |
|   - CenterTabCanvas (13 Tabs): Summary, Chats (28-col/Bubble/Myers), UPI Ledger, Bank+CDR Fusion,   |
|     Crypto Wallets, Mule Link Graph (PyVis + SVG Sankey), SQLite Wizard, VFS Explorer, Malicious APK|
|   - Right Inspectors: PAFieldInspector | ProvenanceSidebar | SyncedHexViewer (mmap byte seeker)     |
|   - Statutory Modals: Sec63BsaModal | Sec230BnssModal | Ncrp1930FreezeModal | AddExtractionModal    |
+=====================================================================================================+
                                    | HTTP/JSON (127.0.0.1:8000) & Electron IPC
                                    v
+=====================================================================================================+
|                     2. API ORCHESTRATION & 1 TB+ PAGINATED CASE STORE LAYER                         |
|  FastAPI REST Server (parsers/api_server.py — 31 Endpoints)                                         |
|   - Asyncio locks (_ingest_lock, _benchmark_lock -> HTTP 409) | ThreadPoolExecutor(max_workers=4)   |
|   - Path traversal workspace sandboxing | Shutdown WAL TRUNCATE checkpointing                       |
|                                                                                                     |
|  CaseUIPaginatorStore (parsers/ui_fts5_paginator.py — bharat_case_store.db)                         |
|   - SQLite WAL + 256MB mmap + 64MB cache | 5,000-row streaming ingestion + deterministic gc.collect() |
|   - 12 Relational Tables + 6 FTS5 Virtual Indexes (AI/AD sync triggers) + RoaringBitmap32 Facets    |
+=====================================================================================================+
                                    | Orchestrates & Feeds
                                    v
+=====================================================================================================+
|               3. HIGH-THROUGHPUT PARSING, CORROBORATION & GRAPH PIPELINES (parsers/)                |
|  TerabyteForensicContainerEngine (selective DB materialization, skip GB media) + EwfImgInfo (.E01)  |
|  PluginRegistry (80 manifests) + CustodialWallets (15 manifests) + SocialInteractionComms (15 apps) |
|  DeepSQLite + HeuristicEngine + CommercialParityEngine (LZ4/CBOR/MsgPack/NSKeyed/AppGenie/mmap)     |
|  CorroborationEngine (RCS split-table join, counterparty healing) + MultiSourceFusion (Bank + CDR)  |
|  AccountProfiler (Master Owner Dossier) + FiatCryptoBridge + GraphIntelligence (NetworkX + PyVis)   |
+=====================================================================================================+
                                    | Backed By & Integrated With
                                    v
+=====================================================================================================+
|                       4. DEEP FORENSIC DOMAIN KERNEL (src/ — 40 Sub-Packages)                       |
|  [Phase 1 Substrate]     vfs (AB/UFD/ZIP/TAR) | provenance (Product A/B SHA-256) | identity | 5D   |
|  [Phase 2 Storage/Key]   sqlite (4-zone, WAL, journal) | crypto (SQLCipher/WCDB/WA/Notes) | nonsqlite|
|                          webview (SimpleCache/NSURLCache/BinaryCookies/JWT)                         |
|  [Phase 3 Indian FinTech] upi (PhonePe/GPay/Paytm/WA/QR) | binding (NPCI CL/SIM/VMN Trojan) | dlt    |
|                          banking (35+ banks/Corp/AePS/RD/150k IFSC/PDF unlocker) | correlator (4-Way)|
|  [Phase 4 Crypto & Seed] web3 (MetaMask/Trust/TronLink/Cake/Ledger) | cex (Binance/Indian Sec194S)  |
|                          validators (Keccak/ABI/WalletConnect v2) | seedhunter (BIP39/HD/INR-USDT)  |
|  [Phase 5 Messaging]     whatsapp (@lid/crypt15) | telegram_signal (TL) | high_opsec | social_voip  |
|                          unified_chat (Truecaller/Betting LiveChat/Dead-Drops/Burner OTP Bridge)    |
|  [Phase 6 OS/Antifor]    ios_telemetry (Biome/CoreDuet/fsevents) | android_telemetry (ABX/UsageStats)|
|                          geolocation | hyperlocal_travel (19 delivery/ride/rail/air + 13 dating)    |
|                          antiforensics (Root/ClockRollback/MockGPS/APK C2/USSD/AnyDesk)             |
|  [Phase 7 Media/OCR]     media_library (C2PA/MotionPhoto) | visual_residuals (SplashBoard/KPA Vault)|
|                          qr_and_receipts (Aadhaar QR/5-pt Forgery) | kyc_and_ocr (PAN/MRZ/Verhoeff) |
|  [Phase 8-10 Workbench]  entity_and_timeline (DSU/50M) | zero_omission_and_fts5 | legal_and_bsa     |
|                          dossier_and_exhibits | chat_reconstructor_and_redline | workstation_shell  |
|                          financial_graph_and_storyboard | geospatial_media_and_tamper | unk_triage  |
+=====================================================================================================+
```

---

## 2. ELECTRON 45 DESKTOP SHELL & IPC ARCHITECTURE (`electron/`, `bharat-pa-forensics/src/main/ipc/`)

### 2.1 Process Lifecycle & Packaged Resolution (`electron/main.cjs`)
1. **Backend Detection & Spawn (`startBackend()`):**
   - First probes `http://127.0.0.1:8000/api/health` (1.5s timeout). If already running (e.g., started by `start_all.py`), reuses the active server cleanly.
   - **Packaged Production Mode (`app.isPackaged === true`):** Locates bundled PyInstaller binary via `findProductionBackendExe()` checking `process.resourcesPath/backend/bharat_backend(.exe)` -> spawns hidden child (`windowsHide: true`).
   - **Development Mode:** Locates Python interpreter in priority order:
     1. `<PROJECT_ROOT>/.venv/Scripts/python.exe`
     2. `<PROJECT_ROOT>/bharat-pa-forensics/.venv/Scripts/python.exe`
     3. `<PROJECT_ROOT>/../.venv/Scripts/python.exe`
     4. `<PROJECT_ROOT>/venv/Scripts/python.exe`
     5. System `python` / `python3`
     and spawns `<pythonExe> -m parsers.api_server` with `cwd: PROJECT_ROOT`.
   - Polls `/api/health` up to 40 attempts at 500 ms intervals (20 s max boot budget) before loading the renderer.
2. **Frontend URL Resolution (`loadAppUrl()`):**
   - In dev mode, checks Vite HMR server at `http://localhost:3000` (3 fast probes at 300 ms); if unavailable, falls back automatically to `dist/index.html` or `bharat-pa-forensics/dist/index.html`.
   - In production mode, loads the compiled static SPA from `app.asar`'s `dist/index.html`.
3. **Zero-Zombie Termination (`stopBackend()`):**
   - Bound to `window-all-closed`, `before-quit`, `will-quit`, `SIGINT`, and `SIGTERM`.
   - On Windows, executes synchronous `taskkill /pid <pid> /T /F` to terminate Uvicorn worker trees before `SIGKILL`, preventing orphaned Python processes from locking port `8000`.

### 2.2 Security & Context-Bridge IPC Contracts (`electron/preload.cjs` & `forensic-ipc.ts`)
- **Electron BrowserWindow Hardening:** `contextIsolation: true`, `nodeIntegration: false`, `webSecurity: true`, native application menu stripped (`Menu.setApplicationMenu(null)`), minimum viewport `1280x720` (default `1600x960`).
- **Preload API (`window.electronAPI`):**
  - `openFileDialog` / `pickFile` -> `ipcMain('dialog:openFile')` filtering `.ufdr`, `.ufd`, `.tar`, `.gz`, `.zip`, `.xry`, `.ofb`, `.ab`, `.db`, `.sqlite`, `.csv`, `.xlsx`.
  - `openFolderDialog` / `pickFolder` -> `ipcMain('dialog:openDirectory')` for unpacked dumps.
  - `saveFileDialog` -> `ipcMain('dialog:saveFile')` for HTML Court Certificates and 1930 NCRP CSV exports.
  - `showItemInFolder` -> `ipcMain('shell:showItemInFolder')`.
  - `getAppVersion`, `isPackaged`, `getTreeCounts` (`api:getTreeCounts` HTTP fallback).
- **TypeScript Direct Native Engine IPC (`bharat-pa-forensics/src/main/ipc/forensic-ipc.ts`):**
  - `vfs:open-dump`: Computes streaming pre-ingestion Dual SHA-256 + MD5 (`DualHasher.calculateStreamDualHash`) in `O_RDONLY` and indexes container with `ReadOnlyVFS`.
  - `vfs:read-byte-range`: Streams raw `[offset, offset+length]` hex + ASCII slices for the hex viewer.
  - `vfs:read-file`, `vfs:get-entry`, `vfs:verify-integrity` (post-ingestion hash comparison), `vfs:close`.
- **Offline Hardware Lock (`src/main/licensing/hardware-lock.ts`):** Supports hardware/dongle offline license validation for field deployment.

---

## 3. FRONTEND WORKBENCH ARCHITECTURE (`bharat-pa-forensics/src/renderer/`)

Built on **React 19**, **Tailwind CSS v4**, **Vite 8**, **Lucide Icons**, and **Zustand v5**:

1. **4-Zone Workstation Layout (`workspace/PAWorkbench.tsx`):**
   - **Top Zone (`TopRibbonBar.tsx`):** Case actions (Add Extraction, Pick File/Folder, Bank/CDR Fusion, Sec 63 BSA Certificate, Sec 230 BNSS Disclosure, 1930 NCRP Bank Freeze), active search, timezone display toggle (UTC vs IST `+05:30`), and server health indicator.
   - **Far-Left Rail (`LeftVerticalRail.tsx`):** Vertical workflow switcher (`Analyzed Data`, etc.).
   - **Left Project Tree (`ProjectTreeDock.tsx`):** Polls `/api/case/tree-counts` every 6s to display Cellebrite-style dual badges: slate badge (`Active` allocated count) and crimson badge (`WAL + Carved / Deleted` recovered count) across expandable tree categories (`UPI & Banking Ledger`, `Chats & Social Comms`, `Crypto & P2P Layering`, `Bank & CDR Fusion`, `Syndicate Link Graph`, `Raw SQLite & B-Tree Explorer`, `Virtual File System`).
   - **Center Multi-Tab Canvas (`CenterTabCanvas.tsx`):** Dynamic closable document strip dispatching **13 primary workspace tabs** backed by **19 specialized view/modal components**:
     - `SUMMARY` -> `ExtractionSummaryTab` (Device metadata, Master Owner Dossier, Dual SHA-256 chain)
     - `CHATS` -> `ChatsMasterWorkspace` + `ChatBubbleView` (Thread sidebar, 28-col PA data table, bubble mode, Myers redline `<del>/<ins>`)
     - `UPI_LEDGER` -> `UPIMasterLedgerView`
     - `CONTACTS` -> `PATableWorkspace` (or `ContactsView`)
     - `CALL_LOGS` -> `BankCdrFusionView` (+ `CallLogsView`)
     - `OS_SPILLOVER` -> `OsSpilloverView`
     - `LOCATIONS_MEDIA` -> `LocationsMediaView`
     - `CRYPTO` -> `CryptoWalletView`
     - `MULE_GRAPH` -> `MuleLinkGraphTab`
     - `SQLITE_WIZARD` -> `SQLiteWizardTab`
     - `FILE_SYSTEM` -> `FileSystemExplorerTab`
     - `MALICIOUS_APKS` -> `MaliciousApkView`
     - `REMOTE_ACCESS` -> `RemoteAccessView`
   - **Right Contextual Inspector Pane (`PAFieldInspector.tsx`, `ProvenanceSidebar.tsx`, `SyncedHexViewer.tsx`):** Displays full record metadata, 5D/provenance pointer breakdown (`File :: Path :: Table :: RowID :: ByteOffset :: RecoveryState`), and live synchronized Hex/ASCII viewer highlighting exact field bytes in the evidence archive or DB.
   - **Floating Statutory Modals:** `AddExtractionModal`, `Sec63BsaModal`, `Sec230BnssModal`, `Ncrp1930FreezeModal`.
2. **State & Transport (`workbenchStore.ts` + `forensicClient.ts`):**
   - Centralized Zustand store holding active tabs, subcategories, selected artifacts, toast queue, modal state, and backend synchronization (`syncWithBackendCase`).
   - `forensicClient.ts` (1,235 lines) wraps all REST API endpoints cleanly with graceful native Electron vs Tkinter dialog abstraction.

---

## 4. FASTAPI REST API SERVER ARCHITECTURE (`parsers/api_server.py`)

Runs on `127.0.0.1:8000` (configurable via `HOST` and `PORT` env vars) via Uvicorn (`timeout_keep_alive=65`).

### 4.1 Concurrency, Threading & Lifecycle Controls
- **Lifespan Management (`@asynccontextmanager`):** On shutdown, drains `_thread_pool = ThreadPoolExecutor(max_workers=4)` and runs `PRAGMA wal_checkpoint(TRUNCATE)` on `_active_store` to leave case SQLite files cleanly consolidated.
- **Mutex Locking:** `_ingest_lock` and `_benchmark_lock` (`asyncio.Lock`) prevent simultaneous ingestion or workspace switches, rejecting overlapping calls with **HTTP `409 Conflict`**.
- **Path Traversal & Workspace Isolation:** All ingested outputs isolate inside `DEFAULT_WORKSPACE_ROOT` (`scratch/active_case/<case_id>/`); `/api/case/hex-window` strictly validates target paths against `_active_store.case_workspace` and `_case_state["evidence_path"]` (returning **HTTP `403`** on escape attempts).

### 4.2 Complete 31-Endpoint REST Catalog
| Group | Method & Path | Line | Function & Behavior |
| :--- | :--- | :--- | :--- |
| **Health & System** | `GET /` | L703 | Service identity, case loaded status, active workspace/DB path |
| | `GET /api/health` | L715 | Platform, Python version, DB existence & byte size check |
| | `POST /api/system/pick-evidence-file` | L783 | Invokes native Windows Tkinter file picker on worker thread |
| | `POST /api/system/pick-evidence-folder` | L791 | Invokes native Windows Tkinter folder picker on worker thread |
| **Case Management** | `GET /api/case/state` | L727 | Returns loaded flag, live tree counts, owner dossier, hashes |
| | `GET /api/case/summary` | L750 | Full case metadata, device profile, mule alerts, syndicate roles, hashes |
| | `POST /api/case/ingest` | L799 | Streaming 8 MB Dual Hash -> selective VFS unpack -> multi-engine parse -> FTS5 commit |
| | `POST /api/case/open` | L1762 | Atomically switches `_active_store` to an existing `workspace_dir/*.db` case DB |
| | `GET /api/case/tree-counts` | L841 | Live `(total, active, wal_and_carved)` counts for left tree badges |
| **Paginated Data & Chats** | `GET /api/artifacts/query` | L853 | Sub-10ms FTS5 + filter paginated query across 12 tables (`limit <= 1000`) |
| | `GET /api/case/records` | L1889 | Strict page/page_size wrapper with `412` guard when no case loaded |
| | `GET /api/chats/threads` | L1033 | Grouped conversation threads + message timeline fetch |
| | `GET /api/chats/thread` | L939 | Singular alias for thread history lookup |
| | `POST /api/chat-redline` | L950 | Myers diff engine computing `<del>` / `<ins>` tokens + financial token detection |
| **OCR Analysis** | `POST /api/ocr/analyze` | L990 | Offline Hindi+English OCR extracting normalized text, UTR, PAN, IFSC, VPA, INR |
| **Multi-Source Fusion** | `POST /api/fusion/bank-statement` | L1090 | Reconciles uploaded CSV/path bank statements against extracted device UPI ledger |
| | `POST /api/fusion/cdr` | L1125 | Correlates Telecom CDR calls/SMS/towers against device transactions ($\pm 15\text{ min}$) |
| **Graph & Intelligence** | `GET /api/graph/network-html` | L1155 | Returns interactive PyVis force-directed HTML graph of mule topology |
| | `GET /api/graph/charge-sheet-chain` | L1173 | Returns structured `Victim -> L1 -> L2 -> Kingpin/Crypto` hop chain |
| | `GET /api/graph/mule-network` | L1184 | Structured nodes/edges/alerts JSON for React canvas rendering |
| | `GET /api/graph/sankey-svg` | L1300 | Generates 5-stage Rupee-to-USDT SVG Sankey diagram |
| **Raw DB & Hex Inspector** | `POST /api/sqlite/inspect` | L1308 | Safe identifier-quoted raw SQLite table listing and row sampling |
| | `GET /api/inspector/hex` | L1353 | `mmap` byte-slice inspector returning hex lines, ASCII, and SHA-256 |
| | `GET /api/case/hex-window` | L1958 | Sandboxed legacy hex window viewer (256 B – 64 KB) with EOF flag |
| **Statutory Reports** | `GET /api/report/sec63-bsa` | L1392 | Generates printable Section 63(4)(c) BSA 2023 statutory certificate HTML |
| | `POST /api/report/sec63-bsa` | L1579 | Custom officer/FIR/FSL parameter injection + Section 63 BSA generation |
| | `POST /api/report/sec230-bnss` | L1591 | Builds Section 230 BNSS defense disclosure bundle with POCSO & Sec 72 BNS redaction |
| | `POST /api/report/ncrp-freeze` | L1644 | Evaluates freeze candidates with victim lock & writes 14-column 1930 NCRP CSV |
| | `POST /api/report/1930-ncrp` | L1645 | Route alias for `POST /api/report/ncrp-freeze` |
| | `GET /api/report/ncrp-freeze` | L1736 | Streams `ncrp_1930_bank_freeze.csv` download |
| **Benchmarking** | `POST /api/benchmark/run` | L2025 | Executes 5-stage `ForensicBenchmarkRecorder` differential parity suite |

---

## 5. CASE STORAGE, FTS5 PAGINATION & 28-COLUMN PA CHAT SCHEMA (`parsers/ui_fts5_paginator.py`)

To process 1 TB+ extractions within tight RAM limits, `CaseUIPaginatorStore` replaces in-memory Pandas DataFrame retention with an on-disk **SQLite WAL + FTS5** architecture (`bharat_case_store.db` / `case_ui_store.db`):
- **Connection PRAGMAs:** `journal_mode=WAL`, `synchronous=NORMAL`, `temp_store=MEMORY`, `mmap_size=268435456` (256 MB), `cache_size=-64000` (64 MB); core `src/core/sqlite_manager.py` adds `busy_timeout=30000` and `foreign_keys=ON`.
- **Streaming Chunked Ingestion (`ingest_dataframe_chunked`):** Inserts batches of `chunk_size=5000` rows inside SQLite transactions, immediately freeing slice buffers and calling `gc.collect()` per batch.

### 5.1 Complete 12-Table & 6-FTS5 Schema
| Table Name | FTS5 Virtual Table & Triggers | Key Columns & Purpose |
| :--- | :--- | :--- |
| `chats` | `chats_fts` (`AFTER INSERT`/`DELETE`) | Exact 28-column PA Categorized Chat Schema (below), indexed on `Application`, `Thread_ID`, `Timestamp_IST`, `Forensic_Provenance`, `Is_Revoked_Deleted` |
| `transactions` | `transactions_fts` | `Date`, `Transaction_ID`, `Amount`, `Counterparty`, `Status`, `Type`, `Account`, `VPA`, `Bank_Ref_No`, `Application`, `Source_File`, `Clock_Tamper_Detected`, `Direction`, `Forensic_Provenance`, `Timestamp_IST` |
| `contacts` | `contacts_fts` | `Contact_Name`, `Phone_Number`, `Identifier`, `Application`, `Email`, `Account_ID`, `Source_File`, `Forensic_Provenance` |
| `calls` | `calls_fts` | `Peer`, `Duration_Sec`, `Call_Type`, `Direction`, `Call_Result`, `Timestamp_UTC`, `Timestamp_IST`, `Application`, `Forensic_Provenance` |
| `locations` | `locations_fts` | `Latitude`, `Longitude`, `Geo_Coordinates`, `Place_Name`, `Timestamp_UTC`, `Timestamp_IST`, `Application`, `Forensic_Provenance` |
| `os_spillover` | `os_spillover_fts` | `Vector_Type`, `Package_Name`, `Content_Snippet`, `Extracted_Entity`, `Timestamp_IST`, `Forensic_Provenance` |
| `notifications` | *(indexed on `Package_Name`)* | `Package_Name`, `Title`, `Text`, `Timestamp_IST`, `Forensic_Provenance` |
| `custodial_wallets` | *(indexed on `Wallet_App`)* | `Wallet_App`, `User_ID`, `Account_Tier`, `KYC_Status`, `Linked_Mobile`, `Linked_Email`, `Deposit_Address`, `Forensic_Provenance` |
| `p2p_orders` | *(indexed on `Platform`, `Order_Number`)* | `Platform`, `Order_Number`, `Trade_Type`, `Fiat_Amount`, `Crypto_Amount`, `Fiat_Currency`, `Crypto_Asset`, `Counterparty_Nick`, `Counterparty_Real_Name`, `Bank_Account`, `UPI_ID`, `Order_Status`, `Timestamp_IST`, `Forensic_Provenance` |
| `fiat_crypto_bridge` | *(indexed on `UPI_Transaction_ID`)* | `UPI_Transaction_ID`, `P2P_Order_Number`, `Fiat_Amount`, `Crypto_Amount`, `Time_Delta_Seconds`, `Bridge_Confidence`, `Fiat_App`, `Crypto_Platform`, `Forensic_Provenance` |
| `crypto_addresses` | *(indexed on `Address`)* | `Address`, `Network`, `Label`, `Source_File`, `Byte_Offset`, `Forensic_Provenance` |
| `vfs_files` | *(indexed on `vfs_path`, `file_name`)* | `vfs_path`, `container_format`, `file_name`, `file_size`, `archive_offset`, `is_materialized`, `local_disk_path` |

### 5.2 The Exact 28-Column PA Categorized Chat Schema (`PA_CATEGORIZED_CHAT_COLUMNS`)
1. **Message & Artifact Details (11 cols):** `Application`, `Message_ID`, `Thread_ID`, `Chat_Type`, `Direction`, `Message_Type`, `Delivery_Status`, `Message_Body`, `Quoted_Message_ID`, `Quoted_Text`, `Forwarding_Score`
2. **Party & Participant Details (6 cols):** `Thread_Title`, `Sender_Name`, `Sender_Identifier`, `Recipient_Name`, `Recipient_Identifier`, `Participant_Bio_Meta`
3. **Privacy & Ephemeral Flags (3 cols):** `Is_View_Once`, `Disappearing_TTL_Sec`, `Is_Revoked_Deleted`
4. **Multi-Format Timestamps — Court Verification Triplet (4 cols):** `Raw_Timestamp_Value`, `Timestamp_UTC`, `Timestamp_IST`, `Read_Timestamp_IST`
5. **Attachments & Geolocation (3 cols):** `Attachment_Path_or_URL`, `Attachment_MIME_Size`, `Geo_Coordinates`
6. **Forensic Source Provenance (1 col):** `Forensic_Provenance` (`basename :: full_path :: table :: RowID=<id> :: Offset=0x... :: State=...`)

*(Complementary high-scale FTS5 indexing in `src/zero_omission_and_fts5/fts5_roaring_engine.py` adds dual `unicode61` + `trigram` + Indic NFC tokenizers paired with compressed 32-bit `RoaringBitmap32` facet filters and $O(\log N)$ Fenwick-tree virtual scrolling in `src/chat_reconstructor_and_redline/fenwick_scroller.py`.)*

---

## 6. ZERO-COPY VFS, STORAGE CARVING & CRYPTOGRAPHIC KEY BROKER

### 6.1 Selective Materialization & Dual-VFS Architecture
- **Streaming Indexers (`src/vfs/`, `parsers/enterprise_1tb_chat_and_container_engine.py`, `parsers/ewf_adapter.py`):**
  - Recognizes container magic bytes without full extraction (`ZIP`/`UFDR`, `TAR`/`TAR.GZ`, `ANDROID BACKUP`, `E01`/`Ex01`/`L01`, iOS `Manifest.db`, unpacked directories).
  - **Selective Target Extraction (`should_materialize_artifact`):** On multi-hundred-GB containers, ignores `BULK_MEDIA_EXTENSIONS` (`.mp4`, `.mov`, `.mkv`, `.so`, `.odex`, `.vdex`, `.iso`, etc.) and materializes only forensic targets (`FORENSIC_TARGET_EXTENSIONS` `.db`, `.sqlite`, `-wal`, `-journal`, `.plist`, `.xml`, `.pb`, `.ldb`, `.log`, `.sst`, `.crypt14/.crypt15`, `.trace`, etc.) plus `FORENSIC_TARGET_FILENAMES` into `extracted_dbs/`, indexing everything else into `vfs_files`.
  - **Companion Family Staging (`VFSReader.StagedSQLiteFamily`):** Automatically pulls `-wal`, `-shm`, and `-journal` sidecars alongside every target SQLite database so ACID/uncommitted transactions are never severed during staging.

### 6.2 4-Zone SQLite Recovery, Non-SQLite Wire Formats & App Genie
- **4-Zone SQLite Carving:** Zone 1 (Live B-Tree leaves) -> Zone 2 (Uncommitted/Superseded `-wal` frames & `-journal` pre-images) -> Zone 3 (Freelist trunk/leaf chains & intra-page freeblocks) -> Zone 4 (Unallocated page slack & `mmap` sliding-window raw carving).
- **Non-SQLite Decoders:** Pure-Python Snappy, LZ4 Block/Frame, Zstd/Zlib/Brotli, MessagePack, CBOR, `NSKeyedArchiver`, Protobuf wire-decoder, LevelDB `.ldb`/`.log`/tombstones, MMKV L1/L2/slack, Apple Biome SEGB v1/v2, and `App Genie` 6-model heuristic table classifier.

### 6.3 Incremental Key-Broker DAG & <3-Second Hot-Patching
When a mobile extraction runs, execution traverses an immutable DAG:
`[VFS Indexing] -> [Dual SHA-256 Seal] -> [Identity/UID/UUID Resolution] -> [Key Broker & Storage Recovery] -> [Domain Parsers] -> [DSU Entity Graph & 4-Way Correlator] -> [Super-Timeline & FTS5] -> [Merkle Ledger & BSA 2023]`
- **Hot-Patcher (`src/unk_triage_and_bsa_studio/key_broker_hotpatcher.py`):** When an examiner supplies a recovered password/PIN for an `ENCRYPTED_GATED` database:
  1. **Target Decrypt** only the locked DB.
  2. **Carve** live + WAL + freelist rows.
  3. **Tokenize** identifiers into FTS5 + RoaringBitmaps.
  4. **Graph Edge Insertion** into the existing DSU Entity Graph.
  5. **Timeline Re-Sort** into the unified Super-Timeline — completing in **< 3.0 seconds** without re-ingesting the archive.

---

## 7. MULTI-ENGINE PARSING, CORROBORATION & GRAPH PIPELINE

When `POST /api/case/ingest` runs (`_execute_ingestion_pipeline`), data flows through an 8-stage orchestration pipeline:
1. **Pre-Ingestion Cryptographic Seal:** Streams 8 MB chunks to record `SHA-256`, `MD5`, and `fileSizeBytes` (`compute_hashes_streaming`).
2. **Container Indexing & Materialization:** Invokes `TerabyteForensicContainerEngine` (archives/images) or directory walker + `build.prop` device profiling.
3. **Plugin Matching & Per-File Deep Parsing:** Matches virtual paths against all **80 `PluginRegistry` manifests** (`plugin_loader.py`), invokes `extract_account_profile`, `harvest_corroboration_signals`, `parse_database_artifacts` (heuristic + per-app overrides + dedicated WhatsApp/Telegram/Zangi/Signal/Social/Custodial parsers), and `parse_crypto_p2p_artifacts`.
4. **Multi-Source Corroboration & Counterparty Healing (`corroboration_engine.py`):** Merges RCS/SMS split-table parts, reconciles DLT SMS notifications and Truecaller caller-IDs onto masked/unnamed UPI counterparties (`heal_counterparties_across_apps`), and resolves Payer vs Payee direction against `owner_identifiers`.
5. **Master Owner Dossier Synthesis (`account_profiler.py`):** Consolidates `Primary_Mobile`, `Secondary_Mobiles`, `Owner_VPAs_Detailed`, `Linked_Bank_Accounts`, `Active_Financial_Apps`, `Security_Key_Handles`, and `UPI_Circle_Delegations`.
6. **Fiat-to-Crypto & Bank-to-Custodial Temporal Alignment (`fiat_crypto_bridge.py`):** Correlates INR UPI outflows against P2P crypto escrow orders ($\pm 45\text{ min}$) and bank-to-custodial on-ramps ($\pm 60\text{ min}$) within $\pm 8\%$ amount tolerance.
7. **Syndicate Link Graph & Mule Decomposition (`graph_intelligence.py`):** Constructs NetworkX MultiDiGraph, scores `Mule_Velocity_Flag`, `Smurfing_Burst`, and role (`Victim`, `Mule Layer-1`, `Aggregator`, `Master Kingpin`), extracts charge-sheet paths, and renders interactive PyVis HTML + 5-Stage SVG Sankey flows.
8. **Chunked Commit to SQLite + FTS5:** Commits all 12 tables to `bharat_case_store.db` and serves sub-10ms live tree counts and paginated grids to React/Electron.

*(In parallel, all 40 specialized domain engines under `src/` provide deep programmatic extraction & analysis across FinTech, SIM Binding, Web3/SeedHunter, High-OpSec, iOS/Android Telemetry, Geolocation/Hyperlocal, Anti-Forensics, Media/C2PA/OCR, Visual Residuals, and Legal Dossiers.) Note: most of these engines are not yet called by the product (see docs/REVIEW_FINDINGS.md S-01).*

---

## 8. EVIDENTIARY INTEGRITY, SECURITY & INDIAN STATUTORY ARCHITECTURE

### 8.1 Dual-Hash Chain of Custody, 5D State Matrix & 18 Groups
- **Product A vs Product B SHA-256 (`src/provenance/hasher.py`, `src/legal_and_bsa/chain_of_custody.py`):** Every raw seized container (`Product A`) and derived SQLite/staged copy (`Product B`) is hashed and anchored into a tamper-evident **SHA-256 Merkle Audit Chain** (`ChainOfCustodyTamperException` triggers on any broken link).
- **5-Dimensional Evidentiary State Matrix (`src/core/enums.py`, `src/evidentiary/enums.py`):**
  - *Dim A (Presence):* `PRESENT`, `PRESENT_EMPTY_STUB`, `SOURCE_PRESENT_NOT_ACQUIRED_{TIER,BFU,LUN}`, `NOT_OBSERVED_GHOST_APP`, `NOT_OBSERVED`, `NOT_ASSESSED` (simplified: `OBSERVED` / `ABSENT` / `NOT_OBSERVED`).
  - *Dim B (Accessibility):* `READABLE`/`PLAINTEXT`, `READABLE_DECRYPTED`/`DECRYPTED`, `PARTIALLY_READABLE_METADATA_ONLY`, `ENCRYPTED_GATED_BY_HARDWARE`, `ENCRYPTED_GATED_MISSING_KEY`, `CORRUPT_OR_ZEROED`.
  - *Dim C (Integrity / Storage Layer):* `VERIFIED_STATIC`, `VERIFIED_LIVE_STAGING_HASH`, `PARTIALLY_VERIFIED_READ_ERRORS`, `MODIFIED_SOURCE_BY_PROCEDURE`, `POTENTIAL_TOOL_ANOMALY` mapped across `LIVE_RECORD`, `WAL_OR_JOURNAL`, `FREELIST_OR_UNALLOCATED`, `MMKV_OR_SLACK`, `VISUAL_OR_NOTIFICATION_RESIDUAL`.
  - *Dim D (Parser Coverage):* `DIRECTLY_PARSED_FULL`, `PARSED_WITH_SUPPLIED_KEYS`, `PARTIALLY_PARSED`, `SCHEMA_MISMATCH_REQUIRES_MANUAL`, `STRUCTURALLY_IDENTIFIED_UNSUPPORTED`, `NOT_TESTED`.
  - *Dim E (Validation Maturity):* `R1` (Path Identified) through `R6` (Independently Corroborated & Peer-Reviewed), paired with `0.0–1.0` corroboration scores.
- **6-Tier Residual Recovery Confidence:** `ORIGINAL_RECORD` -> `HISTORICAL_COMMITTED_RECORD` -> `RESIDUAL_RECORD` -> `PARTIAL_RECORD` -> `RECONSTRUCTED_RECORD` -> `UNVERIFIED_FRAGMENT`.
- **18 Canonical Forensic Groups (`ForensicGroup` `G01`–`G18`):** Standardized taxonomy routing artifacts from `G01_INGESTION_AND_OWNERSHIP` through `G18_DOCUMENTS_APKS_AND_OCR_INDEX`.
- **Timestamp Court Verification Triplet (`src/core/timestamps.py`):** Stores `(raw_timestamp, utc_iso8601, ist_iso8601)` (`Asia/Kolkata +05:30`) across Unix s/ms/µs, Apple Cocoa (`+978307200`), and WebKit/NTFS epochs.
- **Hostile Evidence Sanitizer (`src/workstation_shell_and_hex/security_sanitizer.py`):** Neutralizes XSS HTML tags, Unicode BiDi RTL override spoofing in filenames/chats, and Excel CSV formula injection (`=`, `+`, `-`, `@`).

### 8.2 Statutory Safeguards (BSA 2023, BNSS 2023, 1930 NCRP)
1. **Golden-Hour 1930 NCRP Safeguard Lock (`src/unk_triage_and_bsa_studio/freeze_deconfliction.py`):**
   - Evaluates candidate freeze targets and enforces a non-overridable lock (`is_freeze_locked = True`, `freeze_checkbox_disabled = True`) on the complainant/victim's own bank account (`[VICTIM / COMPLAINANT — DO NOT FREEZE]`), automatically excludes whitelisted utility/govt billers (`irctc`, `bescom`, `uppcl`, `mahadiscom`, `cesc`, `billdesk`, `tata_power`, `airtel_prepaid`, `jio_postpaid`), and emits a signed 14-column CSV compatible with I4C NCRP CFCFRMS.
2. **Section 63(4)(c) BSA 2023 Mandatory 6-Point Gate (`bsa_report_studio.py`):**
   - Refuses final certificate issuance unless all 6 checks pass: Part A & B identities populated; pre/post master SHA-256 match; 0 exhibits missing dual hashes; 0 broken Merkle chain links; 0 unredacted POCSO/intimate items in defense copy; 0 PDF/A-3b font embedding failures.
3. **Section 230 BNSS Dual Disclosure Redaction Gate (`exhibit_packager.py`, `bsa_report_studio.py`):**
   - Emits paired **Court Master Copy** (unredacted sealed record) and **Section 230 BNSS Defense Disclosure Copy** obeying *P. Gopalkrishnan v. State of Kerala (2019)* and **Section 72 BNS 2023**: victim names are pseudonymized (`[VICTIM_PROTECTED_SEC72_BNS_01]`), and CSAM/intimate streams are withheld from binary duplication and substituted with **Statutory Judicial-Inspection Notice Cards**.
