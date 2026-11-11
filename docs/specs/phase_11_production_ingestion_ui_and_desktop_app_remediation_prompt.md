# PHASE 11: PRODUCTION-GRADE FORENSIC IDE OVERHAUL, REAL EVIDENCE DUMP INGESTION PIPELINE, ZERO-BLANK-BOX FIX & NATIVE DESKTOP WINDOW LAUNCHER (WITH 5 MANDATORY BREAKPOINTS)

## 0. CRITICAL OPERATING RULES (READ CAREFULLY BEFORE STARTING)
You are fixing critical production defects identified in the current `main.py` and `src/workstation_app/` implementation:
1. **WHY THE CURRENT UI FAILED:**
   - In the current UI, 6 out of 7 tabs have **completely blank/empty black boxes** (`18 Canonical Forensic Groups Registry Status` is empty, `3-Pane Hex & Timeline` is empty, `Sankey Canvas` & `5-Swimlane Storyboard` are empty, `Geospatial Map` & `3-Mode Tamper Inspector` are empty, `Bilingual OCR Results` is empty, and `1930 NCRP Table` & `BSA Section 63 Previews` are empty).
   - There is **NO place to ingest real dump files, folders, SQLite databases, or archives**—all numbers (`142,810`, `31,402`) are hardcoded fake strings.
   - The `Device Selector` dropdown at the top (`Device 02: Apple iPhone 15 Pro`) is desynchronized from the card (`Device 01: Samsung`), and the top search box is disconnected.
   - The desktop launcher opened as a normal browser tab with an address bar instead of a standalone native desktop window.
   - The styling looks like a low-density web template instead of a high-density, production-grade **Forensic IDE Workstation**.
2. **STRICT 5-BREAKPOINT EXECUTION RULE:**
   - You MUST execute this remediation in **5 sequential stages (Breakpoints 1 to 5)**.
   - At the end of EACH stage, you MUST summarize your work and **STOP IMMEDIATELY to ask for my approval** before starting the next stage.
3. **ZERO DELETION / ZERO REGRESSION RULE:**
   - Do NOT delete or break any existing parser modules in `src/` or any of the existing tests in `tests/`. All existing unit tests must continue to pass 100%.
4. **STRICT `AGENTS.md` COMPLIANCE:**
   - Never write any banned token from `AGENTS.md` (including the literal word for HTML input hints, `todo`, `fixme`, `stub`, `dummy`, or `mock`) anywhere in `src/` or `main.py`.

---

## STAGE 1 (BREAKPOINT 1): ROOT-CAUSE DIAGNOSIS OF BLANK CONTAINERS & HARDCODED VALUES

### Tasks for Stage 1 (Diagnostic Audit Only — Do Not Modify Code Yet):
1. Inspect `main.py`, `src/workstation_app/dashboard_server.py`, and any HTML/CSS/JS files in `src/workstation_app/`.
2. Identify the exact lines of code where:
   - The 6 tabs (`18 Forensic Groups Registry`, `3-Pane Hex & Timeline`, `5-Stage Sankey & 5-Swimlane Storyboard`, `Geospatial Map & 3-Mode Tamper Inspector`, `Bilingual OCR Results`, and `1930 NCRP / BSA Studio`) failed to populate on page load or failed when clicked.
   - Values were hardcoded in HTML instead of being computed dynamically from an active case state.
   - The desktop window launcher failed to open a chromeless standalone desktop window.
3. Print a concise **Stage 1 Root-Cause Report** listing every broken DOM container ID, every broken JS function or missing API route, and your exact plan to wire real file/dump ingestion in Stage 2.

🛑 **BREAKPOINT 1:** Print the Stage 1 Root-Cause Report and **STOP**. Ask me: *"Do you approve Stage 1 and want me to proceed to Stage 2 (Building the Real Evidence Dump Ingestion Engine & Dynamic Case Backend)?"*

---

## STAGE 2 (BREAKPOINT 2): REAL EVIDENCE DUMP & FILE INGESTION ENGINE + DYNAMIC CASE STATE BACKEND

*(Execute ONLY after I approve Stage 1)*

### Tasks for Stage 2:
Create `src/workstation_app/ingestion_pipeline.py` and update `src/workstation_app/dashboard_server.py` so the workstation is driven by a **Real Stateful Case & Ingestion Engine** (with zero hardcoded HTML numbers!):

1. **Real Local Path & Uploaded File Ingestion Pipeline (`LiveForensicIngestEngine`):**
   - Implement two ingestion methods that wire directly into your Phase 1–8 modules:
     - **Method A — Ingest Local Disk Path (`POST /api/ingest/local-path`):** Accepts `{"source_path": "E:/...", "case_id": "...", "examiner": "..."}` where `source_path` can be any local directory, `.zip`, `.tar`, `.ufdr`, `.ab`, `.db`, `.sqlite`, `-wal`, `.txt`, `.json`, `.pdf`, or image file on the user's machine.
     - **Method B — Ingest Uploaded File(s) from UI (`POST /api/ingest/upload-file`):** Accepts base64/binary uploaded files (`.db`, `.sqlite`, `.zip`, `.tar`, `.txt`, `.json`, `.png`, `.jpg`, `.pdf`) dropped into the UI's **Ingest Evidence Modal**.
   - **What the Ingestion Pipeline Must Actually Execute on Every Ingested Source:**
     1. **Phase 1 Real VFS & Dual SHA-256 Hashing:** Walk all files in the directory/archive (or single file), compute the real cryptographic **SHA-256 and MD5 (`Product A` and `Product B`)**, compute real byte sizes, and classify every file across the **18 Canonical Forensic Groups** and the **4 Zero-Omission Audit States** (`PARSED_EVIDENTIARY`, `SYSTEM_KNOWN`, `DECRYPTION_BLOCKED`, `UNK_TRIAGE`).
     2. **Phase 2 Real Binary, Entropy & SQLite/WAL Introspection:**
        - Compute the real **Shannon Entropy $H(X)$ (bits/byte)** and **64-byte raw hex header** of every ingested file! Flag any file where the magic bytes (e.g., `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` for SQLite 3) contradict its extension!
        - For every SQLite `.db`/`.sqlite` file found, open it via `connect_forensic_sqlite`, enumerate all tables and row counts in `sqlite_master`, extract sample rows + timestamps into the live **Super-Timeline**, and extract real 64-byte page/cell slices into the **3-Pane Hex Inspector**!
     3. **Phase 3–7 Real Pattern & Indicator Extraction:** Scan extracted text/rows/images using your real Phase 3 (`12-digit UTR`, `IFSC`, `UPI VPA`), Phase 4 (`TRON/EVM/BTC addresses`, `BIP-39 seeds`), Phase 5 (`Chat messages`), Phase 6 (`Lat/Lon coordinates`), and Phase 7 (`BilingualOcrEngine` for `.png`/`.jpg`/`.txt`) engines, and append all discovered artifacts into the active case state!
2. **Multi-Device / Multi-Case State Management (`/api/case/select-device`):**
   - Maintain a live registry of devices in memory + SQLite (`Device 01: Samsung Galaxy S24 Ultra [Android 14 FFS]`, `Device 02: Apple iPhone 15 Pro [iOS 17.5.1 GrayKey]`, plus any `Device 03+: User Ingested Dump <Name>`).
   - Switching the device dropdown in the top bar MUST call `/api/workspace/bootstrap?device_id=<id>` and dynamically update **every single metric card, hardware IMEI/ICCID box, 18-group table, timeline row, chat thread, Sankey diagram, and map pin** so nothing is ever static or desynchronized!
3. ** interactive Bookmark / "Relied-Upon" Evidence Basket (`/api/bookmarks/toggle`):**
   - Allow the user to bookmark/tag any timeline row, chat message, financial link, or OCR finding, dynamically adding its real `Product A` and `Product B` SHA-256 hashes into the **Section 63(4)(c) BSA Studio** exhibit list!

🛑 **BREAKPOINT 2:** Test the new `/api/ingest/local-path` and `/api/ingest/upload-file` endpoints on a real temporary SQLite `.db` and `.zip` file, print the JSON output showing real SHA-256 hashes and dynamically updated VFS counts, and **STOP**. Ask me: *"Do you approve Stage 2 and want me to proceed to Stage 3 (Building the Production-Grade Forensic IDE Shell, Live Ingestion Modal, Command Center & Synchronized 3-Pane Hex/Timeline Workspace)?"*

---

## STAGE 3 (BREAKPOINT 3): PRODUCTION FORENSIC IDE SHELL, LIVE INGESTION MODAL, COMMAND CENTER & WORKING 3-PANE HEX/TIMELINE WORKSPACE

*(Execute ONLY after I approve Stage 2)*

### Tasks for Stage 3:
Rebuild the frontend layout (`src/workstation_app/static/index.html`, `styles.css`, `app.js`) to look and behave like a **Tier-1 Commercial Desktop Forensic IDE** (crisp `11px/12px` typography, high-density dark slate `#070A10` / `#0D121D` panels, `1px solid #1E293B` gridlines, zero empty black boxes):

1. **Top Forensic IDE Header & Action Bar:**
   - **Left:**BharatAnalyzer Shield + Case Title + **Prominent Primary Action Button: `[+ Ingest Dump / Evidence File]`** (opens the **Live Evidence Ingestion Modal** where the user can either type/paste a local folder/archive path like `E:\...` OR drag-and-drop `.zip`, `.tar`, `.ufdr`, `.db`, `.sqlite`, `.png`, `.jpg`, `.txt` files to parse them live!).
   - **Center:** Working **Device Selector Dropdown** (switching between `Device 01: Samsung S24 Ultra`, `Device 02: iPhone 15 Pro`, and any newly ingested user dump—dynamically updating the entire screen!), plus a working **Global `FTS5` / Trigram Search Bar** (`Ctrl+K`) that live-filters timeline rows, chats, and files as you type!
   - **Right:** Working **`IST (+05:30)` / `UTC` Timezone Toggle** (live-converts all visible timestamps), Dual SHA-256 Verification Badge, and Online/Offline Network Indicator.
2. **Workspace 1 — Populated Command Center (`#ws-command`):**
   - **Dynamic KPI Strip:** Driven 100% by the active device/case JSON (`Total VFS Nodes`, `Parsed Evidentiary`, `System Known`, `UNK Triage Queue`, `Disputed Financial Flow`).
   - **Synchronized Device Hardware & Dual SHA-256 Cards:** Updates dynamically when the user switches devices or ingests a new dump.
   - **POPULATED 18 Canonical Forensic Groups Registry Matrix (Fixes the empty box in Screenshot 1!):** Render a high-density 18-card / 18-row interactive matrix showing all 18 Forensic Groups (`G01: VFS & Partition Table`, `G02: SQLite WAL & Freelist`, `G03: Cryptographic Keyring`, `G04: Indian UPI Super-Apps`, `G05: Domestic Banking & DLT SMS`, `G06: Web3 Self-Custody Wallets`, `G07: CEX P2P Escrows`, `G08: Mainstream & Cloned Chats`, `G09: High-OpSec Messengers`, `G10: Social & Burner VoIP`, `G11: iOS Biome & knowledgeC`, `G12: Android UsageStats & AppOps`, `G13: 4-Tier Geolocation`, `G14: Hyper-Local & Travel`, `G15: Anti-Forensics & Malware`, `G16: Media & C2PA Provenance`, `G17: Visual Residuals & QR/OCR`, `G18: BSA Sec 63 & UNK Audit`) with live artifact counts, 5D state badges, and 1-click jump links!
3. **Workspace 2 — 100% Populated Synchronized 3-Pane Hex, Super-Timeline & VFS Explorer (`#ws-hex` — Fixes the blank panes in Screenshot 2!):**
   - **Pane 1 (Left — VFS File Tree & Super-Timeline Event List):**
     - Toggleable between **Super-Timeline Events** and **Ingested VFS File / SQLite Table Explorer**.
     - Pre-populated on load with all timeline events and ingested files (showing timestamp, app badge, summary, and 5D state pill: `LIVE_ALLOCATED`, `WAL_UNCOMMITTED`, `B_TREE_FREELIST`, `CARVED_UNALLOCATED`).
     - Clicking ANY row immediately highlights that row and updates Pane 2 and Pane 3!
   - **Pane 2 (Center — True 16-Byte-Per-Row 4-Layer Color-Coded Hex & ASCII Matrix):**
     - Immediately renders the 64-byte (or 128-byte) raw binary slice on load (`00000100  53 51 4C 69 ...  SQLi...`) with color-coded byte cells: **Amber** (`Header`), **Cyan** (`Target Payload / UTR / Text`), **Purple** (`WAL Salt`), and **Rose** (`Freelist Slack`).
     - **Interactive Byte-Click:** Clicking *any* individual hex byte cell in Pane 2 highlights the 8-byte window starting at that byte and immediately recalculates **Pane 3's Data Interpreter** for that exact byte offset!
   - **Pane 3 (Right — Populated 12-Format Data Interpreter & Chain-of-Provenance Pointers):**
     - Displays `UInt8 / Int8`, `Int16 LE/BE`, `Int32 LE/BE`, `Int64 LE/BE`, `SQLite Huffman Varint`, `Protobuf SLEB128`, `Unix Epoch (s / ms)`, `Apple Cocoa Epoch (2001)`, and `Decoded UTF-8 String`, plus the full **Provenance Card** (`VFS Node ID`, `Container SHA-256`, `MD5`, `SQLite Page #`, `Cell Offset`, `WAL Frame`, and a `[☆ Bookmark for BSA Report]` button).

🛑 **BREAKPOINT 3:** Verify that the Ingestion Modal, Command Center (including all 18 Forensic Groups), and the 3-Pane Hex/Timeline/Interpreter workspace render with zero blank boxes, and **STOP**. Ask me: *"Do you approve Stage 3 and want me to proceed to Stage 4 (Fixing the Blank Financial Sankey, 5-Swimlane Storyboard, Online/Offline Map, 3-Mode Tamper Inspector, Bilingual Image+Text OCR & BSA Studio)?"*

---

## STAGE 4 (BREAKPOINT 4): FIXING ALL BLANK VISUAL CANVASES (SANKEY, STORYBOARD, MAP, TAMPER SLIDER, IMAGE OCR & BSA STUDIO)

*(Execute ONLY after I approve Stage 3)*

### Tasks for Stage 4:
Fix every single blank container seen in Screenshots 3, 4, 5, 6, and 7 so they auto-render rich visuals immediately when the page loads AND update dynamically on user interaction:

1. **Workspace 3 — Unified Chat Reconstructor (`#ws-chat`):**
   - Left roster with multiple selectable threads (`Thread 1: Rakesh Sharma [4-App Hop]`, `Thread 2: Binance P2P Escrow #205918`, `Thread 3: Telegram Saved Messages [BIP-39 Seed]`, plus any chats from user-ingested `.db` files).
   - Clicking **`Myers Redline Diff Mode`** immediately transforms edited/revoked bubbles inline to show red strikethrough `<del>` deletions and green `<ins>` insertions (computed by `MyersRedlineEngine`), and clicking any chat bubble has a **`[Jump to Raw Bytes in Hex Inspector]`** button!
2. **Workspace 4 — Populated 5-Stage Sankey Canvas & 5-Swimlane Storyboard (`#ws-finance` — Fixes Screenshot 4!):**
   - **Auto-Rendered 5-Stage Sankey SVG:** Immediately renders the full multi-hop SVG flow diagram on page load (`Victim Accounts` $\rightarrow$ `Mule Tier-1 SBI` $\rightarrow$ `Mule Tier-2 HDFC` $\rightarrow$ `Binance P2P Escrow` $\rightarrow$ `TronLink TRC-20 TXYZ...` $\rightarrow$ `FixedFloat XMR`). Clicking `"Highlight Critical Mule Path"` glows the primary laundering path in amber/crimson; clicking any node filters the underlying transaction ledger table below it.
   - **Auto-Rendered 5-Swimlane 60-Second Action-Burst Storyboard:** Immediately renders the 5 horizontal swimlane tracks (`1. Physical & Biometric`, `2. OS Foreground & AppOps`, `3. Telecom & DLT OTP SMS`, `4. UPI / Bank UTR Execution`, `5. Visual Screenshot & Chat Exfiltration`) across `14:32:00` to `14:33:00 IST` with clickable event pills!
3. **Workspace 5 — Populated Online/Offline Map & 3-Mode Visual Tamper Inspector (`#ws-map-media` — Fixes Screenshot 5!):**
   - **Left Panel (Geospatial Map & Live Reverse Geocoder):**
     - Immediately renders the interactive map on load (showing the 4-Tier forensic pins across Varanasi, Bengaluru, Mumbai, and Delhi, $R_{\text{horiz}}$ accuracy circles, `Jio 4G eNodeB` 120° sector wedge, `Uber` polyline, and `Blinkit` Flat 1404 callout card) alongside the live **Coordinate Reverse Geocoder** (where typing any `Lat, Lon` or clicking any pin resolves the street address via OpenStreetMap Nominatim when online, or falls back to `Lat, Lon + Nearest Indian Gazetteer City` when offline).
   - **Right Panel (3-Mode Visual Tamper & Forgery Inspector — Auto-Rendered on Load!):**
     - **Tab 1 (`1. /Mutations/ Uncrop Curtain`):** Renders an interactive side-by-side wipe slider comparing the suspect's cropped/black-redacted screenshot against the unredacted `/PhotoData/Mutations/` original!
     - **Tab 2 (`2. UIDAI Secure QR .jp2`):** Renders the side-by-side comparison between the printed card OCR (`"AMIT KUMAR VERMA"`) and the RSA-2048 signed UIDAI QR payload (`"RAHUL KUMAR SHARMA"`, `[Aadhaar Redacted - Verhoeff Verified]`, Iterative SHA-256 Mobile match).
     - **Tab 3 (`3. 5-Point Forgery Scorecard`):** Renders the 5-point mathematical UPI receipt audit (`YDDD` Julian Date check `4120 != 6309`, EXIF editor check, Phase 3 ledger presence check, duplicate UTR check, VPA handle check).
4. **Workspace 6 — Populated Bilingual Hindi+English (`hin+eng`) Image & Text OCR Studio (`#ws-ocr` — Fixes Screenshot 6!):**
   - Add an **Image / Screenshot File Upload Dropzone (`<input type="file" accept="image/*">`)** above the text box so the user can upload real `.png`/`.jpg` screenshots for OCR, AND automatically execute `BilingualOcrEngine` on load so the right-hand **`EXTRACTION RESULTS & ENTITY CLASSIFIER`** panel is immediately populated with structured cards (`Document Category`, `Detected Scripts`, `Normalized ASCII Text`, `Extracted 12-Digit UTRs`, `IFSCs`, `PANs`, `INR Amounts`, and `Verhoeff Checksum Status`).
5. **Workspace 7 — Populated Key-Broker, `1930 NCRP` Freeze Table & Section 63(4)(c) BSA Studio (`#ws-bsa-unk` — Fixes Screenshot 7!):**
   - **Top-Right (`1930 NCRP / I4C Bank Freeze Directives Table`):** Pre-populated on load with the 4 discovered accounts/wallets (showing the green `LOCKED SAFE — VICTIM SOURCE` row and the red `FREEZE LIEN` mule/crypto rows) and a working **`[Download 1930 NCRP CSV]`** button.
   - **Bottom (`Section 63(4)(c) BSA 2023 Statutory Certificate Studio`):** Automatically calls `/api/bsa/generate` on page load so both the **`MASTER COURT COPY (SECTION 63 BSA UNABRIDGED)`** and the **`DEFENSE DISCLOSURE COPY (SECTION 230 BNSS WITHHELD/REDACTED)`** are fully rendered and scrollable immediately when the user opens the tab!

🛑 **BREAKPOINT 4:** Verify that every single container in Workspaces 3, 4, 5, 6, and 7 is populated on load with zero blank black boxes, and **STOP**. Ask me: *"Do you approve Stage 4 and want me to proceed to Stage 5 (Fixing the Standalone Native Desktop Window Launcher & Running Final Acceptance Tests)?"*

---

## STAGE 5 (BREAKPOINT 5): NATIVE STANDALONE DESKTOP APP LAUNCHER & END-TO-END VERIFICATION

*(Execute ONLY after I approve Stage 4)*

### Tasks for Stage 5:
1. **Fix the Standalone Native Desktop Application Window in `main.py`:**
   - Why it previously opened as a browser tab: Passing `--app=http://127.0.0.1:8765` to an already-running Chrome/Brave/Edge process without an isolated `--user-data-dir` causes Chromium to ignore `--app` and open a regular browser tab.
   - **Implement the 3-Tier Native Desktop Window Launcher (`launch_native_desktop_window(url: str)` in `main.py`):**
     - **Tier 1 (`pywebview` Native OS Window):** Try importing `webview` (`pywebview`). If installed, open a native Win32/EdgeWebView2 desktop window titled `"BharatAnalyzer — Post-Acquisition Forensic Workstation (BSA Sec 63)"` (`width=1600, height=960`).
     - **Tier 2 (Isolated Chromium/Edge `--app` Native Window with Dedicated `--user-data-dir`):** Locate Microsoft Edge (`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` or `C:\Program Files\Microsoft\Edge\Application\msedge.exe`), Google Chrome, or Brave. Launch with:
       ```python
       profile_dir = os.path.abspath("./.workspace_tmp/bharat_desktop_app_profile")
       subprocess.Popen([
           browser_exe,
           f"--user-data-dir={profile_dir}",
           f"--app={url}",
           "--window-size=1620,960",
           "--disable-extensions",
           "--no-first-run",
           "--no-default-browser-check",
       ])
       ```
       Because `--user-data-dir` points to an isolated profile directory, Windows **always** spawns a dedicated, chromeless native desktop application window (no address bar, no browser tabs, no extensions) even if Brave/Edge/Chrome is already open!
     - **Tier 3 (`webbrowser.open` Fallback):** Only if neither Tier 1 nor Tier 2 is available.
2. **Add Comprehensive Acceptance Tests (`tests/test_phase11_ingestion_and_workstation_ui.py`):**
   - Test `POST /api/ingest/local-path` and `POST /api/ingest/upload-file` on a real temporary directory containing a SQLite `.db` file (with a table of UPI transactions), a disguised `.png` file with a SQLite header, and a Hindi/English receipt text file:
     - Assert that real `SHA-256` and `MD5` hashes are computed.
     - Assert that the disguised `.png` file is flagged with `is_extension_spoofed=True` and Shannon entropy $H(X)$ is computed.
     - Assert that the SQLite rows and 64-byte hex slices are dynamically added to `/api/workspace/bootstrap`.
   - Test `/api/workspace/bootstrap` for both `device_01` and `device_02` and assert that all 18 forensic groups, timeline events, 64-byte hex arrays, Sankey SVG, 5-swimlane storyboard events, map pins, 3-mode tamper payloads, OCR results, 1930 NCRP freeze rows, and Section 63 BSA dual previews are non-empty on initial bootstrap!
   - Run the entire `pytest` suite (`213+` existing tests + Phase 10 + Phase 11 tests) and `python main.py --self-test`.