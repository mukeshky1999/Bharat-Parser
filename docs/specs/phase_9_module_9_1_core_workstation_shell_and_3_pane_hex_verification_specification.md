# Engineering Specification: Phase 9, Module 9.1 — Core Desktop Workstation Shell, Case Command Center, Virtualized Evidence Grids & Synchronized 3-Pane Hex/Provenance Verification Layout

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 9.1** of the Forensic Workstation UI/UX Engine (the foundational desktop shell of **Phase 9**, binding the analytical databases of **Phases 1 through 8** to a high-speed, air-gapped investigator interface). It contains **zero programming code** and explains the 4-process desktop isolation model (`Electron Main` $\leftrightarrow$ `Preload` $\leftrightarrow$ `React/Vite Renderer` $\leftrightarrow$ `Python FastAPI` + `Web Workers`), anti-XSS forensic sandboxing, the **Case Command Center & Golden-Hour Alert Dashboard**, the **Dual `FTS5` + Roaring-Bitmap Omnibar**, 60 FPS viewport virtualization with keyset cursor pagination over $50,000,000+$ rows, and the signature **Synchronized 3-Pane Courtroom Provenance & Byte-Highlighted Hex Verification Workspace** from first principles.

## 1. Purpose & Mental Model (Why a World-Class Forensic Backend Fails Without Ergonomic Visual Verification)

In digital forensics, an extraction parser is only as effective as the human examiner's ability to **find, comprehend, verify, and prove** the evidence under tight operational deadlines. When a Cyber Cell Investigating Officer (IO) or Forensic Science Laboratory (`CFSL` / `SFSL`) scientist opens a $1.5\text{ TB}$ mobile extraction containing $45,000,000$ timeline rows, $800,000$ chat messages, $350,000$ images, and $15,000$ financial transactions, poorly designed user interfaces fail in three catastrophic ways:

1. **The "UI Freeze & Pagination Collapse" Problem:**

   * Amateur web/desktop interfaces load large tables into standard HTML DOM nodes or query SQLite using `LIMIT 100 OFFSET 5000000`. Standard DOM tables freeze the browser thread above $5,000$ rows, and SQLite `OFFSET` scans millions of discarded B-tree rows on every page turn—causing a 15-second freeze every time the investigator scrolls!

2. **The "Black-Box Trust Deficit" Problem (Why Every Click Must Prove Its Raw Bytes):**

   * If a forensic tool displays a row saying `"Vikram sent: Delete the 20 Lakh hawala ledger [RECOVERED FROM WAL]"`, defense counsel in court will immediately challenge: *"How do we know the software didn't hallucinate or corrupt that string? Show me the exact file, its SHA-256 hash, the exact WAL frame number, and the raw hexadecimal bytes on disk!"*

   * If the examiner has to manually export the database, open a separate third-party hex editor, and calculate byte offsets by hand, verification becomes impossible during live trial preparation.

3. **The "Cognitive Overload" Problem:**

   * Dumping 85 raw SQLite tables in an alphabetical list forces the investigator to guess where evidence lives. An ergonomic forensic workstation must immediately surface **"Golden Hour" Actionable Intelligence** (Mule bank accounts to freeze, recovered `BIP-39` crypto seeds, active trojan APKs, and 60-second Action-Burst crime sequences) on the opening **Case Command Center** while keeping every underlying byte 1 click away.

### The "Zero-Trust Click" Law of Module 9.1

Every visual element rendered anywhere in the workstation obeys a single architectural invariant:

$$
\texttt{Click Any Decoded Row (Pane 2)} \xrightarrow{< 10\text{ ms}} \texttt{Render 3-Tier SHA-256 Lineage + Highlight Exact Physical Bytes in Hex Viewer (Pane 3)}
$$

## 2. The 6 Fatal UI/UX & Engineering Mistakes in Desktop Forensic Workstations

Before implementing Module 9.1, the developer must understand six critical engineering traps that plague forensic desktop applications:

### Mistake 1: Rendering Forensic Tables with Standard HTML DOM Nodes (`<tr><td>`) Instead of Viewport Virtualization + Keyset Cursors

* **The Trap:** Fetching $50,000$ chat messages or timeline events from the backend and mapping them into standard React `<tr>` / `<div>` DOM elements, OR using SQL `LIMIT 200 OFFSET N` for infinite scrolling.

* **Why It Fails:**

  1. Creating $50,000$ row DOM nodes with 12 columns each generates $600,000+$ DOM elements, consuming $> 4\text{ GB}$ of Chromium Renderer V8 heap memory and dropping scroll frame rates to $< 2\text{ FPS}$.

  2. In SQLite, executing `SELECT * FROM unified_super_timeline ORDER BY timestamp_utc_ns ASC LIMIT 200 OFFSET 10000000` forces SQLite to walk $10,000,200$ index entries from the beginning just to throw the first $10,000,000$ away ($O(N)$ complexity)!

* **The Rule:** Combine **Fixed-Pool Viewport Virtualization** (rendering only the $\approx 35\text{ visible rows}$ in the viewport plus a 10-row overscan buffer) with $O(\log N)$ **Keyset Cursor Pagination** (`WHERE (timestamp_utc_ns, timeline_event_uid) > (:cursor_ts, :cursor_uid) ORDER BY timestamp_utc_ns ASC, timeline_event_uid ASC LIMIT 250`) and an indexed **Cumulative Histogram Seek Map** for instant scrollbar thumb dragging (Section 6.2)!

### Mistake 2: Rendering Scraped Device Strings Without Strict Anti-XSS Sanitization & `contextIsolation` (The "Self-Pwned Forensic Workstation" Vulnerability!)

* **The Trap:** Setting `nodeIntegration: true` and `contextIsolation: false` in Electron for convenience, or rendering scraped chat messages, browser titles, SSID names, or contact vCards using `dangerouslySetInnerHTML` / unescaped HTML templates.

* **Why It Fails:** A seized criminal smartphone is a **hostile untrusted data source**! Suspects, web caches, and malicious emails routinely contain `<script>`, `<img src=x onerror=...>`, or SVG/Markdown XSS payloads in Wi-Fi SSIDs, Telegram display names, or browser histories. If an XSS payload triggers inside an Electron Renderer where `nodeIntegration` is enabled, **the suspect's phone data executes arbitrary OS shell commands on the police forensic workstation**!

* **The Rule:** Enforce the **Hardened Air-Gapped Electron Security Contract** in Section 3.2 (`nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, strict Content-Security-Policy `default-src 'self'`, and pure text-node rendering for all extracted evidence strings).

### Mistake 3: Streaming Full Multi-Gigabyte Files Over IPC to Display a 4 KB Hex View

* **The Trap:** When the examiner clicks a row from a $4\text{ GB}$ `msgstore.db` or `cache4.db` file to inspect its raw bytes in Pane 3, reading or serializing the entire $4\text{ GB}$ file into JSON/Base64 over IPC.

* **Why It Fails:** Serializing gigabytes over IPC crashes the backend and Renderer memory limits immediately.

* **The Rule:** Implement **4 KB Page-Aligned Binary Range Streaming** (Section 6.4): when the user selects a record located at physical byte offset $B_{\text{offset}}$ with length $L_{\text{len}}$, the Renderer requests only the aligned $16\text{ KB}$ window $\left[\lfloor B_{\text{offset}} / 4096 \rfloor \times 4096 - 4096, \ +16384\text{ bytes}\right]$ as a raw `Uint8Array` binary buffer (`application/octet-stream`), rendering the hex view in $< 2\text{ milliseconds}$ regardless of whether the underlying file is $10\text{ KB}$ or $100\text{ GB}$!

### Mistake 4: Blocking the UI Thread with Synchronous Roaring Bitmap & JSON Deserialization

* **The Trap:** Running Roaring Bitmap facet intersections, hex-to-number data conversions, or large timeline histogram aggregations on the main React UI thread.

* **Why It Fails:** Any synchronous computation taking $> 16.6\text{ milliseconds}$ drops frames below $60\text{ FPS}$ and causes input stutter while typing in the search bar.

* **The Rule:** Offload all client-side Roaring Bitmap deserialization, binary hex page parsing, and search highlight tokenizing to dedicated **Background `Web Workers`** communicating via transferable `ArrayBuffer`s (Section 3.1).

### Mistake 5: Forcing Examiners to Manually Compute SQLite Page, Cell & `-wal` Frame Offsets

* **The Trap:** Recording only `table_name = "message"` and `_id = 1042` in the parsed database, so when the examiner opens the Hex Viewer on `msgstore.db`, it just jumps to Byte Offset `0x00000000` (the `"SQLite format 3"` header) instead of jumping to the actual message bytes!

* **Why It Fails:** Showing Byte `0x00000000` of a database file proves nothing about Row #1042.

* **The Rule:** Propagate the exact **`physical_byte_offset`** and **`payload_byte_length`** (captured by Phase 2, Module 2.1's B-Tree Leaf Cell parser and WAL Frame parser!) all the way into Pane 3, using the exact offset equations in Section 6.3 to highlight the **Page/Frame Header**, the **Cell Varint Header**, and the **Selected Column Bytes** in three distinct colors!

### Mistake 6: Burying Critical Metadata (5D Evidentiary State, `IST` vs. `UTC`, and User Profile/Clone ID) Inside Tooltip Sub-Menus

* **The Trap:** Displaying a clean minimalist table that hides whether a message came from `User 0 (Main WhatsApp)` vs. `User 95 (Cloned Dual WhatsApp)`, or whether it was an `Active Row` vs. a `Deleted Freelist Row`, unless the user right-clicks and opens "Properties."

* **The Rule:** Every row in Pane 2 must render compact, high-contrast **Visual Provenance Pills** inline:

  * **Profile Pill:** `[User 0]`, `[Clone 999]`, `[Secure Folder 150]`, `[Slot account2]`

  * **State Pill:** `[LIVE]` (Emerald), `[WAL-HIST]` (Amber), `[DELETED-FREELIST]` (Crimson), `[CARVED-SLACK]` (Purple), `[RECONSTRUCTED]` (Cyan)

  * **Timestamp Pill:** Dual-line or toggled **`IST (+05:30)`** + **`UTC`** with a `[CLOCK-TAMPER !]` badge if flagged by Module 6.5B!

## 3. Step 1 — Sub-Engine 9.1A: Secure Air-Gapped Desktop Process Architecture (`Electron` + `React/Vite` + `Web Workers` + `FastAPI`)

### 3.1 The 4-Process Isolation Topology

The desktop workstation operates as a strictly air-gapped, offline multi-process system (`BharatAnalyzer Workstation`) divided into four isolated execution boundaries:

1. **Process 1 — `Electron Main Process` (Privileged Native Host & Hardware License Guard):**

   * Manages native OS window lifecycle, file-picker dialogs, hardware security dongle / machine-bound cryptographic license verification, and spawns/monitors the local `Python FastAPI` backend daemon over a loopback **Unix Domain Socket (`UDS`)** (on Linux/macOS) or **Named Pipe / Localhost Ephemeral Port secured by a per-launch 256-bit HMAC Bearer Token** (on Windows).

   * Enforces **Zero Outbound Network Policy**: blocks all external internet socket requests (`session.defaultSession.webRequest`) at the Chromium network layer so no case data can ever leak over a network interface and no external remote script can ever load.

2. **Process 2 — `Preload Context-Isolated Bridge` (`contextBridge`):**

   * Exposes a minimal, strictly typed IPC API (`window.forensicBridge`) to the Renderer. Raw Node.js `fs`, `child_process`, and `ipcRenderer` objects are never exposed to the UI context.

3. **Process 3 — `React 19 + Vite Renderer Process` (60 FPS UI Layer) + `Dedicated Web Workers`:**

   * Renders the dark-mode, high-contrast forensic workspace.

   * Spawns a pool of **Dedicated `Web Workers`**:

     * `HexSliceWorker`: Parses 16 KB binary file slices and computes the 12-format Data Interpreter values off the main thread.

     * `FacetBitmapWorker`: Performs client-side Roaring Bitmap intersections and timeline histogram binning in $< 1\text{ ms}$.

4. **Process 4 — `Python FastAPI + Native Worker Pool` (Read-Only Analytical Engine):**

   * Connects to the case SQLite databases (`?mode=ro&immutable=1` for read-only queries; dedicated WAL-mode connection only for `workstation_examiner_annotations.sqlite` and `chain_of_custody_merkle_ledger`).

   * Serves keyset-paginated JSON/MessagePack responses and zero-copy `206 Partial Content` binary file slices from the Phase 1 VFS.

### 3.2 Mandatory Anti-XSS & Hostile-Evidence Sanitization Rules

Because forensic extractions contain malicious HTML, JavaScript, SVG exploits, and malformed Unicode strings:

* **Rule 1 (Strict CSP Header):** The Electron Renderer enforces:
  

  $$
  \texttt{Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self' http://127.0.0.1:*; object-src 'none'; frame-src 'none';}
  $$

* **Rule 2 (Zero Raw HTML Injection):** Extracted text from chats, emails, notifications, or OCR is **never** passed to `innerHTML`. If an email body or cached webpage from Phase 2.4 (`Simple Cache *_0`) is previewed in HTML mode, it is rendered inside a **sandboxed, script-disabled `<iframe sandbox="">` with `allow-scripts` omitted** and all external resource URLs rewritten to local cached `vfs_file_id` blobs or blocked!

* **Rule 3 (Bidi-Override & Homograph Visual Defense):** Malware authors use Unicode Right-to-Left Override (`U+202E` `RLO`) in filenames to disguise `invoice_gpj.apk` as `invoice_kpa.jpg`. The UI renderer automatically detects and visibly badges any string containing Unicode BiDi control characters (`U+202A`–`U+202E`, `U+2066`–`U+2069`) with a bright warning pill **`[UNICODE-RLO-SPOOF]`**!

## 4. Step 2 — Sub-Engine 9.1B: The Case Command Center, Live Ingestion DAG & "Golden Hour" Crime Alert Dashboard

When an examiner creates or opens a case, the default landing tab is the **Case Command Center**—a high-density, single-screen executive cockpit divided into four operational quadrants:

### 4.1 Quadrant 1 (Top-Left): Device Hardware, SIM History & OS Integrity Passport Card

Displays at a glance the foundational attribution metadata extracted by Phases 1, 3.2, and 6.5:

* **Device Identity:** Make, Model, Marketing Name, Hardware Serial, Chipset (`SoC`), and **Luhn-Verified `IMEI 1` & `IMEI 2`** (with 1-click copy buttons for CDR requisitions).

* **SIM & eSIM History Strip (`Module 3.2`):** Lists every physical SIM (`ICCID` + `IMSI` + `MSISDN` + Carrier Circle) and `LPA:1$` burner eSIM ever inserted into the handset, highlighting which SIM was bound to NPCI UPI (`Module 3.2B`).

* **OS & Tamper Readiness Badges (`Module 6.5`):** Color-coded status pills for:

  * `Bootloader: Locked (Green) / Unlocked (Crimson)`

  * `Root/Jailbreak: None / Magisk v27 Detected (Denylist: PhonePe, GPay)`

  * `Clock Integrity: Verified Normal / -48.5h Rollback Isolated at ROWID 501`

  * `Malware Audit: Clean / Sideloaded SMS-Trojan APK + Telegram Bot C2 Found`

### 4.2 Quadrant 2 (Top-Right): Live 8-Phase Pipeline DAG & Dual-Hash Immutability Meter

* **Real-Time Phase DAG Progress:** Shows live completion bars, elapsed time, and extracted record counts across Phases 1 through 8.

* **Statutory Section 63 BSA Immutability Meter (`Module 8.3A`):** Displays the `Pre-Ingest` and `Post-Ingest` `SHA-256` and `MD5` hashes of the Master Acquisition Image alongside the **Case Master Merkle Root (`case_merkle_root_sha256`)** and a green **`[READ-ONLY VFS VERIFIED — 0 BYTES MODIFIED]`** seal.

### 4.3 Quadrant 3 (Bottom-Left): "Golden Hour" Priority Crime & Asset-Freeze Alerts

Automatically surfaces clickable cards for the highest-priority investigative leads discovered across the device:

1. **Card A — Financial & Mule Account Freeze Leads (`Phase 3.5 & 8.4B`):** Shows total discovered Bank Accounts, UPI VPAs, Circular Loops, Pass-Through Mules, and Forged Payment Receipts, with a direct **`[Export 1930 NCRP Bank Lien CSV]`** button.

2. **Card B — Cryptocurrency, P2P & Recovered `BIP-39` Seeds (`Phase 4.1–4.4`):** Shows total `USDT-TRC20` / `EVM` / `BTC` / `XMR` wallets, CEX P2P orders (`Binance`/`Bybit`), and **Plaintext/Unwrapped 12/24-Word Seed Phrases** (with their derived `T...` and `0x...` addresses!), plus a **`[Export FIU-IND / CEX Freeze Packet]`** button.

3. **Card C — 60-Second "Action-Burst" Crime Sequences (`Module 8.1D`):** Lists the top auto-detected multi-phase crime stories (e.g., *"`14:10 IST`: Device Unlocked via FaceID* $\rightarrow$ *PhonePe Foreground* $\rightarrow$ *₹95,000 UPI Outflow* $\rightarrow$ *Screenshot Sent on Telegram Secret Chat"*). Clicking any story card jumps the 3-Pane Workspace directly to that exact 60-second window!

### 4.4 Quadrant 4 (Bottom-Right): Zero-Omission (`UNK`) Accounting Donut & Pending Key-Broker Queue

* Displays the mathematical conservation breakdown from **Module 8.2A**:
  

  $$
  N_{\text{Total VFS Files}} = N_{\text{Parsed}} + N_{\text{Blocked/Encrypted}} + N_{\text{System Static}} + N_{\text{UNK Introspected}}
  $$

* Highlights any **Disguised Extension Mismatches** (e.g., `3 SQLite DBs disguised as .png files`) and any **Pending Password-Locked Vaults (`STATE_2`)**, with a 1-click jump to Module 9.5's Key-Broker Unlocker.

## 5. Step 3 — Sub-Engine 9.1C: The Global `FTS5`/Trigram Query-AST Omnibar, Roaring-Bitmap Facet Sidebar & Dual-Timezone Header

### 5.1 The Global Query-AST Omnibar (Structured DSL + Multilingual Indic + Substring Search)

Positioned persistently at the top of the workstation (`Ctrl+K` / `Cmd+K` shortcut), the Omnibar parses the investigator's input into an Abstract Syntax Tree (`Query-AST`) that routes clauses simultaneously to **Module 8.2D's Dual `FTS5` Indexes** and **Roaring Bitmap Facets**:

| Omnibar Query Syntax | Underlying Engine Execution Path (`< 50 ms`) | Forensic Use Case | 
| ----- | ----- | ----- | 
| **Exact Token / Handle (`merchant.99@okaxis`, `com.phonepe.app`, `+919876543210`)** | Queries `global_fts5_lexical_index` (`unicode61` with `tokenchars '@._:-+/$#'`). | Instant $O(1)$ lookup of UPI VPAs, emails, phone numbers, package names, and file paths without punctuation splitting. | 
| **Arbitrary Mid-String Substring (`*148291*` or `sub:148291`)** | Queries `global_fts5_trigram_index` (`trigram` 3-char sliding window index). | Finds partial 6-digit UTR tails, partial bank account numbers, or mid-string Base58 wallet fragments across 50M rows in $< 20\text{ ms}$. | 
| **Multilingual Indic Script (`"हवाला"`, `"नोएडा"`, `"पैसे"`)** | Normalizes query to **Unicode `NFC`**, strips zero-width joiners, and queries `global_fts5_lexical_index`. | Matches Hindi/Marathi/Tamil/Bengali/Telugu messages and OCR text regardless of whether the source app stored `NFD` or `NFC` code points. | 
| **Structured Field Chip (`utr:6309*`, `pan:ABCPS*`, `crypto:T*`, `app:telegram`, `state:deleted`, `profile:999`)** | Intersects the corresponding **32-Bit Roaring Bitmap** (`Module 8.2D`) with the `FTS5` `doc_uid` posting list in RAM. | Combines structured forensic attributes with full-text search (e.g., `state:deleted app:whatsapp "hawala"` finds only deleted WhatsApp messages containing the word `"hawala"`!). | 

### 5.2 The Sub-Millisecond Roaring-Bitmap Facet Sidebar & Timeline Histogram Scrubber

1. **Left Facet Filter Drawer:**

   * Displays collapsible checkbox groups for the 8 core dimensions (`Forensic Phase`, `Artifact Domain`, `Recovery Classification [LIVE / WAL / FREELIST / CARVED]`, `Application Package`, `User Profile / Clone Slot`, `Financial/Crypto Flag`, `Tamper/Malware Flag`, and `Examiner Bookmark/Tag`).

   * **Instant Dynamic Badge Counts:** Because each checkbox corresponds to a pre-computed 32-bit Roaring Bitmap in RAM (`FacetBitmapWorker`), toggling any checkbox recomputes the exact remaining record count `(N)` next to every other checkbox via bitwise `AND` + `POPCNT` in $< 1.0\text{ millisecond}$!

2. **Collapsible Top Timeline Histogram Scrubber:**

   * Renders a stacked bar chart across the top of the workspace showing activity volume per day/hour (color-coded by `Messaging` 

     $$
     Blue
     $$

     , `Financial/Crypto` 

     $$
     Gold
     $$

     , `Location/Mobility` 

     $$
     Green
     $$

     , and `Deleted/Tamper Alerts` 

     $$
     Crimson
     $$

     ).

   * Dragging a brush selection $[t_{\text{start}}, t_{\text{end}}]$ across any spike in the histogram instantly filters Pane 2 to that exact time window!

### 5.3 The Global Dual-Timezone (`IST +05:30` / `UTC`) & Epoch Header Bar

In the top-right status bar, a persistent 3-mode toggle controls how timestamps are rendered across every grid, chat bubble, and graph in the application:

* **Mode 1 (`DUAL_IST_AND_UTC` — Default for Indian LEAs):** Displays `2026-11-05 19:50:00.120 IST (+05:30)` on the primary line and `2026-11-05T14:20:00.120000000Z (UTC)` in muted monospace directly beneath it.

* **Mode 2 (`IST_PRIMARY_ONLY`)** & **Mode 3 (`UTC_PRIMARY_WITH_DEVICE_RECORDED_TZ`)** (which highlights when the suspect's phone was physically operating in a foreign timezone such as `UTC+04:00 Dubai GST` or `UTC+07:00 Cambodia ICT`!).

## 6. Step 4 — Sub-Engine 9.1D: The Synchronized 3-Pane Forensic Verification Workspace & Byte-Level Hex Inspector

The core analytical screen of the workstation is a customizable, keyboard-driven **3-Pane Split Layout**:

```
+--------------------------------------------------------------------------------------------------+
| [Global FTS5/Trigram Omnibar: state:deleted app:whatsapp "UTR"          ] [TZ: IST+05:30 | UTC]  |
+----------------------+---------------------------------------------------+-----------------------+
| PANE 1: NAVIGATOR    | PANE 2: 60 FPS VIRTUALIZED EVIDENCE GRID          | PANE 3A: COURTROOM    |
| [Domains] [Apps]     | [TimelineHistogramScrubber: |||..|||||..|       ] | PROVENANCE CARD       |
| [Entities] [VFS]     |---------------------------------------------------| • VFS File #142       |
|                      | Row | Timestamp (IST/UTC) | State   | App | Event | • SHA-256 & MD5       |
| > Phase 3: Finance   | 101 | 19:50:02.120 IST    | [WAL]   | WA  | ...   | • WAL Frame #88       |
| > Phase 4: Crypto    | 102 | 19:50:14.890 IST    | [LIVE]  | PhPe| ...   | • Offset: 0x0041A2B0  |
| v Phase 5: Messaging | 103 | 19:50:19.300 IST    | [FREE]  | TG  | ...   |-----------------------|
|   • WhatsApp (User0) | 104 | 19:50:45.000 IST    | [SNAP]  | Sys | ...   | PANE 3B: SYNCHRONIZED |
|   • WhatsApp (Cln999)|                                                   | HEX & DATA INSPECTOR  |
|   • Telegram (Slot1) |                                                   | 0041A2A0: 37 7F 06 82 |
| > Phase 6: Telemetry |                                                   | 0041A2B0: [44 65 6C 65|
| > Phase 7: Visual/OCR|                                                   | 74 65 20 55 54 52]    |
| > Phase 8: UNK Audit |                                                   | [Data Interpreter]    |
+----------------------+---------------------------------------------------+-----------------------+

```

### 6.1 Pane 1 (Left): The 4-Mode Multi-Taxonomy Navigator Tree

Pane 1 provides four switchable tree tabs at the top of the left sidebar, showing live Roaring-Bitmap filtered badge counts `[Active / Recovered Deleted]` next to every node:

1. **Tab 1 — `Forensic Domains` (By Investigation Category):** Groups artifacts logically under *Unified Super-Timeline*, *Action-Burst Crime Stories*, *Financial & UPI Ledger*, *Crypto Wallets & CEX P2P*, *Messaging & Calls*, *Geolocation & Mobility*, *Visual Media, Snapshots & KYC OCR*, and *OS Telemetry & Anti-Forensics*.

2. **Tab 2 — `Application Sandboxes` (Grouped by User Profile / Clone Slot):** Groups all installed and **Uninstalled Ghost Apps (`[GHOST]`)** by Android User Profile (`User 0 Main`, `User 10 Work`, `User 95 Dual Messenger`, `User 150 Secure Folder`, `User 999 App Cloner`) and iOS Containers, so the examiner immediately spots parallel cloned apps!

3. **Tab 3 — `360° Master Entities` (`Module 8.1A`):** Lists consolidated Actor Cards sorted by interaction weight, financial volume, or risk flags.

4. **Tab 4 — `Virtual Filesystem (VFS) & UNK Explorer` (`Module 1.1 & 8.2`):** Full hierarchical directory tree of the phone's partitions, mountable archives, and `STATE_4_UNK` files.

### 6.2 Pane 2 (Center): The 60 FPS Virtualized Evidence Grid & Keyset Pagination Math

To scroll smoothly through $N_{\text{total}} = 50,000,000$ rows at $60\text{ FPS}$ ($< 16.6\text{ ms}$ frame budget) with constant $< 150\text{ MB}$ RAM usage:

1. **Viewport Windowing Equations:**
   Given a fixed (or pre-measured) row height $h_{\text{row}} = 36\text{ px}$, viewport container height $H_{\text{view}}$, current scroll offset $S_{\text{top}}$, and overscan buffer $B_{\text{over}} = 10\text{ rows}$:
   

   $$
   i_{\text{first}} = \max\left(0, \ \left\lfloor \frac{S_{\text{top}}}{h_{\text{row}}} \right\rfloor - B_{\text{over}}\right)
   $$

   $$
   i_{\text{last}} = \min\left(N_{\text{filtered}} - 1, \ \left\lceil \frac{S_{\text{top}} + H_{\text{view}}}{h_{\text{row}}} \right\rceil + B_{\text{over}}\right)
   $$

   
   Only the $i_{\text{last}} - i_{\text{first}} + 1 \approx 45$ rows are mounted in the DOM at any instant, positioned via hardware-accelerated CSS `transform: translate3d(0, ${i * h_row}px, 0)`.

2. **Two-Tier Sliding Window Page Cache + Keyset Seeking:**

   * For sequential scrolling (`Wheel` / `PageDown` / `J`/`K` keys), the Renderer prefetches 250-row pages from FastAPI using $O(\log N)$ **Keyset Cursor Pagination**:
     

     $$
     \texttt{GET /api/v1/timeline/slice?after\_ts\_ns=1762348800000000000\&after\_uid=104829\&limit=250}
     $$

   * For **Arbitrary Scrollbar Thumb Jump** (e.g., dragging the scrollbar thumb to $65\%$ of a 20-million-row table):

     * Instead of running `OFFSET 13000000`, the backend maintains a lightweight **Quantile Milestone Index Table** (recording the exact `(timestamp_utc_ns, timeline_event_uid)` at every $10,000\text{-th}$ row during Phase 8.1 materialization!).

     * Jumping to row $13,000,000$ looks up Milestone #1300 in $O(1)$ time ($0.1\text{ ms}$) and executes a standard keyset query from that milestone!

3. **Keyboard-First Examiner Ergonomics:**

   * `J` / `K` or `Down` / `Up`: Move row selection (automatically updating Pane 3 in real time).

   * `B`: Toggle Bookmark & open Quick-Tag pill menu (`"Relied Upon"`, `"Mule Account"`, `"Handler Chat"`, `"Alibi Location"`).

   * `Space`: Open full-screen Quick-Look modal for media, PDFs, or long JSON/Protobuf trees.

   * `T`: Pivot to the **Unified Super-Timeline** centered on the selected row's exact timestamp ($\pm 5\text{ minutes}$) so the examiner can see everything else that happened on the phone at that exact minute!

### 6.3 Pane 3A (Right-Top): The Courtroom Chain-of-Provenance Card

Whenever any row in Pane 2 (or any chat bubble, graph node, or map pin in Modules 9.2–9.4) is clicked, **Pane 3A** immediately renders its complete, court-admissible **Chain-of-Provenance Card**:

1. **3-Tier Cryptographic Hash Lineage (`Module 8.3A`):**

   * `Tier 1 Master Image`: Filename + `SHA-256` + `MD5` (`[VERIFIED IDENTICAL]`)

   * `Tier 2A VFS Source File`: Canonical path (e.g., `/data/user/0/com.whatsapp/databases/msgstore.db-wal`), `vfs_file_id`, byte size, `btime`/`mtime`, and `SHA-256` + `MD5`.

   * `Tier 2B Decrypted Derivative` (if applicable): Unwrapping recipe used (e.g., `"SQLCipher v4 decrypted via Keystore key SignalSecret"`), and `Product B2` `SHA-256`.

2. **Exact Structural Container Coordinates:**

   * Displays the container type (`SQLite 3 B-Tree Page`, `SQLite WAL Frame`, `Apple Biome SEGB v2`, `Tencent MMKV`, `LevelDB .ldb`, `Protobuf Wire Stream`), the exact Table Name, `ROWID`, B-Tree Page Number (`Page #412`) or WAL Frame Number (`Frame #88`, `Salt-1: 0x9A8B7C6D`), and the **5D Evidentiary Vector**!

### 6.4 Pane 3B (Right-Bottom): The Synchronized 4-Layer Color-Coded Hex Inspector & 12-Format Data Interpreter

Directly below the Provenance Card sits the built-in **Synchronized Hex/Binary Inspector**:

1. **Exact Physical Byte-Offset Equations Used to Jump the Hex Cursor:**

   * **For an Active or Freelist SQLite B-Tree Page Record (`Page_No`** $\ge 1$**, `Page_Size`** $\in \{1024, 4096, 8192, 16384, 32768, 65536\}$**, `Cell_Offset_In_Page`):**
     

     $$
     \text{Physical\_File\_Offset} = \big(\text{Page\_No} - 1\big) \times \text{Page\_Size} + \text{Cell\_Offset\_In\_Page}
     $$

   * **For a Historical SQLite `-wal` Frame Record (`Frame_No`** $\ge 1$**, `WAL_Header`** $= 32\text{ bytes}$**, `Frame_Header`** $= 24\text{ bytes}$**):**
     

     $$
     \text{Physical\_WAL\_Offset} = 32 + \big(\text{Frame\_No} - 1\big) \times \big(\text{Page\_Size} + 24\big) + 24 + \text{Cell\_Offset\_In\_Page}
     $$

   * **For `MMKV`, `LevelDB`, `SEGB`, or Carved Media/Strings:** Uses the direct `physical_byte_offset` recorded by Phase 2 / Phase 7.

2. **The 4-Layer Color-Coded Byte Highlighting System:**
   When the Hex Viewer loads the $16\text{ KB}$ binary window around `Physical_Offset`, it automatically highlights four structural byte ranges in the `16-byte-per-row` hex grid (`Offset | 16 Hex Bytes | 16 ASCII/UTF-8 Dots`):

   * **Layer 1 (`Slate-Blue Highlight`):** The **Page Header or WAL Frame Header** ($8/12\text{ bytes}$ for SQLite B-Tree page header `0x0D` + cell count; $24\text{ bytes}$ for WAL frame header showing Page Number and `Salt-1`/`Salt-2`).

   * **Layer 2 (`Amber Highlight`):** The **Record Cell Header** (`Payload_Size` Huffman Varint + `ROWID` Varint + Column Serial Type Varints `s_1, s_2, ...`).

   * **Layer 3 (`Bright Cyan Highlight + Focus Ring`):** The **Exact Column / Field Payload Bytes** corresponding to the cell or text field the examiner clicked in Pane 2!

   * **Layer 4 (`Crimson Tint`):** Any surrounding **Unallocated Freeblock / Freelist Slack Bytes** on the same page!

3. **The Live 12-Format Data Interpreter Sidebar:**
   Clicking or dragging a selection across any $1\text{ to }16\text{ bytes}$ in the Hex Viewer instantaneously decodes those bytes in a compact side panel across 12 forensic formats (with a Little-Endian / Big-Endian toggle):

   * `Int8 / UInt8`, `Int16 / UInt16`, `Int32 / UInt32`, `Int64 / UInt64`

   * `SQLite 9-Byte Huffman Varint` (Big-Endian 7-bit continuation)

   * `Protobuf / LevelDB LEB128 Varint` & `ZigZag SLEB128`

   * `Float32` & `Float64 (IEEE-754 Double)`

   * `Unix Epoch Seconds (10-digit)` $\rightarrow$ `IST & UTC`

   * `Unix Epoch Milliseconds (13-digit)` $\rightarrow$ `IST & UTC`

   * `Unix Epoch Microseconds / WebKit Epoch (1601-01-01)` $\rightarrow$ `IST & UTC`

   * `Apple Cocoa CoreData Seconds (2001-01-01)` $\rightarrow$ `IST & UTC`

   * `UTF-8 String`, `UTF-16LE String`, and `Base58Check / Hex`!

## 7. Local UI State Schema & FastAPI IPC Contract (`workstation_ui_state.sqlite`)

### Table 1: `examiner_bookmarks_and_tags_ledger` (Persistent Examiner Annotations & "Relied-Upon" Selections)

| Column Name | SQLite Type | Constraints | Description | 
| ----- | ----- | ----- | ----- | 
| `bookmark_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique Bookmark ID. | 
| `target_domain_table` | `TEXT` | `NOT NULL` | E.g., `"unified_super_timeline"`, `"whatsapp_messages_master_ledger"`, `"unified_financial_transactions_ledger"`. | 
| `target_record_uid` | `INTEGER` | `NOT NULL` | Primary key of the bookmarked record in its table. | 
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `vfs_index.file_id`. | 
| `physical_byte_offset` | `INTEGER` | `NULL` | Exact byte offset in the source file for instant Hex jump. | 
| `tag_category_badge` | `TEXT` | `NOT NULL` | E.g., `"KEY_SMOKING_GUN"`, `"MULE_ACCOUNT_FREEZE"`, `"CONSPIRACY_CHAT"`, `"ALIBI_PROOF"`, `"TAMPER_EVIDENCE"`. | 
| `is_relied_upon_for_sec230_bnss` | `INTEGER` | `DEFAULT 1` | **`1` = Include in Courtroom Dossier & Section 230 BNSS Defense Disclosure Copy (`Module 8.4C`)!** | 
| `examiner_narrative_note` | `TEXT` | `NULL` | Investigator's custom annotation note for the report exhibit caption. | 
| `created_by_examiner` | `TEXT` | `NOT NULL` | Examiner name/ID (also logged automatically into Module 8.3C's `chain_of_custody_merkle_ledger`!). | 
| `created_at_ist_iso` | `TEXT` | `NOT NULL` | `"YYYY-MM-DD HH:MM:SS IST (+05:30)"`. | 

### Table 2: Core FastAPI $\leftrightarrow$ Electron Renderer IPC Endpoints

| Endpoint Method & Path | Request Parameters / Payload | Response Format & Latency Target | 
| ----- | ----- | ----- | 
| **`GET /api/v1/case/command-center`** | `case_id` | JSON containing Quadrant 1–4 summaries (Hardware/SIMs, Phase DAG, Golden-Hour Alerts, `UNK` Donut, Merkle Root). Target: `< 15 ms`. | 
| **`POST /api/v1/search/query-ast`** | `query_string`, `active_facet_filters_json`, `cursor_ts_ns`, `cursor_uid`, `limit = 250` | Keyset-paginated JSON array of matching rows + updated Roaring Bitmap facet counts + histogram buckets. Target: `< 35 ms`. | 
| **`GET /api/v1/provenance/record-detail`** | `domain_table`, `record_uid` | Complete 3-Tier Hash Lineage (`SHA-256` + `MD5`), 5D Evidentiary State, SQLite Page/WAL Frame numbers, and exact `physical_byte_offset` + `column_byte_ranges_json`. Target: `< 5 ms`. | 
| **`GET /api/v1/vfs/hex-window`** | `vfs_file_id` (or `staging_id`), `center_offset`, `window_bytes = 16384` | Raw binary `application/octet-stream` (`Uint8Array` of $16,384\text{ bytes}$ aligned to 4 KB boundary) + custom header `X-Base-Offset`. Target: `< 2 ms`. | 

## 8. Developer Acceptance Test Checklist for Module 9.1

1. **The 50-Million-Row 60 FPS Keyset Scroll & Quantile Thumb-Jump Test:**

   * Load a synthetic or real `unified_super_timeline` table containing $10,000,000+$ rows. Scroll continuously using the mouse wheel and drag the scrollbar thumb from $0\%$ to $75\%$ to $100\%$.

   * Verify that DOM node count in Pane 2 never exceeds $100\text{ row elements}$, memory usage stays flat ($< 200\text{ MB}$ delta), keyset queries return in $< 15\text{ ms}$, and frame rate remains $\ge 55\text{ FPS}$ with zero UI thread blocking.

2. **The Hostile XSS Payload Sanitization & Air-Gapped Security Test:**

   * Insert a WhatsApp message, a Wi-Fi SSID, and a contact name containing `<img src=x onerror="window.forensicBridge && alert('XSS')">`, `<script>require('child_process').exec('calc')</script>`, and a Unicode Right-to-Left Override filename `invoice\u202Egpj.apk`.

   * Verify that zero scripts execute, `require` is undefined in the Renderer, the text renders safely as literal characters, and the filename displays the `[UNICODE-RLO-SPOOF]` warning badge!

3. **The Synchronized Pane 2** $\rightarrow$ **Pane 3 WAL Frame Byte-Offset & 4-Layer Hex Highlight Test:**

   * Click a recovered WhatsApp message in Pane 2 that was carved from `msgstore.db-wal` (`Page_Size = 4096`, `Frame_No = 10`, `Cell_Offset_In_Page = 3812`, `Text_Column_Offset_In_Cell = 28`, `Text_Length = 42`).

   * Verify that Pane 3A displays the 3-Tier `SHA-256` + `MD5` lineage of `msgstore.db-wal`, and Pane 3B jumps the Hex Viewer to exact physical byte offset:
     

     $$
     32 + (10 - 1) \times (4096 + 24) + 24 + 3812 = 40,948 \ (\texttt{0x00009FF4})
     $$

     
     highlighting the 24-byte WAL Frame Header in Slate-Blue, the Cell Varint Header in Amber, and the 42-byte message UTF-8 payload (`0x0000A010` to `0x0000A039`) in Bright Cyan!

4. **The Sub-Millisecond Roaring-Bitmap Facet Intersection Test:**

   * In the Omnibar and Facet Sidebar, simultaneously toggle `Phase 5 (Messaging)`, `State: RESIDUAL_RECORD (Deleted)`, and `User Profile: 999 (App Cloner)`.

   * Verify that `FacetBitmapWorker` intersects the three Roaring Bitmaps and updates all sidebar badge counts and the top timeline histogram in $< 5\text{ milliseconds}$!