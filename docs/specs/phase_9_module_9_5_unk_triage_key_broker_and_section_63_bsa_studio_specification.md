# Engineering Specification: Phase 9, Module 9.5 — Interactive Zero-Omission (`UNK`) Triage Workbench, Cryptographic Key-Broker Unlocker Console & The WYSIWYG Section 63(4)(c) BSA 2023 Courtroom Report Studio

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 9.5** of the Forensic Workstation UI/UX Engine (completing **Phase 9** and the entire 9-Phase DFIR Platform Architecture, binding the backend engines of **Modules 2.2, 3.3, 4.4, 8.2, 8.3, and 8.4** to an interactive expert workbench and statutory certification studio). It contains **zero programming code** and explains how to build the **Interactive Zero-Omission (`UNK`) Triage Workbench** (featuring a 4 KB Sliding-Window Block Entropy Profiler $H(b_k)$, 256-Bin $\chi^2$ Byte Histogram, and Zero-Code Schema Mapper to promote unrecognized app tables into the Super-Timeline), how to operate the **Interactive Cryptographic Key-Broker Console** with **Targeted Incremental DAG Hot-Patching**, how to de-conflict and export **Golden-Hour `1930 NCRP` & `FIU-IND` Freeze Packets** with Victim-Account Safeguard Locks, and how to run the **4-Step WYSIWYG Section 63(4)(c) BSA 2023 Statutory Certificate & Section 230 BNSS Dual-Preview Courtroom Dossier Studio** from first principles.

---

## 1. Purpose & Mental Model (Closing the "Last Mile" Between Raw Forensics, Unrecognized Apps, Locked Vaults & Courtroom Admissibility)

In real-world mobile forensic investigations, the final 10% of the workflow determines whether an investigation succeeds in freezing stolen funds and securing a conviction in court:

1. **Triage of Unrecognized (`STATE_4_UNK`) Apps Without Writing Code:**
   * Suppose a seized phone contains a custom-built hawala accounting APK (`com.custom.hisabkitab`) or a brand-new regional chat app whose SQLite schema is not yet hardcoded in Phases 3–7. While **Module 8.2C** automatically sweeps all `STATE_4_UNK` files for 10 forensic indicators, a senior examiner needs an interactive workbench to inspect the unknown SQLite table, map its custom columns (`tx_time` $\rightarrow$ `Timestamp`, `party_mobile` $\rightarrow$ `Actor Phone`, `jama_amount` $\rightarrow$ `Amount`), and click **`[Promote Table to Unified Super-Timeline & Entity Graph]`** in 15 seconds without writing a single line of Python or SQL!
2. **Interactive Password Recovery & Live Incremental Unwrapping (`STATE_2_DECRYPTION_BLOCKED`):**
   * During initial automated ingestion, a password-protected bank statement PDF, a locked `MetaMask` / `Trust Wallet` keystore, a `.crypt15` backup, or a 7-Zip archive may remain locked (`DECRYPTION_PENDING_KEY_BROKER`) because the suspect used a custom passphrase.
   * Two hours into the investigation, the Investigating Officer (IO) finds a handwritten slip in the suspect's wallet—or spots a password in a WhatsApp chat screenshot (`"My pass is Vikram@786"`). The examiner needs an interactive **Cryptographic Key-Broker Console** where typing `"Vikram@786"` unlocks the blocked file **and incrementally hot-patches only its newly decrypted records into the Entity Graph, Super-Timeline, and `FTS5` search index in $< 3\text{ seconds}$**, without re-running the entire 2-hour device ingestion!
3. **De-Conflicting Golden-Hour Freeze Sheets & Signing Statutory `Section 63(4)(c) BSA` Certificates:**
   * Before uploading a bulk bank-freeze CSV to the **`1930` NCRP (`CFCFRMS`)** portal or printing the final **Chargesheet Dossier**, the IO must visually verify that the victim's own bank account is not accidentally listed as a mule account to be frozen, verify that **Part A and Part B of the Section 63(4)(c) BSA 2023 Schedule Certificate** are 100% populated, and preview the **Section 230 BNSS Defense Disclosure Copy** side-by-side with the unredacted Court Master Copy.

---

## 2. The 6 Fatal UI/UX & Engineering Mistakes in Triage Workbenches, Key Unwrappers & Report Studios

Before implementing Module 9.5, the developer must understand six critical engineering traps:

### Mistake 1: Displaying Only a Single Whole-File Shannon Entropy Number ($H(X) = 7.82$) Without a Sliding-Window Block Entropy Curve ($H(b_k)$)
* **The Trap:** Showing a single scalar number `"Entropy: 7.82 bits/byte"` next to an unknown `.bin` or `.dat` file in the `UNK` Triage table.
* **Why It Fails:** Many proprietary vault files, partially encrypted databases, and malware droppers are **hybrid containers**: for example, the first $4\text{ KB}$ is an unencrypted JSON/XML header ($H \approx 4.8$), Bytes $4\text{ KB}\text{–}60\text{ KB}$ are an AES-encrypted payload ($H \approx 7.998$), and the final $16\text{ KB}$ is an unencrypted SQLite index or appended certificate ($H \approx 5.2$)! A single whole-file average ($H = 7.82$) hides where the plaintext islands live inside the file!
* **The Rule:** Sub-Engine 9.5A renders an interactive **Sliding-Window 4 KB Block Entropy Skyline Chart ($H(b_k)$ across blocks $k = 0 \dots M-1$)** paired with a **256-Bin Byte Frequency Histogram** (Section 3.2). Clicking any low-entropy valley on the chart immediately jumps **Pane 3B's Hex Viewer** to that exact unencrypted 4 KB block!

### Mistake 2: Forcing Examiners to Export Unknown SQLite Databases to External Tools Instead of Providing a Zero-Code Column-Role Mapper
* **The Trap:** Telling the examiner that `com.custom.app/databases/data.db` is an unrecognized SQLite database and requiring them to export it to `DB Browser for SQLite` externally.
* **Why It Fails:** Once a database is exported outside the workstation, any rows the examiner finds in an external tool are disconnected from the case's **Unified Super-Timeline**, **Master Entity Graph**, **Roaring Bitmap Facets**, and **Section 63 BSA Hash Schedule**!
* **The Rule:** Sub-Engine 9.5A provides an **Interactive Zero-Code SQLite & Protobuf Schema Mapper** (Section 3.3) where the examiner previews any `STATE_4_UNK` table (including its carved `-wal` and freelist rows!) and assigns semantic column roles (`Timestamp [Epoch Auto-Detect]`, `Sender/Actor`, `Recipient`, `Message/Note`, `Amount`, `Latitude/Longitude`) via dropdown headers to inject those rows directly into the live case!

### Mistake 3: Re-Running Full Case Ingestion When a Single Locked File Is Unwrapped in the Key-Broker Console
* **The Trap:** Requiring a full case re-parse when the examiner supplies a newly discovered password or decryption key for a locked database or PDF.
* **Why It Fails:** Re-parsing a $512\text{ GB}$ extraction takes $30\text{ to }90\text{ minutes}$. During a live suspect interrogation or Golden-Hour freeze operation, waiting 60 minutes after entering a password is unacceptable.
* **The Rule:** Implement **Sub-Engine 9.5B's Targeted Incremental DAG Hot-Patcher** (Section 4.2), which routes only the newly unwrapped `Product B2` derivative file through its specific domain parser (`Phase 3/4/5/7`), appends the resulting nodes/events to `entity_master_profiles` and `unified_super_timeline`, updates `evidentiary_hash_manifest_ledger`, and incrementally updates the `FTS5` and Roaring Bitmap indexes in $< 3\text{ seconds}$!

### Mistake 4: Exporting `1930 NCRP` Bank Lien Sheets Without a "Complainant / Victim Account Safeguard Lock"
* **The Trap:** Automatically exporting every bank account and UPI VPA found in a transaction chain to the `1930 NCRP` bank-freeze CSV without distinguishing the **Complainant/Victim's Source Account** (or the suspect's innocent employer/utility billers like `BESCOM`, `IRCTC`, `Jio Postpaid`) from the **Suspect/Mule Beneficiary Accounts**.
* **Why It Fails:** If an automated freeze sheet includes the victim's own bank account or a utility company's collection account in the `Beneficiary_Account_to_Freeze` column, the Nodal Officer's automated script will freeze the victim's own bank account!
* **The Rule:** Sub-Engine 9.5C enforces a **3-Color De-Confliction & Allowlist Safeguard Table** (Section 5.1) that automatically locks out `KNOWN_UTILITY_MERCHANT_ALLOWLIST` VPAs/accounts and requires explicit `TARGET_MULE_BENEFICIARY` role confirmation before generating the `1930 NCRP` CSV!

### Mistake 5: Allowing Report Export When Section 63(4)(c) BSA Statutory Fields Are Blank or the Merkle Chain Is Unverified
* **The Trap:** Providing a simple `"Export PDF"` button that prints whatever is on screen without validating statutory completeness under **Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023**.
* **Why It Fails:** An incomplete Section 63(4)(c) BSA Certificate—missing the device's IMEI/Serial in Part A, missing the cryptographic hash algorithm declaration in Part B, or missing the Section 63(2)(c) technical anomaly disclosure—renders the entire report vulnerable to exclusion at trial.
* **The Rule:** Sub-Engine 9.5D implements a **Mandatory Pre-Flight Statutory Compliance Gate** (Section 6.2) that validates every required clause of `Part A` and `Part B` and verifies the unbroken **Merkle Chain-of-Custody (`chain_of_custody_merkle_ledger`)** before unlocking the final courtroom export!

### Mistake 6: Generating `Section 230 BNSS` Defense Disclosure Copies Blindly Without a Side-by-Side Redaction Diff Preview
* **The Trap:** Generating the `SECTION_230_BNSS_DEFENSE_DISCLOSURE_COPY` file in the background without showing the Investigating Officer a visual comparison between the **Unredacted Court/IO Master Dossier** and the **Redacted Accused/Defense Copy**.
* **The Rule:** Sub-Engine 9.5D renders a **Synchronized Dual-Preview PDF/HTML5 Studio** (Section 6.3) where the IO can visually inspect every withheld `POCSO / CSAM / Intimate Media` placeholder card (*P. Gopalkrishnan v. State of Kerala* safeguard) and every `Section 72 BNS` victim-name redaction before signing!

---

## 3. Step 1 — Sub-Engine 9.5A: The Interactive Zero-Omission (`UNK`) Triage Workbench, Sliding-Window Entropy Profiler & Zero-Code Schema Mapper

### 3.1 Visual Layout of the Zero-Omission (`UNK`) Triage Workbench

```
+----------------------------------------------------------------------------------------------------------+
| ZERO-OMISSION VFS AUDIT WORKBENCH: [Total Files: 142,810 == Parsed: 98,412 + Blocked: 4 + Static: 44,102 |
|                                     + UNK User Files: 292 (100% Accounted — 0 Files Omitted)]            |
| [Filter UNK: (*) All (292)  ( ) Spoofed Extension (3)  ( ) High-Entropy Encrypted (5)  ( ) Has Hits (18)]|
+---------------------------------------------------+------------------------------------------------------+
| LEFT PANE: STATE_4_UNK & SPOOFED FILE QUEUE       | RIGHT PANE: SLIDING-WINDOW ENTROPY & ZERO-CODE MAPPER|
|---------------------------------------------------|------------------------------------------------------|
| ! logo_icon.png [SPOOFED: SQLite 3 DB!]           | [4 KB Block Entropy Skyline: H(b_k) across File]     |
|   /sdcard/Android/data/com.hisab.app/files/       | 8.0 |      ████████████████████                      |
|   Size: 256 KB | H(X): 6.12 | Hits: 14 UTRs/Phones| 4.0 | █████                    ██████████            |
|---------------------------------------------------|     +----------------------------------------------  |
| 🔒 secret_store.db [SQLCipher Page-Aligned!]      |     Block 0 (Header)   Block 1..14 (AES)   Block 15  |
|   /data/user/0/com.vault.x/databases/             | [Click any block bar to jump Pane 3B Hex Viewer!]    |
|   Size: 65,536 B (16x4096) | H: 7.997 | Chi2: 248 |------------------------------------------------------|
|   [-> Send to Key-Broker Unlocker]                | ZERO-CODE SQLITE / PROTOBUF SCHEMA MAPPER:           |
|---------------------------------------------------| Table: `hisab_ledger` (48 Active + 12 WAL Del Rows)  |
| 📄 cache_blob.dat [Protobuf Wire Stream]          | Col 1: ` jama_ts `  -> [Role: Timestamp (Unix ms) v] |
|   /data/user/0/com.regional.chat/files/           | Col 2: ` party_no ` -> [Role: Actor Phone (E.164) v] |
|   Size: 18 KB | H(X): 5.84 | Hits: 6 Phones       | Col 3: ` रकम_inr `  -> [Role: Fiat Amount (INR)   v] |
|                                                   | [⚡ Promote 60 Rows to Super-Timeline & Entity Graph]|
+---------------------------------------------------+------------------------------------------------------+
```

### 3.2 Mathematical Specification of the 4 KB Sliding-Window Block Entropy Skyline ($H(b_k)$) & Byte-Class Color Map

When the examiner selects any file of size $N\text{ bytes}$ in the `UNK` Triage Queue, `HexSliceWorker` computes a block-by-block diagnostic profile across contiguous $B = 4,096\text{-byte}$ pages ($k = 0, 1, \dots, \lceil N / 4096 \rceil - 1$):

1. **Per-Block Shannon Entropy ($H(b_k) \in [0.0, \ 8.0]\text{ bits/byte}$):**
   For block $b_k$ containing $n_k \le 4096\text{ bytes}$ with byte value counts $c_{k,i}$ ($i \in \{0 \dots 255\}$):
   $$H(b_k) = -\sum_{i=0, \ c_{k,i} > 0}^{255} \left(\frac{c_{k,i}}{n_k}\right) \log_2 \left(\frac{c_{k,i}}{n_k}\right)$$
2. **Per-Block 4-Class Byte Composition Stack:**
   For each 4 KB block $b_k$, compute the percentage of bytes falling into four visual classes:
   * **Class 1 (`Null / Zero Padding` — Byte `0x00`):** Slate Gray (identifies sparse SQLite/filesystem slack pages).
   * **Class 2 (`Printable ASCII & Whitespace` — Bytes `0x09`, `0x0A`, `0x0D`, `0x20`–`0x7E`):** Emerald Green (identifies plaintext JSON, XML, SQL, or chat strings buried inside binary files!).
   * **Class 3 (`High-Bit Structured / UTF-8 Multi-Byte / Varint` — Bytes `0x80`–`0xFE`):** Cyan.
   * **Class 4 (`All-Ones / Erase Fill` — Byte `0xFF`):** Amber.
3. **256-Bin Byte Frequency Histogram with $\chi^2$ Uniformity Reference Line:**
   Renders a 256-bar chart for the selected block or file showing the observed count $c_i$ for each byte `0x00`..`0xFF` against the horizontal dashed **Ideal Uniform Ciphertext Reference Line** $E = \frac{n_k}{256.0}$:
   * True AES/ChaCha20/SQLCipher ciphertext hugs the flat horizontal reference line $E$ across all 256 bars ($\chi^2 \in [180, \ 350]$).
   * Compressed/encoded streams show sharp spikes on structural marker bytes (`0x00`, `0xFF`, or ASCII tag bytes), allowing the examiner to distinguish encryption from compression in 1 second!

### 3.3 The Interactive Zero-Code Schema & Column-Role Mapper (Promoting `UNK` Tables to the Live Case)

When an examiner selects an unrecognized SQLite database (`STATE_4_UNK`), JSON array, CSV, or schema-less Protobuf stream in the `UNK` Triage Workbench:
1. The right pane displays a live preview grid of every table in the file (already processed through **Phase 2, Module 2.1** so active, `-wal` historical, and B-Tree freelist deleted rows are all visible with their `[LIVE]`, `[WAL]`, and `[FREELIST]` pills!).
2. Above each column header sits an interactive **Semantic Role Dropdown** (pre-populated with **Module 8.2C's heuristic guess**, which the examiner can confirm or override):
   * `IGNORE_COLUMN`
   * `TIMESTAMP_EPOCH` (with sub-selector: `Auto-Detect`, `Unix Seconds (10d)`, `Unix Milliseconds (13d)`, `Unix Microseconds (16d)`, `Apple Cocoa Seconds`, `ISO-8601 String`)
   * `ACTOR_SOURCE_IDENTIFIER` (`Phone E.164`, `UPI VPA`, `User ID / Handle`, `Display Name`)
   * `ACTOR_TARGET_IDENTIFIER` (`Phone E.164`, `UPI VPA`, `Bank Account`, `Crypto Address`)
   * `MESSAGE_OR_EVENT_BODY_TEXT`
   * `FINANCIAL_OR_CRYPTO_AMOUNT` (with currency tag `INR`, `USDT`, `USD`)
   * `GPS_LATITUDE` & `GPS_LONGITUDE` (`Decimal Degrees` or `E7 Integer`)
3. Clicking **`[⚡ Promote Table to Super-Timeline & Entity Graph]`** immediately ingests all rows of that custom table into **`unified_super_timeline` (`Module 8.1C`)**, merges the actors into **`entity_master_profiles` (`Module 8.1A`)**, indexes the text into **Dual `FTS5` (`Module 8.2D`)**, and logs the promotion in **`chain_of_custody_merkle_ledger` (`Module 8.3C`)**!

---

## 4. Step 2 — Sub-Engine 9.5B: The Interactive Cryptographic Key-Broker Console, Candidate Password Harvester & Incremental DAG Hot-Patcher

### 4.1 The `STATE_2_DECRYPTION_BLOCKED` Queue & Auto-Harvested Candidate Password Matrix

When the examiner opens the **Key-Broker Unlocker Console**, the UI displays:
1. **Left Panel (`Pending Encrypted Containers — STATE_2`):**
   * Lists every file currently in `ENCRYPTED_GATED_MISSING_KEY`:
     * Password-protected **Indian Bank / Credit Card Statement PDFs** (`Module 3.3`)
     * Locked **Web3 Keystores, MetaMask Vaults & Exodus `seed.seco` Containers** (`Module 4.1 & 4.4C`)
     * Unmatched **`SQLCipher v3/v4` or `WCDB` Databases** (`SimpleX Chat`, `Briar`, `Threema`, or custom `UNK` SQLCipher DBs from `Module 8.2B`)
     * Password-protected **`.zip`, `.rar`, `.7z` Archives** and `.crypt14`/`.crypt15` WhatsApp backups (`Module 5.1A`).
2. **Center Panel (`Auto-Harvested Device Candidate Password & Key Dictionary`):**
   * Displays ranked candidate passphrases, PINs, and keys harvested automatically from the device across Phases 1–7:
     * **Source 1:** Plaintext passwords from Chrome/Safari `Login Data`, iOS `keychain-2.db`, and Android Autofill (`Module 2.2` & `Module 2.4`).
     * **Source 2:** Password/PIN strings found in WhatsApp/Telegram `"Saved Messages"`, Apple Notes (`NoteStore.sqlite`), Google Keep (`keep.db`), and clipboard caches (`"pass"`, `"pin"`, `"code"`, `"key"` context hits).
     * **Source 3:** OCR-extracted strings from handwritten note photos and screenshots (`Module 7.4`).
     * **Source 4:** Deterministic **Indian Bank PDF Password Permutations** (`First4Name + DDMM`, `PAN`, `CustomerID`, `AccountTail`, `DOB` from `Module 3.3 Section 7`).
3. **Right Panel (`Custom Examiner Passphrase / Hex Key Entry & Parameter Tuner`):**
   * Allows the examiner to type a newly discovered suspect passphrase (or raw 64-hex key) and select cipher parameters (`SQLCipher v4 [PBKDF2-SHA512, 256,000 iter, 4096 page]` vs. `SQLCipher v3 [PBKDF2-SHA1, 64,000 iter]` vs. `Web3 scrypt/AES-128-CTR`).

### 4.2 The Targeted Incremental DAG Hot-Patching Pipeline (`< 3 Seconds` Live Re-Ingestion)

When a candidate password or key successfully unlocks a blocked container $F_{\text{locked}}$, Sub-Engine 9.5B **never** restarts the whole case pipeline. Instead, it executes a **5-Step Incremental DAG Hot-Patch**:

1. **Step 1 (`Derivative Materialization & Tier-2B Hashing`):**
   * Writes the decrypted plaintext file (`Product B2`) into `derivative_staging_ledger`, computes its `SHA-256` and `MD5` hashes, and links it to its encrypted parent (`Tier 2A`) in `evidentiary_hash_manifest_ledger` (`Module 8.3A`).
2. **Step 2 (`Targeted Single-File Domain Parsing`):**
   * Dispatches `Product B2` exclusively to its owning domain parser (`Module 3.3` for PDFs; `Module 4.4B/C` for Web3 vaults; `Module 5.3` for `SimpleX`/`Briar`; `Module 2.1` + `Module 8.2C` for SQLCipher DBs).
3. **Step 3 (`Incremental Disjoint-Set Entity Graph Union`):**
   * Loads the current in-memory Disjoint-Set Union (`DSU`) state from **Module 8.1A** and executes `Union(O_new)` only for the newly extracted observations—updating `entity_master_profiles` and `entity_graph_edges_ledger` in $< 200\text{ ms}$!
4. **Step 4 (`Incremental Super-Timeline, FTS5 & Roaring Bitmap Append`):**
   * Inserts the new timestamped events into `unified_super_timeline`, appends the new documents to `global_fts5_lexical_index` and `global_fts5_trigram_index`, and sets the new `doc_uid` bits in `roaring_bitmap_facet_index_store`!
5. **Step 5 (`Merkle Audit Log & UI Toast Broadcast`):**
   * Appends a `CONTAINER_UNWRAPPED_AND_HOT_PATCHED` entry to `chain_of_custody_merkle_ledger` (`Module 8.3C`) and broadcasts a WebSocket event to the React UI so all open tabs update their badge counts immediately!

---

## 5. Step 3 — Sub-Engine 9.5C: The Golden-Hour Nodal Freeze De-Confliction Table (`1930 NCRP` & `FIU-IND`) & Victim Safeguard Lock

Before exporting the **I4C `1930` NCRP (`CFCFRMS`) Bank Lien Sheet** or the **`FIU-IND` / `Binance LERP` Crypto Freeze Packet** (`Module 8.4B`), Sub-Engine 9.5C presents an interactive **De-Confliction & Role Verification Grid**:

```
+----------------------------------------------------------------------------------------------------------+
| GOLDEN-HOUR NODAL FREEZE & SECTION 94 BNSS DE-CONFLICTION CENTER                                         |
| [Safeguard Status: 🛡️ 1 Complainant Victim Account & 2 Utility Billers Automatically Locked From Freeze!]|
+--------+--------------------------+-----------------------+--------------+---------------+---------------+
| Freeze | Account / VPA / Wallet   | Bank / CEX / Chain    | Role Badge   | Volume        | Linked UTRs / |
| [x]    | Identifier               | & IFSC / Branch       | (Click Edit) | (INR / USDT)  | TxIDs Count   |
+--------+--------------------------+-----------------------+--------------+---------------+---------------+
| [🔒NO] | A/c: 50100111222333      | HDFC Bank (HDFC00001) | [🛡️ VICTIM / | ₹1,80,000.00  | 2 Outflows    |
|        | Name: SURESH PATEL       | Mumbai Nariman Point  |  COMPLAINANT]| (Source Funds)| (LOCKED SAFE) |
+--------+--------------------------+-----------------------+--------------+---------------+---------------+
| [✅YES]| A/c: 30984718291         | State Bank of India   | [🚨 LAYER-1  | ₹1,80,000.00  | 4 UTRs +      |
|        | VPA: vikram99@okaxis     | SBIN0004821 (Varanasi)|  MULE TARGET]| Pass-Through  | Cheque OCR    |
+--------+--------------------------+-----------------------+--------------+---------------+---------------+
| [✅YES]| Binance UID: 482910482   | Binance P2P (FIU-IND) | [🚨 CEX P2P  | 2,000.00 USDT | Order #2059...|
|        | PAN: ABCPS1234K          | VPA: seller99@ybl     |  ESCROW MULE]| (₹1,80,000)   | + 6 Chat Msgs |
+--------+--------------------------+-----------------------+--------------+---------------+---------------+
| [✅YES]| TRON: TXYZopYRdj2D9XR... | TRON Mainnet (TRC-20) | [🚨 UNHOSTED | 14,500.00 USDT| 8 TRC-20 TxIDs|
|        | (BIP-39 Seed Recovered!) | Tether USDT Contract  |  SEED WALLET]| Balance       | + FixedFloat  |
+--------+--------------------------+-----------------------+--------------+---------------+---------------+
| [Export 1930 NCRP Bank Lien CSV (14-Col)] [Export FIU-IND & Binance LERP Packet] [Generate Sec 94 Notices]|
+----------------------------------------------------------------------------------------------------------+
```

### 5.1 The 3-Tier Freeze De-Confliction Safeguard Rules

1. **Rule 1 (`COMPLAINANT_OR_VICTIM_SOURCE_LOCK`):**
   * Any bank account, VPA, or phone number designated in the Case Intake metadata as belonging to the **Complainant / Victim** is locked with a green shield **`[🛡️ VICTIM / COMPLAINANT — DO NOT FREEZE]`** (`freeze_checkbox_disabled = true`) so it can only appear in the `Payer / Victim Source Account` column of the NCRP sheet, **never** in the `Beneficiary Account to Freeze` column!
2. **Rule 2 (`KNOWN_PUBLIC_UTILITY_AND_GOVT_BILLER_ALLOWLIST`):**
   * Automatically cross-checks candidate VPAs and accounts against a built-in allowlist of official Indian government/utility billers (`irctc@*`, `bescom@*`, `uppcl@*`, `bharatpe.merchant` verified utility MCCs `4900`/`4112`/`9399`) and marks them **`[⚠️ UTILITY / GOVT BILLER — EXCLUDED BY DEFAULT]`** unless manually overridden by the IO.
3. **Rule 3 (`1-Click Section 94 BNSS Requisition Preview & Batch Export`):**
   * Clicking **`[Generate Sec 94 BNSS Notices]`** previews the grouped statutory notices (`To: Nodal Officer, State Bank of India`, `To: Nodal Officer, Reliance Jio`, `To: Binance Compliance`) and exports them as signed-ready PDF and editable DOCX files!

---

## 6. Step 4 — Sub-Engine 9.5D: The 4-Step WYSIWYG Section 63(4)(c) BSA 2023 Certificate & Section 230 BNSS Dual-Preview Studio

### 6.1 The 4-Step Guided Courtroom Dossier & Statutory Certification Wizard

```
+----------------------------------------------------------------------------------------------------------+
| SECTION 63(4)(c) BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023 & COURTROOM DOSSIER STUDIO                      |
| [Step 1: Dossier Profile] -> [Step 2: Part A & B BSA Form] -> [Step 3: Pre-Flight Audit] -> [4: Dual PDF]|
+---------------------------------------------------+------------------------------------------------------+
| LEFT PANE: MASTER COURT & IO COPY (UNREDACTED)    | RIGHT PANE: SECTION 230 BNSS ACCUSED / DEFENSE COPY  |
|---------------------------------------------------|------------------------------------------------------|
| EXHIBIT 14: RECOVERED EXTORTION MEDIA & AADHAAR   | EXHIBIT 14: RECOVERED EXTORTION MEDIA & AADHAAR      |
| • File: /DCIM/100APPLE/IMG_4899.HEIC              | • File: /DCIM/100APPLE/IMG_4899.HEIC                 |
| • SHA-256: 9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c...    | • SHA-256: 9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c...       |
| • MD5:     1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d       | • MD5:     1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d          |
| +-----------------------------------------------+ | +--------------------------------------------------+ |
| | [UNREDACTED VISUAL EXHIBIT RENDERED FOR       | | | 🔒 STATUTORY JUDICIAL-INSPECTION PLACEHOLDER     | |
| |  SEALED COURT & FSL MASTER RECORD]            | | | Visual media withheld from physical duplication  | |
| |  • Victim Name: [Unmasked in Master Copy]     | | | pursuant to POCSO Act & Hon'ble Supreme Court in | |
| |                                               | | | P. Gopalkrishnan v. State of Kerala (2019).      | |
| |                                               | | | Victim ID: [VICTIM_PROTECTED_SEC72_BNS_01]       | |
| +-----------------------------------------------+ | +--------------------------------------------------+ |
+---------------------------------------------------+------------------------------------------------------+
| [Pre-Flight Gate: ✅ Part A Complete | ✅ Part B Complete | ✅ Merkle Chain Intact | ✅ Dual Hashes Locked] |
+----------------------------------------------------------------------------------------------------------+
```

1. **Step 1 (`Select Crime-Typology Dossier Profile & Relied-Upon Exhibits`):**
   * The examiner selects one of the **4 Crime-Typology Dossier Profiles** (`Module 8.4A`: *Cyber Fraud/USDT*, *Organized Crime/NDPS/Hawala*, *Honeytrap/Sextortion/POCSO*, or *Malware APK/AnyDesk/Tampering*) and reviews the drag-and-drop outline of included Bookmarks, Action-Burst Storyboards, Sankey/Graph figures, and Chat Transcripts.
2. **Step 2 (`Interactive Part A & Part B Section 63(4)(c) BSA 2023 Schedule Editor`):**
   * Displays the side-by-side statutory form for **Part A (Party / Investigating Officer)** and **Part B (Forensic Expert)** (`Module 8.3B`), with all device hardware identifiers (`Make`, `Model`, `IMEI 1/2`, `Serial`, `OS Build`, `SIM ICCIDs`), workstation specifications, **Tier 1 / Tier 2 / Tier 3 `SHA-256` & `MD5` Hashes**, `case_merkle_root_sha256`, and the **Section 63(2)(c) Technical Operating State / Isolated-Anomaly Compensation Clause** pre-populated and editable.
   * Includes a 1-click toggle to add the **Dual Statutory Caption (`Section 63(4)(c) BSA, 2023 / Erstwhile Section 65B(4) IEA, 1872`)** for legacy FIRs registered prior to July 1, 2024.
3. **Step 3 (`Mandatory 6-Point Pre-Flight Statutory & Cryptographic Gate`):**
   * Before the `[Compile & Sign Final Courtroom Packages]` button activates, the studio runs an automated 6-point verification check:
     * **Check 1:** Are all mandatory deponent fields in `Part A` and expert qualification fields in `Part B` non-empty?
     * **Check 2:** Does $\text{SHA256}_{\text{pre\_ingest}}(\text{Master}) == \text{SHA256}_{\text{post\_ingest}}(\text{Master})$ (`IMMUTABILITY_VERIFIED_IDENTICAL`)?
     * **Check 3:** Does every exhibit cited in the dossier have both its `SHA-256` and `MD5` recorded in `evidentiary_hash_manifest_ledger`?
     * **Check 4:** Does the full recomputation of $H_1 \dots H_{\text{last}}$ in `chain_of_custody_merkle_ledger` (`Module 8.3C`) pass with $0$ broken links?
     * **Check 5:** Have all `POCSO / CSAM / Intimate Media` items been locked behind Safeguard 2 for the Section 230 BNSS copy?
     * **Check 6:** Are all Indic script fonts (`Noto Sans Devanagari / Tamil / Bengali / ...`) embedded for `PDF/A-3b` compliance?
4. **Step 4 (`Synchronized Dual-Preview & Final Cryptographic Package Generation`):**
   * Renders the **Unredacted IO/Court Master PDF** on the left and the **Section 230 BNSS Accused/Defense Disclosure Copy** on the right in synchronized scroll mode so the IO can visually verify every redaction and hash schedule before exporting the final `PDF/A-3b` Dossier, the bound **Section 63(4)(c) BSA Certificate**, and the **Air-Gapped HTML5 Optical/Pen-Drive Disclosure Bundle**!

---

## 7. Local UI State Schema & FastAPI IPC Contract for Module 9.5

### Table 1: `unk_promoted_custom_schemas_ledger` (User-Mapped `STATE_4_UNK` Tables Promoted via Zero-Code Mapper)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `mapping_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique mapping ID. |
| `vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to the `STATE_4_UNK` file in `vfs_index`. |
| `source_table_or_key_path` | `TEXT` | `NOT NULL` | E.g., `"hisab_ledger"` in `/com.hisab.app/databases/data.db`. |
| `column_role_mappings_json` | `TEXT` | `NOT NULL` | JSON dictionary mapping raw column names to semantic roles (`{"jama_ts":"TIMESTAMP_UNIX_MS", "party_no":"ACTOR_SOURCE_PHONE"}`). |
| `promoted_rows_count` | `INTEGER` | `NOT NULL` | Count of active + `-wal` + freelist rows promoted into `unified_super_timeline` & `entity_master_profiles`. |
| `promoted_by_examiner` | `TEXT` | `NOT NULL` | Examiner name (logged in `chain_of_custody_merkle_ledger`). |
| `promoted_at_ist_iso` | `TEXT` | `NOT NULL` | `"YYYY-MM-DD HH:MM:SS IST (+05:30)"`. |

### Table 2: FastAPI $\leftrightarrow$ Electron Renderer IPC Endpoints for Module 9.5

| Endpoint Method & Path | Request Parameters / Payload | Response Format & Latency Target |
|---|---|---|
| **`GET /api/v1/unk/entropy-profile`** | `vfs_file_id` | Array of 4 KB block entropy scores $H(b_k)$, 4-class byte composition percentages, and 256-bin $\chi^2$ histogram. Target: `< 15 ms`. |
| **`POST /api/v1/unk/promote-table`** | `vfs_file_id`, `table_name`, `column_role_mappings_json` | Executes zero-code promotion into `unified_super_timeline`, `entity_master_profiles`, and `FTS5`. Target: `< 500 ms`. |
| **`POST /api/v1/keybroker/test-unlock`** | `vfs_file_id`, `candidate_secret`, `cipher_mode` | Tests decryption; if valid, triggers 5-step Incremental DAG Hot-Patcher and returns newly unlocked record counts. Target: `< 2.5 s`. |
| **`POST /api/v1/studio/compile-dossier`** | `dossier_config_json`, `part_a_json`, `part_b_json` | Runs 6-point pre-flight gate, compiles `PDF/A-3b` Master + `Sec 230 BNSS` Defense bundles, and locks Tier-3 hashes. |

---

## 8. Developer Acceptance Test Checklist for Module 9.5

1. **The 4 KB Sliding-Window Block Entropy Skyline ($H(b_k)$) & Zero-Code `UNK` Table Promotion Test:**
   * Open a hybrid `STATE_4_UNK` file containing a 4 KB plaintext header ($H \approx 4.5$) followed by 60 KB of AES ciphertext ($H \approx 7.99$) and verify that the Block Entropy Skyline chart visually separates Block 0 from Blocks $1\dots 15$.
   * Next, open an unrecognized SQLite database (`hisab_ledger`), map its columns in the Zero-Code Schema Mapper, click `[⚡ Promote Table]`, and verify that all 60 rows immediately appear in the **Unified Super-Timeline** and **Global `FTS5` Omnibar**!
2. **The Key-Broker Incremental DAG Hot-Patch Test (`< 3 Seconds` Without Full Re-Ingest):**
   * Supply the password `"Vikram@786"` to a locked bank statement PDF or `SQLCipher` database in the Key-Broker Console.
   * Verify that Sub-Engine 9.5B unwraps the file into `derivative_staging_ledger`, parses only that file, merges its newly discovered transactions/entities into Module 8.1's graph and timeline, updates the Merkle Chain-of-Custody ledger, and refreshes the UI in $< 3\text{ seconds}$!
3. **The `1930 NCRP` Complainant Victim-Account Safeguard Lock & Section 63(4)(c) BSA Pre-Flight Gate Test:**
   * Verify that the Complainant's bank account (`50100111222333`) is locked with `[🛡️ VICTIM / COMPLAINANT — DO NOT FREEZE]` in the Freeze De-Confliction Center, and verify that the Section 63(4)(c) BSA Studio blocks final export if any mandatory `Part A`/`Part B` field is blank or if the Merkle audit chain is tampered with!