# Engineering Specification: Phase 8, Module 8.2 — The Zero-Omission (`UNK`) Unparsed File Audit, Binary Entropy Triage, Generic Introspector & Dual `SQLite FTS5` Search Engine

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 8.2** of the Forensic Data Parser (corresponding to **Groups 8, 12, 15, 16, and 17** of the Unified Master Register). It contains **zero programming code** and explains how to enforce a mathematically provable **100% Zero-Omission File Accounting Guarantee** across the entire Virtual Filesystem (`VFS`), how to detect disguised/renamed files and uncataloged encrypted containers using Magic-Byte Discrepancy Analysis, Shannon Entropy ($H(X)$), and Chi-Square ($\chi^2$) Uniformity Testing, how to automatically introspect unrecognized (`UNK`) third-party applications so bespoke or newly released apps never hide evidence, and how to build a sub-50ms **Dual `SQLite FTS5` (`unicode61` + `trigram` + Indic `NFC`) & Roaring Bitmap Facet Search Engine** over 50+ million forensic records from first principles.

---

## 1. Purpose & Mental Model (Why "Zero-Omission" Accounting & Sub-50ms Search Are Mandatory)

Even after implementing specialized parsers for 150+ mainstream, financial, crypto, regional, and high-opsec applications across **Phases 1 through 7**, two operational realities confront every real-world digital forensic investigation:

1. **The "Bespoke / Uncataloged App & Hidden Container" Problem (Why Zero-Omission `UNK` Auditing Is Essential):**
   * Cybercrime syndicates, hawala operators, and espionage actors constantly deploy custom-compiled APK tools, newly launched regional chat apps, obscure vault apps, or manually renamed SQLite/archive files (e.g., renaming an encrypted `SQLCipher` database or `.zip` archive to `/sdcard/Android/data/com.google.update/cache/font_cache.ttf`).
   * Traditional commercial forensic tools operate on a **"Whitelist-Only" paradigm**: if a file path does not match a hardcoded plugin script, the tool **silently ignores the file**. In court, defense counsel can challenge the completeness of the examination, or worse, the investigator completely misses the suspect's custom ledger app!
   * **Sub-Engines 8.2A, 8.2B, and 8.2C** eliminate silent omissions by enforcing a strict mathematical conservation law over `vfs_index`: **every single file in the extraction must be accounted for**, every disguised file extension is unmasked by its binary header, every high-entropy encrypted blob is isolated by $\left(H(X), \chi^2\right)$ mathematics, and every unrecognized user-space database/file is automatically dissected by the **Universal Fallback Introspector**.
2. **The "Needle in a 50-Million-Row Haystack" Problem (Why Dual `FTS5` & Roaring Bitmaps Are Essential):**
   * A full extraction of a 512 GB smartphone produces $10,000,000\text{ to }50,000,000$ individual text records across chat messages, URLs, Unified Logs, `MMKV`/`LevelDB` keys, OCR text, and `unified_super_timeline` events.
   * If an investigator types a partial 6-digit tail of a bank account (`"482910"`), a UPI handle (`"@okaxis"`), a Hindi/Devanagari word (`"हवाला"`), or a partial TRON wallet string into the search bar, running a standard SQL `LIKE '%482910%'` query across 50 million rows requires a full-disk table scan that freezes the workstation for several minutes.
   * **Sub-Engine 8.2D** builds a dual-index search architecture combining a **Custom-Tokenized Lexical `FTS5` Index**, a **3-Character `Trigram` Substring `FTS5` Index**, and **In-Memory 32-Bit Roaring Bitmap Facets**—returning exact word, prefix, substring, regex, and multi-facet filtered results across 50 million rows in $< 50\text{ milliseconds}$.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in File Auditing, Entropy Analysis & Forensic Search

Before implementing Module 8.2, the developer must understand six critical traps that break standard forensic tools:

### Mistake 1: The "Silent Drop" Fallacy (Failing to Reconcile Parser Consumption Against `vfs_index`)
* **The Trap:** Running Phases 1 through 7 and presenting the extracted tables to the user without tracking which files in `vfs_index` were never opened by any parser.
* **Why It Fails:** If a popular app (like `Telegram`, `PhonePe`, or `WhatsApp`) releases an update next month that renames its internal database from `cache4.db` to `cache5.db`, a traditional parser silently extracts $0$ messages and reports `"0 Telegram Messages"`—leaving the investigator falsely believing the suspect never used Telegram!
* **The Rule:** Sub-Engine 8.2A tracks `consumed_by_phase_module` on every row in `vfs_index`. If an installed application sandbox in `/data/user/<id>/<pkg>/` contains non-empty files in `/databases/` or `/files/` that were **not** claimed by any Phase 1–7 module, Sub-Engine 8.2A immediately flags an **`UNCLAIMED_APP_SANDBOX_DATA_STORE`** alert and routes those files into Sub-Engine 8.2C's Universal Fallback Introspector!

### Mistake 2: Using Shannon Entropy ($H(X)$) Alone to Detect Encryption (Confusing Compressed Media With Encrypted Containers)
* **The Trap:** Flagging every file whose Shannon Entropy $H(X) > 7.90\text{ bits/byte}$ as an `"Encrypted File"`.
* **Why It Fails:** Modern compressed data streams—such as `.jpg` images, `.mp4`/`.heic` videos, `.zip`/`.apk` archives, `.gz` logs, and Brotli/Zstandard WebView cache files—**also** have high Shannon Entropy ($H(X) \in [7.50, \ 7.99]\text{ bits/byte}$) because good compression removes byte redundancy! If you rely on $H(X) > 7.90$ alone, your tool will falsely flag $50,000$ normal `.jpg`, `.mp4`, and `.apk` files as "Encrypted Suspect Containers"!
* **The Rule:** True cryptographic ciphertext (`AES-XTS`, `AES-GCM`, `ChaCha20`, `SQLCipher` raw pages) differs from compressed files in **two mathematical ways**:
  1. **Zero Known Magic Headers/Footers:** Compressed files (`ZIP`, `GZIP`, `ZSTD`, `PNG`, `JPEG`, `MP4`) have deterministic magic bytes at Byte Offset $0$ (and deterministic structural markers/trailers), whereas raw encrypted containers (`SQLCipher`, `VeraCrypt`, raw AES) have pseudo-random bytes starting at Byte Offset $0$!
  2. **The Chi-Square ($\chi^2$) Uniformity Distribution Test:** While a compressed `.jpg` or `.zip` file has $H(X) \approx 7.95$, its 256-bin byte frequency histogram deviates heavily from a true uniform random distribution (yielding a massive $\chi^2$ score $> 500\text{ to }50,000$). True AES/ChaCha20 ciphertext produces a statistically uniform byte distribution across all 256 byte values, yielding a tight Chi-Square value $\chi^2 \in [180.0, \ 340.0]$ (for degrees of freedom $df = 255$) and a Monte Carlo $\pi$ approximation error $< 0.05\%$!
* **The Rule:** Combine **Magic-Header Exclusion + Shannon Entropy ($H(X) \ge 7.98$) + Chi-Square Uniformity ($\chi^2 \in [180, \ 340]$)** in Section 4.2.

### Mistake 3: Trusting File Extensions Instead of Binary Magic Signatures
* **The Trap:** Skipping a file named `lib_update.so` or `avatar_thumb.png` during database discovery because its filename extension is `.so` or `.png`.
* **Why It Fails:** Both malware authors and privacy/vault apps routinely disguise SQLite databases (`53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00`), ZIP/APK archives (`50 4B 03 04`), or Dalvik bytecode (`64 65 78 0A`) by giving them benign extensions like `.png`, `.mp3`, `.ttf`, `.so`, or `.dat`.
* **The Rule:** Sub-Engine 8.2B inspects the first $64\text{ bytes}$ and final $16\text{ bytes}$ of every file in `vfs_index` against the **Master 24-Signature Magic Byte Table** (Section 4.1) and flags every **Signature-vs-Extension Mismatch**!

### Mistake 4: Using Default `SQLite FTS5` `unicode61` Tokenization (Which Destroys Emails, VPAs, URLs & Crypto Paths!)
* **The Trap:** Creating an `FTS5` table with the default `tokenize='unicode61'` configuration.
* **Why It Fails:** By default, `unicode61` treats `@`, `.`, `_`, `-`, `:`, and `/` as **whitespace punctuation separators**!
  * If a user searches for the UPI VPA `"vikram.99@okaxis"`, default `unicode61` splits it into three separate common tokens `"vikram"`, `"99"`, and `"okaxis"`, causing massive false matches and breaking exact handle lookups!
  * Furthermore, `unicode61` can only match **prefixes** (`token*`); it **cannot** match a mid-string substring like searching for the middle 6 digits `"148291"` inside a 12-digit UTR `"630914829104"` or a partial Base58 string inside a TRON address!
* **The Rule:** Deploy **Dual `FTS5` Virtual Tables** (Section 6.1):
  1. **Lexical Index (`tokenize="unicode61 remove_diacritics 2 tokenchars '@._:-+/'"`):** Preserves intact UPI VPAs, emails, package names (`com.phonepe.app`), file paths, and URLs as single searchable tokens!
  2. **Trigram Substring Index (`tokenize="trigram"`):** Indexes every contiguous 3-character sliding window so `LIKE '%148291%'` and `GLOB` queries execute in $< 20\text{ milliseconds}$!

### Mistake 5: Failing to Normalize Indic Scripts (`NFC`) Before `FTS5` Indexing
* **The Trap:** Indexing raw Hindi (`Devanagari`), Bengali, Tamil, Telugu, Marathi, Gujarati, or Kannada strings from WhatsApp, ShareChat, Truecaller, or OCR without Unicode `NFC` (`Canonical Decomposition, followed by Canonical Composition`) normalization.
* **Why It Fails:** In Indic scripts, a single visual character (Akshara) consists of a base consonant plus dependent vowel signs (`Matras`), nasalization marks (`Bindu`/`Chandrabindu`), or `Nukta` dots (e.g., `ड़` can be encoded either as the precomposed code point `U+095C` OR as decomposed `U+0921` `ड` + `U+093C` `़`!). If the database text is decomposed (`NFD`) while the investigator's keyboard types precomposed (`NFC`), a search for `"नोएडा"` or `"लड़की"` returns **zero hits**!
* **The Rule:** Pass every UTF-8 string through **Unicode `NFC` Normalization** (and strip zero-width joiners/non-joiners `U+200B`, `U+200C`, `U+200D`, `U+FEFF` for search indexing while preserving the raw string for display) before inserting into `FTS5`!

### Mistake 6: Running `GROUP BY` Count Queries on Disk Instead of Using Roaring Bitmaps for Facet Filtering
* **The Trap:** Executing `SELECT artifact_domain, COUNT(*) FROM unified_super_timeline WHERE ... GROUP BY artifact_domain;` every time the investigator toggles a filter checkbox in the UI.
* **Why It Fails:** Scanning 20 million rows on disk to recompute sidebar badge counts takes $4\text{ to }12\text{ seconds}$ per click.
* **The Rule:** Pre-compute **32-Bit Roaring Bitmaps** (Section 6.3) for every categorical facet value so intersecting 5 filters and computing exact badge counts across 20 million events takes $< 1\text{ millisecond}$ in RAM via bitwise `AND`/`OR` CPU instructions (`AVX2` / `NEON` `POPCNT`)!

---

## 3. Step 1 — Sub-Engine 8.2A: Exhaustive VFS File Accounting & The 4-State Zero-Omission Ledger

At the conclusion of Phases 1 through 7, Sub-Engine 8.2A audits every row in Phase 1's `vfs_index` (`file_id = 1 ... N_total`) and assigns each file to one of **four mutually exclusive accounting states**:

### 3.1 The 4 Mandatory VFS Accounting States

1. **`STATE_1_PARSED_AND_VERIFIED`:**
   * The file was explicitly claimed, opened, and decoded by one or more specialized parsers in Phases 1 through 7 (e.g., `msgstore.db` claimed by Module 5.1; `cache4.db` claimed by Module 5.2; `IMG_4821.HEIC` claimed by Modules 7.1, 7.3, and 7.4).
   * Record the array of consuming modules (`consumed_by_modules_json`) and the count of extracted records (`extracted_records_count`).
2. **`STATE_2_RECOGNIZED_DECRYPTION_OR_CORRUPTION_BLOCKED`:**
   * The file was recognized by a Phase 1–7 module (or Phase 2, Module 2.2's Cryptographic Key Broker), **but** could not be decoded because:
     * `DIMENSION_B == ENCRYPTED_GATED_MISSING_KEY` (e.g., a password-locked `SimpleX` or `Briar` database or 7-Zip archive whose passphrase was not found on the device), OR
     * `DIMENSION_C == CORRUPTED_TRUNCATED_STREAM` (e.g., an overwritten unallocated file fragment whose header/btree is damaged beyond structural carver repair).
   * These files are automatically surfaced in the **"Blocked / Pending Password & Corruption Audit"** tab so the examiner knows their exact paths, sizes, and encryption algorithms!
3. **`STATE_3_KNOWN_SYSTEM_OR_STATIC_ASSET_IMMUTABLE`:**
   * The file is a static OS system binary, shared library (`.so` / `dyld`), system font (`.ttf` / `.otf`), translation resource (`.arsc` / `.lproj` / `.pak`), or stock UI icon verified either by residing on a read-only system partition (`/system`, `/vendor`, `/product`, `/apex`) or by matching known static asset signatures with zero user-modifiable state.
4. **`STATE_4_UNK_UNPARSED_USER_ARTIFACT` (The Zero-Omission Target Queue!):**
   * **Every remaining file** residing inside user-data partitions (`/data/data/`, `/data/user/<id>/`, `/data/user_de/<id>/`, `/data/system/`, `/data/system_ce/`, `/data/misc/`, `/data/media/<id>/` \[`/sdcard/`\], or iOS `/private/var/mobile/`, `/private/var/containers/Data/`, `/private/var/wireless/`, `/private/var/db/`) that is **not** in States 1, 2, or 3!

### 3.2 The Zero-Omission Conservation Invariant

Before Phase 8.2 can mark case processing as complete, it must verify the strict mathematical conservation invariant across all non-directory file nodes in `vfs_index`:

$$N_{\text{total\_files}} == N_{\text{State 1}} + N_{\text{State 2}} + N_{\text{State 3}} + N_{\text{State 4}}$$

Every single file in **`STATE_4_UNK_UNPARSED_USER_ARTIFACT`** is automatically routed through **Sub-Engine 8.2B (Magic & Entropy Triage)** and **Sub-Engine 8.2C (Universal Fallback Introspector)**!

---

## 4. Step 2 — Sub-Engine 8.2B: Magic-Byte vs. Extension Spoofing Hunter & Shannon Entropy ($H(X)$) + Chi-Square ($\chi^2$) Classifier

### 4.1 The Master 20-Signature Magic Byte Discrepancy Detector

For every file in `vfs_index` (prioritizing `STATE_4_UNK` and `STATE_3` files in user-writable partitions), read the first $64\text{ bytes}$ (`head_64`) and final $16\text{ bytes}$ (`tail_16`) and compare the detected binary format against the filename extension:

| Detected Binary Format | Offset & Exact Hexadecimal Magic Signature | Expected Extension(s) | Action If Extension Contradicts Signature (e.g., `.png`, `.tmp`, `.ttf`, `.so`, `.bin`, `.log`) |
|---|---|---|---|
| **1. `SQLITE_3_DATABASE`** | Offset $0$: `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` (`"SQLite format 3\0"`) | `.db`, `.sqlite`, `.sqlite3`, `.sqlitedb`, `RKStorage`, `.storedata` | **Flag `DISGUISED_SQLITE_DB`**, route to **Module 2.1 (Active + `-wal` + Freelist)** and **Sub-Engine 8.2C**! |
| **2. `SQLITE_WAL_JOURNAL`** | Offset $0$: `37 7F 06 82` or `37 7F 06 83` | `-wal` | **Flag `DISGUISED_WAL_FILE`** and parse frames via Module 2.1! |
| **3. `APPLE_BINARY_PLIST`** | Offset $0$: `62 70 6C 69 73 74 30 30` (`"bplist00"`) or `"bplist15"` / `"bplist16"` | `.plist`, `.icloud`, `.flashed` | **Flag `DISGUISED_BPLIST`** and deserialize object tree! |
| **4. `ANDROID_BINARY_XML_ABX`** | Offset $0$: `41 42 58 00` (`"ABX\0"`) | `.xml` | Deserialize via **Module 6.2B's `ABX\x00` Reader** and scan for indicators! |
| **5. `APPLE_BIOME_SEGB`** | Offset $0$: `53 45 47 42` (`"SEGB"`) or Footer `53 45 47 42` | Biome stream files | Route to **Module 2.3C (`SEGB v1/v2` Decoder)**! |
| **6. `LEVELDB_SSTABLE_LDB`** | Offset $\text{EOF}-8$: `57 FB 80 8B 24 75 47 DB` (64-bit LevelDB Table Magic) | `.ldb`, `.sst` | Route to **Module 2.3B (`LevelDB` Decoder)**! |
| **7. `JAVA_DALVIK_DEX`** | Offset $0$: `64 65 78 0A 30 33` (`"dex\n035\0"` .. `"039\0"`) | `.dex` | **CRITICAL: `HIDDEN_DYNAMIC_DEX_PAYLOAD`!** Route to **Module 6.5E (Trojan C2 Unpacker)**! |
| **8. `ELF_EXECUTABLE_OR_SO`** | Offset $0$: `7F 45 4C 46` (`"\x7fELF"`) | `.so`, binary | If inside `/sdcard/` or `/files/` of a chat/user app, flag **`SUSPICIOUS_USER_SPACE_ELF_BINARY`**! |
| **9. `ZIP_APK_JAR_DOCX_XLSX`** | Offset $0$: `50 4B 03 04` (`"PK\x03\x04"`) | `.zip`, `.apk`, `.jar`, `.docx`, `.xlsx`, `.pptx` | If disguised as `.jpg`/`.dat`/`.tmp`, flag **`DISGUISED_ZIP_OR_APK_ARCHIVE`**, mount recursively in Phase 1 VFS, and scan contents! |
| **10. `RAR_OR_7ZIP_ARCHIVE`** | • RAR: `52 61 72 21 1A 07` (`"Rar!"`)<br>• 7-Zip: `37 7A BC AF 27 1C` (`"7z..."`) | `.rar`, `.7z` | Mount in VFS (or route to Key Broker if encrypted headers detected)! |
| **11. `GZIP_ZSTD_LZ4_BZIP2`** | • Gzip: `1F 8B 08`<br>• Zstandard: `28 B5 2F FD`<br>• LZ4: `04 22 4D 18` | `.gz`, `.zst`, `.lz4` | Decompress stream in memory and re-run Magic Byte inspection on the decompressed payload! |
| **12. `PDF_DOCUMENT`** | Offset $0\text{–}1024$: `25 50 44 46 2D` (`"%PDF-"`) | `.pdf` | Route to **Module 3.3 (PDF Unlocker)** and **Modules 7.3/7.4 (QR & OCR)**! |
| **13. `JPEG_PNG_WEBP_HEIC_GIF`** | • JPEG: `FF D8 FF`<br>• PNG: `89 50 4E 47`<br>• WebP: `52 49 46 46 ... 57 45 42 50`<br>• HEIC/MP4: Offset $4$: `66 74 79 70` (`"ftyp"`) | `.jpg`, `.png`, `.webp`, `.heic`, `.mp4`, `.mov` | If disguised inside a non-media folder or with `.bin`/`.dat`/`.nomedia` extension, flag **`HIDDEN_DISGUISED_MEDIA_FILE`** and route to **Phase 7**! |
| **14. `KTX_GPU_TEXTURE`** | Offset $0$: `AB 4B 54 58 20 31 31 BB` (`"«KTX 11»"`) or `62 76 78 32` (`"bvx2"`) | `.ktx` | Route to **Module 7.2A (`.ktx` Texture to PNG Converter)**! |
| **15. `WHATSAPP_CRYPT_BACKUP`** | Offset $0$: Protobuf header + `67` / `01` (`crypt12`/`14`/`15`) | `.crypt12`, `.crypt14`, `.crypt15` | Route to **Module 2.2 & Module 5.1A**! |
| **16. `LUKS_OR_VERACRYPT_HEADER`** | Offset $0$: `4C 55 4B 53 BA BE` (`"LUKS\xba\xbe"`) | `.luks`, `.img` | Flag **`CRITICAL: LUKS_ENCRYPTED_DISK_VOLUME`** and route to Key Broker! |
| **17. `OPENPGP_OR_AGE_ARMOR`** | `-----BEGIN PGP MESSAGE-----` or `age-encryption.org/v1` | `.asc`, `.gpg`, `.age` | Flag **`CRITICAL: PGP_OR_AGE_ENCRYPTED_PAYLOAD`**! |
| **18. `PKCS12_OR_PEM_PRIVATE_KEY`** | `-----BEGIN PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----` | `.pem`, `.key`, `.p12`, `.pfx` | Extract cryptographic certificate / SSH / VPN private key! |

### 4.2 Mathematical Formulation of the $\left(H(X), \ \chi^2, \ \pi_{\text{err}}\right)$ Encrypted Container Classifier

For any file in `STATE_4_UNK` of size $N \ge 512\text{ bytes}$ that does **not** match any known plaintext or compressed magic header in Table 4.1 (and fails Module 7.2C's Known-Plaintext Header XOR test), compute three statistical metrics over a sample of up to $N_{\text{sample}} = \min(N, \ 1,048,576)\text{ bytes}$ (skipping the first $16\text{ bytes}$ in case a 16-byte salt sits at Offset $0$):

1. **Metric 1 — Shannon Byte Entropy ($H(X) \in [0.0, \ 8.0]\text{ bits/byte}$):**
   Count the occurrence frequency $c_i$ of each byte value $i \in \{0, 1, \dots, 255\}$ across the $N_{\text{sample}}$ bytes, where $P(x_i) = \frac{c_i}{N_{\text{sample}}}$:
   $$H(X) = -\sum_{i=0, \ c_i > 0}^{255} P(x_i) \log_2 P(x_i)$$

2. **Metric 2 — Pearson's Chi-Square ($\chi^2$) Uniformity Statistic (Degrees of Freedom $df = 255$):**
   For a truly uniform pseudo-random ciphertext stream of length $N_{\text{sample}}$, the expected count in each of the 256 byte bins is $E = \frac{N_{\text{sample}}}{256.0}$:
   $$\chi^2 = \sum_{i=0}^{255} \frac{\left(c_i - E\right)^2}{E}$$

3. **Metric 3 — First-Page SQLCipher / Block-Cipher Structural Alignment Check:**
   * Check if total file size $N$ is an exact integer multiple of **$4,096\text{ bytes}$** ($N \bmod 4096 == 0$) or **$1,024\text{ bytes}$** ($N \bmod 1024 == 0$) — the exact page size of an encrypted **`SQLCipher`**, **`WCDB`**, or **`Realm`** database!
   * Check if $N \bmod 16 == 0$ (AES 128-bit block alignment).

4. **Deterministic Classification Rules:**
   * **Rule 1 (`UNCATALOGED_SQLCIPHER_OR_PAGE_ENCRYPTED_DB`):**
     $$\text{If } H(X) \ge 7.980 \quad \text{AND} \quad 180.0 \le \chi^2 \le 350.0 \quad \text{AND} \quad (N \bmod 4096 == 0 \text{ or } N \bmod 1024 == 0):$$
     Flag as **`CRITICAL: UNCATALOGED_SQLCIPHER_ENCRYPTED_DATABASE`** and automatically route the file + its owning app's `/shared_prefs/`, `MMKV`, and Keystore/Keychain keys into **Phase 2, Module 2.2's Universal SQLCipher Key Prober**!
   * **Rule 2 (`HIGH_ENTROPY_ENCRYPTED_BLOB_OR_CONTAINER`):**
     $$\text{If } H(X) \ge 7.980 \quad \text{AND} \quad 180.0 \le \chi^2 \le 380.0 \quad \text{AND} \quad (N \bmod 4096 \neq 0):$$
     Flag as **`HIGH_ENTROPY_ENCRYPTED_OR_KEY_STREAM_BLOB`** in the Zero-Omission Audit Ledger.
   * **Rule 3 (`COMPRESSED_OR_PROPRIETARY_BINARY_STREAM`):**
     $$\text{If } H(X) \ge 7.200 \quad \text{AND} \quad \chi^2 > 380.0:$$
     Classify as **`COMPRESSED_OR_ENCODED_DATA_STREAM`** and pass to Sub-Engine 8.2C for string/indicator carving.

---

## 5. Step 3 — Sub-Engine 8.2C: The Universal Fallback Introspector for Unrecognized (`UNK`) Apps & Databases

Whenever Sub-Engine 8.2A/B discovers an unrecognized SQLite database, JSON, XML, Protobuf, `MMKV`, `LevelDB`, or binary file inside a third-party app sandbox (`STATE_4_UNK`), Sub-Engine 8.2C executes an automated **3-Stage Universal Introspection Pipeline** so that **zero evidence is lost even from an app the parser has never seen before**:

### 5.1 Stage 1: Automated Schema & Column Heuristic Introspection on Unrecognized SQLite Databases

For every SQLite database in `STATE_4_UNK`:
1. Process the database through **Phase 2, Module 2.1 (Pipelines A, B, and C)** to extract all Active rows, `-wal` historical frames, and B-Tree `0x0D` Freelist/Freeblock deleted records!
2. Inspect `sqlite_master` (`SELECT name, sql FROM sqlite_master WHERE type='table';`) and classify every table and column using **Semantic Column-Role Heuristics**:
   * **Timestamp Columns:** Any integer/real column whose name matches `*time*`, `*date*`, `*_at`, `*ts*`, `created*`, `updated*`, `modified*`, `sent*`, `expires*` **AND** whose numeric value falls within valid 2015–2030 ranges for **10-digit Unix Seconds** ($[1.42 \times 10^9, \ 1.90 \times 10^9]$), **13-digit Unix Milliseconds** ($[1.42 \times 10^{12}, \ 1.90 \times 10^{12}]$), **16-digit Unix Microseconds** ($[1.42 \times 10^{15}, \ 1.90 \times 10^{15}]$), or **Apple Cocoa Seconds** ($[4.41 \times 10^8, \ 9.20 \times 10^8]$) is automatically converted to UTC + IST via **Module 1.2** and added to **`unified_super_timeline`**!
   * **Message / Note / Content Columns:** Any `TEXT` column matching `*msg*`, `*message*`, `*body*`, `*text*`, `*content*`, `*chat*`, `*note*`, `*comment*`, `*desc*`, `*title*`, `*caption*`.
   * **Identity / Peer Columns:** Any column matching `*user*`, `*sender*`, `*receiver*`, `*from*`, `*to*`, `*phone*`, `*mobile*`, `*email*`, `*name*`, `*nick*`, `*uid*`, `*jid*`, `*vpa*`, `*account*`.
   * **Geolocation Columns:** Any pair of floating-point or `E6`/`E7` integer columns matching `(*lat*, *lon* | *lng*)` whose values fall within valid WGS-84 coordinates ($[-90, 90]$ and $[-180, 180]$) is automatically exported to **Module 6.3 (`unified_geolocation_fixes_ledger`)**!
   * **Binary `BLOB` Columns:** Automatically tested against **Module 2.3D (Schema-Less Protobuf Decoder)**, `bplist00`, `Gzip`/`Zstd` decompression, and JSON!

### 5.2 Stage 2: The 10-Indicator Global Forensic Sweeper Across All `STATE_4_UNK` Files

Across every row extracted from unrecognized SQLite tables, `MMKV`/`LevelDB` stores, XML/JSON files, and UTF-8 / UTF-16LE strings ($\ge 6\text{ chars}$) carved from binary `STATE_4_UNK` files, Sub-Engine 8.2C runs our **10 Mathematical Indicator Validators**:

1. **12-Digit NPCI UPI `UTR` / `RRN` Validator** (Module 3.5A `YDDD` Julian Day check).
2. **UPI `VPA` Handle Validator** (`<user>@<known_psp_handle>` via Module 3.5B's 55+ NPCI PSP Handle Dictionary).
3. **11-Character `IFSC` & Bank Account Extractor** (Module 3.3 Section 8.2).
4. **7-Ecosystem Checksummed Cryptocurrency Address Validator** (Module 4.3A: `TRON Base58Check`, `BTC Bech32/Bech32m/Base58Check`, `EVM EIP-55`, `Monero Keccak-256`, `TON CRC16-CCITT`).
5. **`BIP-39` 12/24-Word & `Monero` 25-Word Seed Phrase Checksum Validator** (Module 4.4A).
6. **Indian `PAN` (`4th-Char Entity`), `12-Digit Aadhaar` (`Verhoeff`), & `15-Char GSTIN` (`Mod-36`) Validators** (Module 7.4B).
7. **Indian (`+91`) & International (`+971` UAE, `+855` Cambodia, `+1`, `+44`) Phone Number Extractor**.
8. **High-OpSec Covert Handle Detector** (`05[0-9a-fA-F]{64}` Session IDs, `simplex.chat/contact#`, `10-xxxx-xxxx` Zangi numbers, Telegram `bot<TOKEN>` C2 tokens).
9. **URL, `.onion` Tor Hidden Service, IPv4/IPv6 & `JWT` Bearer Token Extractor**.
10. **WGS-84 GPS Coordinate Pair Extractor**.

Every validated indicator found inside a `STATE_4_UNK` file is recorded in `unk_generic_introspection_findings` **and** automatically linked into **Module 8.1's `entity_master_profiles` and `unified_super_timeline`**!

---

## 6. Step 4 — Sub-Engine 8.2D: High-Performance Dual `SQLite FTS5` (`unicode61` + `trigram` + Indic `NFC`) & Roaring Bitmap Search Engine

To give the investigator sub-50ms search and filtering across 50+ million records in Phase 9's UI, Sub-Engine 8.2D builds three specialized index structures at the end of the pipeline:

### 6.1 Index 1: The Custom-Tokenized Lexical `FTS5` Index (`global_fts5_lexical_index`)

1. **Mandatory Pre-Indexing Unicode `NFC` & Grapheme Normalization:**
   * Before inserting any text string into `FTS5`, apply **Unicode `NFC` Normalization** so Indic scripts (`Devanagari` Hindi/Marathi, `Bengali`, `Tamil`, `Telugu`, `Gujarati`, `Kannada`, `Malayalam`, `Gurmukhi`, `Odia`) keep their base consonants and dependent vowel signs (`Matras`) canonically composed.
   * Strip invisible formatting characters (`U+200B` Zero-Width Space, `U+200C` ZWNJ, `U+200D` ZWJ, `U+200E`/`U+200F` LTR/RTL marks, `U+FEFF` BOM) from the indexed copy so hidden zero-width anti-search obfuscation inside Telegram/WhatsApp scam messages is defeated!
2. **Exact `FTS5` DDL Configuration:**
   * Configure the virtual table with:
     $$\texttt{tokenize = "unicode61 remove\_diacritics 2 tokenchars '@.\_:-+/\$#'"}$$
   * **Why `tokenchars '@._:-+/$#'` Is Critical:**
     * Searching for `"vikram.singh@okaxis"` matches the exact single token `vikram.singh@okaxis` in $O(1)$ B-tree lookup time!
     * Searching for `"com.phonepe.app"` or `"/data/adb/magisk.db"` or `"+919876543210"` or `"$USDT"` or `"#hawala"` matches the intact string without splitting on punctuation!
   * Supports full boolean operators (`AND`, `OR`, `NOT`), phrase quotes (`"delete after transfer"`), `NEAR(term1 term2, 10)` proximity searches, and prefix wildcards (`987654*`, `TXYZop*`).

### 6.2 Index 2: The 3-Character `Trigram` Substring & Regex `FTS5` Index (`global_fts5_trigram_index`)

* Configure a second companion virtual table using SQLite's built-in **`trigram` tokenizer**:
  $$\texttt{tokenize = "trigram case\_sensitive 0"}$$
* **How the `Trigram` Index Accelerates Substring & Regex Queries by $1,000\times$:**
  * Suppose the investigator searches for the middle 6 digits `"148291"` of a 12-digit UTR or bank account (`WHERE searchable_text LIKE '%148291%'`), or runs a regular expression (`REGEXP`).
  * Without `trigram`, SQLite must read all 50 million rows from disk.
  * With `global_fts5_trigram_index`, SQLite decomposes `"148291"` into four 3-character trigrams (`"148"`, `"482"`, `"829"`, `"291"`), intersects their inverted posting lists in memory in $< 15\text{ milliseconds}$, and returns the exact matching `doc_uid`s!

### 6.3 Index 3: Compressed 32-Bit Roaring Bitmap Facet Engine (`roaring_bitmap_facet_index_store`)

In Phase 9's UI, the left sidebar displays live filter checkboxes (Facets) with instant record counts across 8 dimensions:
1. `originating_phase` (`Phase 1` .. `Phase 7`)
2. `artifact_domain_category` (`MESSAGING_CHAT`, `FIAT_UPI_BANK_TX`, `CRYPTO_WEB3_CEX_TX`, `GEOLOCATION_RADIO_FIX`, `MEDIA_SNAPSHOT_OCR_QR`, etc.)
3. `recovery_classification` (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD` \[`-wal`\], `RESIDUAL_RECORD` \[Deleted/Freelist/Snapshot\], `RECONSTRUCTED_RECORD`)
4. `app_package_or_subsystem` (`com.whatsapp`, `org.telegram.messenger`, `com.phonepe.app`, `com.binance.dev`, etc.)
5. `android_user_profile_or_locality` (`User 0`, `User 95 Dual`, `User 150 Secure Folder`, `User 999 Cloner`, `iOS Local`, `Cloud Synced`)
6. `has_financial_or_crypto_indicator` (`1` / `0`)
7. `has_deleted_or_tamper_anomaly` (`1` / `0`)
8. `date_bucket_yyyy_mm_dd` (Daily calendar buckets for the timeline histogram bar chart!)

#### How Each Facet Value Is Stored as a Roaring Bitmap:
For every facet key-value pair `(facet_dimension, facet_value)`, collect the sorted set of 32-bit unsigned integer `timeline_event_uid`s (or `doc_uid`s) that match that attribute, and partition the 32-bit integers by their **upper 16 bits (`chunk_key` $= \text{uid} \gg 16$)** into 65,536-integer chunks storing the **lower 16 bits ($\text{uid} \ \& \ \text{0xFFFF}$)**:
* **Container Type 1 (Sparse Array Container):** If a 16-bit chunk contains $< 4,096$ integers, store as a sorted array of `uint16_le` values ($2\text{ bytes}$ per integer).
* **Container Type 2 (Dense Bitset Container):** If a 16-bit chunk contains $\ge 4,096$ integers, store as a fixed $8,192\text{-byte}$ ($65,536\text{-bit}$) bitmask!
* **Container Type 3 (Run-Length Encoded `RLE` Container):** If a chunk contains contiguous runs of integers, store as `(start_uint16, length_uint16)` pairs.

When the examiner clicks any combination of filters in Phase 9's UI, the backend intersects the corresponding Roaring Bitmaps in RAM (`Bitmap_A & Bitmap_B & Bitmap_C`) and computes the exact count of matching rows via CPU `POPCNT` in **under $1.0\text{ millisecond}$**!

---

## 7. Database Schema for Module 8.2 (`zero_omission_unk_and_fts5_engine.sqlite`)

The developer must create the following four tables in the master case convergence database:

### Table 1: `vfs_zero_omission_accounting_ledger` (100% VFS File Accounting, Disguised Magic & Entropy Audit)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `vfs_file_id` | `INTEGER` | `PRIMARY KEY` | 1-to-1 foreign key to Phase 1 `vfs_index.file_id`. |
| `canonical_vfs_path` | `TEXT` | `NOT NULL` | Full path inside the extraction image. |
| `owning_app_package_or_domain` | `TEXT` | `NULL` | Resolved owning package/bundle ID from Module 1.3. |
| `file_byte_size` | `INTEGER` | `NOT NULL` | Logical byte size of the file. |
| `accounting_state` | `TEXT` | `NOT NULL` | Mandatory 4-State Enum: `STATE_1_PARSED_AND_VERIFIED`, `STATE_2_RECOGNIZED_DECRYPTION_OR_CORRUPTION_BLOCKED`, `STATE_3_KNOWN_SYSTEM_OR_STATIC_ASSET_IMMUTABLE`, `STATE_4_UNK_UNPARSED_USER_ARTIFACT`. Indexed! |
| `consumed_by_modules_json` | `TEXT` | `NULL` | JSON array of Phase 1–7 modules that parsed this file (e.g., `["MOD_5_1_WHATSAPP", "MOD_2_1_SQLITE"]`). |
| `extracted_records_count` | `INTEGER` | `DEFAULT 0` | Total records extracted from this file across all modules. |
| `filename_extension` | `TEXT` | `NULL` | Lowercase extension from filename (e.g., `".png"`, `".db"`, `".bin"`). |
| `detected_magic_signature` | `TEXT` | `NOT NULL` | True binary signature from Table 4.1 (e.g., `"SQLITE_3_DATABASE"`, `"JAVA_DALVIK_DEX"`, `"UNKNOWN_BINARY"`). |
| `is_extension_spoofed_mismatch` | `INTEGER` | `DEFAULT 0` | **`1` if `filename_extension` contradicts `detected_magic_signature` (e.g., a SQLite DB or APK renamed to `.png` or `.ttf`)!** Indexed! |
| `shannon_entropy_bits` | `REAL` | `NULL` | Computed $H(X) \in [0.000, \ 8.000]\text{ bits/byte}$. |
| `chi_square_uniformity_score` | `REAL` | `NULL` | Computed Pearson $\chi^2$ score over 256 byte bins ($df = 255$). |
| `entropy_crypto_classification` | `TEXT` | `NULL` | Enum from Section 4.2: `UNCATALOGED_SQLCIPHER_OR_PAGE_ENCRYPTED_DB`, `HIGH_ENTROPY_ENCRYPTED_BLOB_OR_CONTAINER`, `COMPRESSED_OR_PROPRIETARY_BINARY_STREAM`, `LOW_ENTROPY_PLAINTEXT_OR_STRUCTURED`. |
| `unk_introspection_hit_count` | `INTEGER` | `DEFAULT 0` | Number of forensic indicators recovered from this file by Sub-Engine 8.2C! |

### Table 2: `unk_generic_introspection_findings` (Evidence Extracted From Unrecognized Apps & `STATE_4_UNK` Files)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `unk_finding_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `vfs_zero_omission_accounting_ledger.vfs_file_id`. Indexed! |
| `owning_app_package` | `TEXT` | `NOT NULL` | Package or folder name of the unrecognized app. |
| `container_structure_type` | `TEXT` | `NOT NULL` | Enum: `UNK_SQLITE_ACTIVE_ROW`, `UNK_SQLITE_WAL_OR_FREELIST_ROW`, `UNK_JSON_OR_XML_NODE`, `UNK_MMKV_OR_LEVELDB_KV`, `UNK_PROTOBUF_TREE`, `UNK_CARVED_UTF8_UTF16_STRING`. |
| `table_or_object_path` | `TEXT` | `NOT NULL` | Table name + row ID (or JSON/XML key path or physical byte offset). |
| `detected_indicator_category` | `TEXT` | `NOT NULL` | Enum: `GENERIC_TIMESTAMPED_MESSAGE_OR_RECORD`, `VALIDATED_UPI_UTR_12_DIGIT`, `VALIDATED_UPI_VPA`, `VALIDATED_IFSC_AND_BANK`, `VALIDATED_CRYPTO_ADDRESS`, `VALIDATED_BIP39_OR_XMR_SEED`, `VALIDATED_PAN_AADHAAR_GSTIN`, `PHONE_NUMBER_E164`, `OPSEC_HANDLE_OR_C2_URL`, `WGS84_GPS_COORDINATE_PAIR`. |
| `extracted_indicator_value` | `TEXT` | `NOT NULL` | The specific validated phone, UTR, VPA, crypto address, or message text. Indexed! |
| `full_row_or_context_json` | `TEXT` | `NOT NULL` | Complete JSON serialization of all columns in the unrecognized SQLite row or surrounding context! |
| `inferred_timestamp_utc_iso` | `TEXT` | `NULL` | Auto-detected timestamp converted to UTC ISO-8601 (if present in the row). |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 3: `global_fts5_search_catalog` (Backing Master Document Table + Dual `FTS5` Virtual Indexes)

| Table / Virtual Index Name | Engine & Tokenizer Configuration | Columns Indexed |
|---|---|---|
| **`global_search_documents_master`** | Standard B-Tree Table (`doc_uid INTEGER PRIMARY KEY`) | `doc_uid`, `timeline_event_uid`, `originating_phase_module`, `artifact_domain`, `app_package`, `source_vfs_file_id`, `source_record_pointer`, `recovery_classification`, `timestamp_utc_ns`, `actor_names_and_handles_nfc`, `searchable_body_text_nfc`. |
| **`global_fts5_lexical_index`** | `USING fts5(..., content='global_search_documents_master', content_rowid='doc_uid', tokenize="unicode61 remove_diacritics 2 tokenchars '@._:-+/$#'")` | Indexes `actor_names_and_handles_nfc` and `searchable_body_text_nfc` for instant word, prefix, VPA, email, path, and Indic `NFC` queries! |
| **`global_fts5_trigram_index`** | `USING fts5(..., content='global_search_documents_master', content_rowid='doc_uid', tokenize="trigram case_sensitive 0")` | Indexes `actor_names_and_handles_nfc` and `searchable_body_text_nfc` for sub-50ms arbitrary substring (`LIKE '%...%'`), mid-UTR, and `GLOB` / `REGEXP` queries! |

### Table 4: `roaring_bitmap_facet_index_store` (Pre-Computed 32-Bit Roaring Bitmaps for Sub-Millisecond UI Filtering)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `facet_bitmap_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `target_table_scope` | `TEXT` | `NOT NULL` | `"UNIFIED_SUPER_TIMELINE"` or `"GLOBAL_SEARCH_DOCUMENTS"`. |
| `facet_dimension_name` | `TEXT` | `NOT NULL` | E.g., `"originating_phase"`, `"artifact_domain_category"`, `"recovery_classification"`, `"app_package"`, `"user_profile"`, `"date_yyyy_mm_dd"`. |
| `facet_value_key` | `TEXT` | `NOT NULL` | E.g., `"PHASE_5"`, `"MESSAGING_CHAT"`, `"RESIDUAL_RECORD"`, `"com.whatsapp"`, `"2026-11-05"`. |
| `total_matching_cardinality` | `INTEGER` | `NOT NULL` | Pre-computed exact count of matching records (`POPCNT` of bitmap). |
| `serialized_roaring_bitmap_blob` | `BLOB` | `NOT NULL` | Portable serialized 32-bit Roaring Bitmap (`0x3B30` cookie header + chunk directory + Array/Bitset/RLE containers). |

---

## 8. Developer Acceptance Test Checklist for Module 8.2

1. **The Zero-Omission Conservation & Disguised SQLite Extension Mismatch Test:**
   * Take a valid SQLite database (`"SQLite format 3\0"`) containing a table `secret_ledger(id, client_phone, amount_usdt, created_ts)` with row `(1, "+919876543210", "25000 USDT to TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf", 1762348800000)`, rename the file to `/sdcard/Android/data/com.unknown.customapp/files/logo_icon.png`, and run Module 8.2.
   * Verify that:
     1. Sub-Engine 8.2A places the file in `STATE_4_UNK_UNPARSED_USER_ARTIFACT` and verifies $N_{\text{total}} == \sum_{s=1}^4 N_{\text{State } s}$.
     2. Sub-Engine 8.2B sets `detected_magic_signature = "SQLITE_3_DATABASE"` and `is_extension_spoofed_mismatch = 1`.
     3. Sub-Engine 8.2C introspects `secret_ledger`, converts `1762348800000` to `2026-11-05T13:20:00.000Z`, validates the TRON address `TXYZ...` and phone `+919876543210`, and links them into Module 8.1's Entity Graph and Super-Timeline!
2. **The Shannon Entropy ($H(X)$) + Chi-Square ($\chi^2$) Encrypted vs. Compressed Disambiguation Test:**
   * Feed two $65,536\text{-byte}$ ($64\text{ KB}$) files into Sub-Engine 8.2B:
     * File A: A high-entropy compressed `.jpg` image (with header stripped or unknown header) where $H(X) = 7.94\text{ bits/byte}$ and $\chi^2 = 1,420.5$.
     * File B: A $65,536\text{-byte}$ (`16 x 4096-byte pages`) `SQLCipher v4` encrypted database where $H(X) = 7.997\text{ bits/byte}$ and $\chi^2 = 251.4$.
   * Verify that Sub-Engine 8.2B classifies File A as `COMPRESSED_OR_PROPRIETARY_BINARY_STREAM` and classifies File B as `UNCATALOGED_SQLCIPHER_OR_PAGE_ENCRYPTED_DB` (routing File B to Module 2.2's SQLCipher Key Prober!).
3. **The Dual `FTS5` (`tokenchars` VPA + `trigram` Substring + Devanagari `NFC`) Search Test:**
   * Insert three records into `global_search_documents_master`:
     * Doc 1: `"Paid Rs 50,000 to merchant.99@okaxis via UTR 630914829104"`
     * Doc 2 (Decomposed `NFD` Hindi string): `"हवाला का पैसा नोएडा फ्लैट में है"`
   * Verify that:
     1. Querying `global_fts5_lexical_index` for `"merchant.99@okaxis"` returns Doc 1 as an exact single-token match.
     2. Querying `global_fts5_trigram_index` for substring `"148291"` returns Doc 1 in $< 15\text{ ms}$.
     3. Querying `global_fts5_lexical_index` with a keyboard-typed `NFC` string `"नोएडा"` matches Doc 2 after Sub-Engine 8.2D's `NFC` normalization!