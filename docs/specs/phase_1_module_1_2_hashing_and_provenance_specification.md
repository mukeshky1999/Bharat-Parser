# Engineering Specification: Phase 1, Module 1.2 — Dual SHA-256 Hashing & Metadata Provenance Engine

**Document Purpose:** This document provides the complete, step-by-step logical blueprint for building **Module 1.2** of the Forensic Data Parser. It contains **zero programming code** and explains every concept from first principles so that any developer can build a legally defensible, courtroom-grade hashing and metadata preservation engine that complies with **ISO/IEC 27037**, **SWGDE (2025/2026)**, and **Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam (BSA) 2023**.

---

## 1. Purpose & Mental Model (Why Module 1.2 Exists)

In standard software development, if you read a file and show its contents to a user, nobody asks you to prove mathematically that you did not secretly alter the file while reading it. **In digital forensics, defence attorneys will immediately challenge your software in court if you cannot prove three things:**

1. **Container Integrity (Product A):** The extraction file loaded into your software is bit-for-bit identical to the file produced by the acquisition tool (Cellebrite UFED, Inseyets, GrayKey, or Oxygen) at the crime scene or lab.
2. **Working / Derivative Integrity (Product B):** When your software extracts a specific database (like `sms.db` + `sms.db-wal`) or decrypts an encrypted file (like WhatsApp `msgstore.db.crypt15` or Signal `Signal.sqlite`) into a temporary workspace to parse it, it records the exact cryptographic hash of both the raw extracted bytes and the decrypted working file.
3. **Metadata Provenance:** Every file's original mobile device timestamps (Creation, Modification, Access, Status Change), Linux user ownership (`UID`/`GID`), Android SELinux security label, and iOS Data Protection class were captured directly from the archive headers—**never** from the Windows or macOS computer running your parser.

---

## 2. The 5 Fatal Mistakes Beginner Developers Make (And How to Avoid Them)

Before writing a single line of logic for Module 1.2, the developer must understand five classic traps that break forensic tools:

### Mistake 1: Reading the Entire File into RAM to Hash It
* **The Trap:** Calling a naive function like `sha256(read_entire_file("extraction.tar"))`. When an investigator loads a 512 GB Full File-System (FFS) extraction on a laptop with 32 GB of RAM, the program immediately crashes with an Out-Of-Memory (OOM) error.
* **The Rule:** All hashing in Module 1.2 **must use chunked streaming**. You allocate a fixed memory buffer (strictly between $4\text{ MB}$ and $16\text{ MB}$), read one chunk from disk, feed that chunk into the SHA-256 state machine, reuse the exact same buffer for the next chunk, and finalize the hash when the stream reaches End-Of-File (EOF).

### Mistake 2: Opening a Staged SQLite Database Before Hashing It
* **The Trap:** Extracting `sms.db` and `sms.db-wal` into a temporary staging folder, opening `sms.db` with a standard SQLite driver to "check if it is valid," and *then* calculating its SHA-256 hash.
* **Why It Fails:** The instant a standard SQLite library opens a database that has a Write-Ahead Log (`-wal`) sitting next to it, SQLite automatically performs a **checkpoint**—it writes the pages from `sms.db-wal` into `sms.db`, updates the change counter in the `sms.db` header, and truncates or deletes `sms.db-wal`. Your staged file now has a completely different SHA-256 hash than the file inside the evidence archive!
* **The Rule:** You must calculate the SHA-256 hash of `.db`, `-wal`, and `-journal` files **while streaming them out of the archive (before any SQLite engine ever touches them)**, and you must always copy a read-only working duplicate before allowing SQLite to checkpoint a WAL.

### Mistake 3: Hashing a Folder in Random Operating System Order
* **The Trap:** Some extractions (like an Apple iTunes Backup folder or an unpacked UFED directory) are **folders of loose files**, not a single `.zip` or `.tar` file. If you ask Windows, macOS, or Linux for a list of files in a directory and hash them in the order the OS returns them, two different computers will produce two different container hashes because operating systems return directory listings in non-deterministic order.
* **The Rule:** When hashing a folder-based extraction, you must construct a **Deterministic Manifest Tree** sorted strictly by canonical UTF-8 byte order (detailed in Section 3.1, Case C).

### Mistake 4: Converting Timestamps to Strings and Throwing Away the Raw Number
* **The Trap:** Reading a timestamp from a plist or archive header, converting it to a human string like `"04/11/2026 08:30 PM"`, and saving only that string in the database.
* **Why It Fails:** You lose sub-second precision (microseconds/nanoseconds), you lose which clock epoch the timestamp came from (Unix 1970 vs. Apple Cocoa 2001 vs. WebKit 1601), and you create ambiguity over whether the time was originally stored in UTC or the suspect's local timezone.
* **The Rule:** Every timestamp in your software must be stored using the **5-Column Forensic Timestamp Standard** (detailed in Section 4).

### Mistake 5: Ignoring Vendor Hash Logs Already Accompanying the Extraction
* **The Trap:** Calculating your own SHA-256 hash of `extraction.tar`, saving it, and never checking whether matches the hash recorded inside Cellebrite's `.ufd` file or GrayKey's log file when the phone was originally extracted.
* **The Rule:** Module 1.2 must automatically parse the accompanying vendor log file (if present), extract the vendor's original acquisition hash, compare it against your newly calculated Product A hash, and flag `VERIFIED_MATCH` or `CRITICAL_HASH_MISMATCH`.

---

## 3. Step-by-Step Logic: The Dual-Hash Engine (Product A & Product B)

### 3.1 Computing the Product A Hash (Original Evidence Container)

When an investigator loads an evidence source into the software, Module 1.2 must determine which of the **three physical input structures** it is dealing with and execute the corresponding hashing workflow:

#### Case A: Single-File Archive (`.tar`, `.tar.gz`, `.zip`, `.ufdr`, `.bin`, `.dd`)
1. Open the file in binary read-only mode (`O_RDONLY`) with sequential read caching hints enabled.
2. Initialize both a **SHA-256** state object (mandatory primary standard) and, if an older `.ufd` file accompanies the extraction and only lists MD5 or SHA-1, a secondary **SHA-1 / MD5** state object in the same loop so you never have to read a 500 GB file twice.
3. Allocate an $8\text{ MB}$ ($8,388,608\text{ bytes}$) byte buffer.
4. Loop until End-Of-File (EOF):
   * Read up to $8\text{ MB}$ into the buffer.
   * Feed those exact bytes into the SHA-256 state object (and secondary hash state if active).
   * Update the UI progress bar with `bytes_processed / total_file_size`.
5. Finalize the hash digest as a lowercase 64-character hexadecimal string (for SHA-256).
6. Record `start_utc_timestamp`, `completion_utc_timestamp`, `total_bytes_hashed`, and `product_a_sha256` into the `container_integrity_ledger` table.

#### Case B: Multi-Part / Split Archive (`.e01` + `.e02`..., or `.z01` + `.z02` + `.zip`)
1. Identify all segments belonging to the split archive in strict numerical sequence.
2. For each individual segment file (e.g., `image.E01`, `image.E02`), compute and record its **Per-Segment SHA-256 Hash**.
3. If the format is `.E01` (EnCase EWF format), also read the internal EWF checksum/hash footer stored inside the final segment (which holds the hash of the *uncompressed raw disk stream* inside the `.E01` wrapper) and verify it against the decompressed stream.

#### Case C: Folder-Based Extraction (iOS Logical Backup Folder or Unpacked Directory)
Because a folder is not a single file, you cannot feed "a folder" directly into SHA-256. To produce a repeatable, courtroom-verifiable **Product A Composite Container Hash** that any independent expert can reproduce on any operating system:
1. Recursively enumerate every regular file inside the root evidence folder.
2. For each file, compute its relative path from the root of the evidence folder using forward slashes (`/`) only (e.g., `Manifest.db`, `Manifest.plist`, `00/00a1b2c3...`).
3. Normalize all relative path strings to **Unicode Normalization Form C (NFC)** so that macOS (which uses NFD decomposed accents) and Windows/Linux (which use NFC) produce identical path bytes.
4. Sort the complete list of files in strict **lexicographical UTF-8 byte order** of their normalized relative paths.
5. Hash each individual file using chunked SHA-256.
6. Build an in-memory or temp-file **Canonical Hash Manifest** where each line is formatted strictly as:
   `<lowercase_64_char_file_sha256> *<normalized_relative_path>\n` (using a single Unix newline `0x0A`, never Windows `\r\n`).
7. Compute the SHA-256 hash of that complete **Canonical Hash Manifest**.
8. Store the individual file hashes in the per-file ledger, store the manifest file itself in the case audit folder, and store the manifest's SHA-256 as the **Product A Composite Container Hash**.

---

### 3.2 Vendor Hash Cross-Verification Routine

Immediately after computing the Product A hash, Module 1.2 checks if the extraction includes an acquisition tool log file:

1. **Cellebrite `.ufd` / `.ufdx` Files:**
   * Look in the same directory as the `.tar`/`.zip`/`.bin` for a `.ufd` text file.
   * Parse the `[Hashes]` or `[SHA256]` section inside the `.ufd` file, where Cellebrite lists `Filename=HashValue`.
   * Compare your computed `product_a_sha256` (case-insensitively) against the hash recorded in the `.ufd` file.
2. **Magnet GrayKey / VeraKey Hash Logs:**
   * Look for `*_hashes.txt` or the JSON/text extraction summary exported alongside the GrayKey `.zip`/`.tar`.
   * Extract the vendor-recorded SHA-256 value for the FFS archive and Keychain plist.
3. **Verification State Assignment:**
   * If a vendor hash file is present and matches: Set `vendor_verification_status = "VERIFIED_MATCH_WITH_ACQUISITION_TOOL"`.
   * If a vendor hash file is present and does **not** match: Set `vendor_verification_status = "CRITICAL_MISMATCH"`, trigger an immediate red alert banner in the UI, and log the discrepancy in Dimension C (`Corrupt / Modified`).
   * If no vendor hash file was provided with the archive: Set `vendor_verification_status = "SELF_ANCHORED_AT_INGESTION"` (meaning your Product A hash is now the primary baseline hash from the moment the file entered your software).

---

### 3.3 Computing Product B Hashes (Staged & Derivative Files)

In Module 1.1, we established that small plists or XMLs can be read in memory, but **SQLite databases (`.db` + `-wal` + `-journal`)** and **encrypted databases requiring decryption (SQLCipher, WhatsApp `.crypt14/.crypt15`, Realm)** must be materialized into an isolated local staging folder so that SQLite/SQLCipher engines can seek across pages and process WAL frames.

Every time a file leaves the VFS archive and is written to the local staging folder, Module 1.2 executes the **Three-Stage Product B Hashing Protocol**:

#### Stage B1: Pre-Open Staged Hash (Zero-Pass Tee Hashing)
1. When the VFS streams `sms.db` (and its companion `sms.db-wal` and `sms.db-journal`) out of the `.tar` or `.zip` container into the local staging folder:
2. Pass every byte chunk through a **"Tee" stream**—simultaneously writing the chunk to the staging disk file *and* feeding the chunk into a SHA-256 hasher.
3. Before any parser or SQLite driver is allowed to open the staged file, lock and record its hash as `staged_raw_sha256` (**Product B1**).
4. Set the staged original files to read-only (`chmod 0400` / Windows Read-Only attribute).

#### Stage B2: Working Copy & WAL-Checkpointed Derivative Hash
1. When Phase 2's SQLite engine needs to query the database natively (which may trigger WAL recovery or checkpointing) or when Phase 2's decryption engine decrypts an encrypted file (e.g., decrypting WhatsApp `msgstore.db.crypt15` into a plaintext `msgstore_decrypted.db`, or decrypting Signal's `Signal.sqlite` using the 96-hex-char Keychain key):
2. The engine writes the resulting decrypted or WAL-checkpointed database to a distinct derivative filename (e.g., `<staging_uuid>_decrypted.sqlite`).
3. Compute the SHA-256 hash of that newly created derivative file and record it as `derivative_product_b_sha256` (**Product B2**), alongside the exact transformation method used (e.g., `"SQLCipher v4 Decryption via iOS Keychain OWSPrimaryStorage"` or `"SQLite 3 WAL Checkpoint Merge"`).

---

## 4. The Forensic Timestamp Provenance Engine

Mobile devices use at least **five completely different clock systems**. If a developer assumes every integer timestamp is a standard Unix timestamp, Apple databases will appear to be from the year 1995 and Chrome databases will appear to be from the year 2300.

### 4.1 The 5 Mobile Clock Epochs & Exact Conversion Math

Module 1.2 must provide a central, unit-tested timestamp normalization utility that converts all five clock systems while **preserving the original raw value**:

#### 1. Unix Epoch Time (POSIX)
* **Base Date:** `1970-01-01 00:00:00 UTC`.
* **Where Used:** TAR/PAX archive headers, iOS `Manifest.db`, Android `ext4`/`F2FS` inodes, WhatsApp Android `msgstore.db` (milliseconds), Telegram `cache4.db` (seconds), Android `UsageStats` (milliseconds).
* **Sub-Unit Auto-Detection Logic (for integer inputs):**
  * If value is $10\text{ digits}$ (e.g., $1762262400$, roughly between $10^9$ and $4 \times 10^9$): **Seconds**.
  * If value is $13\text{ digits}$ (e.g., $1762262400123$, roughly between $10^{12}$ and $4 \times 10^{12}$): **Milliseconds** (divide by $10^3$ for seconds; keep remainder as milliseconds).
  * If value is $16\text{ digits}$ (e.g., $1762262400123456$, roughly between $10^{15}$ and $4 \times 10^{15}$): **Microseconds** (divide by $10^6$).
  * If value is $19\text{ digits}$ (e.g., $1762262400123456789$, roughly between $10^{18}$ and $4 \times 10^{18}$): **Nanoseconds** (divide by $10^9$).

#### 2. Apple Cocoa / CoreData / Mac Absolute Time
* **Base Date:** `2001-01-01 00:00:00 UTC` (exactly $978,307,200\text{ seconds}$ after the Unix Epoch).
* **Where Used:** Almost every Apple SQLite database and plist (`sms.db`, `Photos.sqlite`, `knowledgeC.db`, `AddressBook.sqlitedb`, `Safari/History.db`, `Notes`, `healthdb_secure.sqlite`, and **Apple Biome SEGB v1/v2 headers**).
* **Sub-Unit & Conversion Math:**
  * **Standard Cocoa Seconds (Float or 9-digit Integer, e.g., $815596800.123456$):**
    $$\text{Unix Seconds} = \text{Cocoa Seconds} + 978307200$$
  * **Cocoa Nanoseconds (18-digit Integer in iOS `sms.db` `date`, `date_read`, `date_delivered` since iOS 11+):**
    $$\text{Unix Seconds} = \left(\frac{\text{Cocoa Nanoseconds}}{10^9}\right) + 978307200$$

#### 3. WebKit / Chromium / Windows FILETIME Epoch
* **Base Date:** `1601-01-01 00:00:00 UTC` (exactly $11,644,473,600\text{ seconds}$ before the Unix Epoch).
* **Where Used:** Google Chrome (`History`, `Cookies`, `Login Data`, `Web Data`), Microsoft Edge, Brave, and **every Android third-party app's embedded `app_webview` SQLite databases**.
* **Conversion Math:**
  * **WebKit Microseconds (17-digit Integer, e.g., $13406755200000000$):**
    $$\text{Unix Seconds} = \left(\frac{\text{WebKit Microseconds}}{10^6}\right) - 11644473600$$

#### 4. MS-DOS Local Timestamp (Standard ZIP Header Fallback)
* **Where Used:** Basic `.zip` Central Directory headers when the archiving tool did not write an Extended Timestamp (`0x5455`) or NTFS (`0x000a`) extra field.
* **Critical Forensics Warning:** Standard MS-DOS ZIP time has only **2-second precision** and is recorded in **unqualified local time** (no UTC offset is stored in the basic header).
* **Rule:** When Module 1.1 indexes a `.zip` file, it must **always check the ZIP Extra Fields first**:
  * If Extra Field `0x5455` (`UT` — Extended Timestamp) or `0x7855`/`0x000a` is present: Read the true 32-bit/64-bit UTC Unix timestamps (`mtime`, `atime`, `crtime`) from the extra field and tag provenance as `UTC_ZIP_EXTRA_FIELD`.
  * If only the basic MS-DOS header exists: Decode the 16-bit date and 16-bit time, and explicitly tag its timezone provenance as `AMBIGUOUS_LOCAL_ZIP_DOS_HEADER` so an investigator never confuses it with a verified UTC timestamp.

#### 5. Unqualified Floating Local Strings (EXIF & Legacy Logs)
* **Where Used:** Camera JPEG/HEIC `DateTimeOriginal` EXIF tags (prior to `OffsetTimeOriginal` inspection) and plain-text application logs that omit `+05:30` or `Z`.
* **Rule:** Never silently assume UTC. Tag as `FLOATING_LOCAL_TIME` until corroborated with the device's system timezone plist (`preferences.plist` / `persist.sys.timezone` in `build.prop` or `settings_global.xml`).

---

### 4.2 The Mandatory 5-Column Timestamp Storage Rule

Whenever Module 1.2 (or any downstream parser in Phases 2–7) stores a timestamp in the database, it must populate **five columns side-by-side**:

1. `ts_raw_value` (`TEXT`): The exact unmodified string or integer read from the evidence (e.g., `"815596800450123000"`).
2. `ts_epoch_unit` (`TEXT`): The source clock format (e.g., `"APPLE_COCOA_NANOSECONDS"`, `"UNIX_SECONDS"`, `"WEBKIT_MICROSECONDS"`, `"ZIP_DOS_LOCAL"`).
3. `ts_utc_unix_ns` (`INTEGER`): Normalized 64-bit integer representing **nanoseconds since 1970-01-01 00:00:00 UTC** (used for ultra-fast numerical sorting and range queries across 50 million timeline events).
4. `ts_utc_iso8601` (`TEXT`): Human-readable UTC string in strict ISO-8601 format with sub-second precision: `YYYY-MM-DDTHH:MM:SS.ffffffZ` (e.g., `"2026-11-04T14:40:00.450123Z"`).
5. `ts_tz_provenance` (`TEXT`): Records whether the UTC offset was `INTRINSIC_UTC`, `EXPLICIT_OFFSET_IN_RECORD` (e.g., `+05:30`), `INFERRED_FROM_DEVICE_CONFIG`, or `FLOATING_UNVERIFIED`.

---

## 5. Extended Attributes (`xattrs`), Permissions & Security Provenance

When Module 1.1 scans a `.tar` (with PAX extended headers), an iOS `Manifest.db`, or a filesystem image, Module 1.2 extracts and decodes four critical pieces of security metadata for every file and stores them in the `file_provenance_catalog`:

### 5.1 POSIX Permissions, UID, and GID
* **What to Capture:**
  * `posix_mode` (`INTEGER` & octal `TEXT`, e.g., `0100600` $\rightarrow$ `-rw-------`).
  * `owner_uid` (`INTEGER`, e.g., `10145` on Android or `501` for `mobile` on iOS).
  * `owner_gid` (`INTEGER`).
* **Why It Matters Forensically:** On Android, every installed app is assigned a unique Linux UID starting at `10000` (for user `0`, UID `10145` corresponds to `u0_a145`). By matching a file's `owner_uid` against `/data/system/packages.list` (in Module 1.3), your parser can prove **which exact application created a file** even if the file is sitting in a shared folder or temporary directory!

### 5.2 iOS Data Protection Class Decoding
* **Where to Read It:**
  * **In `.tar` FFS archives:** Read the PAX header key `SCHILY.xattr.com.apple.fileprotection` or Apple Double `._` resource fork metadata.
  * **In iOS Logical Backups (`Manifest.db`):** Inside the `Files` table, the `file` column contains a binary plist (`NSKeyedArchiver` format). Inside that plist, read the integer key `ProtectionClass`.
* **How to Decode the Protection Class Integer:**
  * `1` $\rightarrow$ **Class A (`NSFileProtectionComplete`):** Accessible only when device is currently unlocked.
  * `2` $\rightarrow$ **Class B (`NSFileProtectionCompleteUnlessOpen`):** Accessible while open even after locking.
  * `3` $\rightarrow$ **Class C (`NSFileProtectionCompleteUntilFirstUserAuthentication`):** Accessible in AFU (After First Unlock until reboot).
  * `4` $\rightarrow$ **Class D (`NSFileProtectionNone`):** Accessible even in BFU (protected only by hardware UID).
* **Forensic Use:** Automatically populates **Dimension B (Accessibility)** and **Group 12/16** encryption domain auditing.

### 5.3 Android SELinux Security Label Decoding (`security.selinux`)
* **Where to Read It:** In PAX `.tar` headers (`SCHILY.xattr.security.selinux`) or ext4/F2FS inode xattrs.
* **What It Looks Like:** A null-terminated ASCII string such as `u:object_r:app_data_file:s0:c512,c768` or `u:object_r:system_file:s0`.
* **Automated Tamper Rule (Group 16 & Group 17):**
  * Module 1.2 must inspect every extracted `security.selinux` string against three high-priority tamper flags:
    1. If the label contains `magisk`, `ksu`, or `su` (e.g., `u:object_r:magisk_file:s0`): Flag immediately as `ROOT_FRAMEWORK_ARTIFACT` in Group 17.
    2. If a file inside `/system/`, `/vendor/`, or `/data/app/` has the label `u:object_r:unlabeled:s0`: Flag immediately as `ANOMALOUS_UNLABELED_SYSTEM_FILE` (indicates offline partition modification or dirty root injection).
    3. If a file inside an app's private `/data/data/<pkg>/` directory has `u:object_r:shell_data_file:s0` or `u:object_r:adb_data_file:s0`: Flag as `ADB_OR_SHELL_INJECTED_FILE` (proves the file was pushed via ADB or shell rather than created naturally by the app).

### 5.4 iOS Download Provenance & Backup Exclusion Flags
* **`com.apple.metadata:kMDItemWhereFroms`:** A binary plist stored inside the file's extended attributes on iOS/macOS that records the **exact source URL** (and referring webpage URL) from which a photo, PDF, or archive was downloaded—even if the user later cleared their Safari browser history! Module 1.2 must automatically decode this binary plist whenever present on a file and log the URLs.
* **`com.apple.MobileBackup` (`NSURLIsExcludedFromBackupKey`):** Indicates that the app developer explicitly marked the file/folder to be excluded from iTunes/Finder Logical Backups. Recording this flag allows your parser to explain *why* an artifact is present in an FFS extraction but missing from a suspect's iCloud/iTunes backup.

---

## 6. Database Schema for Module 1.2 (`provenance_ledger.sqlite`)

The developer must create the following four tables in the case's SQLite database to store all Module 1.2 outputs:

### Table 1: `container_integrity_ledger` (Product A Record)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `container_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each loaded evidence source in the case. |
| `source_input_path` | `TEXT` | `NOT NULL` | Original workstation file/folder path selected by the examiner. |
| `container_type` | `TEXT` | `NOT NULL` | Enum: `TAR`, `TAR_GZ`, `ZIP`, `UFDR`, `UFD_PACKAGE`, `IOS_BACKUP_FOLDER`, `E01`, `RAW_IMAGE`. |
| `acquisition_tier` | `TEXT` | `NOT NULL` | Enum: `TIER_1A_API`, `TIER_1B_BACKUP`, `TIER_2_FFS`, `TIER_3_FS_IMAGE`, `TIER_4_PHYSICAL`, `TIER_5_RAM`. |
| `total_size_bytes` | `INTEGER` | `NOT NULL` | Total byte size of the evidence container on disk. |
| `product_a_sha256` | `TEXT` | `NOT NULL` | Lowercase 64-character SHA-256 hash of the original container (or Canonical Manifest SHA-256 for folders). |
| `product_a_md5` | `TEXT` | `NULL` | Optional MD5 hash (computed only if legacy `.ufd` file requires MD5 comparison). |
| `vendor_log_path` | `TEXT` | `NULL` | Path to accompanying `.ufd`, `.ufdx`, or GrayKey hash log (if found). |
| `vendor_expected_hash` | `TEXT` | `NULL` | Hash string extracted from the vendor's acquisition log. |
| `verification_status` | `TEXT` | `NOT NULL` | Enum: `VERIFIED_MATCH`, `CRITICAL_MISMATCH`, `SELF_ANCHORED_NO_VENDOR_LOG`. |
| `hash_started_utc` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp when Product A hashing started. |
| `hash_completed_utc` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp when Product A hashing finished. |

---

### Table 2: `file_provenance_catalog` (Inode & Security Metadata per File)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `vfs_file_id` | `INTEGER` | `PRIMARY KEY` | Foreign key 1-to-1 with `vfs_index.file_id` from Module 1.1. |
| `canonical_path` | `TEXT` | `NOT NULL` | Normalized device path (e.g., `/data/data/com.phonepe.app/databases/phonepe.db`). |
| `mtime_raw` | `TEXT` | `NULL` | Raw modification time value from archive/manifest header. |
| `mtime_utc_ns` | `INTEGER` | `NULL` | Modification time in UTC nanoseconds since 1970-01-01. |
| `mtime_utc_iso` | `TEXT` | `NULL` | Modification time formatted as `YYYY-MM-DDTHH:MM:SS.ffffffZ`. |
| `btime_raw` | `TEXT` | `NULL` | Raw creation/birth time value (`btime`/`crtime`), if preserved by container. |
| `btime_utc_ns` | `INTEGER` | `NULL` | Creation time in UTC nanoseconds since 1970-01-01. |
| `btime_utc_iso` | `TEXT` | `NULL` | Creation time formatted as `YYYY-MM-DDTHH:MM:SS.ffffffZ`. |
| `ctime_utc_iso` | `TEXT` | `NULL` | Inode metadata change time (`ctime`) in UTC ISO-8601. |
| `atime_utc_iso` | `TEXT` | `NULL` | Last access time (`atime`) in UTC ISO-8601. |
| `ts_tz_provenance` | `TEXT` | `NOT NULL` | Enum: `INTRINSIC_UTC`, `UTC_ZIP_EXTRA_FIELD`, `AMBIGUOUS_LOCAL_ZIP_DOS`, `UNKNOWN`. |
| `posix_mode_octal` | `TEXT` | `NULL` | Octal permission string (e.g., `"0100660"`). |
| `owner_uid` | `INTEGER` | `NULL` | Numeric Linux/Darwin user ID (`UID`). |
| `owner_gid` | `INTEGER` | `NULL` | Numeric Linux/Darwin group ID (`GID`). |
| `ios_protection_class` | `TEXT` | `NULL` | Enum: `CLASS_A`, `CLASS_B`, `CLASS_C`, `CLASS_D`, or `NULL`. |
| `android_selinux_label` | `TEXT` | `NULL` | Extracted `security.selinux` string (e.g., `u:object_r:app_data_file:s0`). |
| `where_froms_urls_json` | `TEXT` | `NULL` | JSON array of URLs decoded from `kMDItemWhereFroms` xattr. |
| `is_backup_excluded` | `INTEGER` | `DEFAULT 0` | `1` if `com.apple.MobileBackup` exclusion flag is set; `0` otherwise. |
| `tamper_anomaly_flag` | `TEXT` | `NULL` | Populated if SELinux label or timestamp exhibits tampering (e.g., `MAGISK_SELINUX_CONTEXT`). |

---

### Table 3: `derivative_staging_ledger` (Product B Record)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `staging_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for every staged or decrypted derivative file. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key pointing to the original file in `vfs_index`. |
| `companion_wal_file_id` | `INTEGER` | `NULL` | Foreign key pointing to the `-wal` file in `vfs_index` (if staged as a SQLite family). |
| `staged_local_path` | `TEXT` | `NOT NULL` | Relative path inside the case's isolated staging workspace. |
| `product_b1_raw_sha256` | `TEXT` | `NOT NULL` | SHA-256 hash of the raw bytes streamed from the archive **before** any SQLite/decryptor touch. |
| `companion_wal_sha256` | `TEXT` | `NULL` | SHA-256 hash of the raw `-wal` file **before** SQLite open/checkpoint. |
| `derivation_action` | `TEXT` | `NOT NULL` | Enum: `RAW_STAGE_ONLY`, `SQLITE_WAL_CHECKPOINT_MERGE`, `SQLCIPHER_DECRYPT`, `CRYPT15_DECRYPT`, `MMKV_RECONSTRUCT`. |
| `crypto_key_reference` | `TEXT` | `NULL` | Reference to the key used (e.g., `Keychain:OWSPrimaryStorage` or `/data/data/com.whatsapp/files/key`). |
| `product_b2_derived_sha256`| `TEXT` | `NULL` | SHA-256 hash of the resulting decrypted or WAL-merged derivative file. |
| `staged_utc_timestamp` | `TEXT` | `NOT NULL` | Exact UTC ISO-8601 timestamp when the staging/derivation occurred. |

---

### Table 4: `chain_of_custody_audit_log` (Courtroom Certificate Trail)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `event_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Sequential monotonic event counter. |
| `event_utc_iso` | `TEXT` | `NOT NULL` | High-precision UTC timestamp of the action. |
| `software_version` | `TEXT` | `NOT NULL` | Exact build version of your forensic parser (e.g., `"v1.0.0-build20261104"`). |
| `workstation_hostname` | `TEXT` | `NOT NULL` | Hostname and OS version of the examiner's workstation. |
| `action_type` | `TEXT` | `NOT NULL` | E.g., `INGEST_START`, `PRODUCT_A_HASH_VERIFIED`, `STAGE_SQLITE_FAMILY`, `DECRYPT_SQLCIPHER`. |
| `target_description` | `TEXT` | `NOT NULL` | Path or artifact family affected. |
| `input_sha256` | `TEXT` | `NULL` | Input hash verified prior to action. |
| `output_sha256` | `TEXT` | `NULL` | Resulting derivative hash after action. |

---

## 7. Developer Acceptance Test Checklist (How to Verify Module 1.2 Works)

Before moving to Module 1.3, the developer must run the following five verification tests:

1. **The 100 GB Constant-RAM Test:** Feed a $\ge 100\text{ GB}$ `.tar` or `.zip` file into the Product A hasher while monitoring the process's RAM usage. Memory consumption of the hashing thread must remain flat (under $30\text{ MB}$) from $0\%$ to $100\%$, and the resulting SHA-256 string must match the output of `sha256sum` / `CertUtil -hashfile` on the command line.
2. **The Cross-OS Folder Hash Test:** Take an iOS Logical Backup folder containing $10,000$ files, run the Case C Folder Hasher on a Windows machine and then on a macOS or Linux machine. Both machines must output the **exact same 64-character Product A Composite SHA-256 hash**.
3. **The SQLite WAL Immutability Test:** Stage an active SQLite database that has a populated `-wal` file (e.g., `sms.db` + `sms.db-wal`). Verify that `product_b1_raw_sha256` matches the hash of `sms.db` inside the archive, and that opening the working derivative copy for parsing does **not** alter the read-only `Product B1` staged files.
4. **The 5-Epoch Timestamp Test:** Pass known test vectors for Unix seconds ($1762262400$), Unix nanoseconds ($1762262400000000000$), Apple Cocoa seconds ($815555200$), Apple Cocoa nanoseconds ($815555200000000000$), and WebKit microseconds ($13406713600000000$) into the timestamp normalizer and verify that all five resolve to the exact same UTC ISO-8601 date (`2026-11-04`).
5. **The Host Timestamp Isolation Test:** Stage a file created in 2023 out of a `.tar` archive onto a Windows workstation in 2026. Query `file_provenance_catalog` and verify that `btime_utc_iso` and `mtime_utc_iso` reflect the 2023 archive header timestamps, completely ignoring the 2026 Windows host file creation timestamp.