# Engineering Specification: Phase 1, Module 1.1 — The Virtual Filesystem (VFS) & Streaming Archive Indexer

**Document Purpose:** This specification provides an exhaustive, zero-ambiguity architectural blueprint for building **Module 1.1** of the Forensic Data Parser. It is written in plain, logical steps—without programming code—so that a developer with zero prior experience in mobile forensics can implement a commercial-grade ingestion engine capable of handling extractions from $10\text{ GB}$ to $1.5\text{ TB}$ without crashing, running out of disk space, or corrupting forensic metadata.

---

## 1. Why Naive Archive Extraction Fails (The 5 Golden Rules)

When a novice developer is asked to parse a `.zip` or `.tar` file produced by Cellebrite UFED, Cellebrite Inseyets, Magnet GrayKey, or Oxygen Forensics, their first instinct is to use a standard library function to "extract all files to a temporary folder on the hard drive." **In commercial forensics, doing that is fatal for five reasons:**

1. **The Disk Space & I/O Wall:** A modern $512\text{ GB}$ or $1\text{ TB}$ iPhone/Android Full File-System (FFS) extraction contains between $1,500,000$ and $4,500,000$ individual files. Extracting $800\text{ GB}$ of small files onto an NTFS or APFS workstation drive takes $3$ to $6\text{ hours}$, consumes $800+\text{ GB}$ of free SSD space, and causes severe disk thrashing.
2. **Host OS Timestamp Destruction:** If you unzip files onto a Windows or macOS workstation, the host operating system overwrites the file's creation timestamp (`btime` / `crtime`) with the current clock time of the forensic workstation, destroying timeline evidence.
3. **Windows Filename & Case-Sensitivity Collisions:** Mobile operating systems (iOS and Android) use case-sensitive filesystems where `Cache_01.dat` and `cache_01.dat` can exist in the exact same directory. Furthermore, Android and Chromium cache filenames frequently contain characters like `:`, `?`, `*`, `"`, `<`, `>`, or `|` (for example, `http://api.phonepe.com:443/v1/tx?id=1`). If your code attempts to extract those filenames onto a Windows NTFS drive, the operating system will throw an immediate file-creation error or silently overwrite files.
4. **Extended Attributes (`xattrs`) & Permission Loss:** Standard extraction drops Linux UID/GID ownership (which tells you which Android app created a file), Android SELinux labels (`security.selinux`), and iOS Data Protection classes (`NSFileProtectionComplete`).
5. **Host Antivirus Quarantine:** Mobile extractions frequently contain banking trojan APKs, rooting binaries (`su`, `magisk`), or browser exploit caches. If you unpack the entire archive onto a Windows folder, Windows Defender or endpoint antivirus will automatically quarantine or delete those files out of your working directory, altering the evidence.

### The Solution: A Zero-Copy Virtual Filesystem (VFS)
Instead of unpacking the archive, **Module 1.1** scans the archive's headers once, records the exact **byte offset** and **metadata** of every file inside a fast local SQLite catalog called `vfs_index.sqlite`, normalizes all file paths into a single standard format, and streams only the specific bytes needed by downstream parsers on demand.

---

## 2. High-Level Data Flow of Module 1.1

When an investigator selects an evidence source in the software, Module 1.1 executes five sequential stages:

1. **Stage 1 (Container Fingerprinting):** Inspect the input path and raw header magic bytes (never trust file extensions alone) to identify which of the 8 supported forensic container formats has been loaded.
2. **Stage 2 (Header-Only Indexing Pass):** Walk through the archive's internal directory structure (without extracting file payloads) to capture every file's path, size, internal byte offset, compression method, original timestamps, permissions, and extended attributes.
3. **Stage 3 (Canonical Path Normalization):** Translate tool-specific path quirks (such as iTunes SHA-1 hash filenames, Cellebrite `fs/` prefixes, `/var` vs. `/private/var`, and `/data/data` vs. `/data/user/0`) into a unified **Canonical Device Path**.
4. **Stage 4 (Catalog Commit):** Bulk-insert all discovered file records into the case's `vfs_index` database in batches of $25,000\text{ rows}$ inside a single transaction for maximum speed.
5. **Stage 5 (On-Demand Stream & Co-File Materialization API):** Expose a clean read interface to Phases 2–7 so any parser can ask for a path (or wildcard pattern) and receive either a memory stream or a safely staged SQLite database family (`.db` + `-wal` + `-journal`).

---

## 3. Stage 1 — Container Magic-Byte Fingerprinting Engine

Never rely solely on a file extension (for example, a `.ufdr` file is actually a ZIP archive, and some Cellebrite `.tar` outputs are actually GZIP-compressed `.tar.gz` streams). When given an input path, the developer must execute the following inspection logic:

### 3.1 Directory vs. File Check
First, check if the input path is a **Directory** on the workstation disk:
* **Case 1 (iOS Logical Backup Directory):** Check if the directory contains `Manifest.db` (starting with the 16-byte SQLite header `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00`, which spells `"SQLite format 3\0"`), `Manifest.plist`, and `Info.plist`. Classify as `IOS_BACKUP_DIR`.
* **Case 2 (Cellebrite UFED Package Directory):** Check if the directory contains a `.ufd` or `.ufdx` descriptor file alongside one or more `.tar`, `.zip`, or `.bin` payload files. Classify as `UFED_PACKAGE_DIR` and register each payload file for indexing.
* **Case 3 (Unpacked File-System Directory):** Any other directory tree containing `/data/`, `/system/`, or `/private/var/`. Classify as `UNPACKED_FS_DIR`.

### 3.2 Single-File Magic Byte Table
If the input path is a **File**, read the first $512\text{ bytes}$ (and the last $64\text{ KB}$ of the file) and match against these exact byte signatures:

| Container Type Enum | Byte Offset | Exact Hexadecimal Magic Signature | ASCII Equivalent & Identification Logic |
|---|---|---|---|
| `ZIP_OR_UFDR` | Offset $0$ (or last $64\text{ KB}$) | `50 4B 03 04` (Local Header) & `50 4B 05 06` or `50 4B 06 06` (EOCD / ZIP64 EOCD at end of file) | `"PK.."`. If file extension is `.ufdr` or contains `report.xml` at root, sub-classify as `CELLEBRITE_UFDR`; otherwise `STANDARD_ZIP`. |
| `TAR_UNCOMPRESSED` | Offset $257$ | `75 73 74 61 72 00` or `75 73 74 61 72 20 20 00` | `"ustar\0"` (POSIX IEEE P1003.1 / PAX TAR) or `"ustar  \0"` (GNU TAR) inside the 512-byte header block. |
| `TAR_GZ_COMPRESSED` | Offset $0$ | `1F 8B 08` | GZIP deflate stream header. Decompress the first $512\text{ bytes}$ in memory and check Offset $257$ for `"ustar"` to confirm it is a `.tar.gz` archive. |
| `ANDROID_AB_BACKUP` | Offset $0$ | `41 4E 44 52 4F 49 44 20 42 41 43 4B 55 50 0A` | `"ANDROID BACKUP\n"` (15 bytes), followed by version line, compression flag (`0` or `1`), and encryption algorithm (`none` or `AES-256`). |
| `ENCASE_E01_IMAGE` | Offset $0$ | `45 56 46 09 0D 0A FF 00` | `"EVF\t\r\n\xff\0"` (8-byte Expert Witness Compression Format signature). |
| `RAW_DISK_OR_APFS` | Offset $32$ (APFS) or Offset $512$ (GPT) | `4E 58 53 42` (`NXSB` at offset $32$ of block) or `45 46 49 20 50 41 52 54` (`EFI PART` at offset $512$) | Raw APFS container superblock or GUID Partition Table (GPT) physical disk image. |

---

## 4. Stage 2 — Zero-Extraction Header Indexing Mechanics

Once the container type is identified, execute the specific header-indexing algorithm for that container:

### 4.1 Indexing `.zip`, `ZIP64`, and `.ufdr` Containers (End-of-File Central Directory Scan)
* **Never scan a ZIP file from byte 0 to the end**, because streaming ZIP writers often set compressed size and CRC to $0$ in the Local File Header (`50 4B 03 04`) and write the real sizes in a trailing Data Descriptor.
* **Correct Algorithm:**
  1. Seek to the end of the `.zip` file and read the final $65,557\text{ bytes}$.
  2. Scan backwards for the **End of Central Directory (EOCD)** signature (`50 4B 05 06`).
  3. Check immediately preceding the EOCD for the **ZIP64 EOCD Locator** (`50 4B 06 07`). *(Crucial: Any mobile extraction larger than $4\text{ GB}$ or containing more than $65,535\text{ files}$ uses **ZIP64**. If you only read 32-bit offsets from standard EOCD, your indexer will fail on every modern FFS extraction!)*
  4. Seek directly to the **Central Directory start offset** (64-bit integer from the ZIP64 EOCD record).
  5. Iterate sequentially through every **Central Directory File Header (`50 4B 01 02`)**:
     * Read `compression_method` ($0 =$ Stored Uncompressed, $8 =$ Deflate, $93 =$ Zstandard).
     * Read `compressed_size`, `uncompressed_size`, and `local_header_offset` (if any of these 32-bit fields equals `0xFFFFFFFF`, read the true 64-bit value from the **ZIP64 Extended Information Extra Field `0x0001`**).
     * Read the filename string bytes and Extra Fields (`0x5455` Extended UTC Timestamp, `0x7875` Info-ZIP Unix UID/GID).
     * Record `local_header_offset` in `vfs_index`. Because the Central Directory is contiguous at the end of the file, **indexing $2,000,000\text{ files}$ in a $300\text{ GB}$ ZIP takes less than $4\text{ seconds}$!**

### 4.2 Indexing Uncompressed `.tar` Archives (512-Byte Block Jumping + PAX Headers)
A `.tar` archive does not have a Central Directory at the end; it is a sequential chain of $512\text{-byte}$ header blocks followed by file payload blocks padded to multiples of $512\text{ bytes}$.
* **Correct Algorithm:**
  1. Start at byte offset $0$. Read $512\text{ bytes}$. If all $512\text{ bytes}$ are `0x00`, check the next $512\text{-byte}$ block; two consecutive all-zero blocks signal End-Of-Archive.
  2. Read the octal `size` string at byte offset $124$ ($12\text{ bytes}$) and convert it from base-8 (octal) to a 64-bit integer (`payload_size`). *(Note: If the first byte of the size field is `0x80`, it is a binary big-endian 64-bit integer used for files $> 8\text{ GB}$).*
  3. Inspect the `typeflag` byte at offset $156$:
     * **`'x'` (`0x78`) or `'g'` (`0x67`) — PAX Extended Header:** The payload immediately following this header is NOT a regular file; it is a list of key-value metadata lines (`"%d %s=%s\n"`) for the *next* file in the archive! Read those `payload_size` bytes into memory and parse keys:
       * `path`: The full UTF-8 file path (overrides the 100-char limit of legacy TAR headers).
       * `linkpath`: Full symlink target path.
       * `size`: True file size in bytes.
       * `mtime`, `atime`, `ctime`, `SCHILY.fflags`, `LIBARCHIVE.creationtime` (`btime`): High-precision floating-point UTC timestamps.
       * `SCHILY.xattr.security.selinux`: Android SELinux label.
       * `SCHILY.xattr.com.apple.fileprotection`: iOS Data Protection class.
     * **`'L'` (`0x4C`) — GNU LongLink Filename:** Read the payload as the full UTF-8 filename for the *next* header block.
     * **`'0'` (`0x30`) or `'\0'` (`0x00`) — Regular File:**
       * The actual file content starts at `data_offset = current_header_offset + 512`.
       * Record `data_offset` and `payload_size` in `vfs_index`.
       * **Jump over the file content without reading it:** Calculate the next header offset using 512-byte ceiling alignment:
         $$\text{next\_header\_offset} = \text{data\_offset} + \left\lceil \frac{\text{payload\_size}}{512} \right\rceil \times 512$$
       * Seek directly to `next_header_offset`.
     * **`'2'` (`0x32`) — Symbolic Link:** Record the symlink source path and target `linkname` so path resolution knows where symlinked directories point.

### 4.3 Indexing Compressed `.tar.gz` / `.tgz` Archives (Sliding-Window Access-Point Checkpointing)
Unlike `.zip` or uncompressed `.tar`, you cannot normally seek to byte $50,000,000,000$ inside a `.tar.gz` file because GZIP is a single continuous Deflate stream where decompressing block $N$ requires the $32\text{ KB}$ sliding LZ77 dictionary from block $N-1$.
* **How Commercial Tools Solve This:**
  1. During Stage 2's single streaming pass through the `.tar.gz` file (which runs simultaneously with Module 1.2's Product A hashing pass so the file is only read once!), decompress the stream in $8\text{ MB}$ chunks to locate TAR headers.
  2. Every $64\text{ MB}$ of uncompressed TAR offset, save a **Deflate Access-Point Checkpoint** in the `gzip_seek_checkpoints` table containing:
     * `compressed_byte_offset`: Exact byte position in the `.tar.gz` file.
     * `uncompressed_byte_offset`: Corresponding virtual TAR byte offset.
     * `bit_offset`: Bit position ($0\text{–}7$) inside the compressed byte.
     * `sliding_window_32kb`: The raw $32,768\text{ bytes}$ of uncompressed data immediately preceding this point (compressed with LZ4/Zstd down to $\approx 10\text{ KB}$).
  3. Later, when a parser asks for a file at uncompressed offset $200\text{ GB}$, the VFS loads the checkpoint at $199.95\text{ GB}$, primes the zlib inflater with that $32\text{ KB}$ window, and seeks directly to the file in milliseconds!

### 4.4 Indexing iOS Logical Backups (`Manifest.db`)
When indexing an `IOS_BACKUP_DIR`:
1. Check `Manifest.plist` first: Read boolean key `IsEncrypted`.
   * If `IsEncrypted == true`, mark the backup container as encrypted and check if the investigator supplied the backup password (needed in Phase 2 to unwrap the `BackupKeyBag` and decrypt `Manifest.db`).
   * If `IsEncrypted == false` (or once `Manifest.db` is decrypted), open `Manifest.db` in SQLite read-only mode.
2. Execute query: `SELECT fileID, domain, relativePath, flags, file FROM Files;`
3. For each row:
   * `fileID` is a 40-character lowercase SHA-1 hex string (e.g., `"3d0d7e5fb2ce288813306e4d4636395e047a3d28"`).
   * The physical file on the workstation disk is located at `<backup_root>/<first_2_chars_of_fileID>/<fileID>` (e.g., `<backup_root>/3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28`).
   * Decode the binary plist (`bplist00` / `NSKeyedArchiver` format) inside the `file` BLOB column to extract: `Size`, `Birth` (`btime`), `LastModified` (`mtime`), `LastStatusChange` (`ctime`), `Mode`, `UserID`, `GroupID`, `ProtectionClass`, and `EncryptionKey` (for encrypted backups).

---

## 5. Stage 3 — Canonical Path Normalization Rules

Different extraction tools wrap the exact same device file inside different archive folder prefixes. To ensure downstream parsers in Phases 2–7 only ever have to query **one standard path**, every path indexed by Module 1.1 must pass through the **6-Step Canonical Path Normalizer**:

1. **Slash & Unicode Normalization:** Convert all Windows backslashes (`\`) to forward slashes (`/`), collapse duplicate slashes (`//` $\rightarrow$ `/`), ensure the path starts with a leading `/`, and normalize the UTF-8 string to **Unicode NFC**.
2. **Strip Vendor Wrapper Prefixes:** If the archive wraps the root filesystem inside a top-level vendor folder—such as `/fs/`, `/root/`, `/Dump/`, `/files/`, or `/<Device_UDID>/root/`—strip that prefix so the path starts at the true mobile OS root.
3. **iOS Symlink Canonicalization (`/var` $\rightarrow$ `/private/var`):** On iOS, `/var` is a symbolic link to `/private/var`, and `/tmp` is a symbolic link to `/private/tmp`. Some tools archive files under `/var/mobile/...` while others archive them under `/private/var/mobile/...`.
   * **Rule:** Any iOS path starting with `/var/` **must** be rewritten to start with `/private/var/`.
4. **Android Primary Sandbox Canonicalization (`/data/data` $\rightarrow$ `/data/user/0`):** On Android, `/data/data/<pkg>` is a symlink/bind-mount to `/data/user/0/<pkg>`.
   * **Rule:** Any Android path starting with `/data/data/` **must** be rewritten to start with `/data/user/0/` (while keeping an alias index so queries for either path succeed).
5. **Android Shared Storage Canonicalization (`/sdcard` & `/storage/emulated/0` $\rightarrow$ `/data/media/0`):**
   * **Rule:** Any Android path starting with `/sdcard/`, `/mnt/sdcard/`, or `/storage/emulated/<user_id>/` **must** be rewritten to `/data/media/<user_id>/`.
6. **iOS Backup Domain-to-Virtual-Path Mapping:** For iOS Logical Backups (`Manifest.db`), translate `domain` + `relativePath` into canonical iOS paths while also preserving the raw `domain`:
   * `HomeDomain` + `Library/SMS/sms.db` $\rightarrow$ `/private/var/mobile/Library/SMS/sms.db`
   * `WirelessDomain` + `Library/CallHistoryDB/CallHistory.storedata` $\rightarrow$ `/private/var/wireless/Library/CallHistoryDB/CallHistory.storedata`
   * `CameraRollDomain` + `Media/PhotoData/Photos.sqlite` $\rightarrow$ `/private/var/mobile/Media/PhotoData/Photos.sqlite`
   * `SystemPreferencesDomain` + `SystemConfiguration/com.apple.wifi.known-networks.plist` $\rightarrow$ `/private/var/preferences/SystemConfiguration/com.apple.wifi.known-networks.plist`
   * `KeychainDomain` + `keychain-backup.plist` $\rightarrow$ `/private/var/Keychains/keychain-backup.plist`
   * `AppDomain-<BundleID>` + `<rel>` $\rightarrow$ `/private/var/mobile/Containers/Data/Application/<BundleID>/<rel>`
   * `AppDomainGroup-<GroupID>` + `<rel>` $\rightarrow$ `/private/var/mobile/Containers/Shared/AppGroup/<GroupID>/<rel>`

---

## 6. Stage 4 — The `vfs_index.sqlite` Database Schema & High-Speed Batch Commit

To index $3,000,000\text{ files}$ in under $30\text{ seconds}$, the developer must configure the SQLite catalog database with `PRAGMA journal_mode = WAL;`, `PRAGMA synchronous = NORMAL;`, and `PRAGMA temp_store = MEMORY;`, and insert rows in **prepared-statement batches of $25,000\text{ rows}$ per `BEGIN IMMEDIATE ... COMMIT` transaction**.

### Table 1: `vfs_index` (Master Virtual File Catalog)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `file_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique internal ID for every indexed file, directory, or symlink. |
| `container_id` | `INTEGER` | `NOT NULL` | Foreign key to `container_integrity_ledger.container_id` (Module 1.2). |
| `canonical_path` | `TEXT` | `NOT NULL` | Normalized device path (e.g., `/private/var/mobile/Library/SMS/sms.db`). Indexed via B-Tree! |
| `parent_dir_path` | `TEXT` | `NOT NULL` | Normalized parent directory (e.g., `/private/var/mobile/Library/SMS`). Indexed for fast directory listing! |
| `filename` | `TEXT` | `NOT NULL` | Base filename (e.g., `sms.db`). Indexed for fast filename searches! |
| `file_extension` | `TEXT` | `NULL` | Lowercase extension without dot (e.g., `db`, `sqlite`, `wal`, `plist`, `xml`, `crypt15`). |
| `original_raw_path` | `TEXT` | `NOT NULL` | Exact unmodified path string inside the archive or `domain:relativePath` in `Manifest.db`. |
| `entry_type` | `TEXT` | `NOT NULL` | Enum: `REGULAR_FILE`, `DIRECTORY`, `SYMLINK`, `HARDLINK`. |
| `symlink_target` | `TEXT` | `NULL` | Target path if `entry_type == 'SYMLINK'`. |
| `uncompressed_size` | `INTEGER` | `NOT NULL DEFAULT 0` | True file size in bytes. |
| `compressed_size` | `INTEGER` | `NOT NULL DEFAULT 0` | Stored payload size inside the archive. |
| `archive_data_offset` | `INTEGER` | `NOT NULL DEFAULT 0` | Exact byte offset inside the archive (or uncompressed TAR stream) where payload or Local Header begins. |
| `compression_method` | `TEXT` | `NOT NULL` | Enum: `RAW_STORED`, `ZIP_DEFLATE`, `ZIP_ZSTD`, `TAR_GZ_STREAM`, `IOS_BACKUP_FILE`, `E01_CHUNK`. |
| `backup_file_id_sha1` | `TEXT` | `NULL` | 40-char SHA-1 filename for iOS backups (or physical relative path for unpacked directories). |
| `is_encrypted_entry` | `INTEGER` | `DEFAULT 0` | `1` if ZIP password-encrypted or iOS encrypted backup blob; `0` otherwise. |

**Mandatory SQLite Indexes on `vfs_index`:**
1. `CREATE INDEX idx_vfs_canonical_path ON vfs_index(canonical_path);`
2. `CREATE INDEX idx_vfs_parent_dir ON vfs_index(parent_dir_path);`
3. `CREATE INDEX idx_vfs_filename ON vfs_index(filename);`
4. `CREATE INDEX idx_vfs_extension ON vfs_index(file_extension);`

### Table 2: `gzip_seek_checkpoints` (For `.tar.gz` Random Seeking)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `checkpoint_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Sequential checkpoint ID. |
| `container_id` | `INTEGER` | `NOT NULL` | Foreign key to container. |
| `compressed_offset` | `INTEGER` | `NOT NULL` | Byte offset in `.tar.gz` file. |
| `uncompressed_offset` | `INTEGER` | `NOT NULL` | Virtual byte offset in uncompressed `.tar` stream (indexed). |
| `bit_offset` | `INTEGER` | `NOT NULL` | Bit alignment ($0\text{–}7$). |
| `window_lz4_blob` | `BLOB` | `NOT NULL` | LZ4-compressed $32\text{ KB}$ deflate sliding window dictionary. |

---

## 7. Stage 5 — On-Demand Stream & SQLite Co-File Family Materialization API

Downstream parsers in Phases 2–7 must **never** open the `.tar` or `.zip` archive directly. They interact exclusively with three VFS API methods:

### Method 1: `vfs_query_paths(pattern_or_exact_path)`
* Accepts an exact canonical path (e.g., `/data/system/packages.xml`) or a SQL `LIKE` / glob pattern (e.g., `/data/user/%/com.whatsapp/databases/msgstore.db`).
* Returns matching rows from `vfs_index` joined with `file_provenance_catalog` (Module 1.2).

### Method 2: `vfs_open_memory_stream(file_id)`
* Used for small configuration files, plists, XMLs, JSONs, and media thumbnails ($< 32\text{ MB}$).
* Seeks directly to `archive_data_offset` inside the container, decompresses the stream in RAM, and returns a read-only byte buffer without touching the workstation hard drive.

### Method 3: `vfs_stage_sqlite_family(primary_db_file_id)` (Crucial Forensic Rule!)
* **Why This Exists:** A SQLite database on a mobile device is rarely just one file. It consists of up to four co-located files in the same directory:
  1. `<name>.db` (or `.sqlite` / `.storedata` / no extension)
  2. `<name>.db-wal` (Write-Ahead Log containing the newest transactions!)
  3. `<name>.db-shm` (Shared-memory WAL index)
  4. `<name>.db-journal` (Rollback journal)
* If a parser stages only `sms.db` and forgets to stage `sms.db-wal` into the exact same staging folder with the exact same filename prefix, **all recent messages in the WAL will be silently lost!**
* **Exact Execution Steps of `vfs_stage_sqlite_family`:**
  1. Look up the requested `primary_db_file_id` in `vfs_index` to get its `parent_dir_path` and `filename` (e.g., `sms.db`).
  2. Automatically query `vfs_index` in the same `parent_dir_path` for companion files named:
     * `<filename>-wal`
     * `<filename>-journal`
     * `<filename>-shm`
     * (Also check iOS/Android WAL variants where `.db` is replaced by `-wal`, if any).
  3. Create an isolated sub-directory inside the case's staging workspace named after a safe **UUID** (e.g., `<case_workspace>/staging/stg_00042/`).
     * *Why a flat UUID folder?* Because the full mobile path or filename might exceed Windows' 260-character `MAX_PATH` limit or contain characters illegal on Windows NTFS!
  4. Inside `stg_00042/`, stream the primary database out as `target.db`, and if companion files exist, stream them out into the exact same folder as `target.db-wal` and `target.db-journal`.
  5. While streaming each file to disk, invoke **Module 1.2's Zero-Pass Tee Hasher** to record `product_b1_raw_sha256` and `companion_wal_sha256` in `derivative_staging_ledger`.
  6. Mark `target.db`, `target.db-wal`, and `target.db-journal` as **Read-Only** (`Product B1`), and create a writable duplicate (`working_copy.db` + `working_copy.db-wal`) in `stg_00042/work/` for Phase 2's SQLite/WAL engine to query and checkpoint (`Product B2`).

---

## 8. Developer Acceptance Test Checklist for Module 1.1

1. **The ZIP64 $> 4\text{ GB}$ Boundary Test:** Load a `.zip` or `.ufdr` file larger than $10\text{ GB}$ containing $> 100,000\text{ files}$. Verify that the Central Directory scanner reads 64-bit offsets from the `0x0001` ZIP64 Extra Field and successfully streams a file located past the $4\text{ GB}$ ($4,294,967,295\text{ byte}$) boundary.
2. **The PAX Long-Path & xattr Test:** Load a `.tar` archive containing a file path longer than $150\text{ characters}$ and a PAX `SCHILY.xattr.security.selinux` attribute. Verify that the full un-truncated path and SELinux label are captured.
3. **The Windows Illegal-Character Survival Test:** Create a synthetic `.tar` containing two files in the same folder: `Cache_A.txt` and `cache_a.txt`, plus a file named `https://upi.bank.in:8443/pay?vpa=a@b*`. Run the VFS indexer on a Windows 11 workstation and stream all three files via `vfs_open_memory_stream`. All three must be indexed and read with zero Windows NTFS errors.
4. **The SQLite Co-File Family Auto-Discovery Test:** Call `vfs_stage_sqlite_family` on `sms.db` only. Verify that the VFS automatically locates `sms.db-wal` in the same virtual directory, stages both files side-by-side in the UUID workspace folder, and hashes both before opening.