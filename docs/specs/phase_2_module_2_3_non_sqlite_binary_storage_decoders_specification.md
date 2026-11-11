# Engineering Specification: Phase 2, Module 2.3 — Non-SQLite Binary Storage Engine Decoders (`MMKV`, `LevelDB`/`IndexedDB`, Apple `SEGB v1/v2` & Schema-Less `Protobuf`)

**Document Purpose:** This document provides the complete, byte-level architectural blueprint for building **Module 2.3** of the Forensic Data Parser. It contains **zero programming code** and explains every binary file layout, variable-length integer encoding, prefix-compression algorithm, and slack-space carving routine from first principles so that a developer with no prior experience in binary reverse engineering can build a commercial-grade decoder for modern non-SQLite mobile data stores.

---

## 1. Purpose & Mental Model (Why SQLite Is Only Half the Battle in 2026)

Ten years ago, almost every mobile application stored its local data in SQLite databases and plain XML/plist preference files. Today, high-concurrency mobile engineering has shifted critical application state, financial ledgers, cryptographic vaults, and operating-system behavioral telemetry into **four high-speed binary storage formats** that traditional SQLite-centric forensic tools fail to parse completely:

1. **Tencent `MMKV` (Memory-Mapped Key-Value Store):** Originally created for WeChat and now used by **PhonePe, Paytm, CRED, Navi, Discord, TikTok, ShareChat, and hundreds of Indian fintech, betting, and React Native/Flutter apps**. Because `MMKV` appends updates sequentially to a memory-mapped file buffer before compacting, a single `MMKV` file preserves a chronological history of overwritten tokens, previous logged-in UPI Virtual Payment Addresses (VPAs), and deleted session states.
2. **Google `LevelDB` & Chromium `IndexedDB`:** The underlying key-value engine for **self-custody cryptocurrency wallets (`MetaMask`, `Trust Wallet`, `Phantom`, `TronLink`, `Coinbase Wallet`)**, **Discord**, **WhatsApp Web/Desktop caches**, and **every embedded `app_webview` / `WKWebView` browser sandbox**.
3. **Apple `SEGB` (`Biome` Binary Streams — v1 & v2):** The binary log engine powering all **84 Apple Biome streams** across iOS 15 through iOS 26 (`/private/var/db/biome/` and `/private/var/mobile/Library/Biome/`), tracking physical location, app focus, Wi-Fi/Bluetooth connections, notifications, and device state.
4. **Google `Protocol Buffers` (Raw Schema-Less Wire Format):** The binary serialization format nested inside `SEGB` payloads, `MMKV` values, Android `UsageStats`, WhatsApp `.crypt15` headers, and gRPC network caches—where the original `.proto` schema definition file is not present on the seized device.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Non-SQLite Binary Parsing

Before implementing Module 2.3, the developer must understand six classic traps that cause data loss or crashes in amateur decoders:

### Mistake 1: Opening `MMKV` or `LevelDB` Files with Their Official Read/Write SDKs
* **The Trap:** Importing the official `mmkv` or `leveldb`/`plyvel` library in your code and calling `mmkv.getString(key)` or `db.iterator()`.
* **Why It Destroys Evidence:**
  * In **`MMKV`**, the official SDK reads the file, builds a hash map in RAM keeping only the *final* value for each key, and **silently discards all earlier overwritten values and unallocated mmap slack space**!
  * In **`LevelDB`**, opening a database directory with the standard LevelDB library can immediately trigger **background SSTable compaction**, which merges `.log` and `.ldb` files, **permanently erasing all `0x00` Deletion Tombstones and historical sequence versions** from the evidence!
* **The Rule:** Never open forensic `MMKV` or `LevelDB` files using their standard runtime SDKs. You must parse the raw byte streams directly in read-only mode using the exact binary specifications in Sections 3 and 4.

### Mistake 2: Confusing SQLite Big-Endian Varints with Protobuf/MMKV/LevelDB Little-Endian Varints
* **The Trap:** Reusing the SQLite Varint decoder from Module 2.1 to read Varints in `MMKV`, `LevelDB`, or `Protobuf`.
* **Why It Fails:**
  * **SQLite Varints (Module 2.1)** are **Big-Endian (Most Significant Group First)**: the first byte holds the highest bits of the number, and each subsequent byte shifts the accumulated result left ($\text{result} = (\text{result} \ll 7) \mid \text{low\_7\_bits}$).
  * **Protobuf, MMKV, and LevelDB Varints (Module 2.3)** are **Little-Endian (Least Significant Group First)**: the first byte holds the *lowest* $7\text{ bits}$ of the number, the second byte holds bits $7\text{–}13$, and so on ($\text{result} = \text{result} \mid (\text{low\_7\_bits} \ll (7 \times i))$)!
* **The Rule:** Keep the SQLite Big-Endian Varint function and the Protobuf/LevelDB Little-Endian Base-128 Varint function strictly separate (see Section 3.2 for the exact Little-Endian math).

### Mistake 3: Failing to Strip the 8-Byte Internal Tag Trailer from LevelDB Keys
* **The Trap:** Reading a key string from a LevelDB `.ldb` or `.sst` Data Block and outputting the entire reconstructed byte array as the key name.
* **Why It Fails:** Inside a LevelDB `.ldb`/`.sst` Data Block, every key is stored as an **`InternalKey`**, which consists of:
  $$\text{InternalKey} = \text{UserKeyBytes} \parallel \text{uint64\_le}\left((\text{SequenceNumber} \ll 8) \mid \text{ValueType}\right)$$
  If you do not strip and unpack the final $8\text{ bytes}$ of the key, every key name in your report will have $8\text{ bytes}$ of binary garbage appended to the end, and you will lose the **Sequence Number** and the **Deletion Tombstone flag (`ValueType == 0x00`)**!
* **The Rule:** Always split the last $8\text{ bytes}$ off every `.ldb`/`.sst` Data Block key (Section 4.3).

### Mistake 4: Crashing on Snappy-Compressed (`0x01`) or Zstd-Compressed (`0x02`) LevelDB Blocks
* **The Trap:** Assuming the bytes inside a LevelDB `.ldb` Data Block are uncompressed plaintext.
* **Why It Fails:** LevelDB compresses individual Data Blocks using **Google Snappy** (or **Zstandard** in modern Chromium builds). At the end of every Data Block sits a 5-byte trailer: 1 byte for `compression_type` (`0x00` = None, `0x01` = Snappy, `0x02` = Zstd) and 4 bytes for the CRC32C checksum.
* **The Rule:** Always inspect the 1-byte `compression_type` trailer at the end of each LevelDB block and decompress via Snappy or Zstd before reading the prefix-compressed keys.

### Mistake 5: Misunderstanding `MMKV`'s Inner Length Prefix on String & Object Values
* **The Trap:** Reading an `MMKV` entry `[key_len][key_bytes][val_container_len][val_bytes]` and treating all of `val_bytes` as a UTF-8 string.
* **Why It Fails:** In `MMKV`, `val_container_len` is the byte length of the outer value container. When `MMKV` writes a UTF-8 String or Byte Array inside that container, it writes an *inner* Protobuf Varint length at the start of `val_bytes`! Furthermore, `MMKV` lacks explicit per-field type tags on disk because the calling app uses typed getters (`decodeBool`, `decodeInt32`, `decodeString`, `decodeBytes`).
* **The Rule:** Use the **MMKV Multi-Type Value Disambiguator** specified in Section 3.4 to cleanly unwrap inner length-prefixed strings, JSON blobs, nested Protobufs, booleans, and numbers.

### Mistake 6: Conflating the `SEGB` Record Write Timestamp with the User Activity Timestamp
* **The Trap:** Reporting the 64-bit Apple Cocoa timestamp stored in the `SEGB v1` header or `SEGB v2` trailer as the exact time the user performed the action.
* **Why It Fails:** The timestamp in the `SEGB` container structure records when the `biomed` system daemon **wrote or updated the record in the stream file** (which can happen during batch flushing or when an entry is marked deleted/zeroed). Many Biome streams store a separate **Payload Event Timestamp** inside the Protobuf record itself.
* **The Rule:** Always extract and display **both** the `segb_container_write_utc` timestamp and the `protobuf_payload_event_utc` timestamp side-by-side.

---

## 3. Sub-Engine 2.3A — Tencent `MMKV` Decoder, Append-History Tracker & Mmap Slack Carver

### 3.1 File Pair Discovery & Encryption Check (`.crc` Companion File)
Whenever a parser or the Phase 1 Unclassified Sweeper locates an `MMKV` directory (typically `/data/user/<id>/<pkg>/files/mmkv/` on Android or `<App-UUID>/Documents/mmkv/` on iOS), every `MMKV` store consists of two files:
1. **`<mmap_id>`** (e.g., `mmkv.default`, `phonepe_prefs`, `user_session_store`): The power-of-two memory-mapped data file ($4096\text{ bytes}$, $65536\text{ bytes}$, $1048576\text{ bytes}$, etc.).
2. **`<mmap_id>.crc`**: The companion metadata and integrity file ($32\text{ to }36\text{ bytes}$).

#### Step 1: Parse the Companion `<mmap_id>.crc` File First
Read the `<mmap_id>.crc` file to determine the protocol version and whether the `MMKV` file is encrypted with **AES-128-CFB**:
* **Bytes $0\text{–}3$ (`crc32_digest`, `uint32_le`):** Expected CRC-32 checksum of the active payload bytes in the main `<mmap_id>` file.
* **Bytes $4\text{–}7$ (`mmkv_version`, `uint32_le`):** Format version integer ($1, 2, 3,$ or $4$).
* **Bytes $8\text{–}11$ (`crc_actual_size`, `uint32_le`):** Duplicate record of the active payload byte length (must match Bytes $0\text{–}3$ of the main `<mmap_id>` file).
* **Bytes $12\text{–}27$ (`aes_cfb_iv`, $16\text{ bytes}$):**
  * If the app initialized `MMKV` with an encryption key (`cryptKey`), Bytes $12\text{–}27$ of the `.crc` file contain the **16-byte random AES-128-CFB Initialization Vector (IV)**!
  * How to verify if `<mmap_id>` is encrypted vs. plaintext:
    * In a **plaintext** `<mmap_id>` file, starting at Byte Offset $4$, the very first key begins with a small 1-byte length Varint (`0x01` to `0x7F`) followed immediately by printable ASCII/UTF-8 key name characters (e.g., `"user_id"`, `"vpa_list"`).
    * If the bytes starting at Offset $4$ are high-entropy non-ASCII ciphertext and Bytes $12\text{–}27$ of `.crc` are non-zero, look up the app's 16-byte `MMKV` key in **Module 2.2 (`case_cryptographic_keyring`)**, decrypt Bytes $4\text{ through }\text{EOF}$ of `<mmap_id>` using **AES-128-CFB** (Full-Block CFB128 mode) with key $K_{128}$ and `aes_cfb_iv` from Bytes $12\text{–}27$ of `.crc`, and then run the parser below!

---

### 3.2 Exact Little-Endian Base-128 Varint & ZigZag Decoding Math
Both `MMKV`, `LevelDB`, and `Protobuf` use **Little-Endian Base-128 Varints** (where the first byte holds the least significant $7\text{ bits}$):

#### 1. Unsigned 64-Bit Little-Endian Varint Decoder (`read_le_varint`)
Given byte buffer `buf` and cursor position `pos`:
1. Initialize 64-bit unsigned integer `result = 0` and bit-shift counter `shift = 0`.
2. Loop `i` from $0\text{ to }9$ (up to $10\text{ bytes}$ for a 64-bit integer):
   * Read unsigned byte `b = buf[pos + i]`.
   * Extract the lower $7\text{ bits}$ and shift them left by `shift`:
     $$\text{result} = \text{result} \mid \left( (b \ \& \ \text{0x7F}) \ll \text{shift} \right)$$
   * If the highest bit of `b` is $0$ (`(b & 0x80) == 0`):
     * Return `(result, next_pos = pos + i + 1)`.
   * Add $7$ to `shift` (`shift = shift + 7`).

#### 2. Signed ZigZag Decoder (`decode_zigzag_64`)
When negative numbers are stored as `sint32` or `sint64` in Protobuf/MMKV, they use **ZigZag encoding** (which maps $-1 \rightarrow 1$, $1 \rightarrow 2$, $-2 \rightarrow 3$, $2 \rightarrow 4$) so small negative numbers only take $1\text{ byte}$. To decode an unsigned Varint `n` via ZigZag:
$$\text{signed\_val} = (n \gg 1) \oplus -(n \ \& \ 1)$$

---

### 3.3 Step-by-Step Parsing of the 3 Forensic Layers in an `MMKV` File

Open the main `<mmap_id>` file (or its AES-128-CFB decrypted stream):

1. **Read the 4-Byte Header (Bytes $0\text{–}3$):**
   * Read `actual_size = uint32_le(buf[0 : 4])`.
   * The **Active Append Stream** runs from **Byte Offset $4$** to **Byte Offset $(4 + \text{actual\_size})$**.
   * The **Unallocated Mmap Slack Space** runs from **Byte Offset $(4 + \text{actual\_size})$** to **End-Of-File (`file_size`)**.

2. **Parse Layer 1 & Layer 2 (The Active Append Stream: Bytes $4\text{ to }4 + \text{actual\_size}$):**
   * Set cursor `pos = 4` and `append_sequence_order = 1`.
   * Create an ordered map: `key_timeline_map = {}` (mapping each `key_name` to a chronological list of all values appended for that key).
   * **While `pos < 4 + actual_size`:**
     1. Read Varint `key_len` at `pos` (advance `pos`).
     2. If `key_len == 0` or `pos + key_len > 4 + actual_size`, break or advance to slack carver.
     3. Read `key_bytes = buf[pos : pos + key_len]` and decode as UTF-8 string `key_name`. Advance `pos += key_len`.
     4. Read Varint `val_container_len` at `pos` (advance `pos`).
     5. Read `raw_val_slice = buf[pos : pos + val_container_len]`. Advance `pos += val_container_len`.
     6. Append the tuple `(append_sequence_order, byte_offset_start, val_container_len, raw_val_slice)` to `key_timeline_map[key_name]` and increment `append_sequence_order += 1`.

3. **Classify Layer 1 (Current Active) vs. Layer 2 (Historical Overwritten / Deleted Appends):**
   * For every `key_name` in `key_timeline_map`, inspect its chronological list of $K$ appended tuples:
     * **Look at the Final Tuple ($K$):**
       * If `val_container_len > 0`: This is the live active value currently seen by the app! Decode `raw_val_slice` (Section 3.4) and emit as **`ORIGINAL_RECORD`**.
       * If `val_container_len == 0`: An empty container (`0x00`) at the end of an `MMKV` key's append history is an **Explicit Key Deletion (`removeValueForKey`)**! Emit a deletion event record tagged as **`HISTORICAL_COMMITTED_RECORD (MMKV Deletion Tombstone)`**.
     * **Look at All Earlier Tuples ($1 \dots K - 1$):**
       * Every single tuple from $1\text{ to }K - 1$ is a **previous value of `key_name` that was later overwritten or deleted by the app**! Decode its `raw_val_slice` and emit every one of them as **`HISTORICAL_COMMITTED_RECORD (Superseded MMKV Append #i of K)`**!

4. **Carve Layer 3 (Unallocated Mmap Slack Space: Bytes $(4 + \text{actual\_size})\text{ to }\text{EOF}$):**
   * Set `slack_cursor = 4 + actual_size`.
   * While `slack_cursor < file_size - 3`:
     * If `buf[slack_cursor] == 0x00`, advance `slack_cursor += 1` (skip zero-fill padding).
     * Speculatively read Varint `cand_key_len` at `slack_cursor`.
     * **Strict Slack Key Sanity Check:**
       * `1 <= cand_key_len <= 256`.
       * Every byte in the candidate key slice must be a valid printable ASCII key character (`0x20 <= b <= 0x7E`, no control chars).
       * Immediately after the candidate key slice, read Varint `cand_val_len` and verify that `slack_cursor + key_varint_bytes + cand_key_len + val_varint_bytes + cand_val_len <= file_size`.
     * If the sanity check passes: Decode the key and value, emit as **`RESIDUAL_RECORD (Carved from MMKV Mmap Slack)`**, and advance `slack_cursor` to the end of the carved value. Otherwise, advance `slack_cursor += 1`.

---

### 3.4 The `MMKV` Multi-Type Value Disambiguator
Because `MMKV` does not store a data-type byte next to each value on disk, given `raw_val_slice` of length $L = \text{val\_container\_len}$, decode it using this exact priority cascade:

1. **Check 1 (Inner Length-Prefixed UTF-8 String or JSON):**
   * Read a Little-Endian Varint `inner_len` from the start of `raw_val_slice` (consuming $v\text{ bytes}$).
   * If $v + \text{inner\_len} == L$ AND the remaining $\text{inner\_len}$ bytes are $100\%$ valid printable UTF-8 text:
     * Unwrap and output the UTF-8 string (and if it starts with `{` or `[`, pretty-print/parse as JSON!).
2. **Check 2 (Inner Length-Prefixed Nested Protobuf / Byte Array):**
   * If $v + \text{inner\_len} == L$, test the remaining $\text{inner\_len}$ bytes against Sub-Engine 2.3D's **Schema-Less Protobuf Validator**. If it parses cleanly to the exact final byte with valid tags, output the decoded Protobuf JSON tree.
3. **Check 3 (Direct Raw Varint — `bool`, `int32`, `uint32`, `int64`):**
   * If $L \le 10$ and reading a single Little-Endian Varint from Byte $0$ consumes **all $L\text{ bytes}$** ($v == L$):
     * Output the integer value (if $L == 1$ and value is $0$ or $1$, display as `"0 (false / int 0)"` or `"1 (true / int 1)"`; also display ZigZag signed equivalent).
4. **Check 4 (Fixed 32-Bit Float or 64-Bit Double):**
   * If $L == 4$: Also decode as `float32_le` (IEEE-754) and `uint32_le`.
   * If $L == 8$: Also decode as `float64_le` (IEEE-754 double — check if it falls in Unix or Cocoa timestamp range!) and `uint64_le`.

---

## 4. Sub-Engine 2.3B — Google `LevelDB` & Chromium `IndexedDB` Raw Block & Tombstone Parser

Whenever a parser in Phase 4 (Crypto Wallets: MetaMask, Trust Wallet, Phantom, TronLink), Phase 5 (Discord/Messengers), or Module 2.4 (`app_webview` LocalStorage / IndexedDB) targets a LevelDB folder, Sub-Engine 2.3B scans **all** `.log` and `.ldb`/`.sst` files in that folder without invoking the standard LevelDB compaction runtime.

### 4.1 Step 1: Parse the `MANIFEST-*` File (Optional Level Metadata Audit)
* Read `CURRENT` (a 1-line text file naming the active manifest, e.g., `MANIFEST-000014`).
* `MANIFEST-xxxxxx` uses the exact same $32,768\text{-byte}$ block format as `.log` files (Section 4.2) and contains `VersionEdit` records listing which `.ldb` files belong to Level $0, 1, 2 \dots$ and which `.ldb` files were recently deleted.
* **Forensic Rule:** Even if an older `.ldb` or `.log` file in the directory is **no longer listed** in `CURRENT` / `MANIFEST`, **parse it anyway** and tag its unique records as `RESIDUAL_RECORD (Orphaned LevelDB Log/Table)`.

---

### 4.2 Step 2: Parse LevelDB Write-Ahead Log (`*.log`) Files
A LevelDB `.log` file holds the newest uncompacted writes and deletions in contiguous **$32,768\text{-byte}$ ($32\text{ KB}$) physical blocks**:

1. **Reassemble Physical Chunks Across $32\text{ KB}$ Block Boundaries:**
   * Within each $32,768\text{-byte}$ block, read sequential chunks. Each chunk starts with a **7-Byte Chunk Header**:
     * **Bytes $0\text{–}3$ (`crc32c`, `uint32_le`):** Masked CRC32C checksum of `chunk_type` + `payload`.
     * **Bytes $4\text{–}5$ (`payload_len`, `uint16_le`):** Number of payload bytes in this chunk.
     * **Byte $6$ (`chunk_type`, `uint8`):**
       * `1` (`FULL`): Complete WriteBatch record in one chunk.
       * `2` (`FIRST`): First fragment of a large record that spans across a $32\text{ KB}$ block boundary.
       * `3` (`MIDDLE`): Middle fragment(s) of a spanning record.
       * `4` (`LAST`): Final fragment of a spanning record (concatenate `FIRST + MIDDLE + LAST` payloads into a single `batch_buffer`).
     * *(Note: If fewer than $7\text{ bytes}$ remain at the end of a $32,768\text{-byte}$ block, they are zero-padding; jump directly to the next $32,768\text{-byte}$ block boundary).*

2. **Decode Each Reassembled `WriteBatch` Buffer:**
   * **Bytes $0\text{–}7$ (`base_sequence_number`, `uint64_le`):** The 64-bit monotonic sequence number of the first entry in this batch!
   * **Bytes $8\text{–}11$ (`record_count`, `uint32_le`):** Number of key-value operations in this batch.
   * Set cursor `pos = 12`. For `idx` from $0\text{ to }(\text{record\_count} - 1)$:
     * Calculate `entry_seq_num = base_sequence_number + idx`.
     * Read 1-byte `value_type = batch_buffer[pos]` (advance `pos += 1`):
       * **Case A (`value_type == 0x01` — Live Key-Value Write):**
         * Read Little-Endian Varint `key_len`, then read `user_key = batch_buffer[pos : pos + key_len]`.
         * Read Little-Endian Varint `val_len`, then read `val_bytes = batch_buffer[pos : pos + val_len]`.
         * Record `(user_key, entry_seq_num, state = LIVE_VALUE, val_bytes, source = ".log")`.
       * **Case B (`value_type == 0x00` — Key Deletion Tombstone):**
         * Read Little-Endian Varint `key_len`, then read `user_key = batch_buffer[pos : pos + key_len]`.
         * *(Note: There is NO `val_len` or `val_bytes` for a `0x00` tombstone!)*
         * Record `(user_key, entry_seq_num, state = DELETION_TOMBSTONE, val_bytes = NULL, source = ".log")`.

---

### 4.3 Step 3: Parse LevelDB Sorted String Table (`*.ldb` / `*.sst`) Files
An `.ldb` or `.sst` file contains prefix-compressed Data Blocks indexed by a Footer at the end of the file:

1. **Read the 48-Byte Footer (Final $48\text{ Bytes}$ of the `.ldb` File):**
   * Seek to `file_size - 48`.
   * **Verify Magic Number (Final $8\text{ Bytes}$, Offsets $40\text{–}47$ of Footer):** Must equal `57 FB 80 8B 24 75 47 DB` (`0xdb4775248b80fb57` in 64-bit little-endian).
   * Starting at Offset $0$ of the Footer:
     * Read `metaindex_offset` (Varint) and `metaindex_size` (Varint).
     * Read **`index_block_offset`** (Varint) and **`index_block_size`** (Varint).

2. **Helper Routine — How to Read & Decompress Any `.ldb` Block `(block_offset, block_size)`:**
   * Seek to `block_offset`. Read `block_size` raw payload bytes, followed immediately by the **5-Byte Block Trailer**:
     * **Trailer Byte $0$ (`compression_type`, `uint8`):**
       * `0x00`: **No Compression** (use raw `block_size` bytes directly).
       * `0x01`: **Google Snappy Compression** (decompress the `block_size` bytes using standard raw Snappy decompression).
       * `0x02`: **Zstandard (`Zstd`) Compression** (used in recent Chromium/Electron builds; decompress via Zstd).
     * **Trailer Bytes $1\text{–}4$ (`crc32c`, `uint32_le`).**

3. **Read the Index Block to Locate All Data Blocks:**
   * Call the Block Decompressor on `(index_block_offset, index_block_size)`.
   * Parse the entries inside the Index Block (using the Prefix-Delta reader in Step 4 below). Each entry's value inside the Index Block consists of two Little-Endian Varints: **`data_block_offset`** and **`data_block_size`**!

4. **Decode Prefix-Compressed Entries Inside Each Decompressed Data Block:**
   * Let `block_buf` be the decompressed Data Block of length $B\text{ bytes}$.
   * Read the last $4\text{ bytes}$ of `block_buf`: `num_restarts = uint32_le(block_buf[B - 4 : B])`.
   * The **Restart Point Array** occupies the $(4 \times \text{num\_restarts})\text{ bytes}$ immediately before that final 4-byte count. Therefore, the actual **Key-Value Entries** run from **Byte Offset $0$** to **Byte Offset $E_{\text{end}} = B - 4 - (4 \times \text{num\_restarts})$**!
   * Set cursor `pos = 0` and initialize `previous_internal_key = empty_byte_array`.
   * **While `pos < E_end`:**
     1. Read Varint `shared_bytes` at `pos` (how many prefix bytes this key shares with `previous_internal_key`).
     2. Read Varint `unshared_bytes` at `pos` (how many new suffix bytes follow).
     3. Read Varint `value_len` at `pos` (length of the value).
     4. Read `key_delta = block_buf[pos : pos + unshared_bytes]`. Advance `pos += unshared_bytes`.
     5. Read `value_bytes = block_buf[pos : pos + value_len]`. Advance `pos += value_len`.
     6. **Reconstruct the Full `InternalKey`:**
        $$\text{current\_internal\_key} = \text{previous\_internal\_key}[0 : \text{shared\_bytes}] \parallel \text{key\_delta}$$
        Set `previous_internal_key = current_internal_key`.
     7. **Unpack the Mandatory 8-Byte Trailer from `current_internal_key`:**
        * Let $K_{\text{len}} = \text{len}(\text{current\_internal\_key})$. (Must be $\ge 8$).
        * **`user_key`** $= \text{current\_internal\_key}[0 : K_{\text{len}} - 8]$.
        * Read the final $8\text{ bytes}$ as a 64-bit little-endian integer: `tag = uint64_le(current_internal_key[K_len - 8 : K_len])`.
        * **`sequence_number`** $= \text{tag} \gg 8$ (the upper $56\text{ bits}$).
        * **`value_type`** $= \text{tag} \ \& \ \text{0xFF}$ (the lowest $8\text{ bits}$: `0x01` = Live Value, `0x00` = Deletion Tombstone).

5. **Step 4: Reconstruct Complete Key Version History Across All `.log` and `.ldb` Files:**
   * Group all extracted records by `user_key` and sort each key's versions by `sequence_number` descending:
     * If the version with the highest `sequence_number` has `value_type == 0x01`: Tag that top version as **`ORIGINAL_RECORD`**, and tag every older version (lower `sequence_number`) as **`HISTORICAL_COMMITTED_RECORD (Superseded LevelDB Sequence #seq)`**!
     * If the version with the highest `sequence_number` has `value_type == 0x00` (a Deletion Tombstone!): The key was **deleted** by the suspect/app! Tag the tombstone and all surviving older `0x01` value versions beneath it as **`RESIDUAL_RECORD (Deleted LevelDB Key Recovered Behind Tombstone #seq)`**!

---

### 4.4 Special Handling for Chromium `Local Storage` & `IndexedDB` Keys inside LevelDB
When LevelDB is used inside Chrome or an app's `app_webview`:
* **In `Local Storage/leveldb/`:**
  * Keys starting with `_https://<domain>\x00\x01<key_name>` store the origin and variable name.
  * The 1-byte prefix on the key/value indicates text encoding: `0x00` or `0x01` = UTF-8 / Latin-1 string; `0x02` or `0x00` with 16-bit alignment = **UTF-16LE** string.
* **In `IndexedDB/<origin>.indexeddb.leveldb/`:**
  * Keys are binary tuples encoding `[DatabaseID, ObjectStoreID, IndexID, IDBKey]`.
  * Values are serialized using Chromium's **Blink / V8 `SerializedScriptValue`** wire format (starts with tag `0xFF` followed by version varint, then tag bytes: `'"'` / `'S'` / `'c'` for strings, `'I'` for 32-bit ZigZag integers, `'N'` for 64-bit IEEE-754 doubles, `'o'` / `'{'` for JS Objects, `'a'` / `'['` for Arrays). Extract all key-value properties from the V8 stream into clean JSON!

---

## 5. Sub-Engine 2.3C — Apple Biome `SEGB` (v1 & v2) Binary Stream Decoder

Apple Biome stores pattern-of-life telemetry across 84 stream directories in `/private/var/db/biome/streams/restricted/`, `/private/var/db/biome/streams/public/`, and `/private/var/mobile/Library/Biome/streams/`. Inside each stream's `local/` or `remote/<Device-UUID>/` folder sit numeric segment files (e.g., `0000000000000001`).

Sub-Engine 2.3C inspects the first $64\text{ bytes}$ of each segment file to auto-detect **`SEGB v1`** vs. **`SEGB v2`**:

### 5.1 Decoding `SEGB v1` (iOS 14 through iOS 16)
* **Magic Detection:** Bytes $52\text{–}55$ equal `53 45 47 42` (`"SEGB"` in ASCII).
* **File Header:** Occupies Bytes $0\text{–}63$ ($64\text{ bytes}$ total).
* **Forward Record Loop (Starting at Byte Offset $64$):**
  Set cursor `pos = 64`. While `pos + 32 <= file_size`:
  1. **Read the 32-Byte Record Header at `pos`:**
     * **Bytes $0\text{–}3$ (`payload_len`, `uint32_le`):** Exact byte length of the record payload. If `payload_len == 0` and remaining bytes are `0x00`, break (end of written stream).
     * **Bytes $4\text{–}7$ (`record_state`, `uint32_le`):**
       * `1` = **Active / Written** (`ORIGINAL_RECORD`).
       * `3` = **Deleted /Pruned** (`RESIDUAL_RECORD` or `PARTIAL_RECORD`).
     * **Bytes $8\text{–}15$ (`cocoa_time_1`, `float64_le`):** Apple Cocoa timestamp (seconds since `2001-01-01 00:00:00 UTC`). Convert to UTC via Module 1.2 ($\text{Unix} = \text{Cocoa} + 978307200$).
     * **Bytes $16\text{–}23$ (`cocoa_time_2`, `float64_le`):** Secondary Cocoa timestamp.
     * **Bytes $24\text{–}27$ (`crc32`, `uint32_le`):** Checksum of payload.
     * **Bytes $28\text{–}31$ (`reserved_flags`, `uint32_le`).**
  2. **Read the Payload Bytes (`buf[pos + 32 : pos + 32 + payload_len]`):**
     * Pass payload bytes to Sub-Engine 2.3D (Schema-Less Protobuf Decoder).
  3. **Advance Cursor with 8-Byte Alignment Padding:**
     $$\text{padded\_len} = \left\lceil \frac{\text{payload\_len}}{8} \right\rceil \times 8$$
     $$\text{pos} = \text{pos} + 32 + \text{padded\_len}$$

---

### 5.2 Decoding `SEGB v2` (iOS 17 through iOS 26)
In iOS 17+, Apple redesigned `SEGB` so that payloads are written **forward** from Byte Offset $32$, while record headers (trailers) are written **backward** from the very end of the file (`EOF`)!
* **Magic Detection:** Bytes $0\text{–}3$ (at the very start of the file!) equal `53 45 47 42` (`"SEGB"` in ASCII).
* **File Header:** Occupies Bytes $0\text{–}31$ ($32\text{ bytes}$ total). Payloads begin at **`data_base_offset = 32`**.
* **Step-by-Step Reverse Trailer Traversal:**
  1. Start at the very end of the file: `trailer_pos = file_size - 16`.
  2. Maintain `previous_record_end_rel = 0` and an empty list `trailer_entries = []`.
  3. **Loop Backward in $16\text{-Byte}$ Steps (`while trailer_pos >= 32`):**
     * Read the 16-byte trailer entry at `buf[trailer_pos : trailer_pos + 16]`:
       * **Bytes $0\text{–}3$ (`record_end_rel`, `uint32_le`):** The ending byte offset of this record's payload, measured **relative to `data_base_offset` ($32$)**!
       * **Bytes $4\text{–}7$ (`record_state`, `uint32_le`):** Must be `1` (Written/Active), `3` (Deleted/Zeroed), or `4` (Pruned).
       * **Bytes $8\text{–}15$ (`segb_write_cocoa_ts`, `float64_le`):** Apple Cocoa floating-point timestamp (seconds since `2001-01-01 00:00:00 UTC`).
     * **Boundary Stop Condition:** Check if `record_state` is in $\{1, 3, 4\}$, whether `record_end_rel >= previous_record_end_rel`, whether `32 + record_end_rel <= trailer_pos`, and whether `segb_write_cocoa_ts` falls within a valid year range ($2015\text{–}2035$). The instant any of these checks fails, you have hit the boundary between the forward payload zone and the reverse trailer zone—**stop the reverse loop**!
     * Calculate this record's exact payload byte range inside the file:
       * `payload_start_abs = 32 + previous_record_end_rel` (aligned to the next 4-byte boundary if padded).
       * `payload_end_abs = 32 + record_end_rel`.
     * Set `previous_record_end_rel = align_up_4(record_end_rel)` and decrement `trailer_pos -= 16`.
  4. **Decode Every Discovered `SEGB v2` Record:**
     * If `record_state == 1`: Decode the Protobuf payload at `[payload_start_abs : payload_end_abs]` and emit as **`ORIGINAL_RECORD`**.
     * If `record_state == 3` or `4`:
       * Check if `[payload_start_abs : payload_end_abs]` consists entirely of `0x00` zero bytes:
         * **If NOT all zeroes (Intact Deleted Payload!):** Decode the surviving Protobuf payload and emit as **`RESIDUAL_RECORD (SEGB Deleted State — Payload Intact)`**!
         * **If all `0x00` zeroes (Zeroed Payload):** Still emit a record containing the stream name, record index, and the surviving **`segb_write_cocoa_ts`** tagged as **`PARTIAL_RECORD (Zeroed SEGB Payload — Write Timestamp Survived)`**!

---

## 6. Sub-Engine 2.3D — Schema-Less Raw Wire-Format `Protobuf` Decoder

Because `SEGB` records, `MMKV` blobs, Android `UsageStats` files, and gRPC caches contain binary Protocol Buffers without `.proto` schema definitions, Sub-Engine 2.3D converts any raw Protobuf byte slice into a structured JSON tree and automatically flags embedded timestamps.

### 6.1 Recursive Wire-Type Disambiguation Algorithm
Given a byte slice `pb_buf` of length $N$:
1. Set `pos = 0` and `fields_dict = {}`.
2. **While `pos < N`:**
   * Read Little-Endian Varint `tag` at `pos` (advance `pos`).
   * Calculate `field_number = tag >> 3` and `wire_type = tag & 0x07`.
   * **Sanity Check:** If `field_number == 0` or `field_number > 500000` or `wire_type` is not in $\{0, 1, 2, 5\}$, this byte slice is **not** a valid Protobuf message (return `is_valid_protobuf = false`).
   * **Switch on `wire_type`:**
     * **Wire Type `0` (`VARINT`):**
       * Read Little-Endian Varint `v` (advance `pos`).
       * Store `unsigned_int = v`, `signed_zigzag = (v >> 1) ^ -(v & 1)`, and check if `v` matches a 10-digit Unix second, 13-digit Unix millisecond, or 18-digit Cocoa nanosecond timestamp!
     * **Wire Type `1` (`64-BIT FIXED`):**
       * Read $8\text{ bytes}$ as both `uint64_le` and `float64_le` (IEEE-754 double). Advance `pos += 8`.
       * **Automatic Cocoa / Unix Float Timestamp Check:** If `float64_le` is between $400,000,000.0$ and $1,200,000,000.0$ (Apple Cocoa seconds between 2013 and 2039), automatically annotate the JSON field with its converted UTC ISO-8601 timestamp (`_inferred_cocoa_utc`)! If `float64_le` is between $1,400,000,000.0$ and $2,200,000,000.0$, annotate with `_inferred_unix_utc`!
     * **Wire Type `2` (`LENGTH-DELIMITED`):**
       * Read Little-Endian Varint `sub_len` (advance `pos`). If `pos + sub_len > N`, return `is_valid_protobuf = false`.
       * Extract `sub_slice = pb_buf[pos : pos + sub_len]`. Advance `pos += sub_len`.
       * **3-Way Disambiguation for `sub_slice`:**
         1. If `sub_len > 0` and `sub_slice` passes a recursive call to this exact Protobuf decoder (consuming $100\%$ of `sub_len` bytes with valid tags): Store as a **Nested Protobuf Object**.
         2. Else if `sub_slice` is $100\%$ valid printable UTF-8 text: Store as a **UTF-8 String**.
         3. Else: Store as a **Hex / Base64 Byte Array**.
     * **Wire Type `5` (`32-BIT FIXED`):**
       * Read $4\text{ bytes}$ as `uint32_le` and `float32_le`. Advance `pos += 4`.

---

## 7. Database Schema for Module 2.3 (`nonsqlite_forensic_engine.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `kv_store_diagnostics` (Per-File / Per-Folder Profile for `MMKV`, `LevelDB`, `SEGB`)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `kv_store_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each processed non-SQLite store. |
| `vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `vfs_index.file_id` (Module 1.1). |
| `app_instance_id` | `INTEGER` | `NULL` | Foreign key to owning application in Module 1.3 (`resolved_application_catalog`). |
| `canonical_path` | `TEXT` | `NOT NULL` | Normalized device path (e.g., `/data/user/0/com.phonepe.app/files/mmkv/mmkv.default`). |
| `engine_format` | `TEXT` | `NOT NULL` | Enum: `TENCENT_MMKV`, `GOOGLE_LEVELDB`, `CHROMIUM_INDEXEDDB`, `APPLE_SEGB_V1`, `APPLE_SEGB_V2`, `RAW_PROTOBUF_FILE`. |
| `is_encrypted` | `INTEGER` | `DEFAULT 0` | `1` if MMKV `.crc` AES-128-CFB encryption was detected and unwrapped. |
| `active_records_count` | `INTEGER` | `DEFAULT 0` | Count of `ORIGINAL_RECORD` active entries extracted. |
| `historical_superseded_count` | `INTEGER` | `DEFAULT 0` | Count of `HISTORICAL_COMMITTED_RECORD` entries (overwritten MMKV appends or older LevelDB sequence numbers). |
| `residual_deleted_count` | `INTEGER` | `DEFAULT 0` | Count of `RESIDUAL_RECORD` / `PARTIAL_RECORD` entries (MMKV slack space, LevelDB `0x00` tombstones, SEGB `state=3` records). |

### Table 2: `kv_recovered_records_master` (Unified `MMKV` & `LevelDB`/`IndexedDB` Record Store)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `kv_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Global unique row ID. |
| `kv_store_id` | `INTEGER` | `NOT NULL` | Foreign key to `kv_store_diagnostics.kv_store_id`. |
| `key_name_text` | `TEXT` | `NOT NULL` | Decoded UTF-8 key name (with LevelDB's 8-byte trailer stripped). |
| `sequence_or_append_order` | `INTEGER` | `NOT NULL` | LevelDB 56-bit `sequence_number` or MMKV 1-based `append_sequence_order`. |
| `value_operation_type` | `TEXT` | `NOT NULL` | Enum: `LIVE_VALUE`, `SUPERSEDED_OVERWRITTEN_VALUE`, `EXPLICIT_DELETION_TOMBSTONE`, `CARVED_SLACK_VALUE`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum: `ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, `PARTIAL_RECORD`, etc. |
| `inferred_data_type` | `TEXT` | `NOT NULL` | Enum: `UTF8_STRING`, `JSON_OBJECT`, `NESTED_PROTOBUF`, `VARINT_INTEGER`, `FLOAT_DOUBLE`, `V8_SERIALIZED_OBJECT`, `RAW_BYTES_HEX`, `TOMBSTONE_NULL`. |
| `decoded_value_text_or_json` | `TEXT` | `NULL` | Human-readable decoded string, pretty-printed JSON, or decoded Protobuf tree. |
| `source_file_name` | `TEXT` | `NOT NULL` | Specific file inside the store (e.g., `000005.ldb`, `000007.log`, `mmkv.default`). |
| `source_byte_offset` | `INTEGER` | `NOT NULL` | Exact byte offset where this key-value record starts (for Phase 8 Hex Viewer linkage). |

### Table 3: `biome_segb_records_master` (Apple Biome `SEGB v1` & `v2` Stream Store)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `segb_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Global unique row ID. |
| `kv_store_id` | `INTEGER` | `NOT NULL` | Foreign key to `kv_store_diagnostics.kv_store_id`. |
| `biome_stream_name` | `TEXT` | `NOT NULL` | Canonical Biome stream name (e.g., `App.InFocus`, `Location.Semantic`, `UserFocus.ComputedMode`). |
| `segb_version` | `TEXT` | `NOT NULL` | Enum: `SEGB_V1`, `SEGB_V2`. |
| `device_locality` | `TEXT` | `NOT NULL` | `LOCAL_DEVICE` (from `local/`) or `REMOTE_SYNCED_DEVICE:<UUID>` (from `remote/<UUID>/`). |
| `segb_record_state` | `INTEGER` | `NOT NULL` | Raw state integer (`1` = Active/Written, `3` = Deleted/Zeroed, `4` = Pruned). |
| `recovery_classification` | `TEXT` | `NOT NULL` | `ORIGINAL_RECORD` (state 1), `RESIDUAL_RECORD` (state 3 with intact payload), or `PARTIAL_RECORD` (state 3 zeroed payload). |
| `segb_write_cocoa_raw` | `REAL` | `NOT NULL` | Raw 64-bit float Cocoa write timestamp from SEGB header/trailer. |
| `segb_write_utc_iso` | `TEXT` | `NOT NULL` | Converted UTC ISO-8601 timestamp when `biomed` wrote/updated the SEGB record. |
| `payload_event_utc_iso` | `TEXT` | `NULL` | Converted UTC ISO-8601 timestamp of the actual user activity extracted from inside the Protobuf payload (if distinct from `segb_write_utc_iso`). |
| `decoded_protobuf_json` | `TEXT` | `NULL` | Decoded Protobuf payload JSON (`NULL` if payload bytes were zero-filled). |
| `payload_byte_offset` | `INTEGER` | `NOT NULL` | Absolute byte offset of the payload in the segment file. |

---

## 8. Developer Acceptance Test Checklist for Module 2.3

1. **The `MMKV` 3-Layer Append & Slack Carving Test:** Construct a test `mmkv.default` file ($4096\text{ bytes}$) where key `"active_upi_vpa"` is appended three times (`"suspect1@ybl"`, then `"mule_account@okaxis"`, then deleted with a 0-length value `val_len = 0`), and place an older key `"jwt_auth_token"` at Byte Offset $2048$ (past `actual_size`). Run Sub-Engine 2.3A and verify that:
   * The deletion tombstone (`val_len = 0`) and both earlier VPAs (`"suspect1@ybl"` and `"mule_account@okaxis"`) are recovered as `HISTORICAL_COMMITTED_RECORD`.
   * `"jwt_auth_token"` past `actual_size` is recovered as `RESIDUAL_RECORD (Carved from MMKV Mmap Slack)`.
2. **The `LevelDB` 8-Byte Trailer & Tombstone Recovery Test:** Load a LevelDB directory containing an `.ldb` file (with Snappy compression `0x01`) and a `.log` file where key `"metamask_vault"` was written at `sequence_number = 100`, updated at `sequence_number = 205`, and deleted (`value_type = 0x00`) at `sequence_number = 310`. Verify that Sub-Engine 2.3B strips the 8-byte trailer from every `.ldb` key, decompresses Snappy blocks, and recovers both `seq = 100` and `seq = 205` behind the `seq = 310` deletion tombstone!
3. **The `SEGB v2` Reverse Trailer & Zeroed-Payload Test:** Feed an iOS 18/26 `SEGB v2` file (magic `"SEGB"` at Byte $0$) containing 20 active records (`state = 1`), 5 deleted records (`state = 3`) with intact Protobuf bytes, and 5 deleted records (`state = 3`) whose payload bytes were zeroed (`0x00`). Verify that Sub-Engine 2.3C walks the 16-byte reverse trailer from `EOF`, decodes all 25 intact Protobuf payloads, and logs the 5 zeroed records as `PARTIAL_RECORD` with their surviving Cocoa write timestamps.