# Engineering Specification: Phase 2, Module 2.1 — Forensic SQLite Engine, Shared `-wal` Historical Frame Reader, Rollback `-journal` Decoder & B-Tree Residual Carver

**Document Purpose:** This document provides the complete, byte-level architectural blueprint for building **Module 2.1** of the Forensic Data Parser. It contains **zero programming code** and explains every binary structure, byte offset, mathematical formula, and state machine from first principles so that a developer with no prior forensic background can build a commercial-grade SQLite recovery engine that extracts active tables, historical edited states, uncommitted transactions, and deleted records.

---

## 1. Purpose & Mental Model (Why Standard SQLite Drivers Lose Critical Evidence)

Over $80\%$ of structured user evidence on iOS and Android—including `sms.db`, WhatsApp `msgstore.db` / `ChatStorage.sqlite`, Signal `Signal.sqlite`, Telegram `cache4.db`, Google Messages `bugle_db`, `Photos.sqlite`, `knowledgeC.db`, `accounts3.sqlite`, and Indian UPI/banking databases—is stored in **SQLite 3**.

When a regular software developer is asked to extract data from a SQLite file, they open the file with a standard SQLite driver (such as `sqlite3` in Python/C/Rust or JDBC) and run `SELECT * FROM messages;`. **In digital forensics, relying only on a standard SQLite driver loses up to $40\%$ of the recoverable evidence for four reasons:**

1. **Standard SQLite Shows Only the Final State of the Database:** If a suspect received an incriminating UPI transfer message at 9:00 PM, edited the message at 9:05 PM, and deleted the message at 9:10 PM, a standard `SELECT` query returns nothing. Yet the 9:00 PM original row and the 9:05 PM edited row are often sitting completely intact inside earlier frames of the Write-Ahead Log (`-wal`).
2. **Standard SQLite Automatically Checkpoints and Alters the Evidence on Open:** When a standard SQLite library opens `sms.db` while `sms.db-wal` is in the same folder, SQLite merges the newest frames from `-wal` into `.db` and updates the `.db` header. If you did not parse the raw `-wal` frames *before* letting SQLite open the file, you risk overwriting or losing track of historical page states.
3. **Standard SQLite Ignores Deleted Rows in Freeblocks and Unallocated Space:** When a row is deleted from a SQLite table (and `secure_delete` is disabled or bypassed), SQLite does not erase the text or numbers of that row. It simply removes the 2-byte pointer to that row from the page's directory and marks those bytes as reusable space.
4. **Standard SQLite Aborts on Minor Page Corruption:** If a phone loses power during seizure or a file carved from physical storage has a single corrupted page, a standard SQLite driver throws `SQLITE_CORRUPT (database disk image is malformed)` and refuses to read the remaining $99.9\%$ of intact pages. A forensic B-tree parser walks pages independently and recovers every intact page even when the database header or interior tree is damaged.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in SQLite Forensics

Before implementing Module 2.1, the developer must understand six classic traps that break amateur SQLite carvers:

### Mistake 1: Forgetting the 100-Byte Header Offset on Page 1
* **The Trap:** Assuming every page in a SQLite file starts with a B-Tree Page Header at Byte Offset $0$ of that page.
* **Why It Fails:** Pages $2, 3, \dots, N$ start their B-Tree Page Header at Byte Offset $0$ of the page. However, **Page 1 is special**: Bytes $0\text{ through }99$ of Page 1 contain the **100-Byte Database File Header**. Therefore, on Page 1 (which holds the root of `sqlite_master` / `sqlite_schema`), the B-Tree Page Header starts at **Byte Offset $100$**, even though all cell pointers inside Page 1 are still measured relative to Byte Offset $0$ of Page 1!
* **The Rule:** Whenever your B-Tree parser reads Page 1 (whether from the main `.db` file or from a `-wal` frame where `page_number == 1`), set `btree_header_offset = 100`. For every other page (`page_number >= 2`), set `btree_header_offset = 0`.

### Mistake 2: Missing the `65,536-Byte` Page Size Edge Case
* **The Trap:** Reading the 2-byte `page_size` integer at Bytes $16\text{–}17$ of the SQLite header and using that integer directly as the page size.
* **Why It Fails:** The maximum number a 16-bit unsigned integer (`uint16_be`) can hold is $65,535$ (`0xFFFF`). Because SQLite supports a maximum page size of $65,536\text{ bytes}$ ($2^{16}$), SQLite stores the value **`1` (`0x0001`)** at Bytes $16\text{–}17$ to represent $65,536\text{ bytes}$!
* **The Rule:** If the `uint16_be` value at Bytes $16\text{–}17$ equals $1$, set `page_size = 65536`.

### Mistake 3: Misreading the 9th Byte of a 64-Bit SQLite Varint
* **The Trap:** Writing a standard Base-128 Varint loop that takes only $7\text{ bits}$ (`byte & 0x7F`) from every byte, including the 9th byte.
* **Why It Fails:** In SQLite's custom Varint format (used for `ROWID`s and 64-bit timestamps), a Varint is at most **9 bytes long**. Bytes $1\text{ through }8$ contribute $7\text{ bits}$ each ($8 \times 7 = 56\text{ bits}$). To fit a full 64-bit integer ($56 + 8 = 64\text{ bits}$), **the 9th byte contributes all $8\text{ bits}$ (`byte & 0xFF`)** and has no continuation flag! If your loop masks the 9th byte with `0x7F`, every negative integer and large 64-bit `ROWID` will be corrupted.
* **The Rule:** Use the exact 9-byte SQLite Varint algorithm specified in Section 5.1.

### Mistake 4: Failing to Reassemble Overflow Pages for Long Messages
* **The Trap:** Assuming the entire row payload sits contiguously inside the `0x0D` Table Leaf Page.
* **Why It Fails:** If a row (such as a long WhatsApp message, a base64 thumbnail, an iOS Note protobuf, or a PhonePe JSON payload) is larger than the page's **Maximum Local Payload ($X$)**, SQLite stores only the first $K\text{ bytes}$ on the `0x0D` Leaf Page, followed by a 4-byte `uint32_be` page number pointing to the first **Overflow Page**.
* **The Rule:** Always calculate the exact local payload size $K$ using the official SQLite overflow math (Section 5.2) and follow the 4-byte Overflow Page chain before decoding the columns.

### Mistake 5: Confusing Pointer-Map (`ptrmap`) Pages with B-Tree Pages
* **The Trap:** Scanning every page in a `.db` file expecting Byte $0$ to be a B-Tree flag (`0x0D`, `0x05`, `0x0A`, `0x02`).
* **Why It Fails:** Many mobile databases enable **Auto-Vacuum** or **Incremental Vacuum** (indicated by a non-zero integer at Header Bytes $52\text{–}55$). When Auto-Vacuum is enabled, **Page 2** (and periodic pages thereafter) is a **Pointer-Map (`ptrmap`) Page**, not a B-Tree page!
* **The Rule:** Never treat a `ptrmap` page as a B-Tree page. Instead, read the `ptrmap` entries (Section 4.3) because they tell you the exact parent page of every page in the database—which helps you attribute orphaned pages back to their parent table!

### Mistake 6: Failing to Recover Freeblock Cells Whose First 4 Bytes Were Overwritten
* **The Trap:** Jumping to `first_freeblock_offset` inside a `0x0D` page and trying to read `payload_length` and `row_id` Varints starting at Byte $0$ of the freeblock.
* **Why It Fails:** When SQLite deletes a cell and turns it into a Freeblock, SQLite **overwrites the first $4\text{ bytes}$ of that deleted cell** with a 2-byte `next_freeblock_offset` (`uint16_be`) and a 2-byte `freeblock_size` (`uint16_be`)! Those first $4\text{ bytes}$ used to hold the deleted cell's `payload_length` Varint, `row_id` Varint, and sometimes the `header_length` Varint.
* **The Rule:** Your Freeblock carver must skip the 4-byte Freeblock header and use **Reverse Serial-Type Alignment** (Section 8.1) to recover the intact column values starting from Byte $4$ of the freeblock.

---

## 3. Step 1 — Parsing the 100-Byte SQLite Database Header (Page 1, Bytes $0\text{–}99$)

When Module 2.1 receives a staged SQLite family from Module 1.1 (`target.db`, `target.db-wal`, `target.db-journal`), it first reads the $100\text{-byte}$ header at the start of `target.db` (or from the latest `page_number == 1` frame inside `target.db-wal` if `target.db` is $0\text{ bytes}$ or truncated!).

| Byte Offset (Inclusive) | Size (Bytes) | Field Name | Integer Endianness | Forensic Meaning & Exact Validation Logic |
|---|---|---|---|---|
| $0\text{–}15$ | $16$ | `header_magic` | ASCII | Must equal `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` (`"SQLite format 3\0"`). If it does not match, route to **Module 2.2 (Key Broker)** to check for SQLCipher/WCDB encryption. |
| $16\text{–}17$ | $2$ | `raw_page_size` | `uint16_be` | Must be a power of two between $512$ and $32768$, OR **`1` (which represents $65,536\text{ bytes}$)**. |
| $18$ | $1$ | `write_version` | `uint8` | `1` = Legacy Rollback Journal; `2` = **Write-Ahead Log (`WAL`) mode**. |
| $19$ | $1$ | `read_version` | `uint8` | `1` = Legacy; `2` = **WAL mode**. |
| $20$ | $1$ | `reserved_bytes_per_page` | `uint8` | Number of unused bytes reserved at the very end of every page (usually `0`, but encrypted/checksummed DBs set this to $16\text{–}48$). **Usable Page Size** $U = \text{page\_size} - \text{reserved\_bytes\_per\_page}$. |
| $21\text{–}23$ | $3$ | `payload_fractions` | `uint8[3]` | Must equal `40 20 20` ($64, 32, 32$). |
| $24\text{–}27$ | $4$ | `file_change_counter` | `uint32_be` | Incremented every time the `.db` file is modified directly. |
| $28\text{–}31$ | $4$ | `in_header_db_size_pages` | `uint32_be` | Official count of active pages in the `.db` file. *(Forensic Tip: If the physical file size on disk divided by `page_size` is **larger** than `in_header_db_size_pages`, the extra pages at the end of the file are **Post-EOF Residual Pages** left over from a truncated/shrunk database—carve them!)* |
| $32\text{–}35$ | $4$ | `first_freelist_trunk_page` | `uint32_be` | 1-based page number of the first Freelist Trunk Page (`0` if no freelist pages exist). |
| $36\text{–}39$ | $4$ | `total_freelist_pages` | `uint32_be` | Total number of deleted/free pages tracked in the Freelist. |
| $40\text{–}43$ | $4$ | `schema_cookie` | `uint32_be` | Incremented whenever `CREATE TABLE`, `ALTER TABLE`, or `DROP TABLE` runs. |
| $44\text{–}47$ | $4$ | `schema_format_number` | `uint32_be` | Usually `4`. |
| $52\text{–}55$ | $4$ | `largest_root_btree_page` | `uint32_be` | **Crucial:** If $> 0$, this database uses **Auto-Vacuum** or **Incremental Vacuum**, which means **Pointer-Map (`ptrmap`) pages** exist in the file (see Section 4.3)! |
| $56\text{–}59$ | $4$ | `text_encoding` | `uint32_be` | **`1` = UTF-8**; **`2` = UTF-16LE** (Little-Endian); **`3` = UTF-16BE** (Big-Endian). All `TEXT` serial types in this database must be decoded using this encoding! |
| $64\text{–}67$ | $4$ | `incremental_vacuum_mode` | `uint32_be` | `0` = Full Auto-Vacuum (if offset $52 > 0$); Non-zero = Incremental Vacuum. |
| $68\text{–}71$ | $4$ | `application_id` | `uint32_be` | Custom magic integer set by some apps via `PRAGMA application_id`. |
| $92\text{–}95$ | $4$ | `version_valid_for` | `uint32_be` | Matches `file_change_counter` of last write. |
| $96\text{–}99$ | $4$ | `sqlite_version_number` | `uint32_be` | Version of SQLite that last wrote to this DB (e.g., `3043002` = SQLite 3.43.2). |

### Check for `PRAGMA secure_delete` Behavior
While `secure_delete` is a runtime pragma rather than a header flag, your carver can automatically detect whether an app had `secure_delete` enabled by inspecting Freeblocks and Unallocated Gaps: if Freeblocks contain all `0x00` zero bytes (or `0x00` with occasional schema remnants), log a diagnostic note in Module 1.4 (`"App utilizes SQLite secure_delete=ON; in-page deleted cells zeroed, prioritizing WAL historical frame recovery"`).

---

## 4. Step 2 — Building the Schema Catalog & Page-to-Table Ownership Map

When you carve a deleted record from Page $842$ of `msgstore.db` or decode WAL Frame $19$ (which updates Page $842$), **how do you know which table Page $842$ belongs to?** You must build a **Page-to-Table Ownership Map** before running the WAL reader or carver.

### 4.1 Parsing `sqlite_schema` (`sqlite_master`) from Page 1
Page 1 (starting at Byte Offset $100$) is always the root B-Tree page of the schema table `sqlite_schema` (historically called `sqlite_master`). Every row in `sqlite_schema` has exactly $5\text{ columns}$:
1. `type` (`TEXT`): `"table"`, `"index"`, `"view"`, or `"trigger"`.
2. `name` (`TEXT`): Name of the object (e.g., `"messages"`).
3. `tbl_name` (`TEXT`): Name of the table the object belongs to.
4. `rootpage` (`INTEGER`): The 1-based page number where the B-Tree for this table or index begins!
5. `sql` (`TEXT`): The exact `CREATE TABLE ...` or `CREATE INDEX ...` DDL statement.

#### Extracting the Schema Fingerprint for Every Table
For every row where `type == "table"`:
1. Parse the `CREATE TABLE` SQL string to extract the ordered list of **Column Names**, **Declared Data Types** (affinity: `INTEGER`, `TEXT`, `BLOB`, `REAL`, `NUMERIC`), **`NOT NULL` constraints**, and whether a column is declared as **`INTEGER PRIMARY KEY`** (which means that column is an alias for the cell's `row_id` Varint, and its value inside the cell payload serial type array will always be `NULL` [Serial Type $0$]!).
2. Check if the `CREATE TABLE` statement ends with `WITHOUT ROWID`:
   * Standard tables (`WITHOUT ROWID == false`) use `0x05` (Interior) and `0x0D` (Leaf) Table B-Tree pages.
   * `WITHOUT ROWID` tables store their rows inside `0x02` (Interior) and `0x0A` (Leaf) Index B-Tree pages!

### 4.2 Walking the B-Tree from `rootpage` to Map Active Pages
For each table's `rootpage`:
1. Record `page_owner_map[rootpage] = table_name`.
2. Read the page at `rootpage`:
   * If the page is a **Table Leaf Page (`0x0D`)**: Stop; it has no child B-tree pages.
   * If the page is a **Table Interior Page (`0x05`)**:
     * Its B-Tree header is **$12\text{ bytes}$ long** (Bytes $0\text{–}7$ are the same as a leaf page, plus **Bytes $8\text{–}11$ (`right_most_child_page`, `uint32_be`)**).
     * Each cell inside a `0x05` Interior Page consists simply of a **4-byte `left_child_page_number` (`uint32_be`)** followed by an integer key Varint.
     * Collect all `left_child_page_number` values plus the `right_most_child_page`, assign all of them to `table_name` in `page_owner_map`, and recursively visit any child page that is also `0x05`!
3. **Important:** Perform this same B-tree walk using the *latest committed pages in the `-wal` file* overlaid on top of `.db` so that newly allocated pages that exist only inside the `-wal` are also mapped to their owning table!

### 4.3 Reading Pointer-Map (`ptrmap`) Pages (When `largest_root_btree_page > 0`)
If `largest_root_btree_page` (Header Bytes $52\text{–}55$) is $> 0$, the database uses Auto-Vacuum and contains **Pointer-Map (`ptrmap`) pages**:
* **Which pages are `ptrmap` pages?**
  * Let $U = \text{page\_size} - \text{reserved\_bytes\_per\_page}$ be the usable page size.
  * Each `ptrmap` entry is exactly **$5\text{ bytes}$** long, so a single `ptrmap` page tracks $J = \lfloor U / 5 \rfloor$ subsequent pages.
  * The **first `ptrmap` page is always Page 2**.
  * Every subsequent `ptrmap` page sits at page number:
    $$\text{ptrmap\_page}_k = 2 + k \times (J + 1) \quad \text{for } k = 0, 1, 2, \dots$$
* **How to read a 5-byte `ptrmap` entry:**
  * **Byte $0$ (`page_role_type`):**
    * `1` = Root B-Tree page (`parent_page == 0`)
    * `2` = Freelist page (`parent_page == 0`)
    * `3` = First Overflow page of a cell (`parent_page` = the `0x0D` B-Tree page that owns the cell!)
    * `4` = Subsequent Overflow page in a chain (`parent_page` = previous overflow page)
    * `5` = Non-root B-Tree page (`parent_page` = the `0x05` Interior B-Tree page that points to this page!)
  * **Bytes $1\text{–}4$ (`parent_page_number`, `uint32_be`):** By tracing `parent_page_number` upward to a `rootpage`, you immediately know which table owns any page or overflow chain!

---

## 5. Step 3 — Exact Cell, Varint, Overflow & Serial-Type Decoding Math

Every active row, WAL row, or carved deleted row is decoded using the following three mathematical routines.

### 5.1 The Exact 9-Byte SQLite Varint Decoder
Given a byte buffer `buf` and a starting offset `pos`:
1. Initialize a 64-bit unsigned integer `result = 0`.
2. Loop `i` from $0\text{ to }7$ (the first $8\text{ bytes}$):
   * Read unsigned byte `b = buf[pos + i]`.
   * Shift `result` left by $7\text{ bits}$ and bitwise-OR the lower $7\text{ bits}$ of `b`:
     $$\text{result} = (\text{result} \ll 7) \mid (b \ \& \ \text{0x7F})$$
   * If the highest bit of `b` is $0$ (`(b & 0x80) == 0`):
     * Return `(signed_int64(result), bytes_consumed = i + 1)`.
3. **If the loop reaches the 9th byte (`i == 8`):**
   * Read unsigned byte `b = buf[pos + 8]`.
   * Shift `result` left by **$8\text{ bits}$** and bitwise-OR **all $8\text{ bits}$** of `b`:
     $$\text{result} = (\text{result} \ll 8) \mid b$$
   * Return `(signed_int64(result), bytes_consumed = 9)`.

### 5.2 Exact Local Payload vs. Overflow Page Calculation ($U, P, X, M, K$)
When you read a cell inside a `0x0D` Table Leaf Page:
1. Read Varint 1: `P` (`total_payload_bytes`).
2. Read Varint 2: `row_id` (64-bit signed integer).
3. Calculate the **Maximum Local Payload ($X$)** and **Minimum Local Payload ($M$)** for a Table B-Tree Leaf Page, where $U = \text{page\_size} - \text{reserved\_bytes\_per\_page}$:
   $$X = U - 35$$
   $$M = \left\lfloor \frac{(U - 12) \times 32}{255} \right\rfloor - 23$$
4. Determine how many payload bytes (`local_bytes`) live on the current page:
   * **Case A ($P \le X$):** The **entire payload** fits on this page (`local_bytes = P`), and there is **no** overflow page pointer!
   * **Case B ($P > X$):** The payload spills onto one or more **Overflow Pages**! Calculate $K$:
     $$K = M + \left( (P - M) \bmod (U - 4) \right)$$
     * If $K \le X$, then `local_bytes = K`.
     * If $K > X$, then `local_bytes = M`.
5. **Reassembling the Overflow Chain (when $P > X$):**
   * Read the first `local_bytes` from the current cell into your `full_payload_buffer`.
   * Immediately after those `local_bytes` (still on the `0x0D` page), read a 4-byte big-endian unsigned integer (`uint32_be`): **`next_overflow_page_number`**.
   * While `bytes_remaining = P - len(full_payload_buffer) > 0` and `next_overflow_page_number != 0`:
     * Seek to `next_overflow_page_number` (checking if an updated copy of that page exists in the same `-wal` transaction first!).
     * On an Overflow Page, **Bytes $0\text{–}3$ (`uint32_be`)** are the page number of the *next* Overflow Page in the chain (or `0` if this is the final overflow page).
     * **Bytes $4\text{ through } U - 1$** contain up to $(U - 4)\text{ bytes}$ of payload data. Append $\min(\text{bytes\_remaining}, U - 4)$ bytes to `full_payload_buffer`.
     * Set `next_overflow_page_number` to the integer read from Bytes $0\text{–}3$.

### 5.3 Decoding the Assembled `full_payload_buffer` into Columns
Once `full_payload_buffer` (of length $P$) is assembled:
1. Starting at Offset $0$ of `full_payload_buffer`, read a Varint: `header_size` (which is the total byte length of the record header, including the `header_size` Varint itself).
2. Read sequential **Serial Type Varints** ($T_1, T_2, \dots, T_m$) until your cursor reaches Byte Offset `header_size`.
3. Set `data_cursor = header_size`.
4. For each column $j = 1 \dots m$, read the value starting at `data_cursor` according to $T_j$:
   * $T_j == 0$: Value is `NULL` ($0\text{ bytes}$). *(Note: If column $j$ is the table's `INTEGER PRIMARY KEY` column, substitute the cell's `row_id` here!)*
   * $T_j == 1$: 1-byte signed integer (`int8`). Advance `data_cursor` by $1$.
   * $T_j == 2$: 2-byte big-endian signed integer (`int16_be`). Advance by $2$.
   * $T_j == 3$: 3-byte big-endian signed integer (`int24_be`: sign-extend bit 23). Advance by $3$.
   * $T_j == 4$: 4-byte big-endian signed integer (`int32_be`). Advance by $4$.
   * $T_j == 5$: 6-byte big-endian signed integer (`int48_be`: sign-extend bit 47). Advance by $6$.
   * $T_j == 6$: 8-byte big-endian signed integer (`int64_be`). Advance by $8$.
   * $T_j == 7$: 8-byte IEEE-754 big-endian floating-point (`float64_be`). Advance by $8$.
   * $T_j == 8$: Integer constant `0` ($0\text{ bytes}$).
   * $T_j == 9$: Integer constant `1` ($0\text{ bytes}$).
   * $T_j \ge 12$ and **Even**: Raw `BLOB` of byte length $L = (T_j - 12) / 2$. Advance `data_cursor` by $L$.
   * $T_j \ge 13$ and **Odd**: `TEXT` string of byte length $L = (T_j - 13) / 2$. Decode those $L\text{ bytes}$ using the database's `text_encoding` (UTF-8, UTF-16LE, or UTF-16BE). Advance `data_cursor` by $L$.

---

## 6. Step 4 — Pipeline B1: The Shared `-wal` Historical & Uncommitted Frame Engine

This is the engine that replicates and expands upon the 2026 LEAPP Shared WAL Reader capability. When `target.db-wal` exists and its size is $> 32\text{ bytes}$, execute the following 4-stage pipeline on the raw `Product B1` `-wal` file.

### 6.1 Stage 1: Parse & Verify the 32-Byte WAL Header
Read Bytes $0\text{–}31$ of `target.db-wal`:
* **Bytes $0\text{–}3$ (`wal_magic`, `uint32_be`):**
  * If `0x377F0682`: Checksums use **32-bit Little-Endian** words.
  * If `0x377F0683`: Checksums use **32-bit Big-Endian** words.
* **Bytes $8\text{–}11$ (`wal_page_size`, `uint32_be`):** Must match the `.db` page size.
* **Bytes $12\text{–}15$ (`checkpoint_seq`, `uint32_be`):** Current checkpoint generation counter.
* **Bytes $16\text{–}19$ (`header_salt_1`, `uint32_be`) & Bytes $20\text{–}23$ (`header_salt_2`, `uint32_be`):** The active salt pair for the current checkpoint cycle.
* **Bytes $24\text{–}27$ (`hdr_s0`, `uint32_be`) & Bytes $28\text{–}31$ (`hdr_s1`, `uint32_be`):** Initial cumulative checksum seed calculated over Bytes $0\text{–}23$.

### 6.2 Stage 2: Exact WAL Cumulative Checksum Math (To Classify Frame State)
Why calculate the WAL checksum? Because when SQLite checkpoints a WAL file and starts writing new frames from the beginning of the `-wal` file, **old frames from the previous checkpoint cycle remain sitting in the second half of the `-wal` file!** By checking `salt_1`/`salt_2` and the cumulative checksum `(s0, s1)`:
* **How SQLite Computes `(s0, s1)` Over a Byte Buffer of 8-Byte Chunks:**
  * Given input seed `(s0, s1)`, process the buffer in steps of $8\text{ bytes}$ (two 32-bit unsigned integers `x0` and `x1`, decoded as Little-Endian if `wal_magic == 0x377F0682` or Big-Endian if `0x377F0683`):
    $$s_0 = (s_0 + x_0 + s_1) \bmod 2^{32}$$
    $$s_1 = (s_1 + x_1 + s_0) \bmod 2^{32}$$
  * For Frame $i$, start with the `(s0, s1)` from Frame $i - 1$ (or from the WAL Header for Frame $1$). First feed **Bytes $0\text{–}7$ of the 24-Byte Frame Header** into the formula, and then feed **all `page_size` bytes of the Frame Payload** into the formula.
  * If the resulting `(s0, s1)` equals Bytes $16\text{–}23$ of the Frame Header AND `frame_salt_1 == header_salt_1` AND `frame_salt_2 == header_salt_2`: The frame is part of the **Active Continuous WAL Chain**.
  * Once the cumulative checksum breaks or `frame_salt_1 != header_salt_1` (which happens at the point where the current WAL write cursor stopped): **Do NOT stop reading the `-wal` file!** Every frame after that point up to `EOF` is a **Pre-Checkpoint Residual WAL Frame** from an earlier database state!

### 6.3 Stage 3: Classify Every WAL Frame into 4 Forensic States
As you walk Frame $1, 2, \dots, N$ (where Frame $i$ starts at byte offset $32 + (i - 1) \times (24 + \text{page\_size})$):

1. Group consecutive frames in the Active Continuous WAL Chain by looking for **Commit Frames** (frames where Bytes $4\text{–}7$ `db_size_after_commit > 0`):
   * **State 1 (`LATEST_COMMITTED_WAL_FRAME`):** For each `page_number`, the *last* frame in the Active Continuous WAL Chain that is at or before the final Commit Frame. (This is the state standard SQLite sees).
   * **State 2 (`HISTORICAL_SUPERSEDED_COMMITTED_FRAME`):** Any frame for that same `page_number` that was part of an *earlier* committed transaction in the WAL, but was later overwritten by a newer frame for that same `page_number`! *(This is where edited and recently deleted messages live!)*
   * **State 3 (`UNCOMMITTED_IN_FLIGHT_WAL_FRAME`):** Frames in the Active Continuous WAL Chain that appear *after* the final Commit Frame (a transaction that was in progress when the phone lost power or was imaged).
   * **State 4 (`PRIOR_CHECKPOINT_RESIDUAL_WAL_FRAME`):** Frames located past the active WAL chain where `frame_salt_1 != header_salt_1`, representing surviving pages from the previous checkpoint generation.

### 6.4 Stage 4: Reconstructing Row Edit & Deletion History Across WAL Frames
For every `0x0D` Table Leaf Page found inside States 2, 3, and 4:
1. Decode all active cells (and in-page Freeblocks!) inside that frame's page buffer.
2. Compare each decoded row `(table_name, row_id, column_values)` against the final active table (`ORIGINAL_RECORD`):
   * **If `row_id` does NOT exist in the final active table:**
     * This row was **inserted and later deleted** (or was uncommitted)! Output the full row to the parser and tag it as `HISTORICAL_COMMITTED_RECORD` (if from State 2) or `RESIDUAL_RECORD` (if from State 3 or 4), recording `wal_frame_number` and `wal_state_Action = "DELETED_IN_LATER_WAL_FRAME"`.
   * **If `row_id` DOES exist in the final active table, but one or more column values differ:**
     * This row was **modified/edited** (for example, an edited message text, an updated transaction status from `PENDING` to `FAILED`, or a contact name change)! Output this historical version of the row alongside the active row, tag it as `HISTORICAL_COMMITTED_RECORD`, and record the exact JSON diff of which columns changed between `wal_frame_number` and the final state!

---

## 7. Step 5 — Pipeline B2: The Rollback Journal (`-journal`) Decoder

When an app uses classic rollback journaling (`DELETE`, `TRUNCATE`, or `PERSIST` mode) and a `<name>.db-journal` file is present with size $> 512\text{ bytes}$:

1. **Read the 28-Byte Journal Sector Header (Bytes $0\text{–}27$):**
   * **Bytes $0\text{–}7$ (`journal_magic`):** Check for `D9 D5 05 F9 20 A1 63 D7`. *(Note: In `TRUNCATE` or `PERSIST` mode after a completed transaction, SQLite zeroes out the first $28\text{ bytes}$, leaving the rest of the journal pages intact starting at Byte Offset `sector_size` [typically Offset $512$ or $4096$]! So if Bytes $0\text{–}7$ are `0x00`, jump to Offset $512$ or $4096$ and begin scanning!).*
   * **Bytes $8\text{–}11$ (`page_count`, `int32_be`):** Number of pages in this journal segment (`-1` means compute from file size).
   * **Bytes $12\text{–}15$ (`checksum_nonce`, `uint32_be`).**
   * **Bytes $16\text{–}19$ (`initial_db_page_count`, `uint32_be`).**
   * **Bytes $20\text{–}23$ (`disk_sector_size`, `uint32_be`):** Typically $512$ or $4096$. The first Journal Page Record starts at Byte Offset `disk_sector_size`!
   * **Bytes $24\text{–}27$ (`journal_page_size`, `uint32_be`):** Page size in bytes.
2. **Iterate Through Journal Page Records (Starting at Byte Offset `disk_sector_size`):**
   * Each record is $4 + \text{page\_size} + 4\text{ bytes}$ long:
     * **Bytes $0\text{–}3$ (`page_number`, `uint32_be`):** Original 1-based page number in `.db`.
     * **Bytes $4\text{ to }4 + \text{page\_size}$:** The pre-transaction rollback image of that page.
     * **Final $4\text{ Bytes}$ (`checksum`, `uint32_be`).**
   * Decode every `0x0D` page in the journal and any rows that differ from the active `.db` are emitted as `RESIDUAL_RECORD (Rollback Journal Pre-Transaction State)`.

---

## 8. Step 6 — Pipeline C: The 4-Zone B-Tree Deleted & Residual Record Carver

Pipeline C scans the raw `.db` file (and all WAL/Journal pages) across all four residual storage zones to recover deleted rows.

### 8.1 Zone 1: In-Page Freeblock Recovery (Including Overwritten 4-Byte Header Reconstruction!)
Inside every `0x0D` Table Leaf Page, inspect Bytes $1\text{–}2$ (`first_freeblock_offset`, `uint16_be`). While `fb_offset != 0`:
1. Read `next_fb_offset = uint16_be(page[fb_offset : fb_offset + 2])`.
2. Read `fb_size = uint16_be(page[fb_offset + 2 : fb_offset + 4])`.
3. Extract the slice `fb_bytes = page[fb_offset : fb_offset + fb_size]`.
4. **Why Standard Carvers Fail Here (And How Your Carver Succeeds):**
   * When this row was originally alive, `fb_bytes[0..3]` held `[payload_length_varint][row_id_varint][header_length_varint]...`.
   * When SQLite deleted the row, SQLite wrote `next_fb_offset` and `fb_size` into `fb_bytes[0..3]`, **clobbering the first $4\text{ bytes}$ of the deleted cell**!
   * **Case A (Small Deleted Cell Where Another Deleted Cell Follows Inside the Same Merged Freeblock):** Sometimes two adjacent deleted cells merge into one large Freeblock. The *second* deleted cell inside `fb_bytes` has its `payload_length`, `row_id`, and `header_length` $100\%$ intact! Scan all of `fb_bytes` using the **Sliding Schema-Fingerprint Scanner** (Section 8.2) to extract any complete cells first.
   * **Case B (Recovering the Clobbered First Cell at `fb_bytes[4..]`):**
     * Look up the owning table of this page in `page_owner_map` (from Section 4.2), which tells you the exact number of columns $M$ and their expected affinities (`INTEGER`, `TEXT`, `BLOB`, `REAL`).
     * Try candidate starting positions $s \in \{4, 5, 6, 7, 8, 9\}$ inside `fb_bytes` as the start of the first surviving **Serial Type Varint ($T_1$ or $T_2$)**.
     * Read $M$ (or $M - 1$) Serial Type Varints from position $s$, sum their corresponding data lengths $\sum L(T_j)$ (using the Serial Type Table in Section 5.3), and check if:
       $$s + (\text{bytes\_used\_by\_serial\_types}) + \sum_{j} L(T_j) \le \text{fb\_size}$$
       and whether every `TEXT` column decodes as valid UTF-8/UTF-16 and every column matches the table's Schema Fingerprint!
     * When a match is found, decode all surviving columns, set `row_id = NULL (Clobbered by Freeblock Header)`, and tag the row as **`RESIDUAL_RECORD` (if all columns recovered)** or **`PARTIAL_RECORD` (if column 1's type varint was inside the clobbered 4 bytes)**.

### 8.2 Zone 2 (Unallocated Page Gap), Zone 3 (Freelist Pages) & Zone 4 (Post-EOF Pages)
For the Unallocated Gap (`page[8 + 2 * active_cell_count : cell_content_area_start]`), every Freelist Leaf/Trunk Page (walked from Header Offset $32$), and any Post-EOF pages:
1. **First Check for Intact Cell Headers:** Slide a byte cursor `p` across the unallocated region:
   * At cursor `p`, speculatively read Varint 1 (`P` = payload size), Varint 2 (`row_id`), and Varint 3 (`header_size`).
   * **Fast Sanity Filter (Rejects $99.9\%$ of non-cell positions in $5\text{ nanoseconds}$):**
     * Check that $4 \le P \le \text{max\_possible\_payload}$.
     * Check that `row_id > 0` and `row_id < 10^16`.
     * Check that $2 \le \text{header\_size} \le 512$ and $\text{header\_size} \le P$.
   * Decode the Serial Type Varints inside `header_size`. Suppose there are $M$ serial types whose data lengths sum to $D$:
     * **Exact Cell Match Condition:** Check that:
       $$\text{header\_size} + D == P$$
     * If $\text{header\_size} + D == P$, you have mathematically located a genuine SQLite B-Tree cell!
2. **Match Against Table Schema Fingerprints:**
   * If this page has a known owner in `page_owner_map`, validate the $M$ serial types against that table's schema (remembering that `ALTER TABLE ADD COLUMN` in older app versions means a historical row on disk may have fewer columns $M_{\text{old}} < M_{\text{current}}$—allow prefix schema matches!).
   * If the page came from the Freelist (`page_owner_map` unknown), compare the $M$ serial types and decoded values against all table schemas in the database and assign the row to the highest-scoring matching table.

---

## 9. Database Schema for Module 2.1 (`sqlite_forensic_engine.sqlite`)

Module 2.1 tracks every processed database and stores a universal audit trail of all recovered WAL and carved residual rows (in addition to feeding those rows directly into the domain parsers in Phases 3–7):

### Table 1: `sqlite_database_diagnostics` (Per-Database Forensic Profile)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `db_profile_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each processed SQLite database. |
| `staging_id` | `INTEGER` | `NOT NULL` | Foreign key to `derivative_staging_ledger.staging_id` (Module 1.2). |
| `canonical_db_path` | `TEXT` | `NOT NULL` | Normalized device path (e.g., `/private/var/mobile/Library/SMS/sms.db`). |
| `page_size_bytes` | `INTEGER` | `NOT NULL` | Decoded page size ($512\text{ to }65536$). |
| `usable_page_size_u` | `INTEGER` | `NOT NULL` | $U = \text{page\_size} - \text{reserved\_bytes}$. |
| `text_encoding` | `TEXT` | `NOT NULL` | Enum: `UTF-8`, `UTF-16LE`, `UTF-16BE`. |
| `journal_mode_header` | `TEXT` | `NOT NULL` | `WAL` (if offset $18 == 2$) or `LEGACY_ROLLBACK` (if offset $18 == 1$). |
| `auto_vacuum_mode` | `TEXT` | `NOT NULL` | Enum: `NONE`, `FULL_AUTO_VACUUM`, `INCREMENTAL_VACUUM`. |
| `secure_delete_suspected` | `INTEGER` | `DEFAULT 0` | `1` if freeblocks/unallocated gaps are zero-filled; `0` otherwise. |
| `header_page_count` | `INTEGER` | `NOT NULL` | Page count from Bytes $28\text{–}31$. |
| `physical_page_count` | `INTEGER` | `NOT NULL` | Actual `file_size / page_size` (if $> \text{header\_page\_count}$, post-EOF pages exist). |
| `freelist_page_count` | `INTEGER` | `NOT NULL` | Count of freelist pages from Bytes $36\text{–}39$. |
| `wal_frames_total` | `INTEGER` | `DEFAULT 0` | Total frames in companion `-wal` file. |
| `wal_historical_commits_recovered` | `INTEGER` | `DEFAULT 0` | Count of `HISTORICAL_COMMITTED_RECORD` rows recovered from superseded WAL frames. |
| `carved_residual_rows_recovered` | `INTEGER` | `DEFAULT 0` | Count of `RESIDUAL_RECORD` and `PARTIAL_RECORD` rows carved from freeblocks/freelist/unallocated. |

### Table 2: `sqlite_recovered_records_master` (Universal Raw & Residual Row Store)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `recovered_row_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique global ID for every extracted or carved SQLite row. |
| `db_profile_id` | `INTEGER` | `NOT NULL` | Foreign key to `sqlite_database_diagnostics.db_profile_id`. |
| `table_name` | `TEXT` | `NOT NULL` | Resolved SQLite table name (e.g., `message`, `chat`, `transactions`). |
| `sqlite_rowid` | `INTEGER` | `NULL` | 64-bit `ROWID` (`NULL` if clobbered by 4-byte Freeblock header or `WITHOUT ROWID`). |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum: `ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, `PARTIAL_RECORD`, `RECONSTRUCTED_RECORD`, `UNVERIFIED_FRAGMENT`. |
| `source_origin_zone` | `TEXT` | `NOT NULL` | Enum: `ACTIVE_BTREE`, `WAL_SUPERSEDED_COMMIT`, `WAL_UNCOMMITTED`, `WAL_PRIOR_CHECKPOINT`, `ROLLBACK_JOURNAL`, `IN_PAGE_FREEBLOCK`, `UNALLOCATED_GAP`, `FREELIST_LEAF_PAGE`, `POST_EOF_PAGE`. |
| `source_page_number` | `INTEGER` | `NOT NULL` | 1-based page number where the record resided. |
| `source_byte_offset` | `INTEGER` | `NOT NULL` | Exact byte offset inside the `.db`, `-wal`, or `-journal` file (used by Phase 8's Hex Viewer!). |
| `wal_frame_number` | `INTEGER` | `NULL` | 1-based WAL frame index (if recovered from `-wal`). |
| `columns_json` | `TEXT` | `NOT NULL` | JSON object mapping `{"column_name": decoded_value}` for all columns in the row. |
| `diff_vs_active_json` | `TEXT` | `NULL` | If `HISTORICAL_COMMITTED_RECORD` of an edited row: JSON showing `{"column": {"old_wal_value": X, "current_active_value": Y}}`. |

---

## 10. Developer Acceptance Test Checklist for Module 2.1

1. **The Page 1 (`Offset 100`) & `65,536-Byte` Page Size Test:** Create a SQLite database with `PRAGMA page_size = 65536;` (`0x0001` at Bytes $16\text{–}17$) and 10 tables. Verify that Module 2.1 reads `page_size = 65536` and parses `sqlite_schema` from Page 1 starting at Byte Offset $100$ without off-by-100 alignment errors.
2. **The Multi-Frame WAL Edit & Delete Timeline Test:** Create a WAL-mode database (`messages` table).
   * Transaction 1: `INSERT INTO messages VALUES (1, 'Meet at warehouse at 10 PM', 1762262400);` (Commit).
   * Transaction 2: `UPDATE messages SET body = 'Meet at cafe at 10 PM' WHERE rowid = 1;` (Commit).
   * Transaction 3: `DELETE FROM messages WHERE rowid = 1;` (Commit — without checkpointing!).
   * Run Module 2.1 on the `.db` + `-wal` pair. Verify that it recovers **both** Transaction 1 (`'Meet at warehouse...'`) and Transaction 2 (`'Meet at cafe...'`) as `HISTORICAL_COMMITTED_RECORD` with their exact `wal_frame_number` and `diff_vs_active_json`.
3. **The Clobbered 4-Byte Freeblock Header Recovery Test:** Create a non-WAL database with `PRAGMA secure_delete = OFF;`. Insert 5 rows into a `transactions(id INT PRIMARY KEY, vpa TEXT, amount REAL, utr TEXT)` table, delete the middle row (`id = 3`), and checkpoint/close. Verify that `first_freeblock_offset` points to the deleted row, and that Module 2.1's Zone 1 Freeblock Carver skips the 4-byte overwritten header (`next_offset` + `size`) and successfully recovers the `vpa`, `amount`, and `utr` columns!
4. **The Overflow Page Chain Reassembly Test:** Insert a row containing a $15,000\text{-byte}$ JSON string into a database with a $4096\text{-byte}$ page size (forcing the record across a `0x0D` Leaf Page + $4$ linked Overflow Pages). Verify that Section 5.2's $U, P, X, M, K$ calculation reassembles all $15,000\text{ bytes}$ without truncation.