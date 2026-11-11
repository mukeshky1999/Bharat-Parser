# Engineering Specification: Phase 1, Module 1.4 — The 5D Evidentiary State & Tripartite Audit Engine

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 1.4** of the Forensic Data Parser. It contains **zero programming code** and explains every legal and forensic tracking mechanism from first principles so that a developer can implement an automated evidentiary state engine that satisfies courtroom cross-examination, **SWGDE (2025/2026)** guidelines, and **Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam (BSA) 2023**.

---

## 1. Purpose & Mental Model (Why Standard Forensic Reports Fail in Court)

When most forensic tools generate a report, they only show **what they successfully parsed**. If an investigator looks at a report and sees $0\text{ Signal messages}$ or $0\text{ Google Pay transactions}$, a standard tool leaves the investigator—and the judge—guessing between five completely different realities:

1. Did the suspect never install Signal or Google Pay?
2. Was the app installed, but the extraction was taken in **BFU (Before First Unlock)** so the Credential Encrypted (`CE`) sandbox was never copied off the phone?
3. Was the file copied into the archive, but encrypted (`Signal.sqlite`) and the iOS Keychain key was missing?
4. Did the suspect recently update the app to a new 2026 version that changed the database schema, causing the parser to silently fail?
5. Did the suspect uninstall the app prior to seizure, leaving only "Ghost App" traces in system logs?

If a forensic tool reports all five of those scenarios simply as `"0 Results Found"`, a defence attorney can easily discredit the examination, or an investigator can miss the smoking gun of the case (such as knowing that a file *is* inside the extraction, waiting for a password or decryption key).

### The Solution: The Tripartite Ledger & 5-Dimensional (5D) State Machine
**Module 1.4** is the central "truth ledger" of your software. Before any parser runs in Phases 2–7, Module 1.4 registers every expected forensic artifact across all **18 Forensic Groups** and tracks its exact status across:
* **The Tripartite Model:** (1) **What Was Stored** on the device architecture $\rightarrow$ (2) **What Was Acquired** into the extraction container $\rightarrow$ (3) **What Was Interpreted** by the parser.
* **The 5 Evidentiary Dimensions:** **Presence (A)** $\times$ **Accessibility (B)** $\times$ **Integrity (C)** $\times$ **Parser Coverage (D)** $\times$ **Research Maturity (E)**.

---

## 2. The 4 Absolute Courtroom Rules Enforced by Module 1.4

The developer must hardcode the following four validation rules into the state machine so that no downstream parser or UI screen can ever violate them:

1. **Rule 1 ("Not Observed" Must Never Be Displayed as "Absent"):** The database enum and UI label `"Absent"` are strictly forbidden. If a target file is not found inside `vfs_index`, the system must classify it either as `SOURCE_PRESENT_NOT_ACQUIRED` (when the lock state or extraction tier excluded it) or `NOT_OBSERVED_IN_EXTRACTION`.
2. **Rule 2 (Automatic Lock-State & Tier Inference):** If the loaded container is an **iOS Logical Backup (`Tier 1B`)** and a parser looks for `knowledgeC.db` or `Signal.sqlite` (which Apple excludes from backups), Module 1.4 must **automatically** set Dimension A to `SOURCE_PRESENT_NOT_ACQUIRED (Excluded by OS Backup Policy)`—never `NOT_OBSERVED`. Similarly, if an Android extraction is **BFU** (where `/data/user_de/0/` exists but `/data/user/0/` is empty), every Credential Encrypted (`CE`) artifact must automatically be marked `SOURCE_PRESENT_NOT_ACQUIRED (Gated by Android BFU CE State)`.
3. **Rule 3 (Strict Separation of Hardware-Gated vs. Lock-State-Gated Secrets):** In Group 12 and encrypted app databases, Module 1.4 must distinguish between:
   * `ENCRYPTED_GATED_BY_HARDWARE`: The key resides inside the Secure Enclave Processor (SEP), Trusted Execution Environment (TEE), or StrongBox and cannot be extracted offline.
   * `ENCRYPTED_GATED_BY_MISSING_KEY_MATERIAL`: The database is present, and decryption is mathematically possible if the examiner supplies the Keychain plist, backup password, or 64-digit recovery key.
4. **Rule 4 (Zero Silent Parser Failures):** If a file is `PRESENT` in `vfs_index` and `READABLE` (valid SQLite/MMKV/Protobuf header), but a parser throws an exception because a table or column name changed in a newer app version, the parser **must catch the exception and update Dimension D to `SCHEMA_MISMATCH_UNSUPPORTED_VERSION`**, automatically adding the file to the **Unclassified / Unknown Artifacts Register (`UNK` Ledger)** for manual review.

---

## 3. Step-by-Step Logic: The 5-Dimensional State Machine

Module 1.4 evaluates every target artifact in three chronological passes:
* **Pass 1 (Pre-Parse Initialization):** Runs right after Modules 1.1–1.3 finish. Checks which expected files exist in `vfs_index` and which apps exist in `resolved_application_catalog`.
* **Pass 2 (Active Parsing Updates):** Runs during Phases 2–7 as each decoder and parser opens files, attempts decryption, and extracts records.
* **Pass 3 (Post-Parse Audit & Unknown File Sweep):** Runs after all parsers finish to identify unparsed files and finalize the Tripartite Coverage Summary.

### 3.1 Dimension A — Acquisition Presence Logic
For every registered target artifact (or discovered app sandbox from Module 1.3), determine **Dimension A** using this decision tree:

1. **Check `vfs_index` for target path(s):**
   * **If file exists and `uncompressed_size > 0`:** Set `dim_a_presence = "PRESENT"`.
   * **If file exists in `vfs_index` with `uncompressed_size == 0`:** Check if a companion `-wal` file has `uncompressed_size > 0`. If so, set `PRESENT`; if both are $0\text{ bytes}$, set `PRESENT_EMPTY_STUB`.
2. **If file does NOT exist in `vfs_index`, check why:**
   * **Case 2A (Uninstalled Ghost App):** Check Module 1.3's `resolved_application_catalog`. If the owning app has `install_status == "UNINSTALLED_GHOST_APP"`, set `dim_a_presence = "NOT_OBSERVED_APP_UNINSTALLED_PRIOR_TO_SEIZURE"`.
   * **Case 2B (Excluded by Acquisition Tier):** Check `container_integrity_ledger.acquisition_tier`. If `acquisition_tier` is `TIER_1A_API` or `TIER_1B_BACKUP` and the artifact requires `TIER_2_FFS` (such as `/.fseventsd/`, `knowledgeC.db`, raw `tracev3`, or a file flagged with `NSURLIsExcludedFromBackupKey` / `allowBackup="false"`), set `dim_a_presence = "SOURCE_PRESENT_NOT_ACQUIRED_TIER_EXCLUSION"`.
   * **Case 2C (Excluded by BFU Lock State):** If the device was extracted in **BFU** (detected because Class D / Android `DE` files are present while Class A–C / Android `CE` directories are missing or empty), set `dim_a_presence = "SOURCE_PRESENT_NOT_ACQUIRED_BFU_LOCK_STATE"`.
   * **Case 2D (Excluded by Partial Physical LUN Scope):** If the container is a physical UFS dump containing `LUN 0` only and the target is in `Boot LUN A/B` or `W-LUN (RPMB)`, set `dim_a_presence = "SOURCE_PRESENT_NOT_ACQUIRED_LUN_OUT_OF_SCOPE"`.
   * **Case 2E (Default Not Observed):** If none of the exclusions apply and the app was never installed, set `dim_a_presence = "NOT_OBSERVED"`.

### 3.2 Dimension B — Content Accessibility Logic
For every artifact where `dim_a_presence == "PRESENT"`, determine **Dimension B**:

1. Inspect the first $64\text{ bytes}$ of the file stream (and its encryption flags from Modules 1.1 & 1.2):
   * **If plaintext header is recognized** (e.g., `"SQLite format 3\0"`, `"bplist00"`, `"abx\0"`, `"SEGB"`, valid XML/JSON, or valid MMKV/LevelDB header):
     * Check if specific columns inside the plaintext table are encrypted (for example, `keychain-2.db` or Chrome `Login Data` where metadata columns are plaintext SQLite, but the `data` / `password_value` BLOB column is encrypted).
     * If all columns are readable OR the required decryption key was successfully applied by Phase 2: Set `dim_b_accessibility = "READABLE"`.
     * If metadata columns are readable in plaintext but secret BLOB columns remain encrypted due to missing hardware/Keychain keys: Set `dim_b_accessibility = "PARTIALLY_READABLE_METADATA_ONLY"` and record the exact readable vs. encrypted columns.
   * **If the file is full ciphertext** (high Shannon entropy $> 7.95\text{ bits/byte}$, or known encrypted wrapper like `.crypt14`/`.crypt15`, SQLCipher salt header, or iOS encrypted backup file without password):
     * If decryption succeeded in Phase 2 using a discovered sandbox/Keychain key: Set `dim_b_accessibility = "READABLE_DECRYPTED"`.
     * If decryption requires a hardware key isolated inside SEP/TEE/StrongBox (and was not unwrapped during live acquisition): Set `dim_b_accessibility = "ENCRYPTED_GATED_BY_HARDWARE"`.
     * If decryption requires an external key/password not present in the extraction (e.g., Signal iOS without `keychain-backup.plist`, or `.crypt15` without E2EE key): Set `dim_b_accessibility = "ENCRYPTED_GATED_MISSING_KEY"`.
   * **If the header is truncated, zero-filled, or fails CRC/page-sanity checks:** Set `dim_b_accessibility = "CORRUPT_OR_ZEROED"`.

### 3.3 Dimension C — Physical & Source Integrity Logic
Dimension C links the artifact to **Module 1.2's Hashing Ledger** and **Module 1.3's Tamper/Downgrade Detector**:

1. Check `container_integrity_ledger.verification_status` and `derivative_staging_ledger`:
   * If the container hash and staged file hash (`product_b1_raw_sha256`) are verified and no source-modifying acquisition method was used on this artifact: Set `dim_c_integrity = "VERIFIED_STATIC"` (for physical/offline images) or `"VERIFIED_LIVE_STAGING_HASH"` (for live FFS/Logical extractions).
2. Check if the artifact was touched by a **Source-Modifying Forensic Procedure**:
   * If Module 1.3 detected `is_forensic_downgraded == 1` (`adb install -r -d` APK downgrade) for this app: Set `dim_c_integrity = "MODIFIED_SOURCE_BY_ACQUISITION_PROCEDURE (APK Downgrade)"`.
   * If the examiner logged a backup password reset (`Reset All Settings`) prior to logical backup, mark affected system preference plists (`preferences.plist`, `known-networks.plist`) as `"MODIFIED_SOURCE_BY_ACQUISITION_PROCEDURE (Settings Reset)"`.
   * If `/.fseventsd/` exhibits a UUID reset matching known ramdisk extraction tool behavior (e.g., VeraKey FSEvents reset), flag as `"POTENTIAL_TOOL_INDUCED_STATE_CHANGE"`.

### 3.4 Dimension D — Parser & Acquisition Coverage Logic
Dimension D tracks how your software's parser handled the file against the specific OS and application version:

1. `DIRECTLY_PARSED_FULL`: The parser recognized the exact schema/version and extracted all supported tables and residual records without errors.
2. `PARSED_WITH_SUPPLIED_KEYS`: Successfully parsed after Phase 2's Key Broker injected a cryptographic key from Keychain, Keystore, or examiner input.
3. `PARTIALLY_PARSED`: Main records were extracted, but new/unknown columns or sub-tables in a recent 2026 app update were skipped (must log exact skipped table/column names).
4. `SCHEMA_MISMATCH_REQUIRES_MANUAL_DECODE`: The file is `PRESENT` and `READABLE`, but the schema did not match any known version in the parser. Automatically routes the file to the Examiner SQLite/Hex Workbench and the `UNK` Ledger.
5. `STRUCTURALLY_IDENTIFIED_UNSUPPORTED`: Format is recognized (e.g., a proprietary OEM daemon database), but no automated parser exists yet.

### 3.5 Dimension E — Research Maturity Classification (`R1`–`R6`)
Every parser module registered in your software carries a static dictionary metadata tag declaring its laboratory validation maturity level (`R1` through `R6`), which is written into the audit trail alongside the evidence basis:
* `R1 (Path Identified)` $\rightarrow$ `R2 (Schema Documented)` $\rightarrow$ `R3 (Partially Decoded)` $\rightarrow$ `R4 (Semantically Interpreted)` $\rightarrow$ `R5 (Experimentally Validated on Controlled Test Corpus)` $\rightarrow$ `R6 (Independently Corroborated & Peer-Reviewed)`.

---

## 4. The Unknown & Unclassified Artifacts Sweeper (`UNK` & `PHY` Ledgers)

Commercial tools ignore any database or binary file inside an app sandbox that they do not have a hardcoded script for. **In investigations involving new Indian betting/loan scam apps, custom corporate banking apps, or novel criminal messengers, the most important database on the phone is often an "unknown" database.**

After all known parsers finish, Module 1.4 runs the **Unclassified Artifact Sweeper**:
1. Query `vfs_index` for all regular files inside `/Containers/Data/Application/`, `/Containers/Shared/AppGroup/`, `/data/user/`, `/data/user_de/`, and `/data/media/` that were **not** marked as `DIRECTLY_PARSED_FULL` or `PARSED_WITH_SUPPLIED_KEYS`.
2. Inspect the magic bytes and file extensions of those unparsed files:
   * Any unparsed **SQLite database** (`53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00`) with $> 0\text{ user rows}$.
   * Any unparsed **MMKV store** (`mmkv.*` or companion `.crc` file).
   * Any unparsed **LevelDB directory** (`CURRENT`, `MANIFEST-*`, `*.ldb`).
   * Any unparsed **Realm database** (`.realm`).
   * Any unparsed **High-Entropy / Encrypted Container** ($> 100\text{ KB}$ inside an app's `databases/` or `files/` directory).
3. Insert each discovered file into the `unclassified_artifacts_register` (`UNK-0001`, `UNK-0002`, ...), automatically resolving its owning application name and user profile via **Module 1.3**, and extracting a preview of its SQLite table names and row counts so the examiner can see at a glance:
   > *`UNK-0014` — App: `Lotus365 Betting (com.lotus365.app)` — File: `wallet_ledger.db` (SQLite, 4 tables: `bets`, `upi_withdrawals`, `agent_chats`, `users` — 14,820 rows).*

---

## 5. Database Schema for Module 1.4 (`evidentiary_state_ledger.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `evidentiary_audit_trail` (The Master 5D Ledger)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `audit_entry_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID for every evaluated artifact or app sandbox target. |
| `artifact_code` | `TEXT` | `NOT NULL` | Standardized artifact code (e.g., `G01_WHATSAPP_ANDROID_LIVE`, `G13_PHONEPE_TX_DB`). |
| `forensic_group_num` | `INTEGER` | `NOT NULL` | Integer `1` through `18` corresponding to the 18-Group Master Register. |
| `forensic_group_name` | `TEXT` | `NOT NULL` | E.g., `"Group 13 — Financial, Commercial & Indian UPI"`. |
| `app_instance_id` | `INTEGER` | `NULL` | Foreign key to `resolved_application_catalog` (Module 1.3), if app-specific. |
| `vfs_file_id` | `INTEGER` | `NULL` | Foreign key to `vfs_index.file_id` (Module 1.1), if `PRESENT` in extraction. |
| `expected_canonical_path` | `TEXT` | `NOT NULL` | The canonical path or pattern evaluated. |
| `tripartite_stored_state` | `TEXT` | `NOT NULL` | Enum: `ARCHITECTURALLY_EXPECTED`, `APP_INSTALLED_STORAGE_EXPECTED`, `APP_UNINSTALLED_GHOST`, `APP_NOT_PRESENT`. |
| `dim_a_presence` | `TEXT` | `NOT NULL` | Enum: `PRESENT`, `PRESENT_EMPTY_STUB`, `SOURCE_PRESENT_NOT_ACQUIRED_TIER`, `SOURCE_PRESENT_NOT_ACQUIRED_BFU`, `SOURCE_PRESENT_NOT_ACQUIRED_LUN`, `NOT_OBSERVED_GHOST_APP`, `NOT_OBSERVED`, `NOT_ASSESSED`. |
| `dim_b_accessibility` | `TEXT` | `NOT NULL` | Enum: `READABLE`, `READABLE_DECRYPTED`, `PARTIALLY_READABLE_METADATA_ONLY`, `ENCRYPTED_GATED_BY_HARDWARE`, `ENCRYPTED_GATED_MISSING_KEY`, `CORRUPT_OR_ZEROED`, `NOT_APPLICABLE`. |
| `dim_c_integrity` | `TEXT` | `NOT NULL` | Enum: `VERIFIED_STATIC`, `VERIFIED_LIVE_STAGING_HASH`, `PARTIALLY_VERIFIED_READ_ERRORS`, `MODIFIED_SOURCE_BY_PROCEDURE`, `POTENTIAL_TOOL_ANOMALY`, `UNKNOWN`. |
| `dim_d_coverage` | `TEXT` | `NOT NULL` | Enum: `DIRECTLY_PARSED_FULL`, `PARSED_WITH_SUPPLIED_KEYS`, `PARTIALLY_PARSED`, `SCHEMA_MISMATCH_REQUIRES_MANUAL`, `STRUCTURALLY_IDENTIFIED_UNSUPPORTED`, `NOT_TESTED`. |
| `dim_e_maturity` | `TEXT` | `NOT NULL` | Enum: `R1`, `R2`, `R3`, `R4`, `R5`, `R6`. |
| `parser_module_name` | `TEXT` | `NULL` | Name and exact version of the parser module that evaluated this artifact. |
| `active_records_parsed` | `INTEGER` | `DEFAULT 0` | Count of active/live records extracted from this source. |
| `residual_records_parsed` | `INTEGER` | `DEFAULT 0` | Count of WAL, freelist, unallocated, or SEGB deleted records recovered from this source. |
| `diagnostic_notes` | `TEXT` | `NULL` | Detailed human-readable explanation (e.g., `"Signal.sqlite present (48.2 MB); requires Keychain item OWSPrimaryStorage to decrypt"`). |

### Table 2: `unclassified_artifacts_register` (The `UNK` & `PHY` Ledger)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `unk_id` | `TEXT` | `PRIMARY KEY` | Sequential code (`UNK-0001`, `UNK-0002`, or `PHY-0001` for unparsed partitions). |
| `vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `vfs_index.file_id`. |
| `app_instance_id` | `INTEGER` | `NULL` | Foreign key to owning application in Module 1.3 (`resolved_application_catalog`). |
| `canonical_path` | `TEXT` | `NOT NULL` | Full normalized path of the unparsed file. |
| `detected_storage_format` | `TEXT` | `NOT NULL` | Enum: `SQLITE3`, `MMKV`, `LEVELDB`, `REALM`, `PROTOBUF_RAW`, `BPLIST`, `HIGH_ENTROPY_ENCRYPTED`, `UNKNOWN_BINARY`. |
| `file_size_bytes` | `INTEGER` | `NOT NULL` | Size in bytes (including companion `-wal` size if SQLite). |
| `sqlite_table_summary_json` | `TEXT` | `NULL` | If `SQLITE3`: JSON dictionary of `{"table_name": row_count}` extracted automatically so the examiner knows what is inside! |
| `inferred_forensic_group` | `INTEGER` | `NULL` | Inferred group (`5` for third-party app sandbox, `8` for system telemetry, `13` if owned by a financial/UPI package). |
| `examiner_review_status` | `TEXT` | `DEFAULT 'PENDING_REVIEW'` | Enum: `PENDING_REVIEW`, `MANUALLY_INSPECTED`, `BOOKMARKED_RELEVANT`, `IGNORED_BENIGN`. |

### Table 3: `tripartite_case_summary` (Executive & Courtroom Rollup Table)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `group_number` | `INTEGER` | `PRIMARY KEY` | Forensic Group `1` through `18`. |
| `group_title` | `TEXT` | `NOT NULL` | Full title of the Forensic Group. |
| `stored_targets_expected` | `INTEGER` | `NOT NULL` | Number of artifact families architecturally expected or installed on the device in this group. |
| `acquired_targets_present` | `INTEGER` | `NOT NULL` | Number of those artifact families successfully present in the extraction (`Dimension A = PRESENT`). |
| `gated_or_excluded_count` | `INTEGER` | `NOT NULL` | Number of targets blocked by BFU lock state, OS backup exclusion, or missing hardware/Keychain keys. |
| `interpreted_targets_count` | `INTEGER` | `NOT NULL` | Number of targets successfully decoded into human-readable evidence (`Dimension B = READABLE` & `Dimension D = PARSED`). |
| `total_active_artifacts` | `INTEGER` | `NOT NULL` | Total live records recovered across this group. |
| `total_residual_artifacts` | `INTEGER` | `NOT NULL` | Total deleted/WAL/freelist/residual records recovered across this group. |

---

## 6. Developer Acceptance Test Checklist for Module 1.4

1. **The BFU Lock-State Attribution Test:** Load a simulated Android BFU extraction where `/data/user_de/0/com.android.providers.telephony/databases/mmssms.db` is present, but `/data/user/0/com.whatsapp/` is missing. Verify that `mmssms.db` is marked `PRESENT × READABLE`, while WhatsApp is automatically marked `SOURCE_PRESENT_NOT_ACQUIRED_BFU × NOT_APPLICABLE` (and **never** reported as `"Absent"`).
2. **The Encrypted Signal Keychain Dependency Test:** Load an iOS FFS extraction containing `Signal.sqlite` without supplying the Keychain file. Verify that Module 1.4 logs `Signal.sqlite` as `PRESENT × ENCRYPTED_GATED_MISSING_KEY × VERIFIED_LIVE_STAGING_HASH × PARSED_WITH_SUPPLIED_KEYS (Awaiting Key) × R4` with the diagnostic note instructing the examiner to load `keychain-2.db` / `keychain-backup.plist`.
3. **The Unclassified SQLite Auto-Inspector Test:** Place a custom SQLite database named `hawala_ledger.db` containing a table `transfers` ($50\text{ rows}$) inside an unknown app folder `/data/user/0/com.custom.calc/databases/`. Run the Phase 1 pipeline and verify that the Unclassified Artifact Sweeper automatically flags it as `UNK-0001`, attributes ownership to `com.custom.calc`, and populates `sqlite_table_summary_json` with `{"transfers": 50}`.