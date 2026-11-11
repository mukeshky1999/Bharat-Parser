# Engineering Specification: Phase 2, Module 2.2 — The Automated Cryptographic Key Broker & Database Unwrapper

**Document Purpose:** This document provides the complete, byte-level architectural blueprint for building **Module 2.2** of the Forensic Data Parser. It contains **zero programming code** and explains every cryptographic structure, byte offset, key derivation formula, and SQLCipher page layout from first principles so that a developer with no prior experience in forensic cryptography can build an automated key-harvesting and database-decryption engine.

---

## 1. Purpose & Mental Model (Why Decryption Must Be Centralized)

In modern mobile applications, high-value databases are rarely stored solely in plaintext. Applications like **Signal (`Signal.sqlite` / `signal.db`)**, **WhatsApp Local Backups (`msgstore.db.crypt14` / `.crypt15`)**, **WeChat (`EnMicroMsg.db`)**, **Session (`session.db`)**, **Threema**, **Element/Matrix**, **Apple Notes (password-locked notes)**, **Chrome (`Login Data`)**, and numerous **Indian UPI & Banking apps** encrypt their local SQLite databases, Realm files, or preference values.

If you allow individual app parsers in Phases 3–7 to run before harvesting the device's cryptographic keys, or if each developer tries to write ad-hoc decryption inside each app parser, the system will fail because:

1. **Cross-Boundary Key Separation (`G1 / G5 ↔ G12`):** An application's database and its decryption key almost never live in the same folder. For example, on iOS, Signal's database lives in a **Shared App Group** container (`/private/var/mobile/Containers/Shared/AppGroup/<UUID>/grdb/Signal.sqlite`), while its 48-byte decryption key lives inside the **iOS System Keychain** (`/private/var/Keychains/keychain-2.db` or `keychain-backup.plist`).
2. **Encrypted SQLite (`SQLCipher`) Replaces the 16-Byte SQLite Header with Random Salt:** When a database is encrypted with SQLCipher, Bytes $0\text{–}15$ of Page 1 do **not** contain `"SQLite format 3\0"`—they contain a **16-byte random cryptographic salt**! If you pass an encrypted SQLCipher file directly to Module 2.1's SQLite reader, it will reject the file as "Not a SQLite database."
3. **WAL Files Are Also Encrypted Page-by-Page:** When a SQLCipher database uses Write-Ahead Logging (`-wal`), the 32-byte WAL Header and the 24-byte WAL Frame Headers remain **unencrypted**, while the $4096\text{-byte}$ page payload inside each WAL frame is **encrypted** using the exact same AES key and page-level IV/HMAC structure!
4. **Distinguishing Software-Decryptable vs. Hardware-Gated Evidence:** When a key is wrapped by the Android Hardware Keystore (`TEE` / `StrongBox`) or iOS Secure Enclave (`SEP`) and was not unwrapped during acquisition, your engine must mathematically identify that the database is **Hardware-Gated (`Dimension B = ENCRYPTED_GATED_BY_HARDWARE`)** rather than crashing or reporting the file as corrupt.

### The Architecture of Module 2.2
**Module 2.2** executes at the very start of Phase 2—**before any application parser runs**:
1. **Stage 1 (Key Harvesting):** Scans all OS credential stores (iOS Keychain, Android Keystore metadata, app `shared_prefs/`, sandbox key files, and examiner-supplied passwords/recovery keys) and populates the central **`case_cryptographic_keyring`** table.
2. **Stage 2 (Encrypted Target Detection):** Scans all staged files for high Shannon entropy ($> 7.9\text{ bits/byte}$), SQLCipher page signatures, `.crypt12/.crypt14/.crypt15` headers, or `EncryptedSharedPreferences` wrappers.
3. **Stage 3 (Automated Unwrapping & `Product B2` Materialization):** Matches each encrypted database with its corresponding key in the keyring, decrypts both the main `.db` file and every frame of its companion `-wal` file into a verified **`Product B2` plaintext SQLite derivative**, hashes it via Module 1.2, and hands the plaintext database to **Module 2.1** for full active + WAL + freelist carving!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Forensic Cryptography

Before implementing Module 2.2, the developer must understand six classic traps that cause decryption failures in amateur forensic tools:

### Mistake 1: Treating Signal iOS's 96-Hex-Character Key as a Passphrase Instead of a Raw Key + Salt
* **The Trap:** Extracting the 48-byte (`96-character hex`) key for Signal iOS from the Keychain (`OWSPrimaryStorage` / `GRDBDatabaseCipherKeySpec`) and passing it into SQLCipher as a regular text password (`PRAGMA key = 'a1b2c3...';`).
* **Why It Fails:** If you pass a string without the `x'...'` raw-hex qualifier, SQLCipher treats the string as a human password and runs $256,000\text{ rounds}$ of `PBKDF2-HMAC-SHA512` over it, producing a completely wrong AES key! Even worse, if you pass a 64-character hex string (`32 bytes`), SQLCipher reads the 16-byte salt from Page 1; when you pass a **96-character hex string (`48 bytes`)** inside `PRAGMA key = "x'<96_hex_chars>'";`, SQLCipher uses the first $32\text{ bytes}$ ($64\text{ hex chars}$) as the direct AES-256 key and the last $16\text{ bytes}$ ($32\text{ hex chars}$) as the explicit salt, completely skipping PBKDF2!
* **The Rule:** Always verify whether a harvested key is a **Passphrase** (requires PBKDF2 key derivation), a **Raw 32-Byte AES Key** ($64\text{ hex chars}$), or a **Raw 48-Byte Key + Salt Blob** ($96\text{ hex chars}$).

### Mistake 2: Decrypting Page 1 of a SQLCipher Database Without Reconstructing Bytes $0\text{–}15$
* **The Trap:** Writing a custom AES-CBC page decryptor for SQLCipher that decrypts every $4096\text{-byte}$ page starting at Byte Offset $0$ of the page.
* **Why It Fails:** On Pages $2, 3, \dots, N$ of a SQLCipher database, the encrypted ciphertext begins at Byte Offset $0$ of the page. However, on **Page 1**, **Bytes $0\text{–}15$ are the unencrypted 16-byte file salt**! The encrypted ciphertext on Page 1 covers only **Bytes $16\text{ through } (\text{page\_size} - \text{reserve\_size} - 1)$** (which corresponds to Bytes $16\text{–}99$ of the SQLite header plus the first B-tree cells). Once decrypted, you must write the standard 16-byte ASCII string `"SQLite format 3\0"` (`53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00`) into Bytes $0\text{–}15$ of the output file so that SQLite recognizes Page 1!
* **The Rule:** Follow the exact Page 1 vs. Page $N$ byte boundary specification in Section 5.2.

### Mistake 3: Forgetting That SQLCipher Encrypted Pages Have Non-Zero `reserved_bytes_per_page`
* **The Trap:** Decrypting all pages of a SQLCipher database, writing `"SQLite format 3\0"` at Bytes $0\text{–}15$, and overwriting the last $48\text{–}80\text{ bytes}$ of each page (where the SQLCipher IV and HMAC were stored) with `0x00` while changing Header Byte $20$ (`reserved_bytes_per_page`) to `0`.
* **Why It Fails:** When SQLCipher originally created the B-Tree pages, it set Header Byte $20$ (`reserved_bytes_per_page`) to the size of its trailer (`48 bytes` in SQLCipher v3 with SHA1, or `80 bytes` in SQLCipher v4 with SHA512—comprising a $16\text{-byte}$ AES IV + a $32\text{-byte}$ or $64\text{-byte}$ HMAC). All B-tree cell offsets and overflow calculations ($U = \text{page\_size} - \text{reserved\_bytes}$) inside the database were computed using that exact `reserved_bytes_per_page` value!
* **The Rule:** When producing a decrypted plaintext `.db` file (`Product B2`), **preserve the original `reserved_bytes_per_page` value at Header Byte $20$** and zero-fill the reserved trailer bytes at the end of each page so every B-tree offset and overflow calculation remains $100\%$ valid.

### Mistake 4: Decrypting `Signal.sqlite` But Forgetting to Decrypt `Signal.sqlite-wal`
* **The Trap:** Decrypting the main `Signal.sqlite` file into a plaintext `.db` file while leaving `Signal.sqlite-wal` untouched (or deleting the `-wal` file).
* **Why It Fails:** On iOS and Android, Signal, Session, and WeChat operate in `WAL` mode. Almost all messages from the last several days sit inside `Signal.sqlite-wal`! If you do not decrypt the page payloads inside the `-wal` frames, you lose the suspect's most recent messages and all historical WAL edits/deletions.
* **The Rule:** Module 2.2 must decrypt **both** the main `.db` file and every encrypted frame payload inside the companion `-wal` file (Section 5.4), writing out a synchronized plaintext pair: `decrypted.db` + `decrypted.db-wal`.

### Mistake 5: Confusing SQLCipher v3 Defaults with SQLCipher v4 Defaults
* **The Trap:** Trying to open a legacy WeChat (`EnMicroMsg.db`) or older Android database using SQLCipher v4 parameters, or trying to open a modern Signal database using SQLCipher v3 parameters.
* **Why It Fails:** SQLCipher changed all four cryptographic parameters between v3 and v4:
  * **SQLCipher v3:** `page_size = 1024`, `kdf_iter = 64000`, `HMAC_SHA1`, `PBKDF2_HMAC_SHA1`.
  * **SQLCipher v4:** `page_size = 4096`, `kdf_iter = 256000`, `HMAC_SHA512`, `PBKDF2_HMAC_SHA512`.
  * **Tencent WCDB (WeChat):** `page_size = 1024` (or `4096` in newer builds), `kdf_iter = 64000` (or `4000`), `HMAC_SHA1` (or no HMAC in legacy v1/v2), `PBKDF2_HMAC_SHA1`.
* **The Rule:** Use the **Page 1 HMAC Auto-Prober** (Section 5.3), which tests the candidate key against Page 1 using the v4, v3, and WCDB profiles in under $50\text{ milliseconds}$ and automatically selects the exact profile that validates Page 1's HMAC!

### Mistake 6: Failing to Handle Both Protobuf Header Variants in WhatsApp `.crypt15`
* **The Trap:** Hardcoding a fixed byte offset (such as Byte Offset $67$ or Byte Offset $191$) for the start of the AES-256-GCM ciphertext inside a WhatsApp `msgstore.db.crypt15` file.
* **Why It Fails:** WhatsApp `.crypt15` files begin with a **variable-length Protocol Buffer header** (preceded by a 1-byte length prefix, plus an optional 1-byte feature flag). Depending on whether the backup was created with a 64-digit hex key or a password-protected key, and which WhatsApp version created it, the header length varies between $\approx 60\text{ bytes}$ and $195\text{ bytes}$!
* **The Rule:** Always read the dynamic header length byte(s) at the start of `.crypt14` and `.crypt15` files and parse the Protobuf header dynamically (Section 6.3).

---

## 3. Step 1 — Harvesting the iOS Keychain (`keychain-2.db`, Vendor Exports & `keychain-backup.plist`)

When an iOS extraction is loaded, Module 2.2 searches `vfs_index` for all three possible representations of the iOS Keychain and merges their findings into `case_cryptographic_keyring`:

### 3.1 Source A: Pre-Decrypted Vendor Keychain Plists (FFS Extractions)
When Cellebrite Inseyets/UFED, Magnet GrayKey, or Elcomsoft acquires an iOS Full File-System (FFS) extraction, the extraction agent running on the phone queries the Secure Enclave while the phone is in AFU/Unlocked state and exports a decrypted plist or XML file alongside the `.tar`/`.zip` archive:
1. Search the container directory and `vfs_index` root for files matching `*keychain*.plist` or `*keychain*.xml`.
2. Parse the plist/XML array of dictionary items. Each dictionary entry contains:
   * `agrp` (`String`): Access Group (e.g., `"D686927323.group.org.whispersystems.signal"`, `"group.net.whatsapp.WhatsApp.shared"`).
   * `svce` (`String`): Service Name (e.g., `"OWSPrimaryStorage"`, `"TSKeyChainService"`).
   * `acct` (`String`): Account Name (e.g., `"GRDBDatabaseCipherKeySpec"`, `"OWSDatabaseCipherKeySpec"`).
   * `pdmn` (`String`): Protection Domain (`ak`, `ck`, `dk`, `aku`, `cku`, `dku`, `akpu`).
   * `v_Data` or `data` (`Data` / `Base64` / `Hex`): **The unwrapped plaintext secret bytes!**
   * `cdat` & `mdat` (`Date` / `Real`): Creation and modification timestamps.
3. Convert `v_Data` to a lowercase hexadecimal string and insert into `case_cryptographic_keyring` with `key_accessibility = "UNWRAPPED_READY"`.

### 3.2 Source B: Encrypted iOS Logical Backups (`keychain-backup.plist` + `Manifest.plist` Keybag)
When an investigator loads an **Encrypted iOS Logical Backup (`Tier 1B`)** and provides the backup password:
1. **Read the `BackupKeyBag` from `Manifest.plist`:**
   * Parse the binary `BackupKeyBag` blob (composed of 4-byte ASCII tag-length-value `[Tag][Length][Value]` blocks: `VERS`, `TYPE`, `UUID`, `HMCK`, `WRAP`, `SALT`, `ITER`, `DPIC`, `DPSL`, followed by per-class blocks `CLAS`, `UUID`, `WRAP`, `WPKY`, `KTYP`, `PBKY`).
2. **Derive the 32-Byte Backup Decryption Key (iOS 10.2 through iOS 26 Dual-PBKDF2 Formula):**
   * First Round (Fast Pass): Run **PBKDF2-HMAC-SHA256** using the UTF-8 `backup_password`, the 20-byte salt `DPSL` (from the keybag header), and iteration count `DPIC` (typically $10,000,000\text{ iterations}$) to produce a 32-byte intermediate key $K_1$.
   * Second Round (Slow Pass): Run **PBKDF2-HMAC-SHA1** using $K_1$ as the input password, the 20-byte salt `SALT`, and iteration count `ITER` (typically $10,000\text{ iterations}$) to produce the final **32-byte Key Encryption Key ($K_{\text{KEK}}$)**.
3. **Unwrap the Protection Class Keys (`WPKY`) via RFC 3394 AES Key Wrap:**
   * For each class entry (`CLAS` $1$ through $11$) in the `BackupKeyBag` where `(WRAP & 2) != 0`:
     * Unwrap the 40-byte wrapped key `WPKY` using **RFC 3394 AES-256 Key Unwrap** with $K_{\text{KEK}}$.
     * Check that the 8-byte RFC 3394 integrity check value (`IV`) equals `A6 A6 A6 A6 A6 A6 A6 A6` (`0xA6A6A6A6A6A6A6A6`). If it matches, the backup password is mathematically verified, and the remaining $32\text{ bytes}$ are the unwrapped **Class Key ($K_{\text{class}}$)**!
4. **Decrypt `keychain-backup.plist` Entities:**
   * Open `KeychainDomain/keychain-backup.plist` (which holds arrays `genp`, `inet`, `cert`, `keys`).
   * For each keychain entry, inspect its `v_Data` encrypted blob:
     * Read the 4-byte little-endian class integer at Bytes $0\text{–}3$ of `v_Data`.
     * Look up the corresponding unwrapped Class Key $K_{\text{class}}$ from Step 3.
     * Unwrap the per-item AES key using RFC 3394 (or AES-GCM in newer keychain formats) and decrypt the item's secret payload.
     * *(Note: If the item's class is a `ThisDeviceOnly` class [`aku`, `cku`, `dku`] and its key in the `BackupKeyBag` is wrapped with the hardware UID [`WRAP & 1`] rather than the backup password, mark that specific entry in `case_cryptographic_keyring` as `HARDWARE_BOUND_UNAVAILABLE` so the investigator knows why a `ThisDeviceOnly` item could not be decrypted from a backup alone).*

### 3.3 Source C: Raw `/private/var/Keychains/keychain-2.db` Metadata & Blob Audit
Always open `/private/var/Keychains/keychain-2.db` using Module 2.1's SQLite reader (because the SQLite table structure and metadata columns `rowid`, `cdat`, `mdat`, `agrp`, `svce`, `acct`, `pdmn` in `genp`, `inet`, `cert`, and `keys` are **plaintext SQLite**!).
* Even if an item's `data` blob is still hardware-wrapped (`ENCRYPTED_GATED_BY_HARDWARE`), recording its `agrp`, `svce`, `acct`, `cdat`, and `mdat` in `case_cryptographic_keyring` proves **when the suspect created or last updated credentials for that app** (Group 12 & Group 5)!

---

## 4. Step 2 — Harvesting Android Cryptographic Material (`shared_prefs`, Sandbox Key Files & Keystore 2.0)

When an Android extraction is loaded, Module 2.2 scans three locations across every user profile (`0`, `10`, `95`, `150`, `999`) identified by Module 1.3:

### 4.1 Location A: Direct Sandbox Key Files (`/files/key`, `encrypted_backup.key`, `KeyInfo.bin`)
Query `vfs_index` across all app sandboxes for known key files:
* `/data/user/<id>/com.whatsapp/files/key` & `com.whatsapp.w4b/files/key` ($158\text{ bytes}$ — WhatsApp `.crypt12/.crypt14` key).
* `/data/user/<id>/com.whatsapp/files/encrypted_backup.key` (WhatsApp `.crypt15` root key).
* `/data/user/<id>/com.tencent.mm/files/KeyInfo.bin` (WeChat device key metadata).
* Any `.key`, `.pem`, `.p12`, `.keystore`, or `.jks` file inside `/data/user/<id>/<pkg>/files/` or `/databases/`.

### 4.2 Location B: `shared_prefs/*.xml` & Jetpack `EncryptedSharedPreferences`
Scan every `.xml` file inside `/data/user/<id>/<pkg>/shared_prefs/` and `/data/user_de/<id>/<pkg>/shared_prefs/`:
1. **Plaintext / Base64 Keys in Standard XML:**
   * Extract keys matching known patterns (e.g., `_auth_uin`, `default_uin` for WeChat; `database_key`, `realm_key`, `sqlcipher_key`, `encryption_key`, `pref_database_encrypted_secret` for messaging and UPI apps).
2. **Android Keystore Ciphertext Blobs in Standard XML:**
   * Many apps (like Signal Android in `org.thoughtcrime.securesms_preferences.xml` under `pref_database_encrypted_secret` / `SignalSecret`) store a JSON object containing:
     * `"data"` or `"ciphertext"`: Base64-encoded AES-GCM encrypted key.
     * `"iv"`: Base64-encoded 12-byte Initialization Vector.
   * The master key that decrypts that JSON blob is an **Android Keystore key alias** (e.g., `"SignalSecret"`).
3. **Google Tink / Jetpack `EncryptedSharedPreferences` XMLs:**
   * Identified by two special `<string>` tags inside the XML file:
     * `__androidx_security_crypto_encrypted_prefs_key_keyset__` (holds the Tink keyset protobuf encrypted by the Android Keystore master key `_androidx_security_master_key_`).
     * `__androidx_security_crypto_encrypted_prefs_value_keyset__`.
   * Every other entry in that XML has its key name encrypted with **AES-256-SIV** (deterministic authenticated encryption) and its value encrypted with **AES-256-GCM**.

### 4.3 Location C: Android Keystore 2.0 (`/data/misc/keystore/persistent.sqlite`) & Unwrapped Exports
1. Check if the upstream extraction tool (Cellebrite Inseyets, GrayKey, or Oxygen) exported unwrapped Android Keystore keys (captured in RAM from `keystore2` / `keymint` while the phone was in AFU state). If present, import those unwrapped 16/32-byte AES keys into `case_cryptographic_keyring` (`UNWRAPPED_READY`), which immediately unlocks Signal Android (`signal.db`), Session (`session.db`), and Jetpack `EncryptedSharedPreferences`!
2. Regardless of whether unwrapped keys were exported, always open `/data/misc/keystore/persistent.sqlite` (Android 12–17 Keystore 2.0 database) using Module 2.1:
   * Query the `keyentry`, `blobentry`, and `keymetadata` tables.
   * Join `keyentry.namespace` (which equals the app's **Linux UID**, e.g., `10145`) with **Module 1.3's `uid_ownership_lookup` table** to map every hardware-bound key `alias` (e.g., `"SignalSecret"`, `"NPCI_CL_KEY"`, `"BiometricAuthKey"`) back to its owning application!
   * If the key's `blobentry` remains hardware-wrapped by the TEE/StrongBox, log it in `case_cryptographic_keyring` with `key_accessibility = "HARDWARE_BOUND_UNAVAILABLE"`.

---

## 5. Step 3 — The Universal SQLCipher & WCDB Page-Level Decryption Engine

Why build a page-level SQLCipher decryptor instead of just calling a single external library binary?
1. Because different apps use incompatible SQLCipher versions (`v1`, `v2`, `v3`, `v4`, and Tencent `WCDB`), custom page sizes (`1024`, `4096`, `8192`), custom KDF iterations (`4000`, `64000`, `256000`), and custom HMAC algorithms (`SHA1`, `SHA256`, `SHA512`, or no HMAC).
2. Because you must also decrypt every page payload inside the companion **`-wal` file** without destroying historical WAL frames!

### 5.1 How a SQLCipher Encrypted Database Is Laid Out on Disk

Let $S_{\text{page}}$ be the page size (typically $4096\text{ bytes}$ for v4, or $1024\text{ bytes}$ for v3/WCDB).

#### 1. Page 1 Layout (Bytes $0\text{ through } S_{\text{page}} - 1$)
Unlike a plaintext SQLite file (which starts with `"SQLite format 3\0"`), Page 1 of a SQLCipher file has four distinct zones:
* **Bytes $0\text{–}15$ (`file_salt`, $16\text{ bytes}$):** Unencrypted random salt used for PBKDF2 key derivation.
* **Bytes $16\text{ through } (S_{\text{page}} - R - 1)$ (`encrypted_payload`):** AES-256-CBC ciphertext of Bytes $16\text{–}99$ of the SQLite header plus Page 1's B-Tree data. *(Notice its length is $S_{\text{page}} - R - 16$, which is always an exact multiple of the 16-byte AES block size!)*
* **Bytes $(S_{\text{page}} - R)\text{ through } (S_{\text{page}} - R + 15)$ (`page_iv`, $16\text{ bytes}$):** The 16-byte AES-CBC Initialization Vector (IV) for Page 1.
* **Bytes $(S_{\text{page}} - R + 16)\text{ through } (S_{\text{page}} - 1)$ (`page_hmac`, $H\text{ bytes}$):** The HMAC signature authenticating Page 1.
  * Here, the **Reserve Size ($R$)** at the end of every page is $R = 16 + H$ (padded to an even multiple of $16\text{ bytes}$ in SQLCipher v3/v4):
    * **For `HMAC_SHA1` ($20\text{-byte}$ digest, padded to $32\text{ bytes}$):** $R = 16\text{ (IV)} + 32\text{ (padded HMAC)} = \mathbf{48\text{ bytes}}$.
    * **For `HMAC_SHA256` ($32\text{-byte}$ digest):** $R = 16\text{ (IV)} + 32\text{ (HMAC)} = \mathbf{48\text{ bytes}}$.
    * **For `HMAC_SHA512` ($64\text{-byte}$ digest):** $R = 16\text{ (IV)} + 64\text{ (HMAC)} = \mathbf{80\text{ bytes}}$.

#### 2. Pages $2, 3, \dots, N$ Layout
On every subsequent page ($p \ge 2$), there is no 16-byte file salt at the beginning:
* **Bytes $0\text{ through } (S_{\text{page}} - R - 1)$ (`encrypted_payload`):** AES-256-CBC ciphertext of the entire usable page ($S_{\text{page}} - R\text{ bytes}$).
* **Bytes $(S_{\text{page}} - R)\text{ through } (S_{\text{page}} - R + 15)$ (`page_iv`, $16\text{ bytes}$):** The 16-byte AES-CBC IV for Page $p$.
* **Bytes $(S_{\text{page}} - R + 16)\text{ through } (S_{\text{page}} - 1)$ (`page_hmac`):** The HMAC signature for Page $p$.

---

### 5.2 Exact Key Derivation & HMAC Math (SQLCipher v3 & v4)

Given either a **Passphrase** (`password_bytes`), a **Raw 32-Byte AES Key**, or a **Raw 48-Byte Key + Salt Blob**:

1. **Step 1: Obtain the 32-Byte Encryption Key ($K_{\text{enc}}$) and 16-Byte Salt ($\text{salt}_{\text{enc}}$):**
   * **If input is a 48-Byte Raw Blob (e.g., Signal iOS `96-hex-char` key):**
     * $K_{\text{enc}} = \text{blob}[0 : 32]$ ($32\text{ bytes}$).
     * $\text{salt}_{\text{enc}} = \text{blob}[32 : 48]$ ($16\text{ bytes}$ — also verify this matches Bytes $0\text{–}15$ of Page 1!).
   * **If input is a 32-Byte Raw Key ($64\text{ hex chars}$):**
     * $K_{\text{enc}} = \text{blob}[0 : 32]$.
     * $\text{salt}_{\text{enc}} = \text{Page\_1}[0 : 16]$ (read directly from Bytes $0\text{–}15$ of the database file).
   * **If input is a Passphrase / Password string:**
     * Read $\text{salt}_{\text{enc}} = \text{Page\_1}[0 : 16]$.
     * Compute $K_{\text{enc}}$ ($32\text{ bytes}$) using **PBKDF2**:
       * In **SQLCipher v4**: `PBKDF2-HMAC-SHA512(password, salt_enc, iterations = 256000, dkLen = 32)`.
       * In **SQLCipher v3 / WCDB**: `PBKDF2-HMAC-SHA1(password, salt_enc, iterations = 64000, dkLen = 32)`.

2. **Step 2: Derive the 32-Byte HMAC Key ($K_{\text{mac}}$):**
   * Compute the **16-byte HMAC Salt ($\text{salt}_{\text{mac}}$)** by XORing every byte of $\text{salt}_{\text{enc}}$ with `0x3A`:
     $$\text{salt}_{\text{mac}}[i] = \text{salt}_{\text{enc}}[i] \oplus \text{0x3A} \quad \text{for } i = 0 \dots 15$$
   * Run **2 iterations** of PBKDF2 using $K_{\text{enc}}$ as the input password and $\text{salt}_{\text{mac}}$ as the salt:
     * In **SQLCipher v4**: $K_{\text{mac}} = \text{PBKDF2-HMAC-SHA512}(\text{password} = K_{\text{enc}}, \text{salt} = \text{salt}_{\text{mac}}, \text{iterations} = 2, \text{dkLen} = 32)$.
     * In **SQLCipher v3 / WCDB**: $K_{\text{mac}} = \text{PBKDF2-HMAC-SHA1}(\text{password} = K_{\text{enc}}, \text{salt} = \text{salt}_{\text{mac}}, \text{iterations} = 2, \text{dkLen} = 32)$.

3. **Step 3: Verify Page $p$'s HMAC Signature (for $p = 1, 2, \dots, N$):**
   * For **Page 1**: The message authenticated by the HMAC consists of `[Bytes 16 .. (S_page - R + 15)]` (that is, the `encrypted_payload` plus the 16-byte `page_iv`) followed by the 4-byte little-endian integer `01 00 00 00` (`uint32_le(1)`).
   * For **Page $p \ge 2$**: The message authenticated by the HMAC consists of `[Bytes 0 .. (S_page - R + 15)]` (`encrypted_payload` + `page_iv`) followed by the 4-byte little-endian page number `uint32_le(p)`.
   * Compute $\text{HMAC}(K_{\text{mac}}, \text{message})$ and compare it against `page_hmac`!

4. **Step 4: Decrypt Page $p$ and Reconstruct Plaintext SQLite Page:**
   * Decrypt `encrypted_payload` using **AES-256-CBC** (with **NO PKCS#7 padding removal**, because the payload is already an exact multiple of $16\text{ bytes}$!) using key $K_{\text{enc}}$ and IV `page_iv`.
   * **For Page 1 Only:**
     * Write the 16-byte ASCII header `"SQLite format 3\0"` (`53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00`) at Bytes $0\text{–}15$.
     * Write the decrypted payload ($S_{\text{page}} - R - 16\text{ bytes}$) starting at Byte $16$.
     * Ensure Byte $20$ of Page 1 (`reserved_bytes_per_page`) is set to $R$ (`48` or `80`), and zero-fill the final $R\text{ bytes}$ of the page (`0x00`).
     * **Sanity Check:** Verify that Bytes $21\text{–}23$ of the newly decrypted Page 1 equal `40 20 20` ($64, 32, 32$ — the invariant SQLite payload fractions)!
   * **For Page $p \ge 2$:**
     * *(Edge case: If all bytes of Page $p$ on disk are `0x00`, pass it through as an all-zero page without decrypting).*
     * Otherwise, write the decrypted payload ($S_{\text{page}} - R\text{ bytes}$) at Bytes $0\text{ through } (S_{\text{page}} - R - 1)$, and zero-fill the final $R\text{ bytes}$ (`0x00`).

---

### 5.3 The Automated Profile Prober (Zero-Configuration SQLCipher Detection)
Whenever Module 2.2 attempts to decrypt a database with a candidate key, it does not guess which SQLCipher version the app used. Instead, it tests Page 1 against an ordered table of **5 Standard Profiles**:

1. **Profile 1 (SQLCipher v4 Default):** $S_{\text{page}} = 4096$, $R = 80$, `HMAC_SHA512`, `PBKDF2_HMAC_SHA512`, $\text{iter} = 256000$.
2. **Profile 2 (SQLCipher v4 Custom 1024/16384):** Same as Profile 1, testing $S_{\text{page}} \in \{1024, 8192, 16384\}$.
3. **Profile 3 (SQLCipher v3 / WCDB Default):** $S_{\text{page}} = 1024$ (and $4096$), $R = 48$, `HMAC_SHA1`, `PBKDF2_HMAC_SHA1`, $\text{iter} = 64000$.
4. **Profile 4 (SQLCipher v2 / Fast WCDB):** $S_{\text{page}} = 1024$ (and $4096$), $R = 48$, `HMAC_SHA1`, `PBKDF2_HMAC_SHA1`, $\text{iter} = 4000$.
5. **Profile 5 (SQLCipher v1 / Raw No-HMAC):** $S_{\text{page}} = 1024$, $R = 16$ (IV only, no HMAC), `PBKDF2_HMAC_SHA1`, $\text{iter} = 4000$.

As soon as a profile produces a valid Page 1 HMAC match **and** decrypted Bytes $21\text{–}23$ equal `40 20 20`, lock in that profile and stream-decrypt the entire database!

---

### 5.4 How to Decrypt a Companion SQLCipher `-wal` File
If the encrypted SQLCipher database has a companion `<name>-wal` file:
1. Read the **32-byte WAL Header** at Bytes $0\text{–}31$: It is **unencrypted** (`0x377F0682` or `0x377F0683`). Copy those $32\text{ bytes}$ to `decrypted.db-wal`.
2. For each WAL Frame $i = 1, 2, \dots, N$ (starting at Byte Offset $32$, each of size $24 + S_{\text{page}}$):
   * Read the **24-byte WAL Frame Header**: It is **unencrypted**! Read `page_number = uint32_be(frame_hdr[0:4])`.
   * Read the **$S_{\text{page}}$-byte Frame Payload**: This payload is encrypted using the **exact same layout as Page `page_number`**!
     * **Important:** Even if `page_number == 1` inside a WAL frame, in SQLCipher v3/v4, a Page 1 frame inside the `-wal` file starts its encrypted payload at **Byte Offset $16$ of the frame payload** (Bytes $0\text{–}15$ of a Page 1 WAL payload hold the salt, just like Page 1 of the main `.db` file!). For all `page_number >= 2`, ciphertext starts at Byte Offset $0$ of the frame payload, and the HMAC uses `uint32_le(page_number)`.
   * Decrypt the frame payload using $K_{\text{enc}}$, zero-fill its trailing $R$ reserve bytes, **recompute the 8-byte SQLite WAL cumulative checksum `(s0, s1)`** (using the formula from Module 2.1 Section 6.2 so standard SQLite accepts the decrypted WAL frame!), update Bytes $16\text{–}23$ of the 24-byte frame header with the new `(s0, s1)`, and write the decrypted frame to `decrypted.db-wal`!

---

## 6. Step 4 — Exact Application Unwrapping Recipes

Module 2.2 comes pre-loaded with the exact cryptographic unwrapping recipes for the highest-priority encrypted targets:

### 6.1 Recipe 1: Signal iOS (`Signal.sqlite`)
* **Target Path:** `/private/var/mobile/Containers/Shared/AppGroup/<Signal-Group-UUID>/grdb/Signal.sqlite` (+ `-wal`).
* **Keyring Lookup:** Find entry where `svce == "OWSPrimaryStorage"` and `acct == "GRDBDatabaseCipherKeySpec"`.
* **Key Format:** 48-byte raw blob (`96 hex chars`): Bytes $0\text{–}31 = K_{\text{enc}}$, Bytes $32\text{–}47 = \text{salt}_{\text{enc}}$.
* **Profile:** SQLCipher v4 ($S_{\text{page}} = 4096$, $R = 80$, `HMAC_SHA512`).

### 6.2 Recipe 2: Signal Android (`signal.db`)
* **Target Path:** `/data/user/<id>/org.thoughtcrime.securesms/databases/signal.db` (+ `-wal`).
* **Step 1 (Read `shared_prefs`):** Open `/data/user/<id>/org.thoughtcrime.securesms/shared_prefs/org.thoughtcrime.securesms_preferences.xml`.
  * Check for legacy plaintext key `pref_database_unencrypted_secret` (if present on older builds, use directly).
  * On modern builds, read `pref_database_encrypted_secret`, which is a JSON string: `{"data":"<base64_ct>","iv":"<base64_iv>"}`.
* **Step 2 (Unwrap via Keystore Key `SignalSecret`):**
  * Look up alias `"SignalSecret"` for `org.thoughtcrime.securesms` in `case_cryptographic_keyring`.
  * If `UNWRAPPED_READY`: Decrypt `data` (where the last $16\text{ bytes}$ of `data` are the 128-bit GCM authentication tag) using **AES-256-GCM** with the unwrapped `"SignalSecret"` key and the 12-byte `iv`.
  * The decrypted plaintext is a **64-character hexadecimal string** (representing the 32-byte passphrase/key material).
* **Step 3 (Decrypt `signal.db`):** Feed the decrypted secret into the SQLCipher v4 engine ($S_{\text{page}} = 4096$, $R = 80$, `HMAC_SHA512`, `kdf_iter = 256000`).

### 6.3 Recipe 3: WhatsApp Android Local Backups (`.crypt12`, `.crypt14`, `.crypt15`)
* **Target Paths:** `/data/media/<id>/Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt14` (or `.crypt15` / `.crypt12`), and `/data/media/<id>/WhatsApp/Databases/...`.
* **For `.crypt12` & `.crypt14` Backups:**
  1. Read `/data/user/<id>/com.whatsapp/files/key` ($158\text{ bytes}$, starts with Java serialization magic `AC ED 00 05`).
  2. Extract the **32-byte AES key ($K_{\text{aes}}$)** at **Bytes $126\text{–}157$** (the final $32\text{ bytes}$ of the key file).
  3. **For `.crypt12`:** Read the 16-byte IV from Bytes $51\text{–}66$ of the `.crypt12` file; ciphertext runs from Byte $67$ to $(\text{EOF} - 20)$. Decrypt with AES-256-GCM and inflate with `zlib`.
  4. **For `.crypt14`:** Read Byte $0$ of the `.crypt14` file (or scan the protobuf header in the first $256\text{ bytes}$) to locate the **16-byte AES-GCM IV** and ciphertext start offset (verify by checking that the first decrypted block inflates via `zlib` to `"SQLite format 3\0"`!).
* **For `.crypt15` Backups (End-to-End Encrypted Backups):**
  1. **Obtain Root Key ($K_{\text{root}}$, $32\text{ bytes}$):**
     * Either read `/data/user/<id>/com.whatsapp/files/encrypted_backup.key` (if present in FFS extraction) OR accept the 64-character hex recovery key from the examiner.
  2. **Derive the 32-Byte Encryption Key ($K_{\text{enc}}$) via RFC 5869 HKDF-SHA256:**
     * Let $\text{salt} = 32\text{ zero bytes}$ (`0x00 * 32`).
     * Compute Extract Step: $\text{PRK} = \text{HMAC-SHA256}(\text{key} = \text{salt}, \text{msg} = K_{\text{root}})$.
     * Compute Expand Step: $K_{\text{enc}} = \text{HMAC-SHA256}(\text{key} = \text{PRK}, \text{msg} = \text{ASCII}(\text{"backup encryption"}) \parallel \text{0x01})$.
  3. **Parse the Dynamic `.crypt15` Protobuf Header:**
     * Read Byte $0$ (`protobuf_len`, `uint8`).
     * Check if Byte $1$ is `0x01` (feature flag byte present in newer `.crypt15` files; if Byte $1 == \text{0x01}$ and Byte $2 == \text{0x0A}$ [Protobuf Field 1 tag], the protobuf header starts at Byte $2$ and ends at Byte $2 + \text{protobuf\_len}$; otherwise it starts at Byte $1$ and ends at Byte $1 + \text{protobuf\_len}$).
     * Decode the Protobuf header using Module 2.3's Protobuf decoder to extract the **16-byte IV** (stored inside the nested `crypt15_metadata` field).
     * Immediately after the Protobuf header, the **AES-256-GCM ciphertext** begins and runs until $(\text{EOF} - 32)$ (where the final $32\text{ bytes}$ consist of the **16-byte AES-GCM Authentication Tag** followed by a **16-byte MD5 file checksum**).
     * Decrypt with AES-256-GCM and decompress the `zlib` stream into a plaintext SQLite database!

### 6.4 Recipe 4: WeChat (`EnMicroMsg.db` — Tencent WCDB)
* **Target Path:** `/data/user/<id>/com.tencent.mm/MicroMsg/<32_char_md5_dir>/EnMicroMsg.db`.
* **Key Derivation Formula:**
  1. Read `_auth_uin` (32-bit signed integer, e.g., `-1098765432`) from `shared_prefs/auth_info_key_prefs.xml` or `system_config_prefs.xml`.
  2. Read the device IMEI string from `shared_prefs/system_config_prefs.xml` or `files/KeyInfo.bin`. In addition to any discovered hardware IMEI, **always also test the default Android 10–17 fallback string `"1234567890ABCDEF"`**!
  3. Concatenate the ASCII string: $\text{seed} = \text{IMEI\_string} \parallel \text{str}(\text{signed\_uin})$.
  4. Compute `md5_hex = lowercase_hex(MD5(UTF8(seed)))`.
  5. Extract the first $7\text{ characters}$: `wcdb_password = md5_hex[0 : 7]`.
  6. Pass `wcdb_password` to the Profile 3 (`WCDB`) decryptor ($S_{\text{page}} = 1024$, $R = 48$, `HMAC_SHA1`, `PBKDF2_HMAC_SHA1`, $\text{iter} = 64000$).

### 6.5 Recipe 5: Password-Protected Apple Notes (`NoteStore.sqlite` Row-Level Decryption)
In Apple Notes (`/private/var/mobile/Containers/Shared/AppGroup/group.com.apple.notes/NoteStore.sqlite`), the SQLite database itself is **plaintext**, but individual locked notes have their gzipped protobuf body (`ZDATA` in `ZICCLOUDSYNCINGOBJECT`) encrypted with AES-GCM/AES-KeyWrap:
* For every row where `ZISPASSWORDPROTECTED == 1`:
  * Extract `ZCRYPTOITERATIONCOUNT`, `ZCRYPTOSALT` ($16\text{ bytes}$), `ZCRYPTOINITIALIZATIONVECTOR` ($16\text{ bytes}$), `ZCRYPTOTAG` ($16\text{ bytes}$), and `ZCRYPTOWRAPPEDKEY` ($40\text{ bytes}$).
  * Check `case_cryptographic_keyring` for the Apple Notes password/key (or test examiner-supplied candidate passwords):
    * Run `KEK = PBKDF2-HMAC-SHA256(password, ZCRYPTOSALT, ZCRYPTOITERATIONCOUNT, dkLen = 16)`.
    * Unwrap `ZCRYPTOWRAPPEDKEY` using **RFC 3394 AES-128 Key Unwrap** with `KEK`.
    * If the 8-byte RFC 3394 integrity prefix equals `0xA6A6A6A6A6A6A6A6`, use the unwrapped 16-byte key + `ZCRYPTOINITIALIZATIONVECTOR` + `ZCRYPTOTAG` to decrypt `ZDATA` via AES-128-GCM and gunzip the note body!

---

## 7. Database Schema for Module 2.2 (`cryptographic_key_broker.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `case_cryptographic_keyring` (Central Key & Credential Vault)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `key_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each harvested key, blob, or password. |
| `source_category` | `TEXT` | `NOT NULL` | Enum: `IOS_VENDOR_KEYCHAIN_EXPORT`, `IOS_BACKUP_KEYCHAIN_PLIST`, `IOS_RAW_KEYCHAIN_DB`, `ANDROID_SANDBOX_KEY_FILE`, `ANDROID_SHARED_PREFS`, `ANDROID_KEYSTORE_2_DB`, `DERIVED_FORMULA`, `EXAMINER_SUPPLIED`. |
| `app_instance_id` | `INTEGER` | `NULL` | Foreign key to owning app in `resolved_application_catalog` (Module 1.3). |
| `access_group_or_pkg` | `TEXT` | `NULL` | iOS `agrp` or Android package name (e.g., `org.thoughtcrime.securesms`). |
| `service_or_alias` | `TEXT` | `NULL` | Keychain `svce` (e.g., `OWSPrimaryStorage`), XML key, or Keystore alias (`SignalSecret`). |
| `account_name` | `TEXT` | `NULL` | Keychain `acct` (e.g., `GRDBDatabaseCipherKeySpec`). |
| `protection_class_domain` | `TEXT` | `NULL` | E.g., `ck`, `dk`, `ak`, `cku`, `TEE_STRONG_BOX`, `PLAINTEXT_SANDBOX`. |
| `key_accessibility` | `TEXT` | `NOT NULL` | Enum: `UNWRAPPED_READY`, `WRAPPED_NEEDS_USER_PASSWORD`, `HARDWARE_BOUND_UNAVAILABLE`. |
| `key_format_type` | `TEXT` | `NOT NULL` | Enum: `RAW_AES_256_HEX_64`, `RAW_KEY_AND_SALT_HEX_96`, `PASSPHRASE_UTF8`, `AES_GCM_JSON_BLOB`, `TINK_KEYSET`, `OPAQUE_HARDWARE_BLOB`. |
| `unwrapped_key_hex` | `TEXT` | `NULL` | Lowercase hexadecimal string of the ready-to-use key material (populated when `UNWRAPPED_READY`). |
| `created_utc_iso` | `TEXT` | `NULL` | Key creation timestamp (`cdat`), normalized via Module 1.2. |
| `modified_utc_iso` | `TEXT` | `NULL` | Key modification timestamp (`mdat`), normalized via Module 1.2. |

### Table 2: `encrypted_database_registry` (Tracking Every Encrypted File & Its Unwrap State)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `enc_target_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each detected encrypted database or backup container. |
| `vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `vfs_index.file_id` (Module 1.1). |
| `app_instance_id` | `INTEGER` | `NULL` | Foreign key to owning application in Module 1.3. |
| `canonical_path` | `TEXT` | `NOT NULL` | Normalized device path of the encrypted file. |
| `encryption_scheme` | `TEXT` | `NOT NULL` | Enum: `SQLCIPHER_V4`, `SQLCIPHER_V3`, `TENCENT_WCDB`, `WHATSAPP_CRYPT14`, `WHATSAPP_CRYPT15`, `JETPACK_TINK_XML`, `REALM_ENCRYPTED`, `UNKNOWN_HIGH_ENTROPY`. |
| `matched_key_id` | `INTEGER` | `NULL` | Foreign key to `case_cryptographic_keyring.key_id` (if a matching key record was found). |
| `decryption_status` | `TEXT` | `NOT NULL` | Enum: `DECRYPTED_VERIFIED`, `AWAITING_EXAMINER_KEY`, `BLOCKED_BY_HARDWARE_TEE_SEP`, `DECRYPTION_FAILED_BAD_KEY`. |
| `derivative_staging_id` | `INTEGER` | `NULL` | Foreign key to `derivative_staging_ledger.staging_id` (Module 1.2 `Product B2` plaintext output). |
| `decrypted_wal_frames` | `INTEGER` | `DEFAULT 0` | Count of companion `-wal` frames successfully decrypted alongside the main DB. |

---

## 8. Developer Acceptance Test Checklist for Module 2.2

1. **The Signal iOS 96-Hex-Char Key + WAL Decryption Test:** Create a SQLCipher v4 database (`page_size = 4096`) in WAL mode, insert 10 messages (leaving 5 in the `-wal` file), and extract its 32-byte key + 16-byte salt as a 96-character hex string. Run Module 2.2's Recipe 1 decryptor. Verify that both `Signal_decrypted.sqlite` and `Signal_decrypted.sqlite-wal` are produced, that Bytes $0\text{–}15$ of Page 1 equal `"SQLite format 3\0"`, that Header Byte $20$ equals `80`, and that Module 2.1 recovers all 10 messages!
2. **The WhatsApp `.crypt15` HKDF & Dynamic Protobuf Header Test:** Using a known 32-byte `.crypt15` root key (`64 hex chars`), derive $K_{\text{enc}}$ via Section 6.3's HKDF-SHA256 `"backup encryption"` formula, parse a test `.crypt15` header, decrypt the AES-256-GCM stream, and inflate via `zlib`. Verify the resulting `Product B2` file passes SQLite `PRAGMA integrity_check;`.
3. **The WeChat WCDB 7-Character MD5 Formula Test:** Pass `IMEI = "1234567890ABCDEF"` and `UIN = "-1357924680"` into Recipe 4. Verify that the derived 7-character lowercase MD5 prefix matches `md5("1234567890ABCDEF-1357924680")[0:7]` and successfully validates Page 1 under Profile 3 (`WCDB`).
4. **The Hardware-Gated Dimension B Audit Test:** Load an Android FFS extraction containing `signal.db` and `/data/misc/keystore/persistent.sqlite` where no unwrapped TEE key export is present. Verify that Module 2.2 maps `persistent.sqlite` namespace UID to `org.thoughtcrime.securesms`, logs `SignalSecret` as `HARDWARE_BOUND_UNAVAILABLE`, and automatically updates **Module 1.4 Dimension B** to `ENCRYPTED_GATED_BY_HARDWARE`.