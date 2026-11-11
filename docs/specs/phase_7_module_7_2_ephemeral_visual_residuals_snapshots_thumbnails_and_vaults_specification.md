# Engineering Specification: Phase 7, Module 7.2 — Ephemeral Visual Residuals: OS App-Switcher Snapshots (`SplashBoard` & `snapshots`), Thumbnail Caches (`.ithmb`, Glide, Fresco, Kingfisher) & Disguised Calculator Vault Unmasking

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 7.2** of the Forensic Data Parser (corresponding to **Groups 3, 5, 11, 13, 15, and 16** of the Unified Master Register). It contains **zero programming code** and explains how to decode iOS `SplashBoard` `.ktx` (`Khronos Texture` `ASTC`/`BGRA`) and Android `TaskSnapshots` (`<task_id>.jpg` + `.proto`) app-switcher screen captures, how to reconstruct raw pixel arrays from iOS `.ithmb` thumbnail containers and third-party `Glide` / `Fresco` / `Kingfisher` / `SDWebImage` LRU caches, and how to unmask files hidden inside Disguised Calculator & Privacy Vault apps (`Calculator+`, `Hide It Pro`, `KeepSafe`, `Gallery Vault`) from first principles.

---

## 1. Purpose & Mental Model (Why Visual Residuals Defeat Disappearing Messages & Permanent File Deletion)

When a suspect uses **Disappearing Messages** (in Signal, Telegram Secret Chats, WhatsApp View-Once, or Snapchat), views a **crypto wallet balance or seed phrase** (in TronLink or MetaMask), or **permanently empties the "Recently Deleted" trash** after deleting incriminating photos, they assume the visual evidence is gone forever.

In reality, mobile operating systems and UI frameworks constantly create **three hidden layers of visual residuals** behind the user's back:

1. **Layer 1 — OS App-Switcher Multitasking Snapshots (iOS `SplashBoard` & Android `TaskSnapshots`):**
   * Every time a user presses the Home button, swipes up to switch apps, or locks the screen while an app is open, the operating system's window compositor (`SpringBoard` on iOS; `WindowManagerService` on Android) **automatically takes a high-resolution screenshot of the active app window** and writes it to disk so the OS can render a smooth animation in the App Switcher carousel!
   * **Forensic Impact:** If a suspect was reading a Telegram Secret Chat, viewing a "View-Once" photo, looking at a hawala ledger in Google Sheets, or checking their `TronLink Pro` USDT balance when they swiped up to switch apps or locked the phone, **the OS secretly saved a full-screen snapshot of that exact screen to disk**!
2. **Layer 2 — Persistent Thumbnail & Image-Loader Disk Caches (`.ithmb`, `.thumbdata4`, `Glide`, `Fresco`, `Kingfisher`, `SDWebImage`):**
   * When a user permanently deletes a photo from `/DCIM/` (and empties the Trash), or when a dating profile (`Tinder`/`Bumble`), Telegram channel, or e-commerce app loads an image, the low-to-medium resolution **Thumbnail** frequently survives inside pre-allocated binary `.ithmb` / `.thumbdata4` containers or inside the app's `/cache/image_manager_disk_cache/` (`DiskLruCache`) folder!
3. **Layer 3 — Disguised "Calculator" & Audio-Manager Media Vaults:**
   * Suspects hide incriminating photos, videos, and PDFs inside "Fake Calculator" or "Fake Audio Manager" apps (`Calculator+`, `Hide It Pro`, `KeepSafe`, `Gallery Vault`). Over $75\%$ of these vault apps do **not** use real full-file AES encryption (because decrypting a $500\text{ MB}$ video on a phone CPU would cause lag)—instead, they simply move the file to a hidden dot-folder, rename the extension to `.bin` / `.dat` / `.lock`, and **XOR or byte-swap the first $16\text{ to }512\text{ bytes}$ of the file header**!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Visual Residual Forensics

Before implementing Module 7.2, the developer must understand six critical traps:

### Mistake 1: Skipping iOS `.ktx` (`Khronos Texture`) Files in `SplashBoard` Because Standard Image Viewers Cannot Open Them
* **The Trap:** Scanning `/Library/SplashBoard/Snapshots/` on iOS for `.jpg` and `.png` files only, and ignoring files ending in **`.ktx`**.
* **Why It Fails:** To accelerate GPU rendering in the iOS App Switcher, Apple stores `SplashBoard` multitasking snapshots inside **`.ktx` (`Khronos Texture 1.1`)** container files encoded with **`ASTC` (`Adaptive Scalable Texture Compression`)** or raw **`BGRA8888`** pixel buffers (often compressed with `LZFSE` / `zlib`)! If your parser cannot unpack `.ktx` headers and decode `ASTC` / `BGRA` textures into standard `.png` files, the examiner will miss the majority of iOS App-Switcher screen captures!
* **The Rule:** Implement the **`.ktx` (`«KTX 11»`) Texture Unpacker & PNG Converter** specified in Section 3.1.

### Mistake 2: Ignoring the Companion `<task_id>.proto` File Next to Android `snapshots/<task_id>.jpg`
* **The Trap:** Extracting `1042.jpg` from `/data/system_ce/0/snapshots/1042.jpg` on Android without parsing `/data/system_ce/0/snapshots/1042.proto`.
* **Why It Fails:** The filename `1042.jpg` is just an arbitrary integer Android `task_id`! If you don't parse the companion **`1042.proto`** file (`TaskSnapshotProto`), you won't know **which app package and which exact `Activity` class** (e.g., `com.phonepe.app/.ui.TransactionSuccessActivity` or `org.telegram.messenger/org.telegram.ui.LaunchActivity`) produced that screenshot!
* **The Rule:** Always pair `<task_id>.jpg` and `<task_id>_reduced.jpg` with `<task_id>.proto` (Section 3.2).

### Mistake 3: Misaligned Row-Stride Padding When Reconstructing iOS `.ithmb` Raw Pixel Buffers
* **The Trap:** Reading $W \times H \times \text{bytes\_per\_pixel}$ bytes from an iOS `.ithmb` file and rendering it directly as a $W \times H$ image, resulting in a diagonally skewed, garbled "venetian blind" image.
* **Why It Fails:** iOS `.ithmb` files store raw uncompressed bitmap slots (`RGB555`, `RGB565`, `BGRA8888`, or `YCbCr`) where each horizontal scanline is padded to a **16-byte or 32-byte hardware memory alignment boundary (`row_bytes_stride`)**! For example, a $120 \times 120$ thumbnail at $2\text{ bytes/pixel}$ has $240\text{ active bytes/row}$, which may be padded to $256\text{ bytes/row}$ (`stride = 256`)!
* **The Rule:** Always read each scanline using the exact `bytes_per_row` stride defined for that `.ithmb` format ID (Section 4.1).

### Mistake 4: Parsing `Glide` / `DiskLruCache` Image Files (`*.0`) Without Reading the Companion `journal` File
* **The Trap:** Copying cached image files (`<64_hex_sha256>.0`) out of `/cache/image_manager_disk_cache/` without parsing the plaintext `journal` file in the same folder.
* **Why It Fails:** The `journal` file inside every `DiskLruCache` / `Glide` directory logs the chronological sequence of `DIRTY`, `CLEAN`, `READ`, and `REMOVE` operations for each cache key! Furthermore, `REMOVE <64_hex_key>` entries in `journal` prove that an image was cached and subsequently evicted/deleted!
* **The Rule:** Parse the `journal` file and inspect `DiskLruCache` headers to link each cached image back to its source URL and access state (Section 4.3).

### Mistake 5: Giving Up on Disguised Vault Files When They Have Corrupted Magic Bytes
* **The Trap:** Running a file-type signature check (`magic`) on files inside `/sdcard/.AudioManager/` or `/data/user/0/com.flatfish.cal.privacy/files/`, seeing that Bytes $0\text{–}3$ do not match `FF D8 FF` (JPEG) or `89 50 4E 47` (PNG), and classifying them as "Encrypted / Unreadable."
* **Why It Fails:** Popular vault apps obfuscate files by **XORing the first $N\text{ bytes}$** ($N \in \{16, 32, 64, 128, 256, 512, 1024\}$) with a fixed 1-byte or 4-byte key, or by **reversing the order of the first $128\text{ bytes}$**, while Bytes $N\text{ through }\text{EOF}$ are **100% plaintext JPEG/MP4 data** (for example, the JPEG quantization table `FF DB`, Huffman table `FF C4`, Start-of-Scan `FF DA`, and End-of-Image `FF D9` at the end of the file are completely untouched in plaintext!).
* **The Rule:** Implement the **Known-Plaintext Header XOR & Byte-Swap Recovery Engine** in Section 5.2!

### Mistake 6: Failing to Pass Recovered Snapshots, Thumbnails & Unmasked Vault Images Into Phase 7's QR & OCR Engines
* **The Trap:** Extracting an App-Switcher snapshot or an unmasked vault image and displaying it only in a gallery tab without running QR decoding and OCR on it.
* **Why It Fails:** App-Switcher snapshots and vault images frequently contain **UPI Payment Receipts (with 12-digit UTRs)**, **QR Codes**, **Aadhaar/PAN cards**, and **12-word `BIP-39` crypto seed phrases**!
* **The Rule:** Every visual artifact recovered in Module 7.2 must be automatically queued into **Module 7.3 (QR/Barcode Decoder)** and **Module 7.4 (Offline Multilingual OCR)**.

---

## 3. Step 1 — Sub-Engine 7.2A: OS App-Switcher Multitasking Snapshots (`SplashBoard` & `TaskSnapshots`)

### 3.1 iOS `SplashBoard` Snapshot & `.ktx` Texture Decoder

1. **Locate All `SplashBoard` Directories in `vfs_index`:**
   * System/Global Snapshot Store: `/private/var/mobile/Library/SplashBoard/Snapshots/<BundleID> - <SceneID>/`
   * Per-App Sandbox Snapshot Store: `/private/var/mobile/Containers/Data/Application/<App-UUID>/Library/SplashBoard/Snapshots/`
2. **Inspect Snapshot Files & `scene-manifest.plist`:**
   * Inside each app's `SplashBoard/Snapshots/` folder sit files named `<UUID>.ktx`, `<UUID>.jpeg`, `<UUID>.heic`, or `<UUID>.png`, along with plist metadata recording the screen dimensions, orientation (`Portrait` vs. `Landscape`), interface style (`Light` vs. `Dark`), and creation/modification timestamps (`btime` / `mtime` from Module 1.2).
3. **Step-by-Step Binary Decoding of Apple `.ktx` (`Khronos Texture 1.1`) Files:**
   * **Check 1 (Decompress Outer `LZFSE` / `zlib` Wrapper if Present):**
     * If Bytes $0\text{–}3$ equal `62 76 78 32` (`"bvx2"` / `"bvxn"` — Apple `LZFSE` compression) or `1F 8B 08` (Gzip): decompress the stream first to reveal the `.ktx` container!
   * **Check 2 (Read the 64-Byte `KTX 1.1` Header):**
     * **Bytes $0\text{–}11$ (`identifier`, $12\text{ bytes}$):** Must equal **`AB 4B 54 58 20 31 31 BB 0D 0A 1A 0A`** (`«KTX 11»\r\n\x1a\n`).
     * **Bytes $12\text{–}15$ (`endianness`, `uint32_le`):** Equals `0x04030201` (confirming Little-Endian!).
     * **Bytes $16\text{–}19$ (`glType`, `uint32_le`)** & **Bytes $24\text{–}27$ (`glFormat`, `uint32_le`).**
     * **Bytes $28\text{–}31$ (`glInternalFormat`, `uint32_le`):**
       * `0x93B0` (`37808`) to `0x93BD` / `0x93D0` to `0x93DD`: **`GL_COMPRESSED_RGBA_ASTC_4x4_KHR` (or `8x8` / `6x6` `ASTC` compressed texture blocks!)**.
       * `0x80E1` / `0x93A1` (`GL_BGRA8_EXT` / `BGRA8888`): Uncompressed 4-bytes-per-pixel `BGRA` bitmap!
     * **Bytes $36\text{–}39$ (`pixelWidth`, `uint32_le`):** Image width $W$ in pixels!
     * **Bytes $40\text{–}43$ (`pixelHeight`, `uint32_le`):** Image height $H$ in pixels!
     * **Bytes $60\text{–}63$ (`bytesOfKeyValueData`, `uint32_le`):** Length $K_{\text{kv}}$ of the metadata key-value block immediately following Byte $63$.
   * **Check 3 (Decode the Image Data Starting at Byte Offset $64 + K_{\text{kv}}$):**
     * Read `imageSize = uint32_le(buf[64 + K_kv : 68 + K_kv])`.
     * The raw texture payload sits at `buf[68 + K_kv : 68 + K_kv + imageSize]`.
     * Decompress the `ASTC` blocks (or read the `BGRA8888` rows), convert to a standard lossless **`.png` derivative (`Product B2`)** in the staging workspace, hash it via Module 1.2, and associate it with its owning `BundleID`!

### 3.2 Android `TaskSnapshots` (`/data/system_ce/<user_id>/snapshots/`) Decoder

Across every Android user profile (`0`, `10`, `95`, `150`, `999`), scan `/data/system_ce/<user_id>/snapshots/` (and `/data/system/recent_images/` on older Android builds):

1. **Group Files by `<task_id>` Integer Stem:**
   * `<task_id>.proto`: Binary Protocol Buffer (`TaskSnapshotProto`).
   * `<task_id>.jpg`: Full-resolution JPEG screenshot of the app window at the moment it left the foreground!
   * `<task_id>_reduced.jpg`: Reduced-scale JPEG thumbnail of the same window.
2. **Decode `<task_id>.proto` via Phase 2, Module 2.3D (Schema-Less Protobuf Decoder):**
   * **Field 1 (`orientation`, `int32`):** `1` = Portrait, `2` = Landscape.
   * **Field 2 (`inset_left`, `top`, `right`, `bottom`).**
   * **Field 3 (`is_real_snapshot`, `bool`):** `1` (`true`) = **Real live screen capture of the user's content**; `0` (`false`) = Placeholder/splash screen because `FLAG_SECURE` blocked screen capture.
   * **Field 4 (`windowing_mode`, `int32`):** `1` = Fullscreen, `3`/`4` = Split-Screen, `5` = Freeform/Pop-up window!
   * **Field 5 (`system_ui_visibility`).**
   * **Field 6 (`is_translucent`, `bool`).**
   * **Field 7 (`top_activity_component`, `UTF-8 String`):** **The exact `package_name/activity_class_name` captured in `<task_id>.jpg`** (e.g., `"com.whatsapp/com.whatsapp.Conversation"`, `"com.tronlinkpro.wallet/.activity.AssetMainActivity"`, `"com.phonepe.app/.ui.HistoryActivity"`)!
   * **Field 9 (`id`, `int64`):** Unique snapshot identifier.
3. **Timestamp Attribution:**
   * Extract the exact filesystem `mtime` and `btime` (down to nanosecond precision via Module 1.2) of `<task_id>.jpg` and `<task_id>.proto`—which records the **exact second the user swiped away from or locked that screen**!

---

## 4. Step 2 — Sub-Engine 7.2B: OS & Third-Party Thumbnail Cache Reconstructors (`.ithmb`, `.thumbdata4`, `Glide`, `Fresco`, `Kingfisher`, `SDWebImage`)

### 4.1 iOS `.ithmb` Raw Bitmap Reconstructor & Orphaned Deleted-Photo Detector

* **Canonical Target Paths:** `/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_xxxx.JPG/*.ithmb` OR pre-allocated container files `/private/var/mobile/Media/PhotoData/Thumbnails/*.ithmb` (`3303.ithmb`, `3309.ithmb`, `3319.ithmb`, `4005.ithmb`, `4142.ithmb`, etc.).

1. **Case A — Per-Folder Modern iOS `.ithmb` / `.ktx` Thumbnails (`/Thumbnails/V2/DCIM/...`):**
   * In modern iOS, `/PhotoData/Thumbnails/V2/DCIM/<folder>/<filename>/` stores individual thumbnail files (`5003.JPG` or `5005.ktx`).
   * **Orphaned Deleted-Photo Check:** Cross-check every folder `/Thumbnails/V2/DCIM/<folder>/<filename>/` against `/private/var/mobile/Media/DCIM/<folder>/<filename>`. If the main photo in `/Media/DCIM/` was **permanently deleted**, the surviving thumbnail in `/Thumbnails/V2/` is flagged as **`RESIDUAL_RECORD (Surviving Thumbnail of Permanently Purged Photo)`**!
2. **Case B — Consolidated Pre-Allocated `.ithmb` Slot Containers:**
   * Each consolidated `.ithmb` file consists of fixed-size byte slots of length $S_{\text{slot}}$ (defined by the format ID in `thumbnailConfiguration`: e.g., $W \times H$ pixels with row stride $R_{\text{stride}}$ plus a 28-to-64 byte slot footer).
   * For every slot index $k = 0, 1, \dots, N-1$ at byte offset $k \times S_{\text{slot}}$:
     * Check if the slot is non-zero.
     * Reconstruct the raw pixel buffer (`BGRA8888`, `RGB565`, or `YCbCr`) using row stride $R_{\text{stride}}$ into a `.png` file.
     * Cross-reference slot index $k$ against `ZASSET.ZTHUMBNAILINDEX` in `Photos.sqlite` (from Module 7.1):
       * **If no active row in `ZASSET` has `ZTHUMBNAILINDEX == k`:** Slot $k$ is an **Orphaned Thumbnail of a Permanently Deleted Photo**! Flag it as **`RESIDUAL_RECORD (Orphaned .ithmb Slot #k — Parent Photo Purged)`**!

### 4.2 Android `.thumbdata4-*` & `/sdcard/Pictures/.thumbnails/` Carver

Scan `/data/media/<id>/DCIM/.thumbnails/` and `/data/media/<id>/Pictures/.thumbnails/`:
* Inside `.thumbdata3-*` and `.thumbdata4-*` indexed container files, scan for contiguous **JPEG Start-Of-Image (`FF D8 FF`) to End-Of-Image (`FF D9`)** byte streams, carve each embedded JPEG thumbnail, and cross-check its index/hash against `external.db` (`Module 7.1`) to flag thumbnails of deleted images!

### 4.3 Third-Party App Disk Image Caches (`Glide`, `Fresco`, `Kingfisher`, `SDWebImage`, `Coil`)

Almost every Android and iOS app (including **Telegram**, **WhatsApp**, **Tinder**, **Bumble**, **Grindr**, **Instagram**, **PhonePe**, **Paytm**, **OLX**, and **Binance**) uses one of five standard image-caching libraries inside its `/cache/` directory:

| Image Loader Library | Sandbox Directory Path Pattern | On-Disk File Structure & Forensic Extraction Rule |
|---|---|---|
| **1. `Glide` (`DiskLruCache`)** (Used by 70%+ of Android apps: Tinder, Telegram, UPI apps) | `/data/user/<id>/<pkg>/cache/image_manager_disk_cache/` | • Contains a plaintext **`journal`** file plus `<64_hex_sha256_key>.0` image files (JPEG, PNG, WebP, GIF).<br>• Parse `journal`: Lines starting with `CLEAN <key> <size>`, `DIRTY <key>`, `READ <key>`, and **`REMOVE <key>` (evicted/deleted cache item!)**.<br>• Inspect every `.0` file (and carve any unlinked/evicted blocks) and link to the owning app! |
| **2. `Fresco` (Meta / React Native)** | `/cache/image_cache/v2.ols100.1/` | Stores files named `<hash>.cnt` (raw JPEG/WebP/PNG bytes) inside 2-digit numbered subfolders (`00/`..`99/`). |
| **3. `Coil` / `OkHttp` Image Cache** | `/cache/image_cache/` | Pairs `<hash>.0` (HTTP metadata/headers including the **original source URL**!) with `<hash>.1` (the raw image bytes!). Always read `.0` to get the exact URL and server timestamp of `.1`! |
| **4. `SDWebImage` & `Kingfisher` (iOS)** | `<App-UUID>/Library/Caches/com.hackemist.SDImageCache/default/` or `com.onevcat.Kingfisher.ImageCache.*/` | Stores cached images named by the **MD5 or SHA-256 hash of the original download URL**. Cross-check against URL strings found in the app's SQLite/WebView databases by hashing discovered URLs and matching the filename! |

---

## 5. Step 3 — Sub-Engine 7.2C: Disguised "Calculator" Vaults, Private OEM Safe Folders & Header-Obfuscation Unmasker

### 5.1 Master Target Catalog of 12 Disguised Vault & Media-Hider Apps

Query **Module 1.3 (`resolve_app_targets`)** (and scan `/data/media/<id>/` for hidden dot-directories even if the vault app was uninstalled!) for the following 12 priority vault ecosystems:

| Vault App Name ( & Disguised Icon Label) | Android Package / iOS Bundle ID | Hidden Storage Directory Path(s) on Device | Encryption / Obfuscation Mechanism Used |
|---|---|---|---|
| **1. `Hide It Pro` (Disguised as `"Audio Manager"`)** | `com.hideitpro` | `/sdcard/ProgramData/Android/Language/.fr/` or `/sdcard/.AudioManager/` | Plaintext files with renamed extensions, OR AES-encrypted `.hip` files (PIN/password often stored in plaintext or Base64 inside `/data/user/0/com.hideitpro/shared_prefs/hideitpro_prefs.xml`!). |
| **2. `Calculator+ / Calculator Vault`** | `com.flatfish.cal.privacy`, `com.hld.anzenbokusucal` | `/sdcard/.calculator/` or `/data/user/<id>/<pkg>/files/vault/` | **Header XOR / Byte-Swap Obfuscation** (first $128\text{–}512\text{ bytes}$ XORed) + SQLite index table (`vault.db` / `files.db`) storing original filenames and lock timestamps! |
| **3. `KeepSafe Photo Vault`** | `com.keepsafe.vault` (`com.kii.safe`) | `/sdcard/.keepsafe/` or `/Android/data/com.keepsafe.vault/files/` | SQLite `keepsafe.db` + obfuscated/encrypted `.ks` / `.kSD` files (check `shared_prefs` & Keychain for PIN/key!). |
| **4. `Gallery Vault — Hide Pictures`** | `com.thinkyeah.galleryvault` | `/sdcard/.galleryvault_DoNotDelete_*/` | Custom header wrapper + XOR/AES key stored in `/data/user/0/com.thinkyeah.galleryvault/shared_prefs/`. |
| **5. `Vault — Hide SMS, Pics & Videos` (`NQ Vault`)** | `com.netqin.ps` | `/sdcard/SystemAndroid/` or `/sdcard/.bin/` | **1-Byte XOR Obfuscation on the first $128\text{ bytes}$** of every `.bin` file! (Instantly reversible via Section 5.2!). |
| **6. `AppLock` (`DoMobile`)** | `com.domobile.applock`, `com.domobile.applockwatcher` | `/sdcard/.domobile/` or `/sdcard/.ava/` | Header byte-shuffling / XOR + SQLite metadata table mapping `.lock` files back to original `/DCIM/` paths! |
| **7. `Folder Lock` & `Vaulty`** | `com.newsoftwares.folderlock_v1`, `com.stoik.mdscan` (`com.hide.vaulty`) | `/sdcard/FolderLock/` or `/sdcard/.vaulty/` | `.vdata` header prefix / XOR obfuscation. |
| **8. OEM Built-In Private Safe (`Xiaomi`, `Vivo`, `Oppo/Realme/OnePlus`)** | • Xiaomi: `com.miui.gallery` (`/sdcard/MIUI/Gallery/cloud/.secretAlbum/`)<br>• Vivo: `com.vivo.imanager`<br>• Oppo/Realme: `com.coloros.encryption` | `/sdcard/MIUI/Gallery/cloud/.secretAlbum/`, `/sdcard/.safebox/`, `/data/system_ce/0/private_safe/` | Xiaomi `.sa` files and Vivo/Oppo safebox files—inspect companion SQLite database for original filenames and apply header restoration or Keystore unwrap! |

### 5.2 The Universal Known-Plaintext Header XOR & Byte-Swap Unmasking Algorithm

Whenever Sub-Engine 7.2C encounters an unknown `.bin`, `.lock`, `.dat`, `.sa`, `.vdata`, or extensionless file of size $> 4\text{ KB}$ inside a vault directory whose first $4\text{ bytes}$ do **not** match a standard media magic header, it executes a **3-Stage Mathematical Unmasking Test**:

#### Stage 1: Check the Unencrypted Tail & Body Signatures (Confirming Header-Only Obfuscation!)
Inspect Bytes $1024\text{ through }\text{EOF}$ of the file:
* **Test A (JPEG Body & Trailer):** Does the file end with `FF D9` (JPEG End-Of-Image) at `buf[file_size - 2 : file_size]`, AND contain `FF DB` (Quantization Table), `FF C4` (Huffman Table), and `FF DA` (Start of Scan) inside the first $64\text{ KB}$?
  * **If YES:** The file is a **JPEG whose first $N\text{ bytes}$ ($N \in \{16, 32, 64, 128, 256, 512, 1024\}$) were XORed or byte-swapped**!
* **Test B (MP4 / MOV Body):** Does the file contain plaintext `6D 6F 6F 76` (`"moov"`), `6D 76 68 64` (`"mvhd"`), `74 72 61 6B` (`"trak"`), and `6D 64 61 74` (`"mdat"`) boxes past Byte $64$?
  * **If YES:** The file is an **MP4/MOV video whose `ftyp` header was XORed or byte-swapped**!
* **Test C (PNG Body & Trailer):** Does the file end with `49 45 4E 44 AE 42 60 82` (`IEND` chunk) and contain `49 44 41 54` (`IDAT`) chunks?
  * **If YES:** The file is a **PNG whose header was XORed or byte-swapped**!

#### Stage 2: Recover the Exact XOR Key ($K_{\text{xor}}$) via Known-Plaintext Attack (`KPA`)
Because every standard file format starts with known invariant magic bytes $M$:
* For **JPEG:** $M[0 : 3] = \texttt{FF D8 FF}$ (and Bytes $6\text{–}10 = \texttt{4A 46 49 46 00}$ `"JFIF\0"` or $\texttt{45 78 69 66 00}$ `"Exif\0"`).
* For **PNG:** $M[0 : 8] = \texttt{89 50 4E 47 0D 0A 1A 0A}$ (`\x89PNG\r\n\x1a\n`).
* For **MP4 / HEIC:** $M[4 : 8] = \texttt{66 74 79 70}$ (`"ftyp"`).
* For **PDF:** $M[0 : 5] = \texttt{25 50 44 46 2D}$ (`"%PDF-"`).

Compute the candidate 1-byte XOR key $k_1 = \text{buf}[0] \oplus \text{0xFF}$:
* If $(\text{buf}[1] \oplus k_1) == \text{0xD8}$ AND $(\text{buf}[2] \oplus k_1) == \text{0xFF}$:
  * **1-Byte XOR Key $k_1$ Confirmed (e.g., `NQ Vault` `com.netqin.ps`)!**
  * Find the exact boundary offset $N \in \{16, 32, 64, 128, 256, 512, 1024\}$ where XORing stops (by checking where valid JPEG segment markers `[0xFF][marker][2-byte length]` align), XOR `buf[0 : N]` with $k_1$, and save the restored `Product B2` `.jpg` file!
* Similarly test **4-byte repeating XOR keys** ($K_4 = \text{buf}[0 : 4] \oplus \texttt{FF D8 FF E0}$ or $\text{buf}[4 : 8] \oplus \texttt{66 74 79 70}$), **Byte-Order Reversal** (`reversed(buf[0 : 128])` starting with `FF D8 FF`), and **Prepended Vault Header Stripping** (where the vault app simply prepended a 32-to-256 byte metadata header before a completely unencrypted `FF D8 FF` JPEG!).

---

## 6. Database Schema for Module 7.2 (`ephemeral_visual_residuals_engine.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `os_app_switcher_snapshots_ledger` (iOS `SplashBoard` `.ktx`/`.jpg` & Android `TaskSnapshots` `<task_id>.jpg` + `.proto`)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `snapshot_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `os_platform` | `TEXT` | `NOT NULL` | Enum: `IOS_SPLASHBOARD`, `ANDROID_TASKSNAPSHOTS`. |
| `android_user_profile_id` | `INTEGER` | `DEFAULT 0` | User profile ID (`0`, `10`, `95`, `150`, `999`). |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `.ktx` or `<task_id>.jpg` in `vfs_index`. |
| `converted_png_staging_id` | `INTEGER` | `NULL` | Foreign key to `derivative_staging_ledger.staging_id` (populated when `.ktx` `ASTC`/`BGRA` texture is converted to `.png`). |
| `captured_app_bundle_or_pkg` | `TEXT` | `NOT NULL` | **Exact application captured on screen (e.g., `"org.telegram.messenger"`, `"com.phonepe.app"`, `"com.tronlinkpro.wallet"`)!** Indexed! |
| `captured_activity_or_scene` | `TEXT` | `NULL` | Exact `top_activity_component` from `<task_id>.proto` or iOS `SceneID`. |
| `is_real_content_snapshot` | `INTEGER` | `DEFAULT 1` | `1` if `is_real_snapshot == true` (actual user screen content); `0` if blank/splash placeholder. |
| `pixel_dimensions_and_orient` | `TEXT` | `NULL` | E.g., `"1080x2400 (Portrait)"`. |
| `snapshot_captured_utc_iso` | `TEXT` | `NOT NULL` | Exact UTC ISO-8601 timestamp when the user swiped away from or locked the app screen (`mtime`). |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `RESIDUAL_RECORD`). |

### Table 2: `reconstructed_thumbnails_and_disk_caches` (`.ithmb`, `.thumbdata4`, `Glide`, `Fresco`, `Kingfisher` & `SDWebImage`)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `thumb_cache_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `cache_engine_type` | `TEXT` | `NOT NULL` | Enum: `IOS_ITHMB_SLOT`, `IOS_THUMBNAILS_V2_FILE`, `ANDROID_THUMBDATA4_CARVED`, `GLIDE_DISKLRLUCACHE`, `FRESCO_CNT_CACHE`, `COIL_OKHTTP_CACHE`, `KINGFISHER_SDWEBIMAGE_IOS`. |
| `owning_app_bundle_or_pkg` | `TEXT` | `NOT NULL` | Application that owns this thumbnail/cache (`com.tinder`, `org.telegram.messenger`, `Photos.sqlite`, etc.). |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `.ithmb`, `.thumbdata4`, or `.0`/`.cnt` file in `vfs_index`. |
| `slot_index_or_cache_key` | `TEXT` | `NOT NULL` | `.ithmb` slot number (`ZTHUMBNAILINDEX`) or 64-hex `Glide`/`SDWebImage` hash key. |
| `is_parent_original_deleted` | `INTEGER` | `DEFAULT 0` | **`1` if the full-resolution original photo was permanently deleted from `/DCIM/` or evicted (`REMOVE` in `journal`), making this thumbnail the ONLY surviving visual proof!** |
| `matched_source_url` | `TEXT` | `NULL` | Original download URL (from `Coil` `.0` header or matched URL hash in app DB, e.g., `https://images-ssl.gotinder.com/...`). |
| `cached_or_accessed_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp. |
| `recovery_classification` | `TEXT` | `NOT NULL` | `ORIGINAL_RECORD` or `RESIDUAL_RECORD`. |

### Table 3: `unmasked_vault_and_hidden_media_ledger` (Restored Files From `Calculator+`, `Hide It Pro`, `NQ Vault` & Private Safe)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `vault_item_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `vault_app_name_and_pkg` | `TEXT` | `NOT NULL` | E.g., `"Calculator+ (com.flatfish.cal.privacy)"`, `"Hide It Pro / Audio Manager (com.hideitpro)"`, `"NQ Vault (com.netqin.ps)"`, `"Xiaomi Secret Album"`. |
| `obfuscated_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to the raw `.bin`/`.lock`/`.sa` file in `vfs_index`. |
| `unmasking_method_applied` | `TEXT` | `NOT NULL` | Enum: `HEADER_1BYTE_XOR_RESTORED`, `HEADER_MULTIBYTE_XOR_RESTORED`, `HEADER_BYTE_SWAP_REVERSED`, `PREPENDED_VAULT_HEADER_STRIPPED`, `VAULT_KEY_AES_DECRYPTED`, `EXTENSION_RENAME_ONLY`. |
| `recovered_xor_or_aes_key_hex` | `TEXT` | `NULL` | Exact XOR byte(s) or AES key used to restore the file header. |
| `original_filename_from_vault_db` | `TEXT` | `NULL` | Original filename recovered from the vault app's internal SQLite database! |
| `restored_mime_type` | `TEXT` | `NOT NULL` | E.g., `"image/jpeg"`, `"video/mp4"`, `"application/pdf"`. |
| `restored_derivative_staging_id` | `INTEGER` | `NOT NULL` | Foreign key to the playable/viewable `Product B2` restored file in `derivative_staging_ledger`. |
| `hidden_into_vault_utc_iso` | `TEXT` | `NULL` | Exact timestamp when the suspect hid the file inside the vault! |

---

## 7. Developer Acceptance Test Checklist for Module 7.2

1. **The Android `TaskSnapshots` `<task_id>.proto` + `<task_id>.jpg` Pairing Test:**
   * Place a test `1055.jpg` and `1055.proto` (`Field 3 is_real_snapshot = true`, `Field 7 top_activity_component = "com.phonepe.app/.ui.TransactionDetailsActivity"`) inside `/data/system_ce/999/snapshots/` (Cloned App profile `999`).
   * Verify that Sub-Engine 7.2A decodes `1055.proto`, pairs it with `1055.jpg`, attributes it to `com.phonepe.app` in User Profile `999`, and queues `1055.jpg` for Phase 7.3/7.4 QR and OCR extraction!
2. **The iOS `.ithmb` Orphaned Deleted-Photo Slot Detection Test:**
   * Create a consolidated `.ithmb` file containing 10 bitmap slots ($k = 0 \dots 9$), while `Photos.sqlite` (`ZASSET`) only has active rows for `ZTHUMBNAILINDEX` $0 \dots 7$ (because Photos $8$ and $9$ were permanently purged from "Recently Deleted").
   * Verify that Sub-Engine 7.2B reconstructs all 10 slots into `.png` images and flags Slots $8$ and $9$ with `is_parent_original_deleted = 1` (`RESIDUAL_RECORD`).
3. **The Disguised Vault Known-Plaintext Header XOR Restoration Test:**
   * Take a valid `100 KB` JPEG image (`FF D8 FF E0...`), XOR its first $128\text{ bytes}$ with `0x5A` (so Byte $0$ becomes `0xA5`, Byte $1$ becomes `0x82`, Byte $2$ becomes `0xA5`), rename it to `/sdcard/.bin/secret_001.bin`, and run Sub-Engine 7.2C.
   * Verify that Sub-Engine 7.2C detects the unencrypted JPEG body (`FF DB`, `FF C4`, `FF DA`, `FF D9`), computes $k_1 = \text{0xA5} \oplus \text{0xFF} = \text{0x5A}$, verifies $(\text{0x82} \oplus \text{0x5A}) == \text{0xD8}$, XORs the first $128\text{ bytes}$ with `0x5A`, and outputs a 100% valid, viewable `Product B2` JPEG file!