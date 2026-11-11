# Engineering Specification: Phase 7, Module 7.1 — OS Media Library Forensics, Deleted & "Hidden Album" Recovery, Cross-App `Syndication` Attribution & Deep `EXIF`/`HEIC`/`ISO-BMFF` Provenance Engine

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 7.1** of the Forensic Data Parser (corresponding to **Groups 3, 5, 7, 13, 15, and 16** of the Unified Master Register). It contains **zero programming code** and explains how to decode iOS `Photos.sqlite` and `Syndication.sqlite`, Android `MediaProvider` (`external.db`), "Recently Deleted" and "Hidden Album" states, uncropped original `/Mutations/` recovery, Android `owner_package_name` attribution, Apple `Live Photos` pairing, and binary `EXIF` / `HEIC` / `MP4` container provenance (distinguishing an authentic camera-captured photo from a WhatsApp/Telegram downloaded image or screenshot) from first principles.

---

## 1. Purpose & Mental Model (Why a Photo File Without Database & Container Provenance Fails in Court)

When an investigator finds an incriminating photograph or video on a seized smartphone—such as a photo of a victim's Aadhaar/PAN card, a handwritten `BIP-39` crypto seed phrase, a stack of hawala cash, a weapon, or a UPI payment screenshot—three questions immediately arise in court:

1. **Where Did This Image Come From (`Provenance Attribution`)?**
   * Did the suspect **physically stand in the room and take this photo with the seized phone's own camera**?
   * Or did the suspect **capture a Screenshot** of an app on their screen?
   * Or did someone **send this image to the suspect over WhatsApp, Telegram, Signal, or Instagram**, or did the suspect **save it from Chrome/Safari or AirDrop**?
   * Simply looking at the `.jpg` or `.heic` file in `/DCIM/` cannot answer this alone. However, combining **iOS `Photos.sqlite` (`ZADDITIONALASSETATTRIBUTES.ZIMPORTEDBYBUNDLEIDENTIFIER` & `ZSYNDICATIONIDENTIFIER`)**, **iOS `Syndication.sqlite`**, **Android `MediaProvider` (`external.db` `owner_package_name`)**, and **binary `EXIF` / `HEIC` / Quantization Table container structure** answers this question with $100\%$ mathematical certainty!
2. **Did the Suspect Try to Hide, Crop, or Delete the Image?**
   * Suspects frequently **crop out** an accomplice's face or a bank account header using the built-in iOS/Android photo editor, move sensitive photos into the biometric-locked **"Hidden Album"**, or delete them into **"Recently Deleted" (Trash)** (which retains files for 30 days before permanent purge).
   * Even better: on iOS and many Android OEM galleries, when a user crops or scribbles black ink over a screenshot to redact a name or UTR number, the OS saves the edited version in `/PhotoData/Mutations/` while keeping the **unredacted, uncropped original image intact inside `/DCIM/100APPLE/`**!
3. **Where and When Was the Media Physically Captured?**
   * Extracts sub-second `EXIF` (`SubSecTimeOriginal`, `OffsetTimeOriginal`), GPS coordinates, altitude, compass direction (`GPSImgDirection` — proving which compass direction the camera lens was pointing!), and motion video clips embedded inside Apple `Live Photos` and Android `Motion Photos`.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Mobile Media Library Forensics

Before implementing Module 7.1, the developer must understand six critical traps that cause standard forensic tools to misattribute or miss media evidence:

### Mistake 1: Missing the Uncropped / Unredacted Original When a Suspect Crops or Blacks Out a Screenshot
* **The Trap:** Displaying only the rendered/adjusted image from `/PhotoData/Mutations/` (or only the main `/DCIM/` file) without checking if the photo has non-destructive edits (`ZHASADJUSTMENTS == 1`).
* **Why It Fails:** Suppose a suspect takes a screenshot of a bank transfer or a chat, opens the iOS Photos app (or Samsung/Google Photos editor), **crops out the top half of the screen** (or uses the Markup pen tool to black out the recipient's name), and clicks "Done".
  * On iOS, when `ZASSET.ZHASADJUSTMENTS == 1`, the original **uncropped, unredacted full-screen image** remains untouched at `/private/var/mobile/Media/DCIM/100APPLE/IMG_xxxx.PNG` (or `.HEIC`), while the cropped/redacted version is stored separately at `/private/var/mobile/Media/PhotoData/Mutations/DCIM/100APPLE/IMG_xxxx/Adjustments/FullSizeRender.jpg` alongside a zlib-compressed plist/JSON (`AdjustmentData`) recording the exact crop rectangle and pen strokes!
* **The Rule:** Whenever `ZHASADJUSTMENTS == 1` (iOS) or non-destructive edit metadata exists (Android), Module 7.1 must link **both** the `Original Unedited Master File` and the `User-Cropped/Redacted Mutation File` side-by-side and flag **`USER_REDACTED_OR_CROPPED_MEDIA_RECOVERED`**!

### Mistake 2: Ignoring `ZIMPORTEDBYBUNDLEIDENTIFIER` and `Syndication.sqlite` on iOS
* **The Trap:** Seeing an image in `/DCIM/100APPLE/IMG_4821.JPG` and assuming the iPhone's camera took the photo because it sits inside the `/DCIM/` folder.
* **Why It Fails:** On iOS, when a user taps "Save to Photos" inside **WhatsApp**, **Telegram**, **Signal**, **Instagram**, **Safari**, or **Chrome**, iOS writes the saved image directly into `/DCIM/100APPLE/IMG_xxxx.JPG` right alongside real camera photos! However, inside `Photos.sqlite` (`ZADDITIONALASSETATTRIBUTES` table), iOS records the **exact Bundle ID of the third-party app that saved the photo** in the column **`ZIMPORTEDBYBUNDLEIDENTIFIER`** (e.g., `"net.whatsapp.WhatsApp"` or `"ph.telegra.Telegraph"`) and the app's display name in **`ZIMPORTEDBYDISPLAYNAME`**!
* **The Rule:** Always join `ZASSET` with `ZADDITIONALASSETATTRIBUTES` and `Syndication.sqlite` to prove which app placed every image into the camera roll (Section 3.2 & Section 3.4).

### Mistake 3: Overlooking Android 10–17 Scoped Storage `owner_package_name` in `external.db`
* **The Trap:** Scanning `/sdcard/Pictures/`, `/sdcard/Download/`, and `/sdcard/DCIM/` on Android via raw filesystem walk without querying Android's `MediaProvider` SQLite database (`external.db`).
* **Why It Fails:** Under Android 10 through Android 17 Scoped Storage, `/data/media/0/` is managed by the **`MediaProvider` APEX module**, which maintains `/data/user/<id>/com.android.providers.media.module/databases/external.db` (and legacy `/com.android.providers.media/databases/external.db`). In the **`files`** table of `external.db`, Android records:
  1. **`owner_package_name` (`TEXT`):** The exact Android package name (`com.whatsapp`, `org.telegram.messenger`, `com.phonepe.app`, `com.android.chrome`) that created or downloaded that media file!
  2. **`is_trashed` (`INTEGER`) & `date_expires` (`INTEGER`):** Files moved to the Android Recycle Bin / Trash!
  3. **Deleted Historical Rows in `external.db-wal` & Freelist Pages:** Even after a photo or PDF is permanently deleted from `/sdcard/`, its metadata row (`_data` path, `owner_package_name`, `date_added`, `latitude`, `longitude`, `_size`) survives inside `external.db-wal` and B-tree freelist pages (recovered via Phase 2, Module 2.1)!

### Mistake 4: Failing to Distinguish `iCloud Shared Photo Library` / `Shared Albums` Uploads From Local Captures
* **The Trap:** Treating every row in `Photos.sqlite` (`ZASSET`) as a photo stored locally by the device owner.
* **Why It Fails:** `Photos.sqlite` indexes both local device photos AND photos synced from **iCloud Shared Photo Libraries** or **Shared Albums** where 5 different family members or co-conspirators contribute photos! If you do not inspect `ZCLOUDISMYASSET`, `ZCLOUDOWNERHASHEDPERSONID`, and `ZCLOUDSHAREDALBUM`, you will falsely attribute a photo uploaded by a remote person to the seized iPhone!
* **The Rule:** Explicitly extract cloud ownership columns (`ZCLOUDISMYASSET`, `ZCLOUDLOCALSTATE`, `ZACTIVELIBRARYSCOPEPARTICIPATIONSTATE`) to separate local captures from remote contributor uploads.

### Mistake 5: Missing the Hidden `.MOV` Video Inside an Apple `Live Photo` or Embedded MP4 Inside an Android `Motion Photo`
* **The Trap:** Treating a `Live Photo` or `Motion Photo` as a static still image only.
* **Why It Fails:**
  * On **iOS (`Live Photos`)**, every time the user snaps a photo with Live Photo enabled (on by default!), the iPhone records a **3-second `.MOV` video AND audio clip** (1.5 seconds before and 1.5 seconds after the shutter press!) stored right next to `IMG_xxxx.HEIC` as **`IMG_xxxx.MOV`** (linked by the identical `ContentIdentifier` UUID in `EXIF` MakerNote Tag `0x0011` and QuickTime `com.apple.quicktime.content.identifier`)! That 3-second `.MOV` clip often captures **human voices speaking in the room**, background television/traffic audio, or a wider camera angle before the phone steadied on a document!
  * On **Android (`Google Pixel` / `Samsung Motion Photo`)**, the 3-second `.mp4` video + audio stream is **appended directly inside the `.jpg` / `.heic` file itself** immediately after the JPEG End-Of-Image (`FF D9`) marker (indexed by the XMP `GCamera:MicroVideoOffset` or `MotionPhoto` `Item:Length` tag)!
* **The Rule:** Automatically pair iOS `.HEIC` + `.MOV` Live Photos and carve embedded `.mp4` video streams out of Android Motion Photos (Section 5.3)!

### Mistake 6: Confusing `EXIF DateTimeOriginal` (No Timezone in Legacy EXIF) with Filesystem UTC `btime`
* **The Trap:** Reading `EXIF DateTimeOriginal` (`"2026:11:05 14:30:00"`) and storing it directly as `2026-11-05T14:30:00Z` (UTC).
* **Why It Fails:** Standard `EXIF DateTimeOriginal` (Tag `0x9003`) is recorded in the phone's **Local Wall-Clock Time** (e.g., `IST = UTC + 05:30`), **not** UTC! Modern iOS and Android write the timezone offset in `EXIF OffsetTimeOriginal` (Tag `0x9011`, e.g., `"+05:30"`), while QuickTime `.MOV`/`.MP4` `mvhd` creation timestamps are recorded in **UTC**.
* **The Rule:** Always combine `DateTimeOriginal` + `SubSecTimeOriginal` (Tag `0x9291`) + `OffsetTimeOriginal` (Tag `0x9011`) via **Phase 1, Module 1.2** to compute the true UTC timestamp while preserving the local wall-clock string and timezone offset!

---

## 3. Step 1 — Sub-Engine 7.1A: iOS `Photos.sqlite` & `Syndication.sqlite` Deep Relational Decoder

* **Canonical Target Paths in `vfs_index`:**
  1. Primary Photo Library Database: `/private/var/mobile/Media/PhotoData/Photos.sqlite` (+ `-wal`)
  2. Cross-App "Shared with You" Attribution Database: `/private/var/mobile/Library/Photos/Libraries/Syndication.photoslibrary/database/Photos.sqlite` (referred to as `Syndication.sqlite`)

### 3.1 Step 1: The Master 5-Table Relational Join in `Photos.sqlite`

Stage `Photos.sqlite` (+ `Photos.sqlite-wal`) via Module 1.1 and process through **Phase 2, Module 2.1 (Active + `-wal` + Freelist)**. Execute the core 5-table relational join across `ZASSET` (or `ZGENERICASSET` on older iOS), `ZADDITIONALASSETATTRIBUTES`, `ZEXTENDEDATTRIBUTES`, `ZCLOUDMASTER`, and `ZINTERNALRESOURCE`:

$$\texttt{ZASSET.ZADDITIONALATTRIBUTES} = \texttt{ZADDITIONALASSETATTRIBUTES.Z\_PK}$$
$$\texttt{ZASSET.ZEXTENDEDATTRIBUTES} = \texttt{ZEXTENDEDATTRIBUTES.Z\_PK}$$
$$\texttt{ZASSET.ZMASTER} = \texttt{ZCLOUDMASTER.Z\_PK}$$

### 3.2 Complete Column Extraction & Forensic State Mapping for `Photos.sqlite`

| Source Table & Column Name | SQLite Type | Forensic Meaning & Exact Decoding Rules |
|---|---|---|
| **`ZASSET.Z_PK`** & **`ZUUID`** | `INTEGER` / `TEXT` | Internal primary key (`Z_PK`) and 36-character asset UUID. |
| **`ZASSET.ZDIRECTORY`** & **`ZFILENAME`** | `TEXT` | Relative folder (e.g., `"DCIM/100APPLE"`, `"PhotoData/CPLAssets/group123"`) and filename (`"IMG_4821.HEIC"`). Reconstruct full path `/private/var/mobile/Media/<ZDIRECTORY>/<ZFILENAME>` and link to `vfs_index.file_id`! |
| **`ZASSET.ZDATECREATED`** & **`ZADDEDDATE`** | `REAL` | Apple Cocoa seconds since `2001-01-01 00:00:00 UTC`. **`ZDATECREATED`** = Capture/creation timestamp; **`ZADDEDDATE`** = Exact second the file was saved/imported into the iPhone's Photo Library! *(If `ZADDEDDATE >> ZDATECREATED`, the image was received/downloaded later rather than captured live!)* |
| **`ZASSET.ZTRASHEDSTATE`** & **`ZTRASHEDDATE`** | `INTEGER` / `REAL` | **`ZTRASHEDSTATE == 1`:** **The user deleted this photo into the "Recently Deleted" album!** `ZTRASHEDDATE` (Cocoa seconds) proves the **exact second the suspect pressed the Delete button**! |
| **`ZASSET.ZHIDDEN`** | `INTEGER` | **`ZHIDDEN == 1`:** **The user intentionally moved this photo into the FaceID/Passcode-locked "Hidden Album"!** |
| **`ZASSET.ZFAVORITE`** | `INTEGER` | `1` = Marked with a Heart ("Favorite") by the user. |
| **`ZASSET.ZHASADJUSTMENTS`** & **`ZADJUSTMENTTIMESTAMP`** | `INTEGER` / `REAL` | **`ZHASADJUSTMENTS == 1`:** **The user cropped, rotated, filtered, or drew Markup ink over this image!** Trigger Section 3.3's `/Mutations/` uncropped original recovery! |
| **`ZASSET.ZKINDSUBTYPE`** | `INTEGER` | `0` = Standard Still Photo; **`2` = `Live Photo` (paired `.MOV` exists!)**; **`10` = `Screenshot` (`UIKit` screen capture!)**; `100` = Video; `102` = Screen Recording! |
| **`ZASSET.ZLATITUDE`** & **`ZLONGITUDE`** | `REAL` | WGS-84 coordinates (`-180.0` indicates no GPS tag recorded). Feed valid coordinates into Module 6.3 (`TIER_1_ACTIVE_DEVICE_FIX`). |
| **`ZASSET.ZTHUMBNAILINDEX`** | `INTEGER` | Slot index into `.ithmb` thumbnail cache files (used by Module 7.2 to recover thumbnails of purged photos!). |
| **`ZADDITIONALASSETATTRIBUTES.ZIMPORTEDBYBUNDLEIDENTIFIER`** & **`ZIMPORTEDBYDISPLAYNAME`** | `TEXT` | **The Provenance Smoking Gun:** Records the exact Bundle ID of the app that saved/created the photo (e.g., `"com.apple.camera"`, `"com.apple.springboard"` \[Screenshot\], `"net.whatsapp.WhatsApp"`, `"ph.telegra.Telegraph"`, `"com.burbn.instagram"`, `"com.apple.mobilesafari"`). |
| **`ZADDITIONALASSETATTRIBUTES.ZORIGINALFILENAME`** | `TEXT` | Preserves the **original filename before iOS renamed it to `IMG_xxxx`**, such as `"WhatsApp Image 2026-11-05 at 14.20.10.jpeg"` or `"aadhaar_front.jpg"`! |
| **`ZADDITIONALASSETATTRIBUTES.ZEXIFTIMESTAMPSTRING`** & **`ZTIMEZONENAME`** & **`ZTIMEZONEOFFSET`** | `TEXT` / `INTEGER` | Original local timestamp string and timezone name (`"Asia/Kolkata"` / `"Asia/Dubai"` — proves which country/timezone the suspect was in when taking the photo!). |
| **`ZADDITIONALASSETATTRIBUTES.ZSYNDICATIONIDENTIFIER`** | `TEXT` | Links syndicated assets across `Syndication.sqlite`, `sms.db` (`iMessage`), `WhatsApp`, and `Telegram` (Section 3.4). |
| **`ZEXTENDEDATTRIBUTES.ZCAMERAMAKE`**, **`ZCAMERAMODEL`** & **`ZLENSMODEL`** | `TEXT` | Hardware camera make (`"Apple"`), model (`"iPhone 16 Pro"`), and lens (`"iPhone 16 Pro back triple camera 6.765mm f/1.78"`). |
| **`ZASSET.ZCLOUDISMYASSET`** & **`ZCLOUDLOCALSTATE`** | `INTEGER` | Distinguishes photos taken by this user's Apple ID (`ZCLOUDISMYASSET == 1`) from photos contributed by other people in a Shared iCloud Library/Album (`0`). |

### 3.3 Step 2: Recovering Uncropped / Unredacted Originals from `/PhotoData/Mutations/`

Whenever `ZASSET.ZHASADJUSTMENTS == 1` (or whenever files exist inside `/private/var/mobile/Media/PhotoData/Mutations/`):
1. Locate the **Unedited Original Master File** at `/private/var/mobile/Media/<ZDIRECTORY>/<ZFILENAME>` (e.g., `/DCIM/100APPLE/IMG_4821.PNG`).
2. Locate the **Edited / Cropped / Markup-Redacted Render** at `/private/var/mobile/Media/PhotoData/Mutations/<ZDIRECTORY>/<IMG_stem>/Adjustments/FullSizeRender.jpg` (or `.mov`).
3. Parse `/private/var/mobile/Media/PhotoData/Mutations/<ZDIRECTORY>/<IMG_stem>/Adjustments/Adjustments.plist`:
   * Extract `adjustmentTimestamp`, `editorBundleID`, and decompress the zlib-compressed `adjustmentData` blob to inspect the applied operations (`Crop`, `Markup` pen strokes, `Straighten`).
4. Link both files into the single media record in `os_media_library_master_ledger` with `has_uncropped_original_recovered = 1`—allowing the examiner to toggle between the suspect's cropped/redacted cover version and the unredacted original!

### 3.4 Step 3: Cross-App `Syndication.sqlite` ("Shared with You") Attribution

Stage `/private/var/mobile/Library/Photos/Libraries/Syndication.photoslibrary/database/Photos.sqlite` via Module 2.1:
* Query `ZASSET` joined with `ZADDITIONALASSETATTRIBUTES`:
  * In `Syndication.sqlite`, iOS indexes media attachments received inside **iMessage (`sms.db`)**, **WhatsApp**, **Telegram**, and **WeChat** even if the user never clicked "Save to Camera Roll"!
  * Extract `ZSYNDICATIONIDENTIFIER` (e.g., `at_0_<GUID>` which joins directly to `sms.db` `attachment.guid`, or app-specific message identifiers) and `ZIMPORTEDBYBUNDLEIDENTIFIER` to link the image directly to the chat message that delivered it!

---

## 4. Step 2 — Sub-Engine 7.1B: Android `MediaProvider` (`external.db`), Scoped Storage Trash & `Google Photos` (`gphotos0.db`) Decoder

### 4.1 Android `MediaProvider` (`/data/user/<id>/com.android.providers.media.module/databases/external.db`)

Stage `external.db` (and `internal.db` + `-wal`) across all Android user profiles (`0`, `10`, `95`, `150`, `999`) via Module 1.1 and process through **Phase 2, Module 2.1 (Active + `-wal` + Freelist)**.

Query the **`files`** table (and **`deleted_media`** / `album_art` tables):
1. **`_id` (`INTEGER`):** MediaStore row ID (preserved in `.thumbnails` and URI grants `content://media/external/images/media/<_id>`).
2. **`_data` (`TEXT`):** Full filesystem path on `/storage/emulated/0/...` (e.g., `/storage/emulated/0/Pictures/Screenshots/Screenshot_20261105-143022_PhonePe.jpg`).
   * **Notice the Android Screenshot Filename Convention:** On Samsung OneUI, Xiaomi HyperOS/MIUI, Vivo Funtouch, Oppo ColorOS, and Pixel Android, the OS automatically embeds the **Foreground App Name or Package Name** at the end of every screenshot filename (`Screenshot_YYYYMMDD-HHMMSS_<AppName>.jpg/.png`)! Even if a screenshot was deleted from disk and only its row in `external.db-wal` or freelist survives, the `_data` / `_display_name` string reveals **which app was screenshotted and at what exact second**!
3. **`owner_package_name` (`TEXT`):** **The exact Android package that created/saved the file** (e.g., `"com.whatsapp"`, `"org.telegram.messenger"`, `"com.phonepe.app"`, `"com.android.chrome"`, `"com.sec.android.app.camera"`).
4. **`is_trashed` (`INTEGER`) & `date_expires` (`INTEGER`):**
   * If `is_trashed == 1` (or if `_data` contains `/.trash` or `.trashed-<timestamp>-<name>`): **The suspect deleted this file into the Android Scoped Storage Trash!**
   * Because Android retains trashed files for $30\text{ days}$, the subtracted timestamp $\text{deleted\_utc} = \text{date\_expires} - (30 \times 86400)$ reveals the **exact second the suspect deleted the file**!
5. **`date_added`, `date_modified` (Unix seconds) & `datetaken` (13-digit Unix ms).**
6. **`width`, `height`, `_size`, `mime_type`, `duration`, `is_favorite`, and `xmp` (`BLOB` — embedded XMP metadata!).**

### 4.2 `Google Photos` (`/data/user/<id>/com.google.android.apps.photos/databases/gphotos0.db`) & Locked Folder (`mars_files`)

Stage `gphotos0.db` (and per-account `gphotos<N>.db` + `-wal`) via Module 2.1:
1. **`local_media` vs. `remote_media` Tables:**
   * Strictly separate files physically present on the phone (`local_media`) from cloud-backed-up history synced from the user's Google Account (`remote_media` — which retains metadata, capture timestamps, GPS coordinates, and camera make/model for photos deleted from local storage years ago!).
2. **`trash` Table & Locked Folder (`mars_files` / `/files/mars_files/`):**
   * Extract every row in the `trash` table and scan `/data/user/<id>/com.google.android.apps.photos/files/mars_files/` (**Google Photos' Biometric-Locked Private Folder**, codenamed *MARS*—in an FFS extraction, files moved by the suspect into Google Photos' "Locked Folder" sit inside `/files/mars_files/`!).

---

## 5. Step 3 — Sub-Engine 7.1C: Binary Container Provenance (`EXIF`, `ISO-BMFF`, Quantization Fingerprinting & `Live`/`Motion Photo` Unpacker)

For every image and video file in `vfs_index`, Sub-Engine 7.1C inspects the raw binary container headers to classify its **Authenticity & Provenance Class**:

### 5.1 The 4-Class Image Provenance Classifier (`Camera Original` vs. `Screenshot` vs. `Messenger Re-Encoded` vs. `Edited`)

| Provenance Class | Deterministic Binary & Metadata Signatures |
|---|---|
| **1. `AUTHENTIC_CAMERA_ORIGINAL`** | • Contains complete hardware `EXIF` IFD0 & ExifIFD (`Make`, `Model`, `ExposureTime`, `FNumber`, `ISOSpeedRatings`, `FocalLength`, `SubSecTimeOriginal`, `OffsetTimeOriginal`).<br>• On iOS: Contains Apple `MakerNote` (`"Apple iOS"` header + `ContentIdentifier` Tag `0x0011` + `RunTime` Mach uptime dictionary!).<br>• Pixel dimensions match native sensor resolution ($4032 \times 3024$ / $12\text{ MP}$, $5712 \times 4284$ / $24\text{ MP}$, or $8064 \times 6048$ / $48\text{ MP}$). |
| **2. `OS_SCREENSHOT_OR_SCREEN_RECORDING`** | • On iOS: `EXIF UserComment` == `"Screenshot"`, or PNG contains `iDOT` / `cHRM` / `pHYs` Apple display color profile (`Display P3`), or `ZKINDSUBTYPE == 10`.<br>• On Android: `_data` path in `/Pictures/Screenshots/` or `/DCIM/Screenshots/`, and pixel dimensions match exact physical screen resolution of the handset (e.g., $1080 \times 2400$, $1440 \times 3120$). |
| **3. `MESSENGER_TRANSMITTED_REENCODED` (`WhatsApp` / `Telegram` / `Instagram` / `Signal`)** | • **Complete absence of Camera `EXIF` tags** (`Make`, `Model`, `GPS`, `DateTimeOriginal` stripped by the messenger's compression pipeline!).<br>• Standard messenger bounding-box dimensions: long edge equals **`1600px` or `1280px`** (Standard WhatsApp/Telegram) or **`2560px` / `4096px`** (WhatsApp HD mode), with progressive JPEG `SOF2` (`FF C2`) encoding and non-camera JPEG Quantization Tables (`DQT` `FF DB`)!<br>• Corroborated by `ZIMPORTEDBYBUNDLEIDENTIFIER` or `owner_package_name`. |
| **4. `SOFTWARE_EDITED_OR_MANIPULATED`** | • `EXIF Software` tag contains `"Adobe Photoshop"`, `"Canva"`, `"PicsArt"`, `"Snapseed"`, `"GIMP"`, or `"Canvas"`, OR `ZHASADJUSTMENTS == 1`, OR XMP history (`xmpMM:History`) records modification steps. |

### 5.2 Parsing `ISO-BMFF` (`HEIC`, `MOV`, `MP4`) Atom / Box Trees

For `.heic`, `.mov`, and `.mp4` files, walk the hierarchical `[4-byte uint32_be box_size][4-byte ASCII box_type]` tree:
* From `ftyp`: Extract major brand (`heic`, `mif1`, `qt  `, `mp42`, `isom`).
* From `moov` $\rightarrow$ `mvhd`: Extract `creation_time` and `modification_time` (32-bit or 64-bit unsigned seconds since the **QuickTime Epoch `1904-01-01 00:00:00 UTC`** — convert via Module 1.2: $\text{Unix Seconds} = \text{QT} - 2082844800$).
* From `moov` $\rightarrow$ `meta` $\rightarrow$ `keys` & `ilst`: Extract Apple QuickTime metadata keys:
  * `com.apple.quicktime.location.ISO6709` (e.g., `"+25.3176+082.9739+080.500/"` — exact GPS latitude, longitude, and altitude of the video!)
  * `com.apple.quicktime.creationdate` (Includes local timezone offset, e.g., `"2026-11-05T14:30:00+0530"`!)
  * `com.apple.quicktime.make` & `com.apple.quicktime.model`
  * `com.apple.quicktime.content.identifier` (UUID linking a `Live Photo` `.HEIC` still image to its companion `.MOV` video clip!)

### 5.3 Pairing Apple `Live Photos` & Carving Embedded `.mp4` Video From Android `Motion Photos`

1. **Apple `Live Photos` Pairing:**
   * Match every `.HEIC`/`.JPG` image and `.MOV` video sharing the same `ContentIdentifier` UUID (or `ZASSET` row where `ZKINDSUBTYPE == 2`) so the examiner can play the 3-second audio/video clip attached to the photo!
2. **Android `Motion Photo` (`Google Pixel` / `Samsung` / `Xiaomi`) Embedded MP4 Extractor:**
   * Scan the JPEG/HEIC file's `XMP` metadata block (`http://ns.adobe.com/xap/1.0/`) for **`GCamera:MicroVideoOffset="<N>"`** or **`Container:Directory`** (`Item:Semantic="MotionPhoto"`, `Item:Length="<N>"`), OR scan the file past the primary JPEG `FF D9` marker for the `ISO-BMFF` `ftyp` magic (`66 74 79 70 6D 70 34 32` `"ftypmp42"` or `"ftypisom"`):
   * Carve the trailing $N\text{ bytes}$ (`buf[file_size - N : file_size]`) into a standalone `Product B2` `.mp4` video file in the staging workspace, hash it via Module 1.2, and link it to the parent photo!

---

## 6. Database Schema for Module 7.1 (`os_media_library_and_provenance.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `os_media_library_master_ledger` (Unified iOS `Photos.sqlite`, `Syndication.sqlite` & Android `external.db` / `gphotos0.db`)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `media_asset_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID for each media asset. |
| `os_platform_source` | `TEXT` | `NOT NULL` | Enum: `IOS_PHOTOS_SQLITE`, `IOS_SYNDICATION_SQLITE`, `ANDROID_MEDIAPROVIDER_EXTERNAL_DB`, `ANDROID_GOOGLE_PHOTOS_DB`, `ANDROID_MARS_LOCKED_FOLDER`, `RAW_FILESYSTEM_CARVED`. |
| `vfs_file_id` | `INTEGER` | `NULL` | Foreign key to `vfs_index.file_id` (`NULL` if file was purged from disk and only the DB/cloud metadata row survived!). |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD` \[`-wal`\], `RESIDUAL_RECORD` \[Trash/Freelist\]). |
| `canonical_file_path` | `TEXT` | `NOT NULL` | Full device path (e.g., `/private/var/mobile/Media/DCIM/100APPLE/IMG_4821.HEIC`). |
| `original_pre_import_filename` | `TEXT` | `NULL` | `ZORIGINALFILENAME` or `_display_name` (e.g., `"Screenshot_20261105-143022_PhonePe.jpg"`). |
| `provenance_classification` | `TEXT` | `NOT NULL` | Enum from Section 5.1: `AUTHENTIC_CAMERA_ORIGINAL`, `OS_SCREENSHOT_OR_SCREEN_RECORDING`, `MESSENGER_TRANSMITTED_REENCODED`, `SOFTWARE_EDITED_OR_MANIPULATED`, `CLOUD_SHARED_BY_OTHER_USER`. |
| `originating_app_bundle_or_pkg` | `TEXT` | `NULL` | **`ZIMPORTEDBYBUNDLEIDENTIFIER` or `owner_package_name` (e.g., `"net.whatsapp.WhatsApp"`, `"com.phonepe.app"`)!** |
| `user_concealment_state` | `TEXT` | `NOT NULL` | Enum: `ACTIVE_VISIBLE`, `IN_RECENTLY_DELETED_TRASH`, `IN_BIOMETRIC_HIDDEN_OR_LOCKED_ALBUM`, `PERMANENTLY_PURGED_DB_RESIDUAL_ONLY`. |
| `trashed_or_deleted_utc_iso` | `TEXT` | `NULL` | Exact UTC ISO-8601 timestamp when the user pressed Delete (`ZTRASHEDDATE` or `date_expires - 30d`). |
| `has_uncropped_original_recovered` | `INTEGER` | `DEFAULT 0` | **`1` if `ZHASADJUSTMENTS == 1` and both the uncropped master and `/Mutations/` edited render were recovered!** |
| `mutations_edited_vfs_file_id` | `INTEGER` | `NULL` | Foreign key to the cropped/redacted `FullSizeRender.jpg` in `vfs_index`. |
| `paired_live_or_motion_video_id` | `INTEGER` | `NULL` | Foreign key to the paired `.MOV` Live Photo or carved `.mp4` Motion Photo clip! |
| `linked_chat_syndication_id` | `TEXT` | `NULL` | `ZSYNDICATIONIDENTIFIER` linking the photo back to its exact WhatsApp/Telegram/iMessage chat row! |
| `capture_created_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 capture/creation timestamp (`EXIF` / `ZDATECREATED` / `datetaken`). |
| `library_imported_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 import/save timestamp (`ZADDEDDATE` / `date_added`). |
| `capture_timezone_offset_str` | `TEXT` | `NULL` | E.g., `"+05:30 (Asia/Kolkata)"`. |
| `gps_lat_lon_alt_heading_json` | `TEXT` | `NULL` | JSON with `lat`, `lon`, `altitude_m`, and `compass_heading_deg` (`GPSImgDirection`). |
| `camera_make_model_lens` | `TEXT` | `NULL` | E.g., `"Apple iPhone 16 Pro (back triple camera 6.765mm)"`. |
| `file_sha256` | `TEXT` | `NULL` | SHA-256 hash of the master media file (from Module 1.2). |

---

## 7. Developer Acceptance Test Checklist for Module 7.1

1. **The Cropped/Redacted Screenshot Unmasking Test (`/Mutations/` vs. `/DCIM/`):**
   * Create a test `Photos.sqlite` row with `ZDIRECTORY = "DCIM/100APPLE"`, `ZFILENAME = "IMG_4821.PNG"`, and `ZHASADJUSTMENTS = 1`, placing the uncropped screenshot in `/DCIM/100APPLE/IMG_4821.PNG` and the cropped version in `/PhotoData/Mutations/DCIM/100APPLE/IMG_4821/Adjustments/FullSizeRender.jpg`.
   * Verify that Sub-Engine 7.1A sets `has_uncropped_original_recovered = 1` and links both files in `os_media_library_master_ledger`.
2. **The `ZIMPORTEDBYBUNDLEIDENTIFIER` & Android `owner_package_name` Provenance Test:**
   * Insert a photo into `/DCIM/100APPLE/IMG_5001.JPG` (with stripped EXIF, dimensions $1600 \times 1200$, and `ZIMPORTEDBYBUNDLEIDENTIFIER = "net.whatsapp.WhatsApp"`), and an Android `external.db` row with `owner_package_name = "org.telegram.messenger"` and `is_trashed = 1`.
   * Verify that Module 7.1 classifies both as `MESSENGER_TRANSMITTED_REENCODED` (not Camera Originals!) and marks the Android file as `IN_RECENTLY_DELETED_TRASH`.
3. **The Android `Motion Photo` Embedded MP4 Carver Test:**
   * Construct a test `.jpg` file containing a standard JPEG (`FF D8 ... FF D9`) followed immediately by a $500\text{ KB}$ `.mp4` video stream (`ftypmp42...`) with XMP tag `GCamera:MicroVideoOffset="512000"`.
   * Verify that Sub-Engine 7.1C carves the trailing $512,000\text{ bytes}$ into a standalone playable `.mp4` file and links it in `paired_live_or_motion_video_id`!