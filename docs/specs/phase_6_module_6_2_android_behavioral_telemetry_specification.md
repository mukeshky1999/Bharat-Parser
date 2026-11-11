# Engineering Specification: Phase 6, Module 6.2 — Android Deep Behavioral Telemetry, Sensor & Usage Engine (`UsageStats` Protobuf/XML, 3-Source `AppOps` & Permission Controller APEX, `Digital Wellbeing`, `Health Connect` & `dropbox`/`netstats`)

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 6.2** of the Forensic Data Parser (corresponding to **Groups 8, 9, 10, 11, 14, and 15** of the Unified Master Register). It contains **zero programming code** and explains how to decode Android `UsageStats` binary Protocol Buffers and ABX/XML files (strictly separating `daily/` granular event logs from `weekly/`/`monthly/`/`yearly/` aggregates), the **3-Source Android `AppOps` & Privacy Dashboard Architecture** (minute-granularity Camera, Microphone, Location, and Overlay accesses), Google & Samsung `Digital Wellbeing`, Android 14–17 Framework `Health Connect`, `/data/system/dropbox/`, and per-UID `netstats` from first principles.

---

## 1. Purpose & Mental Model (How Android Proves Human Operation, Sensor Access & Ghost Apps)

On an Android device (Android 9 through Android 17), proving **what was on the screen, when the screen was unlocked, whether the camera or microphone was active, whether a sideloaded trojan abused `AccessibilityService` or `SYSTEM_ALERT_WINDOW` overlays, and whether the suspect was physically walking** relies on five interlocking operating-system telemetry stores:

1. **Android `UsageStats` (`/data/system_ce/<user_id>/usagestats/` & `/data/system/usagestats/`):** The kernel/framework ledger of every application activity lifecycle transition (`ACTIVITY_RESUMED`, `ACTIVITY_PAUSED`, `ACTIVITY_STOPPED`), screen interactive state (`SCREEN_INTERACTIVE`), keyguard lock/unlock state (`KEYGUARD_HIDDEN`), configuration rotation (`CONFIGURATION_CHANGE`), and device boot/shutdown.
2. **The 3-Source Android `AppOps` & Permission Controller Architecture:** Tracks every time any application—legitimate or malicious—accesses a sensitive hardware sensor or permission (`CAMERA`, `RECORD_AUDIO` \[Microphone\], `FINE_LOCATION`, `READ_SMS`, `SYSTEM_ALERT_WINDOW` \[Screen Overlay\], `BIND_ACCESSIBILITY_SERVICE`, `ACTIVATE_VPN`), including **Android 12–17's 7-Day Rolling Minute-Granularity Discrete Access Logs (`/data/system/appops/discrete/`)**.
3. **Google `Digital Wellbeing` & Samsung `Digital Wellbeing (Forest)`:** High-retention SQLite databases that record screen unlocks, per-app foreground sessions, and notification arrivals—frequently retaining history for **uninstalled "Ghost Apps"** long after the suspect deleted the app!
4. **Android `Health Connect`, `Samsung Health` & `Google Fit`:** The biometric and motion sensor ledger (transitioned in **Android 14–17** into a core system framework database at `/data/system_ce/<user_id>/healthconnect/healthconnect.db`).
5. **System Diagnostic Archives (`/data/system/dropbox/`, `/data/tombstones/`, `/data/system/netstats/` & `adb bugreport`):** Records app crashes (`data_app_crash`), Application Not Responding (`ANR`) freezes, system reboots, and per-app network data transmission counters (`netstats`).

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Android Telemetry Forensics

Before implementing Module 6.2, the developer must understand six critical traps that cause false timelines or missed evidence in amateur Android parsers:

### Mistake 1: Expecting Granular `ACTIVITY_RESUMED` Timelines Inside `weekly/`, `monthly/`, or `yearly/` `UsageStats` Files
* **The Trap:** Telling an investigator that `UsageStats` provides exact second-by-second app open/close event timelines for an entire year because `yearly/` files exist in `/usagestats/`.
* **Why It Fails:** As documented in our Master Register (Group 8), Android's `UsageStatsService` stores four subdirectories inside `/usagestats/<user_id>/`: **`daily/`**, **`weekly/`**, **`monthly/`**, and **`yearly/`**.
  * **ONLY the `daily/` files** (which are retained for approximately **$7\text{ to }10\text{ days}$**) store the granular **`events` (`EventLog`) array** containing individual `ACTIVITY_RESUMED`, `ACTIVITY_PAUSED`, and `KEYGUARD_HIDDEN` timestamps!
  * When Android rolls `daily/` files up into **`weekly/`**, **`monthly/`**, and **`yearly/`** files, **Android strips and discards the granular `events` array**, keeping only **aggregated package summaries** (`package_name`, `last_time_active`, `total_time_in_foreground_ms`, and `app_launch_count`)!
* **The Rule:** Parse `daily/` files into the **Granular Event Timeline (`android_usagestats_and_lifecycle_ledger`)**, and parse `weekly/`, `monthly/`, and `yearly/` files into the **Long-Term Aggregated Package Summary & Ghost-App Ledger**—never conflating an aggregated `last_time_active` timestamp with a continuous session!

### Mistake 2: Miscomputing Relative Protobuf Timestamps (`time_offset_ms`) Inside Binary `UsageStats` Files
* **The Trap:** Reading the integer field `time_ms` (Field 1 or Field 3 inside a binary `UsageStats` protobuf file) and treating it directly as a 13-digit Unix millisecond timestamp.
* **Why It Fails:** In Android 10–17 binary Protocol Buffer `UsageStats` files (`IntervalStatsProto`), to save space through smaller Varints, **individual package timestamps and `EventLog` timestamps are often stored as relative millisecond offsets (`time_offset_ms`) added to the file's `base_timestamp_ms` (which is the integer filename of the `UsageStats` file itself, e.g., `1762300800000`)**!
* **The Rule:** Always read the filename integer as `file_base_time_ms`. When decoding any timestamp field $T_{\text{raw}}$ inside the protobuf:
  * If $T_{\text{raw}} < 1,000,000,000,000$ (less than $10^{12}$, meaning it is a relative offset in milliseconds rather than an absolute Unix epoch ms):
    $$\text{Absolute Unix Milliseconds} = \text{file\_base\_time\_ms} + T_{\text{raw}}$$
  * If $T_{\text{raw}} \ge 1,000,000,000,000$ (already a 13-digit absolute Unix millisecond timestamp):
    $$\text{Absolute Unix Milliseconds} = T_{\text{raw}}$$

### Mistake 3: Parsing Only `/data/system/appops.xml` and Missing `/data/system/appops/discrete/` (Android 12–17)
* **The Trap:** Looking only at `/data/system/appops.xml` to see when WhatsApp, Telegram, or a spyware APK used the Camera or Microphone.
* **Why It Fails:** `/data/system/appops.xml` overwrites the timestamp `t` in place—meaning it only stores the **single most recent** access timestamp for each permission! However, starting in **Android 12 through Android 17**, Google introduced the **Privacy Dashboard Discrete Op History** stored in **`/data/system/appops/discrete/`**. Those files record **every single discrete Camera, Microphone, and Location access over the past 7 days** with minute-level precision, exact duration, and whether the app was in the foreground or background!
* **The Rule:** Sub-Engine 6.2B must parse **all three** `AppOps` & Permission Controller sources (Section 4).

### Mistake 4: Failing to Parse Android 12–17 `ABX` (`Android Binary XML` — `ABX\x00`) Files
* **The Trap:** Opening `/data/system/appops.xml`, `/data/system/users/0/package-restrictions.xml`, or `/data/system/urigrants.xml` on an Android 12–17 image with a standard text XML parser (`ElementTree` / `lxml`) and crashing with `xml.etree.ElementTree.ParseError: not well-formed (invalid token)`.
* **Why It Fails:** Starting in Android 12 (API 31), the Android system server serializes system XML files in `/data/system/` using Google's **`ABX` (`Android Binary XML`)** format, which starts with the 4-byte magic header **`41 42 58 00` (`"ABX\0"`)**!
* **The Rule:** Check the first $4\text{ bytes}$ of every `.xml` file in `/data/system/` and `/data/misc/`. If Bytes $0\text{–}3$ equal `41 42 58 00`, pass the stream through the **Built-In `ABX\x00` Binary Token Deserializer** (Section 4.1) before extracting XML elements and attributes!

### Mistake 5: Looking Only for the Legacy `Health Connect` APK Path on Android 14–17
* **The Trap:** Searching only `/data/data/com.google.android.apps.healthdata/` for Android Health Connect databases.
* **Why It Fails:** As documented in our Master Register (Group 14), in **Android 14 through Android 17**, Google migrated `Health Connect` out of `/data/data/` and made it a **System APEX / Framework service** (`com.google.android.healthconnect.controller`), moving its SQLite database to **`/data/system_ce/<user_id>/healthconnect/healthconnect.db`**!
* **The Rule:** Scan **both** the Android 14–17 system framework path (`/data/system_ce/<user_id>/healthconnect/healthconnect.db`) and the Android 13 APK path (`/data/user/<user_id>/com.google.android.apps.healthdata/databases/`) (Section 6.1).

### Mistake 6: Missing `UsageStats` Across Secondary User Profiles (`User 10`, `User 95`, `User 150`, `User 999`)
* **The Trap:** Parsing only `/data/system_ce/0/usagestats/`.
* **Why It Fails:** When a suspect runs a cloned instance of WhatsApp, Telegram, or PhonePe inside Dual Messenger (`User 95`), Secure Folder (`User 150`), or Xiaomi/Vivo App Cloner (`User 999`), the foreground/background `UsageStats` for those cloned apps are written to **`/data/system_ce/95/usagestats/`**, **`/data/system_ce/150/usagestats/`**, or **`/data/system_ce/999/usagestats/`**!
* **The Rule:** Enumerate `/data/system_ce/<user_id>/usagestats/` across **every user profile ID** discovered by Module 1.3.

---

## 3. Step 1 — Sub-Engine 6.2A: Android `UsageStats` Binary Protobuf & XML Decoder

### 3.1 Locating & Classifying `UsageStats` Files Across Android 9–17
Scan `vfs_index` for all files inside:
* Modern CE Path (Android 10–17): `/data/system_ce/<user_id>/usagestats/<interval_dir>/<timestamp_filename>`
* Legacy / System Path: `/data/system/usagestats/<user_id>/<interval_dir>/<timestamp_filename>`

Where `<interval_dir>` is one of:
1. **`daily/`**: Contains **both** aggregated package statistics **and** the granular **`events` (`EventLog`) array**!
2. **`weekly/`**, **`monthly/`**, **`yearly/`**: Contains **aggregated package statistics only** (`last_time_active`, `total_time_in_foreground`, `app_launch_count`).

### 3.2 Decoding Binary Protobuf `IntervalStatsProto` (`UsageStats`) Files
On Android 10–17, each file in `daily/`, `weekly/`, `monthly/`, and `yearly/` (whose filename is a 13-digit Unix millisecond integer `file_base_time_ms`) is a raw **Google Protocol Buffer (`IntervalStatsProto`)**:

1. **Pass the File Through Phase 2, Module 2.3D's Protobuf Decoder and Extract the 4 Root Sections:**
   * **Section A — `end_time_offset_ms` (`Field 1`, Varint):** Add to `file_base_time_ms` to get the end of this stats window.
   * **Section B — `stringpool` (`Field 2`, Nested Message):**
     * **Crucial Indexing Rule:** Android `IntervalStatsProto` stores a **1-based String Pool array** (`Field 2` $\rightarrow$ repeated `strings` UTF-8 array) at the top of the file! Inside the `packages` and `events` records below, package names and class names are referenced either by a direct string OR by a **1-based integer index (`package_index`, `class_index`)** pointing into `stringpool.strings[index - 1]`! Always build the `stringpool` array first!
   * **Section C — `packages` (`Field 20`, Repeated `UsageStatsProto`):**
     * For each package entry, extract:
       * `package_name` (from `stringpool[package_index - 1]` or direct string).
       * `last_time_active_ms` (`file_base_time_ms + last_time_active_offset`).
       * `total_time_active_ms` (Total foreground screen time in milliseconds during this interval).
       * `last_time_service_used_ms` & `total_time_service_used_ms` (Proves background service execution!).
       * `last_time_visible_ms` & `total_time_visible_ms`.
       * `app_launch_count` (Number of times the user launched this app).
     * **Ghost-App Detection Hook:** Cross-check `package_name` against Module 1.3 (`resolved_application_catalog`). If `package_name` is **not** currently installed in `packages.xml`, automatically register it in Module 1.3 as an **`UNINSTALLED_GHOST_APP`**!
   * **Section D — `event_log` (`Field 22`, Repeated `EventProto` — Present in `daily/` Files!):**
     * For each granular event, extract:
       * `package_name` (resolved via `stringpool`) & `class_name` (the exact Android `Activity` or `Service` class name—e.g., `com.phonepe.app.ui.upi.PinActivity` or `com.whatsapp.Conversation`!).
       * `event_timestamp_ms` (`file_base_time_ms + time_offset_ms`).
       * `event_type` (integer code — decode using Table 3.3 below).
       * `config` (for `event_type == 5`, extracts screen orientation rotation!).
       * `shortcut_id` / `notification_channel_id` (for `event_type == 8` or `10`/`12`).

### 3.3 Master Table of Android `UsageEvents.Event` Integer Codes

| `event_type` Code | Official Android Constant Name | Forensic Meaning in Pattern-of-Life Reconstruction |
|---|---|---|
| **`1`** | `ACTIVITY_RESUMED` (`MOVE_TO_FOREGROUND`) | **App / Activity Entered the Foreground on Screen!** (Inspect `class_name` to see which exact screen inside the app opened). |
| **`2`** | `ACTIVITY_PAUSED` (`MOVE_TO_BACKGROUND`) | **App / Activity Left the Foreground.** |
| **`5`** | `CONFIGURATION_CHANGE` | **Device Configuration Changed (Screen Rotation between Portrait `1` and Landscape `2`, or keyboard/locale change).** |
| **`7`** | `USER_INTERACTION` | **Direct Human Touch / Input Interaction** with the package. |
| **`8`** | `SHORTCUT_INVOCATION` | User tapped a direct home-screen or share-sheet shortcut (e.g., direct chat shortcut). |
| **`10`** & **`12`** | `NOTIFICATION_INTERRUPTION` & `NOTIFICATION_SEEN` | App posted an interrupting notification (`10`) and the user viewed it (`12`). |
| **`11`** | `STANDBY_BUCKET_CHANGED` | OS changed app standby priority (`ACTIVE` = `10`, `WORKING_SET` = `20`, `FREQUENT` = `30`, `RARE` = `40`). |
| **`15`** | `SCREEN_INTERACTIVE` | **Physical Display Turned ON (Interactive)!** |
| **`16`** | `SCREEN_NON_INTERACTIVE` | **Physical Display Turned OFF (Dark)!** |
| **`17`** | `KEYGUARD_SHOWN` | **Lockscreen Shown (Phone Locked)!** |
| **`18`** | `KEYGUARD_HIDDEN` | **Lockscreen Dismissed — Suspect Unlocked the Phone via PIN/Pattern/Biometrics!** |
| **`19`** & **`20`** | `FOREGROUND_SERVICE_START` & `STOP` | App started (`19`) or stopped (`20`) a persistent foreground service (such as an active VoIP call, voice recorder, GPS tracker, or malware screen-capture service!). |
| **`23`** | `ACTIVITY_STOPPED` | Activity window completely hidden/stopped. |
| **`26`** & **`27`** | `DEVICE_SHUTDOWN` & `DEVICE_STARTUP` | **Exact timestamp the Android phone powered OFF (`26`) and booted UP (`27`)!** |

---

## 4. Step 2 — Sub-Engine 6.2B: The 3-Source Android `AppOps` & Privacy Sensor Auditor

To prove when an application accessed the **Camera**, **Microphone**, **GPS Location**, **SMS**, **Clipboard**, **Screen Overlay (`SYSTEM_ALERT_WINDOW`)**, or **`AccessibilityService`**, Sub-Engine 6.2B parses all three Android permission-tracking stores.

### 4.1 Built-In `ABX` (`Android Binary XML` — `41 42 58 00`) Deserializer
Because Android 12–17 serializes `/data/system/appops.xml`, `/data/system/appops/discrete/*`, and `/data/system/packages.xml` in `ABX\x00` format:
1. Verify Bytes $0\text{–}3$ equal `41 42 58 00` (`"ABX\0"`).
2. Read sequential 1-byte token tags starting at Byte Offset $4$, where the **lower $4\text{ bits}$ (`tag & 0x0F`)** give the **Event Type** (`START_DOCUMENT = 0`, `END_DOCUMENT = 1`, `START_TAG = 2`, `END_TAG = 3`, `TEXT = 4`, `ATTRIBUTE = 15`) and the **upper $4\text{ bits}$ (`tag >> 4`)** give the **Data Type** (`TYPE_NULL = 1`, `TYPE_STRING = 2` \[2-byte `uint16_be` length + UTF-8 bytes\], `TYPE_STRING_INTERNED = 3` \[2-byte `uint16_be` index into dynamic interned string table; `0xFFFF` means read new string and append to interned table!\], `TYPE_BYTES_HEX = 4`, `TYPE_BYTES_BASE64 = 5`, `TYPE_INT = 6` \[`int32_be`\], `TYPE_INT_HEX = 7` \[`int32_be`\], `TYPE_LONG = 8` \[`int64_be`\], `TYPE_LONG_HEX = 9` \[`int64_be`\], `TYPE_FLOAT = 10`, `TYPE_DOUBLE = 11`, `TYPE_BOOLEAN_TRUE = 12`, `TYPE_BOOLEAN_FALSE = 13`).
3. Convert the token stream into a standard XML DOM tree for extraction.

### 4.2 Source 1: `/data/system/appops.xml` (Comprehensive Permission & Malware Op State)
Parse `/data/system/appops.xml` (`<app-ops>` $\rightarrow$ `<pkg n="<package_name>">` $\rightarrow$ `<uid id="<linux_uid>">` $\rightarrow$ `<op n="<op_code>" mode="<0=allow,1=ignore,2=errored>">` $\rightarrow$ `<st .../>`):
* **Unpack the Packed 64-Bit State Key `n` (`<st n="..." t="..." r="..." d="..."/>`):**
  * `t`: 13-digit Unix millisecond timestamp of **last successful access**!
  * `r`: 13-digit Unix millisecond timestamp of **last rejected/denied attempt**!
  * `d`: Duration of the access in milliseconds!
  * **High-Priority `op` Codes to Flag:**
    * `0`, `1`, `2`, `41`, `42`: Location & Contacts access.
    * `14`, `16`, `20`, `21`, `22`: **SMS Read / Receive / Send / Write** (flags SMS-stealing banking trojans!).
    * `24`: **`SYSTEM_ALERT_WINDOW` (Draw Over Other Apps — Screen Overlay Attack!)**.
    * `26`: **`CAMERA` (Physical Camera Capture!)**.
    * `27`: **`RECORD_AUDIO` (Physical Microphone Recording / VoIP Call!)**.
    * `29` & `30`: **`READ_CLIPBOARD` & `WRITE_CLIPBOARD`** (proves when an app read a copied crypto address or password from the clipboard!).
    * `43`: `GET_USAGE_STATS`.
    * `45`: **`ACTIVATE_VPN`** (proves the exact timestamp a VPN app activated its tunnel!).
    * `66` & `70`: **`REQUEST_INSTALL_PACKAGES` (Sideloading dropper!) & `BIND_ACCESSIBILITY_SERVICE` (Remote-control / screen-scraping trojan!)**.

### 4.3 Source 2: `/data/system/appops/discrete/` (Android 12–17 7-Day Rolling Minute-Granularity Sensor History)
In Android 12–17, `/data/system/appops/discrete/` contains binary `ABX` files storing the complete 7-day rolling timeline of discrete sensor accesses (`CAMERA`, `RECORD_AUDIO`, `FINE_LOCATION`, `COARSE_LOCATION`, `RECEIVE_EXPLICIT_USER_INTERACTION_AUDIO`):
* Traverse `<h>` $\rightarrow$ `<p pn="<package_name>">` $\rightarrow$ `<u ui="<uid>">` $\rightarrow$ `<o op="<op_code>">` $\rightarrow$ `<a at="<attribution_tag>">` $\rightarrow$ **`<e nt="<access_timestamp_ms>" nd="<duration_ms>" uf="<uid_state_flags>" ef="<op_flags>"/>`**:
  * **`nt` (`int64`):** Exact 13-digit Unix millisecond timestamp when the Camera, Microphone, or GPS access began!
  * **`nd` (`int64`):** Duration of the Camera, Microphone, or GPS usage in milliseconds (`-1` if instantaneous).
  * **`uf` (`uid_state`):** Indicates whether the app accessed the Camera/Microphone while in the **`FOREGROUND`** vs. silently in the **`BACKGROUND_SERVICE`**!

### 4.4 Source 3: Permission Controller APEX (`/data/misc_de/<user_id>/apexdata/com.android.permission/`)
Scan `/data/misc_de/<user_id>/apexdata/com.android.permission/` and `/data/user_de/<user_id>/com.google.android.permissioncontroller/databases/` (`permission_decisions.db` / `access_history_db`) via Module 2.1 to extract historical permission grant/revoke decisions and Privacy Dashboard logs.

---

## 5. Step 3 — Sub-Engine 6.2C: Google `Digital Wellbeing` & Samsung `Digital Wellbeing (Forest)`

1. **Google Digital Wellbeing (`/data/user/<id>/com.google.android.apps.wellbeing/databases/app_usage`):**
   * Stage `app_usage` (+ `app_usage-wal`) via Module 1.1 and process via **Module 2.1 (Active + `-wal` + Freelist)**.
   * Join `events` (or `app_usage_events`) with `packages` (`events.package_id = packages._id`):
     * Extract `package_name` (**retains package names of uninstalled Ghost Apps!**), `timestamp` (Unix ms), and `event_type` (`1` = Activity Resumed, `2` = Activity Paused, `unlock` events, and `notification` counts).
2. **Samsung Digital Wellbeing (`/data/user/<id>/com.samsung.android.forest/databases/dwbCommon.db`):**
   * Stage `dwbCommon.db` (+ `-wal`) via Module 2.1:
     * Extract `usage_events`, `screen_unlock_history`, and `app_usage_summary` (often retaining 30+ days of daily per-app usage and unlock counts on Samsung Galaxy devices!).

---

## 6. Step 4 — Sub-Engine 6.2D: Android `Health Connect`, `Samsung Health` & `Google Fit` Alibi Engine

1. **Android `Health Connect` (Android 14–17 System Framework `/data/system_ce/<user_id>/healthconnect/healthconnect.db` & Android 13 APK `/data/user/<user_id>/com.google.android.apps.healthdata/databases/`):**
   * Stage `healthconnect.db` (+ `-wal`) via Module 2.1.
   * Join `application_info_table` (`row_id`, `package_name`, `app_name`) with:
     * **`steps_record_table`:** `start_time`, `end_time`, `count` (steps), `app_info_id` (proves which sensor/app recorded the steps!), `device_type` (`0` = Unknown, `1` = Watch, `2` = **Phone**!).
     * **`heart_rate_record_table` & `heart_rate_record_series_table`:** `epoch_millis`, `beats_per_minute`.
     * **`distance_record_table`**, **`elevation_gained_record_table`**, **`sleep_session_record_table`**, and **`exercise_session_record_table`** (including `exercise_route` GPS coordinates!).
2. **Samsung Health (`com.sec.android.app.shealth`) & Google Fit (`com.google.android.apps.fitness`):**
   * Parse `/databases/*.db` (`step_daily_trend`, `pedometer_step_count`, `heart_rate`, `Sessions`, `DataPoints`) via Module 2.1.

---

## 7. Step 5 — Sub-Engine 6.2E: `/data/system/dropbox/`, `/data/tombstones/`, `netstats` & `adb bugreport`

1. **`/data/system/dropbox/` (System Event, Reboot, Crash & ANR Archive):**
   * Scan all `.txt` and `.gz` files in `/data/system/dropbox/` (filenames take the form `<tag>@<13_digit_unix_ms>.txt[.gz]`):
     * `SYSTEM_BOOT`, `SYSTEM_RESTART`, `SYSTEM_LAST_KMSG`, `SYSTEM_SHUTDOWN`: Exact hardware boot and shutdown timestamps + OS fingerprint.
     * `data_app_crash`, `system_app_crash`, `data_app_anr`, `SYSTEM_TOMBSTONE`: Proves when a specific app (`Process: <package_name>`, `PID`) crashed or froze—often revealing uninstalled apps, root tools, or failing malware!
2. **`/data/system/netstats/` & `DataUsage` (Per-UID Network Data Transmission Ledger):**
   * Parse the binary `netstats` files (`xt_*`, `uid_*`, `uid_tag_*`) and map each `linux_uid` back to its owning application via **Module 1.3 (`uid_ownership_lookup`)**:
     * Extracts 1-to-2 hour buckets (`bucket_start_ms`, `bucket_end_ms`) showing exact **`rx_bytes` (Downloaded Bytes)** and **`tx_bytes` (Uploaded Bytes)** over **Wi-Fi (`WIFI`)** vs. **Cellular (`MOBILE` + `subscriberId` / `IMSI`)**!
     * **Forensic Value:** Even if a suspect wiped their Telegram, Session, or WhatsApp database, `netstats` mathematically proves that `org.telegram.messenger` (`UID 10184`) uploaded $45\text{ MB}$ of data over Cellular SIM 1 between 2:00 AM and 3:00 AM!

---

## 8. Database Schema for Module 6.2 (`android_behavioral_telemetry_engine.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `android_usagestats_and_lifecycle_ledger` (Granular `daily/` Events, `Digital Wellbeing` & `dropbox` Lifecycle)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `android_event_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `android_user_profile_id` | `INTEGER` | `NOT NULL` | Android user profile (`0` Main, `10` Work, `95` Dual, `150` Secure Folder, `999` Cloner). |
| `telemetry_source` | `TEXT` | `NOT NULL` | Enum: `USAGESTATS_DAILY_EVENTLOG`, `USAGESTATS_AGGREGATE_ROLLUP`, `GOOGLE_DIGITAL_WELLBEING`, `SAMSUNG_FOREST_DWB`, `SYSTEM_DROPBOX_LOG`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source file in `vfs_index`. |
| `granularity_level` | `TEXT` | `NOT NULL` | **`GRANULAR_MILLISECOND_EVENT`** (from `daily/` EventLog, Wellbeing, or Dropbox) vs. **`AGGREGATED_INTERVAL_SUMMARY`** (from `weekly/`, `monthly/`, `yearly/`). |
| `package_name` | `TEXT` | `NOT NULL` | Android package name (e.g., `com.phonepe.app`, `com.whatsapp`). |
| `activity_or_service_class` | `TEXT` | `NULL` | Specific Java/Kotlin class name (e.g., `com.phonepe.app.ui.upi.PinActivity`). |
| `is_uninstalled_ghost_app` | `INTEGER` | `DEFAULT 0` | `1` if this package is no longer installed in `packages.xml` at seizure! |
| `event_category` | `TEXT` | `NOT NULL` | Enum: `ACTIVITY_RESUMED_FOREGROUND`, `ACTIVITY_PAUSED_BACKGROUND`, `KEYGUARD_UNLOCKED`, `KEYGUARD_LOCKED`, `SCREEN_ON_INTERACTIVE`, `SCREEN_OFF_DARK`, `SCREEN_ROTATION_CONFIG`, `FOREGROUND_SERVICE_START`, `FOREGROUND_SERVICE_STOP`, `DEVICE_SHUTDOWN`, `DEVICE_STARTUP`, `APP_CRASH_OR_ANR`, `AGGREGATED_USAGE_WINDOW`. |
| `event_timestamp_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `event_timestamp_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |
| `aggregated_fg_duration_sec` | `REAL` | `NULL` | Populated for interval summaries or paired resume-to-pause windows. |

### Table 2: `android_appops_and_privacy_sensor_audit` (3-Source `AppOps`, Discrete Camera/Mic/GPS & Malware Permissions)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `appop_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `source_subsystem` | `TEXT` | `NOT NULL` | Enum: `APPOPS_DISCRETE_7DAY_HISTORY`, `APPOPS_XML_SUMMARY`, `PERMISSION_CONTROLLER_APEX_DB`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source file in `vfs_index`. |
| `package_name` | `TEXT` | `NOT NULL` | Package that accessed the sensor/permission. |
| `linux_uid` | `INTEGER` | `NULL` | Linux UID (e.g., `10145`). |
| `op_code_and_name` | `TEXT` | `NOT NULL` | E.g., `"26:CAMERA"`, `"27:RECORD_AUDIO"`, `"1:FINE_LOCATION"`, `"24:SYSTEM_ALERT_WINDOW"`, `"70:BIND_ACCESSIBILITY_SERVICE"`, `"45:ACTIVATE_VPN"`. |
| `process_uid_state` | `TEXT` | `NULL` | `FOREGROUND_UI`, `FOREGROUND_SERVICE`, `BACKGROUND`, or `CACHED`. |
| `access_outcome` | `TEXT` | `NOT NULL` | `ALLOWED_GRANTED` vs. `REJECTED_DENIED`. |
| `access_timestamp_utc_iso` | `TEXT` | `NOT NULL` | Exact UTC ISO-8601 timestamp of the sensor/permission access (`nt` or `t`). |
| `access_duration_seconds` | `REAL` | `NULL` | Duration of Camera, Microphone, or Location use in seconds (`nd / 1000.0`). |

### Table 3: `android_health_and_network_usage_ledger` (`Health Connect` Sensor Alibi & Per-UID `netstats` Bandwidth)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `ledger_domain` | `TEXT` | `NOT NULL` | Enum: `HEALTH_CONNECT_FRAMEWORK`, `HEALTH_CONNECT_APK`, `SAMSUNG_OR_GOOGLE_FIT`, `NETSTATS_UID_BANDWIDTH`. |
| `package_or_source_app` | `TEXT` | `NOT NULL` | App package name (resolved from `linux_uid` for `netstats` or `application_info_table` for Health Connect). |
| `metric_type` | `TEXT` | `NOT NULL` | E.g., `STEP_COUNT`, `HEART_RATE_BPM`, `SLEEP_SESSION`, `WIFI_BYTES_TX_RX`, `CELLULAR_BYTES_TX_RX`. |
| `primary_numeric_value` | `REAL` | `NOT NULL` | Step count, BPM, or total bytes transferred (`rx_bytes + tx_bytes`). |
| `secondary_detail_json` | `TEXT` | `NULL` | JSON with `rx_bytes`, `tx_bytes`, `subscriber_imsi` (for `netstats`), or `device_type` (`PHONE` vs. `WATCH` for Health Connect). |
| `window_start_utc_iso` | `TEXT` | `NOT NULL` | Start of sensor or network bucket window. |
| `window_end_utc_iso` | `TEXT` | `NOT NULL` | End of sensor or network bucket window. |

---

## 9. Developer Acceptance Test Checklist for Module 6.2

1. **The `UsageStats` `daily/` Relative Offset & `stringpool` Resolution Test:** Construct a binary `IntervalStatsProto` file named `1762300800000` in `/data/system_ce/0/usagestats/daily/` where `stringpool[0] = "com.phonepe.app"`, `stringpool[1] = "com.phonepe.app.ui.PinActivity"`, and an `EventProto` has `package_index = 1`, `class_index = 2`, `time_offset_ms = 3600000` ($+1\text{ hour}$), and `event_type = 1` (`ACTIVITY_RESUMED`). Verify that Sub-Engine 6.2A resolves the 1-based stringpool indices and computes the exact timestamp `1762300800000 + 3600000 = 1762304400000` (`2026-11-05T01:00:00.000Z`).
2. **The `ABX\x00` Binary XML & `/appops/discrete/` Camera/Mic Test:** Feed an Android 14/16 `ABX\x00` file from `/data/system/appops/discrete/` containing `<p pn="org.telegram.messenger"><u ui="10184"><o op="27"><a at=""><e nt="1762348800000" nd="45000" uf="500"/>`. Verify that Sub-Engine 6.2B deserializes the `ABX\x00` binary stream, identifies `op="27"` as `RECORD_AUDIO` (Microphone), and records a $45.0\text{-second}$ microphone recording by Telegram at `1762348800000`.
3. **The Android 14–17 Framework `Health Connect` Path Test:** Place a `healthconnect.db` file at `/data/system_ce/0/healthconnect/healthconnect.db` with `steps_record_table` (`count = 820`, `device_type = 2` \[Phone\]). Verify that Sub-Engine 6.2D discovers the framework path and records the 820 phone-provenanced steps.