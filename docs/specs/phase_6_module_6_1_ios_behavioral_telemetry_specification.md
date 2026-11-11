# Engineering Specification: Phase 6, Module 6.1 — iOS Deep Behavioral Telemetry, Pattern-of-Life & Unified Log Engine (`knowledgeC.db`, 84 Apple Biome Streams, `tracev3` Unified Logs, Physical Orientation, `HealthDB` & `FSEvents`)

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 6.1** of the Forensic Data Parser (corresponding to **Groups 8, 9, 11, 14, 15, and 16** of the Unified Master Register). It contains **zero programming code** and explains how to decode `knowledgeC.db`, the 84 Apple Biome stream schemas, Apple Unified Logs (`.tracev3` + `/private/var/db/uuidtext/` string reconstruction), physical vs. display device orientation, `healthdb_secure.sqlite` sensor provenance, and `/.fseventsd/` gzipped v1/v2 binary logs from first principles so that any developer can build a courtroom-grade iOS pattern-of-life reconstruction engine.

---

## 1. Purpose & Mental Model (Why Behavioral Telemetry Resolves "Who Was Holding the Phone?")

In violent crime, homicide, hit-and-run, insider corporate espionage, and cyber-fraud investigations, recovering a chat message or a UPI payment is only half the case. The defence attorney's primary strategy in court is **Attribution Denial**:

* *"The phone was lying on a table; a background process or remote malware sent that message."*
* *"My client was asleep at 2:15 AM when the victim was assaulted; the phone never moved."*
* *"Those incriminating files were planted or deleted automatically by the OS, not by my client."*

**Module 6.1** answers the physical human-interaction question (**"Was a human holding, unlocking, rotating, walking with, and actively operating the iPhone at the exact second of the crime?"**) by correlating six independent iOS behavioral subsystems:

1. **CoreDuet (`knowledgeC.db`):** Tracks ~200 event stream types (`ZOBJECT` joined with `ZSTRUCTUREDMETADATA`), recording exact millisecond windows for which app was in the foreground (`/app/inFocus`), whether the screen was locked or unlocked (`/device/isLocked`), whether headphones or CarPlay were connected, and what intents the user executed.
2. **Apple Biome (84 Streams across 5 Categories):** Introduced in iOS 14–15 and expanded through iOS 26 to supplement CoreDuet. While **Phase 2, Module 2.3C** built the low-level binary `SEGB v1/v2` container parser, **Module 6.1** provides the semantic Protobuf field mappings for the 84 Biome streams.
3. **Apple Unified Logs (`.tracev3` + `uuidtext` / `dsc`):** High-frequency binary ring buffers in `/private/var/db/diagnostics/` that record ephemeral hardware and daemon events—including **Physical Device Orientation (`backboardd` / `CMDeviceOrientation`)**, volume/power button presses, screenshot captures, FaceID/TouchID authentication evaluations (`biometrickitd`), passkey assertions, and Lockdown Mode transitions.
4. **Apple Health (`healthdb_secure.sqlite`):** High-precision biometric and motion sensor ledger recording steps, distance walked/run, flights climbed, heart rate, and sleep states—with strict hardware provenance separating the iPhone's internal motion coprocessor from a paired Apple Watch.
5. **Screen Time (`RMAdminStore-Local.sqlite`):** Tracks per-app usage intervals and notifications across both the local iPhone and any iCloud-synced family/companion devices.
6. **File System Events (`/.fseventsd/`):** Gzipped binary kernel event logs (`1SLG` v1 and `2SLG` v2) recording every file creation, deletion, modification, and rename on the APFS Data volume—even after the referenced files have been permanently deleted.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in iOS Telemetry Forensics

Before implementing Module 6.1, the developer must understand six critical traps that invalidate amateur forensic reports in court:

### Mistake 1: Assuming Apple Biome Replaced `knowledgeC.db` on iOS 16–26
* **The Trap:** Checking if the iOS version is $\ge 16$, and if so, skipping `knowledgeC.db` and parsing only Biome (or vice versa).
* **Why It Fails:** As established in our Master Register (Group 8), **Biome has NOT completely replaced `knowledgeC.db`**. Depending on the exact iOS version (iOS 15 through iOS 26) and subsystem, some events are written exclusively to Biome, some are written exclusively to `knowledgeC.db`, and some are mirrored to both with different retention windows (~28 days in Biome vs. ~4 weeks in `knowledgeC.db`).
* **The Rule:** Always parse **both** `knowledgeC.db` and all present Biome `SEGB` streams, and unify them into the `ios_behavioral_timeline_ledger`.

### Mistake 2: Confusing "Display UI Orientation" with "Physical Device Handling Orientation"
* **The Trap:** Reporting that a suspect "physically rotated the phone to landscape" based on an app's UI orientation event, OR assuming a phone was untouched on a table because the screen remained locked and off.
* **Why It Fails:**
  1. **Display UI Orientation** (`SpringBoard` UI rotation) only changes when the screen is unlocked, rotation lock is off, and a foreground app rotates the screen layout.
  2. **Physical Device Orientation** (`backboardd` / `CoreMotion` `CMDeviceOrientation` inside Unified Logs `tracev3` and Biome `Device.Orientation`) is captured directly from the hardware accelerometer/gyroscope **even when the screen is locked and dark**! It records codes `1` (`Portrait`), `2` (`Portrait Upside-Down`), `3` (`Landscape Left`), `4` (`Landscape Right`), `5` (`Face Up`), and `6` (`Face Down`).
* **The Rule:** Strictly separate `PHYSICAL_SENSOR_ORIENTATION` from `DISPLAY_UI_ORIENTATION` in your database and UI (Section 5.3).

### Mistake 3: Trying to Parse `.tracev3` Files Without Staging `/private/var/db/uuidtext/`
* **The Trap:** Extracting only `/private/var/db/diagnostics/Persist/*.tracev3` out of an FFS archive and attempting to decode log messages from the `.tracev3` files alone.
* **Why It Fails:** To save disk space, Apple's Unified Logging system (`logd`) **never writes static format strings inside `.tracev3` files**! If a daemon logs `printf("User unlocked device with method %d", method_id)`, the `.tracev3` file stores only the 16-byte Mach-O binary UUID of the daemon, a 32-bit string offset, and the integer `method_id`. The actual format string `"User unlocked device with method %d"` is stored in a separate catalog directory at **`/private/var/db/uuidtext/`** (organized into 2-character hex folders `00/` through `FF/`, plus shared-cache files in `/private/var/db/uuidtext/dsc/`). Without the exact `/private/var/db/uuidtext/` directory from that same phone, `.tracev3` files cannot be reconstructed into full log strings.
* **The Rule:** Whenever staging Unified Logs from `vfs_index`, always stage `/private/var/db/diagnostics/` **and** `/private/var/db/uuidtext/` together as a mandatory co-file family (Section 5.1).

### Mistake 4: Attributing Apple Watch Steps or iCloud Screen Time to the Seized iPhone
* **The Trap:** Querying `SELECT count, start_date FROM samples;` in `healthdb_secure.sqlite` and testifying in court: *"The suspect walked 450 steps carrying this iPhone between 2:00 AM and 2:10 AM."*
* **Why It Fails:** If the suspect owns an Apple Watch (or a second iPhone/iPad signed into the same iCloud account), `healthdb_secure.sqlite` and `Screen Time` (`RMAdminStore`) sync records across all of the user's devices. If the suspect left their iPhone on the bedroom charger at home while wearing their Apple Watch outside, a naive query attributes those steps or app sessions to the seized iPhone.
* **The Rule:**
  * In `healthdb_secure.sqlite`, **always join `samples`** $\rightarrow$ **`objects`** $\rightarrow$ **`data_provenances`** $\rightarrow$ **`source_devices`** (`hardware` column, e.g., `"iPhone17,1"` vs. `"Watch7,5"`) and `sources` (`bundle_identifier`) before attributing sensor activity to the seized handset (Section 6).
  * In `Screen Time` (`RMAdminStore`) and `Biome` (`remote/<Device-UUID>/`), **always filter and label `local_device` vs. `remote_synced_device`**.

### Mistake 5: Reporting `FSEvents` (`/.fseventsd/`) With a Fake "Exact Timestamp"
* **The Trap:** Assigning the modification timestamp (`mtime`) of a gzipped `/.fseventsd/` log file directly to every file event inside that gzip file as if all 5,000 events happened at that exact second.
* **Why It Fails:**
  1. **Individual `FSEvents` records (`1SLG` / `2SLG`) contain ZERO internal wall-clock timestamps and ZERO user/PID identifiers.** Each record consists only of a null-terminated file path, a 64-bit monotonic `event_id`, and a 32-bit `event_flags` bitmask.
  2. You can only **bracket** the time window $[t_{\text{min}}, t_{\text{max}}]$ of an `FSEvents` record by finding the nearest preceding and succeeding `event_id`s whose referenced files still exist on the APFS filesystem (using their verified inode `btime`/`mtime`/`ctime` from Module 1.2) or by using the `mtime` of the containing gzip file as the upper bound $t_{\text{max}}$.
* **The Rule:** Implement the **Monotonic Event-ID Timestamp Bracketing Algorithm** (Section 7.3) so every `FSEvents` finding reports an honest, mathematically proven `[earliest_possible_utc, latest_possible_utc]` window.

### Mistake 6: Confusing `healthdb_secure.sqlite` Timestamps (`Record Time` vs. `Sync/Import Time`)
* **The Trap:** Confusing `objects.creation_date` with `samples.start_date` and `samples.end_date` in Apple Health.
* **Why It Fails:** `samples.start_date` and `samples.end_date` record the physical time window when the steps or heart rate occurred; `objects.creation_date` records when the batch was written/synced into the SQLite database (which can be hours later when an Apple Watch reconnects via Bluetooth). Always report all three timestamps distinctly.

---

## 3. Step 1 — Sub-Engine 6.1A: CoreDuet (`knowledgeC.db`) Deep Relational & Binary Plist Decoder

* **Canonical Target Paths in `vfs_index`:**
  1. Primary User Store (AFU Class C): `/private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db` (+ `-wal`)
  2. System Root Store: `/private/var/db/CoreDuet/Knowledge/knowledgeC.db` (+ `-wal`)

### 3.1 Step 1: The Master 4-Table CoreDuet Relational Join

Stage `knowledgeC.db` via Module 1.1 and process through **Phase 2, Module 2.1 (Active + `-wal` + Freelist)**. Execute the core relational join across `ZOBJECT`, `ZSTRUCTUREDMETADATA`, `ZSOURCE`, and `ZCUSTOMMETADATA`:

$$\texttt{ZOBJECT.ZSTRUCTUREDMETADATA} = \texttt{ZSTRUCTUREDMETADATA.Z\_PK}$$
$$\texttt{ZOBJECT.ZSOURCE} = \texttt{ZSOURCE.Z\_PK}$$

For every active, `-wal` historical, and freelist-carved row in `ZOBJECT`, extract:
1. **`ZSTREAMNAME` (`TEXT`):** Identifies which of the ~200 CoreDuet telemetry streams this row belongs to (see Table 3.2 below).
2. **Core Timestamps (All in Apple Cocoa Seconds Since `2001-01-01 00:00:00 UTC` — Convert via Module 1.2):**
   * **`ZSTARTDATE` (`REAL`):** Exact timestamp when the activity/state began.
   * **`ZENDDATE` (`REAL`):** Exact timestamp when the activity/state ended.
   * **`ZCREATIONDATE` (`REAL`):** Timestamp when the CoreDuet daemon committed the row to SQLite.
   * **Calculated Duration:** $\text{duration\_seconds} = \text{ZENDDATE} - \text{ZSTARTDATE}$.
   * **`ZSECONDSFROMGMT` (`INTEGER`):** The device's active local timezone offset in seconds from UTC at the exact moment of this event (e.g., `19800` seconds $= +05:30$ **`IST` India**; `14400` seconds $= +04:00$ **`GST` Dubai/UAE**).
3. **Primary Value Columns in `ZOBJECT`:** `ZVALUESTRING`, `ZVALUEINTEGER`, `ZVALUEDOUBLE`.
4. **Device & Source Provenance (`ZSOURCE` Table):** `ZBUNDLEID`, `ZDEVICEID` (`NULL` = local iPhone; non-null UUID = synced from another iCloud device), and `ZINTENTCLASS`.

### 3.2 High-Priority `ZSTREAMNAME` Forensic Mapping Table & `ZSTRUCTUREDMETADATA` Unpacking

| `ZOBJECT.ZSTREAMNAME` | Forensic Event Meaning | Primary Value (`ZVALUESTRING` / `ZVALUEINTEGER`) | Key `ZSTRUCTUREDMETADATA` Columns & Blobs to Unpack |
|---|---|---|---|
| **`/app/inFocus`** | **Foreground App Execution Window** (Proves which app was actively open on screen from `ZSTARTDATE` to `ZENDDATE`) | `ZVALUESTRING` = App Bundle ID (e.g., `com.phonepe.PhonePeApp`, `net.whatsapp.WhatsApp`) | `Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON`, `Z_DKAPPLICATIONMETADATAKEY__EXTENSIONHOSTIDENTIFIER`. |
| **`/app/usage`** & **`/app/activity`** | App user activity & NSUserActivity handoff states | `ZVALUESTRING` = Bundle ID | `Z_DKAPPLICATIONACTIVITYMETADATAKEY__ACTIVITYTYPE`, `Z_DKAPPLICATIONACTIVITYMETADATAKEY__TITLE`, `Z_DKAPPLICATIONACTIVITYMETADATAKEY__USERACTIVITYREQUIREDSTRING` (binary plist containing deep-link URLs and screen titles). |
| **`/app/intents`** | **Siri / App Intents** (Triggered when sending a message, placing a VoIP call, or paying via an app) | `ZVALUESTRING` = Intent Verb | **`Z_DKINTENTMETADATAKEY__SERIALIZEDINTERACTION` (`BLOB`):** An Apple Binary Plist (`bplist00` / `NSKeyedArchiver`) containing the **recipient contact name, handle/phone number, and message snippet** of a WhatsApp/Telegram/Signal/SMS action. |
| **`/app/webUsage`** & **`/safari/history`** | Web page foreground engagement in Safari / WebView | `ZVALUESTRING` = Domain or URL | `Z_DKDIGITALHEALTHMETADATAKEY__WEBPAGEURL`, `Z_DKDIGITALHEALTHMETADATAKEY__WEBDOMAIN`. |
| **`/device/isLocked`** | **Screen Lock / Unlock State** | `ZVALUEINTEGER`: `1` = **Locked**; `0` = **Unlocked** | Proves the exact second the iPhone was unlocked (`0`) and relocked (`1`). |
| **`/device/isPluggedIn`** & **`/device/batteryPercentage`** | Charger Connection & Battery Drain Curve | `ZVALUEINTEGER`: `1` = Charging, `0` = Unplugged; or `0–100` % | `Z_DKBATTERYGBMETADATAKEY__ISFULLYCHARGED`, adapter type (USB data port vs. AC wall charger). |
| **`/display/isBacklit`** | **Screen Backlight On / Off** | `ZVALUEINTEGER`: `1` = Screen Lit; `0` = Screen Dark | Corroborates `/device/isLocked` (a screen can light up (`1`) for a notification while remaining locked (`1`)). |
| **`/audio/outputRoute`** & **`/audio/inputRoute`** | Audio Speaker, Earpiece, Wired Headset, or Bluetooth Routing | `ZVALUESTRING` = Route Type (`Receiver`, `Speaker`, `Headphones`, `BluetoothA2DPOutput`) | `Z_DKAUDIOOMMETADATAKEY__PORTNAME` (e.g., `"Rahul's AirPods Pro"`, `"Car Audio"`), `Z_DKAUDIOOMMETADATAKEY__PORTIDENTIFIER` (Bluetooth MAC address). |
| **`/bluetooth/isConnected`** & **`/carplay/isConnected`** | Bluetooth & Vehicle Infotainment Connection | `ZVALUEINTEGER` = `1` / `0` | `Z_DKBLUETOOTHMETADATAKEY__NAME` (Vehicle or headset name), `Z_DKBLUETOOTHMETADATAKEY__ADDRESS` (MAC), `Z_DKBLUETOOTHMETADATAKEY__DEVICETYPE`. |
| **`/nowPlaying/info`** | Media / Voice Note / Video Currently Playing | `ZVALUESTRING` = App Bundle ID | `Z_DKNOWPLAYINGMETADATAKEY__TITLE`, `ALBUM`, `ARTIST`, `DURATION` (tracks voice notes played in WhatsApp/Telegram or videos watched in browsers). |
| **`/notification/usage`** | Notification Banner Arrival & User Action | `ZVALUESTRING` = Event (`Receive`, `DefaultAction` \[Tapped\], `Dismiss`, `Orb` \[Long-press\]) | `Z_DKNOTIFICATIONUSAGEMETADATAKEY__BUNDLEID`, `Z_DKNOTIFICATIONUSAGEMETADATAKEY__IDENTIFIER`. |

---

## 4. Step 2 — Sub-Engine 6.1B: The 84 Apple Biome Streams (`SEGB v1/v2`) Semantic Mapper & Screen Time (`RMAdminStore`)

### 4.1 Mapping the 5 Categories of Apple Biome Streams (iOS 15–26)

Using **Phase 2, Module 2.3C's `SEGB v1/v2` Decoder** (`biome_segb_records_master`), Sub-Engine 6.1B maps all 84 Biome streams located in `/private/var/db/biome/streams/restricted/`, `/private/var/db/biome/streams/public/`, and `/private/var/mobile/Library/Biome/streams/` into five forensic categories:

1. **Category 1 — Application & Intent Streams (`App.InFocus`, `App.Intent`, `App.Activity`, `App.WebUsage`, `App.Clip`, `App.MediaUsage`):**
   * In `App.InFocus`: Extract `bundleID`, `launchReason`, `starting` (`1` = App entered foreground, `0` = App left foreground), `absoluteTimestamp` (Cocoa seconds inside Protobuf), and `segb_write_utc_iso`.
   * In `App.Intent`: Unpack the embedded `interaction` binary plist inside the Protobuf field to extract the exact contact handle and intent parameters.
2. **Category 2 — Device State, Orientation & Hardware Streams (`Device.ScreenLocked`, `Device.BootSession`, `Device.BatteryPercentage`, `Device.Charging`, `Device.Orientation`, `Device.Metadata`, `Device.TimeZone`, `Device.Display.Backlight`, `Device.Torch`):**
   * **`Device.Orientation`**: Extracts physical orientation changes (`Portrait`, `LandscapeLeft`, `LandscapeRight`, `FaceUp`, `FaceDown`).
   * **`Device.Torch`**: Proves the exact second the suspect turned the iPhone's **Flashlight / Torch** on and off (crucial in night-time burglary, assault, and outdoor cash-drop investigations!).
3. **Category 3 — Connectivity, Location & Environment Streams (`Location.Semantic`, `Location.MicroLocationVisit`, `Location.PointOfInterest`, `Location.SignificantVisit`, `Connectivity.WiFi`, `Connectivity.Bluetooth`, `Connectivity.Cellular`, `CarPlay.Connected`, `Audio.Route`):**
   * **`Location.Semantic`**: Labels whether the user was at `Home`, `Work`, `School`, or `Gym` with arrival/departure timestamps.
   * **`Connectivity.WiFi` & `Bluetooth`**: Logs connected `SSID`/`BSSID` and Bluetooth device names/MACs.
4. **Category 4 — User Focus, Sleep & Activity Streams (`UserFocus.ComputedMode`, `UserFocus.DoNotDisturb`, `SleepMode`, `Activity.Level`, `Motion.Activity`):**
   * Proves when the phone entered `Sleep`, `Driving`, `Work`, or `Personal` Focus modes, and whether `Motion.Activity` detected `Stationary`, `Walking`, `Running`, `Cycling`, or `Automotive` motion.
5. **Category 5 — Communication, Safari, Text Input & Media Streams (`Notification.Usage`, `Safari.PageView`, `Safari.AutoFill`, `Text.InputSession`, `Media.NowPlaying`, `Photos.View`, `Messages.Read`, `FindMy.Location`):**
   * **`Text.InputSession`**: Records the exact start time, duration, and bundle ID of **every keyboard typing session** (proving the user was actively typing on the keyboard inside an app at that second!).

### 4.2 iOS Screen Time (`RMAdminStore-Local.sqlite` & `RMAdminStore-Cloud.sqlite`)

Stage `/private/var/mobile/Library/Application Support/com.apple.remotemanagementd/RMAdminStore-Local.sqlite` (and `-Cloud.sqlite`) via Module 2.1:
* Join `ZUSAGETIMEDITEM` (app usage duration in seconds), `ZUSAGECATEGORYITEM`, `ZUSAGECOUNTEDITEM` (number of notifications and number of **Device Pickups** per hour!), `ZUSAGEBLOCK` (`ZSTARTDATE`, `ZENDDATE`, `ZFIRSTPICKUPDATE` — **the exact second the user first picked up the phone in that block!**), and `ZCOREDEVICE` (`ZNAME`, `ZIDENTIFIER`, `ZPLATFORM` — strictly separating the seized iPhone from any iCloud-synced iPad, Mac, or family device!).

---

## 5. Step 3 — Sub-Engine 6.1C: Native Apple Unified Logs (`.tracev3` + `uuidtext` / `dsc`) & Physical Orientation Engine

### 5.1 Staging & Decoding `.tracev3` Binary Chunks with `/private/var/db/uuidtext/`

1. **Locate the Unified Log Family in `vfs_index`:**
   * Persistent Logs: `/private/var/db/diagnostics/Persist/*.tracev3`
   * High-Volume / Special Logs: `/private/var/db/diagnostics/Special/*.tracev3` and `/Signpost/*.tracev3`
   * Live / In-Flight Memory Flush (if captured by sysdiagnose/FFS): `/private/var/db/diagnostics/HighVolume/*.tracev3`
   * Timesync Database (Boot-UUID to Wall-Clock Anchor): `/private/var/db/diagnostics/timesync/*.timesync`
   * String Catalogs: `/private/var/db/uuidtext/00/` .. `FF/` and `/private/var/db/uuidtext/dsc/`
2. **How `.tracev3` Timestamps Are Anchored to UTC (`timesync` Math):**
   * Inside a `.tracev3` file, individual log firehose chunks record **64-bit Mach Continuous Time ticks (`mach_continuous_time`)** relative to a **Header Boot UUID**.
   * Read the `.timesync` files in `/private/var/db/diagnostics/timesync/` (each boot header starts with magic `0xbbb0`, 16-byte `boot_uuid`, `timebase_numerator`, `timebase_denominator`, `kernel_anchor_tick`, and `wallclock_anchor_utc_ns`; subsequent time-sync records start with magic `0x0020`).
   * For any log entry with tick value $T_{\text{mach}}$ under matching `boot_uuid`, compute its exact UTC nanosecond timestamp using the nearest preceding `.timesync` anchor:
     $$\text{UTC Nanoseconds} = \text{WallClockAnchor}_{\text{ns}} + \left\lfloor \frac{\left(T_{\text{mach}} - \text{KernelAnchorTick}\right) \times \text{Numerator}}{\text{Denominator}} \right\rfloor$$
3. **Decompressing `.tracev3` `LZ4` (`bv41`) Chunks & Resolving Strings:**
   * Walk sequential 16-byte aligned chunks inside each `.tracev3` file (`0x1000` Header chunk, `0x6001` Firehose chunk, `0x6002` Oversize chunk, `0x6003` State chunk, and `0x600d` Compressed chunk using Apple `bv41` / `LZ4` compression).
   * Resolve the format string offset against the corresponding 16-byte UUID file in `/private/var/db/uuidtext/<UU>/<UUUU...>` or `/dsc/` shared cache and format the dynamic arguments into the reconstructed log line.

### 5.2 High-Value Forensic Predicates Extracted from Unified Logs (`.tracev3`)

Sub-Engine 6.1C filters reconstructed Unified Log records for seven high-value forensic event classes:

| Target Process / Subsystem | Subsystem / Category Predicate | Forensic Evidence Extracted |
|---|---|---|
| **`backboardd` & `SpringBoard`** | `com.apple.BackBoard` / `Orientation` / `Button` | **Physical Device Orientation (`1–6`)**, **Display UI Orientation (`1–4`)**, physical **Power / Lock Button presses**, **Volume Up/Down presses**, and **Screenshot button chord** triggers. |
| **`biometrickitd` & `LocalAuthentication`** | `com.apple.BiometricKit` / `CoreAuth` | **FaceID & TouchID Evaluations:** Proves whether a human face (`FaceDetect: 1`, `Match: 1`) or registered finger unlocked the phone vs. failed face match (`Match: 0`) vs. passcode fallback! |
| **`sharingd` (AirDrop)** | `com.apple.sharing` / `AirDrop` | **AirDrop Transfers:** Sender/Receiver device name, Apple ID hash, media filename, and transfer completion timestamp. |
| **`lockdownd` & `usbmuxd`** | `com.apple.mobile.lockdown` | **USB Computer Pairing (`HostID`):** Exact timestamp when the iPhone was plugged into a Mac/PC and whether `"Trust This Computer"` was approved. |
| **`AuthenticationServices` (`Passkeys`)** | `com.apple.AuthenticationServices` | **WebAuthn / Passkey Sign-Ins:** Relying Party domain (`rpId`) and biometric assertion timestamp (`iLEAPP v2026.4.6` aligned). |
| **`MobileSafari`** | `com.apple.mobilesafari` | **Private Browsing Tab Eviction & Memory Warnings:** Proves when Safari Private Browsing tabs were active and purged. |
| **`locationd` & `CoreMotion`** | `com.apple.locationd.Motion` | Pedestrian step cadence, vehicle driving state transitions, and barometer altitude changes. |

### 5.3 Distinguishing Physical Orientation (`CMDeviceOrientation`) vs. Display UI Orientation

Whenever `backboardd`, `SpringBoard`, or Biome `Device.Orientation` logs an orientation integer, classify it strictly into its hardware or UI category:
* **`PHYSICAL_SENSOR_ORIENTATION` (`CMDeviceOrientation` / `BKSDeviceOrientation` — Active Even When Screen Is Locked!):**
  * `1` = **`Portrait` (Held upright vertically)**
  * `2` = **`Portrait Upside-Down`**
  * `3` = **`Landscape Left` (Tilted horizontal left)**
  * `4` = **`Landscape Right` (Tilted horizontal right)**
  * `5` = **`Face Up` (Lying flat on a surface with screen facing ceiling)**
  * `6` = **`Face Down` (Lying flat on a surface with screen facing table)**
* **`DISPLAY_UI_ORIENTATION` (`UIInterfaceOrientation` — Active Only When Screen Is Unlocked & Rotating):**
  * `1` = `UI_Portrait`, `2` = `UI_PortraitUpsideDown`, `3` = `UI_LandscapeLeft`, `4` = `UI_LandscapeRight`.

---

## 6. Step 4 — Sub-Engine 6.1D: Apple Health (`healthdb_secure.sqlite`) Sensor & Alibi Provenance Engine

* **Canonical Target Paths in `vfs_index`:**
  * `/private/var/mobile/Library/Health/healthdb_secure.sqlite` (+ `-wal`)
  * `/private/var/mobile/Library/Health/healthdb.sqlite` (+ `-wal`)

### 6.1 The Mandatory 6-Table Hardware Provenance Join
To prevent false courtroom attribution (confusing Apple Watch steps with iPhone steps), Stage `healthdb_secure.sqlite` via Module 1.1, process via **Module 2.1 (Active + `-wal` + Freelist)**, and execute this exact 6-table join:

$$\texttt{samples.data\_id} = \texttt{objects.data\_id}$$
$$\texttt{objects.provenance} = \texttt{data\_provenances.ROWID}$$
$$\texttt{data\_provenances.device\_id} = \texttt{source\_devices.ROWID}$$
$$\texttt{data\_provenances.source\_id} = \texttt{sources.ROWID}$$

Join `samples` to `quantity_samples` (`samples.data_id = quantity_samples.data_id`) for numeric sensor metrics, and to `category_samples` (`samples.data_id = category_samples.data_id`) for categorical states:

1. **Key `samples.data_type` Integer Codes:**
   * `7`: **`StepCount`** (`quantity` = number of physical steps taken between `start_date` and `end_date`)
   * `8`: **`DistanceWalkingRunning`** (`quantity` = distance in meters/kilometers)
   * `12`: **`FlightsClimbed`** (`quantity` = floors of elevation gained, ~3 meters per flight via barometer)
   * `5`: **`HeartRate`** (`quantity` = beats per minute $\times 60$ or BPM; **spike in heart rate at exact timestamp of violent crime/assault!**)
   * `9` & `10`: **`BasalEnergyBurned` & `ActiveEnergyBurned`**
   * `63`: **`SleepAnalysis`** (`category_samples.value`: `0` = InBed, `1` = Asleep, `2` = Awake, `3` = Core, `4` = Deep, `5` = REM)
   * `70`: **`AppleStandHour` / Watch Worn State**
2. **Mandatory Hardware & Timestamp Separation Columns:**
   * **`hardware_device_model`** (`source_devices.hardware` / `name`): E.g., `"iPhone16,2"` (Proves the **seized iPhone itself** was physically carried!) vs. `"Watch7,1"` (Proves the **Apple Watch** recorded the movement).
   * **`source_bundle_id`** (`sources.bundle_identifier`): E.g., `com.apple.health.<UUID>` (Native hardware motion coprocessor) vs. third-party fitness app (which allows manual user entry—also check `metadata_values` for `HKWasUserEntered == 1` to detect forged/manually typed steps!).
   * **`activity_start_utc_iso` & `activity_end_utc_iso`**: Converted from `samples.start_date` and `samples.end_date` (Cocoa seconds).
   * **`db_committed_utc_iso`**: Converted from `objects.creation_date` (Cocoa seconds when written/synced to SQLite).

---

## 7. Step 5 — Sub-Engine 6.1E: APFS File System Events (`/.fseventsd/`) Binary `1SLG`/`2SLG` Parser & Timestamp Bracketing

* **Canonical Target Paths in `vfs_index`:**
  * `/private/var/root/.fseventsd/*` or `/System/Volumes/Data/.fseventsd/*` or `/.fseventsd/*` (filenames are 16-character hexadecimal numbers representing the starting 64-bit `event_id`, e.g., `000000000008a4f2`).

### 7.1 Step 1: Decompressing & Parsing `1SLG` (v1) and `2SLG` (v2) Binary Pages
Each file in `/.fseventsd/` is a **GZIP-compressed (`1F 8B 08`) stream** containing one or more concatenated **`1SLG` (`FSEvents v1`)** or **`2SLG` (`FSEvents v2`)** binary pages:

1. **Read the 12-Byte Page Header:**
   * **Bytes $0\text{–}3$ (`signature`, ASCII):** Must equal **`31 53 4C 47` (`"1SLG"`)** or **`32 53 4C 47` (`"2SLG"`)**.
   * **Bytes $4\text{–}7$ (`unknown_version`, `uint32_le`).**
   * **Bytes $8\text{–}11$ (`page_byte_size`, `uint32_le`):** Total byte length $P_{\text{len}}$ of this page (including the 12-byte header).
2. **Iterate Through Records Inside the Page (Bytes $12\text{ to } P_{\text{len}} - 1$):**
   Set cursor `pos = 12`. While `pos < P_len`:
   * **Field 1 (`full_file_path`):** Read a **null-terminated (`0x00`) UTF-8 string** starting at `pos`. Advance `pos` past the `0x00` byte.
   * **Field 2 (`event_id`, `uint64_le`):** Read an 8-byte Little-Endian unsigned integer (`pos` to `pos + 8`). Advance `pos += 8`.
   * **Field 3 (`event_flags`, `uint32_le`):** Read a 4-byte Little-Endian unsigned integer (`pos` to `pos + 4`). Advance `pos += 4`.
   * **Field 4 (`node_inode_id`, `uint64_le` — Present ONLY in `"2SLG"` v2 Pages!):**
     * If `signature == "2SLG"`, read an 8-byte Little-Endian unsigned integer (`pos` to `pos + 8`) representing the **APFS Inode / CNID (`node_id`)**! Advance `pos += 8`.

### 7.2 Exact `FSEvents` 32-Bit `event_flags` Bitmask Table
Decode `event_flags` using bitwise-AND checks:
* `0x00000001`: `ItemCreated` | `0x00000002`: `ItemRemoved` (**Deleted!**) | `0x00000004`: `InodeMetaMod` | `0x00000008`: `ItemRenamed` | `0x00000010`: `ItemModified` | `0x00000020`: `FinderInfoMod` | `0x00000040`: `ChangeOwner` | `0x00000080`: `XattrMod` | `0x01000000`: `IsFile` | `0x02000000`: `IsDir` | `0x04000000`: `IsSymlink` | `0x08000000`: `Mount / Unmount`.

### 7.3 The Monotonic `event_id` Timestamp Bracketing Algorithm
Because `FSEvents` records have **no internal timestamps**:
1. Sort all extracted `FSEvents` records across all `/.fseventsd/` files by `event_id` ascending.
2. For each record $k$ that references a file (`node_inode_id` or `full_file_path`) that **still exists** in `vfs_index` (Module 1.1) and has only a single `ItemCreated` (`0x01`) event in `FSEvents`, anchor its timestamp $t_k$ to that file's verified APFS `btime` (Creation Timestamp from Module 1.2).
3. For any deleted file record $m$ (`ItemRemoved`) sitting between an earlier anchored event $a$ ($e_a < e_m$, timestamp $t_a$) and a later anchored event $b$ ($e_m < e_b$, timestamp $t_b$, or the gzip container file's `mtime` if no later anchor exists):
   * Assign the mathematically proven **Bracketed Time Window**:
     $$\text{earliest\_possible\_utc} = t_a, \qquad \text{latest\_possible\_utc} = \min(t_b, \ t_{\text{gzip\_mtime}})$$

---

## 8. Database Schema for Module 6.1 (`ios_behavioral_telemetry_engine.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `ios_behavioral_timeline_ledger` (Unified `knowledgeC`, 84 Biome Streams, `Screen Time` & `tracev3` Events)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `ios_telemetry_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `telemetry_source_engine` | `TEXT` | `NOT NULL` | Enum: `COREDUET_KNOWLEDGEC`, `APPLE_BIOME_SEGB`, `SCREENTIME_RMADMIN`, `UNIFIED_LOG_TRACEV3`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, `PARTIAL_RECORD`). |
| `device_locality` | `TEXT` | `NOT NULL` | **`LOCAL_SEIZED_IPHONE`** vs. **`REMOTE_SYNCED_ICLOUD_DEVICE:<UUID>`** (prevents cross-device confusion!). |
| `stream_or_subsystem_name` | `TEXT` | `NOT NULL` | E.g., `/app/inFocus`, `Device.Orientation`, `backboardd:PhysicalOrientation`, `biometrickitd:FaceID`. |
| `event_category` | `TEXT` | `NOT NULL` | Enum: `APP_IN_FOCUS`, `SCREEN_LOCK_UNLOCK`, `DISPLAY_BACKLIGHT`, `PHYSICAL_SENSOR_ORIENTATION`, `DISPLAY_UI_ORIENTATION`, `FACEID_TOUCHID_AUTH`, `KEYBOARD_TYPING_SESSION`, `TORCH_FLASHLIGHT`, `AUDIO_BT_CARPLAY_ROUTE`, `SIRI_APP_INTENT`, `HARDWARE_BUTTON_PRESS`. |
| `target_app_bundle_id` | `TEXT` | `NULL` | Associated application Bundle ID (if applicable). |
| `primary_state_or_value` | `TEXT` | `NOT NULL` | E.g., `"UNLOCKED"`, `"Portrait (1)"`, `"FaceDown (6)"`, `"FaceID Match Success"`, or Bundle ID. |
| `unpacked_metadata_json` | `TEXT` | `NULL` | Unpacked `ZSTRUCTUREDMETADATA`, Intent contact/message plist, or Biome Protobuf JSON. |
| `start_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `start_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 start timestamp. |
| `end_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 end timestamp (for interval events). |
| `duration_seconds` | `REAL` | `NULL` | Duration in seconds. |
| `recorded_tz_offset_sec` | `INTEGER` | `NULL` | `ZSECONDSFROMGMT` active on the phone at the moment of the event. |

### Table 2: `ios_health_sensor_alibi_ledger` (Hardware-Provenanced Steps, Distance, Flights, Heart Rate & Sleep)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `health_sample_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `healthdb_secure.sqlite` in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `sensor_metric_type` | `TEXT` | `NOT NULL` | Enum: `STEP_COUNT`, `DISTANCE_WALK_RUN_METERS`, `FLIGHTS_CLIMBED`, `HEART_RATE_BPM`, `SLEEP_STAGE`, `ACTIVE_ENERGY`. |
| `metric_value` | `REAL` | `NOT NULL` | Numeric value (e.g., `412` steps, `148.0` BPM). |
| `hardware_source_model` | `TEXT` | `NOT NULL` | **`source_devices.hardware`** (e.g., `"iPhone16,2"` vs. `"Watch7,1"`). |
| `is_local_iphone_sensor` | `INTEGER` | `NOT NULL` | `1` if recorded by the seized iPhone's internal coprocessor; `0` if synced from an Apple Watch or external app. |
| `was_manually_user_entered` | `INTEGER` | `DEFAULT 0` | `1` if `HKWasUserEntered == 1` (warns examiner of manually typed/spoofed health entry!). |
| `activity_start_utc_iso` | `TEXT` | `NOT NULL` | Physical sensor window start (`samples.start_date`). |
| `activity_end_utc_iso` | `TEXT` | `NOT NULL` | Physical sensor window end (`samples.end_date`). |
| `db_sync_committed_utc_iso` | `TEXT` | `NOT NULL` | Database write timestamp (`objects.creation_date`). |

### Table 3: `ios_fsevents_filesystem_audit` (Decompressed `1SLG`/`2SLG` File Events & Bracketed Time Windows)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `fsevent_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `gzip_source_file_name` | `TEXT` | `NOT NULL` | Name of the `/.fseventsd/` gzipped file (e.g., `000000000008a4f2`). |
| `fsevent_format_version` | `TEXT` | `NOT NULL` | `"1SLG"` (v1) or `"2SLG"` (v2). |
| `monotonic_event_id` | `INTEGER` | `NOT NULL` | 64-bit `event_id` (indexed for chronological ordering!). |
| `target_file_path` | `TEXT` | `NOT NULL` | Full APFS path recorded in the event. |
| `apfs_inode_node_id` | `INTEGER` | `NULL` | 64-bit `node_id` (populated in `"2SLG"` v2 records). |
| `decoded_flags_list` | `TEXT` | `NOT NULL` | E.g., `"IsFile | ItemCreated | ItemRemoved"`. |
| `does_file_still_exist` | `INTEGER` | `NOT NULL` | `1` if present in `vfs_index`; `0` if deleted from live filesystem! |
| `bracket_earliest_utc_iso` | `TEXT` | `NULL` | Lower-bound timestamp $t_{\text{min}}$ from preceding inode anchor. |
| `bracket_latest_utc_iso` | `TEXT` | `NOT NULL` | Upper-bound timestamp $t_{\text{max}}$ from succeeding inode anchor or gzip container `mtime`. |

---

## 9. Developer Acceptance Test Checklist for Module 6.1

1. **The `knowledgeC` + `Biome` Dual Ingestion & `ZSECONDSFROMGMT` Test:** Feed a `knowledgeC.db` row (`/app/inFocus`, `ZVALUESTRING = "com.phonepe.PhonePeApp"`, `ZSTARTDATE = 784041600.0`, `ZSECONDSFROMGMT = 19800`) and a Biome `Device.Torch` `SEGB v2` record. Verify that Sub-Engine 6.1A/B normalizes both into `ios_behavioral_timeline_ledger` and records the `+05:30 IST` (`19800` sec) timezone offset.
2. **The Physical Orientation (`backboardd`) vs. UI Orientation (`SpringBoard`) Separation Test:** Feed a `.tracev3` / Biome orientation event with `CMDeviceOrientation = 6` (`Face Down`) while the screen is locked. Verify that Sub-Engine 6.1C classifies it as `PHYSICAL_SENSOR_ORIENTATION` (`"FaceDown (6)"`) rather than `DISPLAY_UI_ORIENTATION`.
3. **The `healthdb_secure.sqlite` iPhone vs. Apple Watch Provenance Test:** Insert two `StepCount` (`data_type = 7`) rows into `healthdb_secure.sqlite`: Row 1 linked via `data_provenances` to `source_devices.hardware = "iPhone16,2"`, and Row 2 linked to `source_devices.hardware = "Watch7,1"`. Verify that Sub-Engine 6.1D sets `is_local_iphone_sensor = 1` on Row 1 and `is_local_iphone_sensor = 0` on Row 2!
4. **The `FSEvents` `2SLG` Binary Parser & Monotonic Timestamp Bracketing Test:** Construct a gzipped `2SLG` page containing three sequential events: `event_id = 100` (existing file with `btime = 10:00:00`), `event_id = 101` (deleted file `/private/var/mobile/Media/DCIM/100APPLE/IMG_0999.HEIC`, `flags = IsFile | ItemRemoved`), and `event_id = 102` (existing file with `btime = 10:05:00`). Verify that Sub-Engine 6.1E parses the 28-byte `2SLG` trailer (`event_id` + `flags` + `node_id`) and brackets `IMG_0999.HEIC`'s deletion window to `[10:00:00, 10:05:00]`.