# Engineering Specification: Phase 1, Module 1.3 — Pre-Flight Global Identity & Sandbox Resolver

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 1.3** of the Forensic Data Parser. It contains **zero programming code** and explains every mobile operating system mechanism from first principles so that a developer with no prior forensic experience can build an automated application, container, multi-user profile, and file-ownership resolution engine across iOS and Android extractions.

---

## 1. Purpose & Mental Model (Why Hardcoded File Paths Fail)

When an inexperienced developer builds a parser for an application like WhatsApp, Signal, PhonePe, or MetaMask, they usually write logic that looks for a single hardcoded file path—such as `/data/data/com.whatsapp/databases/msgstore.db` on Android or `/var/mobile/Applications/WhatsApp/ChatStorage.sqlite` on iOS.

**In real-world mobile forensics, hardcoding paths fails in over $60\%$ of modern examinations for three fundamental reasons:**

1. **iOS Randomizes Folder Names Using 128-Bit UUIDs:** On modern iOS (iOS 8 through iOS 26), applications are never stored in folders named after the app. Instead, iOS places an app's files inside randomly generated 36-character UUID folders like `/private/var/mobile/Containers/Data/Application/3D8A9F21-4E62-4C11-92B1-7A8C2D4E6F10/`. Even more importantly, apps like **WhatsApp, Signal, Telegram, and Apple Notes** do not even keep their main SQLite databases inside their `Data/Application/<UUID>` folder—they keep them inside a completely separate **Shared App Group** folder (`/private/var/mobile/Containers/Shared/AppGroup/<DIFFERENT-UUID>/`) so that background notification extensions and share widgets can access the database simultaneously. Every device has completely different UUIDs.
2. **Android Suspects Use Cloned Apps, Dual Messenger, Secure Folder & Work Profiles:** On Android, `/data/data/<package_name>` only points to the primary user profile (`User 0`). Criminals, mule-account operators, and fraudsters routinely run a second or third hidden copy of WhatsApp, Telegram, PhonePe, or Paytm inside **Samsung Dual Messenger (`User 95`)**, **Samsung Secure Folder (`User 150`)**, **Xiaomi Second Space / Dual Apps (`User 999`)**, **Oppo/Vivo App Cloner (`User 999`)**, or an **Android Work Profile (`User 10`)**. A parser that only checks `/data/data/` will completely miss the suspect's second secret WhatsApp or UPI account.
3. **iOS Logical Backups Use Domain Prefixes Instead of Filesystem Paths:** Inside an iTunes/Finder Logical Backup (`Manifest.db`), files do not have `/private/var/mobile/...` paths at all; they are stored under logical domain strings like `AppDomain-net.whatsapp.WhatsApp` or `AppDomainGroup-group.net.whatsapp.WhatsApp.shared`.

### The Solution: The Pre-Flight Identity & Sandbox Resolver
**Module 1.3** runs immediately after Module 1.1 (VFS Indexing) and Module 1.2 (Hashing)—**before any artifact parser in Phases 2–7 is allowed to run**. It scans the operating system's internal package registries and container metadata plists, builds a master relational catalog of every installed (and previously uninstalled) application across every user profile and cloned space, and exposes a single lookup API. When the WhatsApp or PhonePe parser runs in Phase 3 or Phase 5, it simply asks Module 1.3: *"Give me all storage roots for `com.phonepe.app`"*—and automatically receives every main, cloned, work-profile, shared-group, and backup path on the device.

---

## 2. The 5 Fatal Mistakes Beginner Developers Make in App Resolution

Before implementing Module 1.3, the developer must understand five critical traps that break amateur forensic tools:

### Mistake 1: Feeding Android 12–17 `packages.xml` into a Standard XML Parser
* **The Trap:** Opening `/data/system/packages.xml` or `/data/system/users/userlist.xml` with a standard text-based XML library (`DOMParser`, `ElementTree`, `lxml`).
* **Why It Crashes:** Starting in **Android 12 (API 31) through Android 17**, Google replaced plain-text XML in `/data/system/` with a proprietary binary format called **Android Binary XML (`ABX`)** to speed up boot times. The file still has the `.xml` extension, but its first four bytes are `61 62 78 00` (`abx\0` in ASCII). A standard XML parser will immediately crash with a syntax error.
* **The Rule:** Module 1.3 must inspect the first $4\text{ bytes}$ of every `.xml` file in `/data/system/`. If the bytes are `61 62 78 00`, it must route the stream through a dedicated **ABX Binary Tokenizer** (specified step-by-step in Section 4.1) before parsing the XML tree.

### Mistake 2: Looking Only in iOS `Data/Application` and Ignoring `Shared/AppGroup`
* **The Trap:** Writing an iOS container scanner that only indexes `/private/var/mobile/Containers/Data/Application/<UUID>/`.
* **Why It Fails:** On iOS, **WhatsApp** (`ChatStorage.sqlite`), **Signal** (`Signal.sqlite`), **Telegram**, **Apple Notes** (`NoteStore.sqlite`), and **Google Chrome** store their primary databases inside `/private/var/mobile/Containers/Shared/AppGroup/<UUID>/`. Furthermore, a single application (like WhatsApp) can own **multiple** Shared App Group UUIDs simultaneously.
* **The Rule:** Module 1.3 must scan all **five** iOS container roots (App Data, Shared AppGroup, App Bundle, SystemGroup, and PluginKitPlugin) and link all of them back to the parent application.

### Mistake 3: Assuming Android APK Paths Are Named `/data/app/com.whatsapp-1/`
* **The Trap:** Looking for installed `.apk` files using Android 7–9 path conventions (`/data/app/<package_name>-1/base.apk`).
* **Why It Fails:** Starting in Android 11+, the OS wraps every installed app directory inside two layers of randomized Base64-encoded cryptographic hashes: `/data/app/~~<22_char_random_hash_A>==/<package_name>-<22_char_random_hash_B>==/base.apk`.
* **The Rule:** Never guess `/data/app/` folder names. Always read the exact `codePath` attribute from `/data/system/packages.xml` (and verify it via the `vfs_index` table).

### Mistake 4: Misinterpreting Multi-User Linux UIDs on Android
* **The Trap:** Reading `packages.list`, seeing that `com.whatsapp` has App ID `10145`, and checking only for `owner_uid == 10145`.
* **Why It Fails:** When `com.whatsapp` runs inside an Android Work Profile (`User 10`) or Samsung Dual Messenger (`User 95`), the Linux kernel dynamically offsets the file's `owner_uid` using the formula:
  $$\text{Linux UID} = (\text{User ID} \times 100000) + \text{App ID}$$
  So a file created by Dual Messenger WhatsApp is owned by UID $9510145$, not $10145$.
* **The Rule:** Module 1.3 must apply modular arithmetic ($\text{User ID} = \lfloor \text{UID} / 100000 \rfloor$ and $\text{App ID} = \text{UID} \bmod 100000$) to resolve file ownership across every user profile on the phone.

### Mistake 5: Ignoring Uninstalled ("Ghost") Applications
* **The Trap:** Only cataloging applications that are currently installed in `/data/data/` or `/Containers/Data/Application/` at the moment of seizure.
* **Why It Fails:** Criminals frequently uninstall an incriminating app (such as Signal, Session, TronLink, or a mule banking app) minutes before police seize the phone. Even though the sandbox folder is gone, **residual traces of that uninstalled app's Bundle ID / Package Name remain** in network data counters (`DataUsage.sqlite`), notification databases (`DuetExpertCenter`), usage logs (`knowledgeC.db`, `usagestats`), and package rollback records (`/data/system/rollback/`).
* **The Rule:** Module 1.3 must build a dedicated **Ghost Application Registry** by cross-referencing historical OS telemetry tables against currently installed apps, immediately alerting the investigator to every app that was deleted prior to seizure.

---

## 3. Step-by-Step Logic: iOS Global Sandbox & Bundle Resolution

When `vfs_index` (from Module 1.1) detects an iOS extraction (either an FFS `.tar`/`.zip` or an iTunes Logical Backup), Module 1.3 executes a five-step resolution pipeline.

### Step 3.1: Scan the 5 iOS Container Roots (FFS Extractions)
Query the `vfs_index` table for every file named `.com.apple.mobile_container_manager.metadata.plist` across the following five canonical root directories:

| Container Category | Canonical Root Path in `vfs_index` | What Lives Inside This Container |
|---|---|---|
| **1. App Data Sandbox** | `/private/var/mobile/Containers/Data/Application/<UUID>/` | App-private `Documents/`, `Library/`, `tmp/`, `Library/Preferences/`, and `Library/WebKit/` (`WKWebView`). |
| **2. Shared App Group** | `/private/var/mobile/Containers/Shared/AppGroup/<UUID>/` | Databases and files shared between the main app and its extensions (e.g., WhatsApp `ChatStorage.sqlite`, Signal `grdb/Signal.sqlite`, Notes `NoteStore.sqlite`). |
| **3. App Bundle (`.app`)** | `/private/var/containers/Bundle/Application/<UUID>/` | The signed application binary, `Info.plist` (exact app version & display name), and `iTunesMetadata.plist` (Apple ID used to download the app). |
| **4. Shared System Group** | `/private/var/containers/Shared/SystemGroup/<UUID>/` | System-level shared containers (e.g., `systemgroup.com.apple.configurationprofiles`, Bluetooth preferences, Lockdown profiles). |
| **5. PluginKit / Extensions** | `/private/var/mobile/Containers/Data/PluginKitPlugin/<UUID>/` | Notification Service Extensions (`NotificationService`), Share Extensions, and Widget sandboxes. |

### Step 3.2: Parse `.com.apple.mobile_container_manager.metadata.plist`
For each discovered metadata plist file, stream its bytes from the VFS (typically $500\text{ bytes}$ to $4\text{ KB}$) and parse it using a plist reader that supports both **Apple Binary Plist (`bplist00`)** and **XML Plist**:
1. **Extract the Parent Directory `<UUID>`:** Parse the 36-character UUID directly from the parent directory path of the plist file.
2. **Extract `MCMMetadataIdentifier` (`String`):**
   * For **App Data** and **App Bundle** containers, this is the exact **Bundle ID** (e.g., `net.whatsapp.WhatsApp`, `com.phonepe.PhonePeApp`, `org.whispersystems.signal`).
   * For **Shared App Group** containers, this is the **App Group Identifier** (e.g., `group.net.whatsapp.WhatsApp.shared`, `group.org.whispersystems.signal.group`).
   * For **System Group** containers, this is the **System Group Identifier** (e.g., `systemgroup.com.apple.bluetooth`).
3. **Extract `MCMMetadataContentClass` (`Integer`):** Records Apple's internal container class integer (e.g., `1` = App Bundle, `2` = App Data Sandbox, `4` = PluginKit Plugin, `7` = Shared App Group, `12` = System Group).
4. **Extract `MCMMetadataInfo` Dictionary (if present):** Contains `SandboxProfileDataValidationInfo` and entitlement metadata.

### Step 3.3: Link Shared App Groups & Plugins Back to Their Parent Bundle ID
Because an App Group identifier looks like `group.net.whatsapp.WhatsApp.shared` or `group.com.burbn.instagram.openssl`, your engine must deterministically bind each Shared App Group `<UUID>` to its owning application (`net.whatsapp.WhatsApp` or `com.burbn.instagram`) using a 3-tier matching cascade:
1. **Tier 1 (Exact Entitlement / LaunchServices Lookup — Primary Method):**
   * Query the VFS for `/private/var/installd/Library/MobileInstallation/LastLaunchServicesMap.plist` and `/private/var/mobile/Library/FrontBoard/applicationState.db`.
   * Inside `LastLaunchServicesMap.plist` (under the `User` and `System` dictionaries), each Bundle ID entry contains an explicit array key named `GroupContainers` (which maps every `group.*` string directly to its `<UUID>` path) and `PluginKitPlugins`.
2. **Tier 2 (Known Forensic App Group Dictionary):**
   * Maintain a built-in dictionary of the top 500 forensic apps where the group name differs slightly from the bundle name (for example, Signal's Bundle ID is `org.whispersystems.signal`, and its App Group ID is `group.org.whispersystems.signal.group`).
3. **Tier 3 (Substring Prefix Heuristic Fallback):**
   * If `LastLaunchServicesMap.plist` is unavailable (e.g., partial extraction), strip the leading `group.` prefix from `MCMMetadataIdentifier` and match the longest matching Bundle ID prefix (e.g., `group.net.whatsapp.WhatsApp.shared` $\rightarrow$ prefix `net.whatsapp.WhatsApp`).

### Step 3.4: Enrich App Metadata from `Info.plist` & `iTunesMetadata.plist`
For every resolved **App Bundle (`Bundle/Application/<UUID>/`)**:
1. Locate `<UUID>/<AppName>.app/Info.plist` and extract:
   * `CFBundleDisplayName` / `CFBundleName`: Human-readable name (e.g., `"PhonePe"`, `"WhatsApp"`).
   * `CFBundleShortVersionString`: Marketing version (e.g., `"26.4.1"`).
   * `CFBundleVersion`: Internal build number.
   * `MinimumOSVersion`: Minimum iOS version targeted.
2. Locate `<UUID>/iTunesMetadata.plist` (exists for all App Store installed apps) and extract:
   * `appleId` / `userName`: **The exact Apple ID email address used to download this specific app!** *(Suspects often sign out of their main iCloud account before seizure, or use a secondary Apple ID to download specific regional/crypto apps. `iTunesMetadata.plist` preserves the downloading Apple ID per app).*
   * `purchaseDate` / `releaseDate`: Exact timestamp when the app was acquired from the App Store.
   * `altDSID` / `DSPersonID`: Apple Directory Services Identifier of the purchasing account.
   * `variantID` / `softwareVersionExternalIdentifier`: Exact App Store build identifier.

### Step 3.5: Unify iOS Logical Backups (`Manifest.db` Domains)
If the loaded extraction is an **iOS Logical Backup (`Tier 1B`)** rather than an FFS extraction, `.com.apple.mobile_container_manager.metadata.plist` files do not exist. Instead, Module 1.3 queries the `domain` column of `Manifest.db` (normalized in Module 1.1):
* Every distinct domain starting with `AppDomain-` (e.g., `AppDomain-net.whatsapp.WhatsApp`) is registered as an **App Data Sandbox** for Bundle ID `net.whatsapp.WhatsApp`.
* Every distinct domain starting with `AppDomainGroup-` (e.g., `AppDomainGroup-group.net.whatsapp.WhatsApp.shared`) is registered as a **Shared App Group** container.
* Every distinct domain starting with `AppDomainPlugin-` is registered as a **PluginKit** container.
* Both FFS UUID paths and Backup Domain paths are stored in the exact same `app_storage_mounts` table (Section 6) so downstream parsers do not have to write separate path-lookup code for FFS vs. Backups.

---

## 4. Step-by-Step Logic: Android Package, UID, Multi-User & Cloned-App Resolution

When `vfs_index` detects an Android extraction, Module 1.3 executes a six-step resolution pipeline centered on `/data/system/`.

### Step 4.1: The Android Binary XML (`ABX`) Decoder Specification
Before reading `/data/system/packages.xml`, `/data/system/users/userlist.xml`, or `/data/system/appops.xml`, inspect the first $4\text{ bytes}$ of the file stream:
* If the first $4\text{ bytes}$ are `3C 3F 78 6D` (`<?xm` in ASCII): Parse as standard UTF-8 XML.
* If the first $4\text{ bytes}$ are `61 62 78 00` (`abx\0` in ASCII — Android 12 through Android 17 `BinaryXmlSerializer` format): Pass the stream through your **ABX Decoder** to convert it into an in-memory XML DOM tree or SAX event stream.

#### How the Developer Implements the `ABX` Binary Decoder:
1. **Verify Header:** Read the first $4\text{ bytes}$ (`61 62 78 00`, which corresponds to magic string `"abx\x00"` where version is `0`).
2. **Initialize Interned String Pool (List):** Create an empty, 0-indexed list called `interned_strings = []`. Whenever the file defines a new interned string, append it to this list. Whenever the file references an interned string, read a 16-bit unsigned big-endian integer (`uint16_be`) as the index into `interned_strings`.
3. **Read Token Loop Until EOF:** Read $1\text{ byte}$ (`header_byte`). Split that byte into two 4-bit nibbles using bitwise operations:
   * **Low 4 bits (`command_type = header_byte & 0x0F`):** Tells you the XML structural event:
     * `0` (`START_DOCUMENT`)
     * `1` (`END_DOCUMENT`)
     * `2` (`START_TAG`): Followed by the tag name string.
     * `3` (`END_TAG`): Followed by the tag name string.
     * `4` (`TEXT`): Followed by text content.
     * `15` (`ATTRIBUTE` = `0x0F`): Followed by the attribute's `name` string, and then its typed `value` based on the high 4 bits.
   * **High 4 bits (`data_type = (header_byte & 0xF0) >> 4`):** Tells you how to read the value:
     * `1` (`TYPE_NULL`): No value bytes.
     * `2` (`TYPE_STRING`): Read `uint16_be` byte length, then read that many UTF-8 bytes as a plain string.
     * `3` (`TYPE_STRING_INTERNED`): Read `uint16_be` integer `idx`. If `idx == 0xFFFF` ($65535$), it means a **new** interned string follows: read `uint16_be` byte length, read the UTF-8 string, append it to `interned_strings`, and use it. Otherwise, look up `interned_strings[idx]`.
     * `4` (`TYPE_BYTES_HEX`): Read `uint16_be` byte length, read raw bytes, and convert to a lowercase hex string.
     * `5` (`TYPE_BYTES_BASE64`): Read `uint16_be` byte length, read raw bytes, and encode as Base64.
     * `6` (`TYPE_INT`): Read 4-byte signed big-endian integer (`int32_be`).
     * `7` (`TYPE_INT_HEX`): Read 4-byte big-endian integer and format as hex.
     * `8` (`TYPE_LONG`): Read 8-byte signed big-endian integer (`int64_be`).
     * `9` (`TYPE_LONG_HEX`): Read 8-byte big-endian integer and format as hex.
     * `10` (`TYPE_FLOAT`): Read 4-byte IEEE-754 big-endian float.
     * `11` (`TYPE_DOUBLE`): Read 8-byte IEEE-754 big-endian double.
     * `12` (`TYPE_BOOLEAN_TRUE`): Value is `"true"` ($0$ extra bytes).
     * `13` (`TYPE_BOOLEAN_FALSE`): Value is `"false"` ($0$ extra bytes).

### Step 4.2: Enumerate All User Profiles, Work Profiles & Cloned Spaces
Query the VFS for `/data/system/users/userlist.xml` and every `/data/system/users/<user_id>.xml` file (and scan the VFS directory tree under `/data/user/` and `/data/user_de/` in case `userlist.xml` is missing):

| Android `user_id` | Profile Type Classification | Typical OEM / OS Origin | Storage Roots Created on Device |
|---|---|---|---|
| **`0`** | `PRIMARY_OWNER` | Standard Android Primary User | `/data/user/0/` (aliased as `/data/data/`), `/data/user_de/0/`, `/data/media/0/` (`/sdcard/`) |
| **`10` – `19`** | `MANAGED_WORK_PROFILE` | Android Enterprise Work Profile, **Island**, **Shelter**, or **Insular** (often used by suspects to isolate hidden apps) | `/data/user/10/`, `/data/user_de/10/`, `/data/media/10/`, `/data/system_ce/10/` |
| **`95`** | `SAMSUNG_DUAL_MESSENGER` | Samsung OneUI **Dual Messenger** (second instance of WhatsApp, Telegram, Signal, Snapchat, Facebook) | `/data/user/95/`, `/data/user_de/95/`, `/data/media/95/` |
| **`150` – `160`** | `SAMSUNG_SECURE_FOLDER` | Samsung Knox **Secure Folder** (hardware-backed encrypted second workspace with independent PIN/passcode) | `/data/user/150/`, `/data/user_de/150/`, `/data/media/150/` |
| **`999`** | `OEM_APP_CLONER` | **Xiaomi HyperOS/MIUI Dual Apps**, **OnePlus Parallel Apps**, **Oppo/Realme App Cloner**, **Vivo App Clone** | `/data/user/999/`, `/data/user_de/999/`, `/data/media/999/` |

For each discovered `<user>` XML file, record:
* `user_id` (`id` attribute, e.g., `0`, `10`, `95`, `150`, `999`).
* `profile_name` (`<name>` tag, e.g., `"Owner"`, `"Work profile"`, `"DualApp"`, `"Secure Folder"`).
* `created_ts` (`created` timestamp in Unix milliseconds).
* `last_logged_in_ts` (`lastLoggedIn` timestamp in Unix milliseconds).
* `user_flags` & `user_type` (e.g., `android.os.usertype.profile.MANAGED`, `com.samsung.knox.securefolder`).

### Step 4.3: Parse `/data/system/packages.list` & `/data/system/packages.xml`
Next, parse the package registry files:
1. **From `/data/system/packages.list` (Plain-text space-delimited file):**
   * Each line contains: `<package_name> <app_id> <debuggable_flag> <data_path> <seinfo_label> <gid_list> ...`
   * Record the base `app_id` (e.g., `10145`) and `seinfo` tag for every package.
2. **From `/data/system/packages.xml` (Plain XML or ABX):**
   * Iterate through every `<package>` and `<updated-package>` element and extract:
     * `name`: Exact package identifier (e.g., `com.phonepe.app`, `com.whatsapp`, `com.google.android.apps.nbu.paisa.user`).
     * `codePath`: Exact path in `/data/app/` or `/system/app/` where the APK resides.
     * `userId` or `sharedUserId`: The base integer App ID (e.g., `10145`).
     * `versionCode` / `version`: Installed integer build version.
     * `it` (`firstInstallTime` in hex or decimal Unix milliseconds): **Exact timestamp when the package was first installed.**
     * `ut` (`lastUpdateTime` in hex or decimal Unix milliseconds): **Exact timestamp when the package was last updated.**
     * `installer`: The package name of the installer that put this app on the phone:
       * `com.android.vending` $\rightarrow$ Official Google Play Store.
       * `com.sec.android.app.samsungapps` $\rightarrow$ Samsung Galaxy Store.
       * `com.google.android.packageinstaller` / `com.miui.packageinstaller` $\rightarrow$ **Manual APK Sideload!**
       * `null` / missing / `com.android.shell` $\rightarrow$ **Installed via ADB (`adb install`)!**
     * `initiatingPackageName` & `originatingPackageName`: **Crucial for Malware & Sideload Attribution!** Tells you *which app downloaded and launched the APK installer* (for example, `initiatingPackageName="com.whatsapp"` or `"org.telegram.messenger"` proves the suspect received a malicious or modded APK inside WhatsApp/Telegram and installed it).
     * `<sigs>` / `<cert>`: Extract the signing certificate hex string and compute its **SHA-256 certificate fingerprint** so your software can detect **modded/trojanized apps** (e.g., an app named `com.whatsapp` whose signing certificate does not match Meta's official WhatsApp certificate, proving it is GBWhatsApp or spyware).
3. **Per-User Installation Status (`package-restrictions.xml` or inline `<user-restriction>`):**
   * Check `/data/system/users/<user_id>/package-restrictions.xml` (or the per-user `<pkg>` state) to see whether `installed="true"`, `stopped="true"`, or `hidden="true"` is set for each `user_id` (`0`, `10`, `95`, `150`, `999`).

### Step 4.4: The Multi-User Linux UID Math Engine
For every combination of `user_id` (from Step 4.2) and `app_id` (from Step 4.3), compute the exact Linux `owner_uid` using the Android UID formula:

$$\text{Linux UID} = (\text{user\_id} \times 100000) + \text{app\_id}$$

Populate the `uid_ownership_lookup` table so that for **any file anywhere on the device**, Module 1.3 can instantly reverse-calculate:
1. $\text{user\_id} = \lfloor \text{owner\_uid} / 100000 \rfloor$
2. $\text{app\_id} = \text{owner\_uid} \bmod 100000$
3. Look up `app_id` in `resolved_application_catalog` to identify the exact package name and user profile that created the file.

### Step 4.5: Detect Forensic APK Downgrades (`M2`) & Rollbacks
Query the VFS for `/data/system/rollback/` (`rollback.xml` or per-rollback JSON/XML dirs) and `/data/system/install_sessions/`:
* Check if any package has a recorded rollback event or if `packages.xml` shows an `<updated-package>` or downgrade timestamp occurring within the seizure/acquisition time window.
* If an app's version decreased or was reinstalled via ADB (`installer == null`) during the acquisition window, automatically flag the app with `is_forensic_downgraded = 1` (linking directly to **Dimension C: `Modified source`** and **Group 9 / Group 17**).

### Step 4.6: Register the 5 Canonical Storage Mounts per Android App Instance
For every active `(package_name, user_id)` pair, check the `vfs_index` and register up to **five storage mount paths** in `app_storage_mounts`:
1. **CE Sandbox (`CREDENTIAL_ENCRYPTED_SANDBOX`):** `/data/user/<user_id>/<package_name>/` *(Note: Module 1.1 already normalizes `/data/data/<pkg>` to `/data/user/0/<pkg>`)*.
2. **DE Sandbox (`DEVICE_ENCRYPTED_SANDBOX`):** `/data/user_de/<user_id>/<package_name>/`
3. **Shared External Data (`EXTERNAL_ANDROID_DATA`):** `/data/media/<user_id>/Android/data/<package_name>/`
4. **Shared External Media (`EXTERNAL_ANDROID_MEDIA`):** `/data/media/<user_id>/Android/media/<package_name>/` *(Where WhatsApp `.crypt14/.crypt15` backups and media live).*
5. **APK Code Directory (`APK_CODE_PATH`):** The exact `codePath` from `packages.xml` (e.g., `/data/app/~~.../com.whatsapp-.../`).

---

## 5. The "Ghost App" (Uninstalled Application) Discovery Engine

Criminals routinely delete incriminating apps before handing over a device. Module 1.3 must execute a lightweight **Ghost App Discovery Pass** across OS telemetry files to catalog every Bundle ID / Package Name that is **not** currently present in the active sandbox list:

1. **On iOS Extractions:**
   * Scan bundle identifiers referenced inside:
     * `/private/var/wireless/Library/Databases/DataUsage.sqlite` (`ZPROCESS` table: `ZBUNDLENAME` and `ZPROCNAME` — **Apple never purges `DataUsage.sqlite` rows when an app is uninstalled**).
     * `/private/var/mobile/Library/DuetExpertCenter/streams/notificationAndSuggestionDB.db` (bundle IDs of apps that received notifications in the last $\approx 60\text{ days}$).
     * `/private/var/Keychains/keychain-2.db` (`agrp` column — many apps leave orphaned Keychain items behind after uninstallation).
   * Any Bundle ID found in those tables that does **not** have an active `Data/Application/<UUID>` container is inserted into `resolved_application_catalog` with `install_status = "UNINSTALLED_GHOST_APP"`, recording the earliest and latest residual timestamp observed.
2. **On Android Extractions:**
   * Scan package names referenced inside:
     * `/data/system_ce/<user>/usagestats/` (daily/weekly/monthly/yearly usage records of uninstalled apps).
     * `/data/system/appops.xml` & `/data/misc_de/0/apexdata/com.android.permission/runtime-permissions.xml`.
     * `/data/system/packages.xml` (`<updated-package>` or orphaned shared-user references) and `/data/system/rollback/`.
     * Orphaned folders left behind in `/data/media/<user>/Android/media/<pkg>/` or `/data/media/0/Download/*.apk`.
   * Any package name found in those sources that is absent from active `packages.xml` is inserted into `resolved_application_catalog` with `install_status = "UNINSTALLED_GHOST_APP"`.

---

## 6. Database Schema for Module 1.3 (`identity_sandbox_catalog.sqlite`)

The developer must create the following four tables in the case database:

### Table 1: `device_user_profiles` (OS User & Cloned Spaces)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `profile_row_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Internal primary key. |
| `os_platform` | `TEXT` | `NOT NULL` | Enum: `IOS`, `ANDROID`. |
| `user_id` | `INTEGER` | `NOT NULL` | `0` for iOS default / Android Owner; `10` for Work Profile; `95` for Samsung Dual Messenger; `150` for Secure Folder; `999` for Xiaomi/Oppo Cloner. |
| `profile_type` | `TEXT` | `NOT NULL` | Enum: `PRIMARY_OWNER`, `MANAGED_WORK_PROFILE`, `SAMSUNG_DUAL_MESSENGER`, `SAMSUNG_SECURE_FOLDER`, `OEM_APP_CLONER`, `SECONDARY_USER`. |
| `profile_display_name` | `TEXT` | `NULL` | Name read from `<user>.xml` (e.g., `"Owner"`, `"DualApp"`, `"Secure Folder"`). |
| `created_utc_iso` | `TEXT` | `NULL` | ISO-8601 UTC timestamp when the profile/space was created. |
| `last_login_utc_iso` | `TEXT` | `NULL` | ISO-8601 UTC timestamp when the profile was last unlocked/active. |

### Table 2: `resolved_application_catalog` (Master App Inventory)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `app_instance_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each `(app_identifier, user_id)` instance. |
| `os_platform` | `TEXT` | `NOT NULL` | Enum: `IOS`, `ANDROID`. |
| `user_id` | `INTEGER` | `NOT NULL DEFAULT 0` | Foreign reference to `device_user_profiles.user_id`. |
| `app_identifier` | `TEXT` | `NOT NULL` | Canonical Bundle ID (iOS, e.g., `net.whatsapp.WhatsApp`) or Package Name (Android, e.g., `com.whatsapp`). |
| `display_name` | `TEXT` | `NULL` | Human-readable app name (e.g., `"WhatsApp"`, `"PhonePe"`). |
| `install_status` | `TEXT` | `NOT NULL` | Enum: `INSTALLED_ACTIVE`, `INSTALLED_HIDDEN_OR_STOPPED`, `SYSTEM_PREINSTALLED`, `UNINSTALLED_GHOST_APP`. |
| `version_string` | `TEXT` | `NULL` | Marketing version string (`CFBundleShortVersionString` or APK `versionName`). |
| `version_code` | `INTEGER` | `NULL` | Integer build code (`versionCode` on Android). |
| `base_app_id` | `INTEGER` | `NULL` | Android base `appId` (e.g., `10145`). |
| `effective_linux_uid` | `INTEGER` | `NULL` | Calculated $(\text{user\_id} \times 100000) + \text{base\_app\_id}$ (or `501` on iOS). |
| `first_install_utc_iso` | `TEXT` | `NULL` | First install timestamp (`it` in `packages.xml` or `purchaseDate` in `iTunesMetadata.plist`). |
| `last_update_utc_iso` | `TEXT` | `NULL` | Last update timestamp (`ut` in `packages.xml` or bundle `mtime`). |
| `installer_source` | `TEXT` | `NULL` | E.g., `com.android.vending`, `SIDELOAD_PACKAGE_INSTALLER`, `ADB_SHELL`, `APPLE_APP_STORE`, `TESTFLIGHT_OR_ENTERPRISE`. |
| `initiating_package` | `TEXT` | `NULL` | App that triggered the APK install (e.g., `com.whatsapp`, `org.telegram.messenger`, `com.android.chrome`). |
| `purchasing_account_id` | `TEXT` | `NULL` | Apple ID email (`appleId` from `iTunesMetadata.plist`) or Google Play account. |
| `signing_cert_sha256` | `TEXT` | `NULL` | SHA-256 fingerprint of the APK signing certificate or Mach-O Team ID. |
| `is_signature_verified` | `INTEGER` | `DEFAULT 1` | `0` if package name matches a known mainstream app (e.g., WhatsApp/PhonePe) but signing cert belongs to a modded/trojan build. |
| `is_forensic_downgraded` | `INTEGER` | `DEFAULT 0` | `1` if APK downgrade (`M2`) or rollback detected during seizure window. |
| `ghost_evidence_sources` | `TEXT` | `NULL` | JSON array listing where an uninstalled Ghost App was detected (e.g., `["DataUsage.sqlite", "DuetExpertCenter"]`). |

### Table 3: `app_storage_mounts` (Unified Path Router for Downstream Parsers)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `mount_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each storage directory belonging to an app instance. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to `resolved_application_catalog.app_instance_id`. |
| `mount_category` | `TEXT` | `NOT NULL` | Enum: `IOS_DATA_SANDBOX`, `IOS_SHARED_APP_GROUP`, `IOS_APP_BUNDLE`, `IOS_PLUGINKIT`, `ANDROID_CE_SANDBOX`, `ANDROID_DE_SANDBOX`, `ANDROID_EXT_DATA`, `ANDROID_EXT_MEDIA`, `ANDROID_APK_CODE`. |
| `container_uuid_or_group` | `TEXT` | `NULL` | On iOS: the 36-char `<UUID>` or `group.*` identifier (e.g., `group.net.whatsapp.WhatsApp.shared`). |
| `canonical_root_path` | `TEXT` | `NOT NULL` | Exact normalized directory path in `vfs_index` (e.g., `/private/var/mobile/Containers/Shared/AppGroup/8F2A...` or `/data/user/95/com.whatsapp`). |
| `encryption_domain` | `TEXT` | `NOT NULL` | Enum: `IOS_AFU_SANDBOX`, `ANDROID_CE`, `ANDROID_DE`, `SHARED_MEDIA`, `LOGICAL_BACKUP_DOMAIN`. |
| `is_present_in_vfs` | `INTEGER` | `NOT NULL DEFAULT 1` | `1` if directory exists inside `vfs_index`; `0` if expected by registry but excluded/missing from extraction (e.g., BFU extraction where `ANDROID_CE_SANDBOX` is missing). |

### Table 4: `uid_ownership_lookup` (Fast Reverse Attribution Table)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `effective_linux_uid` | `INTEGER` | `PRIMARY KEY` | Exact integer UID (e.g., `10145`, `1010145`, `9510145`). |
| `user_id` | `INTEGER` | `NOT NULL` | Calculated user profile ID ($\lfloor \text{UID} / 100000 \rfloor$). |
| `base_app_id` | `INTEGER` | `NOT NULL` | Calculated base application ID ($\text{UID} \bmod 100000$). |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to `resolved_application_catalog.app_instance_id`. |
| `app_identifier` | `TEXT` | `NOT NULL` | Resolved package/bundle name (e.g., `com.whatsapp`). |

---

## 7. Downstream Query API Exposed to Phases 2–7

Every application parser in Phases 2–7 must use the following two API calls instead of hardcoding paths:

1. **`resolve_app_targets(app_identifier_or_list)`:**
   * *Example Call:* `resolve_app_targets(["com.whatsapp", "com.whatsapp.w4b", "net.whatsapp.WhatsApp", "net.whatsapp.WhatsAppSMB"])`
   * *What It Returns:* Every matching `app_instance_id` across **all** user profiles (`User 0`, `Work Profile 10`, `Dual Messenger 95`, `Secure Folder 150`, `Cloner 999`) together with all of its registered `app_storage_mounts` (`IOS_DATA_SANDBOX`, `IOS_SHARED_APP_GROUP`, `ANDROID_CE_SANDBOX`, `ANDROID_EXT_MEDIA`, etc.).
   * *Why This Is Powerful:* A single WhatsApp parser automatically parses Primary WhatsApp, WhatsApp Business, Samsung Dual Messenger WhatsApp, Xiaomi Cloned WhatsApp, iOS FFS WhatsApp, and iOS iTunes Backup WhatsApp without changing a single line of SQLite parsing logic!
2. **`resolve_file_owner(owner_uid)`:**
   * Given any file's `owner_uid` from `file_provenance_catalog` (Module 1.2), returns the exact `app_identifier`, `display_name`, and `profile_display_name` that created the file.

---

## 8. Developer Acceptance Test Checklist for Module 1.3

1. **The Android 14–17 Binary XML (`ABX`) Test:** Feed a real Android 14+ `/data/system/packages.xml` file starting with magic bytes `61 62 78 00` into the ABX decoder. Verify that all `<package>` entries, `codePath` strings, `firstInstallTime`, `installer`, `initiatingPackageName`, and SHA-256 certificate fingerprints are extracted without error.
2. **The iOS Shared App Group Join Test:** Load an iOS FFS extraction where WhatsApp's `Data/Application/<UUID-A>` and `Shared/AppGroup/<UUID-B>` have completely different UUIDs. Call `resolve_app_targets("net.whatsapp.WhatsApp")` and verify that both `<UUID-A>` and `<UUID-B>` (containing `ChatStorage.sqlite`) are returned under the same `app_instance_id`.
3. **The Dual Messenger / Cloned App Math Test:** Simulate an Android device with `com.whatsapp` (`base_app_id = 10145`) installed in `User 0` and Samsung Dual Messenger `User 95`. Verify that `uid_ownership_lookup` maps UID `9510145` to `com.whatsapp (Samsung Dual Messenger)` and registers `/data/user/95/com.whatsapp/` in `app_storage_mounts`.
4. **The Ghost App Detection Test:** Remove a target app's `/Containers/Data/Application/<UUID>` folder from a test extraction while leaving its entry inside `DataUsage.sqlite` and `DuetExpertCenter`. Run Module 1.3 and verify that the app appears in `resolved_application_catalog` with `install_status = "UNINSTALLED_GHOST_APP"`.