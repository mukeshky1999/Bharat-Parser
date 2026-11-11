# Engineering Specification: Phase 5, Module 5.1 — The WhatsApp Ecosystem Deep Decoder (`msgstore.db`, `wa.db`, `ChatStorage.sqlite`, `@lid` Identity Unmasking, Revoked/Edited Message Recovery, Linked Companion Devices & Modded APK Variants)

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 5.1** of the Forensic Data Parser (corresponding to **Group 1 and Group 5**, and cross-linked with **Groups 2, 3, 7, 12, 13, 15, and 17** of the Unified Master Register). It contains **zero programming code** and explains every modern WhatsApp database schema, `@lid` privacy identifier mapping, quoted/forwarded/edited/revoked message reconstruction, `-wal` historical recovery, linked companion device (`WhatsApp Web`) audit trail, and modded APK (`GBWhatsApp` / `FMWhatsApp`) anti-revoke table from first principles so that any developer can build a commercial-grade WhatsApp forensic engine.

---

## 1. Purpose & Mental Model (Why Simple WhatsApp Scripts Fail on 2024–2026 Extractions)

In India and across the globe, **WhatsApp** is the primary communication backbone for both everyday citizens and organized crime syndicates (cyber-fraud call centers, mule-account coordinators, narcotics traffickers, extortionists, and hawala networks).

A beginner developer who searches online for "how to parse WhatsApp `msgstore.db`" will find outdated tutorials telling them to run `SELECT key_remote_jid, data, timestamp FROM messages;`. **On modern WhatsApp builds (2023 through 2026), that query fails or misses critical evidence for six architectural reasons:**

1. **Migration from the Legacy `messages` Table to the Normalized `message` + `chat` + `jid` Schema:** Modern Android `msgstore.db` deprecated the flat `messages` table. Every message now lives in the normalized **`message`** table, which does not store phone number strings directly—instead, it stores integer foreign keys (`chat_row_id` and `sender_jid_row_id`) pointing to the **`chat`** and **`jid`** tables.
2. **Introduction of Privacy-Preserving Linked Identity JIDs (`@lid`):** To hide user phone numbers in large groups, communities, and business chats, Meta introduced **Linked Identity JIDs (`<14_to_15_digit_id>@lid`, e.g., `164829104928172@lid`)** alongside traditional phone number JIDs (`919876543210@s.whatsapp.net`). If a parser does not join the `@lid` mapping tables (`jid_map`, `lid_chat_state`, and `wa.db`), messages from suspects in groups will display an anonymous `@lid` number instead of their real `+91` mobile number.
3. **"Delete for Everyone" (Revoked Messages) & In-Place Message Editing:** When a sender clicks **"Delete for Everyone"**, WhatsApp overwrites the original row in `message` (changing `message_type` to `15` or `64` and setting `text_data = NULL`). However, the **original unredacted message text** frequently survives inside earlier committed frames of **`msgstore.db-wal`**, B-Tree Freelist/Freeblock slack (decoded by Phase 2, Module 2.1), or inside the **`message_quoted`** table if someone replied to the message before it was deleted.
4. **Push Names (`wa_name`) Are Stored in a Separate Database (`wa.db` / `ContactsV2.sqlite`):** Suspects rarely save their co-conspirators' phone numbers in their phonebook. If you only parse `msgstore.db`, unsaved contacts appear as raw numbers. However, every WhatsApp user sets a profile **Push Name** (e.g., `"~ Vikram Boss"`), which WhatsApp caches inside **`wa.db`** (`wa_contacts` / `wa_vnames`) on Android and **`ContactsV2.sqlite`** / `ZWAPROFILEPUSHNAME` on iOS.
5. **Multi-Device Companion Linking (`WhatsApp Web` / Desktop / Second Phone):** Under WhatsApp's Multi-Device architecture, a user or handler can link up to **4 companion devices** (a laptop browser, Windows desktop app, or a secondary phone in another city) to the WhatsApp account on the seized phone. The **`companion_devices`** table inside `msgstore.db` / `axolotl.db` logs every linked computer or phone.
6. **Modded "Anti-Revoke" WhatsApp Clients (`GBWhatsApp`, `FMWhatsApp`, `YoWhatsApp`):** Suspects frequently use modded Android WhatsApp APKs because they allow hiding online status and **blocking "Delete for Everyone"** (preserving messages deleted by the other party).

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in WhatsApp Forensics

Before implementing Module 5.1, the developer must understand six critical traps:

### Mistake 1: Failing to Unmask `@lid` Identifiers Into Real Phone Numbers (`@s.whatsapp.net`)
* **The Trap:** Reading `raw_string` from the `jid` table, seeing `164829104928172@lid`, and displaying `"Sender: 164829104928172@lid"` in the forensic report without resolving the phone number.
* **Why It Fails:** An `@lid` number is an internal Meta identifier, not a phone number. Investigators cannot serve a telecom CDR subpoena on an `@lid` string. However, inside the exact same `msgstore.db` (in the **`jid_map`** and **`lid_display_name`** tables) and inside **`wa.db`** (`wa_contacts.jid` $\leftrightarrow$ `wa_contacts.lid`), WhatsApp stores the exact 1-to-1 lookup table mapping `lid_row_id` (`164829104928172@lid`) to `jid_row_id` (`919876543210@s.whatsapp.net`).
* **The Rule:** Always build the **Unified `JID ↔ LID` Resolution Dictionary** (Section 4.1) first before parsing any messages or calls.

### Mistake 2: Ignoring `message_quoted` When Recovering Deleted ("Revoked") Messages
* **The Trap:** Looking only in the `message` table (or `-wal` file) when trying to recover a deleted message.
* **Why It Fails:** Suppose User A sends `"Send the ₹5 Lakh cash to Ravi at Gate 4"` at 10:00 AM. At 10:01 AM, User B swipe-replies to that message saying `"OK done"`. At 10:05 AM, User A clicks **"Delete for Everyone"** on the 10:00 AM message, and the `-wal` file later checkpoints, wiping the 10:00 AM row's `text_data`. **Even when the 10:00 AM row in `message` is wiped, WhatsApp's `message_quoted` table (which stores a verbatim copy of the quoted text attached to the 10:01 AM reply) retains the full text of the deleted 10:00 AM message.**
* **The Rule:** Cross-reference every deleted/revoked `key_id` against `message_quoted.key_id` (Android) and `ZWAMESSAGE.ZPARENTMESSAGE` (iOS) to reconstruct deleted messages from surviving quote replies (Section 6.1).

### Mistake 3: Overlooking Forwarded Message Hop Counters (`forwarding_score`)
* **The Trap:** Treating every message sent by the user as original text authored by the user.
* **Why It Fails:** In investigations, proving whether the user **authored** a message/document versus **forwarded** a message (and whether it was a "Frequently Forwarded" viral message with $\ge 5\text{ hops}$) is legally decisive.
* **The Rule:** Always extract `origination_flags` and `forwarding_score` from `message_forwarded` (Android) and `ZFLAGS` / `ZFORWARDINGSCORE` (iOS).

### Mistake 4: Missing Historical Messages in Local `.crypt14` / `.crypt15` Backups
* **The Trap:** Seeing that `/data/user/0/com.whatsapp/databases/msgstore.db` is present in an FFS extraction and ignoring `/data/media/0/Android/media/com.whatsapp/WhatsApp/Databases/msgstore-YYYY-MM-DD.1.db.crypt14` (or `.crypt15`).
* **Why It Fails:** Every night at 2:00 AM, WhatsApp on Android creates an encrypted snapshot of `msgstore.db` in shared media storage and retains up to **7 daily rolling backups** (`msgstore.db.crypt15`, `msgstore-2026-11-04.1.db.crypt15`, `msgstore-2026-11-03.1.db.crypt15`, ...). If a user deleted an entire chat thread at 10:00 AM on November 5 and vacuumed/checkpointed their live `msgstore.db` before seizure at 2:00 PM, **that entire deleted chat thread is sitting intact inside the 2:00 AM `msgstore-2026-11-05.1.db.crypt15` backup file**. And because `/data/user/0/com.whatsapp/files/key` (or `encrypted_backup.key`) is present in the FFS extraction, **Phase 2, Module 2.2** can automatically decrypt all 7 backups.
* **The Rule:** Decrypt every historical `.crypt12/.14/.15` backup in `/Android/media/` via Module 2.2 and diff their rows against the live `msgstore.db` to recover purged chats (Section 3.2).

### Mistake 5: Failing to Parse Ephemeral ("View Once") Media & Disappearing Message Timers
* **The Trap:** Seeing a `message_type` of `42` (View Once Image), `43` (View Once Video), or `82` (View Once Voice Note) with `file_path = NULL` and skipping it.
* **Why It Fails:** Even after a recipient opens a "View Once" photo or video and WhatsApp deletes the high-resolution file, WhatsApp records the **exact sender, timestamp, view state (`viewed` vs. `unopened`), media SHA-256 hash (`file_hash`), media encryption key (`media_key`), file size**, and sometimes leaves residual blurred/thumbnail blobs or unlinked media files in `/WhatsApp Images/Sent/` or `Cache.db`.
* **The Rule:** Explicitly classify and extract all View-Once and Disappearing Message (`ephemeral_expiration`) metadata (Section 4.3 & Section 6.3).

### Mistake 6: Missing Modded WhatsApp Packages (`com.gbwhatsapp`, `com.fmwhatsapp`, `com.yowhatsapp`)
* **The Trap:** Querying Module 1.3 only for `com.whatsapp` and `com.whatsapp.w4b`.
* **Why It Fails:** Modded WhatsApp clients either install under alternative package names (`com.gbwhatsapp`, `com.fmwhatsapp`, `com.yowhatsapp`, `com.whatsapp.plus`, `com.ogwhatsapp`) OR use the package name `com.whatsapp` signed with a **non-Meta developer certificate** (detected in Phase 1, Module 1.3 via `is_signature_verified == 0`).
* **The Rule:** Scan for all 15+ known official and modded WhatsApp package/bundle identifiers and check `is_signature_verified` (Section 3.1).

---

## 3. Step 1 — Sub-Engine 5.1A: Instance Discovery & Live-vs-Backup Merger Workflow

### 3.1 Master Target List of Official, Business, Cloned & Modded WhatsApp Clients

Query **Module 1.3 (`resolve_app_targets`)** across all user profiles (`User 0`, `Work Profile 10`, `Samsung Dual Messenger 95`, `Samsung Secure Folder 150`, `Xiaomi/Oppo/Vivo App Cloner 999`) for the following identifiers:

| Client Category | Application Name | Android Package Name(s) | iOS Bundle & Shared AppGroup IDs | Core SQLite Databases to Stage via Module 1.1 |
|---|---|---|---|---|
| **Official Consumer** | **WhatsApp Messenger** | `com.whatsapp` | Bundle: `net.whatsapp.WhatsApp`<br>Group: `group.net.whatsapp.WhatsApp.shared` | • Android: `msgstore.db`, `wa.db`, `axolotl.db`, `chatsettings.db`, `companion_devices.db`, `location.db`<br>• iOS: `ChatStorage.sqlite`, `ContactsV2.sqlite`, `CallHistory.sqlite` |
| **Official Business** | **WhatsApp Business** | `com.whatsapp.w4b` | Bundle: `net.whatsapp.WhatsAppSMB`<br>Group: `group.net.whatsapp.WhatsAppSMB.shared` | Same as above, plus business catalog, quick-reply, and automated greeting tables in `wa.db`. |
| **Unofficial / Anti-Revoke Mods** | **GBWhatsApp, FMWhatsApp, YoWhatsApp, WhatsApp Plus, OGWhatsApp, Aero** | `com.gbwhatsapp`, `com.fmwhatsapp`, `com.yowhatsapp`, `com.whatsapp.plus`, `com.ogwhatsapp`, `com.aero`, or `com.whatsapp` (with `is_signature_verified == 0`) | Sideloaded / Enterprise-signed `net.whatsapp.WhatsApp*` | Standard `msgstore.db` + `wa.db`, **PLUS** custom mod databases/tables (`gb_*.db`, `revoked_messages`, `who_online_logs`) and `/shared_prefs/gb_prefs.xml` / `yo_prefs.xml`. |

### 3.2 The Live `msgstore.db` + Rolling `.crypt14/.crypt15` Backup Diff-Merger
For each Android WhatsApp instance:
1. **Parse the Live Sandbox Database First:** Stage `/data/user/<id>/<wa_pkg>/databases/msgstore.db` (+ `-wal`) and `wa.db` (+ `-wal`) through **Phase 2, Module 2.1 (Active + `-wal` + Freelist)**.
2. **Locate & Decrypt Rolling Local Backups:** Query `vfs_index` in `/data/media/<id>/Android/media/<wa_pkg>/WhatsApp/Databases/` (and legacy `/data/media/<id>/WhatsApp/Databases/`) for all `.crypt12`, `.crypt14`, and `.crypt15` files.
3. Unwrap each backup file using **Phase 2, Module 2.2 (Recipe 2)** into a `Product B2` SQLite file.
4. **Execute the Historical Diff-Merge:**
   * Any `message.key_id` (or `chat`) that exists inside an older `.crypt14/.crypt15` backup **but is missing (or revoked/wiped) in the live `msgstore.db`** is imported into the master message table and tagged as **`HISTORICAL_COMMITTED_RECORD (Recovered from Rolling Local .crypt14/.15 Backup <backup_date>)`**.

---

## 4. Step 2 — Sub-Engine 5.1B: Android `msgstore.db` & `wa.db` Deep Relational Schema & `@lid` Unmasker

### 4.1 Step 1: Building the Unified `JID ↔ LID ↔ PushName` Identity Dictionary
Before reading any messages, query `msgstore.db` and `wa.db` (across active, `-wal`, and freelist records) to build an in-memory lookup dictionary indexed by `jid._id` (`jid_row_id`):

1. **Read the `jid` Table in `msgstore.db` (`SELECT _id, user, server, agent, device, type, raw_string FROM jid;`):**
   * Classify each row by its `server` suffix:
     * `s.whatsapp.net`: Standard user phone number (`user` = E.164 digits without `+`, e.g., `"919876543210"`).
     * `lid`: **Privacy Linked Identity JID** (e.g., `"164829104928172@lid"`).
     * `g.us`: Group chat JID (e.g., `"120363048291048291@g.us"`).
     * `newsletter`: WhatsApp Channel / Newsletter (`120363...@newsletter`).
     * `broadcast`: Broadcast list (`status@broadcast` = WhatsApp Status updates!).
2. **Unmask Every `@lid` Row Using the 3-Source Join (`jid_map` + `lid_display_name` + `wa.db`):**
   * **Source 1 (`msgstore.db` $\rightarrow$ `jid_map` table):** Query `SELECT lid_row_id, jid_row_id FROM jid_map;`. This table directly maps the `@lid` row ID (`lid_row_id`) to the real phone-number `@s.whatsapp.net` row ID (`jid_row_id`).
   * **Source 2 (`msgstore.db` $\rightarrow$ `lid_display_name` & `lid_chat_state` tables):** Extracts `display_name` (the user's Push Name associated with that `@lid` even if their phone number was hidden by community privacy rules).
   * **Source 3 (`wa.db` $\rightarrow$ `wa_contacts` & `wa_vnames` tables):** Open `wa.db` and query `SELECT jid, lid, display_name, wa_name, number, status, unseen_msg_count FROM wa_contacts;`.
     * `display_name`: Name saved in the device owner's local address book (`NULL` if unsaved).
     * **`wa_name`**: **The WhatsApp Profile Push Name set by the remote user themselves** (e.g., `"~ Boss Dubai"`).
     * `jid` & `lid`: Provides an additional mapping between the `@s.whatsapp.net` JID and `@lid`.

### 4.2 Step 2: Extracting the Normalized `message` Table & Its 14 Satellite Tables
In modern `msgstore.db`, the core `message` table is joined via `message._id = <satellite_table>.message_row_id` to specialized satellite tables:

1. **Core `message` Table (`SELECT _id, chat_row_id, from_me, key_id, sender_jid_row_id, status, timestamp, received_timestamp, message_type, text_data, starred, lookup_tables, orig_flags FROM message;`):**
   * `chat_row_id`: Joins to `chat._id` $\rightarrow$ `chat.jid_row_id` $\rightarrow$ `jid._id` (identifies the 1-on-1 counterparty or `@g.us` Group).
   * `from_me`: `1` = Sent by device owner; `0` = Received.
   * `sender_jid_row_id`: In a Group chat (`@g.us`), points to the `jid._id` of the specific group member who sent the message (automatically unmasking any `@lid` via Step 4.1).
   * `timestamp`: 13-digit Unix millisecond timestamp when the message was created/sent.
   * `received_timestamp`: 13-digit Unix millisecond timestamp when received by this handset.
   * `text_data`: Message text body (or caption/URL in certain types).
2. **Decode `message_type` Integer Codes:**
   * `0`: Standard Text Message (`text_data`)
   * `1`: Image (`message_media`)
   * `2`: Audio / Voice Note (`message_media`)
   * `3`: Video (`message_media`)
   * `4` / `14`: Contact vCard (`message_vcard`)
   * `5`: Static GPS Location (`message_location`)
   * `7`: System / Security / Group Membership Event (`message_system`)
   * `8` / `10`: WhatsApp Voice/Video Call Event
   * `9`: Document — PDF, APK, XLSX, ZIP (`message_media`)
   * `11` / `64` / `15`: **Revoked / "Deleted for Everyone" Message Tombstone!**
   * `13`: Animated GIF
   * `16`: **Live Real-Time GPS Location Sharing** (`message_location`)
   * `20`: WebP Sticker
   * `42`: **View-Once Image (`Ephemeral View-Once`)**
   * `43`: **View-Once Video (`Ephemeral View-Once`)**
   * `66`: Poll (`message_poll` + `message_poll_option`)
   * `82`: **View-Once Voice Note**
3. **Join the 14 Satellite Tables on `message_row_id = message._id`:**
   * **`message_media`:** Extracts `file_path` (e.g., `Media/WhatsApp Documents/RTO_Challan.apk`), `file_size`, `mime_type`, `file_hash` (**Base64 SHA-256 of the unencrypted media file!**), `media_key` (32-byte E2EE media key), `width`, `height`, and `media_duration`. *(Also join `message_thumbnails` or `message_thumbnail` to recover low-res JPEG previews even when the main media file was deleted from `/sdcard/`).*
   * **`message_quoted`:** Extracts `key_id` (the ID of the parent message being replied to), `sender_jid_row_id`, and `text_data` (the verbatim quoted text).
   * **`message_forwarded`:** Extracts `forwarding_score` ($1\text{–}4$ = Forwarded; $\ge 5$ = `"Frequently Forwarded"` viral message; $\ge 127$ = Highly viral).
   * **`message_edit_info` / `message_details`:** Extracts `original_key_id`, `edited_timestamp`, and edit version counters (pair with `-wal` frames from Module 2.1 to recover the pre-edit text).
   * **`message_ephemeral` / `message_ephemeral_setting`:** Extracts `expire_timestamp` and `duration` ($24\text{ hours}$, $7\text{ days}$, $90\text{ days}$ Disappearing Message timer).
   * **`message_view_once_media`:** Extracts `state` (`0` = Unopened, `1` = Viewed & Purged, `2` = Expired).
   * **`message_location`:** Extracts exact GPS `latitude`, `longitude`, `place_name`, `place_address`, `url`, and `live_location_share_duration` (cross-link to Group 7).
   * **`message_vcard` & `message_vcard_jid`:** Extracts shared contact vCards.
   * **`message_link`:** Extracts URLs shared in messages.
   * **`message_add_on` & `message_add_on_reaction`:** Extracts emoji reactions (`reaction`, `sender_jid_row_id`, `timestamp`) placed on messages.
   * **`message_system` + `message_system_group` / `message_system_value_change`:** Reconstructs who created a group, who added or removed whom, when a group title changed, and when Disappearing Messages were toggled on/off.
   * **`receipt_user` & `receipt_device`:** Extracts exact per-recipient **Delivered Timestamp (`receipt_timestamp`)** and **Read / Blue-Tick Timestamp (`read_timestamp`)** for group and direct messages.
   * **`call_log` + `call_log_participant_v2`:** Extracts WhatsApp Voice & Video calls (`call_id`, `jid_row_id`, `from_me`, `timestamp`, `duration` in seconds, `video_call` boolean, and all participants in group calls).
   * **`pay_transaction`:** Routed to **Phase 3, Module 3.1D (WhatsApp Pay UPI Decoder)** and cross-linked to the chat row.

---

## 5. Step 3 — Sub-Engine 5.1C: iOS WhatsApp (`ChatStorage.sqlite` & `ContactsV2.sqlite`) Deep Schema

On iOS (both FFS extractions and unencrypted/encrypted iTunes Logical Backups in `AppDomainGroup-group.net.whatsapp.WhatsApp.shared`), WhatsApp uses CoreData SQLite databases where timestamps are stored in **Apple Cocoa Seconds since `2001-01-01 00:00:00 UTC`** (convert via Module 1.2: $\text{Unix Seconds} = \text{Cocoa} + 978307200$):

1. **Chats & Contacts (`ZWACHATSESSION` & `ZWAPROFILEPUSHNAME` + `ContactsV2.sqlite`):**
   * In `ZWACHATSESSION`, extract `Z_PK`, `ZCONTACTJID`, `ZPARTNERNAME` (display/saved name), `ZMESSAGECOUNTER`, and `ZLASTMESSAGEDATE`.
   * Join `ZWAPROFILEPUSHNAME` (`ZJID` $\leftrightarrow$ `ZPUSHNAME`) to recover the remote user's self-assigned Push Name for unsaved numbers.
2. **Messages (`ZWAMESSAGE` Joined with `ZWAMEDIAITEM` & `ZWAMESSAGEINFO`):**
   * Extract `Z_PK`, `ZCHATSESSION` (foreign key to `ZWACHATSESSION.Z_PK`), `ZISFROMME` (`1` = Sent, `0` = Received), `ZFROMJID`, `ZTOJID`, `ZGROUPMEMBER` (joins to `ZWAGROUPMEMBER.ZMEMBERJID` for group sender attribution), `ZMESSAGEDATE` (Cocoa seconds), `ZTEXT`, `ZMESSAGETYPE` (`14` = Revoked/Deleted for Everyone), `ZSTARRED`, `ZFLAGS`, and `ZPARENTMESSAGE` (quoted reply parent).
   * Join `ZWAMEDIAITEM` (`ZMESSAGE = ZWAMESSAGE.Z_PK`) to extract `ZMEDIALOCALPATH` (relative path inside `/Message/Media/`), `ZVCARDNAME` (often holds the original filename), `ZFILESIZE`, `ZLATITUDE`, `ZLONGITUDE`, `ZTITLE`, and `ZAUTHORNAME`.

---

## 6. Step 4 — Sub-Engine 5.1D: Revoked/Edited Message Recovery, Linked Companion Devices (`WhatsApp Web`) & Modded APK Anti-Revoke Tables

### 6.1 The 4-Source Revoked ("Delete for Everyone") & Edited Message Recovery Engine
Whenever Module 5.1 encounters a message row where `message_type` is `11`, `15`, or `64` (Android) or `ZMESSAGETYPE == 14` (iOS) — indicating the message was **"Deleted for Everyone" (Revoked)** — or a message with an edit indicator, execute a **4-Source Recovery Search** for that message's `key_id` / `_id`:

1. **Source 1 — `msgstore.db-wal` / `ChatStorage.sqlite-wal` Historical Frames (Phase 2, Module 2.1):**
   * Query `sqlite_recovered_records_master` for any `HISTORICAL_COMMITTED_RECORD` or `RESIDUAL_RECORD` sharing the same `_id` or `key_id` from an earlier WAL frame before the `UPDATE` overwritten `text_data` with `NULL`!
2. **Source 2 — Quoted Reply Survivors (`message_quoted` / `ZPARENTMESSAGE`):**
   * Query `SELECT text_data FROM message_quoted WHERE key_id = <revoked_key_id>;`. If anyone replied to the message before it was revoked, the full original text is recovered from `message_quoted.text_data` and tagged as **`RECONSTRUCTED_RECORD (Recovered from Surviving Quoted Reply)`**!
3. **Source 3 — Rolling Local `.crypt14/.crypt15` Backups & Notification Logs:**
   * Check the decrypted rolling `.crypt14/.crypt15` backups (from Section 3.2) and OS Notification Ledgers (`DuetExpertCenter` / Android `notification_history` from Module 3.4) for that `key_id` or timestamp.
4. **Source 4 — Modded WhatsApp Anti-Revoke Tables (`GBWhatsApp` / `FMWhatsApp` / `YoWhatsApp`):**
   * In modded WhatsApp clients (`com.gbwhatsapp`, `com.fmwhatsapp`, `com.yowhatsapp`), when a remote sender sends a "Delete for Everyone" revoke stanza, the modded APK **blocks the SQLite `UPDATE` that wipes `text_data`** and instead logs the `key_id` inside a custom table (`revoked_messages` / `del_msgs` in `gb_*.db` or `yo_*.db` or `shared_prefs/gb_revoked.xml`)!
   * Cross-check any custom `revoked` table/XML in modded sandboxes to flag messages that the counterparty attempted to delete!

### 6.2 Linked Companion Devices Audit (`WhatsApp Web` / Desktop / Remote Handler Phones)
In organized mule and call-center operations, the person holding the physical phone often scans a **WhatsApp Web QR code** sent by a remote handler so the handler can operate the WhatsApp account from a laptop in another city or country.
* Query `companion_devices` inside `msgstore.db`, `axolotl.db`, or `/databases/companion_devices.db` (Android) and `MultiDevice` tables in `ChatStorage.sqlite` / `axolotl` (iOS):
  * Extract `device_id` (`jid`), **`device_os`** (e.g., `"Windows"`, `"Mac OS"`, `"Chrome"`, `"Edge"`, `"Android"`), **`platform_type`**, **`login_time`** (exact timestamp the QR code was scanned to pair the remote computer!), **`last_active`** (exact timestamp the remote computer was last active on this WhatsApp account!), and **`logout_time`**!

---

## 7. Database Schema for Module 5.1 (`whatsapp_ecosystem_engine.sqlite`)

The developer must create the following four tables in the case database:

### Table 1: `whatsapp_identities_and_lid_map` (Unified `JID ↔ LID ↔ PushName` Directory)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `wa_identity_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to WhatsApp instance in Module 1.3 (`User 0`, `Dual 95`, `Cloner 999`, `W4B`, `GBWhatsApp`). |
| `jid_row_id` | `INTEGER` | `NULL` | Internal `jid._id` in `msgstore.db`. |
| `phone_jid_string` | `TEXT` | `NULL` | Resolved phone JID (`919876543210@s.whatsapp.net`). |
| `linked_lid_string` | `TEXT` | `NULL` | Associated privacy LID (`164829104928172@lid`), mapped via `jid_map` or `wa.db`. |
| `extracted_phone_e164` | `TEXT` | `NULL` | Normalized phone number (`+919876543210`). |
| `address_book_display_name` | `TEXT` | `NULL` | Name saved in suspect's phonebook (`wa_contacts.display_name`). |
| `remote_profile_push_name` | `TEXT` | `NULL` | Self-assigned WhatsApp Push Name (`wa_name` / `ZPUSHNAME`, e.g., `"~ Vikram Boss"`). |
| `status_about_text` | `TEXT` | `NULL` | User's WhatsApp "About / Status" bio string. |
| `identity_type` | `TEXT` | `NOT NULL` | Enum: `USER`, `GROUP_CHAT`, `COMMUNITY`, `NEWSLETTER_CHANNEL`, `BROADCAST_STATUS`. |

### Table 2: `whatsapp_messages_master_ledger` (Active, WAL, Backup-Merged, Edited & Revoked Messages)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `wa_msg_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to WhatsApp instance in Module 1.3. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `msgstore.db`, `.crypt15` backup, or `ChatStorage.sqlite` in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, `RECONSTRUCTED_RECORD`, etc.). |
| `recovery_source_detail` | `TEXT` | `NOT NULL` | E.g., `LIVE_ACTIVE_TABLE`, `WAL_HISTORICAL_FRAME`, `CRYPT15_ROLLING_BACKUP_DIFF`, `QUOTED_REPLY_SURVIVOR`, `MODDED_APK_ANTI_REVOKE`. |
| `chat_jid` | `TEXT` | `NOT NULL` | Conversation JID (`@s.whatsapp.net` or `@g.us`). |
| `chat_display_title` | `TEXT` | `NULL` | Group title or contact name + Push Name. |
| `message_key_id` | `TEXT` | `NOT NULL` | WhatsApp unique `key_id` stanza string. |
| `direction` | `TEXT` | `NOT NULL` | Enum: `OUTGOING_SENT`, `INCOMING_RECEIVED`, `SYSTEM_EVENT`. |
| `sender_resolved_phone_jid` | `TEXT` | `NULL` | Unmasked `@s.whatsapp.net` phone number of the sender (even if sent via `@lid` in a group!). |
| `sender_raw_lid` | `TEXT` | `NULL` | Original `@lid` string if sent under privacy LID. |
| `sender_push_and_saved_name` | `TEXT` | `NULL` | Combined saved name + Push Name of the sender. |
| `message_type_category` | `TEXT` | `NOT NULL` | Enum: `TEXT`, `IMAGE`, `VIDEO`, `VOICE_NOTE`, `DOCUMENT`, `LOCATION_STATIC`, `LOCATION_LIVE`, `VCARD`, `POLL`, `VIEW_ONCE_IMAGE`, `VIEW_ONCE_VIDEO`, `VIEW_ONCE_AUDIO`, `REVOKED_DELETED_FOR_EVERYONE`, `UPI_PAYMENT`. |
| `message_text_or_caption` | `TEXT` | `NULL` | Full text (or recovered pre-revoke / pre-edit text!). |
| `is_revoked_deleted_for_everyone` | `INTEGER` | `DEFAULT 0` | `1` if message was marked "Deleted for Everyone". |
| `recovered_pre_revoke_or_edit_text` | `TEXT` | `NULL` | Populated when original text of a revoked or edited message is recovered from `-wal`, `message_quoted`, `.crypt15`, or modded anti-revoke table! |
| `quoted_parent_key_id` | `TEXT` | `NULL` | `key_id` of the quoted message (if reply). |
| `quoted_parent_text_preview` | `TEXT` | `NULL` | Verbatim quoted text from `message_quoted`. |
| `forwarding_hop_score` | `INTEGER` | `DEFAULT 0` | `0` = Original authored by sender; `1–4` = Forwarded; `>= 5` = Frequently Forwarded viral message. |
| `ephemeral_timer_seconds` | `INTEGER` | `DEFAULT 0` | Disappearing message timer in seconds (`0` if permanent). |
| `media_metadata_json` | `TEXT` | `NULL` | JSON with `file_path`, `mime_type`, `file_size`, `plaintext_sha256_b64`, `view_once_state`, or GPS coordinates. |
| `reactions_json` | `TEXT` | `NULL` | JSON array of emoji reactions (`sender`, `emoji`, `timestamp`). |
| `sent_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `sent_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |
| `delivered_utc_iso` | `TEXT` | `NULL` | Receipt delivered timestamp. |
| `read_blue_tick_utc_iso` | `TEXT` | `NULL` | Receipt read timestamp. |

### Table 3: `whatsapp_companion_devices_audit` (Linked `WhatsApp Web`, Desktops & Remote Handler Phones)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `companion_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Owning WhatsApp instance. |
| `companion_device_jid` | `TEXT` | `NOT NULL` | Device JID (`919876543210:12@s.whatsapp.net`). |
| `companion_os_and_browser` | `TEXT` | `NULL` | E.g., `"Windows (Chrome)"`, `"Mac OS (Desktop)"`, `"Android Companion Phone"`. |
| `paired_login_utc_iso` | `TEXT` | `NULL` | Exact UTC ISO-8601 timestamp when the QR code was scanned to link the remote device. |
| `last_active_utc_iso` | `TEXT` | `NULL` | Exact UTC ISO-8601 timestamp when the remote device was last active. |
| `recovery_classification` | `TEXT` | `NOT NULL` | `ORIGINAL_RECORD` (currently linked) or `HISTORICAL_COMMITTED_RECORD` / `RESIDUAL_RECORD` (previously unlinked device recovered from WAL/freelist!). |

---

## 8. Developer Acceptance Test Checklist for Module 5.1

1. **The `@lid` to Phone Number Unmasking Test:** In a test `msgstore.db`, create a group message where `sender_jid_row_id` points to `jid._id = 50` (`"164829104928172@lid"`), and insert a mapping row in `jid_map` linking `lid_row_id = 50` to `jid_row_id = 12` (`"919876543210@s.whatsapp.net"`), plus a `wa.db` `wa_contacts` row with `wa_name = "~ Hawala King"`. Verify that Module 5.1 outputs `sender_resolved_phone_jid = "+919876543210"` and `sender_push_and_saved_name = "~ Hawala King"`.
2. **The Quoted-Reply Revoked Message Reconstruction Test:** Insert a revoked message row (`_id = 100`, `key_id = "3EB09988"`, `message_type = 15`, `text_data = NULL`) and a reply row (`_id = 101`) with a matching `message_quoted` entry (`message_row_id = 101`, `key_id = "3EB09988"`, `text_data = "Delete this account number 0123456789 after transfer"`). Verify that Sub-Engine 5.1D populates Row 100's `recovered_pre_revoke_or_edit_text` with `"Delete this account number 0123456789 after transfer"` and tags it as `RECONSTRUCTED_RECORD (Recovered from Surviving Quoted Reply)`.
3. **The `.crypt15` Rolling Backup Diff-Recovery Test:** Delete an entire chat thread from the live `msgstore.db` while leaving that chat thread inside a yesterday's `msgstore-2026-11-04.1.db.crypt15` backup in `/Android/media/`. Verify that Sub-Engine 5.1A decrypts the `.crypt15` backup via Module 2.2 and merges the missing chat rows into `whatsapp_messages_master_ledger` tagged as `CRYPT15_ROLLING_BACKUP_DIFF`.