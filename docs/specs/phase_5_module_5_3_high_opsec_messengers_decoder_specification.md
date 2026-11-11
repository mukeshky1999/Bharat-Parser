# Engineering Specification: Phase 5, Module 5.3 — High-OpSec, Decentralized & Privacy Messengers Deep Decoder (`Session`, `SimpleX Chat`, `Threema`, `Briar`, `Element / Matrix`, `Wickr`, `Zangi`, `Wire` & `XMPP / Conversations`)

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 5.3** of the Forensic Data Parser (corresponding to **Group 1 and Group 5**, and cross-linked with **Groups 3, 8, 10, 12, and 15** of the Unified Master Register). It contains **zero programming code** and explains the local sandbox storage structures, cryptographic key-wrapping locations, anonymous routing identifiers (`66-hex Session IDs`, `SimpleX Pairwise Queues`, `8-char Threema IDs`, `Matrix Room Events`, and `Zangi` SQLite stores), and residual notification/attachment recovery methods from first principles so that any developer can build a commercial-grade parser for high-opsec messaging applications.

---

## 1. Purpose & Mental Model (Why High-OpSec Messengers Are Critical in Serious Crime Investigations)

While everyday users and low-tier mules communicate on WhatsApp and Telegram, **high-level syndicate coordinators, darknet narcotics vendors, ransomware operators, extortion rings, and cross-border handlers deliberately migrate to High-OpSec, Decentralized, and Zero-Phone-Number Messengers** specifically because they know law enforcement monitors telecom CDRs and mainstream platforms.

Traditional commercial forensic tools have poor or outdated support for these applications because:
1. **Zero Phone Number / Zero Email Registration:** Apps like **`Session`** (`network.loki.messenger`), **`SimpleX Chat`** (`chat.simplex.app`), **`Threema`** (`ch.threema.app`), and **`Briar`** (`org.briarproject.briar.android`) never ask for a phone number or email address. If an examiner searches a phone only for `+91` phone numbers, these apps appear completely empty.
2. **SQLCipher, H2 & Realm Database Encryption:** Almost all of these apps encrypt their local databases using **SQLCipher (v3 or v4)**, **Encrypted Realm**, or **Encrypted H2**, with keys stored in the **iOS Keychain**, **Android Keystore (`TEE`)**, or user-passphrase KDFs (handled via **Phase 2, Module 2.2**).
3. **Unconventional Database Paradigms:**
   * **`SimpleX Chat`** has **no user identity IDs at all**—not even a random public key ID! Instead, every contact connection uses a separate pair of unidirectional anonymous relay queues (`snd_queue`, `rcv_queue`) stored inside `simplex_v1_chat.db`.
   * **`Element / Matrix`** (`im.vector.app`) stores messages as **Matrix Event JSON objects (`m.room.message`, `m.room.encrypted`)** inside Realm or SQLite/IndexedDB stores.
   * **`Zangi`** (`com.beint.zangi` — heavily used in Indian extortion, "sextortion", and "Digital Arrest" call centers) uses a custom VoIP and messaging SQLite schema.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in High-OpSec Messenger Forensics

Before implementing Module 5.3, the developer must understand six critical traps:

### Mistake 1: Expecting Phone Numbers Instead of Cryptographic Identity Handles (`05...` Session IDs & Threema IDs)
* **The Trap:** Writing a parser schema that requires `sender_phone_number` to be a numeric phone number.
* **Why It Fails:**
  * In **`Session`**, every user is identified by a **66-character hexadecimal `Session ID` that always starts with the prefix `05`** (a `05` version byte followed by a 32-byte Curve25519 public key in hex, e.g., `05a1b2c3d4e5f6...`), or an **Oxen Name System (`ONS`)** human-readable handle!
  * In **`Threema`**, every user is identified by an **8-character alphanumeric `Threema ID`** (e.g., `ABCD1234`).
  * In **`Element / Matrix`**, every user is identified by a federated **`Matrix ID`** (`@username:homeserver.org`, e.g., `@viper:matrix.org`).
* **The Rule:** Normalize and validate each platform's native cryptographic identifier format and cross-link it against **WhatsApp/Telegram/SMS/Notes (`Phase 5.5` & `Phase 4`)** where suspects originally exchanged their `05...` Session ID or `SimpleX` invitation link!

### Mistake 2: Missing the Fact That `Session` Is a Fork of `Signal` (Sharing Core SQLCipher Architecture)
* **The Trap:** Treating `Session` (`network.loki.messenger`) as an unknown custom binary format.
* **Why It Matters:** `Session` was originally forked from Signal Android (`TextSecure`) and Signal iOS (`SignalServiceKit`)!
  * On **Android**, `/data/user/<id>/network.loki.messenger/databases/session.db` uses **SQLCipher v4**, and its encryption secret is stored in `/shared_prefs/network.loki.messenger_preferences.xml` under `pref_database_encrypted_secret` (wrapped by the Android Keystore alias `"SessionSecret"` or `"SignalSecret"`, identical to Signal Recipe 2 in Module 2.2!).
  * On **iOS**, `/private/var/mobile/Containers/Shared/AppGroup/<Session-Group-UUID>/grdb/Signal.sqlite` (or `Session.sqlite`) uses **SQLCipher v4**, with its 48-byte (`96-hex-char`) key stored in the iOS Keychain under service `OWSPrimaryStorage` / `LokiStorage`!
* **The Rule:** Reuse **Phase 2, Module 2.2's Signal Key-Unwrapping Recipes** to automatically decrypt `Session` databases on both Android and iOS!

### Mistake 3: Failing to Extract Out-of-Band Invitation Links (`SimpleX`, `Briar`, `Session`)
* **The Trap:** If a `SimpleX` or `Briar` database is passphrase-locked at rest (`Dimension B = ENCRYPTED_GATED_MISSING_KEY`), giving up and reporting zero intelligence.
* **Why It Fails:** Because `SimpleX` and `Session` have no central user directory, **two criminals cannot connect on `SimpleX` or `Session` without first sending each other an invitation link (`https://simplex.chat/contact#/?v=...` or a `05...` Session ID) over another app** (like WhatsApp, Telegram, SMS, Email, or scanning a QR code screenshot)!
* **The Rule:** Even if the high-opsec app's database is locked, Module 5.3 scans **all other parsed databases, clipboards, keyboard caches, and screenshots on the phone** for `simplex.chat/contact#`, `session.db` / `05[0-9a-fA-F]{64}`, `threema.id/`, and `briar://` connection links—proving **when and with whom** the suspect established the covert channel!

### Mistake 4: Missing Unencrypted Push Notification & Attachment Caches in `Zangi`, `Wickr`, and `Element`
* **The Trap:** Looking only at the main encrypted message database when examining `Zangi`, `Element`, or `Wickr`.
* **Why It Fails:** Even when an app encrypts its primary message database, it frequently caches media thumbnails inside `/cache/image_manager_disk_cache/` (Glide/Fresco), logs incoming call/notification metadata in OS Notification Ledgers (`DuetExpertCenter`, Biome `SEGB`, Android `notification_history`), and leaves VoIP call records inside **iOS `CallHistory.storedata` (`CallKit` integration)**!
* **The Rule:** Always correlate high-opsec app Bundle IDs against **iOS `CallHistory.storedata`** (Group 1 — which records the exact timestamp, duration, and handle of `Zangi`, `Session`, `Threema`, `Element`, and `Wire` VoIP calls!) and **OS Notification Ledgers** (Module 3.4).

### Mistake 5: Ignoring `SimpleX Chat`'s Pairwise Queue Architecture (`connections` & `messages`)
* **The Trap:** Looking for a traditional `users` table with static user IDs inside `SimpleX Chat`'s `simplex_v1_chat.db`.
* **Why It Fails:** `SimpleX` assigns a different anonymous SMP (SimpleX Messaging Protocol) relay server address and queue ID to every single contact and group member. To reconstruct who said what, you must join `messages` $\rightarrow$ `chat_items` $\rightarrow$ `connections` $\rightarrow$ `contacts` / `groups` (Section 4).

### Mistake 6: Missing `XMPP / Jabber` (`Conversations`, `Blabber`, `ChatSecure`) `OMEMO` Key Fingerprints
* **The Trap:** Parsing `Conversations` (`eu.siacs.conversations`) messages without extracting the `OMEMO` (`XEP-0384`) cryptographic device fingerprint and XMPP server domain.
* **Why It Fails:** Darknet vendors use federated XMPP servers (e.g., `user@jabber.calyxinstitute.org`, `vendor@exploit.im`, `mule@404.city`). Extracting the `account`, `counterpart` JID, and `fingerprint` from the SQLite `messages` and `identities` tables links the suspect directly to their darknet forum PGP/OMEMO identity!

---

## 3. Step 1 — Sub-Engine 5.3A: `Session` (`network.loki.messenger`) Decentralized Oxen Onion-Routed Decoder

* **Target Identifiers (Query via Module 1.3 `resolve_app_targets`):**
  * **Android:** `network.loki.messenger`
  * **iOS:** `com.loki-project.loki-messenger` (Shared AppGroup: `group.com.loki-project.loki-messenger`)

### 3.1 Step 1: Unwrapping `session.db` (Android) & `Signal.sqlite` (iOS)
1. **On Android (`/data/user/<id>/network.loki.messenger/databases/session.db`):**
   * Locate `/shared_prefs/network.loki.messenger_preferences.xml`.
   * Extract `pref_database_encrypted_secret` (AES-GCM JSON blob wrapped by Android Keystore key `"SessionSecret"` or `"SignalSecret"`) or `pref_database_unencrypted_secret`.
   * Also extract the suspect's own **66-character `05...` Session ID** (`pref_local_number` / `user_public_key`) and **Seed / Mnemonic** (if cached in encrypted preferences) directly from `network.loki.messenger_preferences.xml`!
   * Decrypt `session.db` (+ `session.db-wal`) via **Phase 2, Module 2.2 (SQLCipher v4 Profile)** and extract active, `-wal`, and freelist records via **Module 2.1**.
2. **On iOS (`/Containers/Shared/AppGroup/<UUID>/grdb/Signal.sqlite` or `Session.sqlite`):**
   * Look up the 48-byte (`96-hex-char`) SQLCipher v4 key in `case_cryptographic_keyring` where `agrp` contains `loki-messenger` (`svce == "OWSPrimaryStorage"` / `acct == "GRDBDatabaseCipherKeySpec"`).
   * Decrypt the database and `-wal` via Module 2.2 and parse via Module 2.1.

### 3.2 Step 2: Extracting Session Identities, Closed Groups, Open Groups (`SOGS`) & Messages
1. **Contacts & Session IDs (`recipient` / `session_contact_database` on Android; `Contact` / `Profile` tables on iOS):**
   * `session_id` / `address`: The 66-character hexadecimal string starting with **`05`** (for standard users and Closed Groups) or **`15` / `25`** (for blinded Session IDs inside Open Groups / Communities!).
   * `name` & `nickname`: The display name set by the remote user and the local nickname set by the suspect.
   * `profile_picture_url` & `profile_key`: URL on the Oxen file server where the user's avatar is hosted.
2. **Threads & Open Group (`SOGS`) Servers (`thread` & `loki_public_chat_database` / `open_group`):**
   * Distinguish:
     * **1-on-1 Direct Chats:** Identified by a `05...` Session ID.
     * **Closed Groups (End-to-End Encrypted):** Identified by a `05...` group ID + member list in `groups` / `closed_group`.
     * **Open Groups / Communities (`SOGS` — Session Open Group Server):** Extract the **exact Open Group Server URL, Room Token, and Public Key** (e.g., `https://open.getsession.org/crypto_traders?public_key=...`).
3. **Messages, Disappearing Timers & Attachments (`sms` / `mms` / `message` on Android; `interaction` / `model_TSInteraction` on iOS):**
   * Extract `_id`, `thread_id`, `address` (sender `05...` Session ID), `date_sent` (13-digit Unix ms), `date_received`, `body` (plaintext message), `expires_in` (Disappearing timer: *Disappear After Read* vs. *Disappear After Send*), and `quote_id` / `quote_body` (surviving quoted replies!).
   * Decrypt on-disk attachments in `/app_parts/` using the `attachment_secret` (`ModernAttachmentCipher` AES-256-CTR from Module 5.2 Section 6.2).

---

## 4. Step 2 — Sub-Engine 5.3B: `SimpleX Chat` (`chat.simplex.app`) Zero-ID Pairwise Queue Decoder

* **Target Identifiers:**
  * **Android:** `chat.simplex.app`
  * **iOS:** `chat.simplex.app` (Shared AppGroup: `group.chat.simplex.app`)
* **Database Files (`/databases/` on Android; `Documents/` or AppGroup on iOS):**
  * **`simplex_v1_chat.db`** (+ `-wal`): Stores user profiles, contacts, groups, chat items (messages), and file transfers.
  * **`simplex_v1_agent.db`** (+ `-wal`): Stores the low-level SMP (SimpleX Messaging Protocol) pairwise relay server queues, server hostnames (`smp://...` and `xftp://...`), and cryptographic ratchets!

### 4.1 Step 1: Unwrapping `simplex_v1_chat.db` & `simplex_v1_agent.db`
1. **Check Passphrase / Keychain State:**
   * By default (or when "Store passphrase in Keychain / Biometrics" is enabled), SimpleX either leaves `simplex_v1_chat.db` as **plaintext SQLite** (`"SQLite format 3\0"`) OR encrypts it with **SQLCipher v4** where the passphrase/key is stored inside Android `EncryptedSharedPreferences` / Keystore or iOS Keychain (`chat.simplex.app`).
   * If encrypted and the key is not in Keystore/Keychain, test the **Candidate Profile Password Dictionary** (from Module 3.3 / Module 2.2) against Page 1 of `simplex_v1_chat.db` using Module 2.2's SQLCipher v4 prober.
2. **Process Both Databases Through Module 2.1 (Active + `-wal` + Freelist):**
   * Because SimpleX frequently deletes expired messages or updates `chat_items` in place, running Module 2.1's `-wal` reader and B-Tree freelist carver on `simplex_v1_chat.db` recovers deleted chat items!

### 4.2 Step 2: Reconstructing `SimpleX` Contacts, Groups, SMP Relay Queues & Messages
1. **Local User Profiles (`users` Table in `simplex_v1_chat.db`):**
   * SimpleX supports **multiple isolated user profiles** (including **Hidden / Incognito Profiles** protected by a separate password!). Extract every row in `users`: `user_id`, `contact_id`, `local_display_name`, `full_name`, `incognito` flag, and `active_user` flag.
2. **Contacts & Groups (`contacts`, `groups`, `group_members` Tables):**
   * From `contacts`: Extract `contact_id`, `user_id` (which local profile owns this contact), `local_display_name` (nickname), `profile_id` $\rightarrow$ `contact_profiles` (`display_name`, `full_name`, `image`), `created_at`, and `updated_at`.
   * From `groups` & `group_members`: Extract `group_id`, `local_display_name` (group title), member list, and member roles (`owner`, `admin`, `member`).
3. **Messages & Chat Items (`chat_items` & `messages` Tables):**
   * Query `chat_items` (`SELECT chat_item_id, user_id, contact_id, group_id, group_member_id, chat_dir, item_ts, item_text, item_content, item_status, item_deleted, item_edited, timed_ttl, created_at FROM chat_items;`):
     * `chat_dir`: Direction (`0`/`1` or string code indicating Sent vs. Received).
     * `item_ts` & `created_at`: Message timestamp.
     * `item_text`: Plaintext message string!
     * `item_content`: **JSON string** containing rich message structure (`{"type":"text","text":"..."}`, `{"type":"file",...}`, `{"type":"voice",...}`, quoted reply text, and forwarding flags!).
     * `item_deleted`: **`1` if the message was deleted!** *(Crucial Forensic Discovery: When a user deletes a message in SimpleX or receives a remote deletion event, SimpleX sometimes keeps the row in `chat_items` with `item_deleted = 1` while the earlier un-deleted `item_text` / `item_content` sits right inside `simplex_v1_chat.db-wal` or B-Tree freeblocks!)*
4. **Pairwise SMP Server & Queue Attribution (`connections` in `simplex_v1_chat.db` + `snd_connections`/`rcv_connections` in `simplex_v1_agent.db`):**
   * Extract the exact **`smp://` and `xftp://` relay server URLs** (including custom self-hosted Tor `.onion` SMP servers used by darknet operators!) and connection invitation strings (`conn_req_inv`).

---

## 5. Step 3 — Sub-Engine 5.3C: `Zangi`, `Threema`, `Briar`, `Element / Matrix`, `Wickr`, `Wire` & `XMPP / Conversations`

### 5.1 Target 1: `Zangi` Private Messenger (`com.beint.zangi` / `com.secret.CallApp`)
* **Why `Zangi` Is High-Priority in India:** `Zangi` assigns users a **10-digit virtual `Zangi Number` (starting with `10-...` or `99-...`, e.g., `10-4829-1049`)** without requiring a SIM card or phone number in recent versions, making it a favorite tool of Indian extortion ("sextortion"), fake-loan harassment, and mule-handling rings.
* **Step-by-Step Sandbox Extraction (`/data/user/<id>/com.beint.zangi/` on Android; `<App-UUID>/Documents/` on iOS):**
  1. **User Profile & `Zangi Number` (`shared_prefs/*.xml` & `MMKV` / `NSUserDefaults`):**
     * Extract the suspect's own **10-digit `Zangi Number`**, registered email/phone (if linked), display name, and registration timestamp.
  2. **SQLite Databases (`/databases/*zangi*.db`, `messenger*.db`, `contacts*.db`, `calls*.db` via Module 2.1 Active + `-wal` + Freelist):**
     * **Contacts Table:** Maps remote **10-digit `Zangi Numbers`** to display names, avatars, and creation dates.
     * **Messages / Conversations Table:** Extracts `message_id`, `conversation_id`, `sender_zangi_number`, `receiver_zangi_number`, `message_body`, `media_url` / local cached file path in `/files/` or `/cache/`, `status`, and `timestamp`.
     * **Call Logs Table (+ iOS `CallHistory.storedata`):** Extracts voice and video call timestamps, durations, and remote `Zangi Numbers`.

### 5.2 Target 2: `Threema` (`ch.threema.app`) & `Threema Work` (`ch.threema.app.work`)
* **Identity Format:** Every user has an **8-character alphanumeric `Threema ID`** (e.g., `X9K2M4P8`) tied to a Curve25519 public key.
* **Sandbox Extraction:**
  * On **Android**, `/databases/threema4.db` (or `threema.db`) is encrypted with **SQLCipher** (key derived from `key.dat` in `/files/key.dat` or master passphrase; if `Passphrase` protection is disabled by the user, `key.dat` holds the raw 32-byte key directly on disk! Unwrap via Module 2.2).
  * On **iOS**, `ThreemaData.sqlite` sits inside the AppGroup container (protected by iOS Data Protection Class C/A).
  * Extract the suspect's own **8-char `Threema ID`**, contacts (`identity`, `public_key`, `first_name`, `last_name`, `nick_name`, `verification_level` $1, 2,$ or $3\text{ green dots}$), messages (`message`, `group_message`), and media files (decrypted via the master `key.dat` stream if encrypted on disk).

### 5.3 Target 3: `Element / Matrix` (`im.vector.app` / `io.element.android.x`)
* **Architecture:** `Element` (and `Element X`) is the flagship client for the decentralized **Matrix protocol**, where users communicate across federated or self-hosted homeservers (`@user:matrix.org`, `@boss:darkserver.onion`).
* **Sandbox Extraction:**
  * **Element Classic (`im.vector.app`):** Uses encrypted/unencrypted **Realm (`.realm`)** databases (`disk_store.realm`, `crypto_store.realm`) and SQLite caches, with keys stored in `/shared_prefs/` (wrapped by Android Keystore) or iOS Keychain.
  * **Element X (`io.element.android.x` — Rust Matrix SDK):** Uses **SQLite (`matrix-sdk-state.sqlite3`, `matrix-sdk-crypto.sqlite3`)** inside `/files/`!
  * Extract:
    * The suspect's **`Matrix ID` (`@user:domain`)**, **`Homeserver URL`**, and **`Device ID`**.
    * Decrypted cached **`m.room.message` timeline events** (`sender`, `room_id`, `content.body`, `origin_server_ts`).
    * Room rosters (`m.room.member`) and `Megolm` session metadata.

### 5.4 Target 4: `Briar` (`org.briarproject.briar.android`), `Wickr` (`com.mywickr.wickr2` / `com.wickr.pro`), `Wire` (`com.wire`) & `XMPP / Conversations` (`eu.siacs.conversations`)

| High-OpSec App | Package / Bundle ID | Database Engine & Key Location | Key Forensic Artifacts to Extract |
|---|---|---|---|
| **Briar (Tor P2P)** | `org.briarproject.briar.android` | **Encrypted H2 Database (`db.mv.db`)** — encrypted with user password (or check RAM/notification/tor-state residue). | Even when `db.mv.db` is password-locked, extract Tor hidden service `.onion` state files in `/app_tor/`, Bluetooth/Wi-Fi peer MAC caches, and `briar://` invitation links from clipboard/keyboard/other chats! |
| **XMPP (`Conversations`, `Blabber`, ` Siskin`, `Monal`, `ChatSecure`)** | Android: `eu.siacs.conversations`, `im.blabber.messenger`<br>iOS: `org.tigase.messenger.siskin`, `im.monal.Monal`, `com.chrisballinger.ChatSecure` | **Plaintext SQLite (`history` DB on Android `Conversations`)** or SQLCipher (`ChatSecure`). | **Crucial:** `eu.siacs.conversations` stores `/databases/history` as **unencrypted plaintext SQLite** by default! Query `accounts` (`username`, `server`), `conversations` (`contactjid`), `messages` (`body`, `timeSent`, `encryption` = `OMEMO` / `PGP` / `OTR`, `fingerprint`), and `identities` (`fingerprint` of every OMEMO device!). |
| **Wire** | `com.wire` | SQLite / CoreData (`store.wiredb` / `ZMESSAGE` on iOS; per-user SQLite on Android). | Extract `@handle`, user UUID, team/workspace ID, plaintext cached messages (`ZGENERICMESSAGE` protobufs), and ephemeral timer settings. |
| **AWS Wickr / Wickr Pro** | `com.wickr.pro`, `com.mywickr.wickr2` | Encrypted SQLite / WIC containers. | Extract account username, company room metadata, CallKit logs (`CallHistory.storedata`), and cached notification/attachment metadata. |

---

## 6. Database Schema for Module 5.3 (`high_opsec_messengers_engine.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `opsec_messenger_identities_and_relays` (Cryptographic IDs, `05...` Session IDs, `Zangi` Numbers, Matrix Homeservers & SMP Queues)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `opsec_id_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_platform_name` | `TEXT` | `NOT NULL` | Enum: `SESSION`, `SIMPLEX_CHAT`, `ZANGI`, `THREEMA`, `ELEMENT_MATRIX`, `BRIAR`, `XMPP_CONVERSATIONS`, `WIRE`, `WICKR`. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning app in Module 1.3. |
| `identity_role` | `TEXT` | `NOT NULL` | Enum: `LOCAL_DEVICE_OWNER`, `REMOTE_CONTACT`, `CLOSED_GROUP`, `OPEN_COMMUNITY_SERVER`, `SMP_RELAY_QUEUE`. |
| `primary_crypto_handle` | `TEXT` | `NOT NULL` | E.g., `05a1b2...` (66-hex Session ID), `10-4829-1049` (Zangi Number), `X9K2M4P8` (Threema ID), `@user:matrix.org`, `user@exploit.im`, or SimpleX `contact_id`. |
| `display_or_nickname` | `TEXT` | `NULL` | User profile name or local nickname. |
| `server_or_relay_url` | `TEXT` | `NULL` | Custom Matrix homeserver, Session Open Group URL (`SOGS`), SimpleX `smp://` relay server, or XMPP domain. |
| `public_key_or_omemo_fp` | `TEXT` | `NULL` | Curve25519 public key or XMPP OMEMO device fingerprint. |
| `invitation_link_raw` | `TEXT` | `NULL` | Out-of-band `simplex.chat/contact#...` or `briar://` invite URI. |
| `created_or_first_seen_utc` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 2: `opsec_messenger_messages_ledger` (Decoded Messages, Disappearing Records & Deleted Queue Survivors)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `opsec_msg_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_platform_name` | `TEXT` | `NOT NULL` | Platform name (`SESSION`, `SIMPLEX_CHAT`, `ZANGI`, etc.). |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to Module 1.3. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source database file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD` \[`-wal`\], `RESIDUAL_RECORD` \[freelist/deleted flag\], etc.). |
| `thread_identifier` | `TEXT` | `NOT NULL` | Thread / conversation / group ID. |
| `direction` | `TEXT` | `NOT NULL` | Enum: `OUTGOING_SENT`, `INCOMING_RECEIVED`, `SYSTEM_EVENT`. |
| `sender_crypto_handle` | `TEXT` | `NULL` | Sender's `05...` Session ID, Zangi Number, Matrix ID, XMPP JID, or SimpleX Contact Name. |
| `receiver_crypto_handle` | `TEXT` | `NULL` | Recipient handle or group name. |
| `message_body_text` | `TEXT` | `NULL` | Decoded message text. |
| `quoted_reply_text` | `TEXT` | `NULL` | Quoted parent message text (if reply). |
| `ephemeral_ttl_seconds` | `INTEGER` | `DEFAULT 0` | Disappearing message timer in seconds (`> 0` if ephemeral). |
| `was_marked_deleted_in_db` | `INTEGER` | `DEFAULT 0` | `1` if `SimpleX` `item_deleted == 1` or recovered from `-wal` / freelist. |
| `attachment_metadata_json` | `TEXT` | `NULL` | JSON detailing decrypted attachment path, filename, MIME type, and SHA-256 hash. |
| `sent_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `sent_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |

### Table 3: `cross_app_opsec_invite_links_discovered` (Out-of-Band Session IDs & SimpleX Links Found in Other Apps)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `invite_discovery_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID. |
| `target_opsec_platform` | `TEXT` | `NOT NULL` | Enum: `SESSION_ID_05`, `SIMPLEX_INVITE_URI`, `THREEMA_ID_LINK`, `BRIAR_LINK`, `MATRIX_ID`, `ZANGI_NUMBER`. |
| `extracted_handle_or_uri` | `TEXT` | `NOT NULL` | Exact `05...` 66-hex ID, `https://simplex.chat/contact#...`, or `10-xxxx-xxxx` Zangi Number found. |
| `found_in_source_app_and_table` | `TEXT` | `NOT NULL` | Where on the phone the link was shared (e.g., `"WhatsApp msgstore.db (Chat with +919876543210)"`, `"iOS Dynamic Keyboard Cache"`, `"Telegram Saved Messages"`). |
| `shared_timestamp_utc_iso` | `TEXT` | `NULL` | Timestamp when the covert handle/link was exchanged! |

---

## 7. Developer Acceptance Test Checklist for Module 5.3

1. **The `Session` (`05...`) SQLCipher Unwrap & Open Group (`SOGS`) Test:** Create a test `session.db` encrypted with SQLCipher v4 containing a 1-on-1 message from `05a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef01` and an Open Group room entry (`https://open.getsession.org/hawala`). Verify that Sub-Engine 5.3A unwraps `session.db` using the key from `network.loki.messenger_preferences.xml`, validates the 66-char `05...` Session ID, and extracts both the message and the Open Group server URL.
2. **The `SimpleX Chat` `item_deleted = 1` & WAL Recovery Test:** In a test `simplex_v1_chat.db`, insert a row in `chat_items` (`item_text = "Drop package at Sector 18"`, `item_deleted = 0`), commit to WAL, and then update the row to `item_text = ""`, `item_deleted = 1` without checkpointing. Verify that Sub-Engine 5.3B recovers the pre-deletion `"Drop package at Sector 18"` text from the `-wal` frame and links the contact to its `smp://` relay server from `simplex_v1_agent.db`.
3. **The Out-of-Band Covert Handle Cross-Linker Test:** Place a WhatsApp message inside `msgstore.db` reading `"Delete WhatsApp and message me on Session: 05f8e7d6c5b4a39281706f5e4d3c2b1a0987654321fedcba0987654321fedcba"` and a second message containing `"https://simplex.chat/contact#/?v=2-7&smp=smp%3A%2F%2F..."`. Verify that Table 3 (`cross_app_opsec_invite_links_discovered`) automatically captures both covert handles and links them to the WhatsApp sender's `+91` phone number!