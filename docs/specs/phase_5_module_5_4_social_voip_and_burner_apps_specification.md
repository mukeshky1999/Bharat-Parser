# Engineering Specification: Phase 5, Module 5.4 — Mainstream Social, Cross-Border VoIP & Virtual Burner Number Decoders (`Instagram Direct`, `Facebook Messenger MSYS`, `Snapchat Arroyo`, `Discord`, `Botim`, `IMO`, `WeChat`, `Viber`, `LINE` & Burner VoIP Apps)

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 5.4** of the Forensic Data Parser (corresponding to **Group 1 and Group 5**, and cross-linked with **Groups 2, 3, 6, 8, 12, 13, and 15** of the Unified Master Register). It contains **zero programming code** and explains Meta's modern `MSYS` / `Lightspeed` and `Reverb` E2EE SQLite architectures, Snapchat's `arroyo.db` binary Protocol Buffer message structures, Discord's `MMKV` + Chromium `Simple Cache` API JSON harvester, cross-border VoIP apps (`Botim`, `IMO`, `WeChat`), and Virtual Burner Number (`+1` / `+44`) OTP correlation from first principles so that any developer can build a commercial-grade social, VoIP, and burner-number forensic engine.

---

## 1. Purpose & Mental Model (Why Social, Cross-Border VoIP & Burner Apps Are Essential in Modern Crime)

While WhatsApp, Telegram, and Signal handle the bulk of text messaging, four specific categories of crime rely heavily on the platforms covered in **Module 5.4**:

1. **Social Media Direct Messaging (`Instagram Direct`, `Facebook Messenger`, `Snapchat`, `Discord`):**
   * Primary channels for financial "sextortion" rings, mule-account recruitment ads, narcotics distribution (`Snapchat` disappearing snaps/chats), and gaming/crypto drainer syndicates (`Discord`).
   * **Architectural Shift:** Meta (`Instagram` and `Facebook Messenger`) and Snap Inc. (`Snapchat`) completely replaced their legacy SQLite schemas over the last three years. Instagram migrated to `direct.db` + `reverb.db` + **`MSYS` (`Mobile System` / `Lightspeed`)** end-to-end encrypted tables; Snapchat migrated to **`arroyo.db`**, which stores every chat message inside a raw binary Google Protocol Buffer (`BLOB`).
2. **Cross-Border Gulf / Middle East Handler VoIP Apps (`Botim` & `IMO`):**
   * In Indian hawala, gold smuggling, cyber-fraud call centers, and mule-account syndicates where the masterminds operate from **Dubai (UAE), Oman, Saudi Arabia, or Qatar**, standard WhatsApp and Telegram voice calls are throttled or blocked by Middle Eastern telecom regulators. Consequently, **Indian field operatives and their Dubai/Gulf handlers communicate almost exclusively over `Botim` (`com.atg.botim`) and `IMO` (`com.imo.android.imoim`)**!
3. **East & Southeast Asian Supply-Chain Syndicate Messengers (`WeChat`, `LINE`, `Viber`):**
   * In investment ("Pig Butchering"), fake loan-app, and illegal betting syndicates managed from Southeast Asia (Cambodia, Myanmar, Laos) or China, handlers coordinate with Indian tech/payment operators using **Tencent `WeChat` (`com.tencent.mm`)** and **`LINE`** (newly supported on iOS in `iLEAPP v2026.4.6`).
4. **Virtual Burner Number / Secondary Line Apps (`TextNow`, `2ndLine`, `NextPlus`, `Hushed`, `Dingtone`, `PingMe`, `Virtual SIM`):**
   * Suspects frequently operate WhatsApp or Telegram accounts registered to **US/Canadian (`+1`)** or **UK (`+44`)** phone numbers. Investigators often assume the suspect had a foreign SIM card or an accomplice abroad. In reality, the suspect installed a **Virtual Burner Number app** right on the seized phone, generated a `+1` or `+44` virtual number over Wi-Fi, received the 6-digit WhatsApp/Telegram registration OTP inside the burner app, and activated the anonymous WhatsApp/Telegram account locally!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Social, VoIP & Burner App Forensics

Before implementing Module 5.4, the developer must understand six critical traps that break legacy forensic scripts:

### Mistake 1: Looking Only for Legacy `threads_db2` in Facebook Messenger & Instagram Instead of `MSYS` / `Lightspeed` & `Reverb`
* **The Trap:** Writing a Facebook Messenger (`com.facebook.orca`) parser that looks only for `/databases/threads_db2` or an Instagram (`com.instagram.android`) parser that looks only for a single `direct.db` file.
* **Why It Fails:**
  1. Meta re-engineered Facebook Messenger and Instagram Direct around Project **Lightspeed (`MSYS` — Mobile System)** and **Labyrinth** (Meta's E2EE messaging protocol). Modern Messenger stores its primary threads, contacts, and messages inside **`msys_database_<user_id>.db`** (or `crypto_db_<user_id>.db`).
  2. Modern Instagram splits direct messages across **three co-existing databases per logged-in user ID**: `direct_<user_id>.db` (JSON-serialized thread/message cache), `reverb_<user_id>.db` (persistent message history cache), and `msys_database_<user_id>.db` / `crypto_db_<user_id>.db` (E2EE and vanish-mode messages)!
* **The Rule:** Enumerate all user-ID-suffixed databases in the Instagram and Messenger sandboxes and parse all three schema families (Section 3).

### Mistake 2: Assuming Snapchat Messages Cannot Be Recovered Because "Snaps Disappear"
* **The Trap:** Skipping `/data/user/0/com.snapchat.android/` under the belief that Snapchat deletes everything in RAM.
* **Why It Fails:** Modern Snapchat uses a unified messaging engine codenamed **`Arroyo`**, stored in `/databases/arroyo.db` (+ `arroyo.db-wal`).
  1. Any chat message or media snap that a user taps to **"Save in Chat"** (or sets to 24-hour retention) is permanently written into `arroyo.db` (`conversation_message` table).
  2. Even for messages set to "Delete After Viewing," before `arroyo.db-wal` checkpoints or `0x0D` B-Tree leaf pages are overwritten, **Phase 2, Module 2.1's Shared `-wal` Reader and Freelist Carver** frequently recover the raw binary Protobuf payloads of expired Snapchat messages!
  3. Furthermore, Snapchat's **`memories.db`** (`memories_entry`, `memories_snap`) and `/files/file_manager/` cache hold saved Memories, **Location/Altitude/Speed overlay metadata**, and **"My Eyes Only" (`MEO`)** encrypted vault entries.
* **The Rule:** Parse `arroyo.db`, `main.db`, and `memories.db` through Module 2.1 + Module 2.3D's Protobuf decoder (Section 4.1).

### Mistake 3: Searching Discord's Sandbox for a SQLite Chat Table Instead of Harvesting `Simple Cache (*_0)` API JSONs
* **The Trap:** Looking inside `/data/user/0/com.discord/databases/` for a SQLite table called `messages` and finding nothing.
* **Why It Fails:** Discord Mobile is a React Native application that caches recent state in **Tencent `MMKV` / `LevelDB`** and caches **entire channel and direct-message JSON histories inside its HTTP network cache (`cache/http-cache/` or `app_webview/Default/Cache/Cache_Data/*_0`)**! Whenever a suspect opens a Discord channel or DM, Discord fetches `https://discord.com/api/v9/channels/<channel_id>/messages?limit=50` and saves the Gzip/Brotli-compressed JSON array of all 50 messages (including author ID, username, avatar, message content, attachment URLs, and edited timestamps) directly into the disk HTTP cache!
* **The Rule:** Combine `MMKV` / `RKStorage` state parsing with an automated HTTP Cache JSON harvester for Discord endpoints (Section 4.2).

### Mistake 4: Ignoring `Botim` and `IMO` in Indian Financial & Organized Crime Investigations
* **The Trap:** Treating `Botim` (`com.atg.botim`) and `IMO` (`com.imo.android.imoim`) as obscure foreign apps and leaving their SQLite databases unparsed in the `UNK` register.
* **Why It Fails:** Almost every Indian cyber-fraud call center or hawala mule communicating with a boss in Dubai/UAE has `Botim` or `IMO` installed. Both apps store rich local SQLite databases (`messages`, `contacts`, `call_logs`) containing the handler's **UAE (`+971...`), Saudi (`+966...`), Oman (`+968...`), or Cambodian (`+855...`) phone number**, voice/video call durations, and shared bank account screenshots!
* **The Rule:** Provide dedicated schema decoders for `Botim` and `IMO` (Section 5.1 & Section 5.2).

### Mistake 5: Failing to Bridge Virtual Burner Numbers (`+1` / `+44`) to Local WhatsApp & Telegram Accounts
* **The Trap:** Parsing `TextNow` or `2ndLine` as a standalone app without checking if the virtual phone number assigned to that app (`+1-415-555-0199`) is the exact phone number registered inside the suspect's `WhatsApp` (`me` file / `startup_prefs.xml`) or `Telegram` (`userconfing.xml` `account2`) on the same phone!
* **Why It Fails:** Proving in court that the `+1-415-555-0199` WhatsApp account used to extort a victim was **created, OTP-verified, and operated on the suspect's seized handset via a burner app** destroys any claim that the account belonged to a foreign national.
* **The Rule:** Sub-Engine 5.4D must automatically cross-match every virtual number and incoming OTP inside burner apps against all local messaging accounts in Modules 5.1, 5.2, and 5.3 (Section 6).

### Mistake 6: Forgetting to Cross-Check iOS `CallHistory.storedata` for Deleted Social & VoIP Calls
* **The Trap:** Relying only on the social app's internal call log table when a suspect deletes their call history inside Instagram, Snapchat, Botim, or Messenger.
* **Why It Fails:** On iOS, all modern VoIP apps integrate with Apple's **`CallKit`** framework. Every incoming and outgoing VoIP call on Instagram, Messenger, Snapchat, Botim, IMO, WhatsApp, Telegram, Signal, Zangi, and Line writes a persistent SQLite row into `/private/var/wireless/Library/CallHistoryDB/CallHistory.storedata` (`ZCALLRECORD` table: `ZSERVICE_PROVIDER`, `ZADDRESS`, `ZDATE`, `ZDURATION`, `ZORIGINATED`). Deleting the call inside the third-party app **never deletes the row in `CallHistory.storedata`**!

---

## 3. Step 1 — Sub-Engine 5.4A: Meta Ecosystem Decoders (`Instagram Direct` & `Facebook Messenger`)

### 3.1 Target 1: Instagram Direct (`com.instagram.android` on Android / `com.burbn.instagram` on iOS)

Instagram allows a user to stay logged into multiple Instagram accounts simultaneously. Every database inside `/data/user/<id>/com.instagram.android/databases/` (or iOS `Library/Application Support/`) is suffixed with the logged-in user's **Instagram Numeric PK (`<ig_user_pk>`, e.g., `17841405829104`)**.

#### Step-by-Step Multi-Database Instagram Extraction Pipeline:
1. **Step 1 — Logged-In Account Inventory (`shared_prefs/` & `user_prefs`):**
   * Scan `/shared_prefs/com.instagram.android_preferences.xml` and `acdc_*.xml` / `user_session_*.xml` (or iOS `Library/Preferences/group.com.burbn.instagram.plist`) to extract every logged-in Instagram account's **`user_id` (`pk`)**, **`@username`**, **Full Name**, **Linked Phone Number**, **Linked Email Address**, and ** linked Facebook UID**.
2. **Step 2 — Database Family A: `direct_<ig_user_pk>.db` (JSON-Serialized Thread & Message Store):**
   * Stage `direct_*.db` (+ `-wal`) via Module 1.1 and process via **Module 2.1 (Active + `-wal` + Freelist)**.
   * **Threads Table (`threads`):**
     * Extract `thread_id`, `viewer_id` (`<ig_user_pk>`), `named` (group title), `last_activity_time` (Unix ms / microseconds), and parse the **`thread_info` (`TEXT` JSON)** column!
     * Inside `thread_info` JSON, iterate through the `recipients` / `users` array to extract every participant's **`pk` (Instagram User ID)**, **`username` (`@handle`)**, **`full_name`**, **`is_verified`**, and profile picture URL.
   * **Messages Table (`messages`):**
     * Extract `_id`, `message_id`, `thread_id`, `sender_id` (`user_id`), `timestamp` (note: Instagram `direct.db` timestamps are often stored in **16-digit Unix Microseconds**—auto-detect via Module 1.2's epoch unit checker and divide by $10^6$ for seconds!), `message_type` (`text`, `media`, `voice_media`, `reel_share`, `story_share`, `clip`, `action_log`, `placeholder`), `text` (plaintext message), and parse the **`message` (`TEXT` JSON)** column!
     * Inside the `message` JSON column, extract:
       * `text` (full text if not in flat column).
       * `replied_to_message`: **Full embedded JSON object of the parent quoted message** (including the parent message's `user_id` and `text`—which survives even after the parent message was **"Unsent"** by the sender!).
       * `media` / `visual_media` / `voice_media`: Extracts `media_url`, expiration timestamps for **View-Once / Replayable Ephemeral Photos ("Raven" media)**, and local cache keys.
       * `reel_share` / `clip` / `felix_share`: Extracts shared Instagram Reel URLs, creator `@username`, and captions.
3. **Step 3 — Database Family B: `reverb_<ig_user_pk>.db` & `msys_database_<ig_user_pk>.db` / `crypto_db_<ig_user_pk>.db` (E2EE & Vanish-Mode Store):**
   * Stage and parse `reverb_*.db` and `msys_database_*.db` / `crypto_db_*.db` via Module 2.1:
     * In `reverb_*.db`: Extract historical synced messages (`messages` / `reverb_messages` tables where payloads are stored as JSON or Protobuf/FlatBuffer blobs) that were scrolled past or evicted from `direct.db`.
     * In `msys_database_*.db` / `crypto_db_*.db`: Query `cql_messages` / `messages` (`message_id`, `thread_key`, `sender_id`, `timestamp_ms`, `text`, `ephemeral_lifetime_ms` for **Vanish Mode** chats) and `participants` / `contacts`.

### 3.2 Target 2: Facebook Messenger (`com.facebook.orca` & `com.facebook.mlite` on Android / `com.facebook.Messenger` on iOS)

1. **Modern `MSYS` / `Lightspeed` Databases (`msys_database_<fb_uid>.db` & `crypto_db_<fb_uid>.db`):**
   * Stage all `msys_database_*.db` and `crypto_db_*.db` files (+ `-wal`) through **Module 2.1 (Active + `-wal` + Freelist)**.
   * Query the core `MSYS` tables:
     * **`contacts` / `participants`:** Maps `contact_id` (**Facebook Numeric UID**, e.g., `100004829104821`) to `name`, `username` (Facebook profile vanity URL slug), `normalized_name_for_search`, and `profile_picture_url`.
     * **`threads`:** Extracts `thread_key`, `thread_name`, `last_activity_timestamp_ms`, and `ongoing_call_state`.
     * **`messages` (`cql_messages`):** Extracts `message_id`, `thread_key`, `sender_id` (Facebook UID), `timestamp_ms` (13-digit Unix ms), `text`, `reply_source_id` & `reply_snippet` (surviving quoted text of unsent messages!), `is_unsent` (`1` = Unsent by sender; check `-wal` frames and `reply_snippet` for original text!), and `authority_level`.
     * **`attachments` (`cql_attachments`):** Extracts `attachment_type`, `filename`, `filesize`, `mime_type`, `playable_url`, and local cached media paths.
2. **Legacy Fallback (`threads_db2` & `prefs_db`):**
   * If the extraction is from an older build or `Messenger Lite` (`com.facebook.mlite`) containing `threads_db2`, automatically parse `threads`, `messages` (`msg_id`, `thread_key`, `text`, `sender` JSON, `timestamp_ms`, `attachments` JSON), and `thread_users`.

---

## 4. Step 2 — Sub-Engine 5.4B: `Snapchat` (`arroyo.db`, `main.db` & `memories.db`) & `Discord` (`MMKV` + `Simple Cache` Harvester)

### 4.1 Target 1: Snapchat (`com.snapchat.android` on Android / `com.toyopagroup.picaboo` on iOS)

Snapchat's modern storage architecture centers on `/databases/arroyo.db` (Android) / `Documents/arroyo.db` (iOS) for messaging, and `main.db` + `memories.db` for contacts, Memories, and location caches.

1. **Step 1 — User Identity & Contacts (`main.db` & `shared_prefs/user_session_shared_pref.xml`):**
   * From `user_session_shared_pref.xml` (or iOS plist): Extract the device owner's `user_id` (UUID), **`username` (Snapchat handle)**, `display_name`, `mobile_number`, `email`, and `birthday`.
   * From `main.db` (`Friend` & `Feed` tables, processed via Module 2.1 Active + `-wal` + Freelist):
     * Extract every Snapchat contact's `userId` (UUID), **`username`**, `displayName`, `phone`, `friendLinkType` (`0` = Mutual Friend, `1` = Outgoing Pending Request, `2` = Blocked, `4` = Following, `6` = Deleted/Removed Friend!), `addedTimestamp`, and `reverseAddedTimestamp`! *(Forensic Gold: Even when a suspect deletes a friend on Snapchat, the row often stays in `Friend` with `friendLinkType = 6` or inside `main.db-wal`/freelist!)*
2. **Step 2 — Decoding `arroyo.db` (`conversation_message` Binary Protobuf Payloads):**
   * Stage `arroyo.db` (+ `arroyo.db-wal`) via Module 1.1 and run **Module 2.1 (Active + `-wal` + Freelist)**.
   * Query `conversation_message` (and `user_conversation`):
     * `client_conversation_id`: Conversation UUID (joins to `user_conversation` to list participant `userId`s).
     * `server_message_id` / `message_id`: Message identifier.
     * `sender_id`: 16-byte binary UUID `BLOB` or 36-char ASCII UUID of the sender (convert 16-byte raw UUID to standard `8-4-4-4-12` hex string and join to `main.db` `Friend.userId` to resolve the sender's `@username`!).
     * `creation_timestamp` & `read_timestamp`: 13-digit Unix millisecond timestamps.
     * **`content_type` (`INTEGER`):**
       * `0`: **Snap (Ephemeral Photo/Video)**
       * `1`: **Chat Text Message**
       * `2`: **External Media (Camera Roll Image/Video sent in Chat)**
       * `3`: **Sticker**
       * `4`: **Shared Story**
       * `5`: **Voice Note / Audio Note**
       * `7`: **Shared Location**
     * **`message_content` (`BLOB` — Nested Google Protocol Buffer!):**
       * Pass `message_content` through **Phase 2, Module 2.3D (Schema-Less Protobuf Decoder)**!
       * Inside the decoded Protobuf tree (`Field 4` $\rightarrow$ nested `Contents` message):
         * For **`content_type == 1` (Chat Text):** `Field 1` inside the chat message sub-message contains the **exact UTF-8 plaintext chat string**!
         * For **Media / Snaps (`content_type` `0`, `2`, `5`):** Extracts the media `cache_key` / `media_id`, the **32-byte AES-256 key (`key`)**, and **16-byte IV (`iv`)** used to decrypt the cached media file sitting inside `/files/file_manager/` or `/cache/disk_cache/`!
3. **Step 3 — Snapchat `memories.db` & "My Eyes Only" (`MEO`) Vault:**
   * Open `memories.db` (`memories_entry`, `memories_snap`, `memories_media`):
     * Extract `snap_id`, `create_time` (Unix ms), **`latitude` & `longitude`** (GPS coordinates where the photo/video was captured!), **`speed` & `altitude`**, `time_zone`, `camera_front_facing`, and **`is_private` (`1` = Inside "My Eyes Only" PIN-protected vault!)**.
     * For unencrypted Memories (`is_private == 0`), link `media_id` to `/files/file_manager/memories_media/` (or decrypt using the plaintext `encrypted_media_key` + `encrypted_media_iv` stored right inside the `memories_snap` row!).

### 4.2 Target 2: Discord (`com.discord` on Android / `com.hammerandchisel.discord` on iOS)

Because Discord uses React Native + Chromium HTTP caching rather than a traditional SQLite message table, Sub-Engine 5.4B executes a **3-Layer Discord Extraction Pipeline**:

1. **Layer 1 — React Native `MMKV` / `RKStorage` & `Local Storage` (User Profile, Auth Token & Guilds):**
   * Query **Module 2.3A (`MMKV`)**, **Module 2.1 (`RKStorage`)**, and **Module 2.4 (`Local Storage/leveldb/`)** inside Discord's sandbox:
     * Extract the suspect's own **Discord `user_id` (18/19-digit Snowflake ID)**, `username`, `global_name`, `email`, `phone`, **linked relationships (Friends list)**, **Direct Message channel list (`PrivateChannelStore`)**, and **Server (`Guild`) list (`GuildStore`)**.
2. **Layer 2 — Chromium `Simple Cache (*_0)` & `NSURLCache` API JSON Harvester (The Message History Goldmine!):**
   * Query **Module 2.4's `webview_http_cache_records`** (and scan `/cache/http-cache/` or `/cache/Cache_Data/*_0` directly via Sub-Engine 2.4A) for all cached HTTP responses inside `com.discord`:
     * **Message History Endpoints (`request_url` matching `*/api/v*/channels/*/messages*`):**
       * The decompressed HTTP response body (`decompressed_body_text`) is a **JSON Array of up to 50–100 complete Discord Message Objects**!
       * For every message object in the JSON array, extract:
         * `id` (18/19-digit Discord Snowflake ID) & `channel_id`.
         * `author`: `id`, `username`, `global_name`, `discriminator`, `bot` flag.
         * `content`: **The exact UTF-8 Discord message text!**
         * `timestamp` & `edited_timestamp` (ISO-8601 UTC strings).
         * `attachments`: Array of shared files (`filename`, `size`, `url`, `proxy_url`, `content_type`).
         * `embeds` & `message_reference` (quoted reply link).
3. **Layer 3 — Discord Snowflake ID Exact Millisecond Timestamp Math:**
   * Every 18- or 19-digit Discord ID (`user_id`, `channel_id`, `guild_id`, `message_id`, `attachment_id`) is a **Twitter/Discord 64-bit Snowflake ID** that mathematically embeds the **exact millisecond the account, server, or message was created**, relative to the **Discord Epoch (`2015-01-01 00:00:00 UTC` = `1420070400000` Unix ms)**!
   * For any Discord Snowflake ID integer $S_{\text{id}}$, compute its exact creation timestamp using bit-shifting:
     $$\text{Unix Milliseconds} = (S_{\text{id}} \gg 22) + 1420070400000$$
   * **Forensic Value:** Even if you only find a suspect's 19-digit `user_id` or `guild_id` in a cache file with no timestamp column, $(S_{\text{id}} \gg 22) + 1420070400000$ proves the **exact millisecond that Discord account or server was created**!

---

## 5. Step 3 — Sub-Engine 5.4C: Cross-Border Handler VoIP & Asian Syndicate Messengers (`Botim`, `IMO`, `WeChat`, `LINE` & `Viber`)

### 5.1 Target 1: `Botim` (`com.atg.botim` / `im.thebot.messenger`) — The India–Dubai/UAE Handler Channel

* **Why `Botim` Is Crucial:** `Botim` is the #1 unlicensed-VoIP-permitted calling and messaging app in the UAE (Dubai/Abu Dhabi) and Gulf states. Indian hawala couriers, gold smugglers, and cyber-scam mule operators install `Botim` specifically to talk to their Dubai-based handlers.
* **Step-by-Step Sandbox Extraction (`/data/user/<id>/com.atg.botim/` on Android; `<App-UUID>/Documents/` on iOS):**
  1. **User Profile (`shared_prefs/*.xml` & `MMKV`):**
     * Extract the suspect's registered phone number (`uid` / `phone`), display name, and last active IP/country code.
  2. **SQLite Databases (`/databases/*.db` — e.g., `botim_*.db`, `chat*.db`, `contacts*.db` via Module 2.1 Active + `-wal` + Freelist):**
     * **Contacts / Friends Table:** Extract remote user phone numbers (specifically flagging **UAE `+971`**, **Saudi `+966`**, **Oman `+968`**, **Qatar `+974`**, **Bahrain `+973`**, **Kuwait `+965`**, **UK `+44`**, and **Cambodia `+855` / Laos `+856` / Myanmar `+95`** numbers!), display names, and avatars.
     * **Messages Table:** Extract `msg_id`, `session_id` / `chat_id`, `sender_id` (`from_uid`), `receiver_id` (`to_uid`), `msg_type` (text, image, voice, video, file, VoIP call event), `content` / `body`, `media_path` (in `/files/` or `/Android/media/com.atg.botim/`), and `timestamp`.
     * **VoIP Call Logs (+ iOS `CallHistory.storedata`):** Extract every incoming, outgoing, and missed Botim voice/video call (`peer_phone`, `call_timestamp`, `duration_seconds`).

### 5.2 Target 2: `IMO` (`com.imo.android.imoim` / `com.imo.android.imoimhd` / `imo.im`)

* **Step-by-Step Sandbox Extraction (`/data/user/<id>/com.imo.android.imoim/databases/`):**
  1. Stage `imo.db`, `imofriends.db`, `chat.db`, and `call_history.db` (or user-suffixed `.db` files) via Module 1.1 and process via **Module 2.1 (Active + `-wal` + Freelist)**.
  2. **Extract Core Tables:**
     * **`friends` / `contacts` Table (`imofriends.db`):** Extracts `buid` (IMO unique user ID), `phone_number`, `name`, `alias`, and `last_seen`.
     * **`messages` Table (`imo.db` / `chat.db`):** Extracts `msg_id`, `buid` (counterparty ID), `message_type`, `last_message` / `msg_body` (plain text or JSON payload containing media file references in `/cache/` or `/sdcard/imo/`), `direction` (`in`/`out`), and `timestamp` (13-digit Unix ms or 10-digit Unix seconds).
     * **`call_history` / `calls` Table:** Extracts VoIP audio/video call timestamps, durations, and counterparty `buid` + phone number.

### 5.3 Target 3: Tencent `WeChat` (`com.tencent.mm` on Android / `com.tencent.xin` on iOS)

Once **Phase 2, Module 2.2 (Recipe 4)** has computed the 7-character lowercase MD5 password ($\text{MD5}(\text{IMEI} \parallel \text{UIN})[0:7]$) and decrypted `/MicroMsg/<32_char_md5_dir>/EnMicroMsg.db` (+ `-wal`) into a `Product B2` plaintext SQLite database (and parsed iOS `WCDB_Contact.sqlite` & `message_*.sqlite`), Sub-Engine 5.4C extracts:

1. **Contacts & WeChat IDs (`rcontact` Table in `EnMicroMsg.db`):**
   * `username`: Internal WeChat identifier (`wxid_...` for standard users, `@chatroom` suffix for Group Chats, `gh_...` for Official Accounts).
   * **`alias`**: **The user's custom searchable WeChat ID handle** (if set by the user).
   * `nickname`: Display name chosen by the user.
   * `conRemark`: Local nickname assigned by the suspect.
   * `lvbuff` (`BLOB`): Binary buffer containing the contact's region/country, signature bio, and linked phone number.
2. **Messages (`message` Table in `EnMicroMsg.db`):**
   * `msgId` & `msgSvrId`: Local and server message IDs.
   * `talker`: Counterparty `wxid_...` or `<id>@chatroom` group ID.
   * `isSend`: `1` = Sent by device owner; `0` = Received (`2` = System).
   * `createTime`: 13-digit Unix millisecond timestamp.
   * `type`:
     * `1`: Plaintext Chat Message (`content`). *(Note: In a `@chatroom` group message where `isSend == 0`, the `content` string starts with `<sender_wxid>:\n<actual_message_text>`—split on the first `:\n` to extract the exact group sender's `wxid`!)*
     * `3`: Image (joins to `ImgInfo2` table to locate `/MicroMsg/<32_char_dir>/image2/` file!).
     * `34`: Voice Note (joins to `voiceinfo` table to locate `.amr` / `SILK v3` audio file in `/voice2/`!).
     * `43` / `62`: Video (`/video/`).
     * `47`: Sticker / Emoji.
     * `48`: Shared GPS Location (XML payload with `x` = latitude, `y` = longitude, `label` = address!).
     * `49`: Rich XML App Message (file transfers, web links, **WeChat Pay red packets & money transfers**!).
     * `50`: WeChat VoIP Audio/Video Call.
     * `10000`: System / **Recalled ("Unsent") Message Notice** (check `EnMicroMsg.db-wal` and freelist via Module 2.1 to recover the original text before recall!).

### 5.4 Target 4: `LINE` (`jp.naver.line.android` / `jp.naver.line`) & `Viber` (`com.viber.voip`)

1. **`LINE` (`/databases/naver_line` on Android; `Line.sqlite` on iOS — `iLEAPP v2026.4.6` aligned):**
   * Query `contacts` (`m_id`, `name`, `status_msg`), `chat_history` (`id`, `chat_id`, `from_mid`, `content`, `created_time`, `attachement_type`, `parameter` — which holds shared GPS coordinates and call duration metadata!), and `groups`.
2. **`Viber` (`/databases/viber_messages` & `viber_data` on Android; `Contacts.data` on iOS):**
   * Query `participants_info` (`number`, `display_name`, `contact_name`), `messages` (`_id`, `conversation_id`, `user_id`, `body`, `send_type`, `msg_date`, `extra_uri` for media), and `calls` (`number`, `date`, `duration`, `viber_call_type`).

---

## 6. Step 4 — Sub-Engine 5.4D: Virtual Burner Number / Secondary Line Apps (`TextNow`, `2ndLine`, `NextPlus`, `Hushed`, `Dingtone`, `PingMe`, `Virtual SIM`)

### 6.1 Master Target List of Virtual Burner Number Apps

Query **Module 1.3 (`resolve_app_targets`)** for any of the following virtual phone number / disposable SMS-verification applications:

| Burner App Name | Android Package Name(s) | iOS Bundle ID(s) | Typical Virtual Country Prefixes Issued |
|---|---|---|---|
| **TextNow** | `com.enflick.android.TextNow` | `com.tinginteractive.usms` | `+1` (USA & Canada) |
| **2ndLine (Second Phone Number)** | `com.enflick.android.tn2ndLine` | `com.enflick.2ndline` | `+1` (USA & Canada) |
| **NextPlus / textPlus** | `me.nextplus.smsfreetext.phonecalls`, `com.gogii.textplus` | `com.gogii.textplusfree` | `+1` (USA & Canada) |
| **Hushed (Anonymous 2nd Number)** | `com.hushed.app` | `com.affinityclick.hushed` | `+1` (US/CA), `+44` (UK), `+61` (AU) |
| **Dingtone / TalkU** | `me.dingtone.app.im`, `me.talkyou.app.im` | `me.dingtone.app.im` | `+1`, `+44`, `+32`, `+31`, `+46` |
| **PingMe / SMS Virtual / Numero eSIM / Vyke** | `com.pinger.textfree`, `io.pingme.app`, `com.numero.esim`, `com.vyke.mobile` | Corresponding iOS bundles | Global disposable OTP reception numbers (`+1`, `+44`, `+62`, `+84`, `+234`) |

### 6.2 Step-by-Step Extraction & The "Burner-to-Messenger" OTP Bridge
For every discovered Virtual Burner Number app:
1. **Extract the Assigned Virtual Phone Number(s) (`shared_prefs/*.xml`, `MMKV`, & SQLite `user` / `numbers` tables):**
   * Extract the exact virtual phone number(s) leased by the suspect (e.g., `"+14158901234"` or `"+447400123456"`), the account login email (`gmail` / temp-mail address used to register the burner app), the lease creation timestamp, and expiry status.
2. **Extract All Burner SMS Messages & VoIP Calls (`/databases/*.db` via Module 2.1 Active + `-wal` + Freelist):**
   * In `TextNow` / `2ndLine` (`textnow_data.db` $\rightarrow$ `messages` & `conversations` tables) and peer burner apps, extract every incoming and outgoing text message and VoIP call.
3. **Execute the Automated "Burner-to-WhatsApp/Telegram" Registration Bridge:**
   * Scan all incoming SMS messages and voicemail transcriptions inside the burner app for **6-digit or 5-digit registration OTPs**:
     * `"Your WhatsApp code: 123-456"` / `"Your WhatsApp Business code: 123-456"`
     * `"Telegram code: 54321"`
     * `"Signal verification code: 987654"`
   * Simultaneously cross-check the burner app's assigned virtual phone number (`+14158901234`) against:
     * **Module 5.1 (`whatsapp_identities_and_lid_map` / local owner JID)**
     * **Module 5.2 (`messaging_accounts_and_peers_directory` — `account0` .. `accountN` owner profiles)**
   * **Courtroom Impact:** When a match is found, populate `virtual_burner_numbers_and_otp_bridge` with `is_linked_to_local_messenger_account = 1`—mathematically proving that the anonymous `+1` or `+44` WhatsApp/Telegram account was **generated, OTP-verified, and operated by the suspect on this exact seized handset**!

---

## 7. Database Schema for Module 5.4 (`social_voip_and_burner_engine.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `social_and_voip_accounts_directory` (All Accounts & Contacts Across Instagram, Messenger, Snapchat, Discord, Botim, IMO, WeChat, LINE & Viber)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `social_peer_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique internal ID. |
| `platform_name` | `TEXT` | `NOT NULL` | Enum: `INSTAGRAM`, `FB_MESSENGER`, `SNAPCHAT`, `DISCORD`, `BOTIM`, `IMO`, `WECHAT`, `LINE`, `VIBER`. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning app in Module 1.3. |
| `account_role` | `TEXT` | `NOT NULL` | Enum: `LOCAL_LOGGED_IN_OWNER`, `REMOTE_CONTACT_OR_FRIEND`, `REMOVED_OR_BLOCKED_FRIEND`, `GROUP_OR_GUILD_CHANNEL`. |
| `native_platform_id` | `TEXT` | `NOT NULL` | Instagram `pk`, Facebook `UID`, Snapchat `UUID`, Discord 19-digit `Snowflake ID`, WeChat `wxid_...`, or IMO `buid`. |
| `username_or_handle` | `TEXT` | `NULL` | `@username`, WeChat `alias`, or Discord handle. |
| `display_full_name` | `TEXT` | `NULL` | Full name or group title. |
| `linked_phone_e164` | `TEXT` | `NULL` | Phone number (`+971...` UAE, `+91...` India, `+86...` China, `+1...` US), if present. |
| `linked_email` | `TEXT` | `NULL` | Linked email address (if local owner or contact). |
| `account_created_or_added_utc` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp (including Discord Snowflake bit-shifted creation date!). |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 2: `social_and_voip_messages_ledger` (Unified Messages & VoIP Calls Across All Module 5.4 Platforms)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `social_msg_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `platform_name` | `TEXT` | `NOT NULL` | `INSTAGRAM`, `FB_MESSENGER`, `SNAPCHAT`, `DISCORD`, `BOTIM`, `IMO`, `WECHAT`, `LINE`, `VIBER`. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to Module 1.3. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `.db`, `*_0` Simple Cache, or `CallHistory.storedata` in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, `RECONSTRUCTED_RECORD`, etc.). |
| `thread_or_channel_id` | `TEXT` | `NOT NULL` | Thread ID, `client_conversation_id` (Snapchat), or Discord `channel_id`. |
| `native_message_id` | `TEXT` | `NOT NULL` | Platform message ID or Snowflake ID. |
| `direction` | `TEXT` | `NOT NULL` | Enum: `OUTGOING_SENT`, `INCOMING_RECEIVED`, `VOIP_CALL_EVENT`, `SYSTEM_EVENT`. |
| `sender_id_and_handle` | `TEXT` | `NULL` | Resolved Sender ID + `@username` + phone number. |
| `receiver_or_thread_title` | `TEXT` | `NULL` | Recipient handle or group/channel name. |
| `content_category` | `TEXT` | `NOT NULL` | Enum: `TEXT`, `EPHEMERAL_SNAP_OR_RAVEN`, `IMAGE`, `VIDEO`, `VOICE_NOTE`, `DOCUMENT`, `SHARED_REEL_OR_STORY`, `LOCATION_GPS`, `VOIP_AUDIO_CALL`, `VOIP_VIDEO_CALL`, `UNSENT_OR_RECALLED`. |
| `message_text` | `TEXT` | `NULL` | Full decoded text (or recovered pre-unsent text from quoted reply / `-wal`). |
| `quoted_reply_text` | `TEXT` | `NULL` | Embedded `replied_to_message` text (survives when parent message was unsent!). |
| `call_duration_seconds` | `INTEGER` | `NULL` | Duration in seconds (if `VOIP_AUDIO_CALL` or `VOIP_VIDEO_CALL`). |
| `media_or_location_json` | `TEXT` | `NULL` | JSON with media path, decryption key/IV (Snapchat), URL (Discord), or GPS coordinates (`memories.db` / WeChat). |
| `sent_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `sent_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |

### Table 3: `virtual_burner_numbers_and_otp_bridge` (Burner Numbers `+1`/`+44` & Linked Local WhatsApp/Telegram Accounts)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `burner_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `burner_app_name` | `TEXT` | `NOT NULL` | E.g., `"TextNow"`, `"2ndLine"`, `"Hushed"`, `"NextPlus"`, `"Dingtone"`. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to burner app in Module 1.3. |
| `assigned_virtual_number` | `TEXT` | `NOT NULL` | Extracted virtual phone number (e.g., `"+14158901234"`, `"+447400123456"`). |
| `burner_login_email_or_user` | `TEXT` | `NULL` | Email or username used to register the burner app. |
| `intercepted_otp_service` | `TEXT` | `NULL` | E.g., `"WHATSAPP"`, `"TELEGRAM"`, `"SIGNAL"`, `"GOOGLE"`, if a registration OTP SMS/voicemail was received on this virtual number! |
| `intercepted_otp_code` | `TEXT` | `NULL` | Exact 5- or 6-digit verification code received inside the burner app. |
| `otp_received_utc_iso` | `TEXT` | `NULL` | Exact UTC ISO-8601 timestamp when the registration OTP arrived. |
| `is_linked_to_local_messenger` | `INTEGER` | `DEFAULT 0` | **`1` if `assigned_virtual_number` matches an active or historical WhatsApp/Telegram/Signal account on this same phone!** |
| `linked_messenger_details` | `TEXT` | `NULL` | E.g., `"Matches Telegram Slot account2 (+14158901234, @dark_vendor)"` or `"Matches Cloned WhatsApp User 95"`. |

---

## 8. Developer Acceptance Test Checklist for Module 5.4

1. **The Instagram 16-Digit Microsecond Timestamp & Unsent Quoted-Reply Test:** Insert a row into `direct_178414.db` (`messages` table) with `timestamp = 1762348800123456` (16-digit Unix microseconds) and a `message` JSON column containing `"replied_to_message":{"user_id":"998877","text":"Send the OTP to +971501234567"}` where parent message `998877` was unsent. Verify that Sub-Engine 5.4A converts the 16-digit microsecond timestamp to `2026-11-05T13:20:00.123456Z` and recovers `"Send the OTP to +971501234567"` in `quoted_reply_text`.
2. **The Snapchat `arroyo.db` Binary Protobuf Chat & UUID Join Test:** Feed a test `arroyo.db` `conversation_message` row (`content_type = 1`) where `sender_id` is a 16-byte binary UUID matching `Friend.userId` (`username = "dealer_snap"`) in `main.db`, and `message_content` is a nested Protobuf containing `"Meet near station"`. Verify that Sub-Engine 5.4B decodes the Protobuf via Module 2.3D and resolves the sender to `"@dealer_snap"`.
3. **The Discord `Simple Cache (*_0)` API JSON & Snowflake Math Test:** Place a Brotli-compressed `*_0` Simple Cache file in `/com.discord/cache/Cache_Data/` with URL `https://discord.com/api/v9/channels/1303377185623048192/messages?limit=50` containing a JSON message with Snowflake ID `"1303377185623048192"`. Verify that Sub-Engine 5.4B decompresses the JSON, extracts the message, and computes the Snowflake creation timestamp $(1303377185623048192 \gg 22) + 1420070400000 = 1730816400000\text{ ms}$.
4. **The Burner Number (`TextNow` `+1`) to Local Telegram Account Bridge Test:** Create a `TextNow` database with virtual number `"+14158901234"` and an incoming SMS `"Telegram code: 44912"`, alongside a Telegram `userconfig1.xml` registered to `"14158901234"`. Verify that Sub-Engine 5.4D sets `is_linked_to_local_messenger = 1` in `virtual_burner_numbers_and_otp_bridge`!