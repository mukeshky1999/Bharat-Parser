# Engineering Specification: Phase 5, Module 5.2 — The Telegram & Signal Deep Decoders (Telegram `cache4.db` TL-Schema Binary Deserializer, Multi-Account & Fork Discovery, Secret Chats, Mini-Apps & Signal `Signal.sqlite` / `signal.db` Disappearing & Edited Message Engine)

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 5.2** of the Forensic Data Parser (corresponding to **Group 1 and Group 5**, and cross-linked with **Groups 2, 3, 6, 8, 12, 13, and 15** of the Unified Master Register). It contains **zero programming code** and explains Telegram's proprietary **Type Language (`TL`) binary serialization format**, 64-bit Dialog/Message ID bit-packing math, multi-account folder structures, iOS `postbox` key-value tables, and Signal's SQLCipher schema (including message edit revisions, View-Once media, and Disappearing Message timers) from first principles so that any developer can build a commercial-grade Telegram and Signal forensic engine.

---

## 1. Purpose & Mental Model (Why Standard SQLite Viewers Fail on Telegram and Signal)

In modern cybercrime, organized mule recruitment, "Task / Investment" fraud, narcotics distribution, and darknet marketplace operations, **Telegram** and **Signal** are the two primary alternatives to WhatsApp. However, standard SQLite database viewers fail almost completely when pointed at Telegram or Signal databases for four architectural reasons:

1. **Telegram Does Not Store Message Text in a SQLite `TEXT` Column (`cache4.db` Uses Binary `TL` Blobs):**
   * If you open Android Telegram's `/data/user/0/org.telegram.messenger/files/cache4.db` in a standard SQLite browser and look at the `messages_v2` (or `messages`) table, **there is no `text` column, no `sender_id` column, and no `media_path` column!**
   * Instead, the `messages_v2` table has a raw binary column named **`data` (`BLOB`)**, and the `users` and `chats` tables also store all names, usernames (`@handle`), and phone numbers inside a binary **`data` (`BLOB`)** column!
   * Every one of those `BLOB` columns is serialized using Telegram's custom binary protocol called **MTProto Type Language (`TL-Schema`)**, where each object starts with a **32-bit Little-Endian Constructor Hash (`uint32_le`)** followed by packed bit-flags, length-prefixed UTF-8 strings, and nested `TLMedia` structures!
2. **Telegram Supports Up to 4 Concurrent Accounts in Separate Subfolders (`account1`, `account2`, `account3`):**
   * A single Telegram installation on Android or iOS allows a suspect to stay logged into **3 or 4 completely different phone numbers/accounts simultaneously** (for example, their personal phone number in the root `/files/cache4.db`, plus three anonymous virtual/+1/+44 burner accounts inside `/files/account1/cache4.db`, `/files/account2/cache4.db`, and `/files/account3/cache4.db`). Naive tools only parse `/files/cache4.db` and miss the suspect's three burner accounts!
3. **iOS Telegram Uses a Custom `postbox` Coding Database (`db_sqlite`), Not `cache4.db`:**
   * On iOS, Telegram does not use `cache4.db` at all. It stores data inside `/private/var/mobile/Containers/Shared/AppGroup/<Telegram-Group-UUID>/telegram-data/accounts-metadata/` and `/account-<AccountID>/postbox/db/db_sqlite`, which packs messages, peers, and media references into custom binary buffers (`t2`, `t7`, `t23` tables) with custom key encodings.
4. **Signal Encrypts Both Its Database (`SQLCipher v4`) and Its On-Disk Attachments (Android):**
   * Once **Phase 2, Module 2.2** unwraps `Signal.sqlite` (iOS) or `signal.db` (Android) into a plaintext `Product B2` SQLite database, the parser must still reconstruct Signal's **Disappearing Message (`expireTimer`) states**, **Message Edit History (`message_revision` / `TSInteraction`)**, **Group V2 (`gv2`) membership rosters**, and decrypt Android Signal's individually AES-encrypted attachment files (`.mms` / `part` files inside `/app_parts/`) using the per-attachment key stored in the `attachment` table!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Telegram & Signal Forensics

Before implementing Module 5.2, the developer must understand six critical traps:

### Mistake 1: Running Regex / ASCII String Scraping on Telegram's `messages_v2.data` BLOB Instead of True `TL` Deserialization
* **The Trap:** Because Telegram's `messages_v2.data` column is a binary `BLOB`, amateur developers simply scan the `BLOB` for printable ASCII characters to extract the message text.
* **Why It Fails:**
  1. Non-ASCII messages (Hindi/Devanagari, Arabic, Russian, Cyrillic, Chinese, or emojis) and short strings get corrupted or split when scraped without reading the exact `TL` string length prefix.
  2. You completely lose the **structured `TL` fields** hidden inside that `BLOB`: the **Author/Sender Peer ID (`from_id`)** in group chats, the **Forwarded-From Peer ID & Original Timestamp (`fwd_from`)**, the **Reply-To Message ID (`reply_to`)**, the **Edit Timestamp (`edit_date`)**, the **Attached File Name, MIME Type, File Size & Document ID (`media`)**, and **Inline Keyboard Buttons (`reply_markup` — which hold the URLs of Telegram scam/betting bots!)**.
* **The Rule:** Implement the deterministic **Telegram `TL-Schema` Binary Stream Reader & Constructor Disambiguator** specified in Section 4.

### Mistake 2: Misinterpreting Telegram's 64-Bit Packed `uid` (Dialog ID) & `mid` (Message ID) in `cache4.db`
* **The Trap:** Treating the `uid` column in `messages_v2` as a simple user ID, or failing to understand why some `uid` values are negative numbers (`-1001928374650`) while others are huge 64-bit integers.
* **Why It Fails:** In Telegram's `cache4.db`:
  * **Positive `uid` ($> 0$, lower 32 bits):** A 1-on-1 private chat with a **User** (`user_id = uid`), OR if the upper 32 bits of the 64-bit `uid` are non-zero (`(uid >> 32) != 0`), it is a **Device-Specific Secret Chat (`EncryptedChat`)** where the lower 32 bits or upper 32 bits encode the `enc_chats.uid`!
  * **Negative `uid` ($< 0$):** Represents a **Group Chat, Supergroup, or Broadcast Channel** (`channel_id = -uid` or `-1000000000000 - uid`)!
  * **Negative or Bit-Shifted `mid`:** In channels/supergroups and Secret Chats, `mid` combines the local message sequence ID with the channel/chat identifier.
* **The Rule:** Use the exact 64-bit `uid` and `mid` bit-unpacking formulas in Section 3.3.

### Mistake 3: Missing Telegram "Saved Messages" (Where `uid == Self_User_ID`)
* **The Trap:** Filtering out rows where `uid` equals the device owner's own Telegram User ID, assuming it is a "loopback status."
* **Why It Fails:** In Telegram, when a user messages their own `user_id` (`uid == self_user_id`), that conversation is Telegram's **"Saved Messages" (Personal Cloud Notebook)**! Cybercriminals, crypto launderers, and mule handlers routinely forward stolen bank account lists, `BIP-39` crypto seed phrases, passwords, and victim spreadsheets into their own **"Saved Messages"** thread!
* **The Rule:** Explicitly label the thread where `uid == self_user_id` as **`"TELEGRAM SAVED MESSAGES (SELF CLOUD VAULT)"`** and flag every message/attachment inside it as high-priority evidence!

### Mistake 4: Ignoring Third-Party & Modded Telegram Clients (`Nicegram`, `Nekogram`, `Plus Messenger`, `Telegram X`)
* **The Trap:** Looking only for `/data/user/0/org.telegram.messenger/`.
* **Why It Fails:** Suspects frequently use alternative Telegram clients (`Nicegram`, `Plus Messenger`, `Nekogram`, `Graph Messenger / Telegraph`, `Bgram`, `Forkgram`, `iMe Messenger`, or `Telegram X`) because those clients bypass Apple/Google blocks on illicit/NSFW/darknet channels, allow up to $10\text{–}50$ concurrent accounts instead of $3\text{–}4$, and include built-in crypto wallets or hidden PIN-locked chat folders!
* **The Rule:** Query **Module 1.3 (`resolve_app_targets`)** for all 20+ official and third-party Telegram package and bundle identifiers (Section 3.1).

### Mistake 5: Forgetting to Parse Telegram Push Notification Residue When Secret Chats or Cloud Chats Were Deleted
* **The Trap:** Seeing that a suspect clicked **"Delete Chat for Both Sides"** on Telegram (which wipes the conversation from `cache4.db` on both phones) and concluding the messages are unrecoverable.
* **Why It Fails:**
  1. When Telegram deletes rows from `messages_v2` in `cache4.db`, **SQLite `secure_delete` is NOT enabled by default in Telegram's native C++ SQLite wrapper**! That means deleted `messages_v2` rows frequently survive inside **`cache4.db-wal`** and **B-Tree `0x0D` Freeblocks / Freelist pages** (recovered by Phase 2, Module 2.1)!
  2. Furthermore, Telegram stores incoming push notification payloads inside `/shared_prefs/notifications.xml` (and `notify_prefs` / OS notification ledgers, as supported in `ALEAPP v2026.4.5`)!
* **The Rule:** Always run Module 2.1's WAL and Freelist carver on `cache4.db` and parse Telegram's local notification cache XMLs (Section 5.3).

### Mistake 6: Missing Signal's Message Edit History (`message_revision` / `EditRecord`) & View-Once Tombstones
* **The Trap:** Extracting only the latest rows from Signal's `message` (Android) or `model_TSInteraction` (iOS) table.
* **Why It Fails:** Modern Signal allows users to edit sent messages multiple times. Unlike apps that overwrite the original row in place, **Signal retains the complete chain of previous original message rows** linked via `latest_revision_id` / `original_message_id` (Android) and `InteractionEditRecord` (iOS)! If your parser filters out superseded revision rows, you hide the original unedited text that the suspect tried to cover up!

---

## 3. Step 1 — Sub-Engine 5.2A: Telegram Ecosystem Discovery, Multi-Account Mapping & `userconfing.xml`

### 3.1 Master Target List of Official & Third-Party Telegram Clients

Query **Module 1.3 (`resolve_app_targets`)** across all user profiles (`0`, `10`, `95`, `150`, `999`) for the following package and bundle identifiers:

| Client Category | Application Name | Android Package Name(s) | iOS Bundle / AppGroup Identifier | Forensic Nuances |
|---|---|---|---|---|
| **Official Clients** | **Telegram** & **Telegram Web-Download Build** | `org.telegram.messenger`, `org.telegram.messenger.web`, `org.telegram.messenger.beta` | `ph.telegra.Telegraph` (`group.ph.telegra.Telegraph`) | Note: `org.telegram.messenger.web` is the direct-APK version from `telegram.org` that bypasses Google Play Store channel censorship! |
| **Official Alternative** | **Telegram X** (TDLib Engine) | `org.thunderdog.challegram` | `org.telegram.TelegramHD` | Uses **TDLib `db.sqlite` (LevelDB-style key-value SQLite binlog)** instead of `cache4.db` (see Section 5.4). |
| **Bypass & Multi-Account Forks** | **Nicegram**, **Plus Messenger**, **Nekogram (NekoX)**, **Bgram**, **Graph / Telegraph**, **iMe**, **Forkgram**, **AyuGram** | `app.nicegram`, `org.telegram.plus`, `tw.nekomimi.nekogram`, `uz.unnarsx.cherrygram`, `org.telegram.BifToGram`, `ir.ilmili.telegraph`, `com.iMe.android`, `com.radolyn.ayugram` | `app.nicegram`, `com.iMe.app` | **High-Priority:** **`AyuGram` (`com.radolyn.ayugram`)** and **`Cherrygram`** are "ghost/anti-delete" Telegram forks that **intentionally save deleted messages and Secret Chat media** even after the sender deletes them! |

### 3.2 Enumerating All Logged-In Telegram Accounts (`Root` + `account1` .. `accountN`)

Inside every Android Telegram sandbox (`/data/user/<id>/<tg_pkg>/`), inspect both `/files/` and `/shared_prefs/`:
1. **Locate Every Account Slot:**
   * **Account Slot 0 (Default Primary Account):**
     * Database: `/files/cache4.db` (+ `cache4.db-wal`)
     * Network/Session State: `/files/tgnet.dat`
     * Account Config: `/shared_prefs/userconfing.xml` *(Note: Telegram's source code literally misspells this filename as **`userconfing.xml`** with an extra `'n'`! Also check `userconfig.xml`)*
   * **Account Slots $1, 2, 3 \dots N$ (Secondary Multi-Accounts):**
     * Databases: `/files/account1/cache4.db`, `/files/account2/cache4.db`, `/files/account3/cache4.db`, ... (up to `account50` in modded forks like Plus/Graph!).
     * Network/Session State: `/files/account1/tgnet.dat`, `/files/account2/tgnet.dat`, ...
     * Account Configs: `/shared_prefs/userconfig1.xml`, `/shared_prefs/userconfig2.xml`, `/shared_prefs/userconfig3.xml`, ...
2. **Parse `userconfing.xml` / `userconfig<N>.xml` for Each Account Slot:**
   * Read the `<int name="user_id" value="..."/>` or `<long name="clientUserId" value="..."/>` tag, OR read the Base64-encoded `<string name="user">...</string>` tag!
   * **Crucial:** The Base64 string inside `<string name="user">` is a **`TLUser` binary object** (Section 4.3) representing the **logged-in suspect's own Telegram profile**! Decoding that Base64 string immediately gives you the suspect's own **Telegram `user_id`**, **Registered Phone Number (e.g., `919876543210`)**, **`@username` handle**, **First Name**, and **Last Name** for that account slot!

### 3.3 Exact 64-Bit `uid` (Dialog ID) & `mid` (Message ID) Bit-Unpacking Math

In Android `cache4.db` (`messages_v2`, `dialogs`, `media_v2`), every conversation is identified by a 64-bit signed integer **`uid` (`int64`)**:

1. **Extract the Lower 32 Bits and Upper 32 Bits of `uid`:**
   $$\text{low\_32} = \text{uid} \ \& \ \text{0xFFFFFFFF}$$
   $$\text{high\_32} = (\text{uid} \gg 32) \ \& \ \text{0xFFFFFFFF}$$
2. **Determine Conversation Peer Type from `uid`:**
   * **Case 1 (`uid > 0` AND `high_32 == 0` — Standard Private 1-on-1 User Chat):**
     * Peer Type = `TELEGRAM_USER`.
     * Target `user_id` in `users` table $= \text{uid}$.
     * *(Check: If $\text{uid} == \text{self\_user\_id}$ from `userconfing.xml`, classify this conversation as **`"SAVED_MESSAGES_SELF_VAULT"`**!)*
   * **Case 2 (`high_32 != 0` AND `uid > 0` — Device-Specific End-to-End Encrypted Secret Chat!):**
     * Peer Type = `TELEGRAM_SECRET_CHAT`.
     * Target Secret Chat ID in `enc_chats` table $= \text{high\_32}$ (or $\text{low\_32}$ depending on schema version; check both against `enc_chats.uid`!).
   * **Case 3 (`uid < 0` — Group Chat, Supergroup, or Broadcast Channel):**
     * Peer Type = `TELEGRAM_GROUP_OR_CHANNEL`.
     * Target Chat/Channel ID in `chats` table $= -\text{uid}$ (or if $-\text{uid} > 10^{12}$, strip the `-100` prefix: $\text{chat\_id} = |\text{uid}| - 1000000000000$).
3. **Unpacking the 64-Bit `mid` (Message ID) in Channels & Supergroups:**
   * In Supergroups and Channels, Telegram packs the 32-bit `channel_id` into the upper 32 bits (or negative offset) of `mid` so `mid` is globally unique in SQLite. To get the true human-visible sequential message number (`telegram_msg_seq_no` used in `https://t.me/c/<channel_id>/<msg_seq_no>` links):
     $$\text{msg\_seq\_no} = \text{mid} \ \& \ \text{0xFFFFFFFF} \quad (\text{as 32-bit positive integer})$$

---

## 4. Step 2 — Sub-Engine 5.2B: The Telegram `TL-Schema` Binary Stream Deserializer

To decode the `data` (`BLOB`) column inside `users`, `chats`, `enc_chats`, `messages_v2`, and `media_v2`, the developer must implement Telegram's **MTProto Type Language (`TL`) Binary Stream Reader**.

### 4.1 The 4 Fundamental `TL` Binary Primitives (All Little-Endian!)

Every `TL` binary blob in `cache4.db` or `tgnet.dat` is built from just four primitive data types aligned on **4-byte boundaries**:

1. **`read_int32()` (`int32_le` / `uint32_le`):** Read $4\text{ bytes}$ in Little-Endian order. Advance cursor by $4$.
2. **`read_int64()` (`int64_le`):** Read $8\text{ bytes}$ in Little-Endian order. Advance cursor by $8$.
3. **`read_double()` (`float64_le`):** Read $8\text{ bytes}$ IEEE-754 Little-Endian double. Advance cursor by $8$.
4. **`read_tl_string()` / `read_tl_bytes()` (4-Byte Aligned Length-Prefixed String/Byte Array):**
   * Read 1 unsigned byte at the current cursor: `first_byte = buf[pos]`.
   * **Case A (Short String: `first_byte < 254` \[`0x00` to `0xFD`\]):**
     * The string byte length is $L = \text{first\_byte}$.
     * The UTF-8 string bytes sit at `buf[pos + 1 : pos + 1 + L]`.
     * Total unpadded bytes consumed $= 1 + L$.
     * **Mandatory 4-Byte Alignment Padding:** Advance cursor by $1 + L$ **rounded up to the next multiple of $4$**:
       $$\text{bytes\_to\_advance} = \left\lceil \frac{1 + L}{4} \right\rceil \times 4$$
   * **Case B (Long String: `first_byte == 254` \[`0xFE`\]):**
     * The next **3 bytes** (`buf[pos + 1 : pos + 4]`) form a 24-bit Little-Endian unsigned integer giving the string byte length:
       $$L = \text{buf}[\text{pos}+1] \mid (\text{buf}[\text{pos}+2] \ll 8) \mid (\text{buf}[\text{pos}+3] \ll 16)$$
     * The UTF-8 string bytes sit at `buf[pos + 4 : pos + 4 + L]`.
     * Total unpadded bytes consumed $= 4 + L$.
     * **Mandatory 4-Byte Alignment Padding:** Advance cursor by $4 + L$ **rounded up to the next multiple of $4$**:
       $$\text{bytes\_to\_advance} = \left\lceil \frac{4 + L}{4} \right\rceil \times 4$$
   * *(Note: If `first_byte == 255` \[`0xFF`\], it indicates a `NULL` or invalid string boundary).*

### 4.2 How `TL` Bitmask `flags` Work (The Secret to Versioning Resilience)

In every `TL` object (`TL_user`, `TL_chat`, `TL_channel`, `TL_message`), immediately after the 4-byte `constructor_id` sits a 32-bit integer **`flags = read_int32()`** (and in newer Layer 145–195+ schemas, a second **`flags2 = read_int32()`** if a specific bit is set).
* **How `flags` Controls Which Fields Exist in the Stream:**
  * Optional fields are **only written into the binary stream if their corresponding bit `(flags & (1 << bit_index)) != 0` is set**!
  * And those optional fields are **always written in strict ascending order of their bit index (`Bit 0`, then `Bit 1`, then `Bit 2`, ...)** interspersed with the fixed mandatory fields!

### 4.3 Decoding `users.data` (`TL_user`) & `chats.data` (`TL_chat` / `TL_channel`)

1. **In the `users` Table (`SELECT uid, name, status, data FROM users;`):**
   * First, split the `name` column on the separator string **`";;;"`**: Telegram stores `"first_name;;;last_name;;;username"` directly in the plaintext `name` column as a fast search index!
   * Next, parse the `data` (`BLOB`) column using `TL_user` deserialization to extract the **suspect's or contact's Phone Number (which is NOT in the `name` column—it is ONLY inside the `data` BLOB!)**:
     * Read `constructor_id = read_int32()`.
     * Read `flags = read_int32()` (and `flags2 = read_int32()` in modern layers where `constructor_id` is a Layer 140–195+ `TL_user` constructor such as `0x215c4438`, `0x8f97c628`, `0xeb602f25`, `0x4b46c37e`, etc.).
     * Read `user_id = read_int64()` (or `read_int32()` in legacy pre-64-bit layers).
     * If `(flags & (1 << 0)) != 0`: Read `access_hash = read_int64()`.
     * If `(flags & (1 << 1)) != 0`: **`first_name = read_tl_string()`**.
     * If `(flags & (1 << 2)) != 0`: **`last_name = read_tl_string()`**.
     * If `(flags & (1 << 3)) != 0`: **`username = read_tl_string()`** (the `@handle`!).
     * If `(flags & (1 << 4)) != 0`: **`phone = read_tl_string()`** (**The exact MSISDN phone number, e.g., `"919876543210"`!**).
     * Check boolean flag bits in `flags`:
       * `Bit 10` (`1 << 10`): `is_self` (This row is the logged-in device owner!).
       * `Bit 11` (`1 << 11`): `is_contact` (In the suspect's contacts).
       * `Bit 12` (`1 << 12`): `is_mutual_contact`.
       * `Bit 13` (`1 << 13`): `is_deleted` (`"Deleted Account"`).
       * `Bit 14` (`1 << 14`): **`is_bot`** (This account is an automated Telegram Bot!).
       * `Bit 24` (`1 << 24`): `is_scam` (Flagged as a scam account by Telegram!).
       * `Bit 26` (`1 << 26`): `is_fake`.
       * `Bit 28` (`1 << 28`): `is_premium` (Telegram Premium subscriber).
2. **In the `chats` Table (`SELECT uid, name, data FROM chats;`):**
   * `name` holds the plaintext Group or Channel title!
   * Inside the `data` `BLOB` (`TL_chat` or `TL_channel`), extract the group/channel `id`, `title`, public **`@username`** (if `flags & (1 << 6)` is set—e.g., `@hawala_rates_india`), `participants_count`, `date` (creation timestamp), and whether the logged-in suspect has **`creator` (`flags & (1 << 0)`)** or **`admin_rights` (`flags & (1 << 14)`)** in that group or channel! *(Proving that the seized phone's owner is the **`Creator`** or **`Admin`** of an illicit Telegram channel or scam group is a decisive courtroom finding!)*

### 4.4 Decoding `messages_v2.data` (`TL_message` & `TL_messageService`)

In `messages_v2` (`SELECT mid, uid, read_state, send_state, date, data, out, ttl, media, replydata, imp, mention FROM messages_v2;`):
* The SQLite columns give you:
  * `mid`: Message ID.
  * `uid`: Dialog ID (unpacked via Section 3.3).
  * `date`: 32-bit Unix seconds timestamp.
  * `out`: `1` = Sent by the device owner; `0` = Received.
  * `read_state`: Read/unread status.
  * `ttl`: Self-destruct / Auto-Delete timer in seconds (`> 0` indicates an ephemeral disappearing message!).
* **Inside the `data` (`BLOB`) Column (`TL_message`):**
  1. Read `constructor_id = read_int32()` and `flags = read_int32()` (plus `flags2` if applicable for the constructor version).
  2. Read `msg_id = read_int32()`.
  3. **If `(flags & (1 << 8)) != 0` (`has_from_id`):** Read the nested `TL_Peer` (`peerUser`, `peerChat`, `peerChannel`) to extract the **exact `sender_user_id` of the person who posted this message inside a Group Chat**!
  4. Read the destination `peer_id` (`TL_Peer`).
  5. **If `(flags & (1 << 2)) != 0` (`has_fwd_from`):** Read the nested `TL_messageFwdHeader` to extract:
     * `from_id` (Original author User/Channel ID of the forwarded message!).
     * `from_name` (Original author name if privacy-hidden).
     * `fwd_date` (Original Unix timestamp when the message was first authored!).
  6. **If `(flags & (1 << 11)) != 0` (`has_via_bot_id`):** Read `via_bot_id = read_int64()` (identifies inline bots used in the chat).
  7. **If `(flags & (1 << 3)) != 0` (`has_reply_to`):** Read `reply_to_msg_id` (and also decode the `replydata` BLOB column if populated).
  8. Read `msg_date = read_int32()`.
  9. **Read **`message_text = read_tl_string()`**:** **This is the exact UTF-8 text of the Telegram message!**
  10. **If `(flags & (1 << 9)) != 0` (`has_media`):** Read the nested **`TL_MessageMedia`** object:
      * **`TL_messageMediaPhoto`:** Extracts `photo_id`, timestamps, and cached sizes/file references in `/cache/` or `/Android/data/org.telegram.messenger/files/Telegram/Telegram Images/`.
      * **`TL_messageMediaDocument` (Videos, Voice Notes, PDFs, APKs, ZIPs):** Extracts `doc_id`, `mime_type` (e.g., `"application/vnd.android.package-archive"` for malicious `.apk` files!), `file_size`, and from the `attributes` vector (`TL_documentAttributeFilename`), the **exact original `file_name`** (e.g., `"RTO_Challan.apk"` or `"Mule_Accounts.xlsx"`)!
      * **`TL_messageMediaGeo` / `TL_messageMediaGeoLive` / `TL_messageMediaVenue`:** Extracts exact shared **GPS `latitude`, `longitude`, venue `title`, and `address`** (cross-link to Group 7)!
      * **`TL_messageMediaContact`:** Extracts shared contact `phone_number`, `first_name`, `last_name`, and `vcard`!
      * **`TL_messageMediaPoll`:** Extracts poll question and options.
  11. **If `(flags & (1 << 6)) != 0` (`has_reply_markup`):** Read the **`TL_ReplyInlineMarkup` / `TL_keyboardButtonUrl` / `TL_keyboardButtonWebView`** rows to extract **every button label and hidden URL / Mini-App URL** attached to bot messages!
  12. **If `(flags & (1 << 15)) != 0` (`has_edit_date`):** Read `edit_date = read_int32()` (proves the message was edited after sending, and triggers a check against `cache4.db-wal` from Module 2.1 to recover the pre-edit text!).
  13. **Fallback Resilient `TL` String Scanner:** Because Telegram updates its MTProto layer number every few weeks (adding new constructor hashes), if `constructor_id` is from a brand-new unseen post-2026 layer where the exact field offset table is unknown, Sub-Engine 5.2B automatically falls back to a **4-Byte Aligned `TL` String & Peer Scanner** that walks 4-byte boundaries looking for valid `read_tl_string()` UTF-8 text blocks and known file/URL attributes so zero messages are ever lost!

---

## 5. Step 3 — Sub-Engine 5.2C: Telegram Secret Chats (`enc_chats`), Mini-Apps (`WebApp`), iOS `postbox` & Notification Residue

### 5.1 Telegram Secret Chats (`enc_chats` Table in `cache4.db`)
Unlike normal Telegram cloud chats, **Secret Chats** are device-specific, end-to-end encrypted conversations stored in the **`enc_chats`** table of `cache4.db`:
* Query `SELECT uid, user, name, data, g, authkey, ttl, layer, seq_in, seq_out FROM enc_chats;` (across active, `-wal`, and freelist records via Module 2.1):
  * `uid`: Secret Chat ID (links to `messages_v2` where `high_32 == uid` or `low_32 == uid`).
  * `user`: The counterparty's **`user_id`** in the `users` table! (Even if every message inside the Secret Chat self-destructed via `ttl`, the `enc_chats` row proves **that the suspect established an end-to-end encrypted Secret Chat with `user`, their `ttl` self-destruct timer setting, and how many messages were sent (`seq_out`) and received (`seq_in`)!**)
  * Any surviving un-expired or `-wal`/freelist-carved Secret Chat messages in `messages_v2` are already stored in plaintext inside the local `cache4.db` (because `cache4.db` sits behind the OS sandbox after MTProto decryption!).

### 5.2 Telegram Mini-Apps (`TMA` / `WebApps`), Crypto Bots & Toncoin (`TON`) Space Wallet
In 2024–2026, Telegram Mini-Apps (web applications launched inside Telegram bots, such as crypto exchanges, P2P markets, and betting portals) and the built-in **Telegram Wallet / TON Space (`@wallet`)** became major channels for illicit finance:
1. Query **Phase 2, Module 2.4 (`webview_http_cache_records` & `webview_autofill_and_storage`)** for all embedded `app_webview` / `WKWebView` records belonging to Telegram (`org.telegram.messenger`, `ph.telegra.Telegraph`, etc.).
2. Extract cached `Local Storage`, `IndexedDB`, and HTTP cache entries for Telegram Mini-Apps and **TON Space** (`ton_connect`, `wallet_address`, `EQ...` / `UQ...` TON blockchain addresses!).

### 5.3 Telegram Push Notification & Download Folder Residue
1. **Parse `/shared_prefs/notifications.xml` & `notify_prefs*.xml` (Android):**
   * Aligned with `ALEAPP v2026.4.5`, Telegram caches recent incoming push messages and sender metadata inside its notification preference files—recovering messages that arrived while the app was backgrounded or before a chat was remotely wiped!
2. **Scan External/Scoped Media Folders for Orphaned Telegram Files:**
   * Check `/data/media/<id>/Telegram/` and `/data/media/<id>/Android/data/org.telegram.messenger/files/Telegram/` (`Telegram Images`, `Telegram Video`, `Telegram Audio`, `Telegram Documents`) and `/Download/Telegram/`.
   * Any image, voice note (`.ogg`), video, or document (`.apk`, `.pdf`, `.xlsx`) sitting on disk whose referring message in `messages_v2` was deleted is flagged as **`RESIDUAL_RECORD (Orphaned Telegram Media File Survived Chat Deletion)`**!

### 5.4 iOS Telegram (`postbox/db/db_sqlite`) & Android Telegram X (`TDLib db.sqlite`)
1. **iOS Telegram (`/private/var/mobile/Containers/Shared/AppGroup/<UUID>/telegram-data/`):**
   * Read `accounts-metadata/db/db_sqlite` to enumerate all logged-in `account-<AccountID>` directories.
   * Inside each `/account-<AccountID>/postbox/db/db_sqlite` (processed via Module 2.1 for active, `-wal`, and freelist records):
     * **`t2` (Peer Table):** Maps 64-bit `key` (`PeerId`) to binary `value` (containing User First/Last Name, `@username`, Phone Number, or Channel/Group Title).
     * **`t7` (Message Index / History Table):** Maps composite binary `key` (`PeerId` + `Namespace` + `Timestamp` + `MessageId`) to the binary `value` buffer containing the message text, sender `PeerId`, forward header, reply ID, and media attachment references (pointing to `/postbox/media/`).
2. **Android Telegram X (`org.thunderdog.challegram` — `TDLib`):**
   * Opens `/files/tdlib/db.sqlite` (where TDLib stores `binlog` and key-value snapshots) and extracts users, chats, and messages.

---

## 6. Step 4 — Sub-Engine 5.2D: The Signal Messenger Deep Decoder (`Signal.sqlite` & `signal.db`)

Once **Phase 2, Module 2.2** has decrypted Signal's SQLCipher v4 database (`Signal.sqlite` on iOS using the 48-byte / 96-hex-char Keychain blob `OWSPrimaryStorage` / `GRDBDatabaseCipherKeySpec`; or `signal.db` on Android using the unwrapped `SignalSecret` key) into a `Product B2` plaintext SQLite file—and **Module 2.1** has extracted all active, `-wal`, and freelist rows—Sub-Engine 5.2D decodes the complete Signal schema.

### 6.1 Signal iOS (`grdb/Signal.sqlite`) Schema & Edit/Disappearing Reconstruction

1. **Recipients & Identity Mapping (`model_SignalRecipient`, `SignalAccount`, `OWSUserProfile`):**
   * Join recipient records to extract:
     * `recipientPhoneNumber` (`e164`, e.g., `"+919876543210"`).
     * `recipientUUID` (**Signal Service UUID / `ACI` — Account Identity UUID**, e.g., `"a1b2c3d4-..."`). *(Crucial: Since Signal introduced **Phone Number Privacy & Usernames** in 2024–2026, two criminals can chat on Signal using only their `@username.01` and **Signal `ACI` UUID** with `recipientPhoneNumber = NULL`! Always extract both `recipientPhoneNumber`, `recipientUUID`/`ACI`, `PNI` \[Phone Number Identity UUID\], and `username`!)*
     * `givenName`, `familyName`, `bio`, and `avatarFileName` from `OWSUserProfile`.
2. **Threads (`model_TSThread`):**
   * Distinguish `TSContactThread` (1-on-1 chat) from `TSGroupThread` (Group V1/V2 chat, extracting `groupModel` plist/protobuf for group title, description, and member UUIDs).
3. **Messages, Calls & Disappearing Timers (`model_TSInteraction`):**
   * Extract every row from `model_TSInteraction` (active + `-wal` + freelist):
     * `uniqueId`, `threadUniqueId`, `body` (message text), `timestamp` (13-digit Unix ms), `receivedAtTimestamp`.
     * **Direction & Call Classification (`recordType`):**
       * `TSIncomingMessage` vs. `TSOutgoingMessage` vs. `TSErrorMessage` vs. `TSInfoMessage` (group membership/timer changes) vs. `TSCall` / `RPRecentCall` (voice/video calls: extract call direction, duration, and answered/missed status!).
     * **Disappearing Messages Audit (`expiresInSeconds` & `expireStartedAt`):**
       * If `expiresInSeconds > 0`, the message was sent under a Disappearing Message timer! Record `expiresInSeconds` and calculate when the message was scheduled to self-destruct (`expireStartedAt + expiresInSeconds * 1000`). Any disappearing message recovered from `Signal.sqlite-wal` or B-Tree Freelist pages after expiration is flagged as **`RECOVERED_EXPIRED_DISAPPEARING_SIGNAL_MESSAGE`**!
     * **View-Once Media Audit (`isViewOnceMessage` & `isViewOnceComplete`):**
       * Proves a View-Once photo or video was sent/received and whether it was opened (`isViewOnceComplete == 1`).
4. **Message Edit History (`InteractionEditRecord` / Past Revisions):**
   * Join `InteractionEditRecord` (`latestRevisionId` $\leftrightarrow$ `pastRevisionId`) back to `model_TSInteraction` so that every earlier pre-edit version of an edited Signal message is displayed chronologically alongside the final edited text!
5. **Attachments (`model_TSAttachment` / `attachment`):**
   * On iOS, once the device is in AFU and the file protection class is unlocked, Signal attachments sit in `/Shared/AppGroup/<UUID>/app_data/Attachments/` as standard media files—join via `uniqueId` / `localRelativeFilePath`.

### 6.2 Signal Android (`databases/signal.db`) Schema, Edit History & Attachment Decryption

1. **Recipients (`recipient` Table):**
   * Extract `_id`, `e164` (phone number), `aci` (Account Identity UUID), `pni` (Phone Number Identity UUID), `username`, `system_joined_name` (local phonebook name), `profile_joined_name` (Signal profile name), and `group_id` (for groups).
2. **Threads & Group V2 Rosters (`thread` & `groups` Tables):**
   * Join `thread.recipient_id = recipient._id` and `groups.recipient_id = recipient._id`.
   * In `groups`, extract `title`, `members` (list of member `recipient_id`s / UUIDs), and decode the `gv2_decrypted_group` Protobuf `BLOB` (via Module 2.3D) to extract **every Group V2 member's role (`ADMINISTRATOR` vs. `NORMAL`), pending invites, and banned/removed members**!
3. **Messages, Edit Revisions & Disappearing Timers (`message` / `mms` Table):**
   * Extract `_id`, `thread_id`, `from_recipient_id` (`address`), `to_recipient_id`, `date_sent` (13-digit Unix ms), `date_received`, `body` (plaintext message!), `expires_in` (Disappearing timer in ms), `expire_started`, `view_once` (`1` = View-Once media), and `scheduled_date` (Scheduled messages!).
   * **Reconstructing Signal Android Edit History (`latest_revision_id` & `revision_number`):**
     * When a user edits a message on Signal Android, Signal inserts a *new* row into `message` for the new text and sets **`original_message_id` / `latest_revision_id`** on the old row to point to the new row!
     * Standard queries filter out rows where `latest_revision_id IS NOT NULL`. **Sub-Engine 5.2D must explicitly extract all rows where `latest_revision_id IS NOT NULL` or `revision_number > 0`** and link them as the **Pre-Edit Original Message History**!
4. **Decrypting Signal Android On-Disk Attachments (`part` / `attachment` Table + `/app_parts/`):**
   * Unlike iOS, Signal Android encrypts every attachment file (`.mms`) inside `/data/user/<id>/org.thoughtcrime.securesms/app_parts/` using **ModernAttachmentCipher (`AES-256-CTR` + `HMAC-SHA256`)**!
   * **How to Decrypt Every Signal Android Attachment:**
     1. Read the master `ModernKey` (`attachment_secret` JSON in `org.thoughtcrime.securesms_preferences.xml`, unwrapped alongside `SignalSecret` in Module 2.2).
     2. For each row in the `part` / `attachment` table, read `data_file` (path inside `/app_parts/part*.mms`), `data_size`, `content_type` (`image/jpeg`, `audio/aac`, `video/mp4`, `application/pdf`), `file_name`, and **`data_random` (`BLOB`, $32\text{ bytes}$)**.
     3. Derive the per-attachment $64\text{-byte}$ key (`32-byte AES key` + `32-byte HMAC key`) by computing **HMAC-SHA256 / HKDF** over `data_random` using the unwrapped `attachment_secret` key, and decrypt `/app_parts/part*.mms` via **AES-256-CTR** (initializing the 16-byte CTR counter to all zeroes) into the staging workspace!

---

## 7. Database Schema for Module 5.2 (`telegram_and_signal_engine.sqlite`)

The developer must create the following four tables in the case database:

### Table 1: `messaging_accounts_and_peers_directory` (All Telegram & Signal Accounts, Users, Bots, Groups & Channels)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `peer_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique internal ID. |
| `platform_family` | `TEXT` | `NOT NULL` | Enum: `TELEGRAM`, `TELEGRAM_X`, `TELEGRAM_FORK_AYUGRAM_NICEGRAM`, `SIGNAL`. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning app in Module 1.3. |
| `account_slot_name` | `TEXT` | `NOT NULL` | E.g., `"account0_primary"`, `"account1"`, `"account2"`, `"signal_primary"`. |
| `peer_type` | `TEXT` | `NOT NULL` | Enum: `SELF_OWNER_ACCOUNT`, `USER_CONTACT`, `TELEGRAM_BOT`, `GROUP_CHAT`, `SUPERGROUP_OR_CHANNEL`, `SECRET_CHAT_PARTNER`. |
| `native_peer_id` | `TEXT` | `NOT NULL` | Telegram `user_id`/`chat_id` or Signal `recipient._id` / `ACI UUID`. |
| `secondary_uuid_or_pni` | `TEXT` | `NULL` | Signal `PNI` UUID or Telegram `access_hash`. |
| `username_handle` | `TEXT` | `NULL` | `@username` (e.g., `"@crypto_king_99"` or Signal `"@vikram.01"`). |
| `phone_number_e164` | `TEXT` | `NULL` | Extracted phone number (`+919876543210`) from `TL_user.phone` or Signal `e164` (`NULL` if hidden by privacy settings). |
| `display_or_group_name` | `TEXT` | `NULL` | First + Last Name, Signal Profile Name, or Group/Channel Title. |
| `local_role_in_group` | `TEXT` | `NULL` | Enum: `CHANNEL_CREATOR_OWNER`, `GROUP_ADMIN`, `MEMBER`, `BANNED`, `NOT_APPLICABLE`. |
| `is_scam_or_fake_flagged` | `INTEGER` | `DEFAULT 0` | `1` if Telegram `TL_user` / `TL_channel` has `is_scam` or `is_fake` bit set. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 2: `telegram_and_signal_messages_ledger` (Unified Messages, Edits, Disappearing & Secret Chats)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `msg_master_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning app in Module 1.3. |
| `account_slot_name` | `TEXT` | `NOT NULL` | E.g., `"account0_primary"`, `"account2"`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `cache4.db`, `db_sqlite`, `Signal.sqlite`, `signal.db`, or `notifications.xml` in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, etc.). |
| `thread_or_dialog_id` | `TEXT` | `NOT NULL` | Unpacked Dialog ID / Thread ID. |
| `thread_classification` | `TEXT` | `NOT NULL` | Enum: `SAVED_MESSAGES_SELF_VAULT`, `DIRECT_1ON1_CHAT`, `SECRET_E2EE_CHAT`, `GROUP_OR_SUPERGROUP`, `BROADCAST_CHANNEL`, `BOT_INTERACTION`. |
| `native_message_id` | `TEXT` | `NOT NULL` | Unpacked `mid` sequence number or Signal message ID. |
| `direction` | `TEXT` | `NOT NULL` | Enum: `OUTGOING_SENT`, `INCOMING_RECEIVED`, `SYSTEM_SERVICE_EVENT`. |
| `sender_peer_id` | `TEXT` | `NULL` | Resolved sender `user_id` or Signal `ACI` / phone number. |
| `sender_display_and_handle` | `TEXT` | `NULL` | Joined Sender Name + `@username` + `+91` phone number. |
| `message_text` | `TEXT` | `NULL` | Full decoded UTF-8 text (from `TL_message`, `postbox`, or Signal `body`). |
| `is_edited_or_past_revision` | `INTEGER` | `DEFAULT 0` | `1` if `edit_date` is set or row is from Signal `InteractionEditRecord` / `latest_revision_id` / `-wal` historical frame. |
| `pre_edit_or_diff_json` | `TEXT` | `NULL` | JSON array of all earlier text revisions and `edit_date` timestamps for this message! |
| `forwarded_from_info_json` | `TEXT` | `NULL` | JSON containing `fwd_from_id`, `fwd_from_name`, and original `fwd_date` (if forwarded). |
| `reply_to_msg_id` | `TEXT` | `NULL` | ID of the parent message being replied to. |
| `ttl_disappearing_seconds` | `INTEGER` | `DEFAULT 0` | Self-destruct / Disappearing timer in seconds (`> 0` = Ephemeral message). |
| `is_view_once_media` | `INTEGER` | `DEFAULT 0` | `1` if View-Once photo/video. |
| `media_attachment_json` | `TEXT` | `NULL` | JSON detailing `file_name`, `mime_type`, `file_size`, `local_staged_path`, `sha256`, or shared GPS coordinates. |
| `inline_bot_buttons_json` | `TEXT` | `NULL` | Extracted `TL_ReplyInlineMarkup` button labels and hidden URLs / Mini-App URLs! |
| `sent_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `sent_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |

---

## 8. Developer Acceptance Test Checklist for Module 5.2

1. **The Telegram `TL-Schema` 4-Byte Aligned String & `users.data` Phone Unpacker Test:** Construct or load a `cache4.db` `users` row where `name = "Vikram;;;Singh;;;vikram_hawala"` and `data` is a binary `TL_user` blob containing the phone string `"919876543210"` (12 bytes $\rightarrow$ 1 length byte + 12 string bytes = 13 bytes, padded to 16 bytes on a 4-byte boundary). Verify that Sub-Engine 5.2B advances by exactly $16\text{ bytes}$ and extracts `phone_number_e164 = "+919876543210"` and `username_handle = "@vikram_hawala"`.
2. **The Multi-Account (`account1` / `account2`) & "Saved Messages" Vault Test:** Place a second Telegram database at `/data/user/0/org.telegram.messenger/files/account1/cache4.db` and `/shared_prefs/userconfig1.xml` (`self_user_id = 5566778899`), containing a message where `uid = 5566778899`. Verify that Sub-Engine 5.2A discovers `account1`, extracts the owner's profile from `userconfig1.xml`, and labels the thread `uid == 5566778899` as `"SAVED_MESSAGES_SELF_VAULT"`.
3. **The Signal Message Edit Revision & Disappearing Message Recovery Test:** In a decrypted `signal.db`, insert an original message row (`_id = 10`, `body = "Send 5 BTC to bc1q..."`, `latest_revision_id = 11`) and an edited revision row (`_id = 11`, `body = "Send 5 documents"`, `latest_revision_id = NULL`), plus a deleted disappearing message inside `signal.db-wal` (`expires_in = 30000`). Verify that Sub-Engine 5.2D links Row 10 into Row 11's `pre_edit_or_diff_json` and recovers the expired disappearing message from the WAL frame!