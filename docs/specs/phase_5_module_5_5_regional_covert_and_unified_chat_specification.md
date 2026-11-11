# Engineering Specification: Phase 5, Module 5.5 — Indian Regional Chat Apps, Covert In-App Dead-Drops, Marketplace/Betting Portals & The Cross-Platform Unified Conversation Correlator

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 5.5** of the Forensic Data Parser (completing **Phase 5 / Group 1 & Group 5**, and cross-linking with **Groups 2, 4, 6, 13, and 15** of the Unified Master Register). It contains **zero programming code** and explains how to decode `Truecaller` (both its built-in IM messenger and its global Caller-ID lookup cache for unsaved phone numbers), Indian regional social apps (`ShareChat`, `Moj`, `JioChat`, `Zoho Arattai`), marketplace fraud initiation chats (`OLX India`, `IndiaMART`, `Quikr`), illegal offshore betting & gaming chats (`Lotus365`, `1xBet`, `Ludo King`, `BGMI`), covert cloud dead-drops (`Google Docs`, `Google Keep`, `Shared Apple Notes`, `Email Drafts`), and the **Master Cross-Platform Actor & Conversation Stitching Engine** from first principles.

---

## 1. Purpose & Mental Model (Why Criminals Hide Outside Traditional Messengers)

When an investigation focuses only on mainstream chat apps (WhatsApp, Telegram, Signal, Instagram), examiners miss four critical communication layers heavily exploited in Indian and cross-border crime:

1. **The `Truecaller` Intelligence & IM Layer (`com.truecaller`):**
   * Over $350\text{ million}$ smartphones in India run **Truecaller**. Investigators rarely realize two forensic facts about Truecaller:
     * First, Truecaller includes a full-fledged **Instant Messenger (IM), SMS inbox, and VoIP calling platform** (`msg.db`) where suspects exchange messages, photos, and voice calls.
     * Second, whenever any unsaved phone number calls, texts, or is searched by the suspect, Truecaller queries its cloud directory and caches the **crowd-sourced Caller-ID Name, Carrier, Location (State/Telecom Circle), Email, and Business Tag** inside a local SQLite database (`tc.db` / `aggregated_contact`). Even when a co-conspirator's number (`+919876543210`) is **not saved** in the suspect's phonebook (`contacts2.db`), Truecaller's local cache reveals who owns that number!
2. **Marketplace, Regional & Betting Initiation Channels (`OLX`, `IndiaMART`, `ShareChat`, `Moj`, `Lotus365`):**
   * Almost every Indian QR-code scam, advance-fee fraud, mule recruitment drive, or honeytrap extortion begins inside a regional or marketplace app (**OLX India, IndiaMART, Quikr, ShareChat Audio Chatrooms, Moj, or an illegal betting portal like Lotus365 / Reddy Anna / 1xBet**) before the perpetrator instructs the victim to move to WhatsApp or Telegram.
3. **Covert "Cloud Dead-Drop" Channels (`Google Docs`, `Google Keep`, `Shared Apple Notes`, `Shared Email Drafts`):**
   * High-opsec terror cells, narcotics syndicates, and hawala operators avoid sending messages over chat networks altogether. Instead, two conspirators share a single **Google Doc**, **Google Keep note**, **collaborative Apple Note**, or log into the **same Gmail / ProtonMail account** and type messages inside an **unsent Email Draft**—reading and deleting text in place.
4. **Cross-Platform Conversation Hopping (Why Stitching Is Essential):**
   * Real-world criminals rarely finish a crime inside one app. A suspect meets a target on **OLX** at 2:00 PM $\rightarrow$ moves to **WhatsApp** at 2:05 PM $\rightarrow$ switches to **Telegram** or **Session** at 2:15 PM $\rightarrow$ and receives ₹50,000 on **PhonePe** at 2:20 PM. Module 5.5 fuses all of those hops into a single **Unified Actor Profile & Cross-App Conversation Timeline**.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Regional, Covert & Unified Chat Forensics

Before implementing Module 5.5, the developer must understand six critical traps:

### Mistake 1: Ignoring `Truecaller`'s Local Caller-ID Cache When Resolving Unsaved Phone Numbers Across the Phone
* **The Trap:** Treating Truecaller (`com.truecaller`) as a standalone utility app and leaving unsaved phone numbers in Call Logs (`CallHistory.storedata` / `calllog.db`), SMS (`mmssms.db`), WhatsApp, and UPI tables labeled as `"Unknown Contact (+919876543210)"`.
* **Why It Fails:** Truecaller's `/databases/tc.db` (and `msg.db`) stores the resolved Caller-ID name (e.g., `"Ramesh Kumar Cyber Cafe Patna"`), spam score, and telecom circle for thousands of unsaved numbers that called, texted, or were searched on the phone!
* **The Rule:** Sub-Engine 5.5A must extract Truecaller's entire `aggregated_contact` / `raw_contact` lookup table and register it as a **Global Phone-Number Enrichment Service** for every other module in your software (Groups 1, 2, 10, and 13)!

### Mistake 2: Missing `ShareChat` & `Moj` Audio Chatroom & Gift Laundering Logs
* **The Trap:** Looking only for text DMs inside `ShareChat` (`in.mohalla.sharechat`) and `Moj` (`in.mohalla.video`).
* **Why It Fails:** In Tier-2 and Tier-3 Indian cities, cyber-fraud gangs use **ShareChat Audio Chatrooms** both to recruit bank-account mules and to **launder small-value fraud proceeds by purchasing virtual "Gems / Coins" via UPI and gifting them to accomplice hosts in audio chatrooms**!
* **The Rule:** Extract direct messages (`chat_db`), Audio Chatroom session histories, and virtual coin/gift transaction ledgers (Section 4.1).

### Mistake 3: Looking Only for Native SQLite Tables in Illegal Betting Apps (`Lotus365`, `1xBet`, `FairPlay`) Instead of Embedded Live-Chat Widgets
* **The Trap:** Inspecting an illegal betting APK (like `Lotus365`, `Mahadev Book`, `Reddy Anna`, `FairPlay`, or `Aviator`) for a native SQLite table called `messages` and finding nothing.
* **Why It Fails:** Almost all illegal offshore betting and bookie apps use embedded customer-support web widgets (**`LiveChatInc`**, **`Tawk.to`**, **`Intercom`**, **`Zendesk`**, or **`Crisp.chat`**) inside `app_webview` where the punter chats with a "Deposit / Withdrawal Agent" to get the latest mule UPI VPA or bank account number to deposit money! Those entire agent chat transcripts, uploaded UTR screenshots, and assigned mule bank details sit inside **`app_webview` (`Simple Cache *_0`, `Local Storage/leveldb/`, and `IndexedDB`)**!
* **The Rule:** Sub-Engine 5.5D automatically scans `webview_http_cache_records` and `webview_autofill_and_storage` (from Phase 2, Module 2.4) for all third-party live-chat widget payloads (Section 6.1).

### Mistake 4: Failing to Reconstruct `Google Docs` & `Apple Notes` Revision Chunks in Dead-Drop Investigations
* **The Trap:** Extracting only the final visible text of a Google Doc, Google Keep note, or Apple Note after the suspect deleted the incriminating paragraph.
* **Why It Fails:**
  * In **Google Docs (`com.google.android.apps.docs`)**, offline document editing is stored as a sequence of **Operational Transformation (`OT`) mutation commands (`insert`, `delete`, `retain`)** inside local SQLite databases (`DocList.db`, `cello.db`, ` mutations` / `commands` tables) and WebKit/IndexedDB caches! Even if the suspect deleted the text before seizure, the `insert` mutation chunks and `-wal` frames preserve what was typed!
  * In **Apple Notes (`NoteStore.sqlite`)**, collaborative notes track per-character **CRDT (Conflict-Free Replicated Data Type)** author UUIDs and timestamps inside the gzipped `ZDATA` protobuf!
* **The Rule:** Unpack mutation logs, CRDT author attributions, and `-wal` historical frames on all cloud document/note databases (Section 6.2).

### Mistake 5: Failing to Normalize Phone Numbers Before Running Cross-Platform Entity Resolution
* **The Trap:** Trying to join `"098765 43210"` (from Contacts), `"919876543210@s.whatsapp.net"` (from WhatsApp), `"+91-9876543210"` (from Truecaller), and `"9876543210@ybl"` (from PhonePe) using exact string equality.
* **Why It Fails:** None of those four strings are equal as raw text, so a naive join creates four separate actor profiles instead of one!
* **The Rule:** Pass every phone number and phone-based handle through the **Canonical E.164 & 10-Digit Subscriber Tail Normalizer** (Section 7.1) before building the Unified Actor Graph.

### Mistake 6: Merging Two Different People Who Share a Generic First Name (`"Rahul"`)
* **The Trap:** Automatically merging two chat accounts into one Unified Actor simply because both have the display name `"Rahul"` or `"Boss"`.
* **Why It Fails:** Merging actors on non-unique display names contaminates the evidentiary graph and fails courtroom scrutiny.
* **The Rule:** Actor fusion in Sub-Engine 5.5E must **only** occur on **Hard Deterministic Join Keys** (exact E.164 phone number, exact email address, exact `@username` handle shared across linked profiles, exact VPA prefix, or explicit in-chat cross-platform handoff links), logging the exact cryptographic or database join key that linked the accounts!

---

## 3. Step 1 — Sub-Engine 5.5A: `Truecaller` (`com.truecaller`) Deep Decoder & Global Caller-ID Enrichment Service

* **Target Identifiers (Query via Module 1.3 `resolve_app_targets`):**
  * **Android:** `com.truecaller`
  * **iOS:** `com.truesoftware.TrueCallerOther` (Shared AppGroup: `group.com.truesoftware.TrueCallerOther`)

### 3.1 Step 1: Extracting Truecaller's Built-In IM Chats, SMS, Flash Messages & VoIP Calls (`msg.db`)
On Android, Truecaller acts as a full messaging and calling replacement app, storing all communications inside `/data/user/<id>/com.truecaller/databases/msg.db` (+ `msg.db-wal`):
1. Stage `msg.db` via Module 1.1 and process through **Phase 2, Module 2.1 (Active + `-wal` + Freelist)**.
2. **Extract Core Tables in `msg.db`:**
   * **`messages` & `entities` Tables:**
     * Join `messages` with `entities` (on `messages._id = entities.message_id`) and `participants` / `conversations`:
       * `transport`: Distinguishes how the message was sent/received:
         * `0` / `1`: Standard Carrier SMS / MMS
         * **`2` (`IM`):** **Truecaller Instant Message (Over-the-Top Internet Chat!)**
         * **`4` (`FLASH`):** **Truecaller Flash Message (Pop-up ephemeral screen message!)**
         * **`5` / `6`:** **Truecaller VoIP Audio/Video Call or Voice Note**
       * `participant_id` $\rightarrow$ `normalized_number` (`+919876543210`) & `raw_address`.
       * `date` & `date_sent`: 13-digit Unix millisecond timestamps.
       * `content` (from `entities` where `type == 'text/plain'`): Full message text!
       * `content_uri` / `mime_type` (from `entities` for attachments): Shared images, videos, voice notes, documents, and GPS locations.
       * `status`: Sent, Received, Read, Deleted/Revoked.

### 3.2 Step 2: Harvesting the Global Unsaved-Number Caller-ID Cache (`tc.db` / `truecaller.db`)
Even if the suspect never used Truecaller's chat feature, Truecaller's contact and call-lookup database (`/databases/tc.db` on Android; `Truecaller.sqlite` / Realm on iOS) is one of the highest-value attribution sources on an Indian smartphone:
1. Stage `/databases/tc.db` (+ `tc.db-wal`) via Module 1.1 and process via **Module 2.1 (Active + `-wal` + Freelist)**.
2. **Extract `aggregated_contact`, `raw_contact`, `data`, and `history` / `search_history` Tables:**
   * For every phone number cached in `tc.db`, extract:
     * **`normalized_number` / `tc_phone`:** E.164 phone number (e.g., `+919876543210`).
     * **`contact_name` (`tc_resolved_name`):** **The crowd-sourced / verified Truecaller name of that phone number** (e.g., `"Vikram Singh Crypto P2P"`, `"SBI Credit Card Fraud"`, `"Raju Hawala Chandni Chowk"`), even when the number is **not** in the phone's native Contacts (`contacts2.db`)!
     * **`spam_score` & `spam_type`:** Number of users who reported this phone number as spam/fraud (e.g., `spam_score = 412`, `spam_type = "SCAM_OR_FRAUD"`).
     * **`carrier` & `country_code` / `city_area`:** Telecom operator and circle/city cached by Truecaller.
     * **`email` / `job_title` / `company_name` / `upi_vpa`:** Additional profile tags returned by Truecaller's API!
     * **`search_timestamp` (`history` table):** Proves **when the suspect manually typed a phone number into Truecaller's search bar to look up who owned it**!
3. **Register as Global Enrichment Dictionary:**
   * Populate `truecaller_global_enrichment_cache` so that **every phone number across Call Logs, SMS, WhatsApp, Telegram, and UPI (Phases 3 & 5)** that lacks a local phonebook contact name is automatically annotated with `[Truecaller ID: "<tc_resolved_name>" (Spam Score: <N>)]`!

---

## 4. Step 2 — Sub-Engine 5.5B: Indian Regional Social & Messaging Apps (`ShareChat`, `Moj`, `JioChat`, `Zoho Arattai`)

### 4.1 Target 1: `ShareChat` (`in.mohalla.sharechat`) & `Moj` (`in.mohalla.video`)
* **Why They Matter:** `ShareChat` and `Moj` have over $300\text{ million}$ Indian users across 15 Indian regional languages (Hindi, Tamil, Telugu, Bengali, Marathi, Kannada, Malayalam, Gujarati, Punjabi, Odia, Bhojpuri, etc.). They are heavily used in regional mule recruitment, fake work-from-home task scams, illegal loan promotion, and virtual gift laundering.
* **Step-by-Step Sandbox Extraction (`/data/user/<id>/in.mohalla.sharechat/` & `in.mohalla.video/`):**
  1. **User Profile (`shared_prefs/*.xml` & `MMKV`):**
     * Extract `userId`, `@handle`, registered 10-digit mobile number, selected language, bio, and linked bank/UPI payout details (for creator monetization/gift cash-outs).
  2. **SQLite & Room Databases (`/databases/` — e.g., `sharechat*.db`, `chat*.db`, `moj*.db`, `room*.db` via Module 2.1 Active + `-wal` + Freelist):**
     * **Direct Messages (`chat_messages`, `conversations`, `dm_threads`):**
       * Extract `messageId`, `chatId`, `senderId`, `recipientId`, `messageType` (`text`, `audio`, `image`, `video`, `gif`, `sticker`), `text`, `mediaUrl` / local cache path, and `createdOn` (13-digit Unix ms).
       * Note: ShareChat supports **"Shake-and-Chat" (Anonymous Random Chat)**. Explicitly flag threads initiated via anonymous matching where a user subsequently revealed their WhatsApp number or UPI VPA!
     * **Audio Chatrooms & Virtual Gift Laundering (`chatroom_sessions`, `gift_transactions`, `coin_ledger`):**
       * Extract `chatroomId`, `chatroomTitle`, `hostUserId`, `participantIds`, live text comments inside the audio room, and **Virtual Coin / Gift Transfers** (`senderId`, `receiverHostId`, `giftType`, `coinValue`, `inrPurchaseUTR`, `timestamp`).

### 4.2 Target 2: `Zoho Arattai` (`com.zoho.arattai`) & `JioChat` (`com.jiochat.jiochatapp`)
1. **`Zoho Arattai` (Indian Homegrown Messenger — `com.zoho.arattai` on Android / `com.zoho.arattai` on iOS):**
   * Stage all SQLite databases in `/databases/` (unwrapping via Module 2.2 if SQLCipher-protected via Android Keystore / iOS Keychain).
   * Extract `users` / `contacts` (`zuid`, `phone_number`, `display_name`, `@username`), `chats` / `channels`, `messages` (`msg_id`, `chat_id`, `sender_id`, `content`, `msg_type`, `sent_time_ms`, `ephemeral_ttl` for Secret Chats), and `meetings` (video call logs).
2. **`JioChat` (`com.jiochat.jiochatapp`):**
   * Parse `/databases/*.db` (`jiochat*.db`, `messages.db`, `contacts.db`) via Module 2.1 to extract 1-on-1 chats, group chats, audio/video call logs, and brand/business channel interactions.

---

## 5. Step 3 — Sub-Engine 5.5C: E-Commerce & Classifieds Fraud Initiation Channels (`OLX India`, `IndiaMART`, `Quikr`, `Meesho`)

In Indian cybercrime, **marketplace scams** (fake army/CISF personnel selling cheap vehicles or furniture on OLX, fake wholesale suppliers on IndiaMART demanding advance RTGS/UPI deposits, or reselling scams on Meesho/Facebook Marketplace) always begin inside the marketplace app's built-in chat before moving to WhatsApp and UPI.

### 5.1 Target 1: `OLX India` (`com.olx.southasia` on Android / `in.olx.olx` on iOS)
* **Sandbox Extraction (`/data/user/<id>/com.olx.southasia/`):**
  1. **Logged-In Profile (`shared_prefs/` & `MMKV`):** Extract `user_id`, registered mobile number, email, display name, and last active GPS coordinates (`latitude`, `longitude`, `locality_name`).
  2. **SQLite Databases (`/databases/*chat*.db`, `*olx*.db`, `*persistence*.db` via Module 2.1) & `app_webview` Cache (`Module 2.4`):**
     * **Ad Listings (`items` / `ads`):** Extract `ad_id`, `title` (e.g., `"Royal Enfield Classic 350 Urgent Sale Army Transfer"`), `price_inr`, `seller_id`, `seller_name`, `location_city`, and `created_at`.
     * **Buyer–Seller Chat Threads (`conversations` & `messages`):**
       * Extract `conversation_id`, `ad_id`, `buyer_id`, `seller_id`, `sender_id`, `message_text` (specifically flagging messages where a party shares a **10-digit mobile number**, a **UPI VPA**, or a **QR code image**!), `attachment_url` / cached image path, and `timestamp_ms`.

### 5.2 Target 2: `IndiaMART` (`com.indiamart.m` on Android / `com.indiamart.indiamart` on iOS)
* **Why IndiaMART Is Critical:** Used in B2B wholesale advance-payment frauds, counterfeit pharmaceutical/chemical sourcing, and GST fake-invoice rackets.
* **Sandbox Extraction (`/data/user/<id>/com.indiamart.m/databases/`):**
  * Stage all SQLite files (`indiamart*.db`, `messages*.db`, `lms*.db` — **Lead Management System Database**) through Module 2.1:
    * Extract `glid` (**IndiaMART Global User ID**), `company_name`, `gstin` (**15-character Indian GST Number**!), `mobile_number`, `email`, `address_city`.
    * Extract **BuyLeads & Enquiry Chats (`lms_chat`, `messages`):** Full buyer-seller negotiation history, shared proforma invoices (`.pdf`), shared bank account + IFSC details, and call timestamps!

### 5.3 Target 3: `Quikr` (`com.quikr`), `Meesho` (`com.meesho.supply`) & `Facebook Marketplace`
* Scan SQLite databases, `MMKV`, and `app_webview` HTTP caches (`webview_http_cache_records`) for buyer-seller chat threads, supplier bank details, return/refund manipulation logs, and shared contact numbers.

---

## 6. Step 4 — Sub-Engine 5.5D: Illegal Betting Portals (`Lotus365`, `1xBet`), Gaming Chats (`Ludo King`, `BGMI`) & Cloud Dead-Drops (`Google Docs`, `Keep`, `Shared Notes`, `Email Drafts`)

### 6.1 Target 1: Illegal Offshore Betting, Hawala Bookie Portals & Gaming Chats
* **Target Betting & Gaming Ecosystems:**
  * **Betting / Bookie Apps & PWAs:** `Lotus365`, `Mahadev Book`, `Reddy Anna`, `FairPlay`, `Laser247`, `Betbhai9`, `1xBet` (`org.xbet.client1`), `Parimatch`, `Melbet`, `Stake`, `Aviator`, `Teen Patti Gold` / `Rummy` real-money clones.
  * **In-Game Multiplayer Voice/Text Chats:** `Ludo King` (`com.ludo.king`), `BGMI — Battlegrounds Mobile India` (`com.pubg.imobile`), `Garena Free Fire MAX` (`com.dts.freefiremax`), `Call of Duty Mobile`, `Roblox`.
* **Step-by-Step Extraction Logic:**
  1. **Embedded Bookie Live-Chat Widgets (`LiveChatInc`, `Tawk.to`, `Intercom`, `Zendesk`, `Crisp` inside `app_webview` & Chrome):**
     * Query **Phase 2, Module 2.4 (`webview_http_cache_records`, `webview_autofill_and_storage`, `kv_recovered_records_master`)** across the entire device for URLs or `Local Storage` / `IndexedDB` origins matching:
       * `*livechatinc.com*`, `*tawk.to*`, `*intercom.io*`, `*zdassets.com*` / `*zendesk.com*`, `*crisp.chat*`, `*lotus365*`, `*1xbet*`, `*parimatch*`, `*fairplay*`, `*laser247*`, `*reddyanna*`.
     * Extract the **Deposit / Withdrawal Agent Chat Transcripts**: In these chats, the bookie agent sends the suspect a **fresh Layer-1 Mule Bank Account + IFSC or UPI QR Code**, and the suspect replies with a **12-digit UPI `UTR` number** or payment screenshot to receive betting panel points/chips!
     * Automatically cross-link every 12-digit `UTR` and mule VPA/Account found inside a betting chat directly to **Phase 3 (`unified_financial_transactions_ledger`)**!
  2. **In-Game Chat & Friend Lists (`Ludo King`, `BGMI`, `Free Fire`):**
     * Parse `/files/`, `/cache/`, `shared_prefs/`, and SQLite/Tencent `GCloud`/`Apollo` voice and text chat logs inside `com.pubg.imobile` (`BGMI`), `com.dts.freefiremax`, and `com.ludo.king` to extract Player UIDs (`CharacterID`), in-game clan/friend lists, private room codes, and cached lobby text messages.

### 6.2 Target 2: Covert "Cloud Dead-Drop" Channels (`Google Docs`, `Google Keep`, `Apple Notes` & `Shared Email Drafts`)
To defeat "Dead-Drop" communication (where two conspirators type and delete messages inside a shared cloud document or email draft without sending messages):

1. **Google Docs (`com.google.android.apps.docs.editors.docs` on Android / `com.google.Docs` on iOS):**
   * Stage all SQLite databases inside `/databases/` (`DocList.db`, `cello.db`, `offline_docs.db`) and inspect `/files/` / `IndexedDB` caches via **Module 2.1 (Active + `-wal` + Freelist)** and **Module 2.3B (LevelDB)**:
     * **Document Collaborator Roster (`acl` / `permissions` / `sharing` tables):** Extract `doc_id`, `title`, `owner_email`, and **every collaborator email address granted `writer` / `commenter` / `reader` access**! *(Proves who the other person on the dead-drop document was!)*
     * **Operational Transformation (`OT`) Mutation Chunks & Comments:** Extract cached document body chunks, inline comments/suggestions (which often survive after being marked "Resolved"!), and `-wal` / freelist historical states showing text that was typed and subsequently erased!
2. **Google Keep (`com.google.android.keep`):**
   * Open `/databases/keep.db` (+ `keep.db-wal`) via Module 2.1:
     * Join `tree_entity` (note title, creation/modification timestamps, `is_trashed`, `is_archived`) with `text_search_tree_entity_content` / `list_item` (note text body) and **`sharing`** (**lists the exact email address of every collaborator sharing that Keep note!**).
     * Recover deleted text and deleted notes from `keep.db-wal` and B-Tree freelist pages!
3. **Shared Apple Notes (`NoteStore.sqlite` — Collaborative `CKShare` Dead-Drops):**
   * In `/private/var/mobile/Containers/Shared/AppGroup/group.com.apple.notes/NoteStore.sqlite`:
     * Inspect `ZICCLOUDSYNCINGOBJECT` where `ZSERVERRECORDDATA` / `ZSHARE` (`CKShare` binary plist) is non-null: decode the `CKShare` plist to extract the **Apple ID email / phone number and name of every participant sharing that collaborative Apple Note**!
     * Inside the note's gunzipped `ZDATA` Protobuf (and earlier `-wal` frames of `NoteStore.sqlite`), decode the CRDT text runs and their per-author UUIDs and edit timestamps!
4. **Shared Email Account `Drafts` Dead-Drop (`Gmail`, `Outlook`, `ProtonMail`, `Apple Mail`):**
   * In `/data/user/<id>/com.google.android.gm/databases/bigtop_data_db.*` (Gmail `items` / `item_messages` tables), `EmailProvider.db`, `ch.protonmail.android`, and iOS `/private/var/mobile/Library/Mail/Envelope Index`:
     * Filter specifically for messages with status/label **`DRAFT` (`^r` in Gmail BigTop)**—especially drafts that have **multiple revision timestamps in the `-wal` file**, or drafts inside an email account accessed from multiple IP addresses!

---

## 7. Step 5 — Sub-Engine 5.5E: The Master Cross-Platform Actor Resolution & Conversation Stitching Engine

Once Modules 5.1 (WhatsApp), 5.2 (Telegram & Signal), 5.3 (High-OpSec Messengers), 5.4 (Social, VoIP & Burner Apps), 5.5A–D (Regional, Marketplace, Betting & Dead-Drops), plus Group 1 Native SMS/Call Logs (`mmssms.db`, `CallHistory.storedata`) and Group 2 Contacts (`contacts2.db`, `AddressBook.sqlitedb`) have finished executing, **Sub-Engine 5.5E fuses all communication silos into a single unified intelligence graph**.

### 7.1 Step 1: Canonical Phone Number & Handle Normalization
To link identities across 40+ apps without false negatives:
1. **Phone Number Canonicalization (`canonical_phone_10_and_e164`):**
   * Strip all spaces, dashes (`-`), parentheses, dots, and WhatsApp `@s.whatsapp.net` suffixes.
   * For Indian numbers (`10 digits` starting with `6–9`, `11 digits` starting with `06–09`, or `12 digits` starting with `916–919`), normalize to both:
     * **`e164_phone`:** `"+919876543210"`
     * **`subscriber_10_tail`:** `"9876543210"`
   * For international numbers (e.g., UAE `+971...`, US `+1...`, UK `+44...`, Cambodia `+855...`), preserve the full E.164 country prefix and national number.

### 7.2 Step 2: Deterministic Multi-App Actor Fusion Rules (Building the Unified Actor Card)
Sub-Engine 5.5E builds a **Connected Components Graph** where each node is an app-specific peer record and an edge is drawn between two nodes **if and only if** they share at least one **Hard Deterministic Join Key**:

1. **Join Key 1 (Exact Phone Number Match):**
   * Links `Contacts (contacts2.db)` $\leftrightarrow$ `Truecaller (tc.db)` $\leftrightarrow$ `Call Logs` $\leftrightarrow$ `SMS` $\leftrightarrow$ `WhatsApp (@s.whatsapp.net & unmasked @lid)` $\leftrightarrow$ `Telegram (TL_user.phone)` $\leftrightarrow$ `Signal (e164)` $\leftrightarrow$ `Botim / IMO` $\leftrightarrow$ `OLX / IndiaMART` $\leftrightarrow$ `Phase 3 UPI VPA Prefix (9876543210@ybl)`!
2. **Join Key 2 (Explicit In-Chat Cross-Platform Handoff Link):**
   * When Actor X in App 1 (e.g., an OLX seller or WhatsApp contact `+919876543210`) sends a message containing a handle/invite for App 2 (e.g., *"Message me on Telegram `@vikram_hawala`"* or *"Add my Session ID `05a1b2...`"* or *"Pay my UPI `merchant99@okaxis`"*), create a verified **`IN_CHAT_HANDOFF_EDGE`** linking Actor X's `+919876543210` profile to `@vikram_hawala`, `05a1b2...`, and `merchant99@okaxis`!
3. **Join Key 3 (Exact Email Address or Shared Cryptographic Address):**
   * Links two profiles that share the exact same normalized email address (`user@gmail.com` across Google Keep dead-drop, Instagram, Discord, and Binance P2P) or the exact same `0x...` / `T...` cryptocurrency wallet address!

### 7.3 Step 3: Cross-Platform Conversation Stitching (Reconstructing Multi-App Hops)
For every **Unified Actor (`unified_actor_uid`)** who communicated with the suspect across **$\ge 2$ different platforms** (for example: OLX Chat $\rightarrow$ Cellular Phone Call $\rightarrow$ WhatsApp Chat $\rightarrow$ Telegram Secret Chat $\rightarrow$ PhonePe UPI Payment):
* Merge all messages, voice/video calls, dead-drop edits, and financial/crypto transfers involving that Unified Actor into a single chronological **Stitched Cross-Platform Timeline**, automatically highlighting **Platform-Switch Transitions** (e.g., flagging the exact minute the conversation jumped from WhatsApp to Session or Telegram prior to a ₹5,00,000 UPI/USDT transfer!).

---

## 8. Database Schema for Module 5.5 (`regional_covert_and_unified_chat_engine.sqlite`)

The developer must create the following four tables in the case database:

### Table 1: `truecaller_global_enrichment_cache` (Caller-ID Names, Spam Scores & Lookup History for Unsaved Numbers)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `tc_enrich_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `normalized_e164_phone` | `TEXT` | `NOT NULL` | E.164 phone number (`+919876543210`, indexed for instant global lookup!). |
| `subscriber_10_tail` | `TEXT` | `NULL` | 10-digit tail (`9876543210`, indexed!). |
| `tc_resolved_name` | `TEXT` | `NOT NULL` | Crowd-sourced / verified Truecaller name (e.g., `"Vikram Singh Crypto P2P"`). |
| `is_saved_in_device_contacts` | `INTEGER` | `DEFAULT 0` | `0` if this number was **unsaved** in the suspect's phonebook (meaning Truecaller unmasked an unknown number!). |
| `tc_spam_score` | `INTEGER` | `DEFAULT 0` | Spam report count (`> 0` indicates reported scammer/telemarketer). |
| `tc_carrier_and_circle` | `TEXT` | `NULL` | E.g., `"Airtel — Bihar & Jharkhand"`. |
| `tc_extracted_email_or_vpa` | `TEXT` | `NULL` | Email, business tag, or VPA cached in Truecaller profile. |
| `was_manually_searched_by_user` | `INTEGER` | `DEFAULT 0` | `1` if the suspect manually searched this number in Truecaller (`search_history`). |
| `last_lookup_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 2: `regional_marketplace_betting_and_deaddrop_ledger` (All Module 5.5A–D Messages, Audio Rooms, Betting Chats & Dead-Drops)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `special_comm_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `channel_category` | `TEXT` | `NOT NULL` | Enum: `TRUECALLER_IM_OR_FLASH`, `SHARECHAT_MOJ_DM_OR_AUDIOROOM`, `JIOCHAT_ARATTAI`, `OLX_INDIAMART_MARKETPLACE`, `BETTING_BOOKIE_LIVECHAT`, `MULTIPLAYER_GAME_CHAT`, `GOOGLE_DOCS_KEEP_DEADDROP`, `APPLE_NOTES_SHARED_DEADDROP`, `EMAIL_DRAFT_DEADDROP`. |
| `app_name` | `TEXT` | `NOT NULL` | E.g., `"OLX India"`, `"IndiaMART"`, `"ShareChat"`, `"Lotus365 WebView"`, `"Google Keep"`, `"Gmail Drafts"`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, etc.). |
| `thread_or_document_id` | `TEXT` | `NOT NULL` | Conversation ID, OLX `ad_id`, Google Doc ID, or Email Draft ID. |
| `thread_or_listing_title` | `TEXT` | `NULL` | Marketplace listing title, Audio Chatroom name, or Shared Note/Doc title. |
| `sender_or_author_id` | `TEXT` | `NULL` | Sender phone, User ID, or Collaborator Email Address. |
| `collaborators_or_peers_json` | `TEXT` | `NULL` | JSON array of all participant phone numbers / emails on the thread or shared dead-drop document! |
| `message_or_mutation_text` | `TEXT` | `Not NULL` | Extracted message text, betting agent UTR instruction, or recovered dead-drop draft/mutation text. |
| `extracted_utr_vpa_or_phone_json` | `TEXT` | `NULL` | Automatically extracted 10-digit phone numbers, UPI VPAs, bank accounts, or 12-digit UTRs found inside the chat/draft! |
| `event_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `event_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |

### Table 3: `unified_cross_platform_actors` (Master 360-Degree Identity Card per Counterparty Across All Apps)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `unified_actor_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Master Actor ID across the entire forensic case. |
| `primary_display_name` | `TEXT` | `NOT NULL` | Best resolved name (Priority: Verified Bank CBS Name $\rightarrow$ Local Contact Name $\rightarrow$ Truecaller Resolved Name $\rightarrow$ WhatsApp Push Name). |
| `phonebook_saved_name` | `TEXT` | `NULL` | Name in `contacts2.db` / `AddressBook.sqlitedb` (`NULL` if unsaved!). |
| `truecaller_unmasked_name` | `TEXT` | `NULL` | Name resolved from `tc.db` (`truecaller_global_enrichment_cache`)! |
| `verified_bank_cbs_name` | `TEXT` | `NULL` | Official Core Banking Solution name from Phase 3 (`PhonePe` / `GPay` / `mPassbook`). |
| `phone_numbers_e164_json` | `TEXT` | `NULL` | JSON array of all linked phone numbers (`["+919876543210", "+971501234567"]`). |
| `whatsapp_jids_and_lids_json` | `TEXT` | `NULL` | Linked `@s.whatsapp.net` and `@lid` identifiers. |
| `telegram_ids_and_handles_json` | `TEXT` | `NULL` | Linked Telegram `user_id`s and `@username` handles. |
| `signal_and_opsec_handles_json` | `TEXT` | `NULL` | Linked Signal `ACI`, Session `05...` ID, Zangi Number, SimpleX queue, or Matrix ID. |
| `social_and_marketplace_ids_json` | `TEXT` | `NULL` | Linked Instagram, Messenger, Snapchat, Discord, OLX, or IndiaMART IDs. |
| `linked_upi_vpas_and_banks_json` | `TEXT` | `NULL` | Linked UPI VPAs (`@ybl`, `@okaxis`) and Bank Accounts from Phase 3! |
| `linked_crypto_addresses_json` | `TEXT` | `NULL` | Linked `T...` (TRON) or `0x...` (EVM) wallet addresses / CEX P2P nicknames from Phase 4! |
| `deterministic_join_proof_json` | `TEXT` | `NOT NULL` | Exact audit log explaining *how* these accounts were linked (e.g., `["Phone +919876543210 match", "In-chat handoff in WhatsApp msg #412 to Session 05a1..."]`). |

### Table 4: `unified_stitched_conversation_timeline` (Chronological Multi-App Hop Reconstruction)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `timeline_event_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Global chronological sequence ID. |
| `unified_actor_uid` | `INTEGER` | `NOT NULL` | Foreign key to `unified_cross_platform_actors.unified_actor_uid`. |
| `source_platform` | `TEXT` | `NOT NULL` | E.g., `OLX_CHAT`, `CELLULAR_CALL`, `WHATSAPP`, `TELEGRAM_SECRET`, `SESSION`, `GOOGLE_KEEP_DEADDROP`, `PHONEPE_UPI_TX`, `BINANCE_P2P_CHAT`. |
| `is_platform_switch_hop` | `INTEGER` | `DEFAULT 0` | **`1` whenever the suspect and this counterparty switched from one app to a different app compared to the immediately preceding event!** |
| `direction` | `TEXT` | `NOT NULL` | `OUTGOING`, `INCOMING`, `DEAD_DROP_EDIT`, `FINANCIAL_TRANSFER`. |
| `event_summary_text` | `TEXT` | `NOT NULL` | Message text, call duration, or transfer amount + UTR. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, etc.). |
| `event_utc_ns` | `INTEGER` | `NOT NULL` | 64-bit UTC nanoseconds (for sub-millisecond sorting across apps). |
| `event_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |

---

## 9. Developer Acceptance Test Checklist for Module 5.5

1. **The `Truecaller` Unsaved-Number Unmasking Test:** Insert a phone call in `calllog.db` and a UPI transfer in PhonePe involving `+919876543210` where `+919876543210` is **not** present in `contacts2.db`. Place a cached lookup row inside Truecaller's `/databases/tc.db` (`aggregated_contact`) for `+919876543210` with `contact_name = "Rakesh Mule Coordinator"` and `spam_score = 85`. Verify that Sub-Engine 5.5A extracts the `tc.db` record and Sub-Engine 5.5E populates `truecaller_unmasked_name = "Rakesh Mule Coordinator"` on the Unified Actor card!
2. **The Betting `app_webview` LiveChat Widget & UTR Bridge Test:** Place a cached `LiveChatInc` JSON transcript inside an illegal betting app's `app_webview` Simple Cache (`*_0`) where the agent writes `"Deposit to VPA bookie77@ybl"` and the user replies `"Done UTR 630914829104"`. Verify that Sub-Engine 5.5D extracts the chat and links `630914829104` to Phase 3's `unified_financial_transactions_ledger`.
3. **The Shared `Google Keep` / `Email Draft` Dead-Drop WAL Recovery Test:** Create a `keep.db` shared note (`sharing` email = `handler@proton.me`) or a Gmail `DRAFT` where the text `"Deliver 20 Lakh to Sector 15 at 6 PM"` was written in a `-wal` frame and then overwritten with `"Shopping list: milk, bread"`. Verify that Sub-Engine 5.5D extracts the collaborator email `handler@proton.me` and recovers the overwritten dead-drop instruction from the `-wal` frame!
4. **The 5-App Cross-Platform Conversation Stitching Test:** Simulate a suspect interacting with the same counterparty across five steps:
   * 14:00 — OLX Chat (`+919876543210`): `"Call me on WhatsApp 9876543210"`
   * 14:05 — WhatsApp (`919876543210@s.whatsapp.net`): `"Add my Session ID 05a1b2c3..."`
   * 14:10 — Session (`05a1b2c3...`): `"Send Rs 50,000 to my PhonePe 9876543210@ybl"`
   * 14:15 — PhonePe (`9876543210@ybl`, CBS Name `"VIKRAM SINGH"`): `₹50,000.00 Sent (UTR 630914829104)`
   Verify that Sub-Engine 5.5E merges all four identifiers into **one single row** in `unified_cross_platform_actors` and outputs a 4-step stitched timeline in `unified_stitched_conversation_timeline` with `is_platform_switch_hop = 1` at each transition!