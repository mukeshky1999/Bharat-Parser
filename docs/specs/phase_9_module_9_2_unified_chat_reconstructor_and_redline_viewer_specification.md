# Engineering Specification: Phase 9, Module 9.2 — Unified Multi-App Chat Reconstructor, Edit/Revoke Redline Viewer & Cross-Platform Conversation Hopping Timeline

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 9.2** of the Forensic Workstation UI/UX Engine (the conversational reconstruction workspace of **Phase 9**, powered by the messaging, social, dating, and entity-resolution databases of **Phases 3, 4, 5, 6.4, 7, and 8.1**). It contains **zero programming code** and explains how to render 60 FPS variable-height chat bubble streams across $500,000+$ message mega-groups using a **Fenwick-Tree (Binary Indexed Tree) Prefix-Sum Virtual Scroller**, how to visually diff edited and revoked ("Delete for Everyone") messages using a **Grapheme-Aware Myers Shortest-Edit-Script (`SES`) Redline Engine**, how to unmask anonymous `@lid` / `05...` / unsaved numbers inline via **4-Source Identity Pills**, how to stream waveform audio and `Live/Motion Photos`, and how to stitch multi-app suspect negotiations into a single **"Follow the Suspect" Cross-Platform Hopping Timeline** from first principles.

---

## 1. Purpose & Mental Model (Why Flat SQLite Tables Fail Investigators in Conspiracy & Fraud Cases)

When an Investigating Officer (IO), Public Prosecutor, or Trial Judge examines digital communications in a cyber-fraud, narcotics, extortion, or terror conspiracy case, reading messages inside a flat spreadsheet grid (`Row | Timestamp | Sender | Receiver | Text`) destroys three critical layers of human and forensic context:

1. **Conversational Threading & Visual Context Loss:**
   * Modern messaging is non-linear. Inside a 200-member Telegram or WhatsApp syndicate group, five different sub-conversations happen simultaneously via **Swipe-to-Reply Quotes (`message_quoted`)**, **Emoji Reactions (`👍` confirming a hawala drop)**, **Forwarded Hop Chains (`forwarding_score >= 5`)**, **Inline Bot Keyboards (`TL_ReplyInlineMarkup` scam/betting URLs)**, **Voice Notes (`.opus` / `SILK v3`)**, and **In-Chat UPI / Crypto Transfers**. In a flat spreadsheet, a message saying `"Yes, send it to this one"` is meaningless unless visually anchored to the quoted parent message or bank QR image it replied to!
2. **The "Edit & Delete for Everyone" Cover-Up:**
   * Suspects routinely edit sent messages (changing an incriminating bank account number or crypto address to innocent text after the recipient copies it) or click **"Delete for Everyone" (Revoke)** in WhatsApp, Telegram, Signal, or SimpleX.
   * While **Phase 5 (Modules 5.1–5.5)** recovers the original pre-edit and pre-revoke text from `-wal` frames, B-Tree freelist pages, rolling `.crypt15` backups, `message_quoted` reply survivors, and modded APK (`GBWhatsApp`/`AyuGram`) tables, displaying the deleted record in a separate "Carved Table" forces the examiner to mentally stitch the timeline together. **Module 9.2 renders the recovered pre-edit/pre-revoke text directly inline inside the conversation bubble using high-contrast Redline Strikethrough Diffs!**
3. **Cross-Platform Evasion ("App-Hopping"):**
   * Real-world perpetrators initiate contact on **OLX**, **IndiaMART**, **Tinder**, **Bumble**, or **Instagram** $\rightarrow$ move to **WhatsApp** to share a voice note $\rightarrow$ jump to **Telegram Secret Chat** or **Session (`05...`)** to share a mule bank account $\rightarrow$ and settle funds on **PhonePe** or **Binance P2P**.
   * **Sub-Engine 9.2D ("Follow the Suspect" Mode)** fuses all communications, voice/video calls, and financial transfers between the device owner and any resolved **Master Entity (`Module 8.1A`)** into a single chronological chat stream with explicit **Platform-Switch Transition Banners**.

---

## 2. The 6 Fatal UI/UX & Engineering Mistakes in Forensic Chat Viewers

Before implementing Module 9.2, the developer must understand six critical engineering traps that break existing forensic chat interfaces:

### Mistake 1: Using Fixed-Height Virtualization on Variable-Height Chat Bubbles (Scroll Jumping & Overlapping Bubbles)
* **The Trap:** Reusing a fixed-row-height table virtualizer ($h_{\text{row}} = 36\text{ px}$) for a chat bubble view where Row 1 is a 1-line `"OK"` bubble ($48\text{ px}$ tall), Row 2 is a 40-line pasted hawala ledger ($850\text{ px}$ tall), and Row 3 is an inline Aadhaar card image with a quoted reply ($420\text{ px}$ tall).
* **Why It Fails:** If the virtual scroller assumes every bubble is $80\text{ px}$ tall ($S_{\text{top}} / 80$), scrolling rapidly or jumping to a bookmarked message in a $250,000\text{-message}$ Telegram supergroup causes violent scroll-position jumping, overlapping DOM nodes, and blank white gaps as variable-height bubbles mount and resize!
* **The Rule:** Implement **Dynamic Fenwick-Tree (Binary Indexed Tree) Prefix-Sum Height Virtualization** (Section 3.2), which tracks exact measured bubble heights $h_i$ in $O(\log N)$ time and resolves the exact visible bubble index $i_{\text{first}}$ for any pixel scroll offset $S_{\text{top}}$ via binary lifting in $< 0.05\text{ milliseconds}$!

### Mistake 2: Rendering Edited or Revoked Messages as Disconnected Duplicate Bubbles Instead of Inline Myers-Diff Redlines
* **The Trap:** When a message (`key_id = "3EB09988"`) has both an active row (`"Send 5 documents"`) and two earlier WAL/revision rows (`"Send 5 Lakh cash"` and `"Send 5 BTC to bc1q..."`), rendering three separate chat bubbles on screen.
* **Why It Fails:** Rendering three separate bubbles makes it look like the suspect sent three distinct messages, confusing the investigator and the court.
* **The Rule:** Group all revisions sharing the same `native_message_id` / `key_id` into a **Single Composite Forensic Bubble** featuring an interactive **Revision History Pill (`[Edited: 3 Versions | WAL + Revision Table]`)** and an inline **Word/Grapheme Myers Diff Redline View** (Section 4.1 & Section 4.2)!

### Mistake 3: Failing to Render Quoted-Reply Parent Previews & "Orphan Quote Survivor" Reconstruction Cards
* **The Trap:** Displaying `quoted_parent_key_id = "3EB01122"` as a raw ID string inside a reply bubble instead of rendering the embedded parent message card, OR failing to insert a reconstructed placeholder bubble at the parent's original timestamp when the parent message itself was purged from `message` but survived inside `message_quoted`!
* **Why It Fails:** As established in **Phase 5, Module 5.1B (Mistake 2)**, when a sender deletes a message for everyone and the `-wal` checkpoints, the verbatim text of that deleted message often survives **only inside a later reply's `message_quoted` row**.
* **The Rule:** Sub-Engine 9.2B renders the quoted preview box inside the reply bubble (clicking it smooth-scrolls to the parent bubble and flashes a cyan border) **and** inserts a **`[RECONSTRUCTED FROM SURVIVING QUOTED REPLY]`** ghost bubble at the original parent timestamp in the timeline!

### Mistake 4: Displaying Raw `@lid` (`164829...@lid`), `05...` Session IDs, or Unsaved Numbers Without Inline 4-Source Unmasking Pills
* **The Trap:** Rendering a group chat bubble header simply as `"164829104928172@lid"` or `"+919876543210"` when the number is not saved in the suspect's phonebook.
* **Why It Fails:** The investigator has to copy the `@lid` or phone number and search three other tables to find out who is speaking.
* **The Rule:** Every chat bubble header in Module 9.2 binds to **Module 8.1A (`entity_master_profiles`)** and renders a compact, color-coded **4-Source Attribution Header** (Section 5.1) showing:
  1. **Unmasked Phone (`@lid` $\rightarrow$ `+919876543210`)**
  2. **Self-Assigned Push Name (`~ Vikram Boss`)**
  3. **Truecaller Unmasked Name (`Vikram Crypto OTC [Spam: 85]`)**
  4. **Verified Bank CBS / KYC Name (`VIKRAM KUMAR SINGH [HDFC / PAN Verified]`)**!

### Mistake 5: Blocking the UI Thread or Requiring External Media Players for `.opus`, `.ogg`, `.amr` & `SILK v3` Voice Notes
* **The Trap:**Forcing the investigator to click "Export File" and open VLC externally to listen to a WhatsApp `.opus`, Telegram `.ogg`, or WeChat `SILK v3` / `.amr` voice note.
* **Why It Fails:** In a chat thread containing 150 back-and-forth voice notes between a mule handler and a field operative, exporting 150 audio files one by one makes review impossible.
* **The Rule:** Sub-Engine 9.2C includes an **Inline Canvas Waveform Player** (backed by an offline `FFmpeg`/`WebAudio` worker pipeline that transcodes proprietary `SILK v3` and `.amr` streams into standard PCM/WAV in the `derivative_staging_ledger` and pre-computes 64-bar peak envelopes) paired with **Interactive Offline Voice-to-Text Transcripts** (Section 5.2)!

### Mistake 6: Losing Pane 3 Hex/Provenance Synchronization Inside Chat Bubbles
* **The Trap:** Making the chat view a "read-only pretty view" that disconnects from **Module 9.1's Pane 3 (Courtroom Provenance Card & Synchronized Hex Viewer)**.
* **The Rule:** Clicking any chat bubble, any revision inside a redline diff, any emoji reaction pill, or any inline media/payment card in Module 9.2 immediately updates **Pane 3A (3-Tier `SHA-256` + `MD5` Lineage)** and jumps **Pane 3B (Hex Viewer)** to the exact physical byte offset of that message cell in `msgstore.db`, `cache4.db`, `signal.db`, or `-wal`!

---

## 3. Step 1 — Sub-Engine 9.2A: The 3-Column Conversational Workspace & Dynamic Fenwick-Tree Virtual Scroller

### 3.1 Architectural Layout of the Unified Chat Workspace

```
+----------------------------------------------------------------------------------------------------------+
| [Mode: (o) Single-App Threads  (*) Unified Actor Multi-App Stitching] [Search in Thread: "UTR" ] [Export]|
+----------------------------+---------------------------------------------------+-------------------------+
| COLUMN 1: THREAD & ACTOR   | COLUMN 2: 60 FPS VARIABLE-HEIGHT CHAT STREAM      | COLUMN 3: SYNCHRONIZED  |
| ROSTER (Filterable)        | [Header: Vikram Singh | +919876543210 | 4 Apps ]  | PANE 3 PROVENANCE &     |
| [All] [Deleted] [OpSec]    | [App Filter Pills: [WA 42] [TG 19] [Session 8] ]  | THREAD INTELLIGENCE     |
|----------------------------|---------------------------------------------------|-------------------------|
| * Vikram Singh [4 Apps]    |   --- [PLATFORM HOP: OLX -> WhatsApp (Clone999)]  | [Tab: Provenance & Hex] |
|   +919876543210 | @vik_otc |                                                   | [Tab: Shared Media (38)]|
|   [12 Revoked] [₹4.5L UPI] | [In] ~ Vikram Boss | [TC: Vikram OTC] [14:02 IST] | [Tab: Extracted Links/  |
|----------------------------| +-----------------------------------------------+ |       UTRs/Crypto (14)] |
| * Hawala Group [TG Super]  | | [WAL-REVOKED: Deleted for Everyone at 14:05]  | |-------------------------|
|   ID: -1001928374 | 412 Mbr| | "Send Rs 95,000 to [-981122@ybl-] [+9876@ybl+]"| | • Source: msgstore-wal  |
|   [Creator: SELF] [89 Del] | | [Rev 1 (WAL #88)] -> [Rev 2 (Edited)] [Hex >] | | • SHA256: 8f3a...91c2   |
|----------------------------| +-----------------------------------------------+ | • Offset: 0x0041A2B0    |
| * TELEGRAM SAVED MESSAGES  |                                                   |-------------------------|
|   (SELF CLOUD VAULT)       | [Out] Device Owner (User 999)         [14:04 IST] | 0041A2B0: [53 65 6E 64  |
|   [3 BIP-39 Seeds Found!]  | +-----------------------------------------------+ | 20 52 73 20 39 35 2C 30 |
|----------------------------| | |> ||||.|..||.| 0:18 / 0:18 [1.5x] [.opus]    | | 30 30 20 74 6F 20 39 38]|
| * 05a1b2c3... [Session ID] | | [Transcript: "Bhai payment kar diya UTR..."]  | | [12-Format Interpreter] |
+----------------------------+---------------------------------------------------+-------------------------+
```

### 3.2 Mathematical Specification of the Dynamic Fenwick-Tree (Binary Indexed Tree) Variable-Height Virtual Scroller

Why is a **Fenwick Tree (`Binary Indexed Tree` — `BIT`)** required for forensic chat virtualization?
In a mega-group or channel containing $N = 500,000$ messages, each message bubble $i \in \{1, 2, \dots, N\}$ has an arbitrary vertical height $h_i$ (ranging from $48\text{ px}$ for a short text bubble to $900\text{ px}$ for a multi-paragraph bot message with inline buttons and an image).

1. **Deterministic Initial Height Estimation ($h_{i,\text{est}}$) Before DOM Mounting:**
   Before bubble $i$ is ever scrolled into view, pre-compute its accurate estimated height $h_{i,\text{est}}$ in $O(1)$ time from its metadata row:
   $$h_{i,\text{est}} = H_{\text{chrome}} + \left\lceil \frac{\text{char\_len}(\text{text}_i)}{C_{\text{chars\_per\_line}}} \right\rceil \times L_{\text{line\_px}} + I_{\text{has\_quote}} \cdot H_{\text{quote}} + I_{\text{has\_media}} \cdot H_{\text{media}} + I_{\text{is\_edited\_or\_revoked}} \cdot H_{\text{redline\_banner}}$$
   *(where $H_{\text{chrome}} = 38\text{ px}$, $L_{\text{line\_px}} = 20\text{ px}$, $H_{\text{quote}} = 56\text{ px}$, $H_{\text{media}} = 240\text{ px}$, and $H_{\text{redline\_banner}} = 32\text{ px}$).*

2. **Maintaining the Fenwick Tree (`BIT[1..N]`) of Bubble Heights in $O(\log N)$ Time:**
   * Store an array $\text{BIT}[1 \dots N]$ of 32-bit integers where each node $\text{BIT}[k]$ stores the sum of heights for the range of length $\text{lowbit}(k) = k \ \& \ (-k)$ ending at index $k$.
   * The **Total Scroll Container Height** is $H_{\text{total}} = \text{PrefixSum}(N)$, and the **Exact Top Pixel Offset $Y_{\text{top}}(i)$ of Bubble $i$** is:
     $$Y_{\text{top}}(i) = \text{PrefixSum}(i - 1) = \sum_{k = i-1, \ k > 0, \ k \gets k - (k \& -k)} \text{BIT}[k]$$
   * When bubble $i$ enters the viewport and the browser's `ResizeObserver` measures its true rendered DOM height $h_{i,\text{actual}} \neq h_{i,\text{curr}}$, compute $\Delta h = h_{i,\text{actual}} - h_{i,\text{curr}}$ and update the Fenwick Tree in **at most $\lceil \log_2(500,000) \rceil = 19$ integer additions**:
     $$\text{For } k \gets i \text{ while } k \le N \text{ do: } \text{BIT}[k] \gets \text{BIT}[k] + \Delta h; \quad k \gets k + (k \ \& \ (-k))$$

3. **$O(\log N)$ Binary-Lifting Search to Find the First Visible Bubble $i_{\text{first}}$ for Any Scroll Offset $S_{\text{top}}$:**
   Given the user's current scroll position $S_{\text{top}}$ (in pixels), find the largest index $idx$ such that $Y_{\text{top}}(idx) \le S_{\text{top}}$ in exactly $19$ loop iterations without binary-searching prefix sums:
   * Initialize $\text{idx} = 0$ and $\text{accum\_px} = 0$.
   * For $p \gets 2^{\lfloor \log_2 N \rfloor}$ down to $1$ (halving $p \gets p \gg 1$ each step):
     $$\text{If } (\text{idx} + p \le N) \text{ AND } \big(\text{accum\_px} + \text{BIT}[\text{idx} + p] \le S_{\text{top}}\big) \text{ then:}$$
     $$\text{idx} \gets \text{idx} + p; \qquad \text{accum\_px} \gets \text{accum\_px} + \text{BIT}[\text{idx}]$$
   * Return $i_{\text{first}} = \text{idx} + 1$.

---

## 4. Step 2 — Sub-Engine 9.2B: Forensic Redline Diff Engine (Edited, Revoked, Disappearing & Quoted-Survivor Bubbles)

### 4.1 The 5 Forensic Chat Bubble Visual States

Every chat bubble rendered in Column 2 is styled according to its **Evidentiary Lifecycle State**:

| Bubble Lifecycle State | Visual Border, Header Badge & Content Rendering Rule |
|---|---|
| **1. `ACTIVE_UNMODIFIED_MESSAGE`** | Standard clean incoming (slate-dark left-aligned) or outgoing (indigo/teal right-aligned) bubble with `[LIVE]` badge and delivered/read (`Blue Tick` receipt timestamp tooltip from `receipt_user`). |
| **2. `EDITED_MESSAGE_WITH_REVISION_HISTORY`** | **Amber Left Border (`4px solid #F59E0B`)** + Header Badge: **`[EDITED: N Revisions Recovered]`**. Displays the **Inline Myers-Diff Redline Text** (strikethrough original tokens in crimson + inserted new tokens in emerald) and a clickable **Revision Stepper (`Rev 1 [14:01:02 IST - WAL Frame #44] -> Rev 2 [14:01:45 IST - Active]`)**! |
| **3. `REVOKED_DELETED_FOR_EVERYONE_RECOVERED`** | **Crimson Dashed Border (`2px dashed #EF4444`) + Tinted Crimson Background** + Header Badge: **`[DELETED FOR EVERYONE — RECOVERED VIA <WAL / QUOTED-REPLY / CRYPT15 / ANTI-REVOKE MOD>]`**. Displays the full recovered message text/media alongside the exact `revoked_timestamp` when the sender tried to wipe it! |
| **4. `REVOKED_TOMBSTONE_UNRECOVERED`** | Muted Crimson Outline + Header Badge: **`[DELETED FOR EVERYONE — TOMBSTONE ONLY]`**. Displays exact sender, timestamp, `key_id`, and deletion timestamp even when the payload was overwritten prior to seizure (proving a message was sent and destroyed at that exact second!). |
| **5. `EXPIRED_DISAPPEARING_OR_VIEW_ONCE_SURVIVOR`** | **Purple Border (`3px solid #A855F7`)** + Stopwatch Icon **`[EPHEMERAL TTL: 24h / VIEW-ONCE — SURVIVED IN <WAL / FREELIST / THUMBNAIL / SNAPSHOT>]`**. Renders the recovered text or links directly to the surviving `.ithmb` / `Glide` / `TaskSnapshot` visual capture from Module 7.2! |

### 4.2 Grapheme-Aware Myers Shortest-Edit-Script (`SES`) Diff Algorithm for Edited Messages

When a message has one or more historical revisions $T_{\text{old}}$ (from Signal `InteractionEditRecord` / `latest_revision_id`, WhatsApp `message_edit_info` + `-wal`, Telegram `edit_date` + `-wal`, or Discord `edited_timestamp` cache) and current text $T_{\text{new}}$:

1. **Step 1 (Unicode Grapheme & Word Tokenization):**
   * Segment $T_{\text{old}}$ and $T_{\text{new}}$ into arrays of tokens $A = [a_1, \dots, a_N]$ and $B = [b_1, \dots, b_M]$ using **Unicode Standard Annex #29 (`UAX #29`) Grapheme Cluster & Word Boundaries**.
   * **Why `UAX #29` Is Mandatory for Indian Forensics:** Splitting a Hindi (`Devanagari`) or Tamil word by raw UTF-16 code units or bytes slices a consonant away from its dependent vowel sign (`Matra`, e.g., `कि` $\rightarrow$ `क` + `ि`), producing broken, unreadable glyph fragments! Segmenting at `UAX #29` grapheme/word boundaries guarantees that Indic words, emojis (`👨‍👩‍👧‍👦`), and numbers (`9876543210` $\rightarrow$ `9811223344`) diff cleanly as whole visual units!
2. **Step 2 (Myers $O((N+M)D)$ Shortest Edit Script Computation):**
   * Compute the minimum edit distance $D$ and optimal alignment path over the $(A, B)$ edit graph:
     * **`EQUAL(token)`:** Rendered in normal high-contrast white text.
     * **`DELETE(token)` (Present in Original $T_{\text{old}}$, Removed in Edit $T_{\text{new}}$):** Rendered inline with a **Crimson Pill Background (`rgba(239, 68, 68, 0.25)`), Strikethrough Decoration, and `[-...-]` brackets** so it is legible even when printed in black-and-white!
     * **`INSERT(token)` (Added in Edit $T_{\text{new}}$):** Rendered inline with an **Emerald Pill Background (`rgba(16, 185, 129, 0.25)`), Bold Underline, and `[+...+]` brackets**!

---

## 5. Step 3 — Sub-Engine 9.2C: Inline Identity Unmasking Pills, Waveform Audio Player & Bot/Payment Cards

### 5.1 The 4-Source Identity Unmasking Header Pill

At the top of every incoming chat bubble (and in the Column 2 Thread Header), Module 9.2 queries the sender's resolved `entity_master_uid` (`Module 8.1A`) and renders a compact, interactive **Attribution Strip**:

$$\texttt{[Saved: Unknown]} \ \longrightarrow \ \texttt{[WA LID Unmasked: +91-9876543210]} \ \mid \ \texttt{[Push: \~ Vikram Boss]} \ \mid \ \texttt{[Truecaller: Vikram Crypto OTC (Spam: 85)]} \ \mid \ \texttt{[Bank CBS: VIKRAM KUMAR SINGH]}$$

* Clicking any pill opens a popover showing the **Deterministic Join Proof** (`Module 8.1A`): e.g., *"LID `164829104928172@lid` unmasked to `919876543210@s.whatsapp.net` via `msgstore.db -> jid_map` (Row #50); linked to CBS Name `VIKRAM KUMAR SINGH` via PhonePe VPA `9876543210@ybl`."*

### 5.2 Offline Voice-Note Transcoder, 60 FPS Canvas Waveform & Interactive Transcript Sync

For every voice note or audio attachment (`.opus`, `.ogg`, `.amr`, Tencent WeChat `SILK v3` `.aud`/`.amr` starting with `\x02#!SILK_V3`, `.m4a`, `.mp3`, `.wav`):
1. **Zero-Config Offline Decoding & Peak Envelope Generation:**
   * During ingestion (or on first thread open via local worker), any proprietary audio stream (`SILK v3` or `.amr`) is decoded into a standard `16 kHz` mono PCM/WAV derivative in `derivative_staging_ledger`, and a **64-sample normalized RMS peak array** $W = [p_1, p_2, \dots, p_{64}] \in [0.05, 1.0]$ is computed over equal time slices of the audio.
2. **Interactive Waveform & Word-Synced Transcript Bubble:**
   * Renders a 64-bar interactive canvas waveform inside the chat bubble with playback speed toggles (`1.0x`, `1.5x`, `2.0x`), volume normalization boost (`+12 dB` for whispered voice notes!), and an inline **Offline Speech-to-Text Transcript Drawer** (`Whisper` / `IndicConformer` offline model output) where clicking any word in the transcript seeks the audio player to that exact timestamp $(t_{\text{word\_start}})$!

### 5.3 Rich Forensic Sub-Cards Inside Chat Bubbles

1. **Telegram Bot Inline Keyboards (`TL_ReplyInlineMarkup` from Module 5.2B):**
   * Renders the exact grid of inline buttons below the bot message, exposing the **hidden destination URL or Mini-App WebView URL** directly inside each button (`[🎰 Deposit via UPI] -> https://lotus365-pay.xyz/pay?uid=4821`)!
2. **In-Chat Financial & Crypto Transfer Cards:**
   * Whenever a message is a native `WhatsApp Pay` UPI transfer (`Module 3.1D`), `WeChat Pay` red packet (`Module 5.4C`), or contains a validated **12-digit `UTR`** / **`T...` TRON address** / **`upi://pay` QR code** (`Module 7.3`), the bubble renders an embedded **Gold Financial Verification Card** showing the linked Phase 3/4 transaction status (`[SETTLED IN PHASE 3 LEDGER: ₹50,000.00 | UTR 630914829104]`) with a 1-click jump to the Financial Sankey Graph (`Module 9.3`)!

---

## 6. Step 4 — Sub-Engine 9.2D: The Cross-Platform Conversation Hopping ("Follow the Suspect") Timeline View

When the investigator switches the top workspace toggle from **`Single-App Threads`** to **`Unified Actor Multi-App Stitching ("Follow the Suspect")`** and selects any counterparty (`unified_actor_uid` / `entity_master_uid` from Module 5.5E / Module 8.1A):

1. **Unified Multi-App Chronological Stream:**
   * Column 2 merges every interaction between the device owner and that specific counterparty across **all 40+ communication, dating, marketplace, calling, and financial platforms** sorted by `timestamp_utc_ns ASC`:
     * Marketplace & Dating Initiation (`OLX`, `IndiaMART`, `Tinder`, `Bumble`, `Aisle`, `Shaadi.com`)
     * Standard & Cloned Messengers (`WhatsApp User 0`, `WhatsApp Clone 999`, `Telegram`, `Telegram Secret Chat`, `Signal`, `Instagram`, `Snapchat`, `Discord`)
     * High-OpSec & Cross-Border Apps (`Session`, `SimpleX Chat`, `Zangi`, `Threema`, `Botim`, `IMO`, `WeChat`)
     * Cloud Dead-Drops (`Shared Google Keep`, `Google Docs`, `Apple Notes`, `Shared Gmail Drafts`)
     * Cellular & VoIP Call Bars (`calllog.db` & iOS `CallHistory.storedata` showing exact call duration and answered/missed status inline between chat messages!)
     * Financial & Crypto Transfers (`PhonePe`/`GPay`/`Bank` UPI/IMPS transfers & `Binance P2P` escrow chats with that actor!)
2. **Automated Platform-Switch Transition Banners (`is_platform_switch_hop == 1`):**
   * Whenever consecutive events $(E_{k-1}, E_k)$ with the counterparty occur on **different applications** ($\text{App}(E_k) \neq \text{App}(E_{k-1})$), Sub-Engine 9.2D injects a high-visibility **Platform-Switch Divider Banner** across the chat stream:
     $$\texttt{⚡ PLATFORM SWITCH DETECTED (+3m 12s): [OLX India Chat] } \longrightarrow \texttt{ [WhatsApp Business (Clone 999)] } \longrightarrow \texttt{ [Session (05a1b2...)]}$$
   * If Event $E_{k-1}$ contained an explicit handoff link or phone number (e.g., *"Delete this chat and text me on Session `05a1b2...`"*), the banner highlights the exact handoff token that bridged the two platforms!

---

## 7. Local UI State Schema & FastAPI IPC Contract for Module 9.2

### Table 1: `chat_media_waveforms_and_transcripts_cache` (Pre-Computed Audio Envelopes & Offline Voice-Note Transcripts)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `audio_cache_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `.opus`, `.ogg`, `.amr`, or `SILK v3` file in `vfs_index`. Indexed! |
| `playable_wav_staging_id` | `INTEGER` | `NULL` | Foreign key to transcoded PCM/WAV file in `derivative_staging_ledger`. |
| `duration_seconds` | `REAL` | `NOT NULL` | Exact audio duration in seconds. |
| `waveform_64_peaks_json` | `TEXT` | `NOT NULL` | JSON array of 64 normalized float peak values $[0.05, 1.0]$ for instant 60 FPS canvas rendering. |
| `offline_stt_transcript_text` | `TEXT` | `NULL` | Full offline speech-to-text transcript (indexed into Module 8.2D's `FTS5` tables!). |
| `word_timestamps_json` | `TEXT` | `NULL` | JSON array of `{"word":"UTR","start_s":4.2,"end_s":4.8}` for synced audio-text clicking. |

### Table 2: FastAPI $\leftrightarrow$ Electron Renderer IPC Endpoints for Module 9.2

| Endpoint Method & Path | Request Parameters / Payload | Response Format & Latency Target |
|---|---|---|
| **`GET /api/v1/chat/roster`** | `mode = "SINGLE_APP" \| "UNIFIED_ACTOR"`, `filter_flags` | Sorted list of threads or Unified Actors with badge counts (`total_msgs`, `deleted_revoked_count`, `platform_hops_count`, `total_inr_transferred`). Target: `< 15 ms`. |
| **`GET /api/v1/chat/messages-slice`** | `thread_or_actor_id`, `mode`, `center_ts_ns` or `cursor_uid`, `limit = 150` | Keyset-paginated message array with pre-computed `myers_diff_tokens_json`, `quoted_parent_object`, `unmasked_identity_pill_json`, and `estimated_height_px`. Target: `< 20 ms`. |
| **`GET /api/v1/chat/thread-intelligence`** | `thread_or_actor_id`, `mode` | Aggregated sidebar summary for Column 3: all shared media thumbnails, all extracted URLs/bot buttons, and all 12-digit UTRs / VPAs / Crypto addresses found in the thread. Target: `< 15 ms`. |

---

## 8. Developer Acceptance Test Checklist for Module 9.2

1. **The 500,000-Message Fenwick-Tree Variable-Height Scroll & Jump Test:**
   * Load a synthetic Telegram supergroup thread containing $500,000$ messages with heights varying randomly between $48\text{ px}$ and $800\text{ px}$. Click a search hit at Message #342,109.
   * Verify that the Fenwick Tree (`BIT`) binary-lifting lookup resolves the exact pixel offset in $< 1\text{ ms}$, mounts the surrounding 40 bubbles without scroll jumping or overlapping DOM nodes, and updates `ResizeObserver` height deltas in $O(\log N)$ time at $60\text{ FPS}$.
2. **The Grapheme-Aware Myers-Diff Redline & Orphan Quoted-Reply Survivor Test:**
   * Load an edited Signal/WhatsApp message where Revision 1 was `"Send ₹50,000 to 9811223344@ybl"` and Revision 2 was `"Send ₹5,000 to 9988776655@ybl"`, plus a revoked message (`text_data = NULL`) whose text `"Meet at Gate 4 with cash"` survived inside a subsequent reply's `message_quoted` row.
   * Verify that the edited bubble renders inline crimson strikethrough `[-₹50,000-]` / `[-9811223344@ybl-]` alongside emerald `[+₹5,000+]` / `[+9988776655@ybl+]`, and the revoked parent message renders inline as a `[RECONSTRUCTED FROM SURVIVING QUOTED REPLY]` bubble!
3. **The 4-Source Identity Unmasking Pill & Synchronized Pane 3 Hex Jump Test:**
   * Click a WhatsApp group message sent by `"164829104928172@lid"`.
   * Verify that the bubble header displays the unmasked phone `+91-9876543210`, Push Name, Truecaller name, and Bank CBS name, and simultaneously jumps **Pane 3B's Hex Viewer** to the exact byte offset of that message in `msgstore.db`!
4. **The 5-App Cross-Platform Conversation Hopping ("Follow the Suspect") Test:**
   * Toggle **`Unified Actor Multi-App Stitching`** for Actor `"Vikram Singh"`.
   * Verify that Column 2 renders the chronological sequence across `OLX Chat` $\rightarrow$ `Cellular Call (2m 14s)` $\rightarrow$ `WhatsApp Clone 999` $\rightarrow$ `Session (05a1b2...)` $\rightarrow$ `PhonePe ₹50,000 UPI Transfer`, inserting high-visibility `⚡ PLATFORM SWITCH DETECTED` banners at each app transition!