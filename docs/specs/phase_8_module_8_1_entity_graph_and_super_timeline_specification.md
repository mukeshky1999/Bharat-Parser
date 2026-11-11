# Engineering Specification: Phase 8, Module 8.1 — The Cross-Phase Entity Resolution, Master Identity Graph & Unified Super-Timeline Engine

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 8.1** of the Forensic Data Parser (the foundational convergence engine of **Phase 8**, synthesizing all outputs from **Phases 1 through 7**). It contains **zero programming code** and explains how to deterministically resolve fragmented identifiers across 12 canonical join keys into a unified **Master Entity Graph (`entity_master_graph`)** without false-positive transitive merging, how to normalize tens of millions of heterogeneous device events into a single **Nanosecond-Normalized Unified Super-Timeline (`unified_super_timeline`)** with dual `UTC` and `IST (+05:30)` indexing, and how to automatically detect multi-subsystem **60-Second "Action-Burst" Crime Sequences** from first principles.

---

## 1. Purpose & Mental Model (Why Siloed Phase Tables Fail Without a Deterministic Graph & Super-Timeline)

By the time **Phases 1 through 7** finish executing on a seized 512 GB or 1 TB smartphone extraction, the case database contains over 80 specialized relational tables holding millions of decoded records:
* **Phase 1 & 2** hold VFS file nodes, dual hashes, unwrapped cryptographic keys, and carved SQLite WAL/freelist records.
* **Phase 3** holds UPI transfers, 25 bank app ledgers, NPCI SIM-binding `ICCID`s, unlocked bank statement PDFs, and TRAI DLT financial SMS rows.
* **Phase 4** holds `TronLink`/`MetaMask`/`Trust Wallet`/`Cake Wallet` transactions, `Binance`/`Bybit`/`CoinDCX` P2P orders, `WalletConnect v2` sessions, and `BIP-39` derived addresses.
* **Phase 5** holds WhatsApp (`@lid`), Telegram (`TL-Schema`), Signal, `Session`, `SimpleX`, `Zangi`, `Botim`, `Instagram`, `Snapchat`, `Truecaller`, and `Google Keep` dead-drop communications.
* **Phase 6** holds iOS (`knowledgeC`, 84 Biome streams, `tracev3`, `HealthDB`, `FSEvents`) and Android (`UsageStats`, 3-source `AppOps`, `Health Connect`) behavioral telemetry, 4-tier geolocation fixes, `Zomato`/`Blinkit`/`Uber`/`IRCTC`/`Tinder` records, and Root/Trojan/Clock-Tamper audits.
* **Phase 7** holds `Photos.sqlite` / `external.db` provenance, `SplashBoard` / `TaskSnapshots`, `.ithmb` thumbnails, UIDAI Aadhaar Secure QR unpacks, forged receipt audits, and OCR-extracted `PAN`/`Aadhaar`/`Passbook`/`Cheque` records.

If these 80+ tables remain separate silos, an Investigating Officer (IO) or forensic analyst faces two insurmountable cognitive bottlenecks:

1. **The "Fragmented Suspect Persona" Problem:**
   * The same syndicate accomplice (`"Vikram Singh"`) appears as `+919876543210` in Android Call Logs, `164829104928172@lid` in a WhatsApp group, `@vikram_otc` in Telegram, `9876543210@ybl` in PhonePe, `Seller Nickname: FastCrypto_IN` in a Binance P2P order, `Account 50100482910421 (HDFC)` in an OCR-scanned cancelled cheque photo, and `Flat 1404, Tower B2` in a Blinkit delivery address!
   * **Module 8.1A & 8.1B** mathematically fuse all of those disparate identifiers into a single **Master Entity Node (`entity_master_profile`)**, while recording the exact **Cryptographic / Deterministic Evidence Chain** that proves why each identifier belongs to that person.
2. **The "Cross-Subsystem Blindness" Problem:**
   * A chat message in Phase 5, a foreground app transition in Phase 6, a microphone access in `appops/discrete`, a UPI debit in Phase 3, and a `TaskSnapshot` screen capture in Phase 7 all happened within **45 seconds of each other**, but live in five different databases with four different timestamp epochs (`Unix ms`, `Unix s`, `Cocoa s`, `Mach ticks`).
   * **Module 8.1C & 8.1D** merge every timestamped artifact from Phases 1–7 into a single **64-bit Nanosecond UTC + Local IST Super-Timeline** and automatically cluster rapid multi-phase events into human-readable **"Action-Burst" Story Blocks**.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Entity Resolution & Forensic Timelining

Before implementing Module 8.1, the developer must understand six critical traps that corrupt forensic graphs and timelines:

### Mistake 1: Transitive Merging on "Weak / Non-Unique Keys" (The `"Rahul"` Snowball Catastrophe)
* **The Trap:** Running a naive Connected Components (Union-Find) algorithm where two records are merged into the same Entity Node if they share **either** a phone number **or** a display name (`"Rahul"`, `"Boss"`, `"Admin"`, `"Customer Care"`) **or** a shared city/address.
* **Why It Fails:** Suppose Contact A (`+919811111111`, saved as `"Rahul"`) and Contact B (`+919822222222`, also saved as `"Rahul"`) both exist in the phonebook. If your Union-Find algorithm allows `display_name == "Rahul"` to act as a transitive merge key, it merges Contact A and Contact B into a single person—contaminating every bank transfer, chat message, and location visit of both people!
* **The Rule:** Enforce the **Two-Tier Key Hierarchy (`TIER_1_HARD_UNIQUE_KEYS` vs. `TIER_2_SOFT_ATTRIBUTE_KEYS`)** in Section 3.1:
  * **ONLY `TIER_1_HARD_UNIQUE_KEYS`** (normalized E.164 phone number, unmasked `@lid`, exact VPA, exact Bank Account, exact `PAN`, exact `Aadhaar`, exact Crypto Address, exact Platform User ID, or explicit In-Chat Handoff Edge) may trigger an automated **Entity Node Merge**!
  * **`TIER_2_SOFT_ATTRIBUTE_KEYS`** (Display Name, Push Name, DOB, Pincode, Shared Wi-Fi `BSSID`, Shared Delivery Flat) are attached as **Queryable Attributes & Co-Location Edges**, **never** as transitive identity merge keys!

### Mistake 2: Merging Shared "Mule Pool" Bank Accounts Into the Identity of Every Payer
* **The Trap:** Merging two actors into one person because both actors sent money to (or shared a screenshot of) the same beneficiary bank account or crypto wallet address.
* **Why It Fails:** Two different victims (or two different sub-mules) sending ₹50,000 to the same bookie account `9988776655@ybl` does **not** mean the two senders are the same person—it means they share a **`TRANSACTED_WITH` Directed Financial Edge** to the owner of `9988776655@ybl`!
* **The Rule:** Distinguish **Identity Equivalence Edges (`SAME_ENTITY_AS`)** from **Interaction / Relationship Edges (`SENT_MONEY_TO`, `MESSAGED_WITH`, `CO_LOCATED_WITH`, `SENT_KYC_DOC_OF`)** in the Master Graph (Section 3.3).

### Mistake 3: Losing Precision or Overflowing When Sorting Mixed-Epoch Timestamps
* **The Trap:** Converting `int64` nanosecond timestamps into floating-point `double` (`REAL`) seconds for sorting in the Super-Timeline.
* **Why It Fails:** An IEEE-754 64-bit float (`double`) has only $53\text{ bits}$ of significand precision ($\approx 9 \times 10^{15}$). A 2026 Unix nanosecond timestamp is $\approx 1.762 \times 10^{18}$ ($61\text{ bits}$)! Converting a 64-bit nanosecond integer to `float64` loses the lower $8\text{ bits}$ ($\approx 256\text{ nanoseconds}$) of precision, scrambling the sub-microsecond order of kernel `tracev3` logs, `FSEvents`, and SQLite `-wal` frame commits!
* **The Rule:** Store and index the primary sorting key of `unified_super_timeline` as a **signed 64-bit integer (`INTEGER` in SQLite, `int64` in memory) representing exact UTC Nanoseconds since `1970-01-01 00:00:00 UTC` (`timestamp_utc_ns`)**, accompanied by a separate `timestamp_precision_tier` column (`NANOSECOND`, `MICROSECOND`, `MILLISECOND`, `SECOND`, `BRACKETED_WINDOW`)!

### Mistake 4: Failing to Separate "Event Occurrence Time" From "Database Write / Sync Time" in the Super-Timeline
* **The Trap:** Inserting only one row into the Super-Timeline when an artifact has two distinct forensic timestamps (for example, a photo captured on `2026-10-15` that was saved into WhatsApp or `Photos.sqlite` on `2026-11-05`, or an Apple Watch step sample recorded at `02:10 AM` that synced to `healthdb_secure.sqlite` at `06:00 AM`).
* **Why It Fails:** Both timestamps are forensically vital! The **Capture Time (`2026-10-15`)** proves when the physical photo was taken; the **Library Import / Receive Time (`2026-11-05`)** proves when the suspect received or downloaded the photo during the crime window!
* **The Rule:** Whenever an artifact has distinct `occurrence_utc_ns` and `committed_or_synced_utc_ns` timestamps (differing by $> 60\text{ seconds}$), emit **two linked timeline entries** (`EVENT_OCCURRED_OR_CAPTURED` and `ARTIFACT_IMPORTED_OR_SYNCED_TO_DB`) referencing the same `source_record_uid`!

### Mistake 5: Polling SQLite Tables With `UNION ALL` at UI Query Time Instead of Materializing `unified_super_timeline`
* **The Trap:** Trying to build a "Unified Timeline" view in the UI by running a massive 60-table `SELECT ... UNION ALL SELECT ... ORDER BY timestamp` query on the fly when the examiner clicks the Timeline tab.
* **Why It Fails:** Running a 60-way `UNION ALL` with `ORDER BY` over $15,000,000$ rows across 8 SQLite files forces SQLite to build a multi-gigabyte temporary B-tree on disk for every single filter change, freezing the UI for $30\text{ to }120\text{ seconds}$!
* **The Rule:** Materialize `unified_super_timeline` once during Phase 8.1 batch ingestion with composite B-tree covering indexes (`(timestamp_utc_ns ASC, timeline_event_uid ASC)`) so Phase 9's UI can scroll through $20,000,000$ events in $< 5\text{ milliseconds}$ using keyset pagination!

### Mistake 6: Stripping the 5D Evidentiary State Badge (`LIVE` vs. `WAL` vs. `FREELIST` vs. `CARVED`) When Aggregating Into the Graph
* **The Trap:** Displaying a merged Entity Card or Timeline row without showing whether the underlying link came from an active table (`ORIGINAL_RECORD`) or from a deleted B-tree freelist page (`RESIDUAL_RECORD`).
* **Why It Fails:** In court, knowing that the link between Suspect A and Bank Account B was **deleted by the suspect and recovered from `msgstore.db-wal` Frame #412** is proof of **mens rea (consciousness of guilt / destruction of evidence)**!
* **The Rule:** Every node, edge, and timeline event in Module 8.1 must preserve and propagate its **Phase 1.4 6-State Recovery Classification** and **5D Evidentiary Vector**.

---

## 3. Step 1 — Sub-Engine 8.1A: The 12-Key Deterministic Identity Resolution & Graph Union-Find Engine

### 3.1 The 12 Canonical `TIER_1_HARD_UNIQUE_KEYS` (Permitted to Merge Entity Nodes)

Sub-Engine 8.1A extracts every identity-bearing record across Phases 1 through 7 and normalizes its identifiers into **12 Canonical Hard Key Namespaces**:

| Hard Key Namespace ID | Canonical Key Format Example | Upstream Phase & Module Sources |
|---|---|---|
| **1. `PHONE_E164`** | `phone:+919876543210` (or `phone_tail10:9876543210` for domestic Indian numbers) | • Phase 1/2/5: `contacts2.db`, `AddressBook.sqlitedb`, `calllog.db`, `CallHistory.storedata`, `mmssms.db`<br>• Phase 3: `telephony.db` (`siminfo`), UPI VPA mobile prefixes (`9876543210@ybl`), Bank KYC<br>• Phase 4: CEX KYC & P2P chat phone numbers<br>• Phase 5: WhatsApp (`@s.whatsapp.net` & unmasked `@lid`), Telegram (`TL_user.phone`), Signal (`e164`), Truecaller (`tc.db`), Burner VoIP (`TextNow`)<br>• Phase 6: `Blinkit`/`Swiggy`/`Zomato`/`Uber`/`IRCTC`/`Shaadi.com` recipient & driver phones<br>• Phase 7: UIDAI Aadhaar Iterative SHA-256 unmasked mobile & OCR text |
| **2. `WHATSAPP_JID_OR_LID`** | `wa_jid:919876543210@s.whatsapp.net` $\leftrightarrow$ `wa_lid:164829104928172@lid` | • Phase 5.1: `msgstore.db` (`jid`, `jid_map`, `lid_display_name`) & `wa.db` (`wa_contacts`) |
| **3. `TELEGRAM_USER_ID`** | `tg_uid:5566778899` $\leftrightarrow$ `tg_handle:@vikram_hawala` | • Phase 5.2: `cache4.db` (`users.data` `TL_user`, `enc_chats`, `userconfing.xml`), iOS `postbox` `t2` |
| **4. `SIGNAL_ACI_OR_PNI`** | `sig_aci:a1b2c3d4-...` $\leftrightarrow$ `sig_user:@vikram.01` | • Phase 5.2D: `signal.db` (`recipient`), iOS `Signal.sqlite` (`model_SignalRecipient`) |
| **5. `OPSEC_CRYPTO_HANDLE`** | `session:05a1b2...`, `zangi:10-4829-1049`, `threema:X9K2M4P8`, `matrix:@user:server` | • Phase 5.3: `session.db`, `simplex_v1_chat.db`, `zangi`, `threema4.db`, `element` |
| **6. `SOCIAL_OR_DATING_UID`** | `ig_pk:17841405829`, `fb_uid:1000048291`, `snap_uuid:...`, `discord_id:1303377...`, `tinder_id:...` | • Phase 5.4 & Phase 6.4: `direct.db`, `msys_database`, `arroyo.db`/`main.db`, Discord `Simple Cache`, `tinder-3.db`, `Bumble.db`, `Shaadi.com` |
| **7. `UPI_VPA_HANDLE`** | `vpa:vikramsingh99@okaxis` (lowercase normalized) | • Phase 3: `PhonePe`, `GPay`, `Paytm`, `BHIM`, `Cred`, `WhatsApp Pay`, DLT SMS<br>• Phase 4.2: Binance/Bybit P2P payment methods<br>• Phase 7.3/7.4: Decoded `upi://pay` QR codes & payment receipt OCR |
| **8. `BANK_ACCOUNT_AND_IFSC`** | `bank:SBIN0004821:30984718291` (or `bank_tail4:SBIN:8291` when masked, upgraded when unmasked!) | • Phase 3.3 & 3.4: 25 Indian Banking Apps, unlocked Statement PDFs, DLT SMS<br>• Phase 4.2: CEX P2P & Indian FIU-IND penny-drop verified bank accounts<br>• Phase 7.4: Cancelled Cheque & Bank Passbook OCR |
| **9. `CRYPTO_WALLET_ADDRESS`** | `crypto:TRON:TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf` or `crypto:EVM:0x71C...` | • Phase 4.1–4.4: Self-custody wallets, `Ledger Live` `xpub`s, CEX withdrawals, `BIP-39` derived addresses<br>• Phase 7.3/7.4: Crypto QR codes & screenshot OCR |
| **10. `CEX_USER_OR_PAY_UID`** | `cex:BINANCE:482910482` | • Phase 4.2: `Binance`, `Bybit`, `KuCoin`, `MEXC`, `CoinDCX` (`MMKV`, SQLite, WebView `*_0`) |
| **11. `INDIAN_PAN_OR_GSTIN`** | `pan:ABCPS1234K` (including Characters $3\text{–}12$ of any `15-char GSTIN`!) | • Phase 3.3: Banking KYC & PDF statements<br>• Phase 4.2: Indian & Global CEX KYC (`userKycInfo`)<br>• Phase 6.4: `IndiaMART` (`gstin`), `Shaadi.com` / `TrulyMadly` KYC<br>• Phase 7.4: PAN Card & GST Certificate OCR |
| **12. `AADHAAR_OR_PASSPORT_ID`** | `aadhaar_full:234567890123` or `aadhaar_ref:4821:RAHUL_SHARMA:1995-08-15` or `passport:IND:Z4829104` | • Phase 6.4: `IRCTC` Master Passenger List, `DigiYatra` `IdentityVC`<br>• Phase 7.3 & 7.4: UIDAI Aadhaar Secure QR unpacks, Aadhaar Card OCR, ICAO 9303 Passport MRZ OCR |

### 3.2 The Constrained Disjoint-Set Union (`DSU`) Algorithm (Preventing False Merges)

To group identifiers into unified **Master Entity Nodes (`entity_master_uid`)** with zero false-positive contamination:

1. **Step 1 (Initialize Atomic Observations):**
   * Every individual identity record extracted by a Phase 1–7 module (e.g., Row #42 in `wa_contacts` containing `phone:+919876543210` and `wa_lid:164829104928172@lid`; or P2P Order #99 in Binance containing `cex:BINANCE:55443322`, `vpa:vikram@ybl`, and `kyc_name:"VIKRAM SINGH"`) is loaded as an **Atomic Observation Document $O_i$** containing a set of Hard Keys $\{k_{i,1}, k_{i,2}, \dots\} \subset \text{TIER\_1\_HARD\_UNIQUE\_KEYS}$.
2. **Step 2 (Union on Shared `TIER_1_HARD_UNIQUE_KEYS`):**
   * Two Atomic Observations $O_i$ and $O_j$ are merged into the same Master Entity Node **if and only if** they share at least one identical `TIER_1_HARD_UNIQUE_KEY` ($k \in O_i \cap O_j$), **subject to the Shared-Resource Guardrail below**:
   * **The Shared-Resource / Escrow Guardrail:**
     * If a `BANK_ACCOUNT_AND_IFSC`, `UPI_VPA_HANDLE`, or `CRYPTO_WALLET_ADDRESS` is flagged as a **Third-Party Triangulation P2P Account** (Module 4.2 Section 2 Mistake 4) or an **Unhosted Syndicate Pool Address** used by $> 3$ distinct KYC-verified names, that bank/wallet key is **promoted to a standalone `FINANCIAL_OR_CRYPTO_INSTRUMENT_ENTITY` node** and connected via directed `USED_INSTRUMENT` / `PAID_INTO` edges rather than collapsing two different human KYC profiles into one person!
3. **Step 3 (Union on Verified `IN_CHAT_HANDOFF_EDGES`):**
   * When Phase 5.3, 5.5, or 6.4 detects an explicit **First-Person Handoff Message** sent by Actor X in Platform A (e.g., `+919876543210` on WhatsApp or Tinder ID `T123` writing: *"Add my Session ID `05a1b2c3...`"* or *"Pay my UPI `vikram99@okaxis`"*), merge the sender's Platform A identity with the target handle in Platform B and record the exact `msg_uid` in `merge_proof_audit_json`!

---

## 4. Step 2 — Sub-Engine 8.1B: Typed Directed Edge Synthesis (Building the Forensic Knowledge Graph)

Once all Master Entity Nodes (`PERSON_ACTOR`, `DEVICE_OWNER_SELF`, `FINANCIAL_ACCOUNT_VPA`, `CRYPTO_WALLET`, `PHYSICAL_LOCATION_HIDEOUT`, `MALICIOUS_APK_OR_C2`) are resolved, Sub-Engine 8.1B constructs the **Typed Directed Edge Ledger (`entity_graph_edges_ledger`)** across 8 forensic relationship classes:

| Edge Relationship Type (`edge_verb`) | Source Node $\rightarrow$ Target Node | Aggregated Metrics Computed on the Edge |
|---|---|---|
| **1. `COMMUNICATED_WITH`** | `Actor A` $\leftrightarrow$ `Actor B` | Total message count, voice/video call count, total call duration (seconds), list of platforms used (`WhatsApp`, `Telegram Secret`, `Session`, `Botim`, `Tinder`), count of **deleted/revoked messages**, and `first_contact_utc` $\rightarrow$ `last_contact_utc`. |
| **2. `TRANSFERRED_FIAT_TO`** | `Actor / Account A` $\rightarrow$ `Actor / Account B` | Total INR volume (`₹`), transaction count, array of 12-digit `UTR`s, payment rails (`UPI`, `IMPS`, `NEFT`, `RTGS`), and whether flagged for **Circular Loop / Mule Pass-Through / Split-UPI Smurfing** (from Phase 3.5 & 4.4). |
| **3. `SETTLED_P2P_ESCROW_WITH`** | `Actor A (Buyer)` $\leftrightarrow$ `Actor B (Seller)` | CEX name (`Binance`/`Bybit`), total `INR` paid vs. total `USDT`/`BTC` released, P2P Order IDs, and whether flagged for **Third-Party Payer Triangulation**. |
| **4. `TRANSFERRED_CRYPTO_TO`** | `Wallet / Actor A` $\rightarrow$ `Wallet / Actor B` | Blockchain (`TRON_TRC20`, `BSC_BEP20`, `ETH`, `BTC`, `XMR`), total token volume (`USDT`, `TRX`, `XMR`), array of `txid`s / `Binance Pay ID`s / `FixedFloat` swap orders, and **TRON Energy Delegation** links! |
| **5. `OWNS_OR_CONTROLS_INSTRUMENT`** | `Actor A` $\rightarrow$ `Bank A/C, VPA, Crypto Wallet, or SIM ICCID` | Provenance proof (`"Penny-drop verified in CoinDCX"`, `"Derived from BIP-39 Seed in Apple Notes"`, `"SIM ICCID bound in NPCI CL"`, `"Printed on Cancelled Cheque OCR IMG_4102.JPG"`). |
| **6. `POSSESSED_KYC_DOCUMENT_OF`** | `Device Owner` $\rightarrow$ `Third-Party Mule / Victim Actor` | Links the suspect's phone to every person whose **Aadhaar Card, PAN Card, Passport, Voter ID, or Cancelled Cheque photo/PDF** was found on the device (distinguishing the device owner's own ID from collected mule/victim IDs!). |
| **7. `VISITED_OR_ORDERED_AT_LOCATION`** | `Actor A` $\rightarrow$ `Physical Location / Hideout Flat` | Links an actor (including third-party `Blinkit`/`Swiggy`/`Zomato` delivery recipients and `Uber` guest riders!) to an exact flat/address or GPS cluster, with arrival/departure windows and `BSSID` handshakes. |
| **8. `COMPROMISED_OR_CONTROLLED_BY`** | `Device / App` $\rightarrow$ `Attacker C2 / AnyDesk ID / Call-Forward Number` | Links sideloaded Trojan APKs to extracted **Telegram Bot C2 (`bot<TOKEN>` + `chat_id`)**, **Remote `AnyDesk` 9-digit Client IDs**, or **`*21*`/`*401*` Call-Forwarding numbers** (from Module 6.5E). |

---

## 5. Step 3 — Sub-Engine 8.1C: The Nanosecond-Normalized Unified Super-Timeline (`unified_super_timeline`)

Sub-Engine 8.1C ingests every timestamped record across **Phases 1 through 7** into a single, chronologically ordered table (`unified_super_timeline`) designed for instant keyset-paginated querying and cross-domain correlation.

### 5.1 Mandatory Dual-Timezone (`UTC` + `IST +05:30`) & Precision Normalization

For every event ingested from Phases 1–7:
1. **Primary Sorting Key (`timestamp_utc_ns`, `INTEGER` / `int64`):**
   * Exact 64-bit signed integer nanoseconds since `1970-01-01 00:00:00.000000000 UTC` (computed via Phase 1, Module 1.2's integer-math epoch converter).
2. **Human-Readable UTC & Indian Standard Time (`IST`) Columns:**
   * `timestamp_utc_iso`: `"YYYY-MM-DDTHH:MM:SS.fffffffffZ"`
   * `timestamp_ist_iso`: Computed by adding $+19,800,000,000,000\text{ nanoseconds}$ ($+05\text{:30:00}$) to `timestamp_utc_ns` and formatting as `"YYYY-MM-DD HH:MM:SS.mmm IST (+05:30)"`!
   * `recorded_device_tz_offset_sec`: Preserves the phone's actual local timezone offset at the moment of the event (e.g., `+19800` for India `IST` vs. `+14400` for Dubai `GST` from `knowledgeC.db` `ZSECONDSFROMGMT` or `EXIF OffsetTimeOriginal`).
3. **Timestamp Integrity & Clock-Tamper Badge (`clock_integrity_status`):**
   * Cross-checks the event against **Phase 6, Module 6.5B (`clock_tampering_and_deletion_gaps_ledger`)**:
     * `VERIFIED_NORMAL_CLOCK`: No monotonic sequence inversion detected.
     * `BRACKETED_NON_TIMESTAMPED_EVENT`: Event from `FSEvents` (`1SLG`/`2SLG`) or `LevelDB` sequence number bounded by `[bracket_earliest_utc, bracket_latest_utc]`.
     * `CRITICAL_CLOCK_ROLLBACK_SUSPECTED`: Event sits on an inverted `ROWID` / `.timesync` jump where the suspect manually rolled the wall clock backward!

---

## 6. Step 4 — Sub-Engine 8.1D: The Sliding-Window "Action-Burst" Behavioral Story Correlator

When a human examiner looks at $500,000$ raw timeline rows, they can easily miss the 15-second sequence where a crime actually occurred. Sub-Engine 8.1D slides a **60-second window ($\Delta t \le 60,000,000,000\text{ ns}$)** across `unified_super_timeline` and automatically emits high-level **Composite Forensic Story Blocks (`forensic_action_burst_stories`)** whenever events from **$\ge 3$ distinct forensic subsystems** co-occur within that window.

### Master Catalog of 6 Pre-Built Multi-Phase "Action-Burst" Crime Signatures

| Story Signature Code | Co-Occurring Multi-Phase Events Within $\Delta t \le 60\text{–}180\text{ Seconds}$ | Courtroom Narrative Automatically Generated |
|---|---|---|
| **1. `ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW`** | 1. **Phase 6.1/6.2:** Screen Unlocked (`KEYGUARD_HIDDEN` / `biometrickitd:FaceID Match`) + Physical Device Orientation = `Portrait (1)` + Steps/Touch active.<br>2. **Phase 6.1/6.2:** Banking/UPI or Crypto Wallet app enters Foreground (`ACTIVITY_RESUMED` / `/app/inFocus`).<br>3. **Phase 3 / Phase 4:** Outbound UPI/IMPS transfer (`UTR`) or `TRC-20` `USDT` transfer executes.<br>4. **Phase 6.3:** Simultaneous GPS/Wi-Fi `BSSID`/Cell `eNodeB` fix recorded. | **Defeats "Remote Hack / Someone Else Used My Phone" Defense:** Proves the suspect physically held the phone upright in their hand, unlocked it with their own FaceID/fingerprint, brought the payment app to the foreground, and executed the transfer at Location $(X, Y)$. |
| **2. `TROJAN_OR_REMOTE_ACCESS_SILENT_DRAIN`** | 1. **Phase 6.5E / 6.2:** Active `AnyDesk` session (`ad_svc.trace`) OR background `AccessibilityService` / `SYSTEM_ALERT_WINDOW` overlay (`appops/discrete`) active.<br>2. **Phase 3.4:** Incoming Bank OTP SMS arrives in `mmssms.db` / Notification ledger.<br>3. **Phase 6.2:** Malicious sideloaded APK accesses `READ_SMS` or `BIND_NOTIFICATION_LISTENER`.<br>4. **Phase 3:** Outbound bank debit occurs while screen is `Stationary / FaceUp` or controlled remotely. | **Corroborates Malware / Remote Access Compromise:** Proves that an active `AnyDesk` session or sideloaded SMS-stealer trojan intercepted the bank OTP and executed the debit. |
| **3. `CROSS_APP_COVERT_HANDOFF_AND_DELETION`** | 1. **Phase 5.1/5.4/6.4:** Chat in App A (`OLX`, `Tinder`, `Instagram`, or `WhatsApp`) contains an invite/handle for App B (`Session`, `SimpleX`, `Telegram`, `Zangi`).<br>2. **Phase 6.1/6.2:** Foreground focus immediately switches from App A to App B within $< 30\text{ seconds}$.<br>3. **Phase 5.1/6.4:** The initiating thread or match in App A is revoked/unmatched/deleted! | **Proves Intentional OpSec Escalation:** Demonstrates that the suspect initiated contact on a mainstream platform, moved the counterparty to a high-opsec messenger, and immediately deleted the initiating trace. |
| **4. `PAYMENT_SCREENSHOT_PROOF_TO_HANDLER`** | 1. **Phase 3 / Phase 4:** UPI transfer (`UTR`) or `TronLink` `USDT` transfer completes at $T_0$.<br>2. **Phase 6.1/7.1/7.2:** Screenshot captured (`SpringBoard` / `Screenshot_..._PhonePe.jpg` / `TaskSnapshot`) within $T_0 + 15\text{ seconds}$.<br>3. **Phase 5 / Phase 4.2:** That exact screenshot (matched by `SHA-256` or OCR `UTR`) is sent inside a WhatsApp, Telegram, Session, or Binance P2P chat within $T_0 + 60\text{ seconds}$! | **Proves Principal–Agent Reporting:** Links the financial/crypto transaction directly to the syndicate handler or P2P counterparty who demanded visual proof of payment. |
| **5. `P2P_ESCROW_TO_SELF_CUSTODY_VELOCITY_HOP`** | 1. **Phase 3:** Domestic UPI/IMPS outflow(s) to P2P seller.<br>2. **Phase 4.2:** Binance/Bybit P2P order releases `USDT` into CEX Funding Wallet.<br>3. **Phase 4.2 $\rightarrow$ 4.1:** Within $< 30\text{ minutes}$, the `USDT` is withdrawn over `TRC-20` to a local `TronLink Pro` / `Trust Wallet` address or swapped via `FixedFloat` into `Monero (XMR)`. | **Proves End-to-End Money Laundering Velocity:** Connects the domestic Indian banking rail directly to the unhosted blockchain exit wallet. |
| **6. `PANIC_MASS_WIPE_PRIOR_TO_SEIZURE`** | 1. **Phase 5 / 6.5C:** Burst of message/chat deletions (`sqlite_sequence` tail gap, `ZTRASHEDSTATE = 1` photo deletions, or app uninstalls in `packages.xml`).<br>2. **Phase 6.1/6.2:** Followed shortly by `DEVICE_SHUTDOWN` or Airplane Mode toggle (`settings_global.xml`) just prior to police seizure timestamp. | **Proves Spoliation / Destruction of Evidence:** Establishes a coordinated panic-wipe sequence immediately preceding arrest. |

---

## 7. Database Schema for Module 8.1 (`entity_graph_and_super_timeline.sqlite`)

The developer must create the following four tables in the master case convergence database:

### Table 1: `entity_master_profiles` (Consolidated 360-Degree Identity Nodes Across All 7 Phases)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `entity_master_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Global unique Entity ID across the entire forensic case. |
| `entity_classification` | `TEXT` | `NOT NULL` | Enum: `DEVICE_OWNER_SELF`, `EXTERNAL_PERSON_ACTOR`, `SHARED_MULE_OR_ESCROW_INSTRUMENT`, `PHYSICAL_HIDEOUT_LOCATION`, `THREAT_APK_OR_C2_ENDPOINT`. |
| `canonical_display_name` | `TEXT` | `NOT NULL` | Best verified name (Priority: `UIDAI Signed Aadhaar QR Name` $\rightarrow$ `Bank CBS / CEX KYC Name` $\rightarrow$ `Local Phonebook Name` $\rightarrow$ `Truecaller Unmasked Name` $\rightarrow$ `WhatsApp Push Name` $\rightarrow$ `Platform @Handle`). |
| `all_observed_names_json` | `TEXT` | `NULL` | JSON dictionary of all names/aliases observed across apps (`{"bank_cbs":"VIKRAM SINGH", "contacts":"Vikram Bhai", "truecaller":"Vikram Crypto OTC", "wa_push":"~ V.S."}`). |
| `tier1_hard_keys_json` | `TEXT` | `NOT NULL` | JSON array of all normalized `TIER_1_HARD_UNIQUE_KEYS` belonging to this entity (`["phone:+919876543210", "wa_lid:164829104928172@lid", "vpa:vikram@ybl", "pan:ABCPS1234K"]`). Indexed via FTS5! |
| `phones_e164_json` | `TEXT` | `NULL` | All linked phone numbers (`+91...`, `+971...`, `+1...` burner numbers). |
| `messaging_handles_json` | `TEXT` | `NULL` | All linked WhatsApp JIDs/LIDs, Telegram IDs/`@handles`, Signal `ACI`s, Session `05...` IDs, Zangi numbers, and Social/Dating IDs. |
| `bank_accounts_and_vpas_json` | `TEXT` | `NULL` | All linked UPI VPAs, Bank Account Numbers, IFSCs, and CEX P2P payment methods. |
| `crypto_addresses_and_uids_json` | `TEXT` | `NULL` | All linked `T...` (TRON), `0x...` (EVM), `bc1q...` (BTC), `4...` (XMR) addresses and CEX `UID`s. |
| `kyc_documents_and_biometrics_json` | `TEXT` | `NULL` | All linked `PAN`, `Aadhaar` (including `.jp2` photo `staging_id`!), `GSTIN`, `Passport MRZ`, `Voter ID`, and `DL` records. |
| `linked_locations_and_addresses_json` | `TEXT` | `NULL` | Linked `Blinkit`/`Swiggy`/`Zomato` flat addresses, `routined` Home/Work clusters, and `IRCTC`/`DigiYatra` travel routes. |
| `risk_and_typology_flags_json` | `TEXT` | `NULL` | E.g., `["MULE_PASS_THROUGH_ACCOUNT", "P2P_USDT_TRADER", "HIGH_OPSEC_SESSION_USER", "UNMATCHED_DATING_PROFILE"]`. |
| `deterministic_merge_proof_json` | `TEXT` | `NOT NULL` | **Courtroom Audit Trail:** Exact list of database rows and `TIER_1` keys that mathematically linked every identifier inside this Entity Profile! |

### Table 2: `entity_graph_edges_ledger` (Typed Directed Relationships & Interaction Summaries)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `graph_edge_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique edge ID. |
| `source_entity_uid` | `INTEGER` | `NOT NULL` | Foreign key to `entity_master_profiles.entity_master_uid`. Indexed! |
| `target_entity_uid` | `INTEGER` | `NOT NULL` | Foreign key to `entity_master_profiles.entity_master_uid`. Indexed! |
| `edge_verb` | `TEXT` | `NOT NULL` | 8-Class Enum from Section 4 (`COMMUNICATED_WITH`, `TRANSFERRED_FIAT_TO`, `SETTLED_P2P_ESCROW_WITH`, `TRANSFERRED_CRYPTO_TO`, `OWNS_OR_CONTROLS_INSTRUMENT`, `POSSESSED_KYC_DOCUMENT_OF`, `VISITED_OR_ORDERED_AT_LOCATION`, `COMPROMISED_OR_CONTROLLED_BY`). |
| `interaction_count` | `INTEGER` | `DEFAULT 1` | Total number of messages, calls, transfers, or visits on this edge. |
| `total_fiat_value_inr` | `REAL` | `DEFAULT 0.0` | Cumulative Rupee (`₹`) value transferred across this edge. |
| `total_crypto_value_summary` | `TEXT` | `NULL` | E.g., `"45,000.00 USDT (TRC-20) + 12.5 XMR"`. |
| `platforms_and_rails_json` | `TEXT` | `Not NULL` | E.g., `["WhatsApp", "Telegram Secret Chat", "PhonePe UPI", "Binance P2P"]`. |
| `has_deleted_or_hidden_evidence` | `INTEGER` | `DEFAULT 0` | **`1` if any record supporting this edge was recovered from `-wal`, B-Tree Freelist, Unallocated space, Unmatched dating cache, or Vault!** |
| `supporting_record_pointers_json` | `TEXT` | `NOT NULL` | JSON array of `(phase_module, table_name, primary_key_uid)` pointers for instant drill-down in Phase 9 UI. |
| `first_interaction_utc_iso` | `TEXT` | `NULL` | Earliest timestamp on this edge. |
| `last_interaction_utc_iso` | `TEXT` | `NULL` | Most recent timestamp on this edge. |

### Table 3: `unified_super_timeline` (The Master Nanosecond-Indexed Cross-Phase Chronological Ledger)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `timeline_event_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Global monotonic event ID. |
| `timestamp_utc_ns` | `INTEGER` | `NOT NULL` | **Primary 64-bit signed integer UTC nanoseconds (`1970-01-01` epoch). Indexed (`idx_timeline_ts_ns`)!** |
| `timestamp_utc_iso` | `TEXT` | `NOT NULL` | `"YYYY-MM-DDTHH:MM:SS.fffffffffZ"`. |
| `timestamp_ist_iso` | `TEXT` | `NOT NULL` | **`"YYYY-MM-DD HH:MM:SS.mmm IST (+05:30)"` (Pre-computed for Indian court reports & UI!).** |
| `timestamp_type_and_precision` | `TEXT` | `NOT NULL` | E.g., `"OCCURRENCE_MS"`, `"CAPTURED_EXIF_SUBSEC"`, `"DB_IMPORTED_SEC"`, `"FSEVENTS_BRACKETED_WINDOW"`. |
| `clock_integrity_status` | `TEXT` | `NOT NULL` | `VERIFIED_NORMAL_CLOCK`, `BRACKETED_WINDOW`, or **`CRITICAL_CLOCK_ROLLBACK_SUSPECTED`**. |
| `originating_phase_and_module` | `TEXT` | `NOT NULL` | E.g., `"PHASE_3_MOD_3_1"`, `"PHASE_4_MOD_4_2"`, `"PHASE_5_MOD_5_1"`, `"PHASE_6_MOD_6_1"`, `"PHASE_7_MOD_7_2"`. |
| `artifact_domain_category` | `TEXT` | `NOT NULL` | Enum: `MESSAGING_CHAT`, `VOICE_VIDEO_CALL`, `FIAT_UPI_BANK_TX`, `CRYPTO_WEB3_CEX_TX`, `OS_APP_LIFECYCLE`, `SCREEN_LOCK_BIOMETRIC`, `SENSOR_CAMERA_MIC_STEP`, `GEOLOCATION_RADIO_FIX`, `HYPERLOCAL_RIDE_TRAVEL`, `DATING_MATRIMONIAL`, `MEDIA_SNAPSHOT_OCR_QR`, `FILESYSTEM_FSEVENT`, `TAMPER_OR_MALWARE_ALERT`. |
| `app_package_or_subsystem` | `TEXT` | `NOT NULL` | E.g., `"com.whatsapp"`, `"com.phonepe.app"`, `"com.binance.dev"`, `"iOS backboardd"`, `"Android AppOps Discrete"`. |
| `android_user_profile_or_locality` | `TEXT` | `NOT NULL` | E.g., `"User 0 (Main)"`, `"User 95 (Dual Messenger)"`, `"User 150 (Secure Folder)"`, `"iOS Local Handset"`. |
| `actor_source_entity_uid` | `INTEGER` | `NULL` | Foreign key to `entity_master_profiles.entity_master_uid` (Initiator / Sender). |
| `actor_target_entity_uid` | `INTEGER` | `NULL` | Foreign key to `entity_master_profiles.entity_master_uid` (Recipient / Counterparty / Location). |
| `event_title_badge` | `TEXT` | `NOT NULL` | Concise action badge (e.g., `"UPI Outflow ₹95,000.00"`, `"WhatsApp Revoked Msg Recovered"`, `"Physical Orientation: Portrait (1)"`). |
| `event_detailed_summary` | `TEXT` | `NOT NULL` | Full searchable summary text (message body, UTR + VPA, `txid` + USDT amount, or OCR snippet). |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD` \[`-wal`\], `RESIDUAL_RECORD` \[Freelist/Trash/Snapshot\], `RECONSTRUCTED_RECORD`). |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `vfs_index.file_id`. |
| `source_table_and_record_uid` | `TEXT` | `NOT NULL` | Exact pointer `<db_name>.<table_name>:<row_uid>` + `physical_byte_offset` for Pane 3 Hex Inspector! |
| `action_burst_story_uid` | `INTEGER` | `NULL` | Foreign key to `forensic_action_burst_stories.story_uid` if part of a detected multi-phase crime sequence! |

### Table 4: `forensic_action_burst_stories` (Automatically Detected 60-Second Multi-Phase Crime Sequences)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `story_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique Story Block ID. |
| `story_signature_code` | `TEXT` | `NOT NULL` | 6-Signature Enum from Section 6 (`ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW`, `TROJAN_OR_REMOTE_ACCESS_SILENT_DRAIN`, `CROSS_APP_COVERT_HANDOFF_AND_DELETION`, `PAYMENT_SCREENSHOT_PROOF_TO_HANDLER`, `P2P_ESCROW_TO_SELF_CUSTODY_VELOCITY_HOP`, `PANIC_MASS_WIPE_PRIOR_TO_SEIZURE`). |
| `severity_level` | `TEXT` | `NOT NULL` | `CRITICAL_SMOKING_GUN`, `HIGH_CORRELATION`, `MEDIUM_BEHAVIORAL`. |
| `burst_start_utc_iso` | `TEXT` | `NOT NULL` | Start timestamp of the multi-phase burst. |
| `burst_end_utc_iso` | `TEXT` | `NOT NULL` | End timestamp of the multi-phase burst. |
| `burst_duration_seconds` | `REAL` | `NOT NULL` | Total elapsed seconds across the sequence. |
| `involved_entity_uids_json` | `TEXT` | `NOT NULL` | JSON array of `entity_master_uid`s involved in this burst. |
| `involved_timeline_event_uids` | `TEXT` | `NOT NULL` | Ordered JSON array of `timeline_event_uid`s comprising the step-by-step sequence. |
| `automated_courtroom_narrative` | `TEXT` | `NOT NULL` | Plain-English chronological synthesis explaining how the OS telemetry, communications, location, and financial/visual artifacts corroborate each other. |

---

## 8. Developer Acceptance Test Checklist for Module 8.1

1. **The Non-Transitive Weak-Key Guardrail Test (No `"Rahul"` Snowballing):**
   * Create two contacts in `contacts2.db`: Contact 1 (`display_name = "Rahul"`, `phone = "+919811111111"`) and Contact 2 (`display_name = "Rahul"`, `phone = "+919822222222"`). Also create a WhatsApp `@lid` mapping (`164829@lid` $\leftrightarrow$ `919811111111@s.whatsapp.net`) and a PhonePe VPA (`9811111111@ybl`, CBS Name `"RAHUL VERMA"`).
   * Verify that Sub-Engine 8.1A merges Contact 1, `164829@lid`, and `9811111111@ybl` into **Entity #1** (via `TIER_1` hard key `phone_tail10:9811111111`), while keeping Contact 2 (`+919822222222`) as a **completely separate Entity #2** despite both sharing the display name `"Rahul"`!
2. **The 6-Phase Mule Identity Unification Test:**
   * Feed six records belonging to the same accomplice across six phases:
     1. Phase 3: UPI transfer to `9876543210@okaxis`
     2. Phase 4.2: Binance P2P Seller with VPA `9876543210@okaxis`, Binance `UID 482910482`, and PAN `ABCPS1234K`
     3. Phase 5.1: WhatsApp chat with `919876543210@s.whatsapp.net` where the user sends `"Pay my Tron wallet TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"`
     4. Phase 6.4: Blinkit saved address `Flat 1404, Tower B2` with `receiver_phone = "9876543210"`
     5. Phase 7.4: Photo of PAN card `ABCPS1234K` (`"VIKRAM SINGH"`)
   * Verify that Sub-Engine 8.1A fuses all five into a single `entity_master_profiles` row with complete `deterministic_merge_proof_json` lineage!
3. **The 60-Second "Action-Burst" Human-Operated Payment Story Test:**
   * Insert four events into `unified_super_timeline` within a 22-second window (`14:10:00` to `14:10:22 UTC`):
     * `14:10:00.120` (Phase 6.2): `KEYGUARD_HIDDEN` (Device Unlocked)
     * `14:10:02.450` (Phase 6.2): `com.phonepe.app` `ACTIVITY_RESUMED`
     * `14:10:14.890` (Phase 3.1): PhonePe UPI Debit `₹95,000.00` (`UTR 630914829104`)
     * `14:10:19.300` (Phase 7.1): Screenshot `Screenshot_20261105-194019_PhonePe.jpg` created and sent on Telegram at `14:10:22.000` (Phase 5.2).
   * Verify that Sub-Engine 8.1D automatically detects and emits both `ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW` and `PAYMENT_SCREENSHOT_PROOF_TO_HANDLER` in `forensic_action_burst_stories`!