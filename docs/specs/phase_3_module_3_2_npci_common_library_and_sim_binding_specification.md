# Engineering Specification: Phase 3, Module 3.2 — NPCI Common Library (`CL`) & Physical SIM / Hardware Device-Binding Forensics

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 3.2** of the Forensic Data Parser (corresponding to **Groups 1, 9, 10, 12, 13, and 17** of the Unified Master Register). It contains **zero programming code** and explains NPCI's hardware-binding cryptography, Android/iOS physical SIM card ledgers (`telephony.db` `siminfo`), outbound Virtual Mobile Number (VMN) verification SMS strings, embedded Common Library (`CL`) vault structures, and remote SIM-binding malware detection from first principles so that any developer can build a courtroom-grade SIM-to-UPI attribution engine.

---

## 1. Purpose & Mental Model (Why SIM-Binding Forensics Wins Courtroom Cases)

Whenever police seize a smartphone involved in UPI fraud, mule-account money laundering, cyber extortion, or illegal betting, the accused's defence lawyer almost always raises one of three courtroom arguments:

1. *"My client's SIM card was never inside this seized phone when the UPI transactions happened."*
2. *"Someone else remotely hacked my client's UPI account or cloned their phone."*
3. *"My client clicked a malicious link (like a fake RTO e-Challan or PM-Kisan APK), and a fraudster sitting in another state secretly registered my client's bank account on the fraudster's own phone."*

Standard forensic tools only extract the list of UPI transactions and leave the investigator unable to prove **which physical SIM card (`ICCID` / `IMSI`)** and **which hardware device (`Android ID` / `IMEI` / `TEE Keystore`)** actually registered and authenticated the UPI account.

### How NPCI's 3-Step Device-Binding Architecture Works Under the Hood
Under the National Payments Corporation of India (NPCI) procedural guidelines, **no UPI account can be activated using a simple incoming OTP SMS alone**. Instead, NPCI enforces a strict **3-Step Hardware & SIM Cryptographic Handshake**:

* **Step 1 (The Silent Outbound VMN Verification SMS):** When a user selects their bank in PhonePe, Google Pay India, Paytm, BHIM, or a banking app, the app generates a unique cryptographic challenge string containing a hash of the handset's hardware `deviceId`, `appId`, and a one-time random token. The app forces the phone's cellular modem to **silently send an outbound SMS** from the user's physical SIM slot to an NPCI / Sponsor Bank **Virtual Mobile Number (VMN) Longcode** (e.g., `9223008333` or `9289592895`).
* **Step 2 (Core Banking MSISDN Lookup — `ReqRegMob`):** The PSP bank's SMS gateway receives that outbound SMS directly from the telecom operator's SMSC, extracts the sender's real hardware mobile number (`MSISDN`) from the telecom signaling header, verifies that the cryptographic string matches the app's active session, and queries the bank's Core Banking Solution (CBS) for all bank accounts linked to that mobile number.
* **Step 3 (NPCI Common Library `K0` Key Provisioning — `ReqListKeys`):** Once the user verifies their debit card (or Aadhaar OTP) and sets an MPIN, the NPCI server provisions a **256-bit Device-Bound Master Key (`K0` / `token`)** directly into the **NPCI Common Library (`CL`)** embedded inside the UPI app. From that moment on, every time the user enters their 4- or 6-digit UPI MPIN, the NPCI Common Library signs the transaction locally using `K0` + the phone's **Android Hardware Keystore (`TEE` / `StrongBox`)** or **iOS Secure Enclave (`Keychain`)**.

**Module 3.2 reconstructs all three steps of this handshake on the seized handset.**

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in SIM & UPI Binding Forensics

Before implementing Module 3.2, the developer must understand six critical traps that cause amateur tools to miss or misinterpret SIM-binding evidence:

### Mistake 1: Looking for the NPCI Common Library as a Separate Installed App
* **The Trap:** Searching `/data/user/0/` for a standalone folder named `/data/user/0/org.npci.upi.security.pinactivitycomponent/`.
* **Why It Fails:** The NPCI Common Library (`CL`) is **not** a standalone app installed from the Play Store. It is an **embedded SDK (AAR / Framework)** compiled directly *inside* every host UPI application (`com.phonepe.app`, `com.google.android.apps.nbu.paisa.user`, `net.one97.paytm`, `in.org.npci.upiapp`, `com.whatsapp`, `com.sbi.lotusintouch`, etc.). Its preference XMLs and SQLite tables sit **inside** each host UPI app's own **`shared_prefs/` and `databases/` folders**.
* **The Rule:** Scan the `shared_prefs/`, `databases/`, and `files/` directories of **every** UPI and banking app resolved by Module 1.3 for NPCI Common Library files (Section 5).

### Mistake 2: Ignoring Android's `telephony.db` (`siminfo` Table) for Historical Ejected SIM Cards
* **The Trap:** Only checking which SIM card is *currently* inserted in the phone at the moment of seizure.
* **Why It Fails:** Mule operators routinely insert "SIM Card A" into the phone, complete the UPI outbound SMS binding, drain the bank account, **physically eject "SIM Card A"**, and insert "SIM Card B" before police arrest them. However, Android maintains a cumulative historical table called **`siminfo`** inside `/data/user_de/0/com.android.providers.telephony/databases/telephony.db` that permanently records the **20-digit `icc_id` (`ICCID`)**, carrier name, phone number, and slot history of **every SIM card ever inserted into the phone**. Because `telephony.db` lives in **DE (Device Encrypted)** storage, it is accessible even in **BFU** extractions.
* **The Rule:** Always parse `telephony.db` (`siminfo`) first to build a complete historical inventory of both currently inserted (`sim_id >= 0`) and previously ejected (`sim_id == -1`) SIM cards (Section 3.1).

### Mistake 3: Failing to Join `mmssms.db` (`sub_id` & `creator`) to `telephony.db` (`siminfo._id`)
* **The Trap:** Finding an outbound UPI verification SMS in `mmssms.db` (or `bugle_db`) and reporting *when* it was sent, without reporting **which SIM card sent it** and **which app triggered it**.
* **Why It Fails:** In a Dual-SIM phone (or a phone that has used 10 different mule SIM cards over a month), every row in Android's `sms` table contains two critical forensic columns:
  1. **`sub_id` (`INTEGER`):** The exact foreign key pointing to **`siminfo._id`** in `telephony.db`. Joining `sms.sub_id = siminfo._id` mathematically proves which exact physical 20-digit `ICCID` SIM card sent the binding SMS or received the bank OTP.
  2. **`creator` (`TEXT`):** The exact **Android package name** of the application that called the OS `SmsManager` API to send the outbound SMS (e.g., `com.phonepe.app`, `com.google.android.apps.nbu.paisa.user`, or a malicious trojan APK `com.mparivahan.challan`).
* **The Rule:** Every SMS analyzed by Module 3.2 must execute the 3-way join: `sms` $\leftrightarrow$ `siminfo._id` (`ICCID`) $\leftrightarrow$ `sms.creator` (`resolved_application_catalog`).

### Mistake 4: Missing Silent Outbound Binding SMS Messages Deleted from `mmssms.db`
* **The Trap:** Only running a keyword search for `"UPI"` in the active `sms` table.
* **Why It Fails:**
  1. Different PSP banks format their outbound verification strings differently (starting with `UPI`, `VERIFY`, `ACTIVATE`, `GPay`, `PP`, `PYTM`, or pure Base64/Hex strings sent to specific 10-digit VMN longcodes).
  2. Malware and some banking SDKs immediately delete the outbound verification SMS from `mmssms.db` after `RESULT_OK` so the user does not see it in their SMS inbox.
* **The Rule:** Match outbound SMS messages by **both** destination VMN longcode/shortcode AND payload regex, and always run **Phase 2, Module 2.1's Shared `-wal` Reader and B-Tree Freelist Carver** on `mmssms.db`, `bugle_db`, and iOS `sms.db` to recover deleted outbound verification messages.

### Mistake 5: Failing to Detect the "Remote Ghost SIM-Binding" APK Trojan Attack
* **The Trap:** Seeing an outbound UPI verification SMS in a phone's `mmssms.db` and automatically concluding that the person holding the phone registered the UPI account on that phone.
* **Why It Fails:** In Indian APK trojan fraud:
  1. The victim installs a malicious sideloaded APK (e.g., fake *RTO e-Challan*, *Electricity Bill*, or *PM-Kisan* app) that requests `SEND_SMS` and `RECEIVE_SMS` permissions.
  2. The fraudster (on Phone B) opens a UPI app on Phone B and types the victim's phone number.
  3. The fraudster's UPI app generates the cryptographic binding SMS string (`UPI <hash_of_Phone_B>`), sends that string via Command-and-Control (C2) to the malicious APK on the victim's Phone A, and **the malicious APK on Phone A silently sends that SMS out through the victim's SIM card**.
* **The Rule:** Use **Sub-Engine 3.2D's 3-Point Ghost-Binding Correlation Test** (Section 6) to mathematically prove whether an outbound binding SMS was sent by a legitimate local UPI app (`creator == com.phonepe.app` + matching local CL token) OR hijacked by a sideloaded trojan APK (`creator == sideloaded_malware_pkg` + zero local UPI app registration at that timestamp).

### Mistake 6: Ignoring iOS eSIM / Physical SIM Swap Artifacts (`CellularUsage.db` & `commcenter.plist`)
* **The Trap:** Assuming SIM history is only recoverable on Android.
* **Why It Fails:** iOS maintains a persistent database of every physical SIM and eSIM ever inserted into the iPhone inside `/private/var/wireless/Library/Databases/CellularUsage.db` (`subscriber_info` / `carrier_bundle` tables) and `/private/var/preferences/SystemConfiguration/com.apple.commcenter.plist`, preserving historical `ICCID`s, `IMSI`s, and phone numbers across SIM swaps.

---

## 3. Step 1 — Sub-Engine 3.2A: Physical SIM & eSIM Historical Ledger (`telephony.db` & iOS `CommCenter`)

Before analyzing any UPI app or SMS, Module 3.2 builds the **Master Device SIM Card Ledger** so every subscription ID (`sub_id`) on the device can be mapped to a physical SIM card.

### 3.1 Android Historical SIM Extraction (`/data/user_de/0/com.android.providers.telephony/databases/telephony.db`)

1. **Stage `telephony.db` via Module 1.1 & Process via Module 2.1:**
   * Canonical path: `/data/user_de/0/com.android.providers.telephony/databases/telephony.db` (also check `/data/user/0/com.android.providers.telephony/databases/telephony.db` on older Android builds).
   * Because this database lives inside **DE (`user_de`) storage**, it is present and readable in both **BFU** and **AFU** extractions.
   * Run Module 2.1's active table query, `-wal` historical frame reader, and B-Tree freelist carver on the **`siminfo`** table.
2. **Extract and Normalize Every Row in `siminfo`:**

| `siminfo` Column Name | SQLite Type | Forensic Meaning & Normalization Rule |
|---|---|---|
| **`_id`** | `INTEGER` | **The Subscription ID (`sub_id`)!** Every row in `mmssms.db` (`sms.sub_id`), `bugle_db`, and `calllog.db` (`calls.subscription_id`) references this exact integer (`1`, `2`, `3`, ...). Because `_id` increments sequentially ($1, 2, 3 \dots N$), it reveals the exact chronological order in which SIM cards were first inserted into the phone! |
| **`icc_id`** | `TEXT` | **The 19-to-20 digit Integrated Circuit Card Identifier (`ICCID`)** printed on the physical SIM card chip (e.g., `8991...` where `89` = Telecom, `91` = India)! Even if the phone number (`number`) column is blank, the `icc_id` uniquely identifies the physical SIM card at the telecom operator level. |
| **`sim_id`** (or `sim_slot_index`) | `INTEGER` | **Current Physical Slot State:**<br>• `0`: Currently inserted in **SIM Slot 1** at the moment of seizure.<br>• `1`: Currently inserted in **SIM Slot 2** at the moment of seizure.<br>• **`-1` (`INVALID_SIM_SLOT_INDEX`):** **Ejected Historical SIM Card!** Proves the SIM card was previously inserted in this handset and was physically removed prior to seizure. |
| **`display_name`** & **`carrier_name`** | `TEXT` | Carrier network label (e.g., `"Jio 4G"`, `"IND airtel"`, `"Vi India"`, `"BSNL Mobile"`). |
| **`number`** | `TEXT` | The 10-digit MSISDN / mobile phone number stored on the SIM or entered by the user (normalize `+91` prefix). |
| **`mcc`** & **`mnc`** | `INTEGER` / `TEXT` | Mobile Country Code (`404` or `405` for India) and Mobile Network Code (identifies the exact Indian state/telecom circle where the SIM was issued!). |
| **`is_embedded`** | `INTEGER` | `1` = **eSIM profile** downloaded onto the motherboard's eUICC chip; `0` = **Removable Physical Nano-SIM card**. |
| **`card_id`** & **`imsi`** | `TEXT` | Hardware card identifier and International Mobile Subscriber Identity (`IMSI` prefix `404`/`405`), if populated. |

### 3.2 iOS Physical SIM & eSIM Historical Extraction
On iOS extractions (Logical Backup `WirelessDomain` or FFS), extract the historical SIM inventory from three sources:
1. **`/private/var/wireless/Library/Databases/CellularUsage.db`:**
   * Query `subscriber_info` (or ` subscriber_mdn` / `bundle_info`): Extracts `subscriber_id` (`ICCID` / `IMSI`), `mdn` (phone number), and `last_update_time` (Apple Cocoa timestamp).
2. **`/private/var/preferences/SystemConfiguration/com.apple.commcenter.plist` & `com.apple.commcenter.device_specific_nobackup.plist`:**
   * Inspect `PersonalWallet`, `LastKnownICCID`, `CarrierBookmarks`, and `SubscriptionInfo` arrays to extract active and historical `ICCID`s, `IMSI`s, `PhoneNumber`, and eSIM activation timestamps.
3. **iOS Unified Logs (`tracev3`) & Biome Connectivity Streams:**
   * Query `CommCenter` predicates for `ICCID`, `IMSI`, and SIM tray insertion/removal state transitions (`CTSIMSupport`).

---

## 4. Step 2 — Sub-Engine 3.2B: Outbound VMN Verification SMS & Binary Data Port Decoder

Every time any UPI app (or a remote SIM-binding trojan) binds a SIM card to a UPI profile, it transmits an outbound SMS from the handset. Sub-Engine 3.2B hunts for these outbound verification messages across `mmssms.db`, `bugle_db`, and iOS `sms.db` (including `-wal` and freelist carved rows from Module 2.1).

### 4.1 Master Directory of Indian UPI Outbound Verification VMN Longcodes & Patterns

Scan all outbound SMS messages (`type == 2` \[Sent\], `type == 4` \[Outbox\], `type == 5` \[Failed\], or `is_from_me == 1` on iOS) matching either the **Destination Number** or the **Payload Pattern** below:

| UPI Platform / PSP Bank | Known Outbound VMN Longcodes & Shortcodes | Outbound SMS Payload Pattern / Prefix |
|---|---|---|
| **PhonePe (`@ybl`, `@ibl`, `@axl`)** | `9223008333`, `9289592895`, `9266801801`, `9212500888`, `8422849999`, `56161*` | `PP <Base64/Hex_Token>`, `UPI <Hex_or_Base64_Challenge>`, or `<AppHash> <Encrypted_Device_Binding_String>` |
| **Google Pay India (`@okaxis`, `@okhdfcbank`, `@okicici`, `@oksbi`)** | `9223008333`, `9289592895`, `9870807070`, `8657002200`, `56161140`, `56767*` | `VERIFY <Base64_Token>`, `GPay <Token>`, or `<6_to_64_char_Alphanumeric_Hash>` |
| **Paytm (`@ptyes`, `@ptaxis`, `@pthdfc`, `@ptsbi`)** | `9289592895`, `9223008333`, `7065970659`, `9211400400`, `56161*` | `PYTM <Token>`, `UPI <Encrypted_Token>`, or `ACTIVATE <Hex_String>` |
| **BHIM (`@upi`) & NPCI Direct** | `9223008333`, `9289592895`, `56161` | `UPI <32_to_128_char_Hex_or_Base64_Token>` |
| **WhatsApp Pay (`@waicici`, `@wahdfcbank`, `@waaxis`, `@wasbi`)** | `9223008333`, `9289592895`, `8657002200` | `WA <Encrypted_Token>` or `UPI <Base64_Challenge>` where `sms.creator == "com.whatsapp"` |
| **YONO SBI / HDFC / ICICI / Axis / Kotak Native Apps** | `9223488888` (SBI), `9289200017` (HDFC), `9215676766` (ICICI), `9212500888` (Axis), `9971056767` (Kotak), `56767*`, `56161*` | `MBSREG <Token>`, `VER <Token>`, `ACT <Token>`, `RSB <Hex_Challenge>` |

### 4.2 The 3-Way Attribution Join on Every Discovered Outbound Binding SMS
For every outbound binding SMS discovered in `mmssms.db` (`sms` table) or `bugle_db`:
1. **Extract Exact Timestamp & Delivery Status:**
   * Read `date` (13-digit Unix ms when sent), `date_sent`, `type` (`2` = Successfully Sent, `5` = Failed due to zero main talktime balance or no network!), and `error_code`.
2. **Join 1 — Physical SIM Attribution (`sms.sub_id` $\rightarrow$ `siminfo._id`):**
   * Look up `sms.sub_id` in Sub-Engine 3.2A's `device_sim_card_history_ledger` to resolve the exact **20-digit `ICCID`**, **Carrier Name**, **MSISDN (`number`)**, and whether that SIM card is still inside the phone (`sim_id >= 0`) or was ejected (`sim_id == -1`).
3. **Join 2 — Originating App Attribution (`sms.creator` $\rightarrow$ `resolved_application_catalog`):**
   * Read the `creator` column from `mmssms.db` (`sms` table):
     * If `creator` is a legitimate UPI/banking package (e.g., `com.phonepe.app`), link it to that app's `app_instance_id` (and check which Android user profile `0`, `95`, or `999` triggered it).
     * If `creator` is **not** a recognized UPI or banking package (for example, `com.rto.echallan`, `com.customer.support`, `com.android.shell`, or an unknown sideloaded APK), immediately flag the SMS for **Sub-Engine 3.2D (Trojan Hijack Audit)**.

---

## 5. Step 3 — Sub-Engine 3.2C: Embedded NPCI Common Library (`CL`) Vault & Hardware Keystore Audit

Inside every UPI app sandbox (`PhonePe`, `GPay India`, `Paytm`, `BHIM`, `WhatsApp`, and banking apps), the embedded **NPCI Common Library (`org.npci.upi.security.pinactivitycomponent`)** stores the cryptographic keys and device-binding parameters provisioned during Step 3 of the NPCI handshake.

### 5.1 Scanning Host UPI Sandboxes for NPCI Common Library (`CL`) Artifacts
For each resolved UPI or banking app instance from Module 1.3, scan its `shared_prefs/`, `databases/`, and `files/` directories for:
1. **NPCI Common Library Preference XMLs & SQLite Stores:**
   * Files matching `*npci*.xml`, `*cl_*.xml`, `*pinactivitycomponent*.xml`, `*vault*.xml`, `*device_binding*.xml`, or SQLite tables inside `cl_*.db` / `npci_*.db`.
2. **Fields to Extract from the Common Library Store:**
   * **`k0_token_or_vault_blob`:** The encrypted `K0` master token or `token` XML value provisioned by NPCI's `ReqListKeys` API.
   * **`token_registration_or_rotation_ts`:** Timestamp when the `K0` key was issued or last rotated (proves when the UPI MPIN / device binding was active on this device).
   * **`cl_device_id` / `imei_or_android_id_hash`:** The hardware identifier bound into the NPCI challenge.
   * **`bound_sim_iccid_or_subid`:** The SIM card `ICCID` or `subscriptionId` saved by the host UPI app's SIM-change monitor! *(Crucial Forensic Mechanism: Every UPI app saves the bound SIM's `ICCID` / `sub_id` in its preferences so that if the user removes the SIM card from the tray, the UPI app immediately detects `current_iccid != saved_iccid` and locks UPI access! Extracting `saved_iccid` from the app's preferences proves which SIM card was bound to that app).*

### 5.2 Cross-Referencing Android Hardware Keystore (`/data/misc/keystore/persistent.sqlite`)
Query **Phase 2, Module 2.2's `case_cryptographic_keyring`** (parsed from `/data/misc/keystore/persistent.sqlite` on Android 12–17 or `/data/misc/keystore/user_0/`):
* Filter for entries where `app_instance_id` matches the UPI app and `service_or_alias` contains `npci`, `cl_`, `upi`, `k0`, `device_binding`, or `pin`.
* Record the hardware key creation/modification timestamp from `keymetadata`—providing hardware-level TEE/StrongBox corroboration of when the UPI cryptographic binding was established on the motherboard.

---

## 6. Step 4 — Sub-Engine 3.2D: The 3-Point "Remote Ghost SIM-Binding" Trojan Detector

To protect innocent victims whose SIM cards were hijacked by remote SMS-forwarding malware—and to defeat false "I was hacked" claims made by actual mule operators—Sub-Engine 3.2D runs a **deterministic 3-Point Correlation Test** on every discovered outbound UPI verification SMS:

| Test Point | Case A: Legitimate Local Handset Registration (Suspect Operated UPI on This Phone) | Case B: Remote "Ghost SIM-Binding" Trojan Attack (Fraudster Registered Victim's SIM on a Remote Phone) |
|---|---|---|
| **Point 1: `sms.creator` & Installer Lineage** | `sms.creator` in `mmssms.db` is an official Play Store-installed UPI/banking app (`com.phonepe.app`, `nbu.paisa.user`, `net.one97.paytm`) with a verified official signing certificate (`is_signature_verified == 1`). | `sms.creator` is a **sideloaded APK** (`installer != com.android.vending`), an app holding `SEND_SMS` + `RECEIVE_SMS` / `BIND_ACCESSIBILITY_SERVICE` permissions, or `com.android.shell`. |
| **Point 2: Local UPI App Sandbox & `CL` Token Match** | The corresponding UPI app is installed on this handset (or in `usagestats`), was in the **Foreground (`ACTIVITY_RESUMED` in `UsageStats` / `knowledgeC`)** at the exact second the outbound SMS was sent, and holds a matching `bound_sim_iccid` / `CL` registration timestamp within $\le 120\text{ seconds}$ of the SMS! | **Zero local UPI app registration** occurred on this handset at the timestamp of the outbound SMS; the UPI app targeted by the VMN was either not installed or not in the foreground when the SMS was transmitted! |
| **Point 3: Subsequent Transaction Execution Layer** | Subsequent UPI transactions appear in **both** Layer 1 (Local UPI App Sandbox DB on this phone) **and** Layer 2 (Bank DLT Debit SMS on this phone). | Subsequent Bank DLT Debit SMS alerts (`Layer 2`) arrive on this phone's SIM card, **but zero corresponding transactions exist in any local UPI app database (`Layer 1`) on this phone**! |

* **Automated Classification:**
  * If Points 1, 2, and 3 match **Case A**: Assign `binding_attribution_verdict = "VERIFIED_LOCAL_HANDSET_AND_SIM_BINDING"` (defeats the "I was remotely hacked" defence in court).
  * If Points 1, 2, and 3 match **Case B**: Assign `binding_attribution_verdict = "COMPROMISED_REMOTE_GHOST_SIM_BINDING_VIA_TROJAN"` and record the exact malicious package name (`sms.creator`), its sideload source (`initiatingPackageName` from Module 1.3), and its installation timestamp.

---

## 7. Database Schema for Module 3.2 (`npci_sim_binding_engine.sqlite`)

The developer must create the following four tables in the case database:

### Table 1: `device_sim_card_history_ledger` (All Active & Ejected Historical SIMs / eSIMs)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `sim_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `os_platform` | `TEXT` | `NOT NULL` | Enum: `ANDROID`, `IOS`. |
| `android_sub_id` | `INTEGER` | `NULL` | Exact `siminfo._id` (`sub_id`) integer on Android (`1, 2, 3...` chronological insertion order). |
| `iccid_20_digit` | `TEXT` | `NULL` | Physical/eSIM 19–20 digit `ICCID` serial number (indexed!). |
| `imsi_number` | `TEXT` | `NULL` | 15-digit `IMSI` (if available). |
| `msisdn_phone_number` | `TEXT` | `NULL` | Normalized 10-digit mobile number associated with this SIM. |
| `carrier_display_name` | `TEXT` | `NULL` | E.g., `"Jio 4G"`, `"IND airtel"`, `"Vi India"`. |
| `mcc_mnc_code` | `TEXT` | `NULL` | Combined `MCC-MNC` (e.g., `"405-86"`). |
| `sim_form_factor` | `TEXT` | `NOT NULL` | Enum: `PHYSICAL_SIM`, `EMBEDDED_ESIM`. |
| `seizure_slot_state` | `TEXT` | `NOT NULL` | Enum: `ACTIVE_SLOT_1`, `ACTIVE_SLOT_2`, `EJECTED_HISTORICAL_SIM` (`sim_id == -1`). |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `first_observed_utc_iso` | `TEXT` | `NULL` | Earliest SMS, call, or registration timestamp tied to this `sub_id` / `ICCID`. |
| `last_observed_utc_iso` | `TEXT` | `NULL` | Latest SMS, call, or registration timestamp tied to this `sub_id` / `ICCID`. |

### Table 2: `upi_outbound_binding_sms_audit` (Every Silent Outbound VMN Verification SMS)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `binding_sms_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `mmssms.db`, `bugle_db`, or `sms.db` in `vfs_index`. |
| `sms_row_id` | `INTEGER` | `NULL` | Original SQLite `ROWID` / `_id` in the SMS table. |
| `recovery_classification` | `TEXT` | `NOT NULL` | `ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD` (`-wal`), or `RESIDUAL_RECORD` (freelist carved). |
| `destination_vmn_number` | `TEXT` | `NOT NULL` | Recipient NPCI / Bank VMN longcode or shortcode (e.g., `"9223008333"`). |
| `sms_payload_raw` | `TEXT` | `NOT NULL` | Exact cryptographic binding string transmitted (`"UPI ..."` / `"PP ..."`). |
| `inferred_target_psp_or_bank` | `TEXT` | `NULL` | Resolved target platform based on VMN and prefix (`"PhonePe"`, `"Google Pay India"`, `"SBI"`). |
| `android_sub_id` | `INTEGER` | `NULL` | `sms.sub_id` value. |
| `resolved_sim_iccid` | `TEXT` | `NULL` | Joined `iccid_20_digit` from `device_sim_card_history_ledger`! |
| `resolved_sim_msisdn` | `TEXT` | `NULL` | Joined 10-digit mobile number of the SIM that sent this SMS. |
| `creator_package_name` | `TEXT` | `NULL` | Exact `sms.creator` package name that triggered the outbound SMS. |
| `delivery_status` | `TEXT` | `NOT NULL` | Enum: `SENT_SUCCESS`, `FAILED_NO_BALANCE_OR_NETWORK`, `OUTBOX_QUEUED`. |
| `sent_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp when the binding SMS was sent. |
| `binding_attribution_verdict` | `TEXT` | `NOT NULL` | Enum from Sub-Engine 3.2D: `VERIFIED_LOCAL_HANDSET_AND_SIM_BINDING` vs. `COMPROMISED_REMOTE_GHOST_SIM_BINDING_VIA_TROJAN`. |

### Table 3: `npci_common_library_vault_records` (Embedded `CL` & Host Sandbox Binding Tokens)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `cl_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to host UPI/banking app in Module 1.3. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `shared_prefs` XML, `MMKV`, or `CL` database in `vfs_index`. |
| `bound_sim_iccid_in_app` | `TEXT` | `NULL` | SIM `ICCID` saved inside the UPI app's SIM-change monitor preferences. |
| `bound_sim_sub_id_in_app` | `INTEGER` | `NULL` | SIM `sub_id` saved inside the UPI app's preferences. |
| `bound_mobile_msisdn` | `TEXT` | `NULL` | 10-digit mobile number bound inside the UPI app. |
| `bound_hardware_device_id` | `TEXT` | `NULL` | Hardware `deviceId` / `Android ID` recorded by the Common Library. |
| `cl_k0_token_present` | `INTEGER` | `DEFAULT 0` | `1` if an active `K0` / `CL` credential blob is present in the sandbox. |
| `matched_keystore_alias` | `TEXT` | `NULL` | Matching hardware key alias in `/data/misc/keystore/persistent.sqlite`. |
| `binding_registered_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp of `CL` token / device binding registration. |

---

## 8. Developer Acceptance Test Checklist for Module 3.2

1. **The Ejected Mule SIM (`sim_id == -1`) Attribution Test:** Populate a test `telephony.db` (`siminfo` table) with Row `_id = 3`, `icc_id = "89918540400012345678"`, `sim_id = -1` (ejected), and `number = "+919876543210"`. Insert an outbound SMS in `mmssms.db` to `"9223008333"` with body `"PP a8f9d2..."`, `sub_id = 3`, and `creator = "com.phonepe.app"`. Verify that Module 3.2 joins `sub_id = 3` to `siminfo._id = 3`, identifies that the PhonePe binding SMS was sent using the now-ejected SIM card `89918540400012345678`, and marks the verdict as `VERIFIED_LOCAL_HANDSET_AND_SIM_BINDING`.
2. **The Remote Ghost SIM-Binding Trojan Detection Test:** Insert an outbound SMS in `mmssms.db` to `"9289592895"` with body `"UPI 7b6c5d..."`, `sub_id = 1`, and `creator = "com.parivahan.echallan.apk"` (where `com.parivahan.echallan.apk` was sideloaded via WhatsApp in Module 1.3 and no local UPI app registration occurred at that timestamp). Verify that Sub-Engine 3.2D automatically flags the SMS as `COMPROMISED_REMOTE_GHOST_SIM_BINDING_VIA_TROJAN`!
3. **The Freelist Deleted Binding SMS Recovery Test:** Delete the outbound `"UPI ..."` verification row from `mmssms.db` (`PRAGMA secure_delete = OFF`) and run Module 3.2. Verify that Module 2.1's B-Tree Freelist/Freeblock Carver recovers the deleted outbound SMS and Module 3.2 successfully links it to its `sub_id` and `creator`.